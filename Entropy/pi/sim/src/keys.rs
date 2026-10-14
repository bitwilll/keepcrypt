//! The simulated keys and clock (tasks/todo.md, M3 group 7, Q30): a script of presses and waits,
//! played on a virtual clock.
//!
//! - Each scripted press becomes a raw edge train with bounce on both edges, run through pi/app's
//!   own `input::Debouncer`, so every press the app sees has passed the debouncer the device uses.
//!   Its event comes 24 ms after the press starts, carrying the first edge's time; the next press
//!   starts 150 ms after it, once its release has stayed up for the debounce time.
//! - A wait is time with no key. The app's timers fire at their deadlines within it, and the next
//!   input starts when it ends. A wait that ends the script ends with a `Tick` at its end, even
//!   before the deadline: the scenario has no more input for now, and the app, finding nothing
//!   due, asks again once the scenario adds some (`hal::Buttons` allows an early tick).
//! - The clock moves only here: to a press's event, to the deadline of a `Tick`, or to the end of a
//!   wait. It never goes back.
//! - A `next_event` call with nothing left in the script fails the test: a scenario feeds the app
//!   only while it has input for it.
//! - So does an app whose deadline never moves: a deadline already past is a `Tick` now, which
//!   leaves the clock where it is, and an app that asks for one more than `STALLED_TICKS` times in
//!   a row would spin forever on the virtual clock.

use std::collections::VecDeque;

use keepcrypt_pi::input::{Debouncer, Event, Key};

const MS: u64 = 1_000_000;
/// A scripted press's raw edges in milliseconds from its start: down with two bounces and held,
/// then up with one bounce.
const PRESS_EDGES_MS: [(u64, bool); 8] = [
    (0, true),
    (1, false),
    (2, true),
    (3, false),
    (4, true),
    (100, false),
    (101, true),
    (102, false),
];
/// From one scripted press's start to the earliest start of the next: after the release's last
/// edge (102 ms) has been stable for the 20 ms debounce time.
const PRESS_SPAN_NS: u64 = 150 * MS;
/// Ticks in a row that leave the clock where it is. The app takes one after a key that came past
/// its next deadline, then sets deadlines ahead; more is a deadline that never moves.
const STALLED_TICKS: u32 = 8;

/// One step of the script.
enum Input {
    Press(Key),
    /// No key for this many nanoseconds.
    Wait(u64),
}

/// The script, the debouncer it runs through, and the virtual clock.
pub(crate) struct Keys {
    script: VecDeque<Input>,
    debouncer: Debouncer,
    now_ns: u64,
    /// The earliest start of the next press.
    free_ns: u64,
    /// The start of the press at the front of the script, once its edges are in the debouncer.
    started_ns: Option<u64>,
    /// The end of the wait at the front of the script, once it has begun.
    wait_until_ns: Option<u64>,
    /// The `Tick`s in a row that left the clock where it was.
    stalled: u32,
}

impl Keys {
    pub(crate) fn new() -> Self {
        Keys {
            script: VecDeque::new(),
            debouncer: Debouncer::default(),
            now_ns: 0,
            free_ns: 0,
            started_ns: None,
            wait_until_ns: None,
            stalled: 0,
        }
    }

    pub(crate) fn press(&mut self, key: Key) {
        self.script.push_back(Input::Press(key));
    }

    pub(crate) fn wait_ns(&mut self, ns: u64) {
        self.script.push_back(Input::Wait(ns));
    }

    /// Presses and waits not yet played to their end.
    pub(crate) fn queued(&self) -> usize {
        self.script.len()
    }

    pub(crate) fn now_ns(&self) -> u64 {
        self.now_ns
    }

    /// `hal::Buttons::next_event`: the front press's event if it settles by `deadline_ns`, else a
    /// `Tick` at the deadline (or now, if the deadline has passed). Fails the test on the tick
    /// after `STALLED_TICKS` in a row that left the clock where it was.
    pub(crate) fn next_event(&mut self, deadline_ns: u64) -> Event {
        let before_ns = self.now_ns;
        let event = self.event(deadline_ns);
        match event {
            Event::Tick { now_ns } if now_ns == before_ns => {
                self.stalled += 1;
                assert!(
                    self.stalled <= STALLED_TICKS,
                    "the app asked for a tick at {deadline_ns} ns, already past, {} times in a \
                     row at {before_ns} ns: its deadline never moves",
                    self.stalled
                );
            }
            Event::Tick { .. } | Event::Key { .. } => self.stalled = 0,
        }
        event
    }

    fn event(&mut self, deadline_ns: u64) -> Event {
        loop {
            match self.script.front() {
                None => panic!("next_event with nothing left in the script"),
                Some(&Input::Press(key)) => {
                    let start_ns = match self.started_ns {
                        Some(start_ns) => start_ns,
                        None => self.start(key),
                    };
                    let due_ns = self.debouncer.due_ns().expect("a scripted press settles");
                    if due_ns > deadline_ns {
                        return self.tick(deadline_ns);
                    }
                    self.now_ns = self.now_ns.max(due_ns);
                    let event = self.debouncer.poll(self.now_ns);
                    let expected = Event::Key {
                        key,
                        at_ns: start_ns,
                    };
                    assert_eq!(
                        event,
                        Some(expected),
                        "the debouncer gives the scripted press"
                    );
                    self.script.pop_front();
                    self.started_ns = None;
                    return expected;
                }
                Some(&Input::Wait(ns)) => {
                    let until_ns = *self
                        .wait_until_ns
                        .get_or_insert(self.now_ns.saturating_add(ns));
                    if deadline_ns <= until_ns {
                        let tick = self.tick(deadline_ns);
                        if self.now_ns >= until_ns {
                            self.end_wait();
                        }
                        return tick;
                    }
                    // The wait ends before the deadline: the next input starts at its end, or,
                    // when the script ends with it, the call ends there.
                    self.now_ns = self.now_ns.max(until_ns);
                    self.end_wait();
                    if self.script.is_empty() {
                        return Event::Tick {
                            now_ns: self.now_ns,
                        };
                    }
                }
            }
        }
    }

    /// Feeds the press's whole edge train into the debouncer, starting now or once the last press
    /// has been released, and returns its start.
    fn start(&mut self, key: Key) -> u64 {
        let start_ns = self.now_ns.max(self.free_ns);
        for (ms, down) in PRESS_EDGES_MS {
            self.debouncer.edge(key, down, start_ns + ms * MS);
        }
        self.free_ns = start_ns + PRESS_SPAN_NS;
        self.started_ns = Some(start_ns);
        start_ns
    }

    fn tick(&mut self, deadline_ns: u64) -> Event {
        self.now_ns = self.now_ns.max(deadline_ns);
        Event::Tick {
            now_ns: self.now_ns,
        }
    }

    fn end_wait(&mut self) {
        self.script.pop_front();
        self.wait_until_ns = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn a_press_comes_24_ms_after_it_starts_with_its_first_edges_time() {
        let mut keys = Keys::new();
        keys.press(Key::Press);
        keys.press(Key::Press);
        keys.press(Key::Key3);
        assert_eq!(keys.queued(), 3);
        assert_eq!(
            keys.next_event(S),
            Event::Key {
                key: Key::Press,
                at_ns: 0
            }
        );
        assert_eq!(keys.now_ns(), 24 * MS);
        // The same key again: a new press only after the release, 150 ms after the first start.
        assert_eq!(
            keys.next_event(S),
            Event::Key {
                key: Key::Press,
                at_ns: 150 * MS
            }
        );
        assert_eq!(keys.now_ns(), 174 * MS);
        assert_eq!(
            keys.next_event(S),
            Event::Key {
                key: Key::Key3,
                at_ns: 300 * MS
            }
        );
        assert_eq!(keys.queued(), 0);
    }

    #[test]
    fn a_deadline_before_the_press_settles_is_a_tick_and_the_press_follows() {
        let mut keys = Keys::new();
        keys.press(Key::Up);
        assert_eq!(keys.next_event(10 * MS), Event::Tick { now_ns: 10 * MS });
        assert_eq!(keys.queued(), 1);
        assert_eq!(keys.next_event(23 * MS), Event::Tick { now_ns: 23 * MS });
        assert_eq!(
            keys.next_event(24 * MS),
            Event::Key {
                key: Key::Up,
                at_ns: 0
            }
        );
        // A deadline already past is a tick now: the clock never goes back.
        keys.press(Key::Down);
        assert_eq!(keys.next_event(5 * MS), Event::Tick { now_ns: 24 * MS });
        assert_eq!(
            keys.next_event(S),
            Event::Key {
                key: Key::Down,
                at_ns: 150 * MS
            }
        );
    }

    #[test]
    fn timers_fire_inside_a_wait_and_the_next_press_starts_at_its_end() {
        let mut keys = Keys::new();
        keys.wait_ns(31 * S);
        keys.press(Key::Key1);
        // The cover's deadline (30 s) falls inside the wait; the warning's (540 s) does not.
        assert_eq!(keys.next_event(30 * S), Event::Tick { now_ns: 30 * S });
        assert_eq!(keys.queued(), 2);
        assert_eq!(
            keys.next_event(540 * S),
            Event::Key {
                key: Key::Key1,
                at_ns: 31 * S
            }
        );
        assert_eq!(keys.now_ns(), 31 * S + 24 * MS);
        // A deadline at the wait's very end ends the wait with that tick.
        keys.wait_ns(10 * S);
        let end = keys.now_ns() + 10 * S;
        assert_eq!(keys.next_event(end), Event::Tick { now_ns: end });
        assert_eq!(keys.queued(), 0);
    }

    #[test]
    fn a_wait_that_ends_the_script_ends_with_a_tick_at_its_end() {
        let mut keys = Keys::new();
        keys.wait_ns(31 * S);
        // The next deadline (the warning's, 540 s) is past the wait: the call ends at 31 s.
        assert_eq!(keys.next_event(540 * S), Event::Tick { now_ns: 31 * S });
        assert_eq!(keys.queued(), 0);
        // With input after it, the wait is passed through to that input instead.
        keys.wait_ns(S);
        keys.press(Key::Press);
        assert_eq!(
            keys.next_event(540 * S),
            Event::Key {
                key: Key::Press,
                at_ns: 32 * S
            }
        );
    }

    #[test]
    #[should_panic(expected = "nothing left in the script")]
    fn next_event_with_an_empty_script_fails() {
        Keys::new().next_event(S);
    }

    #[test]
    fn a_few_ticks_in_a_row_may_leave_the_clock_where_it_is() {
        let mut keys = Keys::new();
        keys.press(Key::Up);
        assert_eq!(keys.next_event(10 * MS), Event::Tick { now_ns: 10 * MS });
        for _ in 0..STALLED_TICKS {
            assert_eq!(keys.next_event(5 * MS), Event::Tick { now_ns: 10 * MS });
        }
        // A tick that moves the clock starts the count again, and so does a key.
        assert_eq!(keys.next_event(11 * MS), Event::Tick { now_ns: 11 * MS });
        for _ in 0..STALLED_TICKS {
            assert_eq!(keys.next_event(11 * MS), Event::Tick { now_ns: 11 * MS });
        }
        assert_eq!(
            keys.next_event(S),
            Event::Key {
                key: Key::Up,
                at_ns: 0
            }
        );
        keys.press(Key::Down);
        for _ in 0..STALLED_TICKS {
            assert_eq!(keys.next_event(0), Event::Tick { now_ns: 24 * MS });
        }
    }

    #[test]
    #[should_panic(expected = "already past, 9 times in a row at 10000000 ns: its deadline never")]
    fn a_deadline_that_never_moves_fails_the_test() {
        let mut keys = Keys::new();
        keys.press(Key::Up);
        assert_eq!(keys.next_event(10 * MS), Event::Tick { now_ns: 10 * MS });
        for _ in 0..=STALLED_TICKS {
            keys.next_event(10 * MS);
        }
    }
}
