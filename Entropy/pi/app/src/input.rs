//! Button input and the idle timer (docs/pi-firmware.md "Buttons", "Protected screens and idle";
//! tasks/todo.md, M3 group 5, Q29 and Q32 (a)).
//!
//! - One press is one event: presses are debounced and nothing more, with no auto-repeat and no
//!   type-ahead filter.
//! - `Debouncer` is pure: raw edges and the time in, presses out. M4's GPIO driver reuses it, and
//!   the simulator runs every scripted press through it as a bounce train.
//! - `Idle` is pure too: the time of the last key in, and the step due on the current screen, and
//!   when the next one falls due, out. The app applies the step.
//! - Times are nanoseconds on one monotonic base (`CLOCK_MONOTONIC` on the device), the same as
//!   `hal::Clock::now_ns`. Subtractions saturate, so a timestamp from before the last one can
//!   never wrap into a huge idle time.

use std::collections::VecDeque;

use crate::screen::Class;

/// A press stable this long is a key event (pi-firmware.md "`hal::Buttons`": 20 ms debounce).
pub const DEBOUNCE_NS: u64 = 20_000_000;
/// A Protected screen is covered after 30 s without input (Q29).
pub const COVER_NS: u64 = 30_000_000_000;
/// The idle warning appears after 9 minutes without input while secrets are held (Q29).
pub const WARN_NS: u64 = 540_000_000_000;
/// The idle wipe after 10 minutes without input (pi-firmware.md "Process rules").
pub const WIPE_NS: u64 = 600_000_000_000;

listed_enum! {
/// The joystick's five inputs and the three keys of the Waveshare HAT, with their BCM pins
/// (pi-firmware.md, "Pin map used by the firmware").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Joystick up, BCM 6.
    Up,
    /// Joystick down, BCM 19.
    Down,
    /// Joystick left, BCM 5.
    Left,
    /// Joystick right, BCM 26.
    Right,
    /// Joystick press, BCM 13.
    Press,
    /// KEY1, BCM 21.
    Key1,
    /// KEY2, BCM 20.
    Key2,
    /// KEY3, BCM 16.
    Key3,
}
}

impl Key {
    /// The key's position in `Key::ALL`.
    pub const fn index(self) -> usize {
        match self {
            Key::Up => 0,
            Key::Down => 1,
            Key::Left => 2,
            Key::Right => 3,
            Key::Press => 4,
            Key::Key1 => 5,
            Key::Key2 => 6,
            Key::Key3 => 7,
        }
    }
}

/// What `hal::Buttons::next_event` returns: a debounced press, or the deadline passing with none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// One press of `key`; `at_ns` is the time of its first raw edge.
    Key { key: Key, at_ns: u64 },
    /// The deadline passed with no press; `now_ns` is the time it was noticed.
    Tick { now_ns: u64 },
}

/// One key's raw line, as `Debouncer` tracks it.
#[derive(Debug, Clone, Copy, Default)]
struct Line {
    /// The line's current level: true while the key is held.
    down: bool,
    /// The time of the line's last edge; `None` before the first.
    last_edge_ns: Option<u64>,
    /// The time of the first edge of the current press: kept through its bounces.
    first_edge_ns: u64,
    /// True once the current press became an event; a new press needs a stable release first.
    counted: bool,
}

impl Line {
    /// When the current press becomes (or became) stable, while it is down and not yet counted.
    fn stable_ns(&self) -> Option<u64> {
        match self.last_edge_ns {
            Some(last) if self.down && !self.counted => Some(last.saturating_add(DEBOUNCE_NS)),
            _ => None,
        }
    }
}

/// Turns raw edges into presses: one event per press, once the line has been held for
/// `DEBOUNCE_NS` with no further edge, carrying the press's first edge's timestamp.
///
/// - A release counts only after the line has stayed up for `DEBOUNCE_NS`; a shorter one is a
///   bounce of the same press, so it gives no second event.
/// - A press that never stays down for `DEBOUNCE_NS` gives no event.
/// - Keys are independent. A key held down gives one event, never a repeat.
/// - Events come out in the order their presses became stable, and none is lost to a later
///   edge: each edge first queues every press that became stable before it.
#[derive(Debug, Default)]
pub struct Debouncer {
    lines: [Line; Key::ALL.len()],
    /// Presses that became stable and were not yet polled, in that order, with that time.
    settled: VecDeque<(u64, Event)>,
}

impl Debouncer {
    /// A raw edge: `key`'s line went down (pressed) or up (released) at `at_ns`. Edges come in
    /// time order.
    pub fn edge(&mut self, key: Key, down: bool, at_ns: u64) {
        self.settle(at_ns);
        let line = &mut self.lines[key.index()];
        if down && !line.down {
            // A press edge after a stable release (or the first edge ever) starts a new press;
            // within `DEBOUNCE_NS` of the last edge it is a bounce of the current one.
            let stable_release = match line.last_edge_ns {
                Some(last) => at_ns.saturating_sub(last) >= DEBOUNCE_NS,
                None => true,
            };
            if stable_release {
                line.first_edge_ns = at_ns;
                line.counted = false;
            }
        }
        line.down = down;
        line.last_edge_ns = Some(at_ns);
    }

    /// The earliest time at which an event is or becomes due, if any: the driver waits until then
    /// (or for the next edge) before it polls.
    pub fn due_ns(&self) -> Option<u64> {
        let queued = self.settled.front().map(|&(stable_ns, _)| stable_ns);
        let pending = self.lines.iter().filter_map(Line::stable_ns).min();
        queued.into_iter().chain(pending).min()
    }

    /// The next press that became stable by `now_ns`, given once, or `None`. Call it until it
    /// gives `None` to drain every press due by then.
    pub fn poll(&mut self, now_ns: u64) -> Option<Event> {
        self.settle(now_ns);
        self.settled.pop_front().map(|(_, event)| event)
    }

    /// Queues every press that became stable by `now_ns`, in the order it did (ties in `Key::ALL`
    /// order).
    fn settle(&mut self, now_ns: u64) {
        loop {
            let earliest = self
                .lines
                .iter()
                .enumerate()
                .filter_map(|(index, line)| Some((line.stable_ns()?, index)))
                .filter(|&(stable_ns, _)| stable_ns <= now_ns)
                .min();
            let Some((stable_ns, index)) = earliest else {
                break;
            };
            let line = &mut self.lines[index];
            line.counted = true;
            let event = Event::Key {
                key: Key::ALL[index],
                at_ns: line.first_edge_ns,
            };
            self.settled.push_back((stable_ns, event));
        }
    }
}

/// What the idle timer asks of the app, in the order the thresholds fall (Q29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleStep {
    /// Cover the Protected screen; the next press only uncovers it.
    Cover,
    /// Warn that the wipe is a minute away; any key keeps everything.
    Warn,
    /// Wipe the session or the checked backup and clear the screen, say so and return Home.
    Wipe,
}

/// The time since the last key, against the cover, warning and wipe thresholds.
#[derive(Debug, Clone, Copy)]
pub struct Idle {
    last_key_ns: u64,
}

impl Idle {
    /// A timer that starts counting at `now_ns`.
    pub fn new(now_ns: u64) -> Self {
        Idle {
            last_key_ns: now_ns,
        }
    }

    /// Any key resets the timer.
    pub fn key(&mut self, at_ns: u64) {
        self.last_key_ns = at_ns;
    }

    /// The step due at `now_ns` on a screen of class `class` (a covered screen keeps its own),
    /// while the app `holds_secrets` (a session or a checked backup, `App::holds_secrets`), or
    /// `None`:
    /// - the wipe at `WIPE_NS`, on any screen while secrets are held, and on a Protected screen
    ///   with nothing held: collision-qr shows the destroyed seed's seal code from the kept
    ///   `Wiped`, which the stage does not hold, and the wipe takes it off the screen (the kept
    ///   `Wiped` stays). With neither, there is nothing to wipe;
    /// - the warning at `WARN_NS`, on any screen, only while secrets are held (pi-firmware.md,
    ///   "Protected screens and idle");
    /// - otherwise the cover at `COVER_NS`, on Protected screens only.
    pub fn step(&self, now_ns: u64, class: Class, holds_secrets: bool) -> Option<IdleStep> {
        let idle = now_ns.saturating_sub(self.last_key_ns);
        if (holds_secrets || class == Class::Protected) && idle >= WIPE_NS {
            Some(IdleStep::Wipe)
        } else if holds_secrets && idle >= WARN_NS {
            Some(IdleStep::Warn)
        } else if class == Class::Protected && idle >= COVER_NS {
            Some(IdleStep::Cover)
        } else {
            None
        }
    }

    /// The first threshold after `now_ns` at which `step` can give a later step than it gives at
    /// `now_ns`, on the same screen and with the same secrets held, or `None`: the deadline the app
    /// hands `hal::Buttons::next_event`.
    pub fn next_ns(&self, now_ns: u64, class: Class, holds_secrets: bool) -> Option<u64> {
        let protected = class == Class::Protected;
        [
            (COVER_NS, protected),
            (WARN_NS, holds_secrets),
            (WIPE_NS, holds_secrets || protected),
        ]
        .into_iter()
        .filter(|&(_, applies)| applies)
        .map(|(after, _)| self.last_key_ns.saturating_add(after))
        .find(|&at| at > now_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;
    const S: u64 = 1_000_000_000;

    /// Every event `poll` gives by `now_ns`, in order.
    fn drain(debouncer: &mut Debouncer, now_ns: u64) -> Vec<Event> {
        let mut events = Vec::new();
        while let Some(event) = debouncer.poll(now_ns) {
            events.push(event);
        }
        events
    }

    #[test]
    fn key_indices_follow_all() {
        for (index, key) in Key::ALL.into_iter().enumerate() {
            assert_eq!(key.index(), index);
        }
    }

    #[test]
    fn a_press_is_an_event_at_20_ms_and_not_at_19_999_ms() {
        let mut debouncer = Debouncer::default();
        debouncer.edge(Key::Press, true, 5 * S);
        assert_eq!(debouncer.due_ns(), Some(5 * S + 20 * MS));
        assert_eq!(debouncer.poll(5 * S + 19_999_999), None);
        assert_eq!(
            debouncer.poll(5 * S + 20 * MS),
            Some(Event::Key {
                key: Key::Press,
                at_ns: 5 * S
            })
        );
        // Held down: reported once, never repeated.
        assert_eq!(debouncer.due_ns(), None);
        assert_eq!(debouncer.poll(60 * S), None);
    }

    #[test]
    fn a_bounce_train_is_one_event_with_its_first_timestamp() {
        let mut debouncer = Debouncer::default();
        let t = 1_000 * MS;
        // Down, up, down, up, down within a few milliseconds, then held.
        for (at, down) in [(0, true), (2, false), (4, true), (6, false), (8, true)] {
            debouncer.edge(Key::Key1, down, t + at * MS);
            assert_eq!(debouncer.poll(t + at * MS), None);
        }
        // Stable 20 ms after the last edge (t + 8 ms), not after the first.
        assert_eq!(debouncer.poll(t + 27 * MS), None);
        assert_eq!(
            drain(&mut debouncer, t + 28 * MS),
            [Event::Key {
                key: Key::Key1,
                at_ns: t
            }]
        );
        // The release bounces too, then stays up: no event.
        debouncer.edge(Key::Key1, false, t + 100 * MS);
        debouncer.edge(Key::Key1, true, t + 101 * MS);
        debouncer.edge(Key::Key1, false, t + 102 * MS);
        assert!(drain(&mut debouncer, t + 200 * MS).is_empty());
        // The next press, after a stable release, is a new event with its own timestamp.
        debouncer.edge(Key::Key1, true, t + 300 * MS);
        assert_eq!(
            drain(&mut debouncer, t + 320 * MS),
            [Event::Key {
                key: Key::Key1,
                at_ns: t + 300 * MS
            }]
        );
    }

    #[test]
    fn a_release_shorter_than_20_ms_does_not_start_a_new_press() {
        let mut debouncer = Debouncer::default();
        debouncer.edge(Key::Up, true, 0);
        assert_eq!(drain(&mut debouncer, 20 * MS).len(), 1);
        // Up for 19.999 ms, then down again and held: the same press.
        debouncer.edge(Key::Up, false, 100 * MS);
        debouncer.edge(Key::Up, true, 100 * MS + 19_999_999);
        assert!(drain(&mut debouncer, 10 * S).is_empty());
        // Up for exactly 20 ms, then down: a new press.
        debouncer.edge(Key::Up, false, 11 * S);
        debouncer.edge(Key::Up, true, 11 * S + 20 * MS);
        assert_eq!(
            drain(&mut debouncer, 11 * S + 40 * MS),
            [Event::Key {
                key: Key::Up,
                at_ns: 11 * S + 20 * MS
            }]
        );
    }

    #[test]
    fn a_glitch_shorter_than_20_ms_is_no_event() {
        let mut debouncer = Debouncer::default();
        debouncer.edge(Key::Down, true, 0);
        debouncer.edge(Key::Down, false, 19_999_999);
        assert_eq!(debouncer.due_ns(), None);
        assert!(drain(&mut debouncer, 10 * S).is_empty());
    }

    #[test]
    fn keys_are_independent_and_keep_their_own_timestamps() {
        let mut debouncer = Debouncer::default();
        // Key2 bounces while Key3 is pressed and held; Key2 settles later.
        debouncer.edge(Key::Key2, true, 0);
        debouncer.edge(Key::Key3, true, MS);
        debouncer.edge(Key::Key2, false, 2 * MS);
        debouncer.edge(Key::Key2, true, 15 * MS);
        assert_eq!(debouncer.due_ns(), Some(21 * MS));
        assert_eq!(
            drain(&mut debouncer, 21 * MS),
            [Event::Key {
                key: Key::Key3,
                at_ns: MS
            }]
        );
        assert_eq!(
            drain(&mut debouncer, 35 * MS),
            [Event::Key {
                key: Key::Key2,
                at_ns: 0
            }]
        );
        // Two presses due by the same poll come out in the order they became stable.
        let mut debouncer = Debouncer::default();
        debouncer.edge(Key::Right, true, 5 * MS);
        debouncer.edge(Key::Left, true, 6 * MS);
        assert_eq!(
            drain(&mut debouncer, S),
            [
                Event::Key {
                    key: Key::Right,
                    at_ns: 5 * MS
                },
                Event::Key {
                    key: Key::Left,
                    at_ns: 6 * MS
                },
            ]
        );
    }

    #[test]
    fn a_press_that_settled_before_its_release_is_kept_without_a_poll_between() {
        let mut debouncer = Debouncer::default();
        // Press, release after 50 ms, press again after a stable release, all before any poll.
        debouncer.edge(Key::Press, true, 0);
        debouncer.edge(Key::Press, false, 50 * MS);
        debouncer.edge(Key::Press, true, 100 * MS);
        assert_eq!(debouncer.due_ns(), Some(20 * MS));
        assert_eq!(
            drain(&mut debouncer, S),
            [
                Event::Key {
                    key: Key::Press,
                    at_ns: 0
                },
                Event::Key {
                    key: Key::Press,
                    at_ns: 100 * MS
                },
            ]
        );
        // Two keys settled before one key's release come out in the order they settled.
        let mut debouncer = Debouncer::default();
        debouncer.edge(Key::Key2, true, 0);
        debouncer.edge(Key::Key1, true, 5 * MS);
        debouncer.edge(Key::Key1, false, 30 * MS);
        debouncer.edge(Key::Key2, false, 31 * MS);
        assert_eq!(
            drain(&mut debouncer, 40 * MS),
            [
                Event::Key {
                    key: Key::Key2,
                    at_ns: 0
                },
                Event::Key {
                    key: Key::Key1,
                    at_ns: 5 * MS
                },
            ]
        );
    }

    #[test]
    fn every_key_debounces() {
        for key in Key::ALL {
            let mut debouncer = Debouncer::default();
            debouncer.edge(key, true, S);
            debouncer.edge(key, false, S + MS);
            debouncer.edge(key, true, S + 3 * MS);
            assert_eq!(debouncer.poll(S + 22 * MS), None);
            assert_eq!(
                drain(&mut debouncer, S + 23 * MS),
                [Event::Key { key, at_ns: S }]
            );
        }
    }

    #[test]
    fn idle_thresholds() {
        let start = 7 * S;
        let mut idle = Idle::new(start);
        let at = |seconds: u64| start + seconds * S;
        // A Protected screen with a session held: cover, warning, wipe.
        let protected = |idle: &Idle, now| idle.step(now, Class::Protected, true);
        assert_eq!(protected(&idle, at(30) - 1), None);
        assert_eq!(protected(&idle, at(30)), Some(IdleStep::Cover));
        assert_eq!(protected(&idle, at(540) - 1), Some(IdleStep::Cover));
        assert_eq!(protected(&idle, at(540)), Some(IdleStep::Warn));
        assert_eq!(protected(&idle, at(600) - 1), Some(IdleStep::Warn));
        assert_eq!(protected(&idle, at(600)), Some(IdleStep::Wipe));
        // A Public screen is never covered; the warning and the wipe come only while secrets are
        // held.
        assert_eq!(idle.step(at(539), Class::Public, true), None);
        assert_eq!(
            idle.step(at(540), Class::Public, true),
            Some(IdleStep::Warn)
        );
        assert_eq!(
            idle.step(at(600), Class::Public, true),
            Some(IdleStep::Wipe)
        );
        assert_eq!(idle.step(at(6_000), Class::Public, false), None);
        // A Protected screen with nothing held (collision-qr: its seal code is the kept
        // `Wiped`'s) is covered and, with no warning, wiped at 600 s.
        let shown_only = |idle: &Idle, now| idle.step(now, Class::Protected, false);
        assert_eq!(shown_only(&idle, at(30) - 1), None);
        assert_eq!(shown_only(&idle, at(30)), Some(IdleStep::Cover));
        assert_eq!(shown_only(&idle, at(540)), Some(IdleStep::Cover));
        assert_eq!(shown_only(&idle, at(600) - 1), Some(IdleStep::Cover));
        assert_eq!(shown_only(&idle, at(600)), Some(IdleStep::Wipe));
        assert_eq!(shown_only(&idle, at(6_000)), Some(IdleStep::Wipe));
        // Any key resets it.
        idle.key(at(599));
        assert_eq!(protected(&idle, at(600)), None);
        assert_eq!(protected(&idle, at(629) - 1), None);
        assert_eq!(protected(&idle, at(629)), Some(IdleStep::Cover));
        assert_eq!(protected(&idle, at(599 + 600) - 1), Some(IdleStep::Warn));
        assert_eq!(protected(&idle, at(599 + 600)), Some(IdleStep::Wipe));
        // A time before the last key is no idle time at all.
        assert_eq!(protected(&idle, at(1)), None);
    }

    #[test]
    fn the_next_deadline_is_the_next_threshold_that_applies() {
        let start = 7 * S;
        let idle = Idle::new(start);
        let at = |seconds: u64| start + seconds * S;
        // A Protected screen with a session held: the cover, the warning, the wipe, then none.
        let protected = |now| idle.next_ns(now, Class::Protected, true);
        assert_eq!(protected(start), Some(at(30)));
        assert_eq!(protected(at(30) - 1), Some(at(30)));
        assert_eq!(protected(at(30)), Some(at(540)));
        assert_eq!(protected(at(540)), Some(at(600)));
        assert_eq!(protected(at(600)), None);
        // A Public screen: the warning and the wipe only while secrets are held.
        assert_eq!(idle.next_ns(start, Class::Public, true), Some(at(540)));
        assert_eq!(idle.next_ns(at(540), Class::Public, true), Some(at(600)));
        assert_eq!(idle.next_ns(start, Class::Public, false), None);
        // A Protected screen with nothing held: the cover, then the wipe, with no warning.
        assert_eq!(idle.next_ns(at(30), Class::Protected, false), Some(at(600)));
        // Each deadline is where `step` changes.
        for (class, holds) in [
            (Class::Protected, true),
            (Class::Protected, false),
            (Class::Public, true),
        ] {
            let mut now = start;
            while let Some(next) = idle.next_ns(now, class, holds) {
                assert_ne!(
                    idle.step(next - 1, class, holds),
                    idle.step(next, class, holds)
                );
                now = next;
            }
            assert_eq!(idle.step(now, class, holds), Some(IdleStep::Wipe));
        }
    }
}
