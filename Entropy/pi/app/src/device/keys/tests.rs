//! The key loop's tests (tasks/todo.md, M4 group 6), on a scripted edge source and a clock that
//! moves only while the loop waits: a bounce train, a held key, the time a press carries, the
//! deadline (ahead, already past, `u64::MAX`), the waits, conversions out of range, a fault of the
//! edge source, a lost edge, and edges queued while the device was busy.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use super::*;

const S: u64 = 1_000_000_000;

/// The waits the loop asked of the source, zero timeouts (taking queued edges) left out.
type Waits = Rc<RefCell<Vec<Option<Duration>>>>;

/// The clock the loop and its source share.
struct TestClock(Rc<Cell<u64>>);

impl Clock for TestClock {
    fn now_ns(&self) -> u64 {
        self.0.get()
    }
}

/// An edge the source gives once the clock reaches `ready_ns`: its stamp for a live edge, earlier
/// for one the kernel queued while the device was busy.
struct Queued {
    ready_ns: u64,
    edge: Edge,
}

/// Gives its edges in script order, each once it is ready. A wait that ends with no edge moves the
/// clock to its end; one with no timeout and no edge left would never end, which fails the test.
struct Script {
    edges: VecDeque<Queued>,
    clock: Rc<Cell<u64>>,
    waits: Waits,
    /// The calls made so far, zero timeouts included.
    calls: usize,
    /// The call, counted from 0, that fails with `Buttons`, as a GPIO fault would.
    fail_at: Option<usize>,
}

impl EdgeSource for Script {
    fn next_edge(&mut self, timeout: Option<Duration>) -> Result<Option<Edge>, HalError> {
        let now_ns = self.clock.get();
        if timeout != Some(Duration::ZERO) {
            self.waits.borrow_mut().push(timeout);
        }
        let call = self.calls;
        self.calls += 1;
        if self.fail_at == Some(call) {
            return Err(HalError::Buttons);
        }
        let until_ns = match timeout {
            Some(timeout) => now_ns + u64::try_from(timeout.as_nanos()).expect("a test timeout"),
            None => u64::MAX,
        };
        match self.edges.front() {
            Some(queued) if queued.ready_ns <= until_ns => {
                self.clock.set(now_ns.max(queued.ready_ns));
                Ok(self.edges.pop_front().map(|queued| queued.edge))
            }
            _ => {
                assert_ne!(
                    until_ns,
                    u64::MAX,
                    "a wait with no timeout and no edge left"
                );
                self.clock.set(until_ns);
                Ok(None)
            }
        }
    }
}

/// `key`'s line falling (`down`) or rising at `at_ns`.
fn edge(key: Key, down: bool, at_ns: u64) -> Edge {
    Edge {
        pin: key.bcm_pin(),
        falling: down,
        timestamp: Duration::from_nanos(at_ns),
    }
}

/// Edges that arrive as the kernel stamps them.
fn live(edges: &[(Key, bool, u64)]) -> Vec<Queued> {
    edges
        .iter()
        .map(|&(key, down, at_ns)| Queued {
            ready_ns: at_ns,
            edge: edge(key, down, at_ns),
        })
        .collect()
}

/// Edges the kernel queued while the device was busy: all ready from the start, in this order.
fn busy(edges: &[(Key, bool, u64)]) -> Vec<Queued> {
    edges
        .iter()
        .map(|&(key, down, at_ns)| Queued {
            ready_ns: 0,
            edge: edge(key, down, at_ns),
        })
        .collect()
}

/// A key loop whose clock reads `now_ns`, over `edges`; the clock and the waits it asks for.
fn start(now_ns: u64, edges: Vec<Queued>) -> (KeyLoop<Script, TestClock>, Rc<Cell<u64>>, Waits) {
    let clock = Rc::new(Cell::new(now_ns));
    let waits = Waits::default();
    let script = Script {
        edges: edges.into(),
        clock: Rc::clone(&clock),
        waits: Rc::clone(&waits),
        calls: 0,
        fail_at: None,
    };
    (
        KeyLoop::new(script, TestClock(Rc::clone(&clock))),
        clock,
        waits,
    )
}

/// Every event up to the first `Tick` at `deadline_ns`, the tick left out.
fn presses(keys: &mut KeyLoop<Script, TestClock>, deadline_ns: u64) -> Vec<Event> {
    let mut events = Vec::new();
    loop {
        match keys.next_event(deadline_ns) {
            Ok(Event::Tick { .. }) => return events,
            Ok(event) => events.push(event),
            Err(fault) => panic!("{fault}"),
        }
    }
}

fn press(key: Key, at_ns: u64) -> Event {
    Event::Key { key, at_ns }
}

/// Down, up, down, up, down within 4 ms, then held: one press, 20 ms after the last edge, at the
/// first edge's time.
#[test]
fn a_bounce_train_is_one_press_carrying_its_first_edges_time() {
    let t = S;
    let (mut keys, clock, _) = start(
        0,
        live(&[
            (Key::Key1, true, t),
            (Key::Key1, false, t + MS),
            (Key::Key1, true, t + 2 * MS),
            (Key::Key1, false, t + 3 * MS),
            (Key::Key1, true, t + 4 * MS),
        ]),
    );
    assert_eq!(keys.next_event(u64::MAX), Ok(press(Key::Key1, t)));
    assert_eq!(clock.get(), t + 24 * MS);
    assert_eq!(keys.next_event(10 * S), Ok(Event::Tick { now_ns: 10 * S }));
}

/// One press however long it is held; its bouncing release is no press either; the next press
/// after a stable release is a new one.
#[test]
fn a_held_key_never_repeats() {
    let (mut keys, _, _) = start(
        0,
        live(&[
            (Key::Press, true, S),
            (Key::Press, false, 61 * S),
            (Key::Press, true, 61 * S + MS),
            (Key::Press, false, 61 * S + 2 * MS),
            (Key::Press, true, 62 * S),
        ]),
    );
    assert_eq!(keys.next_event(u64::MAX), Ok(press(Key::Press, S)));
    assert_eq!(keys.next_event(60 * S), Ok(Event::Tick { now_ns: 60 * S }));
    assert_eq!(
        keys.next_event(61 * S + 500 * MS),
        Ok(Event::Tick {
            now_ns: 61 * S + 500 * MS
        })
    );
    assert_eq!(presses(&mut keys, 70 * S), [press(Key::Press, 62 * S)]);
}

/// With no press, the loop waits until the deadline and ticks there. With one pending, it waits
/// until the earlier of the deadline and the press's due time.
#[test]
fn a_tick_comes_at_the_deadline_and_the_wait_ends_at_the_earlier_of_it_and_a_due_press() {
    let (mut keys, clock, waits) = start(S, Vec::new());
    assert_eq!(keys.next_event(5 * S), Ok(Event::Tick { now_ns: 5 * S }));
    assert_eq!(*waits.borrow(), [Some(Duration::from_secs(4))]);
    assert_eq!(clock.get(), 5 * S);

    // A press due at 1.020 s, a deadline at 1.010 s: the tick first, then the press.
    let (mut keys, _, waits) = start(S, live(&[(Key::Key2, true, S)]));
    assert_eq!(
        keys.next_event(S + 10 * MS),
        Ok(Event::Tick {
            now_ns: S + 10 * MS
        })
    );
    assert_eq!(keys.next_event(10 * S), Ok(press(Key::Key2, S)));
    assert_eq!(
        *waits.borrow(),
        [
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(10))
        ]
    );

    // The same press with a deadline at 10 s: the wait ends when it is due.
    let (mut keys, clock, waits) = start(S, live(&[(Key::Key2, true, S)]));
    assert_eq!(keys.next_event(10 * S), Ok(press(Key::Key2, S)));
    assert_eq!(*waits.borrow(), [Some(Duration::from_millis(20))]);
    assert_eq!(clock.get(), S + 20 * MS);
}

/// A deadline already past ticks at once, at the time read, with no wait. A press that settled by
/// that deadline still comes first; one that settled after it comes on a later call.
#[test]
fn a_deadline_already_past_ticks_at_once_after_presses_that_settled_by_it() {
    let (mut keys, clock, waits) = start(10 * S, Vec::new());
    assert_eq!(keys.next_event(5 * S), Ok(Event::Tick { now_ns: 10 * S }));
    assert!(waits.borrow().is_empty());
    assert_eq!(clock.get(), 10 * S);

    let (mut keys, _, waits) = start(
        10 * S,
        busy(&[(Key::Key3, true, S), (Key::Left, true, 6 * S)]),
    );
    assert_eq!(keys.next_event(5 * S), Ok(press(Key::Key3, S)));
    assert_eq!(keys.next_event(5 * S), Ok(Event::Tick { now_ns: 10 * S }));
    assert_eq!(keys.next_event(20 * S), Ok(press(Key::Left, 6 * S)));
    assert!(waits.borrow().is_empty());
}

/// `u64::MAX` with no press pending waits with no timeout; once a press is pending, until it is
/// due.
#[test]
fn u64_max_waits_with_no_timeout() {
    let (mut keys, clock, waits) = start(0, live(&[(Key::Up, true, 3 * S)]));
    assert_eq!(keys.next_event(u64::MAX), Ok(press(Key::Up, 3 * S)));
    assert_eq!(*waits.borrow(), [None, Some(Duration::from_millis(20))]);
    assert_eq!(clock.get(), 3 * S + 20 * MS);
}

/// Waits are whole milliseconds, rounded up, so the loop never spins on a wait that a
/// millisecond source would truncate to zero; and at most a day, which an `i32` of milliseconds
/// holds.
#[test]
fn waits_are_whole_milliseconds_rounded_up_and_at_most_a_day() {
    assert_eq!(wait(0, u64::MAX), None);
    assert_eq!(wait(5, u64::MAX), None);
    assert_eq!(wait(0, 1), Some(Duration::from_millis(1)));
    assert_eq!(wait(0, MS), Some(Duration::from_millis(1)));
    assert_eq!(wait(0, MS + 1), Some(Duration::from_millis(2)));
    assert_eq!(wait(7, 7), Some(Duration::ZERO));
    assert_eq!(wait(10, 5), Some(Duration::ZERO));
    assert_eq!(wait(0, u64::MAX - 1), Some(Duration::from_secs(86_400)));
    assert!(MAX_WAIT_MS <= u64::try_from(i32::MAX).expect("i32::MAX"));

    // Half a millisecond in, a deadline at 2 ms: one wait of 2 ms, and the tick 0.5 ms late.
    let (mut keys, _, waits) = start(MS / 2, Vec::new());
    assert_eq!(
        keys.next_event(2 * MS),
        Ok(Event::Tick {
            now_ns: 2 * MS + MS / 2
        })
    );
    assert_eq!(*waits.borrow(), [Some(Duration::from_millis(2))]);

    // A deadline 584 years away: day-long waits until an edge comes.
    let day = 86_400 * S;
    let (mut keys, _, waits) = start(0, live(&[(Key::Down, true, day + day / 2)]));
    assert_eq!(
        keys.next_event(u64::MAX - 1),
        Ok(press(Key::Down, day + day / 2))
    );
    assert_eq!(
        *waits.borrow(),
        [
            Some(Duration::from_secs(86_400)),
            Some(Duration::from_secs(86_400)),
            Some(Duration::from_millis(20))
        ]
    );
}

/// An edge time past `u64::MAX` nanoseconds, or a pin that is no key's, is a button fault; the
/// clock's readings convert exactly or not at all, and `clock_ns` panics on one that does not.
#[test]
fn times_out_of_range_and_unknown_pins_are_refused() {
    let longest = Duration::from_nanos(u64::MAX);
    let mut at_max = edge(Key::Up, true, 0);
    at_max.timestamp = longest;
    assert_eq!(key_edge(at_max), Ok((u64::MAX, Key::Up, true)));
    let mut past = at_max;
    past.timestamp = longest + Duration::from_nanos(1);
    assert_eq!(key_edge(past), Err(HalError::Buttons));
    // Pin 4 is no key's.
    let stray = Edge {
        pin: 4,
        falling: true,
        timestamp: Duration::ZERO,
    };
    assert_eq!(key_edge(stray), Err(HalError::Buttons));
    for refused in [past, stray] {
        let queued = Queued {
            ready_ns: 0,
            edge: refused,
        };
        let (mut keys, _, _) = start(0, vec![queued]);
        assert_eq!(keys.next_event(S), Err(HalError::Buttons));
    }
    // The eight keys' pins map back to their keys.
    for key in Key::ALL {
        assert_eq!(key_edge(edge(key, false, 9)), Ok((9, key, false)));
    }

    assert_eq!(timespec_ns(0i64, 0i64), Some(0));
    assert_eq!(timespec_ns(1i64, 5i64), Some(S + 5));
    assert_eq!(timespec_ns(2i32, 999_999_999i32), Some(3 * S - 1));
    assert_eq!(
        timespec_ns(18_446_744_073i64, 709_551_615i64),
        Some(u64::MAX)
    );
    assert_eq!(timespec_ns(18_446_744_073i64, 709_551_616i64), None);
    assert_eq!(timespec_ns(18_446_744_074i64, 0i64), None);
    assert_eq!(timespec_ns(i64::MAX, 0i64), None);
    assert_eq!(timespec_ns(-1i64, 0i64), None);
    assert_eq!(timespec_ns(0i32, -1i32), None);
    assert_eq!(timespec_ns(0i64, 1_000_000_000i64), None);
    assert_eq!(clock_ns(4i32, 2i32), 4 * S + 2);
}

#[test]
#[should_panic(expected = "the monotonic clock is out of range")]
fn a_clock_reading_out_of_range_panics() {
    clock_ns(-1i64, 0i64);
}

/// A fault of the edge source (a GPIO error on the device) comes back from the loop unchanged,
/// whether it meets the drain of queued edges or a wait: `Buttons`, which halts (rule 3).
#[test]
fn an_edge_source_fault_is_the_loops_fault() {
    // With nothing queued, call 0 is the drain and call 1 the wait.
    for call in [0, 1] {
        let (mut keys, _, waits) = start(0, Vec::new());
        keys.edges.fail_at = Some(call);
        assert_eq!(keys.next_event(S), Err(HalError::Buttons), "call {call}");
        assert_eq!(waits.borrow().len(), call, "call {call}");
    }
    assert!(HalError::Buttons.halts());
}

/// Three presses of the joystick, with edges lost (the kernel dropped them from a full queue; their
/// `seqno` would show the gap): whichever are lost, only the second press is, and KEY1, pressed
/// meanwhile, is not touched.
#[test]
fn a_lost_edge_costs_at_most_the_next_press_of_that_key() {
    let edges = [
        (Key::Press, true, 0),
        (Key::Press, false, 100 * MS),
        (Key::Press, true, 300 * MS),
        (Key::Key1, true, 350 * MS),
        (Key::Press, false, 400 * MS),
        (Key::Key1, false, 450 * MS),
        (Key::Press, true, 600 * MS),
        (Key::Press, false, 700 * MS),
    ];
    // All arrive: three presses of the joystick and one of KEY1.
    let (mut keys, _, _) = start(0, live(&edges));
    assert_eq!(
        presses(&mut keys, 2 * S),
        [
            press(Key::Press, 0),
            press(Key::Press, 300 * MS),
            press(Key::Key1, 350 * MS),
            press(Key::Press, 600 * MS)
        ]
    );
    // The first release lost; the second press lost; both, the line's two edges between.
    for lost in [&[1][..], &[2], &[1, 2]] {
        let kept: Vec<(Key, bool, u64)> = (0..edges.len())
            .filter(|i| !lost.contains(i))
            .map(|i| edges[i])
            .collect();
        let (mut keys, _, _) = start(0, live(&kept));
        assert_eq!(
            presses(&mut keys, 2 * S),
            [
                press(Key::Press, 0),
                press(Key::Key1, 350 * MS),
                press(Key::Press, 600 * MS)
            ],
            "edges {lost:?} lost"
        );
    }
}

/// Edges the kernel queued while the device was busy, taken in only at 1 s: a press held 30 ms
/// counts, at its first edge's time; a glitch of 5 ms does not, nor one of 15 ms whose release
/// rppal gives after another line's later one.
#[test]
fn edges_queued_while_the_device_was_busy_are_judged_together_in_time_order() {
    let (mut keys, _, _) = start(
        S,
        busy(&[
            (Key::Key3, true, 100 * MS),
            (Key::Key3, false, 101 * MS),
            (Key::Key3, true, 102 * MS),
            (Key::Key3, false, 300 * MS),
        ]),
    );
    assert_eq!(presses(&mut keys, 2 * S), [press(Key::Key3, 100 * MS)]);

    // Down at 100 ms, up at 105 ms: both were queued before the loop looked.
    let (mut keys, _, _) = start(
        S,
        busy(&[(Key::Key2, true, 100 * MS), (Key::Key2, false, 105 * MS)]),
    );
    assert!(presses(&mut keys, 2 * S).is_empty());

    // rppal's order, one queued edge of each ready line in turn: Down held 30 ms, Up held 15 ms.
    let (mut keys, _, _) = start(
        S,
        busy(&[
            (Key::Down, true, 0),
            (Key::Up, true, 0),
            (Key::Down, false, 30 * MS),
            (Key::Up, false, 15 * MS),
        ]),
    );
    assert_eq!(presses(&mut keys, 2 * S), [press(Key::Down, 0)]);
}
