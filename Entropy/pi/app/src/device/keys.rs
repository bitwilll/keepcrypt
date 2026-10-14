//! The keys and the clock (docs/pi-firmware.md "`hal::Buttons`"; tasks/todo.md, M4 group 6).
//!
//! - Pure: `KeyLoop` implements `hal::Buttons` over an `EdgeSource` (the key lines' raw edges with
//!   the kernel's timestamps) and a `hal::Clock`, which group 10's Linux glue implements over rppal
//!   and nix and the tests script. It does no I/O of its own.
//! - Each edge goes into the app's `input::Debouncer`, the one the simulator runs every press
//!   through, at the kernel's `CLOCK_MONOTONIC` timestamp. The keys switch to ground, so a falling
//!   edge means down; `Key::bcm_pin` names each key's line.
//! - The kernel queues edges while the device is busy (Q39 (a)). Before it judges a press, the
//!   loop takes in every edge already queued and gives them to the debouncer in time order, as the
//!   debouncer requires, so a glitch that came and went while the device was busy is no press.
//! - A lost edge (a full kernel queue drops one, which shows as a `seqno` gap) needs no handling:
//!   each edge carries its line's new level, so the debouncer is right again at that line's next
//!   edge, and the loss costs at most that key's next press.
//! - Times are u64 nanoseconds, converted with checks: an edge's time that does not fit is
//!   `HalError::Buttons`, and a clock reading that does not fit panics (`clock_ns`).

use std::time::Duration;

use keepcrypt_pi::hal::{Buttons, Clock, HalError};
use keepcrypt_pi::input::{Debouncer, Event, Key};

#[cfg(test)]
mod tests;

/// Nanoseconds in a millisecond.
const MS: u64 = 1_000_000;
/// Nanoseconds in a second.
const NS_PER_S: u64 = 1_000_000_000;
/// The longest single wait, a day: rppal hands epoll its timeout as an `i32` of milliseconds,
/// which a wait of about 25 days or more would wrap, possibly into no timeout at all. The loop then
/// waits again.
const MAX_WAIT_MS: u64 = 86_400_000;

/// One raw edge on a key's line, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    /// The line's BCM pin.
    pub pin: u8,
    /// True for a falling edge.
    pub falling: bool,
    /// The kernel's `CLOCK_MONOTONIC` timestamp of the edge.
    pub timestamp: Duration,
}

/// The key lines' edges. Group 10's Linux glue implements it over rppal's
/// `Gpio::poll_interrupts`, which waits in the caller's thread; the tests script it.
pub trait EdgeSource {
    /// The next edge on any key's line, waiting at most `timeout` for one (`None`: no limit), or
    /// `None` once `timeout` passes with none; a zero `timeout` takes only an edge already queued.
    /// Each line's edges come in their order, but not always in time order with another line's:
    /// rppal takes one queued edge from each ready line in turn.
    fn next_edge(&mut self, timeout: Option<Duration>) -> Result<Option<Edge>, HalError>;
}

/// `hal::Buttons` on the device: the key lines' edges through the debouncer, and a `Tick` once the
/// deadline passes.
pub struct KeyLoop<E: EdgeSource, C: Clock> {
    edges: E,
    clock: C,
    debouncer: Debouncer,
    /// Edges taken in and not yet given to the debouncer: each one's time in nanoseconds, its key,
    /// and true for down.
    queued: Vec<(u64, Key, bool)>,
}

impl<E: EdgeSource, C: Clock> KeyLoop<E, C> {
    pub fn new(edges: E, clock: C) -> Self {
        KeyLoop {
            edges,
            clock,
            debouncer: Debouncer::default(),
            queued: Vec::new(),
        }
    }

    /// Takes in every edge the source already holds, then gives the debouncer every edge taken in,
    /// in time order: the debouncer settles all the lines at each edge's time, so one line's later
    /// edge must not come before another line's earlier one. The sort is stable, so a line's edges
    /// keep their order where two times are equal.
    fn take_queued(&mut self) -> Result<(), HalError> {
        while let Some(edge) = self.edges.next_edge(Some(Duration::ZERO))? {
            self.queued.push(key_edge(edge)?);
        }
        self.queued.sort_by_key(|&(at_ns, _, _)| at_ns);
        for (at_ns, key, down) in self.queued.drain(..) {
            self.debouncer.edge(key, down, at_ns);
        }
        Ok(())
    }
}

impl<E: EdgeSource, C: Clock> Buttons for KeyLoop<E, C> {
    /// The next press that settled by `deadline_ns`, in the order presses settle, else a `Tick`
    /// once the deadline has passed; a press that settled after the deadline comes on a later
    /// call, as in the simulator. Until then it waits for the next edge, at most until the earlier
    /// of the deadline and the debouncer's next due time; with `u64::MAX` and no press pending it
    /// waits with no timeout.
    fn next_event(&mut self, deadline_ns: u64) -> Result<Event, HalError> {
        loop {
            // The time first, then every edge already queued: each press is judged at `now_ns`
            // with every edge the kernel stamped before it.
            let now_ns = self.clock.now_ns();
            self.take_queued()?;
            let by_ns = now_ns.min(deadline_ns);
            let due = self.debouncer.due_ns();
            if let Some(due_ns) = due
                && due_ns <= by_ns
                && let Some(event) = self.debouncer.poll(by_ns)
            {
                return Ok(event);
            }
            if now_ns >= deadline_ns {
                return Ok(Event::Tick { now_ns });
            }
            let until_ns = match due {
                Some(due_ns) => due_ns.min(deadline_ns),
                None => deadline_ns,
            };
            if let Some(edge) = self.edges.next_edge(wait(now_ns, until_ns))? {
                self.queued.push(key_edge(edge)?);
            }
        }
    }
}

/// `edge` as the debouncer takes it: its time in nanoseconds, its key, and true for down, which is
/// a falling edge, since the keys switch to ground. A pin that is no key's, or a time past
/// `u64::MAX` nanoseconds, is `Buttons`.
fn key_edge(edge: Edge) -> Result<(u64, Key, bool), HalError> {
    let key = Key::ALL.into_iter().find(|key| key.bcm_pin() == edge.pin);
    match (key, u64::try_from(edge.timestamp.as_nanos())) {
        (Some(key), Ok(at_ns)) => Ok((at_ns, key, edge.falling)),
        _ => Err(HalError::Buttons),
    }
}

/// The wait from `now_ns` until `until_ns`: none at `u64::MAX`, which means no deadline and no
/// press pending. Otherwise it is rounded up to whole milliseconds, epoll's unit, to which rppal
/// truncates, so that a wait of under a millisecond is not a spin; and at most `MAX_WAIT_MS`.
fn wait(now_ns: u64, until_ns: u64) -> Option<Duration> {
    (until_ns != u64::MAX).then(|| {
        let ms = until_ns.saturating_sub(now_ns).div_ceil(MS);
        Duration::from_millis(ms.min(MAX_WAIT_MS))
    })
}

/// A `CLOCK_MONOTONIC` reading, `(tv_sec, tv_nsec)` as `clock_gettime` gives it, in nanoseconds:
/// the device's `hal::Clock::now_ns` (group 10), on the base of the edges' timestamps. `now_ns`
/// returns no `Result`, so a reading that `timespec_ns` refuses panics, with fixed text, and the
/// panic ends in stop mode (Q35).
pub fn clock_ns<S, N>(tv_sec: S, tv_nsec: N) -> u64
where
    u64: TryFrom<S> + TryFrom<N>,
{
    match timespec_ns(tv_sec, tv_nsec) {
        Some(ns) => ns,
        None => panic!("the monotonic clock is out of range"),
    }
}

/// `(tv_sec, tv_nsec)` in nanoseconds, or `None` for a reading that is no time (a negative field,
/// or `tv_nsec` of a second or more) or that passes `u64::MAX` nanoseconds (584 years). Either
/// field may be any integer type: `time_t` and `c_long` are 32 bits on the Pi and 64 on x86_64.
fn timespec_ns<S, N>(tv_sec: S, tv_nsec: N) -> Option<u64>
where
    u64: TryFrom<S> + TryFrom<N>,
{
    match (u64::try_from(tv_sec), u64::try_from(tv_nsec)) {
        (Ok(sec), Ok(nsec)) if nsec < NS_PER_S => sec
            .checked_mul(NS_PER_S)
            .and_then(|ns| ns.checked_add(nsec)),
        _ => None,
    }
}
