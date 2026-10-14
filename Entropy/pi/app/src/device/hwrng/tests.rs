//! The hwrng reader's tests (tasks/todo.md, M4 group 7, Q39 (c)), on a scripted device and a clock
//! that moves only while the reader sleeps: a block arriving in pieces, straight into place and
//! nothing past it; reads that find nothing, until and past the deadline; end of file; interrupted
//! reads; other errors.

use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;

use super::*;

const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;

/// What one read gives, in script order.
#[derive(Clone, Copy)]
enum Read {
    /// Up to this many bytes of the stream, as many as were asked for at most; 0 is end of file.
    Bytes(usize),
    /// This error.
    Fail(ErrorKind),
    /// One byte more than was asked for, as no sound device would.
    TooMany,
}

/// The clock the reader and the device share.
struct TestClock(Rc<Cell<u64>>);

impl Clock for TestClock {
    fn now_ns(&self) -> u64 {
        self.0.get()
    }
}

/// A device that serves the stream 0, 1, 2, … (mod 256) as its script says, then finds nothing
/// yet (`WouldBlock`) forever, as a stalled hwrng would. Each sleep moves the clock.
struct Device {
    script: VecDeque<Read>,
    /// The stream's bytes served so far.
    served: usize,
    /// The bytes each read asked for, in order.
    asked: Vec<usize>,
    sleeps: u32,
    clock: Rc<Cell<u64>>,
}

impl RawRead for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.asked.push(buf.len());
        match self.script.pop_front() {
            Some(Read::Bytes(count)) => {
                let count = count.min(buf.len());
                for (offset, byte) in buf[..count].iter_mut().enumerate() {
                    *byte = (self.served + offset).to_le_bytes()[0];
                }
                self.served += count;
                Ok(count)
            }
            Some(Read::Fail(kind)) => Err(kind.into()),
            Some(Read::TooMany) => Ok(buf.len() + 1),
            None => Err(ErrorKind::WouldBlock.into()),
        }
    }

    fn sleep_ms(&mut self, ms: u16) {
        self.sleeps += 1;
        self.clock.set(self.clock.get() + u64::from(ms) * MS);
    }
}

/// A device that gives `script`, on a clock that reads `now_ns`.
fn device(now_ns: u64, script: &[Read]) -> (Device, TestClock) {
    let clock = Rc::new(Cell::new(now_ns));
    let device = Device {
        script: script.iter().copied().collect(),
        served: 0,
        asked: Vec::new(),
        sleeps: 0,
        clock: Rc::clone(&clock),
    };
    (device, TestClock(clock))
}

/// The stream's bytes `from .. from + 64`.
fn stream(from: usize) -> [u8; 64] {
    std::array::from_fn(|offset| (from + offset).to_le_bytes()[0])
}

/// 1, 7, 20 and then 36 of 100 offered bytes, with a read that found nothing and an interrupted one
/// between: every byte lands in place, each read asks for exactly what is missing, and the next
/// block starts with the stream's 65th byte.
#[test]
fn a_block_arriving_in_pieces_fills_in_place_and_takes_nothing_past_it() {
    let (mut raw, clock) = device(
        S,
        &[
            Read::Bytes(1),
            Read::Fail(ErrorKind::WouldBlock),
            Read::Bytes(7),
            Read::Fail(ErrorKind::Interrupted),
            Read::Bytes(20),
            Read::Bytes(100),
            Read::Bytes(64),
        ],
    );
    let mut block = [0xAA; 64];
    assert_eq!(
        fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
        Ok(())
    );
    assert_eq!(block, stream(0));
    assert_eq!(raw.asked, [64, 63, 63, 56, 56, 36]);
    assert_eq!(raw.served, 64);
    assert_eq!(raw.sleeps, 1);

    assert_eq!(
        fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
        Ok(())
    );
    assert_eq!(block, stream(64));
    assert_eq!(raw.asked[6..], [64]);
    assert_eq!(raw.served, 128);
}

/// Q39 (c): a block still incomplete 2 s after the call is "hwrng read fault", which halts. A
/// device that finds nothing yet is read once a millisecond until then; one whose block completes
/// on the last read before the deadline is fine; bytes that came do not stop the deadline.
#[test]
fn reads_that_find_nothing_fail_at_the_deadline_and_not_before() {
    assert_eq!(DEADLINE_NS, 2 * S);
    assert_eq!(HalError::HwRng.text(), "hwrng read fault");
    assert!(HalError::HwRng.halts());

    let start = 5 * S;
    let (mut raw, clock) = device(start, &[]);
    let mut block = [0; 64];
    assert_eq!(
        fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
        Err(HalError::HwRng)
    );
    assert_eq!(clock.now_ns(), start + 2 * S);
    assert_eq!(raw.asked.len(), 2_000);
    assert_eq!(raw.sleeps, 2_000);

    let mut script = vec![Read::Fail(ErrorKind::WouldBlock); 1_999];
    script.push(Read::Bytes(64));
    let (mut raw, clock) = device(start, &script);
    assert_eq!(
        fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
        Ok(())
    );
    assert_eq!(block, stream(0));
    assert_eq!(clock.now_ns(), start + 2 * S - MS);

    let (mut raw, clock) = device(start, &[Read::Bytes(10)]);
    assert_eq!(
        fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
        Err(HalError::HwRng)
    );
    assert_eq!(clock.now_ns(), start + 2 * S);
    assert_eq!(raw.served, 10);
}

/// End of file, at once or after part of a block, is a fault, with no sleep and no further read.
#[test]
fn end_of_file_is_a_fault() {
    for script in [&[Read::Bytes(0)][..], &[Read::Bytes(10), Read::Bytes(0)]] {
        let (mut raw, clock) = device(S, script);
        let mut block = [0; 64];
        assert_eq!(
            fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
            Err(HalError::HwRng)
        );
        assert_eq!(raw.asked.len(), script.len());
        assert_eq!(raw.sleeps, 0);
    }
}

/// An interrupted read is read again at once, for the same bytes.
#[test]
fn an_interrupted_read_is_read_again() {
    let (mut raw, clock) = device(
        S,
        &[
            Read::Fail(ErrorKind::Interrupted),
            Read::Fail(ErrorKind::Interrupted),
            Read::Bytes(30),
            Read::Fail(ErrorKind::Interrupted),
            Read::Bytes(34),
        ],
    );
    let mut block = [0; 64];
    assert_eq!(
        fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
        Ok(())
    );
    assert_eq!(block, stream(0));
    assert_eq!(raw.asked, [64, 64, 64, 34, 34]);
    assert_eq!(raw.sleeps, 0);
    assert_eq!(clock.now_ns(), S);
}

/// Any other error, or a count past the bytes asked for, is a fault at once: no retry and no
/// default.
#[test]
fn other_errors_are_faults_at_once() {
    let refusals = [
        ErrorKind::Other,
        ErrorKind::PermissionDenied,
        ErrorKind::NotFound,
        ErrorKind::UnexpectedEof,
        ErrorKind::InvalidInput,
        ErrorKind::TimedOut,
        ErrorKind::BrokenPipe,
    ]
    .map(Read::Fail);
    for refusal in refusals.into_iter().chain([Read::TooMany]) {
        for script in [&[refusal][..], &[Read::Bytes(63), refusal]] {
            let (mut raw, clock) = device(S, script);
            let mut block = [0; 64];
            assert_eq!(
                fill_block(&mut raw, &clock, &mut block, DEADLINE_NS),
                Err(HalError::HwRng)
            );
            assert_eq!(raw.asked.len(), script.len());
            assert_eq!(raw.sleeps, 0);
        }
    }
}
