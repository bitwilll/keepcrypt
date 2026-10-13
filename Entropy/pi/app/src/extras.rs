//! The write-only extras (docs/pi-firmware.md "`extras`", "Games, sensors and the entropy pool";
//! tasks/todo.md, M3 group 8): which events the ceremony loop forwards to `Session::add_extra`.
//!
//! - Every key press before the commitment in Mixed mode gives its nanosecond timestamp, eight
//!   bytes big-endian, as `ExtraSource::InputTiming`: core mixes it in and credits it zero. The
//!   choice depends only on the stage and the mode, never on the screen, so a press counts the
//!   same whether or not a game is open.
//! - Nothing else is forwarded: no tick, nothing after the commitment (C fixes D, and the
//!   typestate has no `add_extra` there), nothing in dice-only mode (where core ignores extras).
//! - `extra_for` is pure; the app's one call site hands its answer to `add_extra`.

use keepcrypt_core::{ExtraSource, Mode};

use crate::input::Event;

listed_enum! {
/// Which `app::Stage` variant the app is in, without its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    Idle,
    Collecting,
    Committed,
    Rolling,
    Sealed,
    Checking,
    Ready,
    BackupCheck,
    Checked,
    Halted,
}
}

/// The extra input `event` gives in `stage` and `mode`, or `None`.
pub fn extra_for(stage: StageKind, mode: Mode, event: Event) -> Option<(ExtraSource, [u8; 8])> {
    match (stage, mode, event) {
        (StageKind::Collecting, Mode::Mixed, Event::Key { at_ns, .. }) => {
            Some((ExtraSource::InputTiming, at_ns.to_be_bytes()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Key;

    #[test]
    fn only_key_presses_in_mixed_collecting_are_forwarded() {
        let at_ns = 0x0102_0304_0506_0708;
        for stage in StageKind::ALL {
            for mode in [Mode::Mixed, Mode::DiceOnly] {
                for key in Key::ALL {
                    let forwarded = extra_for(stage, mode, Event::Key { key, at_ns });
                    if stage == StageKind::Collecting && mode == Mode::Mixed {
                        assert_eq!(
                            forwarded,
                            Some((ExtraSource::InputTiming, [1, 2, 3, 4, 5, 6, 7, 8])),
                            "{stage:?} {key:?}"
                        );
                    } else {
                        assert_eq!(forwarded, None, "{stage:?} {mode:?} {key:?}");
                    }
                }
                let tick = Event::Tick { now_ns: at_ns };
                assert_eq!(extra_for(stage, mode, tick), None, "{stage:?} {mode:?}");
            }
        }
    }
}
