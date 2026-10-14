//! The hardware the app runs on (docs/pi-firmware.md "Firmware application architecture";
//! tasks/todo.md, M3 group 5, Q25, Q30 (f) and Q33 (g)).
//!
//! The four traits the docs name, plus a clock, bundled as `Hal`. M4's drivers implement them on
//! the Pi, and pi/sim implements them in RAM; the app is written against `Hal` alone.
//!
//! - Every fault is a `HalError` with fixed text and no payload, so no error can carry a secret or
//!   a piece of what a stick supplied (rule 5). `HalError::halts` sorts them by Q25: a display,
//!   button or hwrng fault halts the device, and so do the device's own start-up faults and stop
//!   mode (M4, Q35 and Q39 (e), (g)); a USB fault returns to its screen.
//! - Files (rule 8): the app reaches a stick only through `Usb`. It lists and reads only `.age`
//!   and `.kcr` files with `FileName`'s names, under a read-only mount, and writes only a core
//!   `BackupFile`, as a new file that never replaces another. Only the file just written can be
//!   read back or removed: each `Usb` implementation keeps its own record of that file and
//!   refuses any other (`NotWritten`). The `Written` a write returns names the file and grants
//!   nothing by itself.

use core::fmt;

use keepcrypt_core::BackupFile;
/// The wiping buffer `Usb` returns, re-exported so that a `Hal` implementation (the simulator) can
/// name it without a zeroize edge of its own.
pub use zeroize::Zeroizing;

use crate::input::Event;
use crate::screen::Screen;
use crate::ui::Frame;

/// The longest file name the app lists or opens (Q33 (g)).
pub const MAX_NAME_LEN: usize = 64;

listed_enum! {
/// A hardware fault. The text is fixed and plain (`HalError::text`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalError {
    /// The panel did not take a frame.
    Display,
    /// A button could not be read.
    Buttons,
    /// `/dev/hwrng` did not give a whole block.
    HwRng,
    /// The firmware's memory could not be locked, before any secret exists (Q39 (e)).
    MemoryLock,
    /// The root filesystem could not be read for its hash prefix (Q39 (g)).
    RootFs,
    /// The firmware process ended, and stop mode says so (Q35).
    Stopped,
    /// No USB stick is inserted.
    NoStick,
    /// More than one USB stick is inserted (Q39 (f)).
    ManySticks,
    /// The stick was removed during the operation.
    Removed,
    /// The stick could not be mounted.
    Mount,
    /// A write was asked of a stick mounted read-only.
    ReadOnly,
    /// A file could not be read.
    Read,
    /// A file is larger than the caller accepts.
    TooLarge,
    /// A file of the backup's name already exists; it is never replaced.
    Exists,
    /// The backup could not be written.
    Write,
    /// The written file could not be synced to the stick.
    Sync,
    /// The stick could not be unmounted.
    Unmount,
    /// A read-back or removal named another file than the one just written.
    NotWritten,
    /// The file just written could not be removed.
    Remove,
}
}

impl HalError {
    /// The fixed text a halt or refusal screen shows.
    pub const fn text(self) -> &'static str {
        match self {
            HalError::Display => "display fault",
            HalError::Buttons => "button fault",
            HalError::HwRng => "hwrng read fault",
            HalError::MemoryLock => "memory could not be locked",
            HalError::RootFs => "the root filesystem could not be read",
            HalError::Stopped => "the firmware stopped unexpectedly",
            HalError::NoStick => "no USB stick found",
            HalError::ManySticks => "more than one USB stick is inserted",
            HalError::Removed => "the USB stick was removed",
            HalError::Mount => "the USB stick could not be mounted",
            HalError::ReadOnly => "the USB stick is mounted read-only",
            HalError::Read => "a file on the USB stick could not be read",
            HalError::TooLarge => "the file on the USB stick is too large",
            HalError::Exists => "a file of that name is already on the USB stick",
            HalError::Write => "the backup could not be written to the USB stick",
            HalError::Sync => "the USB stick could not be synced",
            HalError::Unmount => "the USB stick could not be unmounted",
            HalError::NotWritten => "only the file just written can be read back or removed",
            HalError::Remove => "the file could not be removed from the USB stick",
        }
    }

    /// True when the fault halts the device until a power cycle (Q25: every display, button or
    /// hwrng fault; Q35 and Q39 (e), (g): stop mode, and a memory lock or root filesystem fault at
    /// start-up); false for a USB fault, which returns to its own screen.
    pub const fn halts(self) -> bool {
        match self {
            HalError::Display
            | HalError::Buttons
            | HalError::HwRng
            | HalError::MemoryLock
            | HalError::RootFs
            | HalError::Stopped => true,
            HalError::NoStick
            | HalError::ManySticks
            | HalError::Removed
            | HalError::Mount
            | HalError::ReadOnly
            | HalError::Read
            | HalError::TooLarge
            | HalError::Exists
            | HalError::Write
            | HalError::Sync
            | HalError::Unmount
            | HalError::NotWritten
            | HalError::Remove => false,
        }
    }
}

impl fmt::Display for HalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// The two kinds of file the app ever reads (rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// An age backup, `.age`.
    Age,
    /// A signed registry snapshot, `.kcr`.
    Kcr,
}

/// A name the app lists, opens or writes (Q33 (g)): up to `MAX_NAME_LEN` characters from
/// `[A-Za-z0-9._-]`, ending in `.age` or `.kcr` in any case. No path separator can pass, so a
/// name always stays in the stick's top directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    name: String,
    kind: FileKind,
}

impl FileName {
    /// `name` if it is one the app accepts, else `None` (a listing leaves such a file out).
    pub fn new(name: &str) -> Option<FileName> {
        let allowed = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
        if name.len() > MAX_NAME_LEN || !name.bytes().all(allowed) {
            return None;
        }
        // All ASCII from here, so the last four bytes are the last four characters.
        let extension = name.get(name.len().checked_sub(4)?..)?;
        let kind = if extension.eq_ignore_ascii_case(".age") {
            FileKind::Age
        } else if extension.eq_ignore_ascii_case(".kcr") {
            FileKind::Kcr
        } else {
            return None;
        };
        Some(FileName {
            name: name.to_owned(),
            kind,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> FileKind {
        self.kind
    }
}

/// The name of the file a `Usb::write_backup` just wrote, which the app hands back to read that
/// file back or remove it. Not `Clone`, so a removal uses it up. It grants nothing by itself:
/// `Written::new` is public, for implementations in other crates, so a `Usb` implementation
/// checks every `Written` against its own record of the file it last wrote.
#[derive(Debug, PartialEq, Eq)]
pub struct Written {
    name: FileName,
}

impl Written {
    /// Only for a `Usb` implementation, after its write succeeded.
    pub fn new(name: FileName) -> Self {
        Written { name }
    }

    pub fn name(&self) -> &FileName {
        &self.name
    }
}

/// What the boot screen and About show about this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    /// The firmware version.
    pub version: &'static str,
    /// The root filesystem hash prefix (pi-firmware.md step 1); `sim` in the simulator.
    pub rootfs: String,
    /// True in the simulator: every screen then carries the SIMULATOR banner, which reads
    /// "SIMULATOR · NOT FOR REAL FUNDS" alone (Q30 (h)) and "SIMULATOR" beside TEST REGISTRY
    /// (Q33 (j)).
    pub simulator: bool,
}

/// The 240×240 panel.
pub trait Display {
    /// Shows `frame`. `screen` is the model it was drawn from: the device ignores it, and the
    /// simulator checks and logs it (Q30 (f)).
    fn present(&mut self, frame: &Frame, screen: &Screen<'_>) -> Result<(), HalError>;
}

/// The joystick and the three keys.
pub trait Buttons {
    /// The next debounced press (`input::Debouncer`), or `Event::Tick` once `deadline_ns` passes
    /// with none. Times are on `Clock::now_ns`'s base. A `Tick` may also come early (the
    /// simulator gives one where its script ends with a wait): the app checks its timers against
    /// the tick's `now_ns`, so an early one changes nothing.
    fn next_event(&mut self, deadline_ns: u64) -> Result<Event, HalError>;
}

/// A monotonic clock in nanoseconds, on the same base as the key timestamps.
pub trait Clock {
    fn now_ns(&self) -> u64;
}

/// Raw hardware samples for core's health tests.
pub trait HwRng {
    /// Fills `block` with the next 64 raw bytes of `/dev/hwrng`: exactly 64, or an error.
    fn read_block(&mut self, block: &mut [u8; 64]) -> Result<(), HalError>;
}

/// The USB stick: backup export, backup checks and snapshot import. Each call mounts and unmounts
/// the stick itself; nothing stays mounted between calls.
///
/// Every implementation (M4's driver as well as the simulator) keeps its own record of the file
/// its last successful `write_backup` created. It clears the record at the start of every
/// `write_backup` call and when that file is removed, and `read_written` and `remove_written`
/// refuse any `Written` that does not name the recorded file (`NotWritten`), so a failed later
/// write never leaves an earlier file removable.
pub trait Usb {
    /// True while a stick is inserted.
    fn stick(&mut self) -> Result<bool, HalError>;

    /// The names of `kind` in the stick's top directory, under a read-only mount. Names that
    /// `FileName::new` refuses are left out.
    fn list(&mut self, kind: FileKind) -> Result<Vec<FileName>, HalError>;

    /// The bytes of `name`, under a read-only mount; `TooLarge` past `max` bytes.
    fn read(&mut self, name: &FileName, max: usize) -> Result<Zeroizing<Vec<u8>>, HalError>;

    /// Writes `file` under its own name as a new file (`Exists` if that name is taken, never a
    /// replacement), syncs and unmounts. On an error it has removed whatever part of the file it
    /// created, where it can (pi-firmware.md, "On failure").
    fn write_backup(&mut self, file: &BackupFile) -> Result<Written, HalError>;

    /// The bytes of the file just written, under a read-only remount; `TooLarge` past `max`, and
    /// `NotWritten` unless `written` names the recorded file.
    fn read_written(
        &mut self,
        written: &Written,
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HalError>;

    /// Removes the file just written, when a later step of the backup failed, and nothing else:
    /// `NotWritten` unless `written` names the recorded file.
    fn remove_written(&mut self, written: Written) -> Result<(), HalError>;
}

/// Everything the app needs of the hardware.
pub trait Hal: Display + Buttons + Clock + HwRng + Usb {
    fn build_info(&self) -> BuildInfo;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_q33s() {
        for refused in [
            "../x.age",
            "x.AGE.txt",
            "x.txt",
            "dir/x.age",
            "dir\\x.age",
            "x y.age",
            "x.age ",
            "x\u{0}.age",
            "é.age",
            "x.ag",
            "age",
            "",
        ] {
            assert_eq!(FileName::new(refused), None, "{refused:?}");
        }
        let longest = format!("{}.age", "a".repeat(MAX_NAME_LEN - 4));
        assert_eq!(longest.len(), 64);
        assert!(FileName::new(&longest).is_some());
        let too_long = format!("{}.age", "a".repeat(MAX_NAME_LEN - 3));
        assert_eq!(too_long.len(), 65);
        assert_eq!(FileName::new(&too_long), None);

        let backup = FileName::new("keepcrypt-backup-0a1b2c3d.age").expect("a backup name");
        assert_eq!(backup.kind(), FileKind::Age);
        assert_eq!(backup.as_str(), "keepcrypt-backup-0a1b2c3d.age");
        let snapshot = FileName::new("Snapshot_No.4.KCR").expect("any case");
        assert_eq!(snapshot.kind(), FileKind::Kcr);
        assert_eq!(
            FileName::new("x.AgE").map(|n| n.kind()),
            Some(FileKind::Age)
        );
    }

    #[test]
    fn every_hal_error_displays_fixed_text() {
        for error in HalError::ALL {
            let pinned = match error {
                HalError::Display => "display fault",
                HalError::Buttons => "button fault",
                HalError::HwRng => "hwrng read fault",
                HalError::MemoryLock => "memory could not be locked",
                HalError::RootFs => "the root filesystem could not be read",
                HalError::Stopped => "the firmware stopped unexpectedly",
                HalError::NoStick => "no USB stick found",
                HalError::ManySticks => "more than one USB stick is inserted",
                HalError::Removed => "the USB stick was removed",
                HalError::Mount => "the USB stick could not be mounted",
                HalError::ReadOnly => "the USB stick is mounted read-only",
                HalError::Read => "a file on the USB stick could not be read",
                HalError::TooLarge => "the file on the USB stick is too large",
                HalError::Exists => "a file of that name is already on the USB stick",
                HalError::Write => "the backup could not be written to the USB stick",
                HalError::Sync => "the USB stick could not be synced",
                HalError::Unmount => "the USB stick could not be unmounted",
                HalError::NotWritten => "only the file just written can be read back or removed",
                HalError::Remove => "the file could not be removed from the USB stick",
            };
            assert_eq!(error.to_string(), pinned);
            assert_eq!(error.text(), pinned);
        }
    }

    #[test]
    fn display_button_hwrng_and_start_up_faults_halt_and_usb_faults_do_not() {
        let halting: Vec<HalError> = HalError::ALL.into_iter().filter(|e| e.halts()).collect();
        assert_eq!(
            halting,
            [
                HalError::Display,
                HalError::Buttons,
                HalError::HwRng,
                HalError::MemoryLock,
                HalError::RootFs,
                HalError::Stopped,
            ]
        );
        assert!(!HalError::ManySticks.halts());
    }

    #[test]
    fn a_written_file_keeps_its_name() {
        let name = FileName::new("keepcrypt-backup-00000000.age").expect("a backup name");
        let written = Written::new(name.clone());
        assert_eq!(written.name(), &name);
    }
}
