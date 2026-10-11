//! The simulated USB stick (tasks/todo.md, M3 group 7, Q30; rule 8): files in RAM, inserted or
//! not, and the mount a write gets.
//!
//! - It behaves as pi/app's `hal::Usb` asks of the device: listings and reads under a read-only
//!   mount; a backup written as a new file (an existing name is `Exists`, never replaced); a
//!   read-back or a removal only of the file just written (`NotWritten` for any other).
//! - `Mount::ReadOnly` is a stick that mounts only read-only (a write-protected one): a write is
//!   then `ReadOnly`.
//! - Armed faults (`Fault`): a write that fails (no file is left), a sync that fails (the file is
//!   removed again), a corrupt read-back (one byte flipped) and the stick pulled out mid-call.
//! - Every call that reaches an inserted stick is logged with the mount it ran under, so a
//!   scenario can show that the app only read `.age` and `.kcr` files read-only and only created
//!   new `.age` files (rule 8).
//! - The stick starts out of the slot and empty. The simulator reads no file from disk: tests put
//!   files on the stick in RAM.

use std::collections::BTreeMap;

use keepcrypt_pi::hal::{FileKind, FileName, HalError, Written, Zeroizing};

use crate::mark;
use crate::sim::{Armed, Fault};

/// How the stick mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mount {
    /// Read-write for a write, read-only for everything else.
    ReadWrite,
    /// Read-only always: a write-protected stick.
    ReadOnly,
}

/// One call the app made of an inserted stick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    List(FileKind),
    Read(String),
    Write(String),
    ReadWritten(String),
    RemoveWritten(String),
}

/// One logged call and the mount it ran under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub mount: Mount,
    pub op: Op,
}

/// The stick: its files by name, whether it is inserted, how it mounts, the file just written,
/// and the log of calls.
pub(crate) struct Stick {
    files: BTreeMap<String, Zeroizing<Vec<u8>>>,
    inserted: bool,
    mount: Mount,
    written: Option<String>,
    log: Vec<Access>,
}

impl Stick {
    pub(crate) fn new() -> Self {
        Stick {
            files: BTreeMap::new(),
            inserted: false,
            mount: Mount::ReadWrite,
            written: None,
            log: Vec::new(),
        }
    }

    pub(crate) fn insert(&mut self) {
        self.inserted = true;
    }

    pub(crate) fn remove(&mut self) {
        self.inserted = false;
    }

    pub(crate) fn set_mount(&mut self, mount: Mount) {
        self.mount = mount;
    }

    /// Puts a file on the stick under any name, as a test sets it up (replacing one of that name).
    pub(crate) fn put(&mut self, name: &str, bytes: Vec<u8>) {
        self.files.insert(name.to_owned(), Zeroizing::new(bytes));
    }

    /// Every file's name, in byte order.
    pub(crate) fn names(&self) -> Vec<&str> {
        self.files.keys().map(String::as_str).collect()
    }

    pub(crate) fn file(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(|bytes| bytes.as_slice())
    }

    pub(crate) fn log(&self) -> &[Access] {
        &self.log
    }

    pub(crate) fn inserted(&self) -> bool {
        self.inserted
    }

    /// The stick is there for a call: not pulled out by an armed `Removed` fault, and inserted.
    /// The call is logged under `mount`.
    fn reach(&mut self, armed: &mut Armed, mount: Mount, op: Op) -> Result<(), HalError> {
        if self.inserted && armed.take(Fault::Removed) {
            self.inserted = false;
            return Err(HalError::Removed);
        }
        if !self.inserted {
            return Err(HalError::NoStick);
        }
        self.log.push(Access { mount, op });
        Ok(())
    }

    pub(crate) fn list(
        &mut self,
        armed: &mut Armed,
        kind: FileKind,
    ) -> Result<Vec<FileName>, HalError> {
        self.reach(armed, Mount::ReadOnly, Op::List(kind))?;
        Ok(self
            .files
            .keys()
            .filter_map(|name| FileName::new(name))
            .filter(|name| name.kind() == kind)
            .collect())
    }

    pub(crate) fn read(
        &mut self,
        armed: &mut Armed,
        name: &FileName,
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HalError> {
        self.reach(armed, Mount::ReadOnly, Op::Read(name.as_str().to_owned()))?;
        self.copy(name.as_str(), max)
    }

    /// Writes `bytes` as a new file `name`, or refuses: `ReadOnly` on a read-only stick, `Exists`
    /// over any file, `Write` or `Sync` when armed. No refusal or fault leaves a file behind.
    pub(crate) fn write(
        &mut self,
        armed: &mut Armed,
        name: &str,
        bytes: &[u8],
    ) -> Result<Written, HalError> {
        mark();
        self.reach(armed, self.mount, Op::Write(name.to_owned()))?;
        if self.mount == Mount::ReadOnly {
            return Err(HalError::ReadOnly);
        }
        let Some(file_name) = FileName::new(name) else {
            return Err(HalError::Write);
        };
        if self.files.contains_key(name) {
            return Err(HalError::Exists);
        }
        if armed.take(Fault::Write) {
            return Err(HalError::Write);
        }
        self.files
            .insert(name.to_owned(), Zeroizing::new(bytes.to_vec()));
        if armed.take(Fault::Sync) {
            // The device removes what it created when the sync fails (hal::Usb::write_backup).
            self.files.remove(name);
            return Err(HalError::Sync);
        }
        self.written = Some(name.to_owned());
        Ok(Written::new(file_name))
    }

    /// The file just written, under a read-only remount; flipped in its last byte when a
    /// `ReadBackCorrupt` fault is armed.
    pub(crate) fn read_written(
        &mut self,
        armed: &mut Armed,
        written: &Written,
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HalError> {
        let name = written.name().as_str();
        self.reach(armed, Mount::ReadOnly, Op::ReadWritten(name.to_owned()))?;
        if self.written.as_deref() != Some(name) {
            return Err(HalError::NotWritten);
        }
        let mut bytes = self.copy(name, max)?;
        if armed.take(Fault::ReadBackCorrupt)
            && let Some(last) = bytes.last_mut()
        {
            *last ^= 0x01;
        }
        Ok(bytes)
    }

    /// Removes the file just written, and nothing else.
    pub(crate) fn remove_written(
        &mut self,
        armed: &mut Armed,
        written: Written,
    ) -> Result<(), HalError> {
        let name = written.name().as_str();
        self.reach(armed, Mount::ReadWrite, Op::RemoveWritten(name.to_owned()))?;
        if self.written.as_deref() != Some(name) {
            return Err(HalError::NotWritten);
        }
        self.written = None;
        match self.files.remove(name) {
            Some(_) => Ok(()),
            None => Err(HalError::Remove),
        }
    }

    /// A copy of file `name`: `Read` if there is none, `TooLarge` past `max` bytes.
    fn copy(&self, name: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, HalError> {
        match self.files.get(name) {
            None => Err(HalError::Read),
            Some(bytes) if bytes.len() > max => Err(HalError::TooLarge),
            Some(bytes) => Ok(Zeroizing::new(bytes.to_vec())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKUP: &str = "keepcrypt-backup-0a1b2c3d.age";

    fn name(name: &str) -> FileName {
        FileName::new(name).expect("an accepted name")
    }

    fn inserted() -> (Stick, Armed) {
        let mut stick = Stick::new();
        stick.insert();
        (stick, Armed::default())
    }

    #[test]
    fn a_new_stick_is_out_of_the_slot_and_empty() {
        let mut stick = Stick::new();
        let mut armed = Armed::default();
        assert!(!stick.inserted());
        assert!(stick.names().is_empty());
        assert_eq!(
            stick.list(&mut armed, FileKind::Age),
            Err(HalError::NoStick)
        );
        assert_eq!(
            stick.write(&mut armed, BACKUP, b"x"),
            Err(HalError::NoStick)
        );
        assert!(stick.log().is_empty());
    }

    #[test]
    fn listings_hold_only_accepted_names_of_the_kind_and_reads_are_read_only() {
        let (mut stick, mut armed) = inserted();
        for file in [
            "b.age",
            "a.AGE",
            "snap.kcr",
            "notes.txt",
            "x y.age",
            "c.age.txt",
        ] {
            stick.put(file, file.as_bytes().to_vec());
        }
        let names = |list: Vec<FileName>| -> Vec<String> {
            list.iter().map(|n| n.as_str().to_owned()).collect()
        };
        let ages = stick.list(&mut armed, FileKind::Age).expect("a listing");
        assert_eq!(names(ages), ["a.AGE", "b.age"]);
        let kcrs = stick.list(&mut armed, FileKind::Kcr).expect("a listing");
        assert_eq!(names(kcrs), ["snap.kcr"]);
        let read = stick.read(&mut armed, &name("b.age"), 5).expect("read");
        assert_eq!(&read[..], b"b.age");
        assert_eq!(
            stick.read(&mut armed, &name("b.age"), 4),
            Err(HalError::TooLarge)
        );
        assert_eq!(
            stick.read(&mut armed, &name("gone.age"), 64),
            Err(HalError::Read)
        );
        assert!(stick.log().iter().all(|a| a.mount == Mount::ReadOnly));
        assert_eq!(
            stick.log()[..3],
            [
                Access {
                    mount: Mount::ReadOnly,
                    op: Op::List(FileKind::Age)
                },
                Access {
                    mount: Mount::ReadOnly,
                    op: Op::List(FileKind::Kcr)
                },
                Access {
                    mount: Mount::ReadOnly,
                    op: Op::Read("b.age".into())
                },
            ]
        );
    }

    #[test]
    fn a_write_creates_a_new_file_that_alone_can_be_read_back_and_removed() {
        let (mut stick, mut armed) = inserted();
        stick.put("other.age", b"other".to_vec());
        let written = stick
            .write(&mut armed, BACKUP, b"age file")
            .expect("written");
        assert_eq!(written.name().as_str(), BACKUP);
        assert_eq!(stick.file(BACKUP), Some(&b"age file"[..]));
        let back = stick
            .read_written(&mut armed, &written, 64)
            .expect("read back");
        assert_eq!(&back[..], b"age file");
        assert_eq!(
            stick.read_written(&mut armed, &written, 7),
            Err(HalError::TooLarge)
        );
        // Another file is neither read back nor removed through a `Written`.
        let other = Written::new(name("other.age"));
        assert_eq!(
            stick.read_written(&mut armed, &other, 64),
            Err(HalError::NotWritten)
        );
        assert_eq!(
            stick.remove_written(&mut armed, Written::new(name("other.age"))),
            Err(HalError::NotWritten)
        );
        assert_eq!(stick.file("other.age"), Some(&b"other"[..]));
        assert_eq!(stick.remove_written(&mut armed, written), Ok(()));
        assert_eq!(stick.names(), ["other.age"]);
        // Once removed, it is no longer the file just written.
        assert_eq!(
            stick.remove_written(&mut armed, Written::new(name(BACKUP))),
            Err(HalError::NotWritten)
        );
        let mounts: Vec<Mount> = stick.log().iter().map(|a| a.mount).collect();
        assert_eq!(mounts[0], Mount::ReadWrite);
        assert_eq!(mounts[1..3], [Mount::ReadOnly, Mount::ReadOnly]);
    }

    #[test]
    fn writes_over_a_name_or_on_a_read_only_stick_are_refused() {
        let (mut stick, mut armed) = inserted();
        stick.put(BACKUP, b"earlier".to_vec());
        assert_eq!(
            stick.write(&mut armed, BACKUP, b"new"),
            Err(HalError::Exists)
        );
        assert_eq!(stick.file(BACKUP), Some(&b"earlier"[..]));
        stick.set_mount(Mount::ReadOnly);
        let fresh = "keepcrypt-backup-00000000.age";
        assert_eq!(
            stick.write(&mut armed, fresh, b"new"),
            Err(HalError::ReadOnly)
        );
        assert_eq!(stick.names(), [BACKUP]);
        assert_eq!(stick.log()[1].mount, Mount::ReadOnly);
    }

    #[test]
    fn write_and_sync_faults_leave_no_file_and_fire_once() {
        for fault in [Fault::Write, Fault::Sync] {
            let (mut stick, mut armed) = inserted();
            armed.arm(fault);
            let expected = match fault {
                Fault::Write => HalError::Write,
                _ => HalError::Sync,
            };
            assert_eq!(stick.write(&mut armed, BACKUP, b"x"), Err(expected));
            assert!(stick.names().is_empty(), "{fault:?}");
            assert!(stick.write(&mut armed, BACKUP, b"x").is_ok(), "{fault:?}");
            assert_eq!(stick.names(), [BACKUP]);
        }
    }

    #[test]
    fn a_corrupt_read_back_flips_one_byte_once() {
        let (mut stick, mut armed) = inserted();
        let written = stick.write(&mut armed, BACKUP, b"abc").expect("written");
        armed.arm(Fault::ReadBackCorrupt);
        let corrupt = stick.read_written(&mut armed, &written, 64).expect("read");
        assert_eq!(&corrupt[..], b"abb");
        assert_eq!(stick.file(BACKUP), Some(&b"abc"[..]));
        let clean = stick.read_written(&mut armed, &written, 64).expect("read");
        assert_eq!(&clean[..], b"abc");
    }

    #[test]
    fn a_stick_pulled_mid_call_is_removed_and_stays_out() {
        let (mut stick, mut armed) = inserted();
        armed.arm(Fault::Removed);
        assert_eq!(
            stick.write(&mut armed, BACKUP, b"x"),
            Err(HalError::Removed)
        );
        assert!(!stick.inserted());
        assert!(stick.names().is_empty());
        assert_eq!(
            stick.list(&mut armed, FileKind::Age),
            Err(HalError::NoStick)
        );
        stick.insert();
        assert_eq!(stick.list(&mut armed, FileKind::Age), Ok(Vec::new()));
        assert!(
            stick.log().len() == 1,
            "only the call that reached the stick"
        );
    }
}
