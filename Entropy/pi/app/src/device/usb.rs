//! The USB stick (docs/pi-firmware.md "`hal::Usb`" and "Encrypted backup to a USB stick";
//! tasks/todo.md, M4 group 8, Q39 (f); CLAUDE.md rule 8).
//!
//! - Pure: `DeviceUsb` implements `hal::Usb` over a `Locate` (where the stick is, looked up afresh
//!   for each call) and a `Mounter` (mount(2), umount2(2) and the syncs), which group 10's Linux
//!   glue implements and the tests fake. Its only file I/O is on the stick, under the mount point.
//! - The finder (`Finder`, over `SysBlock`'s view of `/sys/block`) takes exactly one stick: an `sd`
//!   disk on a USB bus, by its first partition, or the whole disk when it has none. Two or more are
//!   `ManySticks`, "more than one USB stick is inserted".
//! - Every call mounts and unmounts; nothing stays mounted between calls. The mounts are data
//!   (`READ_PLAN`, `WRITE_PLAN`): vfat only, so an exFAT or NTFS stick "could not be mounted"; never
//!   set-user-ID files, device files or programs; read-only for every listing and read. A failed
//!   unmount, or a stick pulled out, ends in a lazy detach so the next mount starts clean, and
//!   nothing is ever unmounted by force.
//! - The one file the firmware creates is the backup, through the one `create_new` open below: an
//!   existing name, in any letter case on FAT, is `Exists` and is never touched. A stick the kernel
//!   marks read-only (a write-protected one) is `ReadOnly`, "mounted read-only", before anything is
//!   mounted for writing. The file is written whole, synced with its directory, and the stick
//!   unmounted; a failure removes the file this call created, and nothing else.
//! - Only the file just written can be read back, on a fresh read-only mount, or removed: the
//!   record `hal::Usb` asks for, cleared at the start of every write.
//! - Every fault is a fixed `HalError`: the errno table names a few by cause, and each step names
//!   the rest. No retry and no fallback.
//! - File dates: the Pi has no clock, so the kernel's FAT driver dates the backup 1980-01-01, the
//!   earliest date FAT holds (Q39 (f)). Nothing here sets a date.

use core::ffi::{c_int, c_ulong};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};

use keepcrypt_core::BackupFile;
use keepcrypt_pi::hal::{FileKind, FileName, HalError, Usb, Written, Zeroizing};

#[cfg(test)]
mod tests;

// mount(2)'s flags, as Linux defines them (include/uapi/linux/mount.h), in mount(2)'s own type, so
// the Linux glue hands them on unconverted.
/// Mount read-only.
pub const MS_RDONLY: c_ulong = 1;
/// Ignore set-user-ID and set-group-ID bits.
pub const MS_NOSUID: c_ulong = 2;
/// No access to device files.
pub const MS_NODEV: c_ulong = 4;
/// No program execution.
pub const MS_NOEXEC: c_ulong = 8;
/// umount2(2)'s lazy detach, as Linux defines it (include/linux/fs.h): the mount leaves the
/// namespace at once, and the kernel ends it once nothing uses it.
const MNT_DETACH: c_int = 2;

/// The mount of every listing and read: read-only.
pub const READ_PLAN: MountPlan = MountPlan {
    fstype: "vfat",
    flags: MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
};
/// The mount of the write, and of the removal of the file just written.
pub const WRITE_PLAN: MountPlan = MountPlan {
    fstype: "vfat",
    flags: MS_NOSUID | MS_NODEV | MS_NOEXEC,
};

// Linux's errno values for the errors the table names (asm-generic/errno-base.h, every
// architecture). macOS has the same numbers, so the host tests meet them too.
const ENXIO: i32 = 6;
const EEXIST: i32 = 17;
const ENODEV: i32 = 19;
const EFBIG: i32 = 27;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;

/// The errno table (Q39 (f)): the errors that name their own fault, whatever step met them. Any
/// other error is the step's own fault (`fault`).
const ERRNO_FAULTS: [(i32, HalError); 6] = [
    (EEXIST, HalError::Exists),
    (EROFS, HalError::ReadOnly),
    (ENOSPC, HalError::Write),
    (EFBIG, HalError::Write),
    (ENODEV, HalError::Removed),
    (ENXIO, HalError::Removed),
];

/// A mount of the stick, as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountPlan {
    /// The filesystem type: `vfat`, the only one the firmware mounts.
    pub fstype: &'static str,
    /// mount(2)'s flags.
    pub flags: c_ulong,
}

/// An unmount, as data: plain, or a lazy detach. There is no forced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmount {
    Plain,
    /// Only to clean up after a stick pulled out (`Removed`) or a failed plain unmount.
    Detach,
}

impl Unmount {
    /// umount2(2)'s flags.
    pub const fn flags(self) -> c_int {
        match self {
            Unmount::Plain => 0,
            Unmount::Detach => MNT_DETACH,
        }
    }
}

/// mount(2) and umount2(2) of the stick, and the syncs of what a write changes on it. Group 10's
/// Linux glue implements the first two over nix and keeps `sync` as it is; the tests record all
/// three, and on a loop device call the kernel.
pub trait Mounter {
    /// Mounts `device` at `target` as `plan` says.
    fn mount(&mut self, device: &Path, target: &Path, plan: MountPlan) -> io::Result<()>;
    /// Unmounts `target` as `how` says.
    fn unmount(&mut self, target: &Path, how: Unmount) -> io::Result<()>;
    /// Writes `file`, a file or a directory on the mounted stick, through to the stick: fsync(2).
    fn sync(&mut self, file: &File) -> io::Result<()> {
        file.sync_all()
    }
}

/// The stick a lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stick {
    /// The block device to mount: the disk's first partition, or the whole disk.
    pub device: PathBuf,
    /// True when the kernel marks the disk read-only, as it does a write-protected stick.
    pub read_only: bool,
}

/// Where the stick is, looked up afresh for each call: `Finder` on the device, the loop device in
/// CI's test.
pub trait Locate {
    /// The one stick, or `None` when none is inserted; `ManySticks` when more than one is.
    fn locate(&mut self) -> Result<Option<Stick>, HalError>;
}

/// What the finder reads of `/sys/block`. Group 10's Linux glue implements it over that directory;
/// the tests fake it in memory, so no fixture tree or link is made.
pub trait SysBlock {
    /// The names of the entries of `/sys/block`, one per disk.
    fn entries(&mut self) -> io::Result<Vec<OsString>>;
    /// Where entry `name` links: the disk's device path under `/sys/devices`, as read_link gives
    /// it.
    fn device_link(&mut self, name: &str) -> io::Result<PathBuf>;
    /// Entry `name`'s `ro` attribute, as the kernel gives it (`ro_flag`).
    fn ro(&mut self, name: &str) -> io::Result<Vec<u8>>;
    /// True when the disk has a first partition, `<name>1`; false when it has none.
    fn has_partition(&mut self, name: &str) -> io::Result<bool>;
}

/// The finder (pi-firmware.md "`hal::Usb`": "Detects a stick under `/sys/block`").
pub struct Finder<B: SysBlock> {
    sys: B,
    /// Where the block device nodes are: `/dev` on the device (group 10's `paths.rs`).
    dev: PathBuf,
}

impl<B: SysBlock> Finder<B> {
    pub fn new(sys: B, dev: PathBuf) -> Self {
        Finder { sys, dev }
    }
}

impl<B: SysBlock> Locate for Finder<B> {
    /// A stick is an `sd` disk whose device path runs through a USB bus. Exactly one is taken,
    /// by its first partition if it has one, else as the whole disk; its `ro` attribute says
    /// whether it is read-only. An entry that vanished since the listing is `Removed`.
    fn locate(&mut self) -> Result<Option<Stick>, HalError> {
        let mut found = None;
        for entry in self.sys.entries().map_err(sysfs_fault)? {
            let Some(name) = entry.to_str().filter(|name| is_sd(name)) else {
                continue;
            };
            let link = self.sys.device_link(name).map_err(sysfs_fault)?;
            if !link.components().any(is_usb_bus) {
                continue;
            }
            if found.is_some() {
                return Err(HalError::ManySticks);
            }
            found = Some(name.to_owned());
        }
        let Some(disk) = found else {
            return Ok(None);
        };
        let read_only = ro_flag(&self.sys.ro(&disk).map_err(sysfs_fault)?)?;
        let node = if self.sys.has_partition(&disk).map_err(sysfs_fault)? {
            format!("{disk}1")
        } else {
            disk
        };
        Ok(Some(Stick {
            device: self.dev.join(node),
            read_only,
        }))
    }
}

/// A disk's `ro` attribute: `1\n` for a read-only disk, `0\n` otherwise, as the kernel writes it.
/// Anything else leaves the stick's state unknown, and the stick unused: `Mount`.
pub fn ro_flag(attribute: &[u8]) -> Result<bool, HalError> {
    match attribute {
        b"0\n" => Ok(false),
        b"1\n" => Ok(true),
        _ => Err(HalError::Mount),
    }
}

/// True for a SCSI disk's entry, `sd` and one or more letters (`sda`, `sdb`, … `sdaa`): what a USB
/// stick shows up as. The SD card is `mmcblk0`, and partitions are not entries of `/sys/block`.
fn is_sd(name: &str) -> bool {
    name.strip_prefix("sd").is_some_and(|letters| {
        !letters.is_empty() && letters.bytes().all(|b| b.is_ascii_lowercase())
    })
}

/// True for a USB bus's root hub in a device path: a whole component that is `usb` and the bus
/// number (`usb1`). Every device on a USB bus sits under its root hub, and no other device does.
/// `20980000.usb`, the Pi's USB controller, is not one, nor is a component that only contains
/// `usb`.
fn is_usb_bus(component: Component<'_>) -> bool {
    let Component::Normal(name) = component else {
        return false;
    };
    name.to_str()
        .and_then(|name| name.strip_prefix("usb"))
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// The fault a `/sys/block` read meets: an entry that vanished since the listing is a stick pulled
/// out; anything else leaves the stick unusable, `Mount`.
fn sysfs_fault(error: io::Error) -> HalError {
    match error.kind() {
        ErrorKind::NotFound => HalError::Removed,
        _ => fault(&error, HalError::Mount),
    }
}

/// The fault for `error`, met by a step whose own fault is `step`: the errno table's, else `step`.
fn fault(error: &io::Error, step: HalError) -> HalError {
    let errno = error.raw_os_error();
    match ERRNO_FAULTS.iter().find(|&&(code, _)| errno == Some(code)) {
        Some(&(_, named)) => named,
        None => step,
    }
}

/// `hal::Usb` on the device: the stick `locate` finds, mounted at `mount_point` through `mounter`
/// for each call.
pub struct DeviceUsb<L: Locate, M: Mounter> {
    locate: L,
    mounter: M,
    /// Where the stick is mounted: `/mnt/usb` on the device (group 10's `paths.rs`).
    mount_point: PathBuf,
    /// The file the last successful write created (`hal::Usb`).
    written: Option<FileName>,
}

impl<L: Locate, M: Mounter> DeviceUsb<L, M> {
    pub fn new(locate: L, mounter: M, mount_point: PathBuf) -> Self {
        DeviceUsb {
            locate,
            mounter,
            mount_point,
            written: None,
        }
    }

    /// `write_backup`, for any name and bytes (the tests write through this, since only a session
    /// makes a `BackupFile`):
    /// 1. the record is cleared;
    /// 2. the stick's `ro` flag is checked;
    /// 3. the stick is mounted for writing;
    /// 4. the file is created, only as a new one;
    /// 5. all of `bytes` go in, and the file and its directory are synced;
    /// 6. the stick is unmounted, and only then is the record set.
    ///
    /// Until the create succeeds (a refused name, `ReadOnly`, a mount fault, or `Exists` at the
    /// create itself) nothing was created and nothing is removed. A failure after it removes the
    /// file this call created, while the stick is still mounted, then unmounts and gives that
    /// failure's fault.
    fn write_new(&mut self, name: &str, bytes: &[u8]) -> Result<Written, HalError> {
        // From here on no earlier file is the file just written, whatever this attempt gives.
        self.written = None;
        let Some(name) = FileName::new(name) else {
            return Err(HalError::Write);
        };
        self.mount(WRITE_PLAN)?;
        let path = self.mount_point.join(name.as_str());
        let file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) => return self.unmount(Err(fault(&error, HalError::Write))),
        };
        let filled = fill(&mut self.mounter, file, bytes, &self.mount_point);
        match filled.and_then(|()| self.plain_unmount()) {
            Ok(()) => {
                self.written = Some(name.clone());
                Ok(Written::new(name))
            }
            Err(error) => {
                let failed = match remove_synced(&mut self.mounter, &path, &self.mount_point) {
                    // Nothing this call created is left.
                    Ok(()) => Err(error),
                    // Removed where it can be (pi-firmware.md "On failure"): the fault reported is
                    // the write's own.
                    Err(_) => Err(error),
                };
                // After a failed plain unmount, a second try, then a lazy detach.
                self.unmount(failed)
            }
        }
    }

    /// `NotWritten` unless `written` names the file the last write created.
    fn recorded(&self, written: &Written) -> Result<(), HalError> {
        match &self.written {
            Some(name) if name == written.name() => Ok(()),
            _ => Err(HalError::NotWritten),
        }
    }

    /// Mounts the stick as `plan` says, runs `call` on the mounter and the mount point, and
    /// unmounts.
    fn on_stick<T>(
        &mut self,
        plan: MountPlan,
        call: impl FnOnce(&mut M, &Path) -> Result<T, HalError>,
    ) -> Result<T, HalError> {
        self.mount(plan)?;
        let outcome = call(&mut self.mounter, &self.mount_point);
        self.unmount(outcome)
    }

    /// Looks the stick up and mounts it at the mount point as `plan` says: `NoStick` with none,
    /// and `ReadOnly` for a write on a stick the kernel marks read-only, before anything is
    /// mounted.
    fn mount(&mut self, plan: MountPlan) -> Result<(), HalError> {
        let Some(stick) = self.locate.locate()? else {
            return Err(HalError::NoStick);
        };
        if stick.read_only && plan.flags & MS_RDONLY == 0 {
            return Err(HalError::ReadOnly);
        }
        self.mounter
            .mount(&stick.device, &self.mount_point, plan)
            .map_err(|error| fault(&error, HalError::Mount))
    }

    /// Unmounts the stick after a call that gave `outcome`, and gives the call's result: after
    /// `Removed`, a lazy detach at once; otherwise a plain unmount, and if that fails, a lazy
    /// detach so the next mount starts clean, and the unmount's fault unless the call had failed
    /// already.
    fn unmount<T>(&mut self, outcome: Result<T, HalError>) -> Result<T, HalError> {
        let unmounted = match outcome {
            Err(HalError::Removed) => Err(HalError::Removed),
            _ => self.plain_unmount(),
        };
        let Err(error) = unmounted else {
            return outcome;
        };
        let failed = outcome.and(Err(error));
        match self.mounter.unmount(&self.mount_point, Unmount::Detach) {
            // Gone from the namespace: the next mount starts clean.
            Ok(()) => failed,
            // Still mounted. The call reports its fault all the same; nothing more can be done
            // about the mount.
            Err(_) => failed,
        }
    }

    fn plain_unmount(&mut self) -> Result<(), HalError> {
        self.mounter
            .unmount(&self.mount_point, Unmount::Plain)
            .map_err(|error| fault(&error, HalError::Unmount))
    }
}

impl<L: Locate, M: Mounter> Usb for DeviceUsb<L, M> {
    fn stick(&mut self) -> Result<bool, HalError> {
        Ok(self.locate.locate()?.is_some())
    }

    fn list(&mut self, kind: FileKind) -> Result<Vec<FileName>, HalError> {
        self.on_stick(READ_PLAN, |_, dir| list_dir(dir, kind))
    }

    fn read(&mut self, name: &FileName, max: usize) -> Result<Zeroizing<Vec<u8>>, HalError> {
        self.on_stick(READ_PLAN, |_, dir| {
            read_capped(&dir.join(name.as_str()), max)
        })
    }

    fn write_backup(&mut self, file: &BackupFile) -> Result<Written, HalError> {
        self.write_new(file.name(), file.bytes())
    }

    fn read_written(
        &mut self,
        written: &Written,
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HalError> {
        self.recorded(written)?;
        self.on_stick(READ_PLAN, |_, dir| {
            read_capped(&dir.join(written.name().as_str()), max)
        })
    }

    fn remove_written(&mut self, written: Written) -> Result<(), HalError> {
        self.recorded(&written)?;
        let removed = self.on_stick(WRITE_PLAN, |mounter, dir| {
            remove_synced(mounter, &dir.join(written.name().as_str()), dir)
        });
        if removed.is_ok() {
            self.written = None;
        }
        removed
    }
}

/// The files of `kind` in directory `dir`, by the names `FileName` accepts, in byte order as the
/// simulator lists them. Anything but a file is left out.
fn list_dir(dir: &Path, kind: FileKind) -> Result<Vec<FileName>, HalError> {
    let read = |error: io::Error| fault(&error, HalError::Read);
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(read)? {
        let entry = entry.map_err(read)?;
        if let Some(name) = entry.file_name().to_str().and_then(FileName::new)
            && name.kind() == kind
            && entry.file_type().map_err(read)?.is_file()
        {
            names.push(name);
        }
    }
    names.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(names)
}

/// File `path`'s bytes, read straight into a wiping buffer: `TooLarge` past `max` (`read_bounded`).
fn read_capped(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, HalError> {
    let read = |error: io::Error| fault(&error, HalError::Read);
    let file = File::open(path).map_err(read)?;
    let len = file.metadata().map_err(read)?.len();
    read_bounded(file, len, max)
}

/// The bytes of `file`, `len` long by its metadata, read straight into a wiping buffer: `TooLarge`
/// past `max`. The buffer has room for the file and one byte more, but never more than `max + 1`
/// bytes, so the read stops one byte past `max` and never grows the buffer, which would leave an
/// unwiped copy behind, however large the file.
fn read_bounded<R: Read>(file: R, len: u64, max: usize) -> Result<Zeroizing<Vec<u8>>, HalError> {
    let room = match usize::try_from(len) {
        Ok(len) if len < max => len + 1,
        _ => max.saturating_add(1),
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(room));
    file.take(u64::try_from(room).expect("a usize fits a u64"))
        .read_to_end(&mut bytes)
        .map_err(|error| fault(&error, HalError::Read))?;
    if bytes.len() > max {
        return Err(HalError::TooLarge);
    }
    Ok(bytes)
}

/// All of `bytes` into the new `file`, then the file and its directory `dir` synced to the stick
/// through `mounter`. The file is closed when this returns, so the unmount that follows does not
/// find the stick busy.
fn fill<M: Mounter>(
    mounter: &mut M,
    mut file: File,
    bytes: &[u8],
    dir: &Path,
) -> Result<(), HalError> {
    file.write_all(bytes)
        .map_err(|error| fault(&error, HalError::Write))?;
    mounter
        .sync(&file)
        .map_err(|error| fault(&error, HalError::Sync))?;
    sync_dir(mounter, dir)
}

/// Removes file `path`, then syncs its directory `dir` through `mounter`.
fn remove_synced<M: Mounter>(mounter: &mut M, path: &Path, dir: &Path) -> Result<(), HalError> {
    fs::remove_file(path).map_err(|error| fault(&error, HalError::Remove))?;
    sync_dir(mounter, dir)
}

/// Syncs directory `dir` through `mounter`, so that a file created or removed in it is on the
/// stick.
fn sync_dir<M: Mounter>(mounter: &mut M, dir: &Path) -> Result<(), HalError> {
    File::open(dir)
        .and_then(|dir| mounter.sync(&dir))
        .map_err(|error| fault(&error, HalError::Sync))
}
