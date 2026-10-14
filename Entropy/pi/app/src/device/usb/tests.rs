//! The stick's tests (tasks/todo.md, M4 group 8, Q39 (f)).
//!
//! - On every host: the finder over a `/sys/block` in memory; the mount plans, the unmounts and the
//!   errno table, pinned; and `hal::Usb`'s contract over a temp dir standing in for the mounted
//!   stick and a recording `Mounter`, as pi/sim/tests/hal.rs holds the simulator to it. Nothing is
//!   mounted there, so these tests pin which mount and which syncs each call asks for, not what
//!   the kernel makes of them.
//! - On Linux: the plans against the kernel's flags; and, as root in CI's test job only
//!   (`#[ignore]`d), `loop_device`, the same calls on a FAT32 loop device through mount(2) and
//!   umount2(2).

use std::collections::VecDeque;
use std::os::unix::ffi::OsStringExt;

#[cfg(target_os = "linux")]
use nix::mount::{MntFlags, MsFlags};

use super::*;

const BACKUP: &str = "keepcrypt-backup-0a1b2c3d.age";
/// The SD card's disk on the Pi Zero, as `/sys/block/mmcblk0` links.
const SD_CARD: &str = "../devices/platform/soc/20202000.mmc/mmc_host/mmc0/mmc0:aaaa/block/mmcblk0";

/// One entry of a `/sys/block` in memory, and what each read of it gives.
struct Entry {
    name: String,
    link: Result<PathBuf, ErrorKind>,
    ro: Result<&'static [u8], ErrorKind>,
    partition: Result<bool, ErrorKind>,
}

/// A `/sys/block` in memory, as the finder reads it. An entry it no longer holds has vanished
/// since the listing: reading it is `NotFound`.
#[derive(Default)]
struct FakeSys {
    entries: Vec<Entry>,
    /// Names listed after the entries, with nothing behind them.
    unknown: Vec<OsString>,
    /// The error the listing fails with, if any.
    listing: Option<ErrorKind>,
}

impl FakeSys {
    fn entry(&self, name: &str) -> io::Result<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| ErrorKind::NotFound.into())
    }
}

impl SysBlock for FakeSys {
    fn entries(&mut self) -> io::Result<Vec<OsString>> {
        if let Some(kind) = self.listing {
            return Err(kind.into());
        }
        let names = self.entries.iter().map(|entry| OsString::from(&entry.name));
        Ok(names.chain(self.unknown.iter().cloned()).collect())
    }

    fn device_link(&mut self, name: &str) -> io::Result<PathBuf> {
        self.entry(name)?.link.clone().map_err(io::Error::from)
    }

    fn ro(&mut self, name: &str) -> io::Result<Vec<u8>> {
        self.entry(name)?
            .ro
            .map(<[u8]>::to_vec)
            .map_err(io::Error::from)
    }

    fn has_partition(&mut self, name: &str) -> io::Result<bool> {
        self.entry(name)?.partition.map_err(io::Error::from)
    }
}

/// Entry `name`, linking to `link`: writable, with no first partition.
fn entry(name: &str, link: &str) -> Entry {
    Entry {
        name: name.to_owned(),
        link: Ok(PathBuf::from(link)),
        ro: Ok(b"0\n"),
        partition: Ok(false),
    }
}

/// A USB stick's disk on the Pi Zero, with a first partition: under the USB controller and its
/// root hub `usb1`, as `/sys/block/<name>` links.
fn usb_disk(name: &str) -> Entry {
    let link = format!(
        "../devices/platform/soc/20980000.usb/usb1/1-1/1-1:1.0/host0/target0:0:0/0:0:0:0/block/{name}"
    );
    Entry {
        partition: Ok(true),
        ..entry(name, &link)
    }
}

/// The block device nodes' folder in these tests: a relative name that nothing opens.
fn dev() -> PathBuf {
    PathBuf::from("dev")
}

/// A `/sys/block` with the SD card and one stick, `sda`, which has a first partition.
fn one_stick() -> FakeSys {
    FakeSys {
        entries: vec![entry("mmcblk0", SD_CARD), usb_disk("sda")],
        ..FakeSys::default()
    }
}

/// `name` as the app hands it over.
fn name(name: &str) -> FileName {
    FileName::new(name).expect("an accepted name")
}

/// One call a `Mounter` was asked to make.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Mount {
        device: PathBuf,
        target: PathBuf,
        plan: MountPlan,
    },
    Unmount {
        target: PathBuf,
        how: Unmount,
    },
}

/// One sync a `Mounter` was asked for: of a file, with its length then, or of a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flushed {
    File(u64),
    Dir,
}

/// Records every call and mounts nothing; a call fails, with an errno, when told to. Syncs are
/// recorded apart, each only while the stick is mounted.
#[derive(Default)]
struct Recorder {
    calls: Vec<Call>,
    /// The errno the next mount fails with.
    mount_fails: Option<i32>,
    /// The errnos the next plain unmounts fail with, in order.
    plain_fails: VecDeque<i32>,
    /// The errno every lazy detach fails with.
    detach_fails: Option<i32>,
    syncs: Vec<Flushed>,
    /// What the next syncs give, in order: an errno to fail with, or `None`.
    sync_fails: VecDeque<Option<i32>>,
    /// True from a mount that worked until an unmount that did.
    mounted: bool,
}

impl Mounter for Recorder {
    fn mount(&mut self, device: &Path, target: &Path, plan: MountPlan) -> io::Result<()> {
        self.calls.push(Call::Mount {
            device: device.to_path_buf(),
            target: target.to_path_buf(),
            plan,
        });
        match self.mount_fails.take() {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => {
                self.mounted = true;
                Ok(())
            }
        }
    }

    fn unmount(&mut self, target: &Path, how: Unmount) -> io::Result<()> {
        self.calls.push(Call::Unmount {
            target: target.to_path_buf(),
            how,
        });
        let fails = match how {
            Unmount::Plain => self.plain_fails.pop_front(),
            Unmount::Detach => self.detach_fails,
        };
        match fails {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => {
                self.mounted = false;
                Ok(())
            }
        }
    }

    fn sync(&mut self, file: &File) -> io::Result<()> {
        assert!(self.mounted, "a sync while the stick is not mounted");
        let metadata = file.metadata()?;
        self.syncs.push(if metadata.is_dir() {
            Flushed::Dir
        } else {
            Flushed::File(metadata.len())
        });
        match self.sync_fails.pop_front().flatten() {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => Ok(()),
        }
    }
}

/// `hal::Usb` over `sys` and a recorder, with `dir` as the mount point.
fn device(sys: FakeSys, dir: &Path) -> DeviceUsb<Finder<FakeSys>, Recorder> {
    DeviceUsb::new(
        Finder::new(sys, dev()),
        Recorder::default(),
        dir.to_path_buf(),
    )
}

/// The mount of `one_stick`'s stick at `dir` as `plan` says.
fn mount(dir: &Path, plan: MountPlan) -> Call {
    Call::Mount {
        device: dev().join("sda1"),
        target: dir.to_path_buf(),
        plan,
    }
}

fn unmount(dir: &Path, how: Unmount) -> Call {
    Call::Unmount {
        target: dir.to_path_buf(),
        how,
    }
}

/// The calls of stick calls that each mounted as its plan says and unmounted plainly.
fn calls(dir: &Path, plans: &[MountPlan]) -> Vec<Call> {
    plans
        .iter()
        .flat_map(|&plan| [mount(dir, plan), unmount(dir, Unmount::Plain)])
        .collect()
}

/// A fresh, empty folder under the OS's temp dir for test `test`, standing in for the mounted
/// stick. `clear` removes it with what it holds.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keepcrypt-pi-usb-{}-{test}", std::process::id()));
    clear(&dir);
    fs::create_dir(&dir).expect("a scratch folder");
    dir
}

fn clear(dir: &Path) {
    match fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("cannot clear {}: {error}", dir.display()),
    }
}

/// The names in `dir`, in byte order.
fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("a listing")
        .map(|entry| {
            let name = entry.expect("an entry").file_name();
            name.into_string().expect("a UTF-8 name")
        })
        .collect();
    names.sort();
    names
}

/// The names of a listing.
fn names(listed: Vec<FileName>) -> Vec<String> {
    listed.iter().map(|name| name.as_str().to_owned()).collect()
}

#[test]
fn the_finder_takes_the_one_usb_disk_by_its_first_partition_or_whole() {
    let sata = "../devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda";
    let sys = FakeSys {
        entries: vec![
            entry("mmcblk0", SD_CARD),
            entry("loop0", "../devices/virtual/block/loop0"),
            entry("ram0", "../devices/virtual/block/ram0"),
            entry("sda", sata),
            usb_disk("sdb"),
        ],
        ..FakeSys::default()
    };
    let mut finder = Finder::new(sys, dev());
    assert_eq!(
        finder.locate(),
        Ok(Some(Stick {
            device: dev().join("sdb1"),
            read_only: false,
        }))
    );
    finder.sys.entries[4].partition = Ok(false);
    assert_eq!(
        finder.locate(),
        Ok(Some(Stick {
            device: dev().join("sdb"),
            read_only: false,
        }))
    );
}

#[test]
fn the_finder_ignores_every_other_block_device() {
    let sys = FakeSys {
        entries: vec![
            entry("mmcblk0", SD_CARD),
            entry("loop0", "../devices/virtual/block/loop0"),
            entry("ram0", "../devices/virtual/block/ram0"),
            entry(
                "sda",
                "../devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda",
            ),
            // On a USB bus, but no `sd` disk: a CD drive, and names that are not `sd` and letters.
            usb_disk("sr0"),
            usb_disk("sd"),
            usb_disk("sdA"),
            usb_disk("sd1"),
            usb_disk("xsda"),
            // `sd` disks whose paths only look like USB: no component is a root hub, `usb` and a
            // bus number.
            entry(
                "sdb",
                "../devices/platform/soc/20980000.usb/host0/target0:0:0/0:0:0:0/block/sdb",
            ),
            entry("sdc", "../devices/virtual/usbmon/block/sdc"),
            entry("sdd", "../devices/usb/block/sdd"),
            entry("sde", "../devices/xusb1/block/sde"),
            entry("sdf", "../devices/usb1x/block/sdf"),
        ],
        // Not UTF-8, so no `sd` name: looking it up would find nothing, which is `Removed`.
        unknown: vec![OsString::from_vec(b"sd\xff".to_vec())],
        listing: None,
    };
    assert_eq!(Finder::new(sys, dev()).locate(), Ok(None));
}

#[test]
fn two_usb_disks_are_more_than_one_stick() {
    for [first, second] in [["sda", "sdb"], ["sdz", "sdaa"]] {
        let sys = FakeSys {
            entries: vec![entry("mmcblk0", SD_CARD), usb_disk(first), usb_disk(second)],
            ..FakeSys::default()
        };
        assert_eq!(Finder::new(sys, dev()).locate(), Err(HalError::ManySticks));
    }
    assert_eq!(
        HalError::ManySticks.text(),
        "more than one USB stick is inserted"
    );
    assert!(!HalError::ManySticks.halts());
}

#[test]
fn the_ro_attribute_marks_a_write_protected_stick() {
    let locate = |ro: &'static [u8]| {
        let mut sys = one_stick();
        sys.entries[1].ro = Ok(ro);
        Finder::new(sys, dev()).locate()
    };
    for (ro, read_only) in [(&b"1\n"[..], true), (&b"0\n"[..], false)] {
        assert_eq!(
            locate(ro),
            Ok(Some(Stick {
                device: dev().join("sda1"),
                read_only,
            }))
        );
        assert_eq!(ro_flag(ro), Ok(read_only));
    }
    // Anything else leaves the stick's state unknown, and the stick unused.
    for unknown in [
        &b""[..],
        b"0",
        b"1",
        b"2\n",
        b"01\n",
        b" 1\n",
        b"1\n\n",
        b"true\n",
    ] {
        assert_eq!(ro_flag(unknown), Err(HalError::Mount), "{unknown:?}");
        assert_eq!(locate(unknown), Err(HalError::Mount), "{unknown:?}");
    }
}

#[test]
fn an_entry_that_vanished_is_a_stick_pulled_out_and_other_sysfs_faults_are_mount() {
    for (kind, expected) in [
        (ErrorKind::NotFound, HalError::Removed),
        (ErrorKind::PermissionDenied, HalError::Mount),
        (ErrorKind::Other, HalError::Mount),
    ] {
        // Its link, its `ro` attribute or its partition, read after the listing.
        for read in 0..3 {
            let mut sys = one_stick();
            let stick = &mut sys.entries[1];
            match read {
                0 => stick.link = Err(kind),
                1 => stick.ro = Err(kind),
                _ => stick.partition = Err(kind),
            }
            assert_eq!(
                Finder::new(sys, dev()).locate(),
                Err(expected),
                "{kind:?}, read {read}"
            );
        }
    }
    // Listed, then gone from `/sys/block` altogether.
    let mut finder = Finder::new(one_stick(), dev());
    finder.sys.unknown.push(OsString::from("sdb"));
    assert_eq!(finder.locate(), Err(HalError::Removed));
    // `/sys/block` cannot be listed.
    let sys = FakeSys {
        listing: Some(ErrorKind::PermissionDenied),
        ..one_stick()
    };
    assert_eq!(Finder::new(sys, dev()).locate(), Err(HalError::Mount));
}

#[test]
fn the_mount_plans_unmounts_and_errno_table_are_pinned() {
    // Linux's values (include/uapi/linux/mount.h; include/linux/fs.h).
    assert_eq!([MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC], [1, 2, 4, 8]);
    assert_eq!(
        READ_PLAN,
        MountPlan {
            fstype: "vfat",
            flags: 15,
        }
    );
    assert_eq!(
        WRITE_PLAN,
        MountPlan {
            fstype: "vfat",
            flags: 14,
        }
    );
    assert_eq!([Unmount::Plain.flags(), Unmount::Detach.flags()], [0, 2]);

    // The errno table names these whatever the step; any other error is the step's own fault: no
    // permission (EPERM, EACCES), no such file (ENOENT), an I/O error (EIO), a busy mount (EBUSY),
    // an unknown filesystem (EINVAL), or an error with no errno.
    for step in [
        HalError::Mount,
        HalError::Read,
        HalError::Write,
        HalError::Sync,
        HalError::Unmount,
        HalError::Remove,
    ] {
        for (errno, named) in [
            (17, HalError::Exists),
            (30, HalError::ReadOnly),
            (28, HalError::Write),
            (27, HalError::Write),
            (19, HalError::Removed),
            (6, HalError::Removed),
        ] {
            assert_eq!(fault(&io::Error::from_raw_os_error(errno), step), named);
        }
        for errno in [1, 2, 5, 13, 16, 22] {
            assert_eq!(fault(&io::Error::from_raw_os_error(errno), step), step);
        }
        assert_eq!(fault(&io::Error::other("no errno"), step), step);
    }
}

#[test]
fn with_no_stick_or_more_than_one_every_call_is_refused_before_any_mount() {
    let dir = scratch("refused");
    fs::write(dir.join(BACKUP), b"earlier").expect("a file");
    let none = FakeSys {
        entries: vec![entry("mmcblk0", SD_CARD)],
        ..FakeSys::default()
    };
    let two = FakeSys {
        entries: vec![usb_disk("sda"), usb_disk("sdb")],
        ..FakeSys::default()
    };
    for (sys, refusal) in [(none, HalError::NoStick), (two, HalError::ManySticks)] {
        let mut usb = device(sys, &dir);
        let inserted = match refusal {
            HalError::NoStick => Ok(false),
            _ => Err(refusal),
        };
        assert_eq!(usb.stick(), inserted);
        assert_eq!(usb.list(FileKind::Age), Err(refusal));
        assert_eq!(usb.read(&name(BACKUP), 64), Err(refusal));
        let fresh = "keepcrypt-backup-00000000.age";
        assert_eq!(usb.write_new(fresh, b"new"), Err(refusal));
        assert!(usb.mounter.calls.is_empty(), "{refusal:?}");
    }
    assert_eq!(names_in(&dir), [BACKUP]);
    clear(&dir);
}

#[test]
fn listings_hold_only_files_of_the_kind_with_accepted_names_in_byte_order_read_only() {
    let dir = scratch("list");
    for file in [
        "b.age",
        "a.AGE",
        "snap.kcr",
        "notes.txt",
        "x y.age",
        "c.age.txt",
    ] {
        fs::write(dir.join(file), file).expect("a file");
    }
    fs::create_dir(dir.join("folder.age")).expect("a folder");
    let mut usb = device(one_stick(), &dir);
    assert_eq!(usb.stick(), Ok(true));
    let ages = usb.list(FileKind::Age).expect("a listing");
    assert_eq!(names(ages), ["a.AGE", "b.age"]);
    let kcrs = usb.list(FileKind::Kcr).expect("a listing");
    assert_eq!(names(kcrs), ["snap.kcr"]);
    assert_eq!(usb.mounter.calls, calls(&dir, &[READ_PLAN, READ_PLAN]));
    clear(&dir);
}

#[test]
fn reads_are_read_only_and_stop_one_byte_past_the_limit_without_growing_the_buffer() {
    let dir = scratch("read");
    fs::write(dir.join("b.age"), b"b.age bytes").expect("a file");
    fs::create_dir(dir.join("folder.age")).expect("a folder");
    let mut usb = device(one_stick(), &dir);
    for max in [11, 64] {
        let read = usb.read(&name("b.age"), max).expect("read");
        assert_eq!(&read[..], b"b.age bytes");
        // Room for the file and one byte more: the read never grew the buffer.
        assert_eq!(read.capacity(), 12);
    }
    for max in [10, 0] {
        assert_eq!(usb.read(&name("b.age"), max), Err(HalError::TooLarge));
    }
    assert_eq!(usb.read(&name("gone.age"), 64), Err(HalError::Read));
    assert_eq!(usb.read(&name("folder.age"), 64), Err(HalError::Read));
    assert_eq!(usb.mounter.calls, calls(&dir, &[READ_PLAN; 6]));
    clear(&dir);
}

/// A file of `left` bytes that counts the bytes read from it.
struct Counting {
    left: usize,
    read: usize,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.left.min(buf.len());
        buf[..count].fill(0xA5);
        self.left -= count;
        self.read += count;
        Ok(count)
    }
}

/// A file far larger than the limit, as a hostile stick could hold: one byte past `max` is read, and
/// no more, so the buffer never grows and the Pi's memory is never filled.
#[test]
fn a_read_takes_one_byte_past_the_limit_and_no_more() {
    let mib = 1 << 20;
    let mut file = Counting { left: mib, read: 0 };
    let len = u64::try_from(mib).expect("a MiB");
    assert_eq!(read_bounded(&mut file, len, 10), Err(HalError::TooLarge));
    assert_eq!(file.read, 11);
    let mut file = Counting { left: mib, read: 0 };
    let read = read_bounded(&mut file, len, mib).expect("read");
    assert_eq!(
        (read.len(), read.capacity(), file.read),
        (mib, mib + 1, mib)
    );
}

/// A call that fails keeps its own fault when the unmount after it fails too, and the stick is still
/// detached: a read of a missing file is `Read`, and a write over an existing name `Exists`, not
/// `Unmount`.
#[test]
fn a_calls_fault_comes_before_a_failed_unmounts() {
    let dir = scratch("fault-and-unmount");
    fs::write(dir.join(BACKUP), b"earlier").expect("a file");
    let mut usb = device(one_stick(), &dir);
    usb.mounter.plain_fails = VecDeque::from([16]);
    assert_eq!(usb.read(&name("gone.age"), 64), Err(HalError::Read));
    usb.mounter.plain_fails = VecDeque::from([16]);
    assert_eq!(usb.write_new(BACKUP, b"new"), Err(HalError::Exists));
    let failed = |plan| {
        [
            mount(&dir, plan),
            unmount(&dir, Unmount::Plain),
            unmount(&dir, Unmount::Detach),
        ]
    };
    assert_eq!(
        usb.mounter.calls,
        [failed(READ_PLAN), failed(WRITE_PLAN)].concat()
    );
    assert_eq!(fs::read(dir.join(BACKUP)).expect("the file"), b"earlier");
    clear(&dir);
}

#[test]
fn a_write_creates_a_new_file_that_alone_can_be_read_back_and_removed() {
    let dir = scratch("write");
    fs::write(dir.join("other.age"), b"other").expect("a file");
    let mut usb = device(one_stick(), &dir);
    let written = usb.write_new(BACKUP, b"age file").expect("written");
    assert_eq!(written.name().as_str(), BACKUP);
    assert_eq!(fs::read(dir.join(BACKUP)).expect("the backup"), b"age file");
    let back = usb.read_written(&written, 64).expect("read back");
    assert_eq!(&back[..], b"age file");
    assert_eq!(usb.read_written(&written, 7), Err(HalError::TooLarge));

    // Another file, or the backup's name in another letter case (the same file on FAT), is neither
    // read back nor removed through a `Written`, and the stick is not even mounted for it.
    let made = usb.mounter.calls.len();
    for other in ["other.age", "KEEPCRYPT-BACKUP-0A1B2C3D.AGE"] {
        let other = || Written::new(name(other));
        assert_eq!(usb.read_written(&other(), 64), Err(HalError::NotWritten));
        assert_eq!(usb.remove_written(other()), Err(HalError::NotWritten));
    }
    assert_eq!(usb.mounter.calls.len(), made);

    assert_eq!(usb.remove_written(written), Ok(()));
    assert_eq!(names_in(&dir), ["other.age"]);
    // Once removed, it is no longer the file just written.
    assert_eq!(
        usb.remove_written(Written::new(name(BACKUP))),
        Err(HalError::NotWritten)
    );
    assert_eq!(
        usb.mounter.calls,
        calls(&dir, &[WRITE_PLAN, READ_PLAN, READ_PLAN, WRITE_PLAN])
    );
    clear(&dir);
}

/// Step 5: the new file is synced once it holds every byte, then its directory, while the stick
/// is mounted; a removal syncs the directory. A sync that fails is `Sync`, or the errno table's
/// fault (a full stick's ENOSPC is `Write`), and the file the write created is removed, its
/// directory synced, before the plain unmount.
#[test]
fn a_write_syncs_its_file_then_its_directory_and_a_failed_sync_removes_the_file() {
    let dir = scratch("sync");
    let mut usb = device(one_stick(), &dir);
    let written = usb.write_new(BACKUP, b"age file").expect("written");
    assert_eq!(usb.mounter.syncs, [Flushed::File(8), Flushed::Dir]);
    assert_eq!(usb.remove_written(written), Ok(()));
    assert_eq!(usb.mounter.syncs[2..], [Flushed::Dir]);
    let (file, folder) = (Flushed::File(8), Flushed::Dir);
    for (fails, fault, syncs) in [
        (&[Some(5)][..], HalError::Sync, &[file, folder][..]),
        (&[Some(28)], HalError::Write, &[file, folder]),
        (&[None, Some(5)], HalError::Sync, &[file, folder, folder]),
    ] {
        usb.mounter.calls.clear();
        usb.mounter.syncs.clear();
        usb.mounter.sync_fails = fails.iter().copied().collect();
        assert_eq!(usb.write_new(BACKUP, b"age file"), Err(fault));
        assert_eq!(usb.mounter.syncs, syncs);
        assert!(names_in(&dir).is_empty());
        assert_eq!(usb.mounter.calls, calls(&dir, &[WRITE_PLAN]));
    }
    assert_eq!(
        usb.read_written(&Written::new(name(BACKUP)), 64),
        Err(HalError::NotWritten)
    );
    clear(&dir);
}

#[test]
fn a_refused_write_leaves_an_existing_file_untouched() {
    let dir = scratch("refused-write");
    fs::write(dir.join(BACKUP), b"earlier").expect("a file");
    let mut usb = device(one_stick(), &dir);
    // An existing name: the create fails, so nothing was created and nothing is removed.
    assert_eq!(usb.write_new(BACKUP, b"new"), Err(HalError::Exists));
    assert_eq!(fs::read(dir.join(BACKUP)).expect("the file"), b"earlier");
    // A name `FileName` refuses, and a stick the kernel marks read-only: refused before anything
    // is mounted.
    assert_eq!(usb.write_new("../x.age", b"new"), Err(HalError::Write));
    usb.locate.sys.entries[1].ro = Ok(b"1\n");
    let fresh = "keepcrypt-backup-00000000.age";
    assert_eq!(usb.write_new(fresh, b"new"), Err(HalError::ReadOnly));
    assert_eq!(usb.mounter.calls, calls(&dir, &[WRITE_PLAN]));
    assert_eq!(names_in(&dir), [BACKUP]);
    // A read-only stick is still read.
    let read = usb.read(&name(BACKUP), 64).expect("read");
    assert_eq!(&read[..], b"earlier");
    clear(&dir);
}

#[test]
fn a_later_write_attempt_leaves_no_earlier_file_readable_or_removable() {
    let later = "keepcrypt-backup-00000000.age";
    for attempt in [
        "over the name",
        "read-only",
        "mount",
        "bad name",
        "no stick",
    ] {
        let dir = scratch("later");
        let mut usb = device(one_stick(), &dir);
        assert!(usb.write_new(BACKUP, b"earlier").is_ok());
        let refused = match attempt {
            "over the name" => usb.write_new(BACKUP, b"later"),
            "read-only" => {
                usb.locate.sys.entries[1].ro = Ok(b"1\n");
                usb.write_new(later, b"later")
            }
            "mount" => {
                usb.mounter.mount_fails = Some(22);
                usb.write_new(later, b"later")
            }
            "bad name" => usb.write_new("later.txt", b"later"),
            _ => {
                usb.locate.sys.entries.pop();
                usb.write_new(later, b"later")
            }
        };
        assert!(refused.is_err(), "{attempt}");
        let minted = || Written::new(name(BACKUP));
        assert_eq!(
            usb.read_written(&minted(), 64),
            Err(HalError::NotWritten),
            "{attempt}"
        );
        assert_eq!(
            usb.remove_written(minted()),
            Err(HalError::NotWritten),
            "{attempt}"
        );
        assert_eq!(names_in(&dir), [BACKUP], "{attempt}");
        clear(&dir);
    }
}

#[test]
fn a_failed_mount_is_named_and_nothing_is_unmounted() {
    let dir = scratch("mount-fault");
    let mut usb = device(one_stick(), &dir);
    // An exFAT or NTFS stick, which vfat refuses (EINVAL); an I/O error; a stick pulled out
    // (ENODEV, ENXIO); a write mount of a stick the kernel then finds read-only (EROFS).
    for (errno, expected) in [
        (22, HalError::Mount),
        (5, HalError::Mount),
        (19, HalError::Removed),
        (6, HalError::Removed),
        (30, HalError::ReadOnly),
    ] {
        usb.mounter.mount_fails = Some(errno);
        assert_eq!(usb.list(FileKind::Age), Err(expected), "{errno}");
        usb.mounter.mount_fails = Some(errno);
        assert_eq!(usb.write_new(BACKUP, b"x"), Err(expected), "{errno}");
    }
    assert_eq!(usb.mounter.calls.len(), 10);
    assert!(
        usb.mounter
            .calls
            .iter()
            .all(|call| matches!(call, Call::Mount { .. }))
    );
    assert!(names_in(&dir).is_empty());
    clear(&dir);
}

#[test]
fn a_failed_unmount_ends_in_a_lazy_detach_and_the_next_mount_starts_clean() {
    let dir = scratch("unmount-fault");
    fs::write(dir.join("b.age"), b"b").expect("a file");
    let mut usb = device(one_stick(), &dir);
    // A busy mount (EBUSY): `Unmount`, after a lazy detach, and so when the detach fails too.
    usb.mounter.plain_fails = VecDeque::from([16]);
    assert_eq!(usb.list(FileKind::Age), Err(HalError::Unmount));
    usb.mounter.plain_fails = VecDeque::from([16]);
    usb.mounter.detach_fails = Some(16);
    assert_eq!(usb.read(&name("b.age"), 64), Err(HalError::Unmount));
    usb.mounter.detach_fails = None;
    // The next call mounts and unmounts as ever.
    assert_eq!(
        usb.list(FileKind::Age).map(names),
        Ok(vec!["b.age".to_owned()])
    );
    // The stick gone at the unmount (ENXIO): `Removed`, after a lazy detach.
    usb.mounter.plain_fails = VecDeque::from([6]);
    assert_eq!(usb.read(&name("b.age"), 64), Err(HalError::Removed));

    let failed = [
        mount(&dir, READ_PLAN),
        unmount(&dir, Unmount::Plain),
        unmount(&dir, Unmount::Detach),
    ];
    let expected = [&failed[..], &failed, &calls(&dir, &[READ_PLAN]), &failed].concat();
    assert_eq!(usb.mounter.calls, expected);
    clear(&dir);
}

#[test]
fn a_write_whose_unmount_fails_removes_the_file_it_created_and_nothing_else() {
    let dir = scratch("write-unmount");
    fs::write(dir.join("other.age"), b"other").expect("a file");
    let mut usb = device(one_stick(), &dir);
    // Step 6 fails, and the second try after the removal works.
    usb.mounter.plain_fails = VecDeque::from([16]);
    assert_eq!(usb.write_new(BACKUP, b"age file"), Err(HalError::Unmount));
    assert_eq!(names_in(&dir), ["other.age"]);
    // Both fail: then a lazy detach as well.
    usb.mounter.plain_fails = VecDeque::from([16, 16]);
    assert_eq!(usb.write_new(BACKUP, b"age file"), Err(HalError::Unmount));
    assert_eq!(names_in(&dir), ["other.age"]);
    // Neither attempt left a file just written.
    assert_eq!(
        usb.read_written(&Written::new(name(BACKUP)), 64),
        Err(HalError::NotWritten)
    );
    let plain = || unmount(&dir, Unmount::Plain);
    assert_eq!(
        usb.mounter.calls,
        [
            mount(&dir, WRITE_PLAN),
            plain(),
            plain(),
            mount(&dir, WRITE_PLAN),
            plain(),
            plain(),
            unmount(&dir, Unmount::Detach),
        ]
    );
    clear(&dir);
}

#[test]
fn a_removal_that_fails_says_so_and_leaves_the_record() {
    let dir = scratch("remove-fault");
    let mut usb = device(one_stick(), &dir);
    let written = usb.write_new(BACKUP, b"age file").expect("written");
    // Gone from the stick by other means: `Remove`, and the name is still the file just written.
    fs::remove_file(dir.join(BACKUP)).expect("removed by hand");
    assert_eq!(usb.remove_written(written), Err(HalError::Remove));
    assert_eq!(
        usb.read_written(&Written::new(name(BACKUP)), 64),
        Err(HalError::Read)
    );
    assert_eq!(
        usb.mounter.calls,
        calls(&dir, &[WRITE_PLAN, WRITE_PLAN, READ_PLAN])
    );
    clear(&dir);
}

#[test]
fn after_a_stick_pulled_out_the_mount_is_detached_at_once() {
    let dir = Path::new("mnt");
    let mut usb = device(one_stick(), dir);
    assert_eq!(
        usb.unmount::<()>(Err(HalError::Removed)),
        Err(HalError::Removed)
    );
    assert_eq!(usb.unmount::<()>(Err(HalError::Read)), Err(HalError::Read));
    assert_eq!(usb.unmount(Ok(7)), Ok(7));
    assert_eq!(
        usb.mounter.calls,
        [
            unmount(dir, Unmount::Detach),
            unmount(dir, Unmount::Plain),
            unmount(dir, Unmount::Plain),
        ]
    );
}

/// The plans' flags are the kernel's, as nix (and libc) name them.
#[cfg(target_os = "linux")]
#[test]
fn the_mount_plans_hold_the_kernels_flags() {
    let named = |plan: MountPlan| MsFlags::from_bits(plan.flags);
    let never = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    assert_eq!(named(READ_PLAN), Some(MsFlags::MS_RDONLY | never));
    assert_eq!(named(WRITE_PLAN), Some(never));
}

/// The loop device CI's test job makes (tasks/todo.md, M4 group 12), from the environment: its
/// block device, its `ro` attribute, the mount point, and this process's mountinfo.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LoopEnv {
    dev: PathBuf,
    ro: PathBuf,
    mnt: PathBuf,
    mountinfo: PathBuf,
}

#[cfg(target_os = "linux")]
impl LoopEnv {
    /// From `KC_LOOP_DEV`, `KC_LOOP_RO`, `KC_LOOP_MNT` and `KC_MOUNTINFO`; a missing one fails the
    /// test.
    fn from_env() -> Self {
        let var = |name: &str| match std::env::var_os(name) {
            Some(value) => PathBuf::from(value),
            None => panic!("{name} is not set; CI's test job sets it (tasks/todo.md, M4 group 12)"),
        };
        LoopEnv {
            dev: var("KC_LOOP_DEV"),
            ro: var("KC_LOOP_RO"),
            mnt: var("KC_LOOP_MNT"),
            mountinfo: var("KC_MOUNTINFO"),
        }
    }

    /// The mounts at the mount point now (proc_pid_mountinfo(5)): each one's per-mount options,
    /// filesystem type and source.
    fn mounts(&self) -> Vec<[String; 3]> {
        let text = fs::read_to_string(&self.mountinfo).expect("the mountinfo");
        let mnt = self.mnt.to_str().expect("a UTF-8 mount point");
        text.lines()
            .filter_map(|line| {
                let (mount, filesystem) = line.split_once(" - ")?;
                let mount: Vec<&str> = mount.split(' ').collect();
                let filesystem: Vec<&str> = filesystem.split(' ').collect();
                (mount.get(4) == Some(&mnt))
                    .then(|| [mount[5], filesystem[0], filesystem[1]].map(str::to_owned))
            })
            .collect()
    }

    /// Nothing is mounted at the mount point: the check after every call.
    fn unmounted<T>(&self, result: T) -> T {
        let mounts = self.mounts();
        assert!(mounts.is_empty(), "left mounted: {mounts:?}");
        result
    }
}

/// The loop device as the stick, bypassing the finder: its `ro` attribute is read for each call.
#[cfg(target_os = "linux")]
struct LoopStick(LoopEnv);

#[cfg(target_os = "linux")]
impl Locate for LoopStick {
    fn locate(&mut self) -> Result<Option<Stick>, HalError> {
        let ro = fs::read(&self.0.ro).expect("the loop device's ro attribute");
        Ok(Some(Stick {
            device: self.0.dev.clone(),
            read_only: ro_flag(&ro)?,
        }))
    }
}

/// mount(2) and umount2(2) through nix, as group 10's glue makes them, checking each mount against
/// mountinfo: one mount at the mount point, vfat from the loop device, `nosuid,nodev,noexec`, and
/// read-only exactly for a read-only plan, where no file can be created (EROFS).
#[cfg(target_os = "linux")]
struct Kernel {
    env: LoopEnv,
    /// Each mount in order: `r` read-only, `w` read-write.
    mounts: String,
    /// Holds the mount point open from the next plain unmount until the detach, so that the plain
    /// unmount finds the mount busy and only the lazy detach ends it.
    busy: bool,
    held: Option<File>,
}

#[cfg(target_os = "linux")]
impl Mounter for Kernel {
    fn mount(&mut self, device: &Path, target: &Path, plan: MountPlan) -> io::Result<()> {
        let flags = MsFlags::from_bits(plan.flags).expect("flags the kernel defines");
        nix::mount::mount(Some(device), target, Some(plan.fstype), flags, None::<&str>)?;
        let mounts = self.env.mounts();
        let [[options, fstype, source]] = mounts.as_slice() else {
            panic!("one mount at the mount point, not {mounts:?}");
        };
        assert_eq!(fstype, "vfat");
        assert_eq!(Path::new(source), self.env.dev);
        let options: Vec<&str> = options.split(',').collect();
        let read_only = plan.flags & MS_RDONLY != 0;
        let mode = if read_only { "ro" } else { "rw" };
        for option in [mode, "nosuid", "nodev", "noexec"] {
            assert!(options.contains(&option), "{option} in {options:?}");
        }
        if read_only {
            let probe = fs::write(target.join("probe.age"), b"probe");
            let refused = probe.expect_err("no file is created on a read-only mount");
            assert_eq!(refused.raw_os_error(), Some(EROFS));
        }
        self.mounts.push(if read_only { 'r' } else { 'w' });
        Ok(())
    }

    fn unmount(&mut self, target: &Path, how: Unmount) -> io::Result<()> {
        if self.busy && how == Unmount::Plain {
            self.held = Some(File::open(target)?);
        }
        let flags = MntFlags::from_bits(how.flags()).expect("flags the kernel defines");
        let unmounted = nix::mount::umount2(target, flags).map_err(io::Error::from);
        if how == Unmount::Detach {
            self.busy = false;
            self.held = None;
        }
        unmounted
    }
}

/// Group 8's proof on the kernel: `DeviceUsb` over the FAT32 loop device CI's test job makes, run
/// as root (tasks/todo.md, M4 groups 8 and 12):
/// - a create-new write; a second write of its name is `Exists`, and so is a write whose name
///   differs only in case from a file written there first, and both files stay byte for byte;
/// - every listing and read mounts read-only, where no file can be created (EROFS), and the write
///   and the removal read-write, all `nosuid,nodev,noexec`;
/// - the read-back on a fresh read-only mount, and the removal of the file just written;
/// - a busy mount's failed unmount ends in a lazy detach, and the next mount starts clean;
/// - nothing is left mounted after any call.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root and the loop device CI's test job makes (tasks/todo.md, M4 group 12)"]
fn loop_device() {
    let env = LoopEnv::from_env();
    let kernel = Kernel {
        env: env.clone(),
        mounts: String::new(),
        busy: false,
        held: None,
    };
    let mut usb = DeviceUsb::new(LoopStick(env.clone()), kernel, env.mnt.clone());
    assert_eq!(env.unmounted(usb.stick()), Ok(true));

    // Their file, whose name differs from the backup's only in case, written there first by hand.
    let theirs = BACKUP.to_uppercase();
    usb.mounter
        .mount(&env.dev, &env.mnt, WRITE_PLAN)
        .expect("mounted by hand");
    fs::write(env.mnt.join(&theirs), b"theirs").expect("their file");
    File::open(&env.mnt)
        .and_then(|dir| dir.sync_all())
        .expect("synced by hand");
    env.unmounted(usb.mounter.unmount(&env.mnt, Unmount::Plain))
        .expect("unmounted by hand");
    // FAT's names ignore case: `Exists`, and their file is as it was.
    assert_eq!(
        env.unmounted(usb.write_new(BACKUP, b"ours")),
        Err(HalError::Exists)
    );
    let read = env.unmounted(usb.read(&name(&theirs), 64)).expect("read");
    assert_eq!(&read[..], b"theirs");

    // A create-new write, then a second of its name: `Exists`, and the file is as it was. After
    // that refusal it is no longer the file just written.
    let first = "keepcrypt-backup-00000000.age";
    let stale = env
        .unmounted(usb.write_new(first, b"first"))
        .expect("written");
    assert_eq!(
        env.unmounted(usb.write_new(first, b"second")),
        Err(HalError::Exists)
    );
    let read = env.unmounted(usb.read(&name(first), 64)).expect("read");
    assert_eq!(&read[..], b"first");
    assert_eq!(
        env.unmounted(usb.read_written(&stale, 64)),
        Err(HalError::NotWritten)
    );

    // The read-back on a fresh read-only mount, and the removal of the file just written.
    let second = "keepcrypt-backup-11111111.age";
    let written = env
        .unmounted(usb.write_new(second, b"backup"))
        .expect("written");
    let back = env
        .unmounted(usb.read_written(&written, 64))
        .expect("read back");
    assert_eq!(&back[..], b"backup");
    let listed = env.unmounted(usb.list(FileKind::Age)).expect("a listing");
    assert_eq!(names(listed), [theirs.as_str(), first, second]);
    assert_eq!(env.unmounted(usb.remove_written(written)), Ok(()));
    let listed = env.unmounted(usb.list(FileKind::Age)).expect("a listing");
    assert_eq!(names(listed), [theirs.as_str(), first]);

    // A busy mount: the plain unmount fails, a lazy detach ends the mount, and the next call
    // mounts as ever.
    usb.mounter.busy = true;
    assert_eq!(
        env.unmounted(usb.list(FileKind::Age)),
        Err(HalError::Unmount)
    );
    assert!(usb.mounter.held.is_none());
    let listed = env.unmounted(usb.list(FileKind::Age)).expect("a listing");
    assert_eq!(listed.len(), 2);

    // Which mount each call made: by hand (w), the refused write over their name (w), its read
    // (r), the first write and its refused second (w w), its read (r), the second write (w), its
    // read-back and the listing (r r), the removal (w), and three listings (r r r).
    assert_eq!(usb.mounter.mounts, "wwrwwrwrrwrrr");
}
