//! The USB stick (tasks/todo.md, M3 group 9; docs/pi-firmware.md "Encrypted backup to a USB
//! stick"; CLAUDE.md rule 8): step 11's backup write, and Home's side flows, "Load registry
//! snapshot" and "Check a backup".
//!
//! - usb-insert looks for a stick once per tick and goes on by itself when one is there.
//! - Home's flows list one kind of file (`.kcr` or `.age`); with more than one, usb-pick lists
//!   them (Q33 (g)). Snapshots are read up to the format's largest size, backups up to 8 KiB.
//! - The backup is written as a new file, read back under a read-only remount and verified; on a
//!   fault, only the file just written is removed, and backup-failed offers Retry (a new file
//!   under the same passphrase) or Skip.
//! - Refusals of what the stick or the user supplied return to their screen with their fixed
//!   text; every other error halts (Q25).

use keepcrypt_core::{
    BackupApp, CreatedBy, TypedBackupPassphrase, decrypt_backup, verify_snapshot,
};
use zeroize::{Zeroize, Zeroizing};

use super::{App, Flow, Note, OUT_OF_ORDER, Refusal, Stage, Stop, refused, usb_fault};
use crate::grid::{self, ENTRIES, ENTRIES_LEN};
use crate::hal::{FileKind, FileName, Hal, HalError};
use crate::input::Key;
use crate::screen::ScreenId;
use crate::screens;

/// The largest backup file core reads (age's 8 KiB limit).
const MAX_BACKUP_BYTES: usize = 8 * 1024;
/// The largest snapshot: the 58-byte header, its 64-byte signature and 2^22 entries of 18 bytes
/// (docs/seal-watchonly-braille.md "Snapshot format").
const MAX_SNAPSHOT_BYTES: usize = 58 + 64 + 18 * (1 << 22);
/// This firmware in the backup's `created-by:` line: `keepcrypt-pi X.Y.Z`, the crate version.
const CREATED_BY: CreatedBy = CreatedBy::new(
    BackupApp::Pi,
    version_part(env!("CARGO_PKG_VERSION_MAJOR")),
    version_part(env!("CARGO_PKG_VERSION_MINOR")),
    version_part(env!("CARGO_PKG_VERSION_PATCH")),
);

/// One part of the crate version, at compile time: a version that is no `u16` fails the build.
const fn version_part(part: &str) -> u16 {
    match u16::from_str_radix(part, 10) {
        Ok(number) => number,
        Err(_) => panic!("a crate version part fits a u16"),
    }
}

impl<H: Hal> App<H> {
    /// A tick on usb-insert: once a stick is there, the flow goes on.
    pub(super) fn look_for_stick(&mut self) -> Result<(), Stop> {
        let Note::Usb(flow) = self.view.note else {
            return Err(OUT_OF_ORDER);
        };
        match self.hal.stick() {
            Ok(false) => Ok(()),
            Ok(true) => match flow {
                Flow::Write => self.write_backup(),
                Flow::Open(kind) => self.list(kind),
            },
            Err(fault) => self.usb_refused(flow, fault),
        }
    }

    /// The files of `kind` on the stick: one is opened, several are listed, none is said.
    fn list(&mut self, kind: FileKind) -> Result<(), Stop> {
        let names = match self.hal.list(kind) {
            Ok(names) => names,
            Err(fault) => return self.usb_refused(Flow::Open(kind), fault),
        };
        if let [name] = names.as_slice() {
            let name = name.clone();
            return self.open(kind, &name);
        }
        self.enter(
            ScreenId::UsbPick,
            Note::Pick {
                kind,
                names,
                problem: None,
            },
        );
        self.redraw()
    }

    /// usb-pick: move, open the file under the cursor, or back to Home.
    pub(super) fn pick(&mut self, key: Key) -> Result<(), Stop> {
        let Note::Pick { kind, names, .. } = &self.view.note else {
            return Err(OUT_OF_ORDER);
        };
        match key {
            Key::Up | Key::Down => {
                let n = names.len();
                self.view.cursor = match key {
                    Key::Up => (self.view.cursor + n - 1) % n,
                    _ => (self.view.cursor + 1) % n,
                };
            }
            Key::Press => {
                let (kind, Some(name)) = (*kind, names.get(self.view.cursor).cloned()) else {
                    return Err(OUT_OF_ORDER);
                };
                return self.open(kind, &name);
            }
            Key::Key1 => self.enter(ScreenId::Home, Note::None),
            Key::Left | Key::Right | Key::Key2 | Key::Key3 => return Err(OUT_OF_ORDER),
        }
        self.redraw()
    }

    /// Opens `name`: a snapshot is verified and loaded (or refused with core's text); a backup's
    /// bytes go into the stage, and its passphrase is asked for behind the privacy gate.
    fn open(&mut self, kind: FileKind, name: &FileName) -> Result<(), Stop> {
        if !matches!(self.held.stage, Stage::Idle) {
            return Err(OUT_OF_ORDER);
        }
        let max = match kind {
            FileKind::Kcr => MAX_SNAPSHOT_BYTES,
            FileKind::Age => MAX_BACKUP_BYTES,
        };
        let file = match self.hal.read(name, max) {
            Ok(file) => file,
            Err(fault) => return self.usb_refused(Flow::Open(kind), fault),
        };
        match kind {
            FileKind::Kcr => {
                self.wait(screens::WAIT_SNAPSHOT)?;
                match verify_snapshot(&file) {
                    Ok(snapshot) => {
                        self.held.snapshot = Some(snapshot);
                        self.enter(ScreenId::SnapshotLoaded, Note::None);
                    }
                    Err(error) => {
                        let refusal = refused(error)?;
                        self.enter(ScreenId::SnapshotFailed, Note::Refused(refusal));
                    }
                }
            }
            FileKind::Age => {
                self.held.stage = Stage::BackupCheck {
                    file,
                    typed: Zeroizing::new(String::with_capacity(ENTRIES_LEN)),
                };
                self.enter(ScreenId::BackupCheckEntry, Note::None);
            }
        }
        self.redraw()
    }

    /// Done on backup-check-entry: the entry is complete, and the next one starts; after the
    /// eighth, the passphrase opens the backup (Q32 (b)). An unrecognised entry or a wrong
    /// passphrase returns to the entry, emptied, with core's text.
    pub(super) fn entry_typed(&mut self) -> Result<(), Stop> {
        let Stage::BackupCheck { file, mut typed } = self.take() else {
            return Err(OUT_OF_ORDER);
        };
        if grid::entry_number(&typed) < ENTRIES {
            typed.push(' ');
            self.held.stage = Stage::BackupCheck { file, typed };
            return self.redraw();
        }
        let entries: Vec<&str> = typed.split(' ').map(grid::letters).collect();
        let passphrase = TypedBackupPassphrase::from_first_four(&entries);
        drop(entries);
        typed.zeroize();
        let refusal = match passphrase {
            Err(error) => refused(error)?,
            Ok(passphrase) => {
                self.wait(screens::WAIT_OPEN)?;
                match decrypt_backup(&file, &passphrase) {
                    Ok(backup) => {
                        let seal = backup.seal().map_err(Stop::Core)?;
                        self.held.stage = Stage::Checked {
                            backup,
                            seal: Box::new(seal),
                        };
                        self.enter(ScreenId::BackupCheckResult, Note::None);
                        return self.redraw();
                    }
                    Err(error) => refused(error)?,
                }
            }
        };
        self.held.stage = Stage::BackupCheck { file, typed };
        self.view.note = Note::Refused(refusal);
        self.redraw()
    }

    /// Step 11's write, once a stick is there: encrypt under the stored passphrase, write a new
    /// file, read it back and verify it (pi-firmware.md USB steps 4 and 5).
    fn write_backup(&mut self) -> Result<(), Stop> {
        self.wait(screens::WAIT_BACKUP)?;
        let file = self.export(|session| session.encrypt_backup(&CREATED_BY))?;
        let written = match self.hal.write_backup(&file) {
            Ok(written) => written,
            Err(fault) => return self.backup_failed(Refusal::Usb(usb_fault(fault)?), None),
        };
        let verdict = match self.hal.read_written(&written, MAX_BACKUP_BYTES) {
            Err(fault) => Err(Refusal::Usb(usb_fault(fault)?)),
            Ok(bytes) => match &self.held.stage {
                Stage::Ready { session, .. } => match session.verify_backup(&bytes) {
                    Ok(()) => Ok(()),
                    Err(error) => Err(refused(error)?),
                },
                _ => return Err(OUT_OF_ORDER),
            },
        };
        match verdict {
            Ok(()) => {
                self.enter(ScreenId::BackupVerified, Note::None);
                self.redraw()
            }
            Err(reason) => {
                // Only the file just written is removed; a fault doing so leaves it, and says so.
                let left = match self.hal.remove_written(written) {
                    Ok(()) => None,
                    Err(fault) => Some(usb_fault(fault)?),
                };
                self.backup_failed(reason, left)
            }
        }
    }

    /// backup-failed, with Retry and Skip: the ceremony stays open (pi-firmware.md USB step 6).
    fn backup_failed(&mut self, reason: Refusal, left: Option<HalError>) -> Result<(), Stop> {
        self.enter(ScreenId::BackupFailed, Note::BackupFailed { reason, left });
        self.redraw()
    }

    /// A USB fault: step 11 says so on backup-failed, Home's flows on usb-pick.
    fn usb_refused(&mut self, flow: Flow, fault: HalError) -> Result<(), Stop> {
        let fault = usb_fault(fault)?;
        match flow {
            Flow::Write => self.backup_failed(Refusal::Usb(fault), None),
            Flow::Open(kind) => {
                self.enter(
                    ScreenId::UsbPick,
                    Note::Pick {
                        kind,
                        names: Vec::new(),
                        problem: Some(fault),
                    },
                );
                self.redraw()
            }
        }
    }
}
