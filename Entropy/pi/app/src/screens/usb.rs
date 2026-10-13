//! The models of the USB screens (tasks/todo.md, M3 group 9; docs/pi-firmware.md "Encrypted backup
//! to a USB stick"): usb-insert for step 11 and Home's side flows, the file picker (Q33 (g)), the
//! snapshot's result, and "Check a backup": the passphrase entry, the result and the re-check QR.
//!
//! - The backup-passphrase entry is typed as the first four letters of each word, or a whole
//!   three-letter word (Q32 (b)). A refusal shows core's text verbatim, and the screen's own
//!   instruction stays under it: core's `PassphraseWords` text asks for 8 list words, which the
//!   grid types by their first fours.
//! - The result shows the backup's fingerprint and Seal ID, and with a snapshot loaded the seal's
//!   registration count "as of" its date (Q33 (l)). Its words show only on request, behind the
//!   privacy gate.

use super::{Page, choices, date_text, fingerprint_hex, grid_text};
use crate::app::{Flow, Held, Note, OUT_OF_ORDER, Stage, Stop, View};
use crate::grid::{self, Grid};
use crate::hal::FileKind;
use crate::input::Key;
use crate::screen::{Class, Item, QR_SIDE, Screen, ScreenId};

/// usb-pick lists this many names a page: a name of 64 characters takes two lines.
const PICK_ROWS: usize = 7;
/// backup-check-entry's instruction, under any refusal.
const FIRST_FOURS: &str = "Type the first four letters of each word, or a whole three-letter word.";

/// True for the screens this module builds.
pub(super) fn shows(id: ScreenId) -> bool {
    matches!(
        id,
        ScreenId::UsbInsert
            | ScreenId::UsbPick
            | ScreenId::SnapshotLoaded
            | ScreenId::SnapshotFailed
            | ScreenId::BackupCheckEntry
            | ScreenId::BackupCheckResult
            | ScreenId::BackupCheckRecheckQr
    )
}

/// The model of a USB screen.
pub(super) fn model<'a>(held: &'a Held, view: &'a View) -> Result<Screen<'a>, Stop> {
    let id = view.shown();
    let page = |title| Page::new(id, title, held.banners);
    let screen = match (id, &held.stage) {
        (ScreenId::UsbInsert, _) => {
            let what = match view.note {
                Note::Usb(Flow::Write) => "For the backup: a FAT32 stick, in the OTG port.",
                Note::Usb(Flow::Open(FileKind::Kcr)) => "One holding a .kcr registry snapshot.",
                Note::Usb(Flow::Open(FileKind::Age)) => "One holding a KeepCrypt .age backup.",
                _ => return Err(OUT_OF_ORDER),
            };
            page("USB stick")
                .text("Insert a USB stick")
                .small(what)
                .small("The device goes on by itself once the stick is in.")
                .done()
        }
        (ScreenId::UsbPick, _) => pick(page("USB stick"), view)?,
        (ScreenId::SnapshotLoaded, _) => {
            let Some(snapshot) = &held.snapshot else {
                return Err(OUT_OF_ORDER);
            };
            page("Registry snapshot")
                .text("Snapshot loaded")
                .small(format!(
                    "Snapshot No. {}, dated {}, {} entries.",
                    snapshot.number(),
                    date_text(snapshot.date()),
                    snapshot.entry_count()
                ))
                .small("Check now asks you to confirm its date: the Pi has no clock.")
                .done()
        }
        (ScreenId::SnapshotFailed, _) => {
            let Note::Refused(refusal) = &view.note else {
                return Err(OUT_OF_ORDER);
            };
            page("Registry snapshot")
                .text("Snapshot not loaded")
                .small(refusal.to_string())
                .done()
        }
        (ScreenId::BackupCheckEntry, Stage::BackupCheck { typed, .. }) => {
            let current = grid::current_entry(typed);
            let accepted = match Grid::Letters.symbol(view.cursor) {
                Some(symbol) => grid::face_accepted(current, symbol),
                None => false,
            };
            let mut entry = page("Check a backup").small(format!(
                "Backup passphrase, word {} of 8",
                grid::entry_number(typed)
            ));
            if let Note::Refused(refusal) = &view.note {
                entry = entry.small(refusal.to_string());
            }
            entry
                .small(FIRST_FOURS)
                .text_in(Class::Protected, typed.as_str())
                .text_in(Class::Protected, grid_text(Grid::Letters, view.cursor))
                .offer(Key::Press, accepted)
                .offer(Key::Key1, !typed.is_empty())
                .offer(Key::Key3, grid::entry_done(current))
                .done()
        }
        (ScreenId::BackupCheckResult, Stage::Checked { backup, seal }) => {
            let mut result = page("Check a backup")
                .text("The backup opens")
                .small(format!(
                    "Fingerprint {}",
                    fingerprint_hex(backup.fingerprint())
                ))
                .small(format!("Seal ID {}", seal.seal_id()));
            if let Some(snapshot) = &held.snapshot {
                let count = match snapshot.lookup(seal.tag()) {
                    Some(count) => count.get(),
                    None => 0,
                };
                result = result
                    .small(format!(
                        "Registrations: {count}, as of {}",
                        date_text(snapshot.date())
                    ))
                    .small("If you registered once and this is 2 or more, move your funds now.");
            }
            result.menu(choices(id, held), view.cursor).done()
        }
        (ScreenId::BackupCheckRecheckQr, Stage::Checked { seal, .. }) => {
            page("Re-check QR: T only, no nonce")
                .centred(QR_SIDE, Class::Public, Item::Qr(seal.recheck_url().into()))
                .done()
        }
        _ => return Err(OUT_OF_ORDER),
    };
    Ok(screen)
}

/// usb-pick (Q33 (g)): the files of one kind on the stick, a page at a time; or none; or the USB
/// fault that kept them from being read. Back returns Home.
fn pick<'a>(page: Page<'a>, view: &'a View) -> Result<Screen<'a>, Stop> {
    let Note::Pick {
        kind,
        names,
        problem,
    } = &view.note
    else {
        return Err(OUT_OF_ORDER);
    };
    let what = match kind {
        FileKind::Kcr => "registry snapshot (.kcr)",
        FileKind::Age => "backup (.age)",
    };
    if let Some(fault) = problem {
        return Ok(page
            .text("Cannot read the stick")
            .small(fault.text())
            .only(&[Key::Key1])
            .done());
    }
    if names.is_empty() {
        return Ok(page
            .text("Nothing to open")
            .small(format!("No {what} file on this USB stick."))
            .only(&[Key::Key1])
            .done());
    }
    let first = view.cursor / PICK_ROWS * PICK_ROWS;
    let mut list = page.small(format!("Pick a {what}:"));
    for (i, name) in names.iter().enumerate().skip(first).take(PICK_ROWS) {
        let mark = if i == view.cursor { '>' } else { ' ' };
        list = list.small(format!("{mark}{}", name.as_str()));
    }
    if names.len() > PICK_ROWS {
        list = list.small(format!(
            "{}-{} of {}",
            first + 1,
            (first + PICK_ROWS).min(names.len()),
            names.len()
        ));
    }
    Ok(list
        .offer(Key::Up, names.len() > 1)
        .offer(Key::Down, names.len() > 1)
        .done())
}
