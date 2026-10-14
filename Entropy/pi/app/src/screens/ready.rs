//! The models of steps 8-15 (tasks/todo.md, M3 group 9; docs/pi-firmware.md "User flow" steps
//! 8-15, "Buttons"; docs/seal-watchonly-braille.md "Braille backup", "Watch-only export",
//! "Registering a new seal").
//!
//! - The words, in insert view (one insert a page: its header, the word at ×2 with the letters
//!   past the fourth lighter, its SeedBook number, five face cells with numbered dots, and face 6)
//!   and in the overview (four words a page). Every insert and overview page names its device.
//! - The read-back: the faces as typed, with no suggestion, then the whole word on a match, or a
//!   verdict per face on a mismatch.
//! - The exports, each Protected screen showing its secret as Protected elements: the backup
//!   passphrase and its confirm, the BIP39 passphrase as typed, the account and descriptor QRs,
//!   the registration QR and D. The wallet and watch-only summaries stay Public (Q29).

use embedded_graphics::prelude::Size;
use keepcrypt_core::{BrailleInserts, Dots, FaceVerdict, Insert, Ready, SeedLength, Session};
use zeroize::Zeroizing;

use super::{Page, built, choices, fingerprint_hex, grid_text, push_number};
use crate::app::{Held, Holding, Note, OUT_OF_ORDER, Stage, Steps, Stop, View};
use crate::grid::{self, Grid, MAX_PASSPHRASE};
use crate::input::Key;
use crate::screen::{BODY_FONT, Cell, Class, Item, QR_SIDE, Screen, ScreenId, advance, px};
use crate::ui::hex_groups;

/// An insert's letters past the fourth are drawn lighter.
const LIGHTER_FROM: usize = 4;
/// Faces 1-5 of an insert.
const FACES: usize = 5;
/// One face cell's box: numbered dots, as on the metal.
const FACE_PITCH: Size = Size::new(44, 70);
/// Words on an overview page, and backup-passphrase words on a page.
const PER_PAGE: usize = 4;
/// The longest BIP39 word.
const LONGEST_WORD: usize = 8;
/// "SeedBook 0001".
const SEEDBOOK_LEN: usize = 13;
/// Four overview lines of "01 abandon  0001" (16 characters) and three line feeds.
const OVERVIEW_LEN: usize = PER_PAGE * 16 + PER_PAGE - 1;
/// "Face 1: wrong letter: missing 1 2 3 4 5 6, extra 1 2 3 4 5 6" is 60 characters.
const VERDICT_LEN: usize = 64;
/// Four lines of "8 ostrich" and three line feeds.
const PASSPHRASE_PAGE_LEN: usize = PER_PAGE * (2 + LONGEST_WORD) + PER_PAGE - 1;
/// Four marked choices and three line feeds.
const CHOICES_LEN: usize = PER_PAGE * (1 + LONGEST_WORD) + PER_PAGE - 1;

// The longer screen copy.
const READBACK_HOW: &str = "Type faces 1-4 as punched on the metal; _ is a blank face 4.";
const DEVICE_SWAP: &str = "Close device 1 of 2, fastened shut, and put it away before you \
    open device 2. Both insert sets are engraved 01-12.";
const MIRRORS: &str = "Read the insert again, face by face: the mirror pairs e/i, d/f, h/j \
    and r/w read twice.";
const BACKUP_OFFER: &str = "Write an encrypted backup to a USB stick. Its 8-word passphrase is \
    shown once: write it down and store it apart from the stick.";
const WATCH_OFFER: &str = "An account QR for Sparrow and a descriptor QR for Bitcoin Core: \
    public keys only, but an xpub shows every address and balance.";
const BIP39_ASK: &str = "Only if you use one: the export is then that passphrase's wallet. The \
    Pi takes printable ASCII, up to 100 characters.";
const TREAT_PRIVATE: &str = "Treat the xpub as private: it shows every address and balance.";
const PASSPHRASE_WALLET: &str = "Your BIP39 passphrase's wallet: compare this address in Sparrow \
    or Core, not the wallet summary's.";
const REGISTER_ONCE: &str = "Register once, and never from a restored seed: a second \
    registration of the same seed looks like a collision.";
const REVEAL_D: &str = "For verification runs only: D plus the rolls recreates the seed.";
const VERIFY_PROMPT: &str = "On the offline computer, type each value into verify.py only after \
    its prompt appears.";
/// The SeedBook's "before you walk away" checklist (swb "Braille backup"), three items a page.
const CHECKLIST: [&str; 6] = [
    "- Every face read back.",
    "- Inserts reassembled in sequence order, 01 first.",
    "- Device fastened shut and back in place.",
    "- Whole phrase test-restored from the metal.",
    "- Every paper copy destroyed.",
    "- No photograph of the inserts anywhere.",
];
const TWO_DEVICES: &str = "Device 1 of 2 holds words 1-12; device 2 of 2 holds words 13-24.";

/// True for the screens this module builds.
pub(super) fn shows(id: ScreenId) -> bool {
    matches!(
        id,
        ScreenId::WordsInsert
            | ScreenId::WordsOverview
            | ScreenId::DeviceSwap
            | ScreenId::ReadbackEntry
            | ScreenId::ReadbackMismatch
            | ScreenId::ReadbackDone
            | ScreenId::Wallet
            | ScreenId::BackupOffer
            | ScreenId::BackupPassphrase
            | ScreenId::BackupConfirm
            | ScreenId::BackupConfirmWrong
            | ScreenId::BackupVerified
            | ScreenId::BackupFailed
            | ScreenId::WatchOffer
            | ScreenId::Bip39Ask
            | ScreenId::Bip39Entry
            | ScreenId::WatchSummary
            | ScreenId::WatchAccountQr
            | ScreenId::WatchDescriptorQr
            | ScreenId::RegisterOffer
            | ScreenId::RegisterQr
            | ScreenId::RevealDOffer
            | ScreenId::RevealD
            | ScreenId::Checklist
            | ScreenId::PowerOff
    )
}

/// The model of a screen of steps 8-15.
pub(super) fn model<'a>(held: &'a Held, view: &'a View) -> Result<Screen<'a>, Stop> {
    let id = view.shown();
    let page = |title| Page::new(id, title, held.banners);
    let menu = || choices(id, held);
    let screen = match (id, &held.stage) {
        (ScreenId::WordsInsert, stage) => insert(page("Seed words"), stage, view)?,
        (ScreenId::WordsOverview, stage) => overview(page("Seed words: overview"), stage, view)?,
        (ScreenId::DeviceSwap, _) => page("Device swap")
            .text("Words 13-24 go on device 2 of 2")
            .small(DEVICE_SWAP)
            .done(),
        (ScreenId::ReadbackEntry, Stage::Ready { session, steps }) => {
            readback_entry(page("Read-back"), session, steps, view)?
        }
        (ScreenId::ReadbackMismatch, Stage::Ready { session, steps }) => {
            mismatch(page("Read-back"), session, steps)?
        }
        (ScreenId::ReadbackDone, Stage::Ready { .. }) => page("Read-back")
            .text("Read-back complete")
            .small("Every insert matches the seed. Next: the wallet summary.")
            .done(),
        (ScreenId::Wallet, Stage::Ready { session, .. }) => page("Wallet summary")
            .text("Wallet summary")
            .small("Fingerprint")
            .large(fingerprint_hex(session.fingerprint()))
            .small("First receive address")
            .text(session.first_address())
            .small("Compare both after any restore.")
            .done(),
        (ScreenId::BackupOffer, Stage::Ready { .. }) => page("Encrypted backup")
            .text("Encrypted backup")
            .small(BACKUP_OFFER)
            .menu(menu(), view.cursor)
            .done(),
        (ScreenId::BackupPassphrase, Stage::Ready { steps, .. }) => {
            passphrase(page("Backup passphrase"), steps, view)?
        }
        (ScreenId::BackupConfirm, Stage::Ready { steps, .. }) => {
            confirm(page("Confirm the passphrase"), steps, view)?
        }
        (ScreenId::BackupConfirmWrong, Stage::Ready { .. }) => page("Confirm the passphrase")
            .text("Not that word")
            .small(
                "The passphrase is shown again from its first word; the questions stay the same.",
            )
            .done(),
        (ScreenId::BackupVerified, Stage::Ready { .. }) => page("Encrypted backup")
            .text("Backup verified")
            .small("Remove the stick. On an offline computer, age -d and the passphrase open it.")
            .done(),
        (ScreenId::BackupFailed, Stage::Ready { .. }) => {
            let Note::BackupFailed { reason, left } = &view.note else {
                return Err(OUT_OF_ORDER);
            };
            let mut failed = page("Encrypted backup")
                .text("Backup not saved")
                .small(reason.to_string());
            if let Some(fault) = left {
                failed = failed.small(format!("The file stays on the stick: {}", fault.text()));
            }
            failed
                .small("Retry writes a new file under the same passphrase.")
                .menu(menu(), view.cursor)
                .done()
        }
        (ScreenId::WatchOffer, Stage::Ready { .. }) => page("Watch-only export")
            .text("Watch-only export")
            .small(WATCH_OFFER)
            .menu(menu(), view.cursor)
            .done(),
        (ScreenId::Bip39Ask, Stage::Ready { .. }) => page("Watch-only export")
            .text("BIP39 passphrase?")
            .small(BIP39_ASK)
            .menu(menu(), view.cursor)
            .done(),
        (ScreenId::Bip39Entry, Stage::Ready { steps, .. }) => {
            passphrase_entry(page("BIP39 passphrase"), steps, view)
        }
        (ScreenId::WatchSummary, Stage::Ready { steps, .. }) => {
            let Holding::Export(export) = &steps.holding else {
                return Err(OUT_OF_ORDER);
            };
            let mut summary = page("Watch-only wallet")
                .text("Watch-only wallet")
                .small("Fingerprint")
                .large(fingerprint_hex(export.fingerprint()))
                .small("First receive address")
                .text(export.first_address())
                .small(TREAT_PRIVATE);
            if export.passphrase_used() {
                summary = summary.small(PASSPHRASE_WALLET);
            }
            summary.done()
        }
        (ScreenId::WatchAccountQr, Stage::Ready { steps, .. }) => {
            let Holding::Export(export) = &steps.holding else {
                return Err(OUT_OF_ORDER);
            };
            page("Account QR for Sparrow")
                .centred(QR_SIDE, Class::Protected, Item::Qr(export.qr_text().into()))
                .offer(Key::Key2, false)
                .done()
        }
        (ScreenId::WatchDescriptorQr, Stage::Ready { steps, .. }) => {
            let Holding::Export(export) = &steps.holding else {
                return Err(OUT_OF_ORDER);
            };
            // Both descriptors on two lines (swb "Watch-only export"): xpub data, built in place.
            let (receive, change) = (export.receive_descriptor(), export.change_descriptor());
            let payload = built(receive.len() + 1 + change.len(), |out| {
                out.push_str(receive);
                out.push('\n');
                out.push_str(change);
            });
            page("Descriptor QR for Bitcoin Core")
                .centred(QR_SIDE, Class::Protected, Item::Qr(payload.into()))
                .offer(Key::Key3, false)
                .done()
        }
        (ScreenId::RegisterOffer, Stage::Ready { .. }) => page("Register seal")
            .text("Register seal")
            .small(REGISTER_ONCE)
            .menu(menu(), view.cursor)
            .done(),
        (ScreenId::RegisterQr, Stage::Ready { steps, .. }) => {
            let Holding::Registration(registration) = &steps.holding else {
                return Err(OUT_OF_ORDER);
            };
            // The QR fills the content area: the reminder is the title, and register-offer's.
            page("Register once, never from a restore")
                .centred(
                    QR_SIDE,
                    Class::Protected,
                    Item::Qr(registration.url().into()),
                )
                .done()
        }
        (ScreenId::RevealDOffer, Stage::Ready { .. }) => page("Reveal D")
            .text("Reveal D")
            .small(REVEAL_D)
            .small(VERIFY_PROMPT)
            .menu(menu(), view.cursor)
            .done(),
        (ScreenId::RevealD, Stage::Ready { steps, .. }) => {
            let Holding::DeviceLeg(d) = &steps.holding else {
                return Err(OUT_OF_ORDER);
            };
            let width = 19 * advance(&BODY_FONT);
            page("Device leg D")
                .text("Device leg D")
                .centred(
                    width,
                    Class::Protected,
                    Item::Hex(hex_groups(d.expose_secret()).into()),
                )
                .small("Only for verify.py on an offline computer.")
                .done()
        }
        (ScreenId::Checklist, Stage::Ready { session, .. }) => {
            let mut list = page("Before you walk away").text("Before you walk away");
            for &item in CHECKLIST.iter().skip(view.page * 3).take(3) {
                list = list.small(item);
            }
            if session.seed_length() == SeedLength::Words24 {
                list = list.small(TWO_DEVICES);
            }
            list.small(format!("Page {} of 2", view.page + 1))
                .offer(Key::Key2, view.page > 0)
                .offer(Key::Key3, view.page == 0)
                .done()
        }
        (ScreenId::PowerOff, _) => page("Safe to power off")
            .text("Safe to power off")
            .small("The session is wiped. A new ceremony starts after a power cycle.")
            .done(),
        _ => return Err(OUT_OF_ORDER),
    };
    Ok(screen)
}

/// The braille inserts of the words the stage holds: the ceremony's, or a checked backup's.
fn inserts(stage: &Stage) -> Result<BrailleInserts<'_>, Stop> {
    match stage {
        Stage::Ready { session, .. } => Ok(session.braille()),
        Stage::Checked { backup, .. } => Ok(backup.reveal_braille()),
        _ => Err(OUT_OF_ORDER),
    }
}

/// An insert's header: its position and its device (swb "24-word seeds").
fn header(insert: &Insert<'_>) -> String {
    format!(
        "Insert {:02} · device {} of {}",
        insert.position(),
        insert.device(),
        insert.device_count()
    )
}

/// The insert view (step 8): one insert of the page `view.page`. Press is offered on the last
/// insert, and in the ceremony on the insert of a read-back mismatch, which offers nothing else. A
/// checked backup's words have no read-back: there Press is "done", back to the backup's result.
fn insert<'a>(page: Page<'a>, stage: &'a Stage, view: &View) -> Result<Screen<'a>, Stop> {
    let inserts = inserts(stage)?;
    let count = inserts.count();
    let position = u8::try_from(view.page + 1).map_err(|_| OUT_OF_ORDER)?;
    let insert = inserts.insert(position).map_err(Stop::Core)?;
    let reviewing = matches!((stage, &view.note), (Stage::Ready { .. }, Note::Reviewing));
    let last = view.page + 1 == count;
    let seedbook = built(SEEDBOOK_LEN, |out| {
        out.push_str("SeedBook ");
        push_number(out, insert.seedbook_number(), 4);
    });
    let cells = Item::Cells {
        cells: faces(&insert),
        pitch: FACE_PITCH,
    };
    let screen = page
        .small(header(&insert))
        .large_in(Class::Protected, insert.word(), Some(LIGHTER_FROM))
        .small_in(Class::Protected, seedbook)
        .centred(px(FACES, FACE_PITCH.width), Class::Protected, cells)
        .small(format!(
            "Face 6: the engraved number {:02}",
            insert.sequence()
        ))
        .offer(Key::Press, last || reviewing)
        .offer(Key::Key1, !reviewing)
        .offer(Key::Key2, !reviewing && view.page > 0)
        .offer(Key::Key3, !reviewing && !last)
        .done();
    Ok(match stage {
        Stage::Checked { .. } => screen.relabel(Key::Press, "done"),
        _ => screen,
    })
}

/// Faces 1-5 of an insert as cells: raised dots, blank faces, face 5 lighter, mirror letters.
fn faces(insert: &Insert<'_>) -> Zeroizing<Vec<Cell>> {
    let mut cells = Zeroizing::new(Vec::with_capacity(FACES));
    for face in insert.faces() {
        let dots = match face.dots() {
            Some(dots) => dots.bits(),
            None => 0,
        };
        cells.push(Cell {
            dots,
            blank: face.is_blank(),
            lighter: face.is_lighter(),
            mirror: face.mirror_partner().is_some(),
        });
    }
    cells
}

/// The overview (step 8): four words a page, each with its position and SeedBook number, for the
/// paper copy.
fn overview<'a>(page: Page<'a>, stage: &'a Stage, view: &View) -> Result<Screen<'a>, Stop> {
    let inserts = inserts(stage)?;
    let pages = inserts.count().div_ceil(PER_PAGE);
    let shown: Vec<Insert<'a>> = inserts
        .iter()
        .skip(view.page * PER_PAGE)
        .take(PER_PAGE)
        .collect();
    let (Some(head), Some(tail)) = (shown.first(), shown.last()) else {
        return Err(OUT_OF_ORDER);
    };
    let range = format!(
        "Words {:02}-{:02} · device {} of {}",
        head.position(),
        tail.position(),
        head.device(),
        head.device_count()
    );
    let lines = built(OVERVIEW_LEN, |out| {
        for insert in &shown {
            if !out.is_empty() {
                out.push('\n');
            }
            push_number(out, u16::from(insert.position()), 2);
            out.push(' ');
            out.push_str(insert.word());
            for _ in insert.word().len()..LONGEST_WORD {
                out.push(' ');
            }
            out.push(' ');
            push_number(out, insert.seedbook_number(), 4);
        }
    });
    Ok(page
        .small(range)
        .text_in(Class::Protected, lines)
        .offer(Key::Press, false)
        .offer(Key::Key2, view.page > 0)
        .offer(Key::Key3, view.page + 1 < pages)
        .done())
}

/// readback-entry (step 9; Q33 (m)): the faces of the insert being read back as typed, with no
/// suggestion, and the letters grid. After a match, the whole word, and only done.
fn readback_entry<'a>(
    page: Page<'a>,
    session: &'a Session<Ready>,
    steps: &'a Steps,
    view: &View,
) -> Result<Screen<'a>, Stop> {
    let insert = session
        .braille()
        .insert(steps.position)
        .map_err(Stop::Core)?;
    let page = page.small(format!(
        "Read back insert {:02} · device {} of {}",
        insert.position(),
        insert.device(),
        insert.device_count()
    ));
    if let Note::Matched = view.note {
        return Ok(page
            .small("It matches the seed, which completes it as:")
            .large_in(Class::Protected, insert.word(), Some(LIGHTER_FROM))
            .only(&[Key::Key3])
            .done());
    }
    let typed = steps.typed.as_str();
    let shown = built(grid::FACES, |out| {
        out.push_str(typed);
        for _ in typed.len()..grid::FACES {
            out.push('-');
        }
    });
    let accepted = match Grid::Letters.symbol(view.cursor) {
        Some(symbol) => grid::face_accepted(typed, symbol),
        None => false,
    };
    Ok(page
        .small(READBACK_HOW)
        .large_in(Class::Protected, shown, None)
        .text_in(Class::Protected, grid_text(Grid::Letters, view.cursor))
        .offer(Key::Press, accepted)
        .offer(Key::Key1, !typed.is_empty())
        .offer(Key::Key3, grid::entry_done(typed))
        .done())
}

/// readback-mismatch (step 9): each face's verdict, as core gives it.
fn mismatch<'a>(
    page: Page<'a>,
    session: &'a Session<Ready>,
    steps: &'a Steps,
) -> Result<Screen<'a>, Stop> {
    let Holding::Mismatch(mismatch) = &steps.holding else {
        return Err(OUT_OF_ORDER);
    };
    let insert = session
        .braille()
        .insert(steps.position)
        .map_err(Stop::Core)?;
    let mut page = page.small(format!(
        "Insert {:02} does not match · device {} of {}",
        insert.position(),
        insert.device(),
        insert.device_count()
    ));
    for (number, verdict) in (b'1'..).zip(mismatch.faces()) {
        page = page.small_in(Class::Protected, verdict_line(number, verdict));
    }
    Ok(page.small(MIRRORS).done())
}

/// "Face N: <verdict>": a mirror misread, should be blank, should have a letter, or a wrong letter
/// with the dots it lacks and the dots it should not have.
fn verdict_line(number: u8, verdict: &FaceVerdict) -> Zeroizing<String> {
    built(VERDICT_LEN, |out| {
        out.push_str("Face ");
        out.push(char::from(number));
        out.push_str(": ");
        match verdict {
            FaceVerdict::Ok => out.push_str("ok"),
            FaceVerdict::MirrorMisread => out.push_str("mirror misread"),
            FaceVerdict::ShouldBeBlank => out.push_str("should be blank"),
            FaceVerdict::ShouldHaveLetter => out.push_str("should have a letter"),
            FaceVerdict::WrongLetter { missing, extra } => {
                out.push_str("wrong letter: missing");
                push_dots(out, missing);
                out.push_str(", extra");
                push_dots(out, extra);
            }
        }
    })
}

/// Appends each raised dot's number after a space, or " none".
fn push_dots(out: &mut String, dots: &Dots) {
    let mut any = false;
    for (dot, digit) in (1..=6u8).zip(b'1'..) {
        if dots.is_raised(dot) {
            out.push(' ');
            out.push(char::from(digit));
            any = true;
        }
    }
    if !any {
        out.push_str(" none");
    }
}

/// backup-passphrase (USB step 1): four words a page, with the label to store it apart.
fn passphrase<'a>(page: Page<'a>, steps: &'a Steps, view: &View) -> Result<Screen<'a>, Stop> {
    let Holding::Passphrase(new) = &steps.holding else {
        return Err(OUT_OF_ORDER);
    };
    let first = view.page * PER_PAGE;
    let lines = built(PASSPHRASE_PAGE_LEN, |out| {
        for (number, word) in (1u16..).zip(new.words()).skip(first).take(PER_PAGE) {
            if !out.is_empty() {
                out.push('\n');
            }
            push_number(out, number, 1);
            out.push(' ');
            out.push_str(word);
        }
    });
    Ok(page
        .small("Backup passphrase: store apart from the USB stick.")
        .small(format!("Words {}-{} of 8", first + 1, first + PER_PAGE))
        .text_in(Class::Protected, lines)
        .offer(Key::Key2, view.page > 0)
        .offer(Key::Key3, view.page == 0)
        .done())
}

/// backup-confirm (USB step 2): question `view.page` of two, its four choices marked.
fn confirm<'a>(page: Page<'a>, steps: &'a Steps, view: &View) -> Result<Screen<'a>, Stop> {
    let Holding::Passphrase(new) = &steps.holding else {
        return Err(OUT_OF_ORDER);
    };
    let questions = new.challenge().questions();
    let Some(&(position, choices)) = questions.get(view.page) else {
        return Err(OUT_OF_ORDER);
    };
    let lines = built(CHOICES_LEN, |out| {
        for (i, choice) in choices.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push(if i == view.cursor { '>' } else { ' ' });
            out.push_str(choice);
        }
    });
    Ok(page
        .small(format!(
            "Check your copy: question {} of {}",
            view.page + 1,
            questions.len()
        ))
        .text(format!("Which is word {position}?"))
        .listed(Class::Protected, lines, choices.len())
        .done())
}

/// bip39-entry (step 12; Q32 (c)): the passphrase as typed, a space shown as `·`, and the
/// printable-ASCII grid's page. Type is offered below 100 characters, delete and done above none.
/// KEY2, always offered, goes back to bip39-ask.
fn passphrase_entry<'a>(page: Page<'a>, steps: &'a Steps, view: &View) -> Screen<'a> {
    let typed = steps.typed.as_str();
    // '·' is two bytes of UTF-8.
    let shown = built(2 * MAX_PASSPHRASE, |out| {
        for c in typed.chars() {
            out.push(if c == ' ' { '·' } else { c });
        }
    });
    let grid_page = view.cursor / Grid::Ascii.columns() / grid::PAGE_ROWS + 1;
    let accepted = typed.len() < MAX_PASSPHRASE && Grid::Ascii.symbol(view.cursor).is_some();
    let mut entry = page
        .small(format!(
            "As typed, · for a space. Grid page {grid_page} of 3: down past its last row for more."
        ))
        .small_in(Class::Protected, shown);
    if let Note::Refused(refusal) = &view.note {
        entry = entry.small(refusal.to_string());
    }
    entry
        .text_in(Class::Protected, grid_text(Grid::Ascii, view.cursor))
        .offer(Key::Press, accepted)
        .offer(Key::Key1, !typed.is_empty())
        .offer(Key::Key3, !typed.is_empty())
        .done()
}
