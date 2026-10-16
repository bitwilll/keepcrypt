//! Steps 8-15 (tasks/todo.md, M3 group 9; docs/pi-firmware.md "User flow" steps 8-15;
//! docs/seal-watchonly-braille.md "Braille backup", "Watch-only export", "Registering a new
//! seal"): the words, the read-back from the metal, the wallet summary, the backup passphrase
//! and its confirm, the watch-only export, the registration, D and Finish.
//!
//! - Every export goes through `export`: it moves the session into core's call and back, and an
//!   `Err` (core has wiped the session) halts. core's read-back gate stands behind every export,
//!   and the shell reaches steps 10-15 only after `readback_complete()`, so no export is called
//!   early by mistake.
//! - The secret a step shows besides the session (`Holding`) is replaced, and so wiped, when its
//!   screens are left; the grid's text is zeroized after each entry is used.
//! - The words view serves the ceremony (`Stage::Ready`) and "Check a backup" (`Stage::Checked`)
//!   alike. For a 24-word seed, device-swap comes before word 13: paging on past word 12, in insert
//!   view or in the overview, passes it. Paging back needs none, since every page names its
//!   device.

use keepcrypt_core::{Bip39Passphrase, CoreError, Mode, ReadbackResult, Ready, Session};
use zeroize::Zeroize;

use super::{App, Flow, Holding, Note, OUT_OF_ORDER, Stage, Stop, refused};
use crate::grid;
use crate::hal::Hal;
use crate::input::Key;
use crate::screen::ScreenId;
use crate::screens::{self, Choice};

/// Inserts per device: words 13-24 of a 24-word seed go on the second device.
const INSERTS_PER_DEVICE: usize = 12;
/// The insert view shows one insert per page, the overview four.
const OVERVIEW_WORDS: usize = 4;

impl<H: Hal> App<H> {
    /// A key on a screen of steps 8-15 that is no menu, grid or words view.
    pub(super) fn ready_key(&mut self, key: Key) -> Result<(), Stop> {
        let id = self.view.id;
        let page = self.view.page;
        match (id, key) {
            (ScreenId::DeviceSwap, Key::Press) => {
                let Note::Swap { to, page } = self.view.note else {
                    return Err(OUT_OF_ORDER);
                };
                self.enter_page(to, page, Note::None);
            }
            (ScreenId::ReadbackMismatch, Key::Press) => {
                self.set_holding(Holding::Nothing)?;
                self.enter(ScreenId::ReadbackEntry, Note::None);
            }
            (ScreenId::ReadbackMismatch, Key::Key1) => {
                let position = match &self.held.stage {
                    Stage::Ready { steps, .. } => usize::from(steps.position),
                    _ => return Err(OUT_OF_ORDER),
                };
                self.set_holding(Holding::Nothing)?;
                let insert = position.checked_sub(1).ok_or(OUT_OF_ORDER)?;
                self.enter_page(ScreenId::WordsInsert, insert, Note::Reviewing);
            }
            (ScreenId::ReadbackDone, Key::Press) => self.enter(ScreenId::Wallet, Note::None),
            (ScreenId::Wallet, Key::Press) => self.enter(ScreenId::BackupOffer, Note::None),
            (ScreenId::BackupPassphrase | ScreenId::Checklist, Key::Key3)
            | (ScreenId::BackupPassphrase | ScreenId::Checklist, Key::Press)
                if page == 0 =>
            {
                self.enter_page(id, 1, Note::None);
            }
            (ScreenId::BackupPassphrase | ScreenId::Checklist, Key::Key2) => {
                self.enter_page(id, 0, Note::None);
            }
            (ScreenId::BackupPassphrase, Key::Press) => {
                self.enter(ScreenId::BackupConfirm, Note::None);
            }
            (ScreenId::Checklist, Key::Press) => return self.finish(),
            (ScreenId::BackupConfirmWrong, Key::Press) => {
                self.enter(ScreenId::BackupPassphrase, Note::None);
            }
            (ScreenId::BackupVerified, Key::Press) => {
                self.enter(ScreenId::WatchOffer, Note::None);
            }
            (ScreenId::WatchSummary, Key::Press) => {
                self.enter(ScreenId::WatchAccountQr, Note::None);
            }
            (ScreenId::WatchAccountQr, Key::Press | Key::Key3) => {
                self.enter(ScreenId::WatchDescriptorQr, Note::None);
            }
            (ScreenId::WatchDescriptorQr, Key::Key2) => {
                self.enter(ScreenId::WatchAccountQr, Note::None);
            }
            (ScreenId::WatchDescriptorQr, Key::Press) => {
                self.set_holding(Holding::Nothing)?;
                self.enter(ScreenId::RegisterOffer, Note::None);
            }
            (ScreenId::RegisterQr, Key::Press) => {
                self.set_holding(Holding::Nothing)?;
                let next = screens::after_register(self.ready_mode()?);
                self.enter(next, Note::None);
            }
            (ScreenId::RevealD, Key::Press) => {
                self.set_holding(Holding::Nothing)?;
                self.enter(ScreenId::Checklist, Note::None);
            }
            _ => return Err(OUT_OF_ORDER),
        }
        self.redraw()
    }

    /// A menu choice of steps 11-14.
    pub(super) fn ready_choice(&mut self, choice: Choice) -> Result<(), Stop> {
        match choice {
            Choice::BackUp => return self.back_up(),
            Choice::SkipBackup | Choice::SkipFailedBackup => {
                self.enter(ScreenId::WatchOffer, Note::None);
            }
            Choice::Retry => self.enter(ScreenId::UsbInsert, Note::Usb(Flow::Write)),
            Choice::ShowWatchOnly => self.enter(ScreenId::Bip39Ask, Note::None),
            Choice::SkipWatchOnly => self.enter(ScreenId::RegisterOffer, Note::None),
            Choice::NoPassphrase => {
                let export = self.export(|session| session.watch_only(None))?;
                self.fence();
                self.set_holding(Holding::Export(Box::new(export)))?;
                self.enter(ScreenId::WatchSummary, Note::None);
            }
            Choice::WithPassphrase => {
                match &mut self.held.stage {
                    Stage::Ready { steps, .. } => steps.typed.zeroize(),
                    _ => return Err(OUT_OF_ORDER),
                }
                self.enter(ScreenId::Bip39Entry, Note::None);
            }
            Choice::ShowRegistration => {
                let registration = self.export(Session::registration)?;
                self.set_holding(Holding::Registration(registration))?;
                self.enter(ScreenId::RegisterQr, Note::None);
            }
            Choice::SkipRegistration => {
                let next = screens::after_register(self.ready_mode()?);
                self.enter(next, Note::None);
            }
            Choice::ShowD => {
                // Step 14 is offered in Mixed mode only, where D exists.
                let Some(d) = self.export(Session::reveal_device_leg)? else {
                    return Err(OUT_OF_ORDER);
                };
                self.set_holding(Holding::DeviceLeg(d))?;
                self.enter(ScreenId::RevealD, Note::None);
            }
            Choice::SkipD => self.enter(ScreenId::Checklist, Note::None),
            _ => return Err(OUT_OF_ORDER),
        }
        self.redraw()
    }

    /// The words view: page through the inserts, switch to the overview and back, and Press on
    /// the last insert (in the ceremony, the read-back; in "Check a backup", back to its
    /// result) or on a mismatch's insert (back to its entry).
    pub(super) fn words(&mut self, key: Key) -> Result<(), Stop> {
        let count = match &self.held.stage {
            Stage::Ready { session, .. } => session.braille().count(),
            Stage::Checked { backup, .. } => backup.reveal_braille().count(),
            _ => return Err(OUT_OF_ORDER),
        };
        let (id, page) = (self.view.id, self.view.page);
        // The words on one page: an insert, or four in the overview.
        let per_page = match id {
            ScreenId::WordsOverview => OVERVIEW_WORDS,
            _ => 1,
        };
        match (id, key) {
            // On past word 12 of a 24-word seed: device-swap first, then that view's next page.
            (ScreenId::WordsInsert | ScreenId::WordsOverview, Key::Key3)
                if count > INSERTS_PER_DEVICE && (page + 1) * per_page == INSERTS_PER_DEVICE =>
            {
                self.enter(
                    ScreenId::DeviceSwap,
                    Note::Swap {
                        to: id,
                        page: page + 1,
                    },
                );
            }
            (ScreenId::WordsInsert | ScreenId::WordsOverview, Key::Key3) => {
                self.enter_page(self.view.id, page + 1, Note::None);
            }
            (ScreenId::WordsInsert | ScreenId::WordsOverview, Key::Key2) => {
                let previous = page.checked_sub(1).ok_or(OUT_OF_ORDER)?;
                self.enter_page(self.view.id, previous, Note::None);
            }
            (ScreenId::WordsInsert, Key::Key1) => {
                self.enter_page(ScreenId::WordsOverview, page / OVERVIEW_WORDS, Note::None);
            }
            (ScreenId::WordsOverview, Key::Key1) => {
                self.enter_page(ScreenId::WordsInsert, page * OVERVIEW_WORDS, Note::None);
            }
            (ScreenId::WordsInsert, Key::Press) => match (&mut self.held.stage, &self.view.note) {
                // Back to the entry of the insert that did not match.
                (Stage::Ready { .. }, Note::Reviewing) => {
                    self.enter(ScreenId::ReadbackEntry, Note::None);
                }
                (Stage::Ready { steps, .. }, _) => {
                    steps.position = 1;
                    steps.typed.zeroize();
                    self.enter(ScreenId::ReadbackEntry, Note::None);
                }
                (Stage::Checked { .. }, _) => {
                    self.enter(ScreenId::BackupCheckResult, Note::None);
                }
                _ => return Err(OUT_OF_ORDER),
            },
            _ => return Err(OUT_OF_ORDER),
        }
        self.redraw()
    }

    /// Done on readback-entry: the faces typed are compared with the seed (`check_readback`). A
    /// match shows the whole word, and the next done goes on to the next insert, or to
    /// readback-done once core says every word read back; a mismatch shows its verdicts.
    pub(super) fn read_back(&mut self) -> Result<(), Stop> {
        let (next, note) = match (&mut self.held.stage, &self.view.note) {
            (Stage::Ready { session, steps }, Note::Matched) => {
                if session.readback_complete() {
                    (ScreenId::ReadbackDone, Note::None)
                } else if usize::from(steps.position) < session.braille().count() {
                    steps.position += 1;
                    (ScreenId::ReadbackEntry, Note::None)
                } else {
                    return Err(OUT_OF_ORDER);
                }
            }
            (Stage::Ready { session, steps }, _) => {
                // Done is offered only for 3 or 4 letters, so core's two errors (a position
                // outside the seed, a malformed entry) are shell bugs, and halt.
                let result = session
                    .check_readback(steps.position, grid::letters(&steps.typed))
                    .map_err(Stop::Core)?;
                steps.typed.zeroize();
                match result {
                    ReadbackResult::Match => (ScreenId::ReadbackEntry, Note::Matched),
                    ReadbackResult::Mismatch(mismatch) => {
                        steps.holding = Holding::Mismatch(mismatch);
                        (ScreenId::ReadbackMismatch, Note::None)
                    }
                }
            }
            _ => return Err(OUT_OF_ORDER),
        };
        self.enter(next, note);
        self.redraw()
    }

    /// "Back up to USB" (step 11): the passphrase is generated once, then shown and confirmed;
    /// once generated, the offer goes straight to the stick, under the same passphrase.
    fn back_up(&mut self) -> Result<(), Stop> {
        let generated = match &self.held.stage {
            Stage::Ready { steps, .. } => steps.passphrase_generated,
            _ => return Err(OUT_OF_ORDER),
        };
        if generated {
            self.enter(ScreenId::UsbInsert, Note::Usb(Flow::Write));
            return self.redraw();
        }
        let new = self.export(Session::generate_backup_passphrase)?;
        let Stage::Ready { steps, .. } = &mut self.held.stage else {
            return Err(OUT_OF_ORDER);
        };
        steps.passphrase_generated = true;
        steps.holding = Holding::Passphrase(new);
        self.enter(ScreenId::BackupPassphrase, Note::None);
        self.redraw()
    }

    /// backup-confirm (pi-firmware.md USB step 2): two questions of four choices, graded against
    /// the passphrase. A wrong pick shows the words again, with the same questions; once both
    /// are right, the display copy is dropped and the stick is next.
    pub(super) fn confirm(&mut self, key: Key) -> Result<(), Stop> {
        let Stage::Ready { steps, .. } = &mut self.held.stage else {
            return Err(OUT_OF_ORDER);
        };
        let Holding::Passphrase(new) = &steps.holding else {
            return Err(OUT_OF_ORDER);
        };
        let questions = new.challenge().questions();
        let Some((position, choices)) = questions.get(self.view.page) else {
            return Err(OUT_OF_ORDER);
        };
        match key {
            Key::Up | Key::Down => {
                let n = choices.len();
                self.view.cursor = match key {
                    Key::Up => (self.view.cursor + n - 1) % n,
                    _ => (self.view.cursor + 1) % n,
                };
                return self.redraw();
            }
            Key::Press => {}
            Key::Left | Key::Right | Key::Key1 | Key::Key2 | Key::Key3 => {
                return Err(OUT_OF_ORDER);
            }
        }
        let index = usize::from(*position).checked_sub(1).ok_or(OUT_OF_ORDER)?;
        let right = new.words().nth(index);
        let picked = choices.get(self.view.cursor).copied();
        if right.is_none() || picked != right {
            self.enter(ScreenId::BackupConfirmWrong, Note::None);
        } else if self.view.page + 1 < questions.len() {
            let page = self.view.page + 1;
            self.enter_page(ScreenId::BackupConfirm, page, Note::None);
        } else {
            steps.holding = Holding::Nothing;
            self.enter(ScreenId::UsbInsert, Note::Usb(Flow::Write));
        }
        self.redraw()
    }

    /// Done on bip39-entry (step 12; Q32 (c)): the passphrase as typed makes the export of that
    /// wallet. An empty one is core's refusal, which stays on the screen.
    pub(super) fn passphrase_typed(&mut self) -> Result<(), Stop> {
        let typed = match &self.held.stage {
            Stage::Ready { steps, .. } => Bip39Passphrase::new(&steps.typed),
            _ => return Err(OUT_OF_ORDER),
        };
        let passphrase = match typed {
            Ok(passphrase) => passphrase,
            Err(error) => {
                self.view.note = Note::Refused(refused(error)?);
                return self.redraw();
            }
        };
        let export = self.export(|session| session.watch_only(Some(&passphrase)))?;
        self.fence();
        drop(passphrase);
        let Stage::Ready { steps, .. } = &mut self.held.stage else {
            return Err(OUT_OF_ORDER);
        };
        steps.typed.zeroize();
        steps.holding = Holding::Export(Box::new(export));
        self.enter(ScreenId::WatchSummary, Note::None);
        self.redraw()
    }

    /// KEY2 on bip39-entry (the owner's decision of 2026-10-14): back to bip39-ask, the typed
    /// passphrase wiped in place. The stage stays `Ready` with the same session and holdings, and
    /// no core call or export is made: the export is still made only from a typed passphrase or
    /// "No BIP39 passphrase". Not a refusal or a halt (Q25).
    pub(super) fn passphrase_back(&mut self) -> Result<(), Stop> {
        match &mut self.held.stage {
            Stage::Ready { steps, .. } => steps.typed.zeroize(),
            _ => return Err(OUT_OF_ORDER),
        }
        self.enter(ScreenId::Bip39Ask, Note::None);
        self.redraw()
    }

    /// Step 15: after the checklist the session is wiped, the screen goes black and "Safe to
    /// power off" stays; no key leaves it (Q33 (f)). A loaded snapshot stays until power-off.
    fn finish(&mut self) -> Result<(), Stop> {
        self.wipe(Stage::Idle)?;
        self.enter(ScreenId::PowerOff, Note::None);
        self.redraw()
    }

    /// One of the five gated exports: the session goes into core's call and comes back with what
    /// it made. An `Err` has wiped the session, and halts.
    pub(super) fn export<T>(
        &mut self,
        call: impl FnOnce(Session<Ready>) -> Result<(Session<Ready>, T), CoreError>,
    ) -> Result<T, Stop> {
        let Stage::Ready { session, steps } = self.take() else {
            return Err(OUT_OF_ORDER);
        };
        let (session, made) = call(session).map_err(Stop::Core)?;
        self.held.stage = Stage::Ready { session, steps };
        Ok(made)
    }

    /// Replaces what the current step holds beside the session, which wipes the old one.
    fn set_holding(&mut self, holding: Holding) -> Result<(), Stop> {
        match &mut self.held.stage {
            Stage::Ready { steps, .. } => {
                steps.holding = holding;
                Ok(())
            }
            _ => Err(OUT_OF_ORDER),
        }
    }

    /// The ceremony's mode: dice-only skips step 14.
    fn ready_mode(&self) -> Result<Mode, Stop> {
        match &self.held.stage {
            Stage::Ready { session, .. } => Ok(session.mode()),
            _ => Err(OUT_OF_ORDER),
        }
    }
}
