//! `SimHal`: every trait of pi/app's `hal` in RAM (tasks/todo.md, M3 group 7, Q30).
//!
//! - Display: the panel checks and logs each present (`panel`). Buttons and Clock: the script of
//!   presses and waits on a virtual clock (`keys`). HwRng: one fixed stream (`hwrng`). Usb: the RAM
//!   stick (`stick`). `build_info` names the crate version, rootfs `sim` and the simulator flag.
//! - A `next_event` call while no screen or a transient screen is showing fails the test: the app
//!   waits for a key only on an input-waiting screen.
//! - A scenario arms a `Fault` at the step it chooses; the next call it applies to fails, once.

use std::path::PathBuf;

use keepcrypt_core::BackupFile;
use keepcrypt_pi::hal::{
    BuildInfo, Buttons, Clock, Display, FileKind, FileName, Hal, HalError, HwRng, Usb, Written,
    Zeroizing,
};
use keepcrypt_pi::input::{Event, Key};
use keepcrypt_pi::screen::{Kind, Screen, ScreenId};
use keepcrypt_pi::ui::Frame;

use crate::hwrng::{HwRngStream, Hwrng};
use crate::keys::Keys;
use crate::panel::{Panel, Present, ProtectedFrames};
use crate::stick::{Access, Mount, Stick};

/// A fault a scenario arms: the next call it applies to fails, once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The next `next_event` is `HalError::Buttons`.
    Buttons,
    /// The next `read_block` is `HalError::HwRng` and serves no byte.
    HwRng,
    /// The next write on the stick is `HalError::Write` and leaves no file.
    Write,
    /// The next write on the stick creates the file, cannot sync it, removes it again and is
    /// `HalError::Sync`.
    Sync,
    /// The next read-back of the file just written gives it with its last byte flipped.
    ReadBackCorrupt,
    /// The next removal of the file just written is `HalError::Remove`, and the file stays.
    Remove,
    /// The stick is pulled out during the next call that reaches it: `HalError::Removed`, and it
    /// stays out until `insert_stick`.
    Removed,
}

/// The armed faults.
#[derive(Default)]
pub(crate) struct Armed(Vec<Fault>);

impl Armed {
    pub(crate) fn arm(&mut self, fault: Fault) {
        self.0.push(fault);
    }

    /// True, and disarmed, when `fault` was armed.
    pub(crate) fn take(&mut self, fault: Fault) -> bool {
        match self.0.iter().position(|&armed| armed == fault) {
            Some(index) => {
                self.0.remove(index);
                true
            }
            None => false,
        }
    }
}

/// The simulated hardware. No `Debug` or `Clone`: its log holds frames and models.
pub struct SimHal {
    panel: Panel,
    keys: Keys,
    hwrng: Hwrng,
    stick: Stick,
    armed: Armed,
}

impl SimHal {
    /// The hardware at power-on: no screen shown, an empty script, the clock at 0, `hwrng` ready
    /// and the stick out of the slot and empty.
    pub fn new(hwrng: HwRngStream) -> Self {
        SimHal {
            panel: Panel::new(),
            keys: Keys::new(),
            hwrng: Hwrng::new(hwrng),
            stick: Stick::new(),
            armed: Armed::default(),
        }
    }

    /// Adds a press of `key` to the script.
    pub fn press(&mut self, key: Key) {
        self.keys.press(key);
    }

    /// Adds `ns` nanoseconds with no key to the script.
    pub fn wait_ns(&mut self, ns: u64) {
        self.keys.wait_ns(ns);
    }

    /// Presses and waits in the script not yet played to their end.
    pub fn queued(&self) -> usize {
        self.keys.queued()
    }

    /// Arms `fault` for the next call it applies to.
    pub fn fault(&mut self, fault: Fault) {
        self.armed.arm(fault);
    }

    /// The presents since the last call, oldest first.
    pub fn take_presents(&mut self) -> Vec<Present> {
        self.panel.take()
    }

    /// The id of the last model presented.
    pub fn showing(&self) -> Option<ScreenId> {
        self.panel.showing()
    }

    /// From now on, writes every present as a PNG file into `dir`, with Protected screens as
    /// `protected` says, numbered on from `written`: the files the hardware before a power cycle
    /// wrote there in the same run.
    pub fn capture(&mut self, dir: PathBuf, protected: ProtectedFrames, written: u32) {
        self.panel.capture(dir, protected, written);
    }

    /// Live mode (tasks/todo.md, M3 group 12; Q30 (h)): from now on, rewrites `dir/live.png` with
    /// every present. Every Protected screen is written as `placeholder`, whatever the run: live
    /// mode takes no `ProtectedFrames`.
    pub fn live(&mut self, dir: PathBuf) {
        self.panel.live(dir);
    }

    pub fn insert_stick(&mut self) {
        self.stick.insert();
    }

    pub fn remove_stick(&mut self) {
        self.stick.remove();
    }

    /// How the stick mounts from now on.
    pub fn set_mount(&mut self, mount: Mount) {
        self.stick.set_mount(mount);
    }

    /// Puts a file on the stick, under any name (replacing one of that name).
    pub fn put_file(&mut self, name: &str, bytes: Vec<u8>) {
        self.stick.put(name, bytes);
    }

    /// The names of the files on the stick, in byte order.
    pub fn stick_files(&self) -> Vec<&str> {
        self.stick.names()
    }

    /// The bytes of file `name` on the stick.
    pub fn stick_file(&self, name: &str) -> Option<&[u8]> {
        self.stick.file(name)
    }

    /// Every call that reached the stick, with its mount.
    pub fn stick_log(&self) -> &[Access] {
        self.stick.log()
    }
}

impl Display for SimHal {
    fn present(&mut self, frame: &Frame, screen: &Screen<'_>) -> Result<(), HalError> {
        self.panel.present(frame, screen);
        Ok(())
    }
}

impl Buttons for SimHal {
    fn next_event(&mut self, deadline_ns: u64) -> Result<Event, HalError> {
        match self.panel.showing() {
            Some(id) if id.kind() == Kind::InputWaiting => {}
            Some(id) => panic!("next_event on {}, a transient screen", id.name()),
            None => panic!("next_event before any screen was presented"),
        }
        if self.armed.take(Fault::Buttons) {
            return Err(HalError::Buttons);
        }
        Ok(self.keys.next_event(deadline_ns))
    }
}

impl Clock for SimHal {
    fn now_ns(&self) -> u64 {
        self.keys.now_ns()
    }
}

impl HwRng for SimHal {
    fn read_block(&mut self, block: &mut [u8; 64]) -> Result<(), HalError> {
        if self.armed.take(Fault::HwRng) {
            return Err(HalError::HwRng);
        }
        self.hwrng.read(block)
    }
}

impl Usb for SimHal {
    fn stick(&mut self) -> Result<bool, HalError> {
        Ok(self.stick.inserted())
    }

    fn list(&mut self, kind: FileKind) -> Result<Vec<FileName>, HalError> {
        self.stick.list(&mut self.armed, kind)
    }

    fn read(&mut self, name: &FileName, max: usize) -> Result<Zeroizing<Vec<u8>>, HalError> {
        self.stick.read(&mut self.armed, name, max)
    }

    fn write_backup(&mut self, file: &BackupFile) -> Result<Written, HalError> {
        self.stick.write(&mut self.armed, file.name(), file.bytes())
    }

    fn read_written(
        &mut self,
        written: &Written,
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HalError> {
        self.stick.read_written(&mut self.armed, written, max)
    }

    fn remove_written(&mut self, written: Written) -> Result<(), HalError> {
        self.stick.remove_written(&mut self.armed, written)
    }
}

impl Hal for SimHal {
    fn build_info(&self) -> BuildInfo {
        BuildInfo {
            version: env!("CARGO_PKG_VERSION"),
            rootfs: String::from("sim"),
            simulator: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use keepcrypt_pi::screen::{Banners, Element, Item};
    use keepcrypt_pi::ui::Painter;

    use super::*;

    const NO_BANNERS: Banners = Banners {
        test_registry: false,
        simulator: false,
    };

    fn show(hal: &mut SimHal, id: ScreenId) {
        Painter::new()
            .present(hal, &Screen::new(id, "", NO_BANNERS))
            .expect("draws");
    }

    #[test]
    fn keys_are_played_on_input_waiting_screens_on_the_virtual_clock() {
        let mut hal = SimHal::new(HwRngStream::Counting);
        assert_eq!(hal.now_ns(), 0);
        show(&mut hal, ScreenId::Home);
        hal.press(Key::Down);
        hal.wait_ns(5_000_000_000);
        hal.press(Key::Press);
        assert_eq!(hal.queued(), 3);
        assert_eq!(
            hal.next_event(u64::MAX),
            Ok(Event::Key {
                key: Key::Down,
                at_ns: 0
            })
        );
        assert_eq!(
            hal.next_event(1_000_000_000),
            Ok(Event::Tick {
                now_ns: 1_000_000_000
            })
        );
        assert_eq!(
            hal.next_event(u64::MAX),
            Ok(Event::Key {
                key: Key::Press,
                at_ns: 5_024_000_000
            })
        );
        assert_eq!(hal.now_ns(), 5_048_000_000);
        assert_eq!(hal.queued(), 0);
        // A Buttons fault fails the next call only, and plays nothing.
        hal.press(Key::Key1);
        hal.fault(Fault::Buttons);
        assert_eq!(hal.next_event(u64::MAX), Err(HalError::Buttons));
        assert_eq!(hal.queued(), 1);
        assert!(matches!(
            hal.next_event(u64::MAX),
            Ok(Event::Key { key: Key::Key1, .. })
        ));
    }

    #[test]
    #[should_panic(expected = "next_event on wait, a transient screen")]
    fn waiting_for_a_key_on_a_transient_screen_fails() {
        let mut hal = SimHal::new(HwRngStream::Counting);
        show(&mut hal, ScreenId::Wait);
        hal.press(Key::Press);
        let event = hal.next_event(u64::MAX);
        unreachable!("next_event gave {event:?}");
    }

    #[test]
    #[should_panic(expected = "next_event before any screen was presented")]
    fn waiting_for_a_key_before_any_screen_fails() {
        let mut hal = SimHal::new(HwRngStream::Counting);
        hal.press(Key::Press);
        let event = hal.next_event(u64::MAX);
        unreachable!("next_event gave {event:?}");
    }

    #[test]
    fn an_hwrng_fault_fails_one_read_and_serves_no_byte() {
        let mut hal = SimHal::new(HwRngStream::Counting);
        let mut block = [0u8; 64];
        hal.fault(Fault::HwRng);
        assert_eq!(hal.read_block(&mut block), Err(HalError::HwRng));
        assert_eq!(hal.read_block(&mut block), Ok(()));
        assert_eq!(block[..4], [0, 1, 2, 3], "the stream starts where it was");
    }

    #[test]
    fn the_build_is_the_simulator() {
        let hal = SimHal::new(HwRngStream::Counting);
        assert_eq!(
            hal.build_info(),
            BuildInfo {
                version: "0.0.0",
                rootfs: String::from("sim"),
                simulator: true,
            }
        );
    }

    #[test]
    fn the_display_logs_each_model_it_is_handed() {
        let mut hal = SimHal::new(HwRngStream::Counting);
        let screen = Screen::new(ScreenId::Dice, "Dice", NO_BANNERS).with(Element::public(
            (0, 0).into(),
            Item::Text("37 / 50 rolls".into()),
        ));
        Painter::new().present(&mut hal, &screen).expect("draws");
        assert_eq!(hal.showing(), Some(ScreenId::Dice));
        let presents = hal.take_presents();
        assert_eq!(presents.len(), 1);
        assert_eq!(presents[0].elements[0].item.text(), Some("37 / 50 rolls"));
        assert!(hal.take_presents().is_empty());
    }
}
