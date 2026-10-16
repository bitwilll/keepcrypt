//! The Linux glue (tasks/todo.md, M4 group 10; Q35, Q39 (e)): `PiHal`, the drivers' pure parts on
//! the Pi Zero's devices through rppal and nix, and `run`, the binary's whole life on the Pi.
//!
//! - Compiled on Linux alone, so CI's lint and cross jobs build it first and the board runs it
//!   first (H1a). Nothing here runs on a host: the rules are the pure parts' and their tests', and
//!   each call made here maps its error to one fixed `HalError` and nothing else (rule 3).
//! - `run` opens the panel before anything else, so that stop mode and every start-up fault can be
//!   shown, and parks the process on any of them: the process never exits, init waits for it, and
//!   the stop screen stays until a power cycle (Q35). A panic prints nothing (the hook) and unwinds
//!   out of `run` through `App`, whose `hal` drops first, so the panel blanks and its backlight
//!   goes off before the session is wiped; the process then ends, and init starts stop mode.
//! - Memory is locked, current and future pages, before any secret exists (Q39 (e)).
//! - Every path opened or mounted is a constant of `paths` (rule 8); rppal names its own.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use keepcrypt_core::BackupFile;
use keepcrypt_pi::hal::{
    BuildInfo, Buttons, Clock, Display, FileKind, FileName, Hal, HalError, HwRng, Usb, Written,
    Zeroizing,
};
use keepcrypt_pi::input::{Event, Key};
use keepcrypt_pi::screen::Screen;
use keepcrypt_pi::ui::Frame;
use keepcrypt_pi::{App, show_stop};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::mount::{MntFlags, MsFlags};
use nix::sys::mman::{MlockAllFlags, mlockall};
use nix::time::{ClockId, clock_gettime};
use rppal::gpio::{Gpio, InputPin, Level, OutputPin, Trigger};
use rppal::spi::{self, SlaveSelect, Spi};

use super::hwrng::{self, RawRead};
use super::keys::{self, Edge, EdgeSource, KeyLoop};
use super::panel::{Bus, PANEL, Panel};
use super::usb::{DeviceUsb, Finder, MountPlan, Mounter, SysBlock, Unmount};
use super::{Mode, mode, paths, rootfs};

// The panel's pins (pi-firmware.md "Pin map used by the firmware"): the same on every screen (Q48).
/// The data/command line.
const DC_PIN: u8 = 25;
/// The reset line (active low).
const RST_PIN: u8 = 27;
/// The backlight (active high).
const BL_PIN: u8 = 24;

/// The binary on the Pi, in group 10's order. It never returns: the ceremony runs until power-off,
/// and every other outcome parks the process on what the panel shows.
pub fn run() -> ! {
    // 1. A crash prints nothing: a panic message could name a secret (Q35).
    std::panic::set_hook(Box::new(|_| {}));
    // 2. The panel, with all of its frame memory black, so that whatever follows can be shown.
    //    With no panel nothing can be: its backlight, opened first and driven low, is off.
    let gpio = match Gpio::new() {
        Ok(gpio) => gpio,
        Err(_) => park(),
    };
    let panel = match open_panel(&gpio) {
        Ok(panel) => panel,
        Err(_) => park(),
    };
    // 3. Stop mode (Q35): the stop screen until a power cycle, with nothing else opened.
    if mode(env::args_os().skip(1)) == Mode::Stopped {
        stop(panel, HalError::Stopped);
    }
    // 4. Every page, now and later, stays in RAM (Q39 (e)).
    match mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
        Ok(()) => {}
        Err(_) => stop(panel, HalError::MemoryLock),
    }
    // 5. The root filesystem's prefix for the boot screen and About (Q39 (g)).
    let rootfs = match rootfs_prefix() {
        Ok(prefix) => prefix,
        Err(_) => stop(panel, HalError::RootFs),
    };
    // 6. The keys, then the hwrng.
    let keys = match open_keys(gpio) {
        Ok(edges) => KeyLoop::new(edges, MonotonicClock),
        Err(_) => stop(panel, HalError::Buttons),
    };
    let hwrng = match HwRngDevice::open() {
        Ok(device) => device,
        Err(_) => stop(panel, HalError::HwRng),
    };
    // 7. The stick is looked up and mounted on each call, so nothing is opened for it here.
    let usb = DeviceUsb::new(
        Finder::new(SysFs::new(), PathBuf::from(paths::DEV)),
        KernelMounter,
        PathBuf::from(paths::USB_MOUNT),
    );
    let hal = PiHal {
        panel,
        keys,
        clock: MonotonicClock,
        hwrng,
        usb,
        rootfs,
    };
    App::new(hal).run()
}

/// The stop screen for `fault` (Q35) on `panel`, then the process parks on it: init waits for the
/// process, so nothing else starts, and only a power cycle ends the screen.
fn stop<B: Bus>(mut panel: Panel<B>, fault: HalError) -> ! {
    match show_stop(&mut panel, fault) {
        // The stop screen is on the panel until the power cycle.
        Ok(()) => park(),
        // Only the panel can stop the stop screen; it then keeps what it last took, with its
        // backlight off (the driver's rule on every bus fault). Nothing is held, so nothing is
        // left to do but wait for the power cycle all the same.
        Err(_) => park(),
    }
}

/// Parks the thread for good: the process never exits, so init never moves on. A park may end
/// early, hence the loop.
fn park() -> ! {
    loop {
        thread::park();
    }
}

/// Waits `ms` milliseconds (the panel's and the hwrng's pauses).
fn sleep_ms(ms: u16) {
    thread::sleep(Duration::from_millis(u64::from(ms)));
}

/// The panel through its init, steps 1-8, so that all of its frame memory is black. Any fault is
/// `Display`, and the backlight pin, opened first and driven low, then stays low.
fn open_panel(gpio: &Gpio) -> Result<Panel<SpiBus>, HalError> {
    let bl = output(gpio, BL_PIN)?;
    let dc = output(gpio, DC_PIN)?;
    let rst = output(gpio, RST_PIN)?;
    let spi = Spi::new(
        spi::Bus::Spi0,
        SlaveSelect::Ss0,
        PANEL.spi_hz,
        spi::Mode::Mode0,
    )
    .map_err(|_| HalError::Display)?;
    Panel::new(SpiBus { spi, dc, rst, bl }, PANEL)
}

/// Output `pin`, driven low, and left as the driver leaves it when dropped: rppal would otherwise
/// return the pin to an input, which would float the backlight.
fn output(gpio: &Gpio, pin: u8) -> Result<OutputPin, HalError> {
    let mut output = gpio
        .get(pin)
        .map_err(|_| HalError::Display)?
        .into_output_low();
    output.set_reset_on_drop(false);
    Ok(output)
}

/// The panel's wires: spidev's `/dev/spidev0.0` in mode 0 at the profile's clock, and three output
/// pins. A GPIO write is one register write through rppal's `/dev/gpiomem` map, which cannot fail;
/// an SPI write is one write(2), whole or a `Display` fault.
struct SpiBus {
    spi: Spi,
    /// DC, BCM 25.
    dc: OutputPin,
    /// RST, BCM 27.
    rst: OutputPin,
    /// BL, BCM 24.
    bl: OutputPin,
}

impl SpiBus {
    /// One write(2) of `bytes`: all of them, or `Display`. spidev takes at most 4,096 bytes a
    /// write, and the panel never sends more.
    fn write(&mut self, bytes: &[u8]) -> Result<(), HalError> {
        match self.spi.write(bytes) {
            Ok(written) if written == bytes.len() => Ok(()),
            Ok(_) | Err(_) => Err(HalError::Display),
        }
    }
}

impl Bus for SpiBus {
    fn command(&mut self, cmd: u8, args: &[u8]) -> Result<(), HalError> {
        self.dc.set_low();
        self.write(&[cmd])?;
        if !args.is_empty() {
            self.dc.set_high();
            self.write(args)?;
        }
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> Result<(), HalError> {
        self.dc.set_high();
        self.write(bytes)
    }

    fn reset(&mut self, high: bool) {
        self.rst.write(Level::from(high));
    }

    fn backlight(&mut self, on: bool) {
        self.bl.write(Level::from(on));
    }

    fn sleep_ms(&mut self, ms: u16) {
        sleep_ms(ms);
    }
}

/// The eight key lines, inputs with pull-ups and both-edge events (pi-firmware.md
/// "`hal::Buttons`"), on the pins `Key::bcm_pin` names. Any fault is `Buttons`.
fn open_keys(gpio: Gpio) -> Result<GpioEdges, HalError> {
    let mut pins = Vec::with_capacity(Key::ALL.len());
    for key in Key::ALL {
        let mut pin = gpio
            .get(key.bcm_pin())
            .map_err(|_| HalError::Buttons)?
            .into_input_pullup();
        pin.set_interrupt(Trigger::Both, None)
            .map_err(|_| HalError::Buttons)?;
        pins.push(pin);
    }
    Ok(GpioEdges { gpio, pins })
}

/// The key lines' edges, with the kernel's `CLOCK_MONOTONIC` timestamps, through rppal's
/// synchronous poll in this thread.
struct GpioEdges {
    gpio: Gpio,
    pins: Vec<InputPin>,
}

impl EdgeSource for GpioEdges {
    fn next_edge(&mut self, timeout: Option<Duration>) -> Result<Option<Edge>, HalError> {
        let pins: Vec<&InputPin> = self.pins.iter().collect();
        // `reset` false: an edge rppal has already taken from the kernel and holds is given out,
        // not dropped.
        match self.gpio.poll_interrupts(&pins, false, timeout) {
            Ok(None) => Ok(None),
            Ok(Some((pin, event))) => {
                let falling = match event.trigger {
                    Trigger::FallingEdge => true,
                    Trigger::RisingEdge => false,
                    // An event carries one of the two edges; anything else is no edge.
                    Trigger::Disabled | Trigger::Both => return Err(HalError::Buttons),
                };
                Ok(Some(Edge {
                    pin: pin.pin(),
                    falling,
                    timestamp: event.timestamp,
                }))
            }
            Err(_) => Err(HalError::Buttons),
        }
    }
}

/// `CLOCK_MONOTONIC`, the base of the edges' timestamps, in nanoseconds (`keys::clock_ns`).
struct MonotonicClock;

impl Clock for MonotonicClock {
    fn now_ns(&self) -> u64 {
        match clock_gettime(ClockId::CLOCK_MONOTONIC) {
            Ok(now) => keys::clock_ns(now.tv_sec(), now.tv_nsec()),
            // `now_ns` returns no `Result`: the panic ends in stop mode (Q35).
            Err(_) => panic!("the monotonic clock could not be read"),
        }
    }
}

/// `/dev/hwrng`, opened once, non-blocking: a read that finds nothing yet is `WouldBlock`, which
/// `fill_block` retries until its deadline (Q39 (c)).
struct HwRngDevice {
    file: File,
}

impl HwRngDevice {
    fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(OFlag::O_NONBLOCK.bits())
            .open(paths::HWRNG)?;
        Ok(HwRngDevice { file })
    }
}

impl RawRead for HwRngDevice {
    /// One read(2); std gives `EAGAIN` as `WouldBlock` and `EINTR` as `Interrupted`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    fn sleep_ms(&mut self, ms: u16) {
        sleep_ms(ms);
    }
}

/// The root filesystem's prefix from the root partition (Q39 (g)). A block device's metadata gives
/// no length, so its end is sought and the device rewound before the read.
fn rootfs_prefix() -> Result<String, HalError> {
    let mut partition = File::open(paths::ROOT_PARTITION).map_err(|_| HalError::RootFs)?;
    let len = partition
        .seek(SeekFrom::End(0))
        .map_err(|_| HalError::RootFs)?;
    partition
        .seek(SeekFrom::Start(0))
        .map_err(|_| HalError::RootFs)?;
    rootfs::prefix(&mut partition, len)
}

/// `/sys/block` as the finder reads it: one entry per disk, a link into `/sys/devices`, with its
/// `ro` attribute and, when the disk has a first partition, that partition's directory.
struct SysFs {
    block: PathBuf,
}

impl SysFs {
    fn new() -> Self {
        SysFs {
            block: PathBuf::from(paths::SYS_BLOCK),
        }
    }
}

impl SysBlock for SysFs {
    fn entries(&mut self) -> io::Result<Vec<OsString>> {
        fs::read_dir(&self.block)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    }

    fn device_link(&mut self, name: &str) -> io::Result<PathBuf> {
        fs::read_link(self.block.join(name))
    }

    fn ro(&mut self, name: &str) -> io::Result<Vec<u8>> {
        fs::read(self.block.join(name).join("ro"))
    }

    fn has_partition(&mut self, name: &str) -> io::Result<bool> {
        self.block.join(name).join(format!("{name}1")).try_exists()
    }
}

/// mount(2) and umount2(2) through nix; `sync` keeps its default, `File::sync_all` (9c). The plans
/// hold the kernel's own flag values in mount(2)'s type, so `from_bits` only checks that each is one
/// the kernel defines (the Linux test pins both plans) and refuses any other with `EINVAL`, before
/// the call. The loop-device test drives this mounter, so the mounts it proves are the image's.
pub struct KernelMounter;

impl Mounter for KernelMounter {
    fn mount(&mut self, device: &Path, target: &Path, plan: MountPlan) -> io::Result<()> {
        let Some(flags) = MsFlags::from_bits(plan.flags) else {
            return Err(io::Error::from(Errno::EINVAL));
        };
        nix::mount::mount(Some(device), target, Some(plan.fstype), flags, None::<&str>)
            .map_err(io::Error::from)
    }

    fn unmount(&mut self, target: &Path, how: Unmount) -> io::Result<()> {
        let Some(flags) = MntFlags::from_bits(how.flags()) else {
            return Err(io::Error::from(Errno::EINVAL));
        };
        nix::mount::umount2(target, flags).map_err(io::Error::from)
    }
}

/// The Pi Zero's hardware for `App`. The panel is its first field, so it drops first when the app
/// unwinds: frame memory blanks and the backlight goes off before anything else is dropped.
struct PiHal {
    panel: Panel<SpiBus>,
    keys: KeyLoop<GpioEdges, MonotonicClock>,
    clock: MonotonicClock,
    hwrng: HwRngDevice,
    usb: DeviceUsb<Finder<SysFs>, KernelMounter>,
    /// The root filesystem's prefix, computed once at start-up.
    rootfs: String,
}

impl Display for PiHal {
    fn present(&mut self, frame: &Frame, screen: &Screen<'_>) -> Result<(), HalError> {
        self.panel.present(frame, screen)
    }
}

impl Buttons for PiHal {
    fn next_event(&mut self, deadline_ns: u64) -> Result<Event, HalError> {
        self.keys.next_event(deadline_ns)
    }
}

impl Clock for PiHal {
    fn now_ns(&self) -> u64 {
        self.clock.now_ns()
    }
}

impl HwRng for PiHal {
    fn read_block(&mut self, block: &mut [u8; 64]) -> Result<(), HalError> {
        hwrng::fill_block(&mut self.hwrng, &self.clock, block, hwrng::DEADLINE_NS)
    }
}

impl Usb for PiHal {
    fn stick(&mut self) -> Result<bool, HalError> {
        self.usb.stick()
    }

    fn list(&mut self, kind: FileKind) -> Result<Vec<FileName>, HalError> {
        self.usb.list(kind)
    }

    fn read(&mut self, name: &FileName, max: usize) -> Result<Zeroizing<Vec<u8>>, HalError> {
        self.usb.read(name, max)
    }

    fn write_backup(&mut self, file: &BackupFile) -> Result<Written, HalError> {
        self.usb.write_backup(file)
    }

    fn read_written(
        &mut self,
        written: &Written,
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HalError> {
        self.usb.read_written(written, max)
    }

    fn remove_written(&mut self, written: Written) -> Result<(), HalError> {
        self.usb.remove_written(written)
    }
}

impl Hal for PiHal {
    fn build_info(&self) -> BuildInfo {
        BuildInfo {
            version: env!("CARGO_PKG_VERSION"),
            rootfs: self.rootfs.clone(),
            simulator: false,
        }
    }
}
