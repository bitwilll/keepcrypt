// The device module alone opens files, calls rppal and nix, and parks the thread.
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use nix::mount::{MntFlags, MsFlags};
use rppal::gpio::Gpio;
let hwrng = OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(paths::HWRNG)?;
let partition = File::open(paths::ROOT_PARTITION)?;
for entry in fs::read_dir(paths::SYS_BLOCK)? {
    let target = fs::read_link(entry?.path())?;
}
nix::mount::mount(Some(device), paths::USB_MOUNT, Some("vfat"), MsFlags::MS_RDONLY, None::<&str>)?;
let flags = MntFlags::from_bits(how.flags()).ok_or(Errno::EINVAL)?;
let gpio = Gpio::new()?;
loop {
    std::thread::park();
}
