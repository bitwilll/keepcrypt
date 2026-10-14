//! Every path the firmware opens or mounts (CLAUDE.md rule 8; docs/pi-firmware.md "Process rules";
//! tasks/todo.md, M4 groups 10 and 11), as constants: the one place in pi/app where a path
//! literal lives, so the grep gate can hold the firmware to pi-firmware.md's list. rppal builds its
//! own `/dev/spidev*`, `/dev/gpio*` and `/proc` paths, which that list also names.

/// The hardware random number generator, read raw for core's health tests (`hal::HwRng`).
pub const HWRNG: &str = "/dev/hwrng";
/// The root partition, hashed at start-up for the prefix on the boot screen and About (Q39 (g)).
pub const ROOT_PARTITION: &str = "/dev/mmcblk0p2";
/// Where the block device nodes are: the stick is `sdX1` there, or `sdX` with no first partition.
pub const DEV: &str = "/dev";
/// The kernel's block devices, searched for the one stick (`hal::Usb`).
pub const SYS_BLOCK: &str = "/sys/block";
/// Where the stick is mounted for each call, and unmounted again (pi-firmware.md "USB stick").
pub const USB_MOUNT: &str = "/mnt/usb";
