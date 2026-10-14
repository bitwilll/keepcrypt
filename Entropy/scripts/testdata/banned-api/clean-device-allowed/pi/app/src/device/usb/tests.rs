// Temp-dir fixtures: declared by usb.rs with #[cfg(test)] right before mod tests;.
use nix::mount::MsFlags;
fs::create_dir(&dir).expect("a scratch folder");
fs::write(dir.join(BACKUP), b"earlier").expect("a file");
fs::remove_dir_all(dir).expect("removed");
