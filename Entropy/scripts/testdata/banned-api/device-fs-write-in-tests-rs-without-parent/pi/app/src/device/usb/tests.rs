// No usb.rs or usb/mod.rs declares this file with #[cfg(test)], so it is an ordinary device file.
fs::write(dir.join("b.age"), b"b").expect("a file");
