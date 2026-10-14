//! The one file the firmware creates is the backup, through the one create_new open below; a
//! listing walks `/sys/block` and follows where each entry links under `/sys/devices`.
use std::fs::{self, File, OpenOptions};
const MNT_DETACH: c_int = 2;
let file = OpenOptions::new().write(true).create_new(true).open(&path)?;
fs::remove_file(&path)?;
// No buffered reader: the block is read straight into the buffer the app wipes. Joined names,
// a slash inside a string and a slash character are not path literals.
let joined = dir.join("seed.age");
let half = "a/b";
let slash = '/';
let detach = Unmount::Detach;

#[cfg(test)]
mod tests;
