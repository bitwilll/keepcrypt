// The HAL names files only in prose: every implementation keeps its own record of the file it
// last wrote, and a Vec grows with extend, never append( or truncate( after a dot.
fn write_backup(&mut self, name: &str, bytes: &[u8]) -> Result<(), HalError>;
let renamed_key = key;
let appended = v.len();
let fs_total = 2;
let fsck = 1;
let ratio = "K/T";
