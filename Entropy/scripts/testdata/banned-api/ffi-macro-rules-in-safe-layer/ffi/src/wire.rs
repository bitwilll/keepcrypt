// A macro here could be exported to keepcrypt-jni and write an export there (lead decision M5-35).
macro_rules! status_byte { ($s:expr) => { $s.code() }; }
