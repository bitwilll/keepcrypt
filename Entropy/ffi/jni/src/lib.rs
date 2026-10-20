//! keepcrypt-jni: the Android JNI boundary, built as libkeepcrypt.so (Q53), and the workspace's
//! only unsafe code. Its exports come with M5 commit 12: each one calls keepcrypt_guard::guarded,
//! the one panic catch, and every unsafe block holds one operation and a SAFETY: comment.
