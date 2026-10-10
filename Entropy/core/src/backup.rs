//! The encrypted backup (docs/build-plan.md "Encrypted backup format"; CLAUDE.md rule 8;
//! tasks/todo.md, M1 group 8, Q1, Q5, Q6e).
//!
//! The only file KeepCrypt ever writes is an age v1 file with one scrypt stanza, armored, at work
//! factor 18 under a generated 8-word passphrase; the only backups it reads are such files.
//! - `armor`: the strict PEM armor (vectors/backup.json spec "armor").
//! - `age`: the header, the scrypt stanza, the reader and the writer (spec "header",
//!   "scrypt_stanza", "keys", "reader"), checked against every CCTV scrypt file and backup.json.
//!
//! Core does no file I/O: the shells write and read the bytes.

pub(crate) mod age;
pub(crate) mod armor;
