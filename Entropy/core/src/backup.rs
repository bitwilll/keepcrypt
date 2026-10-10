//! The encrypted backup (docs/build-plan.md "Encrypted backup format"; CLAUDE.md rule 8;
//! tasks/todo.md, M1 group 8, Q1, Q5, Q6e).
//!
//! The only file KeepCrypt ever writes is an age v1 file with one scrypt stanza, armored, at work
//! factor 18 under a generated 8-word passphrase; the only backups it reads are such files.
//! - `armor`: the strict PEM armor (vectors/backup.json spec "armor").
//! - `age`: the header, the scrypt stanza, the reader and the writer (spec "header",
//!   "scrypt_stanza", "keys", "reader"), checked against every CCTV scrypt file and backup.json.
//! - `passphrase`: the generated passphrase and its 2-of-4 confirm challenge (spec "passphrase",
//!   "generate").
//! - `plaintext`: the plaintext v1 writer and reader (spec "plaintext", "plaintext_reader").
//!
//! The API (Q5): `Session<Ready>` generates the passphrase and keeps it
//! (`generate_backup_passphrase`, returning a `NewBackupPassphrase` display copy); `encrypt_backup`
//! and `verify_backup` take no passphrase and use the stored one, so typed words can never encrypt.
//! Typed words (`TypedBackupPassphrase`) reach only `decrypt_backup` ("Check a backup"), which
//! returns a `CheckedBackup`: the fingerprint and the seal for re-checks, and the words and braille
//! only through `reveal_words` and `reveal_braille`. Each file's key, salt, nonce and name come from
//! the session's OS source in that order, in reads of their own that never touch the pool.
//!
//! Core does no file I/O: the shells write and read the bytes.

pub(crate) mod age;
pub(crate) mod armor;
mod passphrase;
mod plaintext;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::braille::BrailleInserts;
use crate::error::{CoreError, KatId};
use crate::kat::{self, Suite};
use crate::seal::{self, SealPublic};
use crate::secret::{BackupPassphrase, NewBackupPassphrase, SecretMnemonic, TypedBackupPassphrase};
use crate::source::Source;

/// The file name's prefix and suffix around 8 lowercase hex digits.
const FILE_NAME_PREFIX: &str = "keepcrypt-backup-";
const FILE_NAME_SUFFIX: &str = ".age";
/// OS bytes behind a file name.
const FILE_NAME_BYTES: usize = 4;
/// The created-by line's text before the app's name.
const CREATED_BY_PREFIX: &str = "created-by: keepcrypt-";

/// The app that wrote a backup, named in its `created-by:` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupApp {
    /// The Raspberry Pi firmware: `keepcrypt-pi`.
    Pi,
    /// The Android app: `keepcrypt-android`.
    Android,
    /// The iPhone app: `keepcrypt-ios`.
    Ios,
}

impl BackupApp {
    const fn name(self) -> &'static str {
        match self {
            BackupApp::Pi => "pi",
            BackupApp::Android => "android",
            BackupApp::Ios => "ios",
        }
    }
}

/// The plaintext's `created-by: keepcrypt-<app> X.Y.Z` line: public, given by the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatedBy {
    app: BackupApp,
    version: [u16; 3],
}

impl CreatedBy {
    /// `keepcrypt-<app> major.minor.patch`.
    pub const fn new(app: BackupApp, major: u16, minor: u16, patch: u16) -> Self {
        Self {
            app,
            version: [major, minor, patch],
        }
    }

    /// The app.
    pub fn app(&self) -> BackupApp {
        self.app
    }

    /// The version, major first.
    pub fn version(&self) -> [u16; 3] {
        self.version
    }

    /// The length of the line `push_line` writes, its LF included.
    fn line_len(&self) -> usize {
        let digits = |n: u16| match n {
            0..=9 => 1,
            10..=99 => 2,
            100..=999 => 3,
            1000..=9999 => 4,
            _ => 5,
        };
        let numbers = self.version.iter().map(|&n| digits(n)).sum::<usize>();
        CREATED_BY_PREFIX.len() + self.app.name().len() + 1 + numbers + 2 + 1
    }

    /// Appends `created-by: keepcrypt-<app> X.Y.Z` and LF.
    fn push_line(&self, out: &mut String) {
        out.push_str(CREATED_BY_PREFIX);
        out.push_str(self.app.name());
        out.push(' ');
        for (n, &part) in self.version.iter().enumerate() {
            if n > 0 {
                out.push('.');
            }
            push_decimal(out, part);
        }
        out.push('\n');
    }

    /// The created-by line without its LF, read back; `None` if it is not one. Lenient about the
    /// numbers ("+1", "01"): the plaintext reader writes the line again and compares the bytes.
    fn parse_line(line: &str) -> Option<Self> {
        let (app, version) = line.strip_prefix(CREATED_BY_PREFIX)?.split_once(' ')?;
        let app = match app {
            "pi" => BackupApp::Pi,
            "android" => BackupApp::Android,
            "ios" => BackupApp::Ios,
            _ => return None,
        };
        let mut parts = version.split('.');
        let mut numbers = [0u16; 3];
        for number in &mut numbers {
            *number = match parts.next()?.parse::<u16>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        }
        match parts.next() {
            Some(_) => None,
            None => Some(Self::new(app, numbers[0], numbers[1], numbers[2])),
        }
    }
}

/// Appends a number in decimal, without leading zeros.
fn push_decimal(out: &mut String, n: u16) {
    let mut digits = [0u8; 5];
    let mut rest = n;
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (rest % 10).to_be_bytes()[1];
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    out.extend(digits[start..].iter().map(|&d| char::from(d)));
}

/// A written backup: the file name and the armored bytes for the shell to save. Ciphertext, so
/// public; no `Debug`, so it is never printed by accident.
pub struct BackupFile {
    name: String,
    bytes: Vec<u8>,
}

impl BackupFile {
    /// `keepcrypt-backup-<8 lowercase hex>.age`, from 4 fresh OS bytes: no fingerprint or date.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The armored age file.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A backup that opened and holds a valid KeepCrypt plaintext ("Check a backup"): its words and
/// its fingerprint, which the plaintext names and which was recomputed from the words. Wiped on
/// drop; no `Debug`, `Display` or `Clone`. The shells show the fingerprint, and the words or the
/// braille only when the user asks (pi-firmware.md and mobile-apps.md, "Checking a backup").
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CheckedBackup {
    mnemonic: SecretMnemonic,
    fingerprint: [u8; 4],
}

impl CheckedBackup {
    /// The master key fingerprint of the words with the empty passphrase.
    pub fn fingerprint(&self) -> [u8; 4] {
        self.fingerprint
    }

    /// The seal of these words, for a re-check by loaded snapshot or online
    /// (`SealPublic::recheck_url`). Runs the Seal known-answer group (`seal_from_mnemonic`).
    pub fn seal(&self) -> Result<SealPublic, CoreError> {
        seal::seal_from_mnemonic(&self.mnemonic)
    }

    /// The words, in order: only when the user asks to see them. Each borrows `self`.
    pub fn reveal_words(&self) -> impl Iterator<Item = &str> + '_ {
        self.mnemonic.words()
    }

    /// The braille inserts of these words: only when the user asks. They borrow `self`. The
    /// plaintext's braille lines were checked against these words when it was read.
    pub fn reveal_braille(&self) -> BrailleInserts<'_> {
        BrailleInserts::new(&self.mnemonic)
    }
}

/// "Check a backup": opens an armored or binary age file with typed passphrase words and reads
/// its plaintext. Runs the Age known-answer group first. Errors: `Kat(Age)`, `WrongPassphrase`,
/// and `Backup(_)` for a file or plaintext that is not a KeepCrypt backup.
pub fn decrypt_backup(
    file: &[u8],
    passphrase: &TypedBackupPassphrase,
) -> Result<CheckedBackup, CoreError> {
    decrypt_backup_body(file, passphrase, None)
}

/// `decrypt_backup` with known-answer group `fault` made to fail (tests only).
#[cfg(feature = "test-sources")]
pub fn decrypt_backup_with_kat_fault(
    file: &[u8],
    passphrase: &TypedBackupPassphrase,
    fault: KatId,
) -> Result<CheckedBackup, CoreError> {
    decrypt_backup_body(file, passphrase, Some(fault))
}

fn decrypt_backup_body(
    file: &[u8],
    passphrase: &TypedBackupPassphrase,
    fault: Option<KatId>,
) -> Result<CheckedBackup, CoreError> {
    kat::run(Suite::Backup, fault)?;
    let opened = age::decrypt(file, passphrase.text().as_bytes())?;
    let mut checked = CheckedBackup {
        mnemonic: SecretMnemonic::zeroed(),
        fingerprint: [0; 4],
    };
    checked.fingerprint = plaintext::parse_into(&opened, &mut checked.mnemonic)?;
    Ok(checked)
}

/// Generates the session's backup passphrase into `stored`, replacing any earlier one, with its
/// confirm challenge; returns the display copy (`Session<Ready>::generate_backup_passphrase`).
pub(crate) fn new_passphrase(
    source: &mut Source,
    stored: &mut BackupPassphrase,
) -> Result<NewBackupPassphrase, CoreError> {
    passphrase::generate(source, stored)
}

/// Writes the session's backup under the stored passphrase (`Session<Ready>::encrypt_backup`):
/// the plaintext v1, then the file key, salt, nonce and file name from the OS source, in that
/// order, at work factor 18. `NoBackupPassphrase` before one was generated.
pub(crate) fn encrypt(
    source: &mut Source,
    stored: &BackupPassphrase,
    mnemonic: &SecretMnemonic,
    fingerprint: [u8; 4],
    by: &CreatedBy,
) -> Result<BackupFile, CoreError> {
    if !stored.is_present() {
        return Err(CoreError::NoBackupPassphrase);
    }
    let mut text = Zeroizing::new(String::with_capacity(plaintext::len(mnemonic, by)));
    plaintext::write_into(mnemonic, fingerprint, by, &mut text);
    let file_key = source.os_bytes::<{ age::FILE_KEY_BYTES }>()?;
    let salt = source.os_bytes::<{ age::SALT_BYTES }>()?;
    let nonce = source.os_bytes::<{ age::NONCE_BYTES }>()?;
    let name = source.os_bytes::<FILE_NAME_BYTES>()?;
    let secrets = age::FileSecrets::new(&file_key, &salt, &nonce);
    let binary = age::encrypt(
        stored.text().as_bytes(),
        &secrets,
        age::WRITE_WORK_FACTOR,
        text.as_bytes(),
    )?;
    Ok(BackupFile {
        name: file_name(&name),
        bytes: armor::encode(&binary)?,
    })
}

/// `keepcrypt-backup-<8 lowercase hex>.age`.
fn file_name(bytes: &[u8; FILE_NAME_BYTES]) -> String {
    let mut name = String::with_capacity(
        FILE_NAME_PREFIX.len() + 2 * FILE_NAME_BYTES + FILE_NAME_SUFFIX.len(),
    );
    name.push_str(FILE_NAME_PREFIX);
    seal::push_hex(&mut name, bytes);
    name.push_str(FILE_NAME_SUFFIX);
    name
}

/// Reads a written backup back with the stored passphrase and compares its words and fingerprint
/// with the session's (`Session<Ready>::verify_backup`). Errors: `NoBackupPassphrase`,
/// `WrongPassphrase`, `ReadbackMismatch`, and `Backup(_)` for a malformed file.
pub(crate) fn verify(
    stored: &BackupPassphrase,
    file: &[u8],
    mnemonic: &SecretMnemonic,
    fingerprint: [u8; 4],
) -> Result<(), CoreError> {
    if !stored.is_present() {
        return Err(CoreError::NoBackupPassphrase);
    }
    let opened = age::decrypt(file, stored.text().as_bytes())?;
    let mut read_back = SecretMnemonic::zeroed();
    let read_fingerprint = plaintext::parse_into(&opened, &mut read_back)?;
    if read_back.matches(mnemonic) && read_fingerprint == fingerprint {
        Ok(())
    } else {
        Err(CoreError::ReadbackMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BackupError;
    use crate::secret::TestFill;
    use crate::session::{Ready, Session};
    use crate::test_vectors::{hex, hex_str, named, read, text};
    use serde_json::Value;

    /// BIP39 word indices of a mnemonic.
    fn indices(mnemonic: &str) -> Vec<usize> {
        mnemonic
            .split(' ')
            .map(|w| usize::from(bip39::Language::English.find_word(w).expect("a list word")))
            .collect()
    }

    fn mnemonic_of(words: &str) -> SecretMnemonic {
        let mut mnemonic = SecretMnemonic::zeroed();
        mnemonic
            .fill_from(indices(words).into_iter())
            .expect("12 or 24 words");
        mnemonic
    }

    fn created_by(case: &Value) -> CreatedBy {
        let app = match text(&case["created_by"]["app"]) {
            "pi" => BackupApp::Pi,
            "android" => BackupApp::Android,
            _ => BackupApp::Ios,
        };
        let v: Vec<u16> = case["created_by"]["version"]
            .as_array()
            .expect("a version")
            .iter()
            .map(|n| u16::try_from(n.as_u64().expect("a number")).expect("u16"))
            .collect();
        CreatedBy::new(app, v[0], v[1], v[2])
    }

    fn fingerprint_of(case: &Value) -> [u8; 4] {
        <[u8; 4]>::try_from(hex(&case["fingerprint"]).as_slice()).expect("4 bytes")
    }

    fn typed(passphrase: &str) -> TypedBackupPassphrase {
        let words: Vec<&str> = passphrase.split(' ').collect();
        TypedBackupPassphrase::from_words(&words).expect("8 list words")
    }

    fn words_of(new: &NewBackupPassphrase) -> String {
        new.words().collect::<Vec<_>>().join(" ")
    }

    fn ready(mnemonic: &str) -> Session<Ready> {
        Session::<Ready>::ready_for_test(&indices(mnemonic), Source::Os).expect("a Ready session")
    }

    fn plaintext_case<'a>(doc: &'a Value, name: &str) -> &'a Value {
        named(&doc["plaintexts"], name)
    }

    /// A backup.json file entry's bytes: armored text in "file", anything else in "file_hex".
    fn case_file(case: &Value) -> Vec<u8> {
        match case["file"].as_str() {
            Some(file) => file.as_bytes().to_vec(),
            None => hex(&case["file_hex"]),
        }
    }

    /// The salt in a backup's stanza and the nonce at the start of its payload, as base64 and bytes.
    fn salt_and_nonce(file: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let binary = armor::decode(file).expect("armored");
        let version = b"age-encryption.org/v1\n".len();
        let stanza_end = version
            + binary[version..]
                .iter()
                .position(|&b| b == b'\n')
                .expect("a stanza line");
        let salt = binary[version..stanza_end]
            .split(|&b| b == b' ')
            .nth(2)
            .expect("the salt")
            .to_vec();
        let mac_line = binary
            .windows(4)
            .position(|w| w == b"--- ")
            .expect("the MAC line");
        let payload = mac_line + 4 + 43 + 1;
        (salt, binary[payload..payload + 16].to_vec())
    }

    // The writer gives every backup.json plaintext byte for byte, sized exactly (no reallocation),
    // and the reader gives back its words and fingerprint.
    #[test]
    fn plaintexts_match_backup_json() {
        let doc = read("backup.json");
        for case in doc["plaintexts"].as_array().expect("plaintexts") {
            let mnemonic = mnemonic_of(text(&case["mnemonic"]));
            let by = created_by(case);
            let size = plaintext::len(&mnemonic, &by);
            let mut out = Zeroizing::new(String::with_capacity(size));
            plaintext::write_into(&mnemonic, fingerprint_of(case), &by, &mut out);
            assert_eq!(out.as_str(), text(&case["text"]), "{}", case["name"]);
            assert_eq!(
                (out.len(), out.capacity()),
                (size, size),
                "{}",
                case["name"]
            );
            assert_eq!(case["bytes"], Value::from(size), "{}", case["name"]);
            let mut read_back = SecretMnemonic::zeroed();
            let fingerprint = plaintext::parse_into(out.as_bytes(), &mut read_back);
            assert_eq!(fingerprint, Ok(fingerprint_of(case)), "{}", case["name"]);
            assert!(read_back.matches(&mnemonic), "{}", case["name"]);
        }
    }

    // Every refused plaintext gives its error, and the half-read words are wiped.
    #[test]
    fn every_refused_plaintext_gives_its_error() {
        let doc = read("backup.json");
        let cases = doc["plaintext_refused"]
            .as_array()
            .expect("plaintext_refused");
        assert_eq!(cases.len(), 22);
        for case in cases {
            let mut read_back = SecretMnemonic::zeroed();
            let result = plaintext::parse_into(&hex(&case["text_hex"]), &mut read_back);
            let got = match result {
                Ok(_) => "accepted".to_string(),
                Err(e) => format!("{e:?}"),
            };
            assert_eq!(got, text(&case["error"]), "{}", case["name"]);
            assert!(read_back.is_zero(), "{}", case["name"]);
        }
    }

    #[test]
    fn created_by_lines() {
        for (by, line) in [
            (
                CreatedBy::new(BackupApp::Pi, 1, 0, 0),
                "created-by: keepcrypt-pi 1.0.0",
            ),
            (
                CreatedBy::new(BackupApp::Android, 10, 99, 100),
                "created-by: keepcrypt-android 10.99.100",
            ),
            (
                CreatedBy::new(BackupApp::Ios, 65535, 9999, 1000),
                "created-by: keepcrypt-ios 65535.9999.1000",
            ),
        ] {
            let mut out = String::new();
            by.push_line(&mut out);
            assert_eq!(out, format!("{line}\n"));
            assert_eq!(out.len(), by.line_len());
            assert_eq!(CreatedBy::parse_line(line), Some(by));
            assert_eq!((by.app(), by.version()[0]), (by.app, by.version[0]));
        }
        for bad in [
            "created-by: keepcrypt-mac 1.0.0",
            "created-by: keepcrypt-pi 1.0",
            "created-by: keepcrypt-pi 1.0.0.0",
            "created-by: keepcrypt-pi 65536.0.0",
            "created-by: keepcrypt-pi1.0.0",
            "created-by keepcrypt-pi 1.0.0",
            "created-by: keepcrypt-pi 1.x.0",
        ] {
            assert_eq!(CreatedBy::parse_line(bad), None, "{bad}");
        }
    }

    // The 11 passphrase bytes become 8 indices of 11 bits, most significant first (Q6e), and the
    // age passphrase is the words joined by single spaces.
    #[test]
    fn passphrase_layouts_match_backup_json() {
        let doc = read("backup.json");
        for case in doc["passphrases"].as_array().expect("passphrases") {
            let bytes = <[u8; 11]>::try_from(hex(&case["os_hex"]).as_slice()).expect("11 bytes");
            let mut stored = BackupPassphrase::zeroed();
            assert!(!stored.is_present());
            stored.fill_from_bytes(&bytes);
            assert!(stored.is_present());
            let want: Vec<u16> = case["indices"]
                .as_array()
                .expect("indices")
                .iter()
                .map(|i| u16::try_from(i.as_u64().expect("an index")).expect("u16"))
                .collect();
            assert_eq!(stored.indices().as_slice(), want, "{}", case["name"]);
            assert_eq!(
                stored.text().as_str(),
                text(&case["passphrase"]),
                "{}",
                case["name"]
            );
            assert_eq!(
                typed(text(&case["passphrase"])).text().as_str(),
                text(&case["passphrase"])
            );
        }
    }

    // Each of the 88 single-bit flips of the passphrase bytes changes exactly one word.
    #[test]
    fn each_of_the_88_bit_flips_changes_exactly_one_word() {
        let doc = read("backup.json");
        let base =
            <[u8; 11]>::try_from(hex(&named(&doc["passphrases"], "stream")["os_hex"]).as_slice())
                .expect("11 bytes");
        let mut stored = BackupPassphrase::zeroed();
        stored.fill_from_bytes(&base);
        let original = *stored.indices();
        for bit in 0..88 {
            let mut flipped = base;
            flipped[bit / 8] ^= 0x80 >> (bit % 8);
            stored.fill_from_bytes(&flipped);
            let changed = (0..8)
                .filter(|&i| stored.indices()[i] != original[i])
                .count();
            assert_eq!(changed, 1, "bit {bit}");
            assert_ne!(stored.indices()[bit / 11], original[bit / 11], "bit {bit}");
        }
    }

    #[test]
    fn file_names_match_backup_json() {
        let doc = read("backup.json");
        for case in doc["file_names"].as_array().expect("file_names") {
            let bytes = <[u8; 4]>::try_from(hex(&case["os_hex"]).as_slice()).expect("4 bytes");
            assert_eq!(file_name(&bytes), text(&case["name"]));
        }
    }

    // A backup round-trips at work factor 18 for 12 and 24 words: the file is armored, its stanza
    // says 18, its name follows the rule, its plaintext is backup.json's, verify_backup accepts it,
    // and decrypt_backup with the written-down words gives the words, the fingerprint, the braille
    // and the seal of the session.
    #[test]
    fn round_trips_at_work_factor_18() {
        let doc = read("backup.json");
        for name in ["abandon-12", "zoo-24"] {
            let case = plaintext_case(&doc, name);
            let session = ready(text(&case["mnemonic"]));
            let (session, new) = session.generate_backup_passphrase().expect("generated");
            let (session, file) = session.encrypt_backup(&created_by(case)).expect("written");
            let file_name = file.name();
            assert!(file_name.starts_with("keepcrypt-backup-") && file_name.ends_with(".age"));
            assert_eq!(
                file_name.len(),
                "keepcrypt-backup-".len() + 8 + ".age".len()
            );
            assert!(
                file_name["keepcrypt-backup-".len()..file_name.len() - 4]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert!(
                file.bytes()
                    .starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----\n")
            );
            let binary = armor::decode(file.bytes()).expect("armored");
            let stanza = binary[22..].split(|&b| b == b'\n').next().expect("stanza");
            assert!(
                stanza.starts_with(b"-> scrypt ") && stanza.ends_with(b" 18"),
                "{name}"
            );
            let opened = age::decrypt(file.bytes(), words_of(&new).as_bytes()).expect("opens");
            assert_eq!(opened.as_slice(), text(&case["text"]).as_bytes(), "{name}");
            assert_eq!(session.verify_backup(file.bytes()), Ok(()), "{name}");
            let checked = decrypt_backup(file.bytes(), &typed(&words_of(&new))).expect("checked");
            assert_eq!(checked.fingerprint(), fingerprint_of(case), "{name}");
            assert_eq!(
                checked.reveal_words().collect::<Vec<_>>().join(" "),
                text(&case["mnemonic"])
            );
            let mut lines = String::new();
            checked.reveal_braille().backup_lines_into(&mut lines);
            assert!(text(&case["text"]).contains(&lines), "{name}");
            let seal = checked.seal().expect("a seal");
            assert_eq!(
                Ok(seal),
                crate::seal::seal_from_mnemonic(&mnemonic_of(text(&case["mnemonic"])))
            );
        }
    }

    // Two backups of one session differ in salt, nonce, name and ciphertext, and both verify; the
    // paper passphrase stays valid for a retry.
    #[test]
    fn two_backups_of_one_session_differ_and_both_verify() {
        let doc = read("backup.json");
        let case = plaintext_case(&doc, "abandon-12");
        let (session, _new) = ready(text(&case["mnemonic"]))
            .generate_backup_passphrase()
            .expect("generated");
        let (session, first) = session.encrypt_backup(&created_by(case)).expect("first");
        let (session, second) = session.encrypt_backup(&created_by(case)).expect("second");
        let (salt_1, nonce_1) = salt_and_nonce(first.bytes());
        let (salt_2, nonce_2) = salt_and_nonce(second.bytes());
        assert_ne!(salt_1, salt_2);
        assert_ne!(nonce_1, nonce_2);
        assert_ne!(first.name(), second.name());
        assert_ne!(first.bytes(), second.bytes());
        assert_eq!(session.verify_backup(first.bytes()), Ok(()));
        assert_eq!(session.verify_backup(second.bytes()), Ok(()));
    }

    // Another session's file is WrongPassphrase; after a second generate_backup_passphrase, a file
    // under the first one is too.
    #[test]
    fn other_passphrases_do_not_verify() {
        let doc = read("backup.json");
        let case = plaintext_case(&doc, "abandon-12");
        let words = text(&case["mnemonic"]);
        let (other, _) = ready(words)
            .generate_backup_passphrase()
            .expect("generated");
        let (other, file) = other.encrypt_backup(&created_by(case)).expect("written");
        let (session, _) = ready(words)
            .generate_backup_passphrase()
            .expect("generated");
        assert_eq!(
            session.verify_backup(file.bytes()),
            Err(CoreError::WrongPassphrase)
        );
        let (other, _) = other.generate_backup_passphrase().expect("generated again");
        assert_eq!(
            other.verify_backup(file.bytes()),
            Err(CoreError::WrongPassphrase)
        );
        assert_eq!(
            session.verify_backup(b"not a backup"),
            Err(CoreError::Backup(BackupError::Header))
        );
    }

    // A file under this session's passphrase that holds another seed's plaintext is
    // ReadbackMismatch, and so is one whose plaintext names another fingerprint.
    #[test]
    fn another_seed_under_this_passphrase_is_a_mismatch() {
        let doc = read("backup.json");
        let abandon = plaintext_case(&doc, "abandon-12");
        let zoo = plaintext_case(&doc, "zoo-24");
        let mut source = Source::Os;
        let mut stored = BackupPassphrase::zeroed();
        new_passphrase(&mut source, &mut stored).expect("generated");
        let zoo_words = mnemonic_of(text(&zoo["mnemonic"]));
        let file = encrypt(
            &mut source,
            &stored,
            &zoo_words,
            fingerprint_of(zoo),
            &created_by(zoo),
        )
        .expect("written");
        let abandon_words = mnemonic_of(text(&abandon["mnemonic"]));
        assert_eq!(
            verify(
                &stored,
                file.bytes(),
                &abandon_words,
                fingerprint_of(abandon)
            ),
            Err(CoreError::ReadbackMismatch)
        );
        assert_eq!(
            verify(&stored, file.bytes(), &zoo_words, fingerprint_of(abandon)),
            Err(CoreError::ReadbackMismatch)
        );
        assert_eq!(
            verify(&stored, file.bytes(), &zoo_words, fingerprint_of(zoo)),
            Ok(())
        );
    }

    // Before generate_backup_passphrase: encrypt_backup is NoBackupPassphrase (the session is
    // consumed, so wiped), and verify_backup is NoBackupPassphrase without a wipe.
    #[test]
    fn nothing_before_a_passphrase() {
        let session = ready(text(
            &plaintext_case(&read("backup.json"), "abandon-12")["mnemonic"],
        ));
        assert_eq!(
            session.verify_backup(b""),
            Err(CoreError::NoBackupPassphrase)
        );
        assert!(matches!(
            session.encrypt_backup(&CreatedBy::new(BackupApp::Pi, 1, 0, 0)),
            Err(CoreError::NoBackupPassphrase)
        ));
    }

    // The age CLI's files decrypt to backup.json's plaintexts, and a wrong typed passphrase gives
    // WrongPassphrase.
    #[test]
    fn the_age_cli_files_decrypt() {
        let doc = read("backup.json");
        let cli = read("age/age_cli_written.json");
        let files = cli["files"].as_array().expect("files");
        assert_eq!(files.len(), 4);
        for file in files {
            let case = plaintext_case(&doc, text(&file["plaintext"]));
            let bytes = case_file(file);
            let checked =
                decrypt_backup(&bytes, &typed(text(&file["passphrase"]))).expect("checked");
            assert_eq!(
                checked.fingerprint(),
                fingerprint_of(case),
                "{}",
                file["name"]
            );
            assert_eq!(
                checked.reveal_words().collect::<Vec<_>>().join(" "),
                text(&case["mnemonic"])
            );
        }
        let wrong = text(&named(&doc["passphrases"], "zeros")["passphrase"]);
        assert!(matches!(
            decrypt_backup(&case_file(&files[0]), &typed(wrong)),
            Err(CoreError::WrongPassphrase)
        ));
    }

    // decrypt_backup on backup.json's files: the backups give their fingerprints; a 4,096-byte
    // chunk of noise is not a plaintext; every refused file under an 8-word passphrase gives the
    // same error as the age reader.
    #[test]
    fn decrypt_backup_reads_backup_json() {
        let doc = read("backup.json");
        for case in doc["age_files"].as_array().expect("age_files") {
            let Ok(passphrase) = TypedBackupPassphrase::from_words(
                &text(&case["passphrase"]).split(' ').collect::<Vec<_>>(),
            ) else {
                continue; // CCTV's "password"
            };
            let result = decrypt_backup(&case_file(case), &passphrase);
            match case["plaintext"].as_str() {
                Some(name) => assert_eq!(
                    result.map(|c| c.fingerprint()).expect("checked"),
                    fingerprint_of(plaintext_case(&doc, name))
                ),
                None => assert!(matches!(
                    result,
                    Err(CoreError::Backup(BackupError::Plaintext))
                )),
            }
        }
        for case in doc["age_refused"].as_array().expect("age_refused") {
            let result = decrypt_backup(&case_file(case), &typed(text(&case["passphrase"])));
            let got = match result {
                Ok(_) => "accepted".to_string(),
                Err(e) => format!("{e:?}"),
            };
            assert_eq!(got, text(&case["error"]), "{}", case["name"]);
        }
    }

    #[test]
    fn checked_backup_zeroizes() {
        let mut checked = CheckedBackup {
            mnemonic: SecretMnemonic::zeroed(),
            fingerprint: [0x73; 4],
        };
        checked.mnemonic.fill();
        assert!(!checked.mnemonic.is_zero());
        checked.zeroize();
        assert!(checked.mnemonic.is_zero());
        assert_eq!(checked.fingerprint, [0; 4]);
    }

    const fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    const _: () = zeroize_on_drop::<CheckedBackup>();

    #[test]
    fn push_decimal_writes_every_width() {
        for (n, want) in [
            (0, "0"),
            (7, "7"),
            (10, "10"),
            (65535, "65535"),
            (1000, "1000"),
        ] {
            let mut out = String::new();
            push_decimal(&mut out, n);
            assert_eq!(out, want);
        }
        assert_eq!(hex_str("00ff"), [0, 255]);
    }

    // Run by scripts/age-interop.py --core with KC_AGE_INTEROP_DIR naming a directory: core reads
    // every file the age CLI wrote there (cli-<label>.age, with cli-<label>.words, the passphrase,
    // and cli-<label>.mnemonic, the words it holds), then writes a fresh backup of abandon-12 and
    // zoo-24 for age to read (core-<name>.age, with core-<name>.words), at work factor 18 with OS
    // randomness. Test files of public test mnemonics in a temporary directory; core itself does no
    // file I/O.
    #[test]
    #[ignore = "scripts/age-interop.py --core runs it against the age CLI"]
    fn age_interop_files() {
        let dir = std::path::PathBuf::from(
            std::env::var_os("KC_AGE_INTEROP_DIR").expect("KC_AGE_INTEROP_DIR is set"),
        );
        let mut opened = 0;
        for entry in std::fs::read_dir(&dir).expect("list the directory") {
            let path = entry.expect("an entry").path();
            let label = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("cli-"))
                .and_then(|name| name.strip_suffix(".age"));
            let Some(label) = label else {
                continue;
            };
            let side = |ext: &str| {
                std::fs::read_to_string(dir.join(format!("cli-{label}.{ext}")))
                    .expect("a side file")
            };
            let file = std::fs::read(&path).expect("read the file");
            let checked = decrypt_backup(&file, &typed(side("words").trim_end())).expect("checked");
            assert_eq!(
                checked.reveal_words().collect::<Vec<_>>().join(" "),
                side("mnemonic").trim_end(),
                "{label}"
            );
            opened += 1;
        }
        assert!(opened > 0, "no file from the age CLI");
        let doc = read("backup.json");
        for name in ["abandon-12", "zoo-24"] {
            let case = plaintext_case(&doc, name);
            let (session, new) = ready(text(&case["mnemonic"]))
                .generate_backup_passphrase()
                .expect("generated");
            let (_, file) = session.encrypt_backup(&created_by(case)).expect("written");
            std::fs::write(dir.join(format!("core-{name}.age")), file.bytes()).expect("write");
            std::fs::write(dir.join(format!("core-{name}.words")), words_of(&new)).expect("write");
        }
    }

    #[cfg(feature = "test-sources")]
    mod stub {
        use super::*;
        use crate::error::SourceFault;
        use crate::source::{StubEntropy, StubSource, WipeProbe};
        use base64ct::Encoding;

        fn stub_ready(mnemonic: &str, bytes: Vec<u8>, probe: &WipeProbe) -> Session<Ready> {
            let source = Source::Stub(StubSource::new(StubEntropy::Fixed(bytes), probe));
            Session::<Ready>::ready_for_test(&indices(mnemonic), source).expect("Ready")
        }

        // generate_backup_passphrase reads exactly backup.json's bytes and gives its passphrase
        // and challenge: the right word sits at each question's answer slot. The exhausted case
        // fails closed with Source(NoUsableDraw) and wipes the session once.
        #[test]
        fn generate_matches_backup_json() {
            let doc = read("backup.json");
            let mnemonic = text(&plaintext_case(&doc, "abandon-12")["mnemonic"]);
            for case in doc["generate"].as_array().expect("generate") {
                let probe = WipeProbe::new();
                let session = stub_ready(mnemonic, hex(&case["os_hex"]), &probe);
                match session.generate_backup_passphrase() {
                    Ok((session, new)) => {
                        assert_eq!(
                            words_of(&new),
                            text(&case["passphrase"]),
                            "{}",
                            case["name"]
                        );
                        let words: Vec<&str> = new.words().collect();
                        let questions = new.challenge().questions();
                        for (q, (position, choices)) in questions.iter().enumerate() {
                            let want = &case["questions"][q];
                            assert_eq!(want["position"], u64::from(*position));
                            assert_eq!(Value::from(choices.to_vec()), want["choices"]);
                            let answer = usize::try_from(want["answer"].as_u64().expect("slot"))
                                .expect("small");
                            assert_eq!(choices[answer], words[usize::from(*position) - 1]);
                        }
                        // Every byte was read: the next draw finds the stub used up.
                        assert!(matches!(
                            session.generate_backup_passphrase(),
                            Err(CoreError::Source(SourceFault::Os))
                        ));
                    }
                    Err(e) => {
                        assert_eq!(format!("{e:?}"), text(&case["error"]), "{}", case["name"]);
                        assert_eq!(probe.wipes(), 1, "{}", case["name"]);
                        // All 64 attempts were read before it gave up, and the passphrase is gone.
                        let mut source = Source::Stub(StubSource::new(
                            StubEntropy::Fixed(hex(&case["os_hex"])),
                            &WipeProbe::new(),
                        ));
                        let mut stored = BackupPassphrase::zeroed();
                        assert!(new_passphrase(&mut source, &mut stored).is_err());
                        assert!(stored.is_zero());
                        assert!(source.os_bytes::<1>().is_err(), "every byte was read");
                    }
                }
                assert_eq!(probe.wipes(), 1, "{}", case["name"]);
            }
        }

        // encrypt_backup reads 52 bytes, in this order: file key, salt, nonce, file name; the
        // file opens under the stored passphrase and verifies; a source failure inside it, and
        // calling it before generate_backup_passphrase, wipe the session once.
        #[test]
        fn encrypt_reads_key_salt_nonce_and_name_in_order() {
            let doc = read("backup.json");
            let case = plaintext_case(&doc, "abandon-12");
            let generate = hex(&named(&doc["generate"], "stream")["os_hex"]);
            let drawn: Vec<u8> = (0u8..52).collect();
            let probe = WipeProbe::new();
            let session = stub_ready(
                text(&case["mnemonic"]),
                [generate.clone(), drawn.clone()].concat(),
                &probe,
            );
            let (session, new) = session.generate_backup_passphrase().expect("generated");
            let (session, file) = session.encrypt_backup(&created_by(case)).expect("written");
            assert_eq!(file.name(), "keepcrypt-backup-30313233.age");
            let (salt, nonce) = salt_and_nonce(file.bytes());
            let mut salt_text = [0u8; 22];
            let salt_b64 =
                base64ct::Base64Unpadded::encode(&drawn[16..32], &mut salt_text).expect("encoded");
            assert_eq!(salt, salt_b64.as_bytes());
            assert_eq!(nonce, &drawn[32..48]);
            assert_eq!(session.verify_backup(file.bytes()), Ok(()));
            let opened = age::decrypt(file.bytes(), words_of(&new).as_bytes()).expect("opens");
            assert_eq!(opened.as_slice(), text(&case["text"]).as_bytes());
            assert!(matches!(
                session.encrypt_backup(&created_by(case)),
                Err(CoreError::Source(SourceFault::Os))
            ));
            assert_eq!(probe.wipes(), 1);

            let probe = WipeProbe::new();
            let session = stub_ready(text(&case["mnemonic"]), generate, &probe);
            let (session, _) = session.generate_backup_passphrase().expect("generated");
            assert!(matches!(
                session.encrypt_backup(&created_by(case)),
                Err(CoreError::Source(SourceFault::Os))
            ));
            assert_eq!(probe.wipes(), 1);

            let probe = WipeProbe::new();
            let session = stub_ready(text(&case["mnemonic"]), drawn, &probe);
            assert!(matches!(
                session.encrypt_backup(&created_by(case)),
                Err(CoreError::NoBackupPassphrase)
            ));
            assert_eq!(probe.wipes(), 1);
        }

        // A failing source inside generate_backup_passphrase wipes the session once, and the
        // stored passphrase with it.
        #[test]
        fn a_failing_source_in_generate_wipes() {
            for entropy in [
                StubEntropy::Fail,
                StubEntropy::FailAt(1),
                StubEntropy::ShortAfter(20),
            ] {
                let probe = WipeProbe::new();
                let source = Source::Stub(StubSource::new(entropy, &probe));
                let session = Session::<Ready>::ready_for_test(
                    &indices("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
                    source,
                )
                .expect("Ready");
                let result = session.generate_backup_passphrase();
                assert!(matches!(result, Err(CoreError::Source(_))));
                assert_eq!(probe.wipes(), 1);
            }
            let mut stored = BackupPassphrase::zeroed();
            let mut source =
                Source::Stub(StubSource::new(StubEntropy::FailAt(1), &WipeProbe::new()));
            assert!(new_passphrase(&mut source, &mut stored).is_err());
            assert!(
                stored.is_zero(),
                "a failed draw leaves no passphrase behind"
            );
        }

        // decrypt_backup runs the Age group: its fault twin fails with Kat(Age) for that group and
        // reads the file for every other.
        #[test]
        fn decrypt_backup_runs_the_age_group() {
            let doc = read("backup.json");
            let file = named(&doc["age_files"], "abandon-12");
            let passphrase = typed(text(&file["passphrase"]));
            for id in KatId::ALL {
                let result = decrypt_backup_with_kat_fault(&case_file(file), &passphrase, id);
                if id == KatId::Age {
                    assert!(matches!(result, Err(CoreError::Kat(KatId::Age))));
                } else {
                    assert!(result.is_ok(), "{id:?}");
                }
            }
        }
    }
}
