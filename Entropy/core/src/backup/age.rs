//! The age v1 file with one scrypt stanza (C2SP age v1; docs/build-plan.md "Encrypted backup
//! format"; tasks/todo.md, M1 group 8 and Q1 (i); vectors/backup.json spec "header",
//! "scrypt_stanza", "keys", "reader").
//!
//! - Header: `age-encryption.org/v1` LF, stanzas (`-> ` and arguments of 0x21-0x7e separated by
//!   single spaces, LF, then the body in canonical unpadded base64, 64-column lines ending with a
//!   shorter one), then `--- ` and the 43-character base64 MAC, LF. A binary file starts with the
//!   version line at its first byte.
//! - The reader, in this order: at most 8 KiB (`TooLarge`); armor or binary; the header grammar
//!   (`Header`); the scrypt stanza: if there is one it must be alone, with three arguments, a
//!   canonical 16-byte salt and a work factor matching `[1-9][0-9]?` (`Header`) of at most 18
//!   (`WorkFactor`), and a 32-byte body (`Header`), while a header with no scrypt stanza is no match
//!   (`WrongPassphrase`); a payload of the 16-byte nonce and one final chunk of at most 4 KiB of
//!   plaintext (`Payload`). Only then scrypt: a body that does not open is `WrongPassphrase`; the
//!   header MAC, checked in constant time (`HeaderMac`); the chunk, opened with the final-chunk
//!   nonce (`Payload`).
//! - wrap key = scrypt(passphrase, `age-encryption.org/v1/scrypt` || salt, 2^N, 8, 1); the body
//!   wraps the 16-byte file key with ChaCha20-Poly1305 under 12 zero bytes; the MAC key is
//!   HKDF-SHA256(file key, empty salt, `header`), the payload key HKDF-SHA256(file key, nonce,
//!   `payload`).
//! - The writer uses work factor 18 in the backup (`WRITE_WORK_FACTOR`); the file key, salt and
//!   nonce come from the session's OS source (backup.rs). The Age known-answer group writes CCTV's
//!   file at work factor 10 from its fixed inputs.
//! - Every key and the plaintext stay in zeroizing buffers. Beyond core's reach: scrypt 0.12 never
//!   wipes its working buffers (2^N x 1 KiB, derived from the backup passphrase, not from the seed;
//!   tasks/todo.md, M1 Q1 (iii), accepted). HKDF's extract step leaves its own copies of the
//!   pseudorandom key in its frames (the copy it returns is wiped here), and the header MAC's hmac
//!   its padded key block (M1 group 7); tasks/todo.md records both for the owner, not accepted.

use base64ct::{Base64Unpadded, Encoding};
use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::armor;
use crate::error::{BackupError, CoreError, InternalFault};

/// The version line, with its LF.
const VERSION_LINE: &[u8] = b"age-encryption.org/v1\n";
/// The scrypt salt's label.
const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
/// The scrypt stanza's type, its first argument.
const SCRYPT_TYPE: &[u8] = b"scrypt";
/// The HKDF info strings.
const HEADER_INFO: &[u8] = b"header";
const PAYLOAD_INFO: &[u8] = b"payload";
/// Base64 characters per full stanza body line.
const COLUMNS: usize = 64;
/// scrypt's block size and parallelism, fixed by the spec.
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
/// The work factor (log2 N) the backup is written with: about 256 MiB (docs/build-plan.md "Work
/// factor").
pub(crate) const WRITE_WORK_FACTOR: u8 = 18;
/// The largest work factor the reader accepts (Q1 (i)): 2^19 would need 512 MiB, more than a Pi Zero
/// has.
pub(crate) const MAX_WORK_FACTOR: u8 = 18;
/// The largest file the reader looks at, armored or binary (Q1 (i)).
pub(crate) const MAX_FILE_BYTES: usize = 8 * 1024;
/// The largest plaintext: one final chunk of at most 4 KiB (Q1 (i)).
pub(crate) const MAX_CHUNK_BYTES: usize = 4 * 1024;
/// The file key, salt and payload nonce sizes.
pub(crate) const FILE_KEY_BYTES: usize = 16;
pub(crate) const SALT_BYTES: usize = 16;
pub(crate) const NONCE_BYTES: usize = 16;
/// The wrapped file key: 16 bytes and the 16-byte tag.
const BODY_BYTES: usize = FILE_KEY_BYTES + TAG_BYTES;
const TAG_BYTES: usize = 16;
/// The header MAC and its unpadded base64.
const MAC_BYTES: usize = 32;
const MAC_CHARS: usize = 43;

/// What the writer draws for each file: the file key (secret) and the salt and payload nonce
/// (written into the file). Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct FileSecrets {
    file_key: [u8; FILE_KEY_BYTES],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
}

impl FileSecrets {
    /// The three values, each from its own read of the OS source in the backup (`backup::encrypt`), or
    /// fixed in the Age known-answer group and the tests.
    pub(crate) fn new(
        file_key: &[u8; FILE_KEY_BYTES],
        salt: &[u8; SALT_BYTES],
        nonce: &[u8; NONCE_BYTES],
    ) -> Self {
        Self {
            file_key: *file_key,
            salt: *salt,
            nonce: *nonce,
        }
    }
}

fn refused(error: BackupError) -> CoreError {
    CoreError::Backup(error)
}

/// Canonical unpadded base64 of exactly `N` bytes, or `Backup(Header)`.
fn decode_exact<const N: usize>(text: &[u8]) -> Result<[u8; N], CoreError> {
    let mut out = [0u8; N];
    match Base64Unpadded::decode(text, &mut out) {
        Ok(decoded) if decoded.len() == N => Ok(out),
        _ => Err(refused(BackupError::Header)),
    }
}

/// The parts of a header the reader keeps.
struct Header<'a> {
    /// How many stanzas the header has.
    stanzas: usize,
    /// Whether any stanza's type is `scrypt`.
    any_scrypt: bool,
    /// The first stanza's argument line (after `-> `) and its body.
    first_arguments: &'a [u8],
    first_body: Vec<u8>,
    /// The header up to and including `---`: what the MAC covers.
    mac_input: &'a [u8],
    mac: [u8; MAC_BYTES],
    payload: &'a [u8],
}

/// The line starting at `at`, without its LF, and where the next one starts; `None` if no LF
/// follows.
fn line_at(data: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let rest = data.get(at..)?;
    let end = rest.iter().position(|&b| b == b'\n')?;
    Some((&rest[..end], at + end + 1))
}

/// The header grammar (vectors/backup.json spec "header"), or `Backup(Header)`.
fn parse(binary: &[u8]) -> Result<Header<'_>, CoreError> {
    let bad = refused(BackupError::Header);
    if !binary.starts_with(VERSION_LINE) {
        return Err(bad);
    }
    let mut at = VERSION_LINE.len();
    let mut stanzas = 0usize;
    let mut any_scrypt = false;
    let mut first_arguments: &[u8] = &[];
    let mut first_body = Vec::new();
    while !binary[at..].starts_with(b"--- ") {
        let (line, next) = line_at(binary, at).ok_or(bad)?;
        let arguments = line.strip_prefix(b"-> ").ok_or(bad)?;
        let well_formed = arguments
            .split(|&b| b == b' ')
            .all(|a| !a.is_empty() && a.iter().all(|&b| (0x21..=0x7e).contains(&b)));
        if !well_formed {
            return Err(bad);
        }
        at = next;
        let mut text = Vec::new();
        loop {
            let (body_line, next) = line_at(binary, at).ok_or(bad)?;
            if body_line.len() > COLUMNS {
                return Err(bad);
            }
            text.extend_from_slice(body_line);
            at = next;
            if body_line.len() < COLUMNS {
                break;
            }
        }
        let mut body = vec![0u8; text.len() * 3 / 4 + 1];
        let decoded = Base64Unpadded::decode(&text, &mut body)
            .map_err(|_| bad)?
            .len();
        body.truncate(decoded);
        any_scrypt |= arguments.split(|&b| b == b' ').next() == Some(SCRYPT_TYPE);
        if stanzas == 0 {
            first_arguments = arguments;
            first_body = body;
        }
        stanzas += 1;
    }
    let mac_at = at + b"--- ".len();
    let mac_text = binary.get(mac_at..mac_at + MAC_CHARS).ok_or(bad)?;
    if stanzas == 0 || binary.get(mac_at + MAC_CHARS) != Some(&b'\n') {
        return Err(bad);
    }
    Ok(Header {
        stanzas,
        any_scrypt,
        first_arguments,
        first_body,
        mac_input: &binary[..at + b"---".len()],
        mac: decode_exact::<MAC_BYTES>(mac_text)?,
        payload: &binary[mac_at + MAC_CHARS + 1..],
    })
}

/// The scrypt stanza's salt, work factor and body, all checked before any scrypt work.
struct ScryptStanza {
    salt: [u8; SALT_BYTES],
    work_factor: u8,
    body: [u8; BODY_BYTES],
}

/// The one scrypt stanza (vectors/backup.json spec "scrypt_stanza").
fn scrypt_stanza(header: &Header<'_>) -> Result<ScryptStanza, CoreError> {
    if !header.any_scrypt {
        return Err(CoreError::WrongPassphrase); // no match: no stanza takes a passphrase
    }
    let bad = refused(BackupError::Header);
    let mut arguments = header.first_arguments.split(|&b| b == b' ');
    let (Some(SCRYPT_TYPE), Some(salt), Some(work_factor), None) = (
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) else {
        return Err(bad);
    };
    if header.stanzas != 1 {
        return Err(bad);
    }
    let salt = decode_exact::<SALT_BYTES>(salt)?;
    let work_factor = match work_factor {
        [d @ b'1'..=b'9'] => *d - b'0',
        [d @ b'1'..=b'9', e @ b'0'..=b'9'] => 10 * (*d - b'0') + (*e - b'0'),
        _ => return Err(bad),
    };
    let body = <[u8; BODY_BYTES]>::try_from(header.first_body.as_slice()).map_err(|_| bad)?;
    if work_factor > MAX_WORK_FACTOR {
        return Err(refused(BackupError::WorkFactor));
    }
    Ok(ScryptStanza {
        salt,
        work_factor,
        body,
    })
}

#[cfg(test)]
thread_local! {
    /// Wrap keys derived on this thread: the tests prove a refused file never reached scrypt.
    pub(crate) static SCRYPT_RUNS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The stanza's wrap key, written into `out`.
fn wrap_key_into(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
    work_factor: u8,
    out: &mut [u8; 32],
) -> Result<(), CoreError> {
    #[cfg(test)]
    SCRYPT_RUNS.with(|runs| runs.set(runs.get() + 1));
    let mut label_salt = [0u8; SCRYPT_LABEL.len() + SALT_BYTES];
    label_salt[..SCRYPT_LABEL.len()].copy_from_slice(SCRYPT_LABEL);
    label_salt[SCRYPT_LABEL.len()..].copy_from_slice(salt);
    let params = scrypt::Params::new(work_factor, SCRYPT_R, SCRYPT_P)
        .map_err(|_| refused(BackupError::WorkFactor))?;
    scrypt::scrypt(passphrase, &label_salt, &params, out)
        .map_err(|_| CoreError::Internal(InternalFault::Length))
}

/// HKDF-SHA256(ikm, salt, info), 32 bytes, into `out`. The pseudorandom key HKDF's extract step
/// returns is wiped here.
fn hkdf_into(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8; 32]) -> Result<(), CoreError> {
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.as_mut_slice().zeroize();
    hkdf.expand(info, out)
        .map_err(|_| CoreError::Internal(InternalFault::Length))
}

/// The STREAM nonce of chunk 0: 11 zero bytes, then 1 for the final chunk.
fn chunk_nonce(final_chunk: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[11] = u8::from(final_chunk);
    nonce
}

/// Opens `sealed` (ciphertext || tag) into `out`, which must be 16 bytes shorter. Nothing is
/// written to `out` unless the tag is right.
fn open(key: &[u8; 32], nonce: &[u8; 12], sealed: &[u8], out: &mut [u8]) -> Result<(), ()> {
    let split = sealed.len().checked_sub(TAG_BYTES).ok_or(())?;
    let (ciphertext, tag) = sealed.split_at(split);
    let tag = Tag::try_from(tag).map_err(|_| ())?;
    let buffer = InOutBuf::new(ciphertext, out).map_err(|_| ())?;
    ChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(nonce.into(), &[], buffer, &tag)
        .map_err(|_| ())
}

/// Seals `plaintext` and appends ciphertext || tag to `out`.
fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), CoreError> {
    let start = out.len();
    out.resize(start + plaintext.len(), 0);
    let buffer = InOutBuf::new(plaintext, &mut out[start..])
        .map_err(|_| CoreError::Internal(InternalFault::Length))?;
    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(nonce.into(), &[], buffer)
        .map_err(|_| CoreError::Internal(InternalFault::Length))?;
    out.extend_from_slice(tag.as_slice());
    Ok(())
}

/// The file key the stanza's body wraps under `passphrase`: scrypt, then the body opened with the
/// wrap key; a body that does not open is `WrongPassphrase`.
fn unwrap_file_key(
    passphrase: &[u8],
    stanza: &ScryptStanza,
) -> Result<Zeroizing<[u8; FILE_KEY_BYTES]>, CoreError> {
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    wrap_key_into(passphrase, &stanza.salt, stanza.work_factor, &mut wrap_key)?;
    let mut file_key = Zeroizing::new([0u8; FILE_KEY_BYTES]);
    open(&wrap_key, &[0; 12], &stanza.body, file_key.as_mut_slice())
        .map_err(|()| CoreError::WrongPassphrase)?;
    Ok(file_key)
}

/// The file key inside an armored or binary age file under `passphrase` (tests only), so the
/// backup tests can show which bytes the writer used as the key.
#[cfg(test)]
pub(crate) fn file_key_of(
    file: &[u8],
    passphrase: &[u8],
) -> Result<Zeroizing<[u8; FILE_KEY_BYTES]>, CoreError> {
    let dearmored;
    let binary = if armor::is_armored(file) {
        dearmored = armor::decode(file)?;
        dearmored.as_slice()
    } else {
        file
    };
    unwrap_file_key(passphrase, &scrypt_stanza(&parse(binary)?)?)
}

/// The plaintext of an armored or binary age file under `passphrase` (the reader order in the
/// module comment).
pub(crate) fn decrypt(file: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if file.len() > MAX_FILE_BYTES {
        return Err(refused(BackupError::TooLarge));
    }
    let dearmored;
    let binary = if armor::is_armored(file) {
        dearmored = armor::decode(file)?;
        dearmored.as_slice()
    } else {
        file
    };
    let header = parse(binary)?;
    let stanza = scrypt_stanza(&header)?;
    let payload = header.payload;
    if payload.len() < NONCE_BYTES + TAG_BYTES
        || payload.len() > NONCE_BYTES + MAX_CHUNK_BYTES + TAG_BYTES
    {
        return Err(refused(BackupError::Payload));
    }
    let file_key = unwrap_file_key(passphrase, &stanza)?;
    let mut mac_key = Zeroizing::new([0u8; 32]);
    hkdf_into(file_key.as_slice(), &[], HEADER_INFO, &mut mac_key)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key.as_slice())
        .map_err(|_| CoreError::Internal(InternalFault::Length))?;
    mac.update(header.mac_input);
    mac.verify_slice(&header.mac)
        .map_err(|_| refused(BackupError::HeaderMac))?;
    let (nonce, sealed) = payload.split_at(NONCE_BYTES);
    let mut payload_key = Zeroizing::new([0u8; 32]);
    hkdf_into(file_key.as_slice(), nonce, PAYLOAD_INFO, &mut payload_key)?;
    let mut plaintext = Zeroizing::new(vec![0u8; sealed.len() - TAG_BYTES]);
    open(&payload_key, &chunk_nonce(true), sealed, &mut plaintext)
        .map_err(|()| refused(BackupError::Payload))?;
    Ok(plaintext)
}

/// Appends the decimal digits of a work factor (1 to 99).
fn push_work_factor(out: &mut Vec<u8>, work_factor: u8) {
    if work_factor >= 10 {
        out.push(b'0' + work_factor / 10);
    }
    out.push(b'0' + work_factor % 10);
}

/// Appends the unpadded base64 of `bytes`.
fn push_unpadded(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CoreError> {
    let start = out.len();
    out.resize(start + Base64Unpadded::encoded_len(bytes), 0);
    Base64Unpadded::encode(bytes, &mut out[start..])
        .map_err(|_| CoreError::Internal(InternalFault::Length))?;
    Ok(())
}

/// A binary age file with one scrypt stanza holding `plaintext` in one final chunk. Only what the
/// reader reads: a work factor of 1 to 18 and at most 4 KiB of plaintext, else `Internal(Length)`.
pub(crate) fn encrypt(
    passphrase: &[u8],
    secrets: &FileSecrets,
    work_factor: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    write(passphrase, secrets, work_factor, plaintext, true)
}

/// `encrypt`, with the one chunk marked final or not (a refused case in the tests).
fn write(
    passphrase: &[u8],
    secrets: &FileSecrets,
    work_factor: u8,
    plaintext: &[u8],
    final_chunk: bool,
) -> Result<Vec<u8>, CoreError> {
    if !(1..=MAX_WORK_FACTOR).contains(&work_factor) || plaintext.len() > MAX_CHUNK_BYTES {
        return Err(CoreError::Internal(InternalFault::Length));
    }
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    wrap_key_into(passphrase, &secrets.salt, work_factor, &mut wrap_key)?;
    let mut body = Vec::with_capacity(BODY_BYTES);
    seal(&wrap_key, &[0; 12], &secrets.file_key, &mut body)?;
    let mut out = Vec::with_capacity(160 + NONCE_BYTES + plaintext.len() + TAG_BYTES);
    out.extend_from_slice(VERSION_LINE);
    out.extend_from_slice(b"-> scrypt ");
    push_unpadded(&mut out, &secrets.salt)?;
    out.push(b' ');
    push_work_factor(&mut out, work_factor);
    out.push(b'\n');
    push_unpadded(&mut out, &body)?;
    out.extend_from_slice(b"\n---");
    let mut mac_key = Zeroizing::new([0u8; 32]);
    hkdf_into(&secrets.file_key, &[], HEADER_INFO, &mut mac_key)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key.as_slice())
        .map_err(|_| CoreError::Internal(InternalFault::Length))?;
    mac.update(&out);
    let tag = mac.finalize().into_bytes();
    out.push(b' ');
    push_unpadded(&mut out, tag.as_slice())?;
    out.push(b'\n');
    out.extend_from_slice(&secrets.nonce);
    let mut payload_key = Zeroizing::new([0u8; 32]);
    hkdf_into(
        &secrets.file_key,
        &secrets.nonce,
        PAYLOAD_INFO,
        &mut payload_key,
    )?;
    seal(&payload_key, &chunk_nonce(final_chunk), plaintext, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, named, read, text};
    use serde_json::Value;
    use sha2::Digest;
    use std::collections::BTreeMap;
    use std::path::Path;

    fn scrypt_runs() -> usize {
        SCRYPT_RUNS.with(|runs| runs.get())
    }

    /// A backup.json file entry's bytes: armored text in "file", anything else in "file_hex".
    fn case_file(case: &Value) -> Vec<u8> {
        match case["file"].as_str() {
            Some(file) => file.as_bytes().to_vec(),
            None => hex(&case["file_hex"]),
        }
    }

    /// The plaintext an age_files entry holds: a plaintexts entry by name, or hex.
    fn case_plaintext(doc: &Value, case: &Value) -> Vec<u8> {
        match case["plaintext"].as_str() {
            Some(name) => text(&named(&doc["plaintexts"], name)["text"])
                .as_bytes()
                .to_vec(),
            None => hex(&case["plaintext_hex"]),
        }
    }

    fn array<const N: usize>(v: &Value) -> [u8; N] {
        <[u8; N]>::try_from(hex(v).as_slice()).expect("the right length")
    }

    fn secrets(case: &Value) -> FileSecrets {
        FileSecrets::new(
            &array(&case["file_key_hex"]),
            &array(&case["salt_hex"]),
            &array(&case["nonce_hex"]),
        )
    }

    fn work_factor(case: &Value) -> u8 {
        u8::try_from(case["work_factor"].as_u64().expect("a work factor")).expect("a small number")
    }

    /// backup.json names errors as CoreError's Debug text: "Backup(Header)", "WrongPassphrase".
    fn outcome(result: &Result<Zeroizing<Vec<u8>>, CoreError>) -> String {
        match result {
            Ok(_) => "accepted".into(),
            Err(e) => format!("{e:?}"),
        }
    }

    /// CCTV's outcome classes for this reader's results (vectors/SOURCES.md "CCTV age test file
    /// format").
    fn cctv_class(result: &Result<Zeroizing<Vec<u8>>, CoreError>) -> String {
        match result {
            Ok(_) => "success".into(),
            Err(CoreError::WrongPassphrase) => "no match".into(),
            Err(CoreError::Backup(BackupError::Header | BackupError::WorkFactor)) => {
                "header failure".into()
            }
            Err(CoreError::Backup(BackupError::HeaderMac)) => "HMAC failure".into(),
            Err(CoreError::Backup(BackupError::Payload)) => "payload failure".into(),
            Err(CoreError::Backup(BackupError::Armor)) => "armor failure".into(),
            Err(e) => format!("{e:?}"),
        }
    }

    fn cctv_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/age/scrypt")
    }

    /// (header fields, age file) of one CCTV test file.
    fn cctv_case(name: &str) -> (BTreeMap<String, Vec<String>>, Vec<u8>) {
        let raw = std::fs::read(cctv_dir().join(name)).expect("read a CCTV file");
        let split = raw
            .windows(2)
            .position(|pair| pair == b"\n\n")
            .expect("a header");
        let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in std::str::from_utf8(&raw[..split]).expect("UTF-8").lines() {
            let (key, value) = line.split_once(": ").expect("key: value");
            fields.entry(key.into()).or_default().push(value.into());
        }
        (fields, raw[split + 2..].to_vec())
    }

    // Every CCTV scrypt file reaches its expected outcome: 2 success (with the stated payload), 4 no
    // match, 20 header failure, exactly 26 files, and a file with a header key outside age/README.md's
    // list fails the test (tasks/todo.md, M1 group 8).
    #[test]
    fn every_cctv_scrypt_file_reaches_its_outcome() {
        const KEYS: [&str; 7] = [
            "expect",
            "payload",
            "file key",
            "passphrase",
            "identity",
            "armored",
            "comment",
        ];
        let mut names: Vec<String> = std::fs::read_dir(cctv_dir())
            .expect("list the CCTV files")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .into_string()
                    .expect("a name")
            })
            .filter(|name| name != ".DS_Store")
            .collect();
        names.sort();
        assert_eq!(names.len(), 26);
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for name in &names {
            let (fields, file) = cctv_case(name);
            for key in fields.keys() {
                assert!(KEYS.contains(&key.as_str()), "{name}: unknown key {key}");
            }
            let expect = &fields["expect"][0];
            assert_eq!(
                fields.get("armored").is_some_and(|a| a[0] == "yes"),
                armor::is_armored(&file),
                "{name}"
            );
            let mut classes = Vec::new();
            for passphrase in &fields["passphrase"] {
                let result = decrypt(&file, passphrase.as_bytes());
                if let Ok(plaintext) = &result {
                    let digest = Sha256::digest(plaintext.as_slice());
                    assert_eq!(
                        crate::test_vectors::hex_str(&fields["payload"][0]),
                        digest.as_slice(),
                        "{name}"
                    );
                }
                classes.push(cctv_class(&result));
            }
            let class = if classes.iter().any(|c| c == "success") {
                "success".to_string()
            } else {
                classes.sort();
                classes.dedup();
                assert_eq!(classes.len(), 1, "{name}: {classes:?}");
                classes[0].clone()
            };
            assert_eq!(&class, expect, "{name}");
            *counts.entry(class).or_default() += 1;
        }
        let want: BTreeMap<String, usize> =
            [("success", 2), ("no match", 4), ("header failure", 20)]
                .into_iter()
                .map(|(class, n)| (class.to_string(), n))
                .collect();
        assert_eq!(counts, want);
    }

    // The writer rebuilds every written backup.json file byte for byte from its inputs: CCTV scrypt
    // and armor_scrypt, the 12- and 24-word backups and a 4,096-byte chunk.
    #[test]
    fn the_writer_rebuilds_every_written_file() {
        let doc = read("backup.json");
        let mut written = 0;
        for case in doc["age_files"].as_array().expect("age_files") {
            if case["written"] != true {
                continue;
            }
            let file = encrypt(
                text(&case["passphrase"]).as_bytes(),
                &secrets(case),
                work_factor(case),
                &case_plaintext(&doc, case),
            )
            .expect("written");
            let file = if case["armored"] == true {
                armor::encode(&file).expect("armored")
            } else {
                file
            };
            assert_eq!(file, case_file(case), "{}", case["name"]);
            written += 1;
        }
        assert_eq!(written, 6);
        for (name, cctv) in [
            ("cctv-scrypt", "scrypt"),
            ("cctv-armor-scrypt", "armor_scrypt"),
        ] {
            assert_eq!(
                case_file(named(&doc["age_files"], name)),
                cctv_case(cctv).1,
                "{name}"
            );
        }
    }

    // The tests' file-key reader gives back the file key every written backup.json file was made
    // with, binary or armored, and nothing under another passphrase.
    #[test]
    fn file_key_of_gives_the_key_each_file_was_written_with() {
        let doc = read("backup.json");
        let mut written = 0;
        for case in doc["age_files"].as_array().expect("age_files") {
            if case["written"] != true {
                continue;
            }
            let file = case_file(case);
            let key = file_key_of(&file, text(&case["passphrase"]).as_bytes()).expect("opens");
            assert_eq!(
                key.as_slice(),
                hex(&case["file_key_hex"]),
                "{}",
                case["name"]
            );
            assert_eq!(
                file_key_of(&file, b"another passphrase").map(|k| *k),
                Err(CoreError::WrongPassphrase),
                "{}",
                case["name"]
            );
            written += 1;
        }
        assert_eq!(written, 6);
    }

    // Every backup.json file, written or a reader-only armor variant, decrypts to its plaintext.
    #[test]
    fn every_file_decrypts_to_its_plaintext() {
        let doc = read("backup.json");
        for case in doc["age_files"].as_array().expect("age_files") {
            let plaintext =
                decrypt(&case_file(case), text(&case["passphrase"]).as_bytes()).expect("decrypts");
            assert_eq!(*plaintext, case_plaintext(&doc, case), "{}", case["name"]);
        }
    }

    // Every refused file gives exactly its error, and reaches scrypt only where backup.json says it
    // may: everything the header, the stanza and the payload's length can refuse is refused first.
    #[test]
    fn every_refused_file_gives_its_error() {
        let doc = read("backup.json");
        let cases = doc["age_refused"].as_array().expect("age_refused");
        assert_eq!(cases.len(), 37);
        for case in cases {
            let before = scrypt_runs();
            let result = decrypt(&case_file(case), text(&case["passphrase"]).as_bytes());
            let reached = scrypt_runs() != before;
            assert_eq!(outcome(&result), text(&case["error"]), "{}", case["name"]);
            assert_eq!(Value::from(reached), case["scrypt"], "{}", case["name"]);
        }
    }

    // The production work factor: a 12-word backup written at 18 says so in its stanza and reads
    // back (two scrypt runs at 2^18, about 256 MiB each; timed in tasks/todo.md, M1 group 1).
    #[test]
    fn a_round_trip_at_work_factor_18() {
        let doc = read("backup.json");
        let plaintext = text(&named(&doc["plaintexts"], "abandon-12")["text"]).as_bytes();
        let case = named(&doc["age_files"], "abandon-12");
        let passphrase = text(&case["passphrase"]).as_bytes();
        let file =
            encrypt(passphrase, &secrets(case), WRITE_WORK_FACTOR, plaintext).expect("written");
        let stanza_end = file[VERSION_LINE.len()..]
            .iter()
            .position(|&b| b == b'\n')
            .expect("a stanza line");
        assert!(file[..VERSION_LINE.len() + stanza_end].ends_with(b" 18"));
        let armored = armor::encode(&file).expect("armored");
        assert_eq!(*decrypt(&armored, passphrase).expect("decrypts"), plaintext);
    }

    // The writer writes only what the reader reads.
    #[test]
    fn the_writer_refuses_what_the_reader_refuses() {
        let secrets = FileSecrets::new(&[1; 16], &[2; 16], &[3; 16]);
        for (work_factor, len) in [(0, 10), (19, 10), (10, MAX_CHUNK_BYTES + 1)] {
            assert_eq!(
                encrypt(b"p", &secrets, work_factor, &vec![0; len]),
                Err(CoreError::Internal(InternalFault::Length)),
                "{work_factor} {len}"
            );
        }
        let not_final = write(b"p", &secrets, 1, b"x", false).expect("written");
        assert_eq!(
            outcome(&decrypt(&not_final, b"p")),
            "Backup(Payload)",
            "a chunk not marked final is refused"
        );
    }

    // No single flipped bit anywhere in a binary backup is accepted, and none panics: each of the
    // 8 bits of every byte, flipped alone, gives an error from the reader's list.
    #[test]
    fn no_flipped_bit_is_accepted() {
        let doc = read("backup.json");
        let case = named(&doc["age_files"], "abandon-12-binary");
        let file = case_file(case);
        let passphrase = text(&case["passphrase"]).as_bytes();
        for bit in 0..8 * file.len() {
            let mut flipped = file.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            let result = decrypt(&flipped, passphrase);
            assert!(
                matches!(
                    result,
                    Err(CoreError::WrongPassphrase
                        | CoreError::Backup(
                            BackupError::Header
                                | BackupError::WorkFactor
                                | BackupError::HeaderMac
                                | BackupError::Payload
                        ))
                ),
                "byte {} bit {}: {}",
                bit / 8,
                bit % 8,
                outcome(&result)
            );
        }
    }

    #[test]
    fn file_secrets_zeroize() {
        let mut secrets = FileSecrets::new(&[0xa5; 16], &[0x5a; 16], &[0x77; 16]);
        secrets.zeroize();
        assert_eq!(
            (secrets.file_key, secrets.salt, secrets.nonce),
            ([0; 16], [0; 16], [0; 16])
        );
    }

    const fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    const _: () = {
        zeroize_on_drop::<FileSecrets>();
        zeroize_on_drop::<ChaCha20Poly1305>();
    };
}
