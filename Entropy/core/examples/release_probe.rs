//! The release probe (tasks/todo.md, M1 group 11; docs/build-plan.md "Security rules enforced in
//! CI", rows "One RNG path in shipped binaries" and "Test stubs never ship"; CLAUDE.md rules 1 and
//! 10).
//!
//! A linked program on core's public API with default features, built in release mode for every
//! target so `scripts/banned-api-check.sh --artifact` can scan a real binary: the OS import for
//! the target must be there, and no other RNG symbol, no test marker and no test registry key may
//! be. It walks every path that draws from the OS: the known-answer tests, a phone ceremony in
//! Mixed mode (the OS read at the commitment) with fixed public dice, `start_check` (the nonce),
//! the go-ahead code, the read-back of every word, `generate_backup_passphrase` (the passphrase and
//! its challenge) and `encrypt_backup` (file key, salt, nonce and file name). It also links the
//! registry-key path through `registry_key_is_test` and `verify_snapshot`, so a build with
//! `test-registry` holds that feature's marker and key and the scan's positive controls can catch
//! them (scripts/canaries.sh).
//!
//! It prints nothing (core's lints forbid it): every step that fails exits with its own code, and
//! 0 means every step gave what a build with these features must give. The seed comes from the
//! real OS source and is dropped, and so wiped, at the end.

use std::process::ExitCode;

use keepcrypt_core::{
    BackupApp, CoreError, CreatedBy, GoAhead, Mode, Platform, ReadbackResult, SeedLength, Session,
    registry_key_is_test, self_test, verify_snapshot,
};
use sha2::{Digest, Sha256};

/// vectors/kcr.json, snapshots, "empty": the empty snapshot signed by the test registry key (122
/// bytes: the 58-byte header and its signature). Public test bytes: a release build pins no key
/// and refuses them with `NoRegistryKey`; a `test-registry` build verifies them.
const EMPTY_SNAPSHOT_HEX: &str = concat!(
    "4b43523100010000000000000001013525cd0000000000000000b73ca0379e73400458ebe358b6aeec7a39baa7ddd8e1",
    "f78abe7436de44e4ba9357aa7af0960c2b6b1604a9b92a5cb5e157bf2c9dc84896b030d539a7bf041106253a07e0626b",
    "4543b530e8fb3192e8033af8f1c9741fb37384d91101acd02509",
);

/// Public dice: 1 to 6 in turn, 50 rolls, the 12-word minimum.
const ROLLS: usize = 50;

const GO_DOMAIN: &[u8] = b"KCE/v1/go";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(step) => ExitCode::from(step),
    }
}

/// Every step, in ceremony order. The error is the failing step's exit code.
fn run() -> Result<(), u8> {
    self_test().map_err(|_| 10)?;

    let committed = Session::new(SeedLength::Words12, Mode::Mixed, Platform::Phone)
        .and_then(Session::commit)
        .map_err(|_| 11)?;
    let mut rolling = committed.start_dice();
    for face in (1..=6u8).cycle().take(ROLLS) {
        rolling = rolling.push_roll(face).map_err(|_| 12)?;
    }
    let checking = rolling
        .finish()
        .and_then(|sealed| sealed.start_check())
        .map_err(|_| 13)?;

    // The checker's answer, worked out here as the registry page would: G is the first 40 bits of
    // SHA-256("KCE/v1/go" || T || n) in Crockford base32.
    let nonce = nonce_from_url(checking.check_request().url())?;
    let code = go_ahead_code(checking.seal().tag().as_bytes(), &nonce)?;
    let code = core::str::from_utf8(&code).map_err(|_| 14)?;
    let mut ready = match checking.reveal(GoAhead::Code(code)) {
        Ok(ready) => ready,
        Err(_) => return Err(15),
    };

    // Read every word back from its own insert: faces 1-4, up to the first blank face.
    for position in 1..=12u8 {
        let insert = ready.braille().insert(position).map_err(|_| 16)?;
        let letters: String = insert.faces()[..4]
            .iter()
            .map_while(|face| face.letter())
            .collect();
        match ready.check_readback(position, &letters) {
            Ok(ReadbackResult::Match) => {}
            _ => return Err(16),
        }
    }

    // The display copy a user would write down; it wipes itself when dropped.
    let (ready, written_down) = ready.generate_backup_passphrase().map_err(|_| 17)?;
    drop(written_down);
    let by = CreatedBy::new(BackupApp::Android, 0, 0, 0);
    let (ready, file) = ready.encrypt_backup(&by).map_err(|_| 18)?;
    ready.verify_backup(file.bytes()).map_err(|_| 18)?;

    // The registry-key path: no key in a release build, the test key under test-registry.
    let snapshot = hex(EMPTY_SNAPSHOT_HEX).ok_or(19)?;
    match (registry_key_is_test(), verify_snapshot(&snapshot)) {
        (false, Err(CoreError::NoRegistryKey)) => Ok(()),
        (true, Ok(verified)) if verified.entry_count() == 0 => Ok(()),
        _ => Err(19),
    }
}

/// The 8 bytes of n from `.../check#t=<64 hex>&n=<16 hex>`.
fn nonce_from_url(url: &str) -> Result<[u8; 8], u8> {
    let (_, n) = url.split_once("&n=").ok_or(14)?;
    <[u8; 8]>::try_from(hex(n).ok_or(14)?.as_slice()).map_err(|_| 14)
}

/// G without its dash: 8 Crockford characters, 5 bits each, most significant first.
fn go_ahead_code(tag: &[u8; 32], nonce: &[u8; 8]) -> Result<[u8; 8], u8> {
    let digest = Sha256::new()
        .chain_update(GO_DOMAIN)
        .chain_update(tag)
        .chain_update(nonce)
        .finalize();
    let bits = digest[..5]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut code = [0u8; 8];
    for (i, c) in code.iter_mut().enumerate() {
        let shift = 35 - 5 * i;
        let index = usize::try_from((bits >> shift) & 31).map_err(|_| 14)?;
        *c = CROCKFORD[index];
    }
    Ok(code)
}

/// Lowercase hex to bytes; None for anything else.
fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}
