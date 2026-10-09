//! The check request and the go-ahead code (CLAUDE.md "Check nonce", "Go-ahead code";
//! docs/seal-watchonly-braille.md "The seal card", "Online lookup privacy", "Go-ahead code";
//! tasks/todo.md, M1 group 7, Q6d).
//!
//! - The check nonce n is 8 fresh bytes per check, drawn by `source::Source::os_bytes`, a read of
//!   its own that never touches the pool. No file under `core/src/seal` names the OS RNG crate: the
//!   nonce's bytes come only through `Source::os_bytes` (one test below hands it the real OS arm,
//!   `Source::Os`, to show that two draws differ).
//! - The check QR carries `<origin>/check#t=<T as 64 lowercase hex>&n=<n as 16 lowercase hex>`.
//! - G = the first 40 bits of SHA-256("KCE/v1/go" || T || n), 8 Crockford characters. A typed code
//!   is decoded leniently (case, dashes, spaces, O/I/L) and its 40 bits are compared with G's in
//!   constant time, `fixed_time_eq` over fixed-size arrays. A wrong or malformed code is a
//!   `CheckError` the session survives: retries are unlimited and keep the same n.

use bitcoin::hashes::cmp::fixed_time_eq;
use sha2::{Digest, Sha256};

use super::{REGISTRY_ORIGIN, SealTag, crockford, push_hex};
use crate::error::{CheckError, CoreError};
use crate::source::Source;

/// The go-ahead code's domain tag.
pub(crate) const GO_DOMAIN: &[u8] = b"KCE/v1/go";
/// The check URL's path and fragment keys (Q6d).
const CHECK_PATH: &str = "/check#t=";
const NONCE_KEY: &str = "&n=";

/// The check nonce n: 8 fresh bytes for one check, so an old or borrowed answer cannot be
/// replayed. Public: it travels in the check QR. Private field: only core draws one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckNonce([u8; 8]);

impl CheckNonce {
    /// A fresh nonce from the session's source, in a read of its own (never the pool). A source
    /// failure is an `Err`, which wipes the session that asked.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Session::start_check draws the nonce (M1 group 9)"
        )
    )]
    pub(crate) fn draw(source: &mut Source) -> Result<Self, CoreError> {
        let bytes = source.os_bytes::<8>()?;
        Ok(Self(*bytes))
    }

    /// A nonce from known bytes: the known-answer tests and the vectors.
    pub(crate) const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// The 8 bytes of n.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

/// What the seal card's check QR carries: T and n in the URL fragment, which a browser never sends
/// to the server. The seal image and Seal ID come from the session's `SealPublic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    url: String,
}

impl CheckRequest {
    /// The request for this seal and nonce.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Session::check_request builds it (M1 group 9)")
    )]
    pub(crate) fn new(tag: &SealTag, nonce: &CheckNonce) -> Self {
        let mut url = String::with_capacity(
            REGISTRY_ORIGIN.len() + CHECK_PATH.len() + 64 + NONCE_KEY.len() + 16,
        );
        url.push_str(REGISTRY_ORIGIN);
        url.push_str(CHECK_PATH);
        push_hex(&mut url, tag.as_bytes());
        url.push_str(NONCE_KEY);
        push_hex(&mut url, nonce.as_bytes());
        Self { url }
    }

    /// `https://registry.invalid/check#t=<64 lowercase hex>&n=<16 lowercase hex>` until M9.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// SHA-256("KCE/v1/go" || T || n): G is its first 40 bits.
fn go_ahead_digest(tag: &SealTag, nonce: &CheckNonce) -> [u8; 32] {
    Sha256::new()
        .chain_update(GO_DOMAIN)
        .chain_update(tag.as_bytes())
        .chain_update(nonce.as_bytes())
        .finalize()
        .into()
}

/// G as the checker shows it, without the dash: 8 Crockford characters.
pub(crate) fn go_ahead_code(tag: &SealTag, nonce: &CheckNonce) -> [u8; 8] {
    crockford::encode::<{ crockford::GO_AHEAD_SYMBOLS }>(&go_ahead_digest(tag, nonce))
}

/// Whether 40 typed bits are this check's G, compared in constant time.
pub(crate) fn go_ahead_matches(tag: &SealTag, nonce: &CheckNonce, typed: &[u8; 5]) -> bool {
    let digest = go_ahead_digest(tag, nonce);
    let expected: [u8; 5] = [digest[0], digest[1], digest[2], digest[3], digest[4]];
    fixed_time_eq(typed, &expected)
}

/// Ok if `typed` is this check's go-ahead code. Malformed text is `MalformedCode`, a well-formed
/// code for another seal or nonce `WrongCode`; neither echoes the input.
pub(crate) fn verify_go_ahead(
    tag: &SealTag,
    nonce: &CheckNonce,
    typed: &str,
) -> Result<(), CheckError> {
    let bits = crockford::decode_go_ahead(typed)?;
    if go_ahead_matches(tag, nonce, &bits) {
        Ok(())
    } else {
        Err(CheckError::WrongCode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, read, text};

    fn tag_of(v: &serde_json::Value) -> SealTag {
        SealTag::from_bytes(hex(&v["seal_tag_hex"]).try_into().expect("32 bytes"))
    }

    fn nonce_of(v: &serde_json::Value) -> CheckNonce {
        CheckNonce::from_bytes(
            hex(&v["go_ahead"]["nonce_hex"])
                .try_into()
                .expect("8 bytes"),
        )
    }

    // CF94-BCAJ and the codes of seal vectors 2 and 3 pass, typed in any accepted form.
    #[test]
    fn each_seal_vector_code_passes() {
        let doc = read("seal.json");
        for v in doc["vectors"].as_array().expect("vectors") {
            let (tag, nonce) = (tag_of(v), nonce_of(v));
            let code = text(&v["go_ahead"]["code"]);
            for typed in [
                code.to_owned(),
                code.to_ascii_lowercase(),
                text(&v["go_ahead"]["code_compact"]).to_owned(),
                code.chars().flat_map(|c| [c, ' ']).collect(),
            ] {
                assert_eq!(verify_go_ahead(&tag, &nonce, &typed), Ok(()), "{typed}");
            }
        }
        let v1 = &doc["vectors"][0];
        assert_eq!(text(&v1["go_ahead"]["code"]), "CF94-BCAJ");
    }

    // A code for another T, any single flipped bit of n, and every single flipped bit of G fail.
    #[test]
    fn codes_for_another_seal_nonce_or_bit_fail() {
        let doc = read("seal.json");
        let (v1, v2) = (&doc["vectors"][0], &doc["vectors"][1]);
        let (tag, nonce) = (tag_of(v1), nonce_of(v1));
        let right = text(&v1["go_ahead"]["code"]);
        assert_eq!(
            verify_go_ahead(&tag_of(v2), &nonce, right),
            Err(CheckError::WrongCode)
        );
        for bit in 0..64 {
            let mut flipped = *nonce.as_bytes();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                verify_go_ahead(&tag, &CheckNonce::from_bytes(flipped), right),
                Err(CheckError::WrongCode),
                "nonce bit {bit}"
            );
        }
        let bits = crockford::decode_go_ahead(right).expect("a code");
        for bit in 0..40 {
            let mut flipped = bits;
            flipped[bit / 8] ^= 0x80 >> (bit % 8);
            let mut digest = [0u8; 32];
            digest[..5].copy_from_slice(&flipped);
            let typed = crockford::encode::<8>(&digest);
            let typed = core::str::from_utf8(&typed).expect("ASCII");
            assert_eq!(
                verify_go_ahead(&tag, &nonce, typed),
                Err(CheckError::WrongCode),
                "G bit {bit}"
            );
        }
    }

    // A typo keeps the check alive: the same function then accepts the right code (the session's
    // Retry is M1 group 9).
    #[test]
    fn a_malformed_code_then_the_right_one() {
        let doc = read("seal.json");
        let v1 = &doc["vectors"][0];
        let (tag, nonce) = (tag_of(v1), nonce_of(v1));
        assert_eq!(
            verify_go_ahead(&tag, &nonce, "CF94-BCA"),
            Err(CheckError::MalformedCode)
        );
        assert_eq!(
            verify_go_ahead(&tag, &nonce, "CF94-BCAK"),
            Err(CheckError::WrongCode)
        );
        assert_eq!(verify_go_ahead(&tag, &nonce, "CF94-BCAJ"), Ok(()));
    }

    #[test]
    fn the_check_url_of_vector_1() {
        let doc = read("seal.json");
        let v1 = &doc["vectors"][0];
        assert_eq!(
            CheckRequest::new(&tag_of(v1), &nonce_of(v1)).url(),
            "https://registry.invalid/check#t=2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c&n=0001020304050607"
        );
    }

    #[test]
    fn the_nonce_comes_from_the_os_source() {
        let mut source = Source::Os;
        match (CheckNonce::draw(&mut source), CheckNonce::draw(&mut source)) {
            (Ok(a), Ok(b)) => assert_ne!(a, b, "two fresh nonces"),
            _ => panic!("the OS source failed"),
        }
    }

    #[cfg(feature = "test-sources")]
    #[test]
    fn the_nonce_is_the_stub_bytes_and_a_failure_fails_closed() {
        use crate::error::SourceFault;
        use crate::source::{StubEntropy, StubSource, WipeProbe};
        let probe = WipeProbe::new();
        let mut source = Source::Stub(StubSource::new(
            StubEntropy::Fixed(vec![0, 1, 2, 3, 4, 5, 6, 7]),
            &probe,
        ));
        assert_eq!(
            CheckNonce::draw(&mut source),
            Ok(CheckNonce::from_bytes([0, 1, 2, 3, 4, 5, 6, 7]))
        );
        assert_eq!(
            CheckNonce::draw(&mut source),
            Err(CoreError::Source(SourceFault::Os)),
            "a used-up stub fails like the OS"
        );
        let mut short = Source::Stub(StubSource::new(StubEntropy::ShortAfter(4), &probe));
        assert_eq!(
            CheckNonce::draw(&mut short),
            Err(CoreError::Source(SourceFault::ShortRead))
        );
    }
}
