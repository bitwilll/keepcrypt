//! The collision seal (CLAUDE.md rule 7, "Seal code", "Seal tag", "Check nonce", "Go-ahead code";
//! docs/seal-watchonly-braille.md "Seal derivation spec", "The seal image", "Go-ahead before
//! reveal", "Registration, re-checks and safety"; tasks/todo.md, M1 group 7, Q6d).
//!
//! - The seal code is the top 130 bits of HMAC-SHA256(S, "KCE/v1/seal") as 26 Crockford base32
//!   characters, where S is the BIP39 seed with the empty passphrase. No passphrase parameter
//!   exists anywhere on this path, and no public key is used.
//! - T = SHA-256("KCE/v1/seal-tag" || the code's 26 ASCII characters, uppercase, no dashes). The
//!   dashes are display only (tasks/lessons.md: state the exact bytes).
//! - From T, computed once: the Seal ID (first 40 bits, 8 characters) and its braille caption, the
//!   lookup prefix (5 hex characters) and bucket (20 bits), the 8x8 grid and its colour, and the
//!   re-check URL `<origin>/check#t=<64 lowercase hex>`, with no nonce, so a checker can show the
//!   registration count but never a go-ahead code (Q6d).
//! - `SealCode` and the QRs that carry it (`SealRegistration`, `CollisionReport`) are wiped on drop
//!   and have no `Debug`, `Display` or `Clone`: anyone holding a code can file a false collision
//!   report. `SealPublic` holds public values only.
//! - `seal_from_mnemonic` serves later re-checks (a decrypted backup, the M2 verifier's twin): it
//!   runs the Seal known-answer group first.
//! - Signed registry evidence: `verify_snapshot` reads a `.kcr` snapshot and `verify_bucket_proof`
//!   (or `verify_bucket_proof_qr`, from the go-ahead QR) a KCP1 bucket proof, each against the key
//!   this build pins (`registry_key`; none in release builds until M9), after the Ed25519 and Merkle
//!   known-answer groups. Both verified types give their date and its freshness.
//!
//! Beyond core's reach (tasks/todo.md, M1 group 7, residual): hmac 0.13 builds its keyed state from
//! a padded copy of the key, S xor 0x5c by the end, in a local block of its own `new_from_slice`,
//! and leaves that block on the stack unwiped. Its two hash states and its output are wiped (sha2's
//! and digest's `zeroize`). This is the same class as the residuals recorded for bip39 and
//! rust-bitcoin in M1 group 4.
//!
//! vectors/seal.json pins every public field for three seeds, and vectors/kcr.json four more seeds
//! with their full S; tools/verify/verify.py computes all of them.

mod check;
mod crockford;
mod date;
mod merkle;
mod proof;
mod registration;
mod registry_key;
mod snapshot;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use check::{CheckNonce, CheckRequest};
pub(crate) use check::{go_ahead_code, verify_go_ahead};
pub use date::{Freshness, RegistryDate};
pub(crate) use merkle::{
    leaf as merkle_leaf, node as merkle_node, root_of_path as merkle_root_of_path,
};
pub use proof::{VerifiedProof, verify_bucket_proof, verify_bucket_proof_qr};
#[cfg(feature = "test-sources")]
pub use proof::{verify_bucket_proof_qr_with_kat_fault, verify_bucket_proof_with_kat_fault};
pub use registration::{CollisionReport, SealRegistration};
pub use registry_key::registry_key_is_test;
#[cfg(feature = "test-sources")]
pub use snapshot::verify_snapshot_with_kat_fault;
pub use snapshot::{VerifiedSnapshot, verify_snapshot};

use crate::braille;
use crate::error::{CoreError, KatId};
use crate::kat::{self, Suite};
use crate::secret::{SecretMnemonic, SecretSeed64};
use crate::seed::seed_from_mnemonic_into;

/// The seal code's HMAC message.
pub(crate) const SEAL_DOMAIN: &[u8] = b"KCE/v1/seal";
/// The seal tag's domain tag.
pub(crate) const SEAL_TAG_DOMAIN: &[u8] = b"KCE/v1/seal-tag";
/// The registry origin in every URL a QR carries: a placeholder until M9 (tasks/todo.md, "Later").
pub(crate) const REGISTRY_ORIGIN: &str = "https://registry.invalid";
/// The re-check URL's path and fragment key, before T (Q6d).
const RECHECK_PATH: &str = "/check#t=";
/// Characters in a seal code: 130 bits at 5 bits each.
pub(crate) const SEAL_CODE_CHARS: usize = 26;
/// The display groups of a seal code: 5-5-5-5-6.
const SEAL_CODE_GROUPS: [usize; 5] = [5, 5, 5, 5, 6];
/// Characters in a Seal ID: 40 bits.
const SEAL_ID_CHARS: usize = 8;
/// The Okabe-Ito palette, indexed by T[0] mod 8 (docs "The seal image").
const OKABE_ITO: [&str; 8] = [
    "#000000", "#E69F00", "#56B4E9", "#009E73", "#F0E442", "#0072B2", "#D55E00", "#CC79A7",
];

/// The HMAC behind the seal code. sha2's `zeroize` wipes both of its hash states on drop.
type SealMac = Hmac<Sha256>;

/// The seal tag T: public, stored in the registry and safe to share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealTag([u8; 32]);

impl SealTag {
    /// A tag from its 32 bytes, to look a known tag up in a snapshot or proof.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes of T.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// T as 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        push_hex(&mut out, &self.0);
        out
    }

    /// The registry bucket: the first 20 bits of T, as an index below 2^20.
    pub fn bucket(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]]) >> 4
    }
}

/// The private seal code: 26 Crockford base32 characters, held as ASCII. Sent only when
/// registering or reporting a collision; anyone holding it can file a false collision report, so it
/// is wiped on drop and cannot be printed or copied.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SealCode([u8; SEAL_CODE_CHARS]);

impl SealCode {
    pub(crate) const fn zeroed() -> Self {
        Self([0; SEAL_CODE_CHARS])
    }

    /// Fills the code in place from S: the top 130 bits of HMAC-SHA256(S, "KCE/v1/seal"). The MAC
    /// output is read through a borrow of its zeroizing wrapper, never copied out.
    pub(crate) fn fill_from_seed(&mut self, seed: &SecretSeed64) {
        let mut mac = SealMac::new(seed.expose_secret().into());
        mac.update(SEAL_DOMAIN);
        let output = mac.finalize();
        let digest: &[u8; 32] = output.as_bytes().as_ref();
        crockford::encode_into(digest, &mut self.0);
    }

    /// The 26 characters as hashed and sent: uppercase, no dashes.
    pub(crate) fn as_ascii(&self) -> &[u8; SEAL_CODE_CHARS] {
        &self.0
    }

    /// The code as displayed, `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`, appended to `out`.
    pub(crate) fn push_grouped(&self, out: &mut String) {
        let mut at = 0;
        for (n, size) in SEAL_CODE_GROUPS.into_iter().enumerate() {
            if n > 0 {
                out.push('-');
            }
            out.extend(self.0[at..at + size].iter().map(|&b| char::from(b)));
            at += size;
        }
    }

    /// The length of the grouped form: 26 characters and 4 dashes.
    pub(crate) const GROUPED_LEN: usize = SEAL_CODE_CHARS + SEAL_CODE_GROUPS.len() - 1;
}

/// Everything public about a seal, computed once from the code: the tag T, the Seal ID and its
/// braille caption, the lookup prefix and bucket, the 8x8 grid and its colour, and the re-check
/// URL. Private fields: only core builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealPublic {
    tag: SealTag,
    seal_id: String,
    seal_id_braille: String,
    lookup_prefix: String,
    grid: [[bool; 8]; 8],
    colour_index: u8,
    recheck_url: String,
}

impl SealPublic {
    /// T, computed over the code's 26 characters without dashes, then everything drawn from it.
    pub(crate) fn from_code(code: &SealCode) -> Result<Self, CoreError> {
        let tag = SealTag(
            Sha256::new()
                .chain_update(SEAL_TAG_DOMAIN)
                .chain_update(code.as_ascii())
                .finalize()
                .into(),
        );
        let seal_id: String = crockford::encode::<SEAL_ID_CHARS>(&tag.0)
            .iter()
            .map(|&b| char::from(b))
            .collect();
        let seal_id_braille = braille::render_text(&seal_id.to_ascii_lowercase())?;
        let mut lookup_prefix = tag.to_hex();
        lookup_prefix.truncate(5);
        let mut recheck_url =
            String::with_capacity(REGISTRY_ORIGIN.len() + RECHECK_PATH.len() + 64);
        recheck_url.push_str(REGISTRY_ORIGIN);
        recheck_url.push_str(RECHECK_PATH);
        push_hex(&mut recheck_url, &tag.0);
        Ok(Self {
            tag,
            seal_id,
            seal_id_braille,
            lookup_prefix,
            grid: grid(&tag),
            colour_index: tag.0[0] % 8,
            recheck_url,
        })
    }

    /// The seal tag T.
    pub fn tag(&self) -> &SealTag {
        &self.tag
    }

    /// The Seal ID: the first 40 bits of T as 8 Crockford characters, printed under the image.
    pub fn seal_id(&self) -> &str {
        &self.seal_id
    }

    /// The Seal ID in braille (UEB grade 1, lowercase, docs "Cell alphabet"): the caption for blind
    /// users.
    pub fn seal_id_braille(&self) -> &str {
        &self.seal_id_braille
    }

    /// The first 5 lowercase hex characters (20 bits) of T: all an online lookup sends.
    pub fn lookup_prefix(&self) -> &str {
        &self.lookup_prefix
    }

    /// The registry bucket: the first 20 bits of T.
    pub fn bucket(&self) -> u32 {
        self.tag.bucket()
    }

    /// The 8x8 seal image, row by row, `true` for a filled cell: the left four columns from bytes
    /// 1-4 of T, most significant bit first; the right four mirror them.
    pub fn grid(&self) -> &[[bool; 8]; 8] {
        &self.grid
    }

    /// The colour of the filled cells: T[0] mod 8, an index into the Okabe-Ito palette.
    pub fn colour_index(&self) -> u8 {
        self.colour_index
    }

    /// The colour of the filled cells as `#RRGGBB`.
    pub fn colour_hex(&self) -> &'static str {
        OKABE_ITO[usize::from(self.colour_index)]
    }

    /// The online re-check QR: `https://registry.invalid/check#t=<64 lowercase hex>` until M9, with
    /// no nonce, so a checker shows the registration count but never a go-ahead code.
    pub fn recheck_url(&self) -> &str {
        &self.recheck_url
    }
}

/// The 8x8 grid: bit 31 - (4r + c) of T[1..5] fills row r, column c and its mirror 7 - c.
fn grid(tag: &SealTag) -> [[bool; 8]; 8] {
    let bits = u32::from_be_bytes([tag.0[1], tag.0[2], tag.0[3], tag.0[4]]);
    let mut grid = [[false; 8]; 8];
    let mut bit = 32u32;
    for row in &mut grid {
        for column in 0..4 {
            bit -= 1;
            let filled = bits >> bit & 1 == 1;
            row[column] = filled;
            row[7 - column] = filled;
        }
    }
    grid
}

/// Lowercase hex of `bytes`, appended to `out`.
pub(crate) fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
}

/// The seal of a BIP39 seed S (empty passphrase): the code, filled in place, and its public half.
/// `seal_from_mnemonic` and, from M1 group 9, `Session::finish` derive it this way.
pub(crate) fn derive_seal(
    seed: &SecretSeed64,
    code: &mut SealCode,
) -> Result<SealPublic, CoreError> {
    code.fill_from_seed(seed);
    SealPublic::from_code(code)
}

/// The public seal of a seed's words, for re-checks of an existing wallet (a decrypted backup):
/// S with the empty passphrase, then the code and T. Runs the Seal known-answer group first.
pub fn seal_from_mnemonic(mnemonic: &SecretMnemonic) -> Result<SealPublic, CoreError> {
    seal_from_mnemonic_body(mnemonic, None)
}

/// `seal_from_mnemonic` with known-answer group `fault` made to fail (tests only).
#[cfg(feature = "test-sources")]
pub fn seal_from_mnemonic_with_kat_fault(
    mnemonic: &SecretMnemonic,
    fault: KatId,
) -> Result<SealPublic, CoreError> {
    seal_from_mnemonic_body(mnemonic, Some(fault))
}

fn seal_from_mnemonic_body(
    mnemonic: &SecretMnemonic,
    fault: Option<KatId>,
) -> Result<SealPublic, CoreError> {
    kat::run(Suite::Seal, fault)?;
    let mut seed = SecretSeed64::zeroed();
    seed_from_mnemonic_into(mnemonic, &mut seed)?;
    let mut code = SealCode::zeroed();
    derive_seal(&seed, &mut code)
}

/// White-box test support for the seal's secret types.
#[cfg(test)]
mod test_fill {
    use super::*;
    use crate::secret::TestFill;

    impl TestFill for SealCode {
        fn fill(&mut self) {
            self.0 = [b'Z'; SEAL_CODE_CHARS];
        }
        fn is_zero(&self) -> bool {
            self.0 == [0; SEAL_CODE_CHARS]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::TestFill;
    use crate::test_vectors::{hex, read, text};

    /// A mnemonic from its words (public test mnemonics only).
    pub(crate) fn mnemonic(words: &str) -> SecretMnemonic {
        let mut m = SecretMnemonic::zeroed();
        let indices: Vec<usize> = words
            .split(' ')
            .map(|w| usize::from(bip39::Language::English.find_word(w).expect("a BIP39 word")))
            .collect();
        m.fill_from(indices.into_iter()).expect("12 or 24 words");
        m
    }

    fn seed_of(words: &str) -> SecretSeed64 {
        let mut seed = SecretSeed64::zeroed();
        seed_from_mnemonic_into(&mnemonic(words), &mut seed).expect("a valid mnemonic");
        seed
    }

    fn grouped(code: &SealCode) -> String {
        let mut out = String::new();
        code.push_grouped(&mut out);
        out
    }

    fn rows(public: &SealPublic) -> Vec<String> {
        public
            .grid()
            .iter()
            .map(|row| row.iter().map(|&c| if c { '#' } else { '.' }).collect())
            .collect()
    }

    // Every field of the three seal.json vectors (tasks/todo.md, M1 group 7), the S prefix included:
    // it is the BIP39 seed with the empty passphrase, so it pins that no passphrase reaches the seal.
    #[test]
    fn every_seal_json_field() {
        let doc = read("seal.json");
        let vectors = doc["vectors"].as_array().expect("vectors");
        assert_eq!(vectors.len(), 3);
        for v in vectors {
            let seed = seed_of(text(&v["mnemonic"]));
            assert_eq!(
                &seed.expose_secret()[..16],
                hex(&v["seed_prefix_hex"]).as_slice()
            );
            let mut code = SealCode::zeroed();
            let public = derive_seal(&seed, &mut code).expect("a seal");
            assert_eq!(grouped(&code), text(&v["seal_code"]));
            assert_eq!(code.as_ascii(), text(&v["seal_code_hashed"]).as_bytes());
            assert_eq!(public.tag().as_bytes().as_slice(), hex(&v["seal_tag_hex"]));
            assert_eq!(public.tag().to_hex(), text(&v["seal_tag_hex"]));
            assert_eq!(public.seal_id(), text(&v["seal_id"]));
            assert_eq!(public.seal_id_braille(), text(&v["seal_id_braille"]));
            assert_eq!(public.lookup_prefix(), text(&v["lookup_prefix"]));
            assert_eq!(
                Some(u64::from(public.colour_index())),
                v["colour_index"].as_u64()
            );
            assert_eq!(public.colour_hex(), text(&v["colour_hex"]));
            let grid: Vec<String> = v["grid"]
                .as_array()
                .expect("grid")
                .iter()
                .map(|r| text(r).to_owned())
                .collect();
            assert_eq!(rows(&public), grid);
            let nonce = CheckNonce::from_bytes(
                hex(&v["go_ahead"]["nonce_hex"])
                    .try_into()
                    .expect("8 bytes"),
            );
            let code_g = go_ahead_code(public.tag(), &nonce);
            assert_eq!(&code_g, text(&v["go_ahead"]["code_compact"]).as_bytes());
            assert_eq!(
                seal_from_mnemonic(&mnemonic(text(&v["mnemonic"]))),
                Ok(public)
            );
        }
    }

    // T is over the 26 characters without dashes; the dashed form gives another T (tasks/lessons.md).
    #[test]
    fn the_dashed_code_gives_a_different_tag() {
        let seed = seed_of(text(&read("seal.json")["vectors"][0]["mnemonic"]));
        let mut code = SealCode::zeroed();
        let public = derive_seal(&seed, &mut code).expect("a seal");
        let dashed = Sha256::new()
            .chain_update(SEAL_TAG_DOMAIN)
            .chain_update(grouped(&code).as_bytes())
            .finalize();
        assert_ne!(dashed.as_slice(), public.tag().as_bytes());
        assert_eq!(SealCode::GROUPED_LEN, grouped(&code).len());
    }

    #[test]
    fn the_recheck_url_of_vector_1() {
        let public = seal_from_mnemonic(&mnemonic(text(
            &read("seal.json")["vectors"][0]["mnemonic"],
        )))
        .expect("a seal");
        assert_eq!(
            public.recheck_url(),
            "https://registry.invalid/check#t=2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c"
        );
        assert_eq!(public.bucket(), 0x2b810);
        assert_eq!(public.tag().bucket(), 0x2b810);
    }

    // kcr.json's seeds: seal vector 1 and the 50- and 99-roll dice-only seeds, with their full S, T,
    // Seal ID, bucket and go-ahead code.
    #[test]
    fn kcr_json_seeds() {
        let doc = read("kcr.json");
        let seeds = doc["seeds"].as_array().expect("seeds");
        assert_eq!(seeds.len(), 4);
        for s in seeds {
            let seed = seed_of(text(&s["mnemonic"]));
            assert_eq!(seed.expose_secret().as_slice(), hex(&s["seed_hex"]));
            let mut code = SealCode::zeroed();
            let public = derive_seal(&seed, &mut code).expect("a seal");
            assert_eq!(grouped(&code), text(&s["seal_code"]));
            assert_eq!(public.tag().to_hex(), text(&s["seal_tag_hex"]));
            assert_eq!(public.seal_id(), text(&s["seal_id"]));
            assert_eq!(Some(u64::from(public.bucket())), s["bucket"].as_u64());
            let nonce = CheckNonce::from_bytes(hex(&s["nonce_hex"]).try_into().expect("8 bytes"));
            assert_eq!(
                &go_ahead_code(public.tag(), &nonce),
                text(&s["go_ahead_compact"]).as_bytes()
            );
            assert_eq!(
                verify_go_ahead(public.tag(), &nonce, text(&s["go_ahead"])),
                Ok(())
            );
        }
    }

    #[test]
    fn grid_rows_mirror_and_read_t_most_significant_first() {
        let mut bytes = [0u8; 32];
        bytes[1] = 0x80;
        bytes[4] = 0x01;
        let grid = grid(&SealTag::from_bytes(bytes));
        assert!(grid[0][0] && grid[0][7]);
        assert!(grid[7][3] && grid[7][4]);
        let filled: usize = grid.iter().flatten().filter(|&&c| c).count();
        assert_eq!(filled, 4);
    }

    #[test]
    fn hex_is_lowercase_and_complete() {
        let mut out = String::new();
        push_hex(&mut out, &[0x00, 0x0f, 0xa5, 0xff]);
        assert_eq!(out, "000fa5ff");
    }

    #[test]
    fn seal_code_zeroizes() {
        let mut code = SealCode::zeroed();
        code.fill();
        assert!(!code.is_zero());
        code.zeroize();
        assert!(code.is_zero());
    }

    // Every secret type here wipes itself when dropped (CLAUDE.md rule 5).
    const fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    const _: () = {
        zeroize_on_drop::<SealCode>();
        zeroize_on_drop::<SealRegistration>();
        zeroize_on_drop::<CollisionReport>();
    };

    #[test]
    fn an_invalid_mnemonic_has_no_seal() {
        let mut m = SecretMnemonic::zeroed();
        m.fill_from([0usize; 12].into_iter()).expect("12 indices");
        assert_eq!(
            seal_from_mnemonic(&m),
            Err(CoreError::Internal(crate::error::InternalFault::Bip39))
        );
    }

    #[cfg(feature = "test-sources")]
    #[test]
    fn every_kat_fault_reaches_seal_from_mnemonic_only_for_its_groups() {
        let m = mnemonic(text(&read("seal.json")["vectors"][0]["mnemonic"]));
        for id in KatId::ALL {
            let result = seal_from_mnemonic_with_kat_fault(&m, id);
            if id == KatId::Seal {
                assert_eq!(result, Err(CoreError::Kat(id)));
            } else {
                assert!(result.is_ok(), "{id:?}");
            }
        }
    }
}
