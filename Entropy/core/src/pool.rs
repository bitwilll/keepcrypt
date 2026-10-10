//! The device-leg pool (CLAUDE.md rules 2 and 4; docs/build-plan.md "pool"; docs/design.md
//! "Mixing and conditioning"; tasks/todo.md, M1 group 3 and Q6a).
//!
//! One SHA-512 state, 512 bits wide. `new` absorbs the 11 bytes `KCE/v1/pool` once, before any
//! record. Each record is the source id (u16, big-endian), the length (u64, big-endian) and the
//! data; a record with no bytes writes nothing. Sources are hashed together, never XORed. D is the
//! first 32 bytes of the digest, written in place into the session's D, and the digest is then
//! zeroized. Nothing between the pool and the seed is narrower than 256 bits.

use sha2::digest::Output;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CoreError, InternalFault};
use crate::secret::SecretBytes32;
use crate::source::SourceId;

/// The pool's domain tag, absorbed once, first.
pub(crate) const POOL_TAG: &[u8] = b"KCE/v1/pool";

/// The SHA-512 state holds every absorbed byte's influence: it must wipe itself when dropped.
const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
const _: () = assert_zeroize_on_drop::<Sha512>();

/// The SHA-512 pool behind D.
pub(crate) struct Pool {
    hasher: Sha512,
}

impl Pool {
    /// A pool that has absorbed its tag and no record.
    pub(crate) fn new() -> Self {
        let mut hasher = Sha512::new();
        hasher.update(POOL_TAG);
        Self { hasher }
    }

    /// Absorbs one record: id (u16 BE) || length (u64 BE) || data. Empty data writes nothing.
    pub(crate) fn absorb(&mut self, source: SourceId, data: &[u8]) -> Result<(), CoreError> {
        if data.is_empty() {
            return Ok(());
        }
        let len =
            u64::try_from(data.len()).map_err(|_| CoreError::Internal(InternalFault::Length))?;
        self.hasher.update(source.to_be_bytes());
        self.hasher.update(len.to_be_bytes());
        self.hasher.update(data);
        Ok(())
    }

    /// Ends the pool: D = SHA-512(everything absorbed)[0..32], written into `d`. The 64-byte digest
    /// is zeroized, and the consumed hasher wipes itself.
    pub(crate) fn finish_into(self, d: &mut SecretBytes32) {
        let mut digest = Output::<Sha512>::default();
        self.hasher.finalize_into(&mut digest);
        d.expose_secret_mut().copy_from_slice(&digest[..32]);
        digest.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ExtraSource;
    use crate::test_vectors::{hex, keepcrypt_json, named, text};
    use serde_json::Value;
    use std::collections::HashSet;

    fn source_id(id: &Value) -> SourceId {
        match id.as_u64().expect("an id") {
            0x0001 => SourceId::Os,
            0x0002 => SourceId::Hwrng,
            0x0101 => SourceId::Extra(ExtraSource::InputTiming),
            0x0102 => SourceId::Extra(ExtraSource::Motion),
            0x0103 => SourceId::Extra(ExtraSource::Camera),
            0x0104 => SourceId::Extra(ExtraSource::Microphone),
            other => panic!("no source id {other}"),
        }
    }

    fn device_leg(records: &[(SourceId, Vec<u8>)]) -> [u8; 32] {
        let mut pool = Pool::new();
        for (source, data) in records {
            assert_eq!(pool.absorb(*source, data), Ok(()));
        }
        let mut d = SecretBytes32::zeroed();
        pool.finish_into(&mut d);
        *d.expose_secret()
    }

    fn records(case: &Value) -> Vec<(SourceId, Vec<u8>)> {
        let list = case["records"].as_array().expect("records");
        list.iter()
            .map(|r| (source_id(&r["id"]), hex(&r["data_hex"])))
            .collect()
    }

    #[test]
    fn every_keepcrypt_json_pool_case() {
        let doc = keepcrypt_json();
        assert_eq!(doc["constants"]["pool_tag_ascii"], "KCE/v1/pool");
        assert_eq!(
            text(&doc["constants"]["pool_tag_ascii"]).as_bytes(),
            POOL_TAG
        );
        let cases = doc["pool"].as_array().expect("pool cases");
        for case in cases {
            assert_eq!(
                device_leg(&records(case)).to_vec(),
                hex(&case["d_hex"]),
                "{}",
                text(&case["name"])
            );
        }
        let pool = &doc["pool"];
        assert_eq!(
            hex(&named(pool, "empty")["d_hex"]),
            device_leg(&[]).to_vec()
        );
        assert_ne!(
            named(pool, "split-ab-c")["d_hex"],
            named(pool, "split-a-bc")["d_hex"],
            "lengths frame records"
        );
        assert_eq!(
            named(pool, "empty-record-skipped")["d_hex"],
            named(pool, "one-os-record")["d_hex"]
        );
    }

    // The same pool over the source-substitution sessions' records (the session maps events to
    // these records; tests/source_substitution.rs drives it).
    #[test]
    fn source_substitution_records_give_their_d() {
        let doc = keepcrypt_json();
        for case in doc["source_substitution"].as_array().expect("cases") {
            assert_eq!(
                device_leg(&records(case)).to_vec(),
                hex(&case["d_hex"]),
                "{}",
                text(&case["name"])
            );
        }
    }

    // CLAUDE.md rule 2: each of the 512 single-bit flips of the 64-byte OS record changes D (and
    // all 513 values of D differ). Base bytes: keepcrypt.json "one-os-record", SHA-256 counter mode.
    #[test]
    fn every_bit_of_the_os_record_reaches_d() {
        let base =
            hex(&named(&keepcrypt_json()["pool"], "one-os-record")["records"][0]["data_hex"]);
        assert_eq!(base.len(), 64);
        let mut seen = HashSet::new();
        assert!(seen.insert(device_leg(&[(SourceId::Os, base.clone())])));
        for bit in 0..512 {
            let mut flipped = base.clone();
            flipped[bit / 8] ^= 0x80 >> (bit % 8);
            assert!(
                seen.insert(device_leg(&[(SourceId::Os, flipped)])),
                "bit {bit} did not change D"
            );
        }
        assert_eq!(seen.len(), 513);
    }

    #[test]
    fn empty_data_writes_no_record() {
        let mut with_empty = Pool::new();
        assert_eq!(with_empty.absorb(SourceId::Hwrng, &[]), Ok(()));
        let mut d_empty = SecretBytes32::zeroed();
        with_empty.finish_into(&mut d_empty);
        assert_eq!(d_empty.expose_secret(), &device_leg(&[]));
    }
}
