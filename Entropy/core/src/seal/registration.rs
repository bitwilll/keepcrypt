//! The "Register seal" and "Report collision" QRs (docs/seal-watchonly-braille.md "Registering a
//! new seal", "Reporting a collision"; tasks/todo.md, M1 group 7, Q6d).
//!
//! Both carry `<origin>/register#c=<the 26 seal-code characters, uppercase, no dashes>`, plus the
//! grouped code and the Seal ID for the screen, and one builder makes both. They hold a seal code,
//! so they are wiped on drop and have no `Debug`, `Display` or `Clone`. Every string is sized
//! exactly before it is filled, so none reallocates and leaves a copy behind.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{REGISTRY_ORIGIN, SEAL_CODE_CHARS, SealCode, SealPublic};

/// The register URL's path and fragment key, before the code (Q6d).
const REGISTER_PATH: &str = "/register#c=";

/// The contents of a register QR: the URL, the grouped code and the Seal ID.
#[derive(Zeroize, ZeroizeOnDrop)]
struct RegisterQr {
    url: String,
    grouped_code: String,
    seal_id: String,
}

impl RegisterQr {
    /// The one builder behind both QRs.
    fn build(code: &SealCode, public: &SealPublic) -> Self {
        let mut url =
            String::with_capacity(REGISTRY_ORIGIN.len() + REGISTER_PATH.len() + SEAL_CODE_CHARS);
        url.push_str(REGISTRY_ORIGIN);
        url.push_str(REGISTER_PATH);
        url.extend(code.as_ascii().iter().map(|&b| char::from(b)));
        let mut grouped_code = String::with_capacity(SealCode::GROUPED_LEN);
        code.push_grouped(&mut grouped_code);
        Self {
            url,
            grouped_code,
            seal_id: public.seal_id().to_owned(),
        }
    }
}

/// The "Register seal" QR, shown once after the backups (opt-in): it carries this wallet's seal
/// code, so it is wiped on drop and cannot be printed or copied.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SealRegistration(RegisterQr);

impl SealRegistration {
    /// The QR for this seal.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Session<Ready>::registration builds it (M1 group 9)"
        )
    )]
    pub(crate) fn new(code: &SealCode, public: &SealPublic) -> Self {
        Self(RegisterQr::build(code, public))
    }

    /// The QR text: `https://registry.invalid/register#c=<26 uppercase characters>` until M9.
    pub fn url(&self) -> &str {
        &self.0.url
    }

    /// The seal code as shown: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`.
    pub fn grouped_code(&self) -> &str {
        &self.0.grouped_code
    }

    /// The Seal ID, to compare with the registry page.
    pub fn seal_id(&self) -> &str {
        &self.0.seal_id
    }
}

/// The "Report collision" QR, offered after a match: the destroyed seed's seal code, so that
/// registering it raises the count the earlier owner's next re-check sees. Built like a
/// registration; wiped on drop all the same.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CollisionReport(RegisterQr);

impl CollisionReport {
    /// The report for this seal.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Session<Checking>::reveal and discard keep it (M1 group 9)"
        )
    )]
    pub(crate) fn new(code: &SealCode, public: &SealPublic) -> Self {
        Self(RegisterQr::build(code, public))
    }

    /// The QR text: `https://registry.invalid/register#c=<26 uppercase characters>` until M9.
    pub fn url(&self) -> &str {
        &self.0.url
    }

    /// The seal code as shown: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`.
    pub fn grouped_code(&self) -> &str {
        &self.0.grouped_code
    }

    /// The destroyed seed's Seal ID.
    pub fn seal_id(&self) -> &str {
        &self.0.seal_id
    }
}

#[cfg(test)]
mod tests {
    use super::super::derive_seal;
    use super::*;
    use crate::secret::SecretMnemonic;
    use crate::seed::{EmptyPassphraseSeed, seed_from_mnemonic_into};
    use crate::test_vectors::{hex, read};

    /// The abandon seal, from its words (S with the empty passphrase), checked against kcr.json's S.
    fn abandon() -> (SealCode, SealPublic) {
        let doc = read("kcr.json");
        let mut words = SecretMnemonic::zeroed();
        words
            .fill_from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3].into_iter())
            .expect("12 words");
        let mut seed = EmptyPassphraseSeed::zeroed();
        seed_from_mnemonic_into(&words, &mut seed).expect("a valid mnemonic");
        assert_eq!(
            seed.as_seed().expose_secret().as_slice(),
            hex(&doc["seeds"][0]["seed_hex"])
        );
        let mut code = SealCode::zeroed();
        let public = derive_seal(&seed, &mut code).expect("a seal");
        (code, public)
    }

    #[test]
    fn the_abandon_registration_and_its_collision_report() {
        let (code, public) = abandon();
        let registration = SealRegistration::new(&code, &public);
        assert_eq!(
            registration.url(),
            "https://registry.invalid/register#c=JXP3RDXYACJZ1NAX3RGQDJCJJN"
        );
        assert_eq!(
            registration.grouped_code(),
            "JXP3R-DXYAC-JZ1NA-X3RGQ-DJCJJN"
        );
        assert_eq!(registration.seal_id(), "5E0G7J6X");
        let report = CollisionReport::new(&code, &public);
        assert_eq!(report.url(), registration.url());
        assert_eq!(report.grouped_code(), registration.grouped_code());
        assert_eq!(report.seal_id(), registration.seal_id());
        // Sized exactly: no string grew, so none left a copy behind.
        assert_eq!(registration.0.url.capacity(), registration.0.url.len());
        assert_eq!(
            registration.0.grouped_code.capacity(),
            registration.0.grouped_code.len()
        );
    }

    #[test]
    fn zeroize_clears_every_field() {
        let (code, public) = abandon();
        let mut registration = SealRegistration::new(&code, &public);
        registration.zeroize();
        assert!(registration.url().is_empty());
        assert!(registration.grouped_code().is_empty());
        assert!(registration.seal_id().is_empty());
        let mut report = CollisionReport::new(&code, &public);
        report.zeroize();
        assert!(report.url().is_empty() && report.grouped_code().is_empty());
    }
}
