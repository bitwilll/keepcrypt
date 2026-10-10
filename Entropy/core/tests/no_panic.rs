//! Hostile input never panics (CLAUDE.md rule 3; tasks/todo.md, M1 group 9 "core never panics on
//! public input" and group 10). Deterministic truncations and byte flips, chosen by SHA-256 counter
//! mode (never a PRNG), of every kind of public input core reads: hwrng samples, dice faces,
//! go-ahead codes, bucket proofs (bytes and UR text), registry snapshots, `.age` backups, typed
//! backup words, read-back strings, BIP39 passphrases and registry dates. Each gives a result, and
//! where the input is known to be broken, an error; a panic would fail the test.
//!
//! The signed vectors verify only where the test registry key is pinned, so this suite runs with
//! `test-sources` (which turns on `test-registry`); a release build refuses them all before reading.

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    Bip39Passphrase, CheckError, Checking, Collecting, CoreError, GoAhead, Mode, Platform, Ready,
    RegistryDate, Rejected, Rolling, SeedLength, Session, StubEntropy, StubSource,
    TypedBackupPassphrase, WipeProbe, decrypt_backup, verify_bucket_proof, verify_bucket_proof_qr,
    verify_snapshot,
};
use sha2::{Digest, Sha256};

/// `n` bytes of SHA-256 counter mode over `label`: block i is SHA-256(label || i as u64 BE).
fn stream(label: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut block = 0u64;
    while out.len() < n {
        out.extend(
            Sha256::new()
                .chain_update(label.as_bytes())
                .chain_update(block.to_be_bytes())
                .finalize(),
        );
        block += 1;
    }
    out.truncate(n);
    out
}

/// `count` positions below `len`, from counter mode over `label`.
fn positions(label: &str, len: usize, count: usize) -> Vec<usize> {
    stream(label, 4 * count)
        .chunks(4)
        .map(|b| {
            let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            usize::try_from(n).expect("32 bits fit") % len
        })
        .collect()
}

/// Every truncation of `input`, then a copy with one byte replaced at each of `count` positions
/// (the new byte from counter mode, never the old one).
fn mutations(label: &str, input: &[u8], count: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = (0..input.len()).map(|end| input[..end].to_vec()).collect();
    let values = stream(&format!("{label}/values"), count);
    for (at, value) in positions(label, input.len(), count).into_iter().zip(values) {
        let mut changed = input.to_vec();
        changed[at] = if value == changed[at] { !value } else { value };
        out.push(changed);
    }
    out
}

fn stub_session(platform: Platform, mode: Mode, entropy: StubEntropy) -> Session<Collecting> {
    Session::new_with_stub(
        SeedLength::Words12,
        mode,
        platform,
        StubSource::new(entropy, &WipeProbe::new()),
        None,
    )
    .expect("a session")
}

fn rolling(entropy: StubEntropy) -> Session<Rolling> {
    stub_session(Platform::Phone, Mode::DiceOnly, entropy)
        .commit()
        .expect("committed")
        .start_dice()
}

fn rolled(entropy: StubEntropy) -> Session<Rolling> {
    let mut session = rolling(entropy);
    for face in (1..=6).cycle().take(50) {
        session = session.push_roll(face).expect("a face");
    }
    session
}

fn checking() -> Session<Checking> {
    rolled(StubEntropy::Fixed(vec![9; 8]))
        .finish()
        .and_then(|sealed| sealed.start_check())
        .expect("checking")
}

fn ready() -> Session<Ready> {
    rolled(StubEntropy::Fail)
        .finish()
        .expect("sealed")
        .skip_check()
}

#[test]
fn hwrng_samples() {
    let clean = hex(&named(&read("keepcrypt.json")["health"], "clean-4096")["samples_hex"]);
    let mut inputs: Vec<Vec<u8>> = positions("hwrng/lengths", clean.len(), 12)
        .into_iter()
        .map(|end| clean[..end].to_vec())
        .collect();
    let values = stream("hwrng/values", 12);
    for (at, value) in positions("hwrng/flips", clean.len(), 12)
        .into_iter()
        .zip(values)
    {
        let mut changed = clean.clone();
        changed[at] = value;
        inputs.push(changed);
    }
    inputs.extend([
        Vec::new(),
        vec![0],
        vec![0; 4_096],
        vec![0xff; 6],
        stream("hwrng/mebibyte", 1 << 20),
    ]);
    let mut refused = 0;
    for input in &inputs {
        let session = stub_session(
            Platform::Pi,
            Mode::Mixed,
            StubEntropy::Stream(b"os".to_vec()),
        );
        match session.add_hw_samples(input) {
            Ok(session) => assert!(session.hw_bytes_tested() <= 1 << 20),
            Err(e) => {
                assert!(matches!(e, CoreError::Health(_)), "{e:?}");
                refused += 1;
            }
        }
    }
    assert!(refused >= 2, "the stuck streams fail");
}

#[test]
fn dice_faces() {
    for face in [0, 7, 8, 9, 48, 49, 54, 127, 128, 200, 255] {
        assert_eq!(
            rolling(StubEntropy::Fail).push_roll(face).map(|_| ()),
            Err(CoreError::InvalidRoll),
            "face {face}"
        );
    }
    let mut session = rolling(StubEntropy::Fail);
    session.undo_roll();
    for face in (1..=6).cycle().take(256) {
        session = session.push_roll(face).expect("a face");
    }
    assert_eq!(session.rolls(), 256);
    assert_eq!(
        session.push_roll(1).map(|_| ()),
        Err(CoreError::TooManyRolls)
    );
}

#[test]
fn go_ahead_codes() {
    let base = "CF94-BCAJ";
    let mut codes: Vec<String> = (0..=base.len()).map(|end| base[..end].to_owned()).collect();
    let replacements = [
        '\0',
        ' ',
        '-',
        'o',
        'I',
        'l',
        'U',
        '9',
        '\u{e9}',
        '\u{2800}',
        '\u{1f511}',
    ];
    for at in 0..base.len() {
        for &c in &replacements {
            let mut code: Vec<char> = base.chars().collect();
            code[at] = c;
            codes.push(code.into_iter().collect());
        }
    }
    codes.extend([
        String::new(),
        " ".repeat(64),
        "-".repeat(10_000),
        "0".repeat(10_000),
        format!("{base}{base}"),
        "\u{1f511}".repeat(8),
        String::from_utf8_lossy(&stream("codes", 512)).into_owned(),
    ]);
    let mut session = checking();
    for code in &codes {
        session = match session.reveal(GoAhead::Code(code)) {
            Err(Rejected::Retry(session, why)) => {
                assert!(matches!(
                    why,
                    CheckError::MalformedCode | CheckError::WrongCode
                ));
                session
            }
            Err(Rejected::Collision(_)) => panic!("a code is never a collision"),
            Ok(_) => panic!("a stray code revealed"),
        };
    }
}

#[test]
fn bucket_proofs_as_bytes_and_as_ur_text() {
    let kcr = read("kcr.json");
    let proof = hex(&named(&kcr["proofs"], "clear-shared-prefix")["kcp1_hex"]);
    for input in mutations("proof", &proof, 1_024) {
        assert!(verify_bucket_proof(&input).is_err());
    }
    assert!(verify_bucket_proof(&stream("proof/garbage", 4_000)).is_err());

    let ur = text(&named(&kcr["proofs"], "ur-lowercase")["ur"]).to_owned();
    let chars: Vec<char> = ur.chars().collect();
    let replacements = [
        'a',
        'z',
        'A',
        '/',
        ':',
        '-',
        '0',
        ' ',
        '\u{e9}',
        '\u{1f511}',
    ];
    let mut texts: Vec<String> = (0..chars.len())
        .map(|end| chars[..end].iter().collect())
        .collect();
    for (n, at) in positions("ur", chars.len(), 512).into_iter().enumerate() {
        let mut changed = chars.clone();
        let mut replacement = replacements[n % replacements.len()];
        if replacement == changed[at] {
            replacement = replacements[(n + 1) % replacements.len()];
        }
        changed[at] = replacement;
        texts.push(changed.into_iter().collect());
    }
    texts.push(ur.to_uppercase().repeat(3));
    for text in &texts {
        assert!(verify_bucket_proof_qr(text).is_err());
    }
}

#[test]
fn registry_snapshots() {
    let kcr = read("kcr.json");
    let small = hex(&named(&kcr["snapshots"], "small")["kcr_hex"]);
    // Every truncation, and a byte changed at each of 64 places in the signed header and signature.
    for end in 0..small.len() {
        assert!(
            verify_snapshot(&small[..end]).is_err(),
            "truncated to {end}"
        );
    }
    let values = stream("snapshot/values", 64);
    for (at, value) in positions("snapshot", 122, 64).into_iter().zip(values) {
        let mut changed = small.clone();
        changed[at] = if value == changed[at] { !value } else { value };
        assert!(verify_snapshot(&changed).is_err(), "byte {at}");
    }
    // Two changed entries: each passes the signature and costs one full root pass.
    for at in [122, small.len() - 1] {
        let mut changed = small.clone();
        changed[at] ^= 0x80;
        assert!(verify_snapshot(&changed).is_err(), "entry byte {at}");
    }
    for len in [0, 1, 57, 121, 122, 123, 300] {
        assert!(verify_snapshot(&stream("snapshot/garbage", len)).is_err());
    }
}

#[test]
fn age_backups() {
    let doc = read("backup.json");
    let binary = named(&doc["age_files"], "abandon-12-binary");
    let armored = named(&doc["age_files"], "abandon-12");
    let words: Vec<&str> = text(&binary["passphrase"]).split(' ').collect();
    let typed = TypedBackupPassphrase::from_words(&words).expect("8 words");
    let mut opened = 0;
    for input in mutations("age/binary", &hex(&binary["file_hex"]), 256) {
        if decrypt_backup(&input, &typed).is_ok() {
            opened += 1;
        }
    }
    assert_eq!(
        opened, 0,
        "no truncation or changed byte of a binary backup opens"
    );
    // The armored file: every fourth truncation, then the 256 changed bytes.
    let file = text(&armored["file"]).as_bytes().to_vec();
    let mut opened = 0;
    for (n, input) in mutations("age/armored", &file, 256).into_iter().enumerate() {
        if n % 4 == 0 || n >= file.len() {
            opened += usize::from(decrypt_backup(&input, &typed).is_ok());
        }
    }
    assert_eq!(
        opened, 0,
        "no truncation or changed byte of an armored backup opens"
    );
    assert!(decrypt_backup(&stream("age/garbage", 9_000), &typed).is_err());
}

#[test]
fn typed_backup_words() {
    let base = [
        "praise", "bone", "derive", "dinner", "acid", "winter", "choose", "control",
    ];
    let mut lists: Vec<Vec<String>> = (0..=9)
        .map(|n| {
            base.iter()
                .cycle()
                .take(n)
                .map(|w| (*w).to_owned())
                .collect()
        })
        .collect();
    for at in 0..base.len() {
        for word in [
            "", " ", "PRAISE", "prais", "praisee", "\u{e9}", "zoo\0", "a b",
        ] {
            let mut list: Vec<String> = base.iter().map(|w| (*w).to_owned()).collect();
            list[at] = word.to_owned();
            lists.push(list);
        }
    }
    lists.push(vec![
        String::from_utf8_lossy(&stream("words", 300))
            .into_owned();
        8
    ]);
    lists.push(vec!["abandon".to_owned(); 10_000]);
    let mut accepted = 0;
    for list in &lists {
        let words: Vec<&str> = list.iter().map(String::as_str).collect();
        accepted += usize::from(TypedBackupPassphrase::from_words(&words).is_ok());
    }
    assert_eq!(accepted, 1, "only the eight list words themselves");
}

#[test]
fn read_back_strings() {
    let mut session = ready();
    let mut typed: Vec<String> = [
        "",
        "a",
        "ab",
        "abc",
        "abcd",
        "abcde",
        "ABC",
        "a1c",
        "\u{e9}t\u{e9}",
    ]
    .map(str::to_owned)
    .to_vec();
    for len in 0..12 {
        typed.push(String::from_utf8_lossy(&stream(&format!("readback/{len}"), len)).into_owned());
    }
    typed.push("z".repeat(100_000));
    for position in 0..=u8::MAX {
        for letters in &typed {
            let result = session.check_readback(position, letters);
            if position == 0 || position > 12 {
                assert!(result.is_err());
            }
        }
    }
}

#[test]
fn bip39_passphrases_and_registry_dates() {
    let mut session = ready();
    let letters: Vec<(u8, String)> = session
        .braille()
        .iter()
        .map(|i| (i.position(), i.word().chars().take(4).collect()))
        .collect();
    for (position, word) in letters {
        assert!(session.check_readback(position, &word).is_ok());
    }
    for passphrase in [
        " ",
        "\0",
        "a\u{1dc0}\u{1dc1}\u{1dc2}\u{1dc3}\u{1dc4}\u{1dc5}\u{1dc6}\u{1dc7}",
        "\u{fb03}\u{3392}",
        &"\u{1f511}".repeat(1_000),
    ] {
        let p = Bip39Passphrase::new(passphrase).expect("not empty");
        let (next, export) = session.watch_only(Some(&p)).expect("an export");
        assert!(export.passphrase_used());
        session = next;
    }
    assert!(Bip39Passphrase::new("").is_err());

    for value in [0, 1, 101, 10_000_101, 99_991_231, 100_000_101, u32::MAX] {
        assert!(
            RegistryDate::from_yyyymmdd(value).is_ok()
                == (value == 10_000_101 || value == 99_991_231)
        );
    }
    for chunk in stream("dates", 4 * 256).chunks(4) {
        let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Ok(date) = RegistryDate::from_yyyymmdd(value) {
            assert_eq!(date.yyyymmdd(), value);
        }
    }
    for (year, month, day) in [
        (0, 1, 1),
        (10_000, 1, 1),
        (2026, 0, 1),
        (2026, 13, 1),
        (2026, 2, 29),
        (2024, 2, 30),
        (u16::MAX, u8::MAX, u8::MAX),
    ] {
        assert!(RegistryDate::new(year, month, day).is_err());
    }
}
