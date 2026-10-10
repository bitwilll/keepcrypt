//! Secrets never printed (docs/build-plan.md CI rule "Secrets never printed", as refined by Q10;
//! CLAUDE.md rule 5; tasks/todo.md, M1 group 10). Public-vector ceremonies (Coldcard's 50, 99 and
//! 100 rolls in dice-only mode, and keepcrypt.json's two Mixed source-substitution sessions) are run
//! end to end, and every public value they produce that implements `Debug` or `Display` is formatted
//! with both, together with every error variant. A token is a maximal run of ASCII letters,
//! case-folded. Three checks, each with a planted leak it catches:
//!
//! 1. No word of the seed appears in its transcript as a token unless it also appears as a token in
//!    the transcript of a control seed with no word in common. Fixed text such as "test", "wrong"
//!    or "error" is made of BIP39 words; it appears for both seeds alike. Both sides compare whole
//!    tokens: a substring match excused a seed word the control prints only inside a longer token
//!    ("keep" inside "keepcrypt"), so a lone leak of it went unseen (review fix after commit 25).
//!    Whole tokens also keep base58, bytewords and base32 text from matching by chance.
//! 2. No two consecutive seed words appear in order, as adjacent tokens.
//! 3. The `Debug` output of the types that hold or replace a session, `Rejected` and `Wiped`,
//!    contains no BIP39 word as a whole token: not even "session", "report", "flag", "check" or
//!    "code", which are BIP39 words.
//!
//! The secret types themselves have no `Debug` or `Display` at all (tests/typestate.rs).

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    BackupApp, BackupError, BrailleError, CheckError, CoreError, CreatedBy, Discard, ExtraSource,
    Freshness, GoAhead, HW_BYTES_NEEDED, HealthFailure, HealthStage, HealthTest, InternalFault,
    KatId, Mode, Platform, ReadbackResult, Rejected, Sealed, SecretMnemonic, SeedLength, Session,
    SnapshotError, SourceFault, StubEntropy, StubSource, TypedBackupPassphrase, UrError,
    VerifiedSnapshot, WipeProbe, decrypt_backup, verify_bucket_proof, verify_snapshot,
};
use std::fmt::{self, Debug, Write as _};

/// A public-vector ceremony.
struct Ceremony {
    name: &'static str,
    len: SeedLength,
    mode: Mode,
    platform: Platform,
    rolls: &'static str,
}

const CEREMONIES: [Ceremony; 5] = [
    Ceremony {
        name: "dice-only, Coldcard 50 rolls",
        len: SeedLength::Words12,
        mode: Mode::DiceOnly,
        platform: Platform::Phone,
        rolls: "coldcard-50",
    },
    Ceremony {
        name: "dice-only, Coldcard 99 rolls",
        len: SeedLength::Words24,
        mode: Mode::DiceOnly,
        platform: Platform::Pi,
        rolls: "coldcard-99",
    },
    Ceremony {
        name: "dice-only, Coldcard 100 rolls",
        len: SeedLength::Words12,
        mode: Mode::DiceOnly,
        platform: Platform::Pi,
        rolls: "coldcard-100",
    },
    Ceremony {
        name: "Mixed, keepcrypt.json's Pi session",
        len: SeedLength::Words12,
        mode: Mode::Mixed,
        platform: Platform::Pi,
        rolls: "coldcard-50",
    },
    Ceremony {
        name: "Mixed, keepcrypt.json's phone session",
        len: SeedLength::Words24,
        mode: Mode::Mixed,
        platform: Platform::Phone,
        rolls: "coldcard-99",
    },
];

const BY: CreatedBy = CreatedBy::new(BackupApp::Ios, 1, 0, 0);

/// Appends `{:?}` and, for `Display` types, `{}` of each value, one per line.
macro_rules! debug {
    ($out:expr, $($value:expr),+ $(,)?) => {
        $( writeln!($out, "{:?}", $value).expect("written"); )+
    };
}
macro_rules! both {
    ($out:expr, $($value:expr),+ $(,)?) => {
        $( writeln!($out, "{:?} | {}", $value, $value).expect("written"); )+
    };
}

/// keepcrypt.json's roll string `name`, as faces.
fn faces(name: &str) -> Vec<u8> {
    let doc = read("keepcrypt.json");
    text(&named(&doc["dice_only"], name)["rolls"])
        .bytes()
        .map(|b| b - b'0')
        .collect()
}

/// The source-substitution case of a Mixed ceremony: its OS bytes and its calls before `commit`.
fn mixed_case(platform: Platform) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let doc = read("keepcrypt.json");
    let name = match platform {
        Platform::Pi => "pi",
        Platform::Phone => "phone",
    };
    let case = named(&doc["source_substitution"], name);
    let events = case["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|e| {
            let kind = match text(&e["kind"]) {
                "hwrng" => "hwrng".to_owned(),
                _ => text(&e["source"]).to_owned(),
            };
            (kind, hex(&e["data_hex"]))
        })
        .collect();
    (hex(&case["os_hex"]), events)
}

fn extra(name: &str) -> ExtraSource {
    match name {
        "input_timing" => ExtraSource::InputTiming,
        "motion" => ExtraSource::Motion,
        "camera" => ExtraSource::Camera,
        _ => ExtraSource::Microphone,
    }
}

/// Every `CoreError` core can report, from exhaustive matches: a new variant does not compile in
/// `every_error_is_listed` until it is listed here. The other error core reports, `CheckError` (in
/// `Rejected::Retry`), is listed by its generated `CheckError::ALL` in `fixed_text`.
fn every_error() -> Vec<CoreError> {
    let mut all = vec![
        CoreError::QuotaUnmet,
        CoreError::NotInThisMode,
        CoreError::InvalidRoll,
        CoreError::TooManyRolls,
        CoreError::TooFewRolls,
        CoreError::EmptyPassphrase,
        CoreError::ReadbackIncomplete,
        CoreError::NoBackupPassphrase,
        CoreError::WrongPassphrase,
        CoreError::ReadbackMismatch,
        CoreError::ExportSelfCheck,
        CoreError::NoRegistryKey,
    ];
    all.extend(KatId::ALL.map(CoreError::Kat));
    all.extend(SourceFault::ALL.map(CoreError::Source));
    for test in HealthTest::ALL {
        for stage in HealthStage::ALL {
            all.push(CoreError::Health(HealthFailure {
                test,
                stage,
                sample: 1_234,
            }));
        }
    }
    let snapshot = [
        SnapshotError::TooShort,
        SnapshotError::BadMagic,
        SnapshotError::BadVersion,
        SnapshotError::BadSignature,
        SnapshotError::BadDate,
        SnapshotError::TooManyEntries,
        SnapshotError::BadLength,
        SnapshotError::Unsorted,
        SnapshotError::Duplicate,
        SnapshotError::ZeroCount,
        SnapshotError::RootMismatch,
        SnapshotError::BucketOutOfRange,
        SnapshotError::EntryOutsideBucket,
        SnapshotError::ProofCount,
    ];
    all.extend(snapshot.map(CoreError::Snapshot));
    all.extend(UrError::ALL.map(|u| CoreError::Snapshot(SnapshotError::Ur(u))));
    all.extend(BackupError::ALL.map(CoreError::Backup));
    all.extend(BrailleError::ALL.map(CoreError::Braille));
    all.extend(InternalFault::ALL.map(CoreError::Internal));
    all
}

/// The place of each top-level and snapshot variant, by exhaustive match, so that the list above
/// can be checked for completeness.
fn variant(e: CoreError) -> usize {
    match e {
        CoreError::Kat(_) => 0,
        CoreError::Source(_) => 1,
        CoreError::Health(_) => 2,
        CoreError::QuotaUnmet => 3,
        CoreError::NotInThisMode => 4,
        CoreError::InvalidRoll => 5,
        CoreError::TooManyRolls => 6,
        CoreError::TooFewRolls => 7,
        CoreError::EmptyPassphrase => 8,
        CoreError::ReadbackIncomplete => 9,
        CoreError::NoBackupPassphrase => 10,
        CoreError::WrongPassphrase => 11,
        CoreError::ReadbackMismatch => 12,
        CoreError::ExportSelfCheck => 13,
        CoreError::NoRegistryKey => 14,
        CoreError::Snapshot(s) => match s {
            SnapshotError::TooShort => 15,
            SnapshotError::BadMagic => 16,
            SnapshotError::BadVersion => 17,
            SnapshotError::BadSignature => 18,
            SnapshotError::BadDate => 19,
            SnapshotError::TooManyEntries => 20,
            SnapshotError::BadLength => 21,
            SnapshotError::Unsorted => 22,
            SnapshotError::Duplicate => 23,
            SnapshotError::ZeroCount => 24,
            SnapshotError::RootMismatch => 25,
            SnapshotError::BucketOutOfRange => 26,
            SnapshotError::EntryOutsideBucket => 27,
            SnapshotError::ProofCount => 28,
            SnapshotError::Ur(_) => 29,
        },
        CoreError::Backup(_) => 30,
        CoreError::Braille(_) => 31,
        CoreError::Internal(_) => 32,
    }
}

#[test]
fn every_error_is_listed() {
    let mut seen = [false; 33];
    for e in every_error() {
        seen[variant(e)] = true;
    }
    assert_eq!(seen, [true; 33]);
}

/// The text every transcript shares: each variant of the public enums and every error, with `{:?}`
/// and `{}`. It is the same for every seed, so a ceremony's own settings (say, `Phone`, a BIP39 word)
/// never count as a leak against a control seed run on another platform.
///
/// Left out: the `Debug` of `VerifiedSnapshot` and `VerifiedProof`. Both are built from a registry
/// file alone and are the same in every transcript, so they cannot print a seed word; their dates'
/// field names ("year", "month", "day") are BIP39 words, and as fixed text they would excuse those
/// seed words from check 1 ("day" in two of these seeds, "month" in one).
fn fixed_text() -> String {
    let mut out = String::new();
    debug!(
        out,
        SeedLength::Words12,
        SeedLength::Words24,
        Mode::Mixed,
        Mode::DiceOnly,
        Platform::Pi,
        Platform::Phone,
        ExtraSource::InputTiming,
        ExtraSource::Motion,
        ExtraSource::Camera,
        ExtraSource::Microphone,
        Discard::Collision,
        Discard::CannotCheck,
        Freshness::Current,
        Freshness::Stale,
        Freshness::Future,
        HW_BYTES_NEEDED,
        BY,
        BY.app(),
        BY.version()
    );
    for e in every_error() {
        both!(out, e);
    }
    for e in CheckError::ALL {
        both!(out, e);
    }
    out
}

/// What a ceremony shows, formatted: the seed's words and the transcript.
struct Transcript {
    words: Vec<String>,
    text: String,
}

/// Runs one ceremony end to end on deterministic stubs and formats every public value it gives
/// with `{:?}` and `{}`, and every error variant.
fn transcript(ceremony: &Ceremony, clear: &VerifiedSnapshot) -> Transcript {
    let mut out = fixed_text();
    // The same seed again, for the collision report of a check stopped by "Match found".
    let wiped = sealed(ceremony, &[0; 8], &mut out)
        .start_check()
        .expect("checking")
        .discard(Discard::Collision);
    let report = wiped.collision_report().expect("a report");
    both!(out, report.url(), report.grouped_code(), report.seal_id());
    // The nonce, then a stream for the backup.
    let mut after_commit = vec![0; 8];
    after_commit.extend_from_slice(&hex(
        &named(&read("backup.json")["generate"], "stream")["os_hex"],
    ));
    after_commit.extend((0u8..52).map(|b| b.wrapping_mul(37)));
    let sealed = sealed(ceremony, &after_commit, &mut out);
    let seal = sealed.seal();
    debug!(
        out,
        seal,
        seal.tag(),
        seal.bucket(),
        seal.grid(),
        seal.colour_index()
    );
    both!(
        out,
        seal.tag().to_hex(),
        seal.seal_id(),
        seal.seal_id_braille(),
        seal.lookup_prefix(),
        seal.colour_hex(),
        seal.recheck_url()
    );
    let checking = sealed.start_check().expect("checking");
    let request = checking.check_request();
    debug!(out, request, checking.seal());
    both!(out, request.url());
    let typo = GoAhead::Code("0000-0000");
    debug!(out, typo);
    let checking = match checking.reveal(typo) {
        Err(rejected @ Rejected::Retry(..)) => {
            debug!(out, rejected);
            let Rejected::Retry(checking, why) = rejected else {
                panic!("a retry")
            };
            both!(out, why);
            checking
        }
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("a wrong code revealed"),
    };
    let mut ready = match checking.reveal(GoAhead::Snapshot(clear)) {
        Ok(ready) => ready,
        Err(rejected) => panic!("{rejected:?}"),
    };
    let words: Vec<String> = ready.mnemonic().words().map(str::to_owned).collect();
    debug!(out, ready.fingerprint(), ready.readback_complete());
    both!(out, ready.first_address());
    let typed: Vec<(u8, String)> = ready
        .braille()
        .iter()
        .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
        .collect();
    for (position, letters) in typed {
        let result = ready.check_readback(position, &letters);
        assert!(matches!(result, Ok(ReadbackResult::Match)));
    }
    for e in [
        ready.check_readback(0, "abc").map(|_| ()),
        ready.check_readback(1, "a").map(|_| ()),
    ] {
        debug!(out, e);
    }
    debug!(out, ready.readback_complete());
    let (ready, d) = ready.reveal_device_leg().expect("revealed");
    debug!(out, d.is_some());
    let (ready, new) = ready.generate_backup_passphrase().expect("generated");
    let passphrase: Vec<String> = new.words().map(str::to_owned).collect();
    let (ready, file) = ready.encrypt_backup(&BY).expect("written");
    debug!(out, ready.verify_backup(file.bytes()));
    both!(out, file.name());
    let typed = TypedBackupPassphrase::from_words(
        &passphrase.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .expect("8 words");
    let checked = decrypt_backup(file.bytes(), &typed).expect("checked");
    debug!(out, checked.fingerprint(), checked.seal());
    let (ready, registration) = ready.registration().expect("a registration");
    both!(
        out,
        registration.url(),
        registration.grouped_code(),
        registration.seal_id()
    );
    let (ready, export) = ready.watch_only(None).expect("an export");
    debug!(out, export.fingerprint(), export.passphrase_used());
    both!(
        out,
        export.xpub(),
        export.receive_descriptor(),
        export.change_descriptor(),
        export.ur(),
        export.qr_text(),
        export.first_address()
    );
    debug!(out, ready.fingerprint());
    Transcript { words, text: out }
}

/// The ceremony's seed on a stub, through `finish`, formatting each public value on the way. The
/// stub serves a Mixed ceremony's OS bytes at commit, then `after_commit`.
fn sealed(ceremony: &Ceremony, after_commit: &[u8], out: &mut String) -> Session<Sealed> {
    let (os, events) = match ceremony.mode {
        Mode::Mixed => mixed_case(ceremony.platform),
        Mode::DiceOnly => (Vec::new(), Vec::new()),
    };
    let mut bytes = os;
    bytes.extend_from_slice(after_commit);
    let stub = StubSource::new(StubEntropy::Fixed(bytes), &WipeProbe::new());
    let mut session =
        Session::new_with_stub(ceremony.len, ceremony.mode, ceremony.platform, stub, None)
            .expect("a session");
    debug!(
        out,
        session.seed_length(),
        session.mode(),
        session.platform()
    );
    for (kind, data) in events {
        session = match kind.as_str() {
            "hwrng" => session.add_hw_samples(&data).expect("healthy"),
            name => {
                session.add_extra(extra(name), &data);
                session
            }
        };
    }
    debug!(
        out,
        session.credited_bits(),
        session.required_bits(),
        session.hw_bytes_tested()
    );
    let committed = session.commit().expect("committed");
    debug!(out, committed.commitment());
    let mut rolling = committed.start_dice();
    for face in faces(ceremony.rolls) {
        rolling = rolling.push_roll(face).expect("a face");
    }
    debug!(
        out,
        rolling.rolls(),
        rolling.millibits(),
        rolling.minimum_rolls()
    );
    rolling.finish().expect("sealed")
}

/// The seed words that `text` holds as whole tokens and `control` does not.
fn leaked_words(words: &[String], text: &str, control: &str) -> Vec<String> {
    let (text, control) = (tokens(text), tokens(control));
    words
        .iter()
        .filter(|w| text.contains(w) && !control.contains(w))
        .cloned()
        .collect()
}

/// Maximal runs of ASCII letters, case-folded.
fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Consecutive seed words found as adjacent tokens, in order.
fn pairs_in_order(words: &[String], text: &str) -> Vec<String> {
    let tokens = tokens(text);
    let mut found = Vec::new();
    for pair in words.windows(2) {
        if tokens
            .windows(2)
            .any(|t| t[0] == pair[0] && t[1] == pair[1])
        {
            found.push(format!("{} {}", pair[0], pair[1]));
        }
    }
    found
}

/// The whole tokens of `debug` that are BIP39 words.
fn bip39_tokens(debug: &str) -> Vec<String> {
    let list = bip39::Language::English.word_list();
    tokens(debug)
        .into_iter()
        .filter(|t| list.contains(&t.as_str()))
        .collect()
}

fn clear_snapshot() -> VerifiedSnapshot {
    verify_snapshot(&hex(
        &named(&read("kcr.json")["snapshots"], "small")["kcr_hex"],
    ))
    .expect("valid")
}

/// For each ceremony, the first other one whose seed shares no word with it.
fn controls(transcripts: &[Transcript]) -> Vec<usize> {
    transcripts
        .iter()
        .enumerate()
        .map(|(i, t)| {
            (0..transcripts.len())
                .find(|&j| j != i && t.words.iter().all(|w| !transcripts[j].words.contains(w)))
                .expect("a control seed with no word in common")
        })
        .collect()
}

#[test]
fn no_seed_word_is_printed() {
    let clear = clear_snapshot();
    let transcripts: Vec<Transcript> = CEREMONIES.iter().map(|c| transcript(c, &clear)).collect();
    for (i, control) in controls(&transcripts).into_iter().enumerate() {
        let (seed, other) = (&transcripts[i], &transcripts[control]);
        let name = CEREMONIES[i].name;
        assert_eq!(seed.words.len() % 12, 0, "{name}");
        let leaked = leaked_words(&seed.words, &seed.text, &other.text);
        assert!(
            leaked.is_empty(),
            "{name}: {} seed words printed",
            leaked.len()
        );
        let pairs = pairs_in_order(&seed.words, &seed.text);
        assert!(
            pairs.is_empty(),
            "{name}: {} word pairs printed",
            pairs.len()
        );
    }
}

/// `Rejected` and `Wiped` print no BIP39 word as a whole token, for a retry, a collision and both
/// discards.
#[test]
fn rejected_and_wiped_print_no_bip39_token() {
    let kcr = read("kcr.json");
    let with_dice_50 =
        verify_snapshot(&hex(&named(&kcr["snapshots"], "with-dice-50")["kcr_hex"])).expect("valid");
    let other_bucket = verify_bucket_proof(&hex(
        &named(&kcr["proofs"], "clear-shared-prefix")["kcp1_hex"],
    ))
    .expect("valid");
    let checking = || {
        let stub = StubSource::new(StubEntropy::Fixed(vec![0; 8]), &WipeProbe::new());
        let mut rolling = Session::new_with_stub(
            SeedLength::Words12,
            Mode::DiceOnly,
            Platform::Phone,
            stub,
            None,
        )
        .and_then(Session::commit)
        .expect("committed")
        .start_dice();
        for face in faces("coldcard-50") {
            rolling = rolling.push_roll(face).expect("a face");
        }
        rolling
            .finish()
            .and_then(|sealed| sealed.start_check())
            .expect("checking")
    };
    let mut printed = Vec::new();
    for go in [
        GoAhead::Code("x"),
        GoAhead::Code("0000-0000"),
        GoAhead::BucketProof(&other_bucket),
        GoAhead::Snapshot(&with_dice_50),
    ] {
        match checking().reveal(go) {
            Err(rejected) => printed.push(format!("{rejected:?} {rejected:#?}")),
            Ok(_) => panic!("revealed"),
        }
    }
    for why in [Discard::Collision, Discard::CannotCheck] {
        let wiped = checking().discard(why);
        printed.push(format!("{wiped:?} {wiped:#?}"));
    }
    let all = printed.join("\n");
    assert!(all.contains("Rejected::Retry") && all.contains("Rejected::Collision"));
    assert!(all.contains("Wiped"));
    for line in &printed {
        assert_eq!(bip39_tokens(line), Vec::<String>::new(), "{line}");
    }
}

/// A shell bug that prints a mnemonic: what each check must catch.
struct Leaky<'a>(&'a SecretMnemonic);

impl Debug for Leaky<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.words().take(1)).finish()
    }
}

/// A planted leak is caught by each check: one word printed by a leaking formatter (check 1), two
/// consecutive words in order whose single words also appear for the control (check 2, which check
/// 1 alone would pass), and a hand-written `Debug` naming the session (check 3).
#[test]
fn a_planted_leak_is_caught_by_each_check() {
    let clear = clear_snapshot();
    let seed = transcript(&CEREMONIES[0], &clear);
    let control = transcript(&CEREMONIES[1], &clear);
    assert!(leaked_words(&seed.words, &seed.text, &control.text).is_empty());

    let stub = StubSource::new(StubEntropy::Fail, &WipeProbe::new());
    let mut rolling = Session::new_with_stub(
        SeedLength::Words12,
        Mode::DiceOnly,
        Platform::Phone,
        stub,
        None,
    )
    .and_then(Session::commit)
    .expect("committed")
    .start_dice();
    for face in faces(CEREMONIES[0].rolls) {
        rolling = rolling.push_roll(face).expect("a face");
    }
    let ready = rolling.finish().expect("sealed").skip_check();
    let planted = format!("{}{:?}", seed.text, Leaky(ready.mnemonic()));
    assert_eq!(
        leaked_words(&seed.words, &planted, &control.text),
        [seed.words[0].clone()],
        "check 1"
    );

    let (first, second) = (&seed.words[3], &seed.words[4]);
    let planted = format!("{}\n{first} {second}\n", seed.text);
    let planted_control = format!("{}\n{second} then {first}\n", control.text);
    assert!(leaked_words(&seed.words, &planted, &planted_control).is_empty());
    assert_eq!(
        pairs_in_order(&seed.words, &planted),
        [format!("{first} {second}")],
        "check 2"
    );

    assert_eq!(
        bip39_tokens("Rejected::Retry(Session<Checking>, WrongCode)"),
        ["session"],
        "check 3"
    );
    assert_eq!(bip39_tokens("Wiped { report: .. }"), ["report"], "check 3");
}

/// Check 1 compares whole tokens on both sides. Matched as substrings, a seed word that the control
/// prints only inside a longer token ("keep" inside "keepcrypt") was excused, so a lone leak of it
/// passed all three checks. Each such word of each ceremony, planted as a token of its own, must be
/// caught by check 1; a return to substring matching fails here (review fix after commit 25).
#[test]
fn a_seed_word_inside_a_longer_control_token_is_still_caught() {
    let clear = clear_snapshot();
    let transcripts: Vec<Transcript> = CEREMONIES.iter().map(|c| transcript(c, &clear)).collect();
    let mut planted = 0;
    for (i, control) in controls(&transcripts).into_iter().enumerate() {
        let (seed, other) = (&transcripts[i], &transcripts[control]);
        let (control_text, control_tokens) = (other.text.to_ascii_lowercase(), tokens(&other.text));
        let inside_longer = seed
            .words
            .iter()
            .filter(|w| control_text.contains(w.as_str()) && !control_tokens.contains(w));
        for word in inside_longer {
            let leaked = format!("{}\nleaked: {word}\n", seed.text);
            assert_eq!(
                leaked_words(&seed.words, &leaked, &other.text),
                std::slice::from_ref(word),
                "{}",
                CEREMONIES[i].name
            );
            planted += 1;
        }
    }
    assert!(
        planted > 0,
        "no seed word sits inside a longer control token"
    );
}
