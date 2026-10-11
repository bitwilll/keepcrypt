//! Verifier agreement, core's side (docs/build-plan.md M2 gate and test matrix "Verifier
//! agreement, 1,000 cases"; tasks/todo.md, M2 group 6; CLAUDE.md rules 5, 6, 10 and 12). Every
//! case of vectors/agreement.json, which tools/verify/vectorgen.py writes from verify.py's
//! `verification_run` and `render`, replayed through core's public session API on stub entropy.
//!
//! - Each stub (`StubEntropy::Fixed`) holds exactly the bytes core must read: 64 at `commit` in
//!   Mixed mode, then 8 at `start_check`. A missing, extra or reordered read changes n or fails
//!   closed. The hwrng chunks and extras are rebuilt from their counter-mode labels.
//! - Compared with the case's `expect`: C, D, the seed bits (the words' SeedBook numbers as 11-bit
//!   indices), the words, the seal before the words and again from `seal_from_mnemonic`, the
//!   registration (grouped code, register URL, Seal ID), n and the check URL, G accepted and the
//!   next-value wrong G refused as exactly `WrongCode` with the same URL, every insert line built
//!   from core's own accessors, and after a collision the first ceremony's report. The URLs are
//!   compared whole, so core's registry origin ties the verifier's. Every key of `expect` is
//!   compared, and compared once.
//! - The 28 refusals stop with the recorded error at the recorded step, and the verifier's verdict
//!   is the one core's refusal and the mode call for. The 98-roll restarts are the recorded known
//!   divergence (Q21): core refuses them, and the same inputs as a first ceremony give the words
//!   the verifier computed.
//! - One test per combination of length, mode and platform, plus one for the refusals, each
//!   asserting its case count: libtest runs them in parallel (every session start runs the full
//!   known-answer suite), and a truncated file fails.
//! - A failure names the case and the field, never a value (`assert!(got == want, ...)`, as
//!   tests/ceremony.rs does).

mod common;

use std::sync::OnceLock;

use common::{hex, named, read, text};
use keepcrypt_core::{
    CheckError, Collecting, Committed, CoreError, Discard, ExtraSource, GoAhead, Insert, Mode,
    Platform, ReadbackResult, Ready, Rejected, Rolling, Sealed, SeedLength, Session, StubEntropy,
    StubSource, WipeProbe, Wiped, seal_from_mnemonic,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Ceremonies per combination of seed length, mode and platform.
const CASES_PER_COMBINATION: usize = 125;
/// Refusal cases: 3 per combination, and 4 restarts with 98 rolls for 12 words.
const REFUSALS: usize = 28;

/// Where core refused: the error, the call, and for `push_roll` the 1-based roll.
type Refusal = (CoreError, &'static str, Option<usize>);

/// vectors/agreement.json, parsed once for every test.
fn doc() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| read("agreement.json"))
}

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

/// The number at `v`.
fn count(v: &Value) -> usize {
    usize::try_from(v.as_u64().expect("a count")).expect("fits")
}

/// The bytes of a `{label, length}` object: its label's first `length` counter-mode bytes.
fn labelled(v: &Value) -> Vec<u8> {
    stream(text(&v["label"]), count(&v["length"]))
}

/// The value of `r`, or a panic naming the case and the call.
fn must<T>(name: &str, call: &str, r: Result<T, CoreError>) -> T {
    match r {
        Ok(value) => value,
        Err(e) => panic!("{name}: {call}: {e:?}"),
    }
}

/// A case's `expect` object. Each key is taken once, and `done` fails on any key left untaken,
/// so every recorded value is compared, and compared once.
struct Expect<'a> {
    name: &'a str,
    left: Map<String, Value>,
}

impl<'a> Expect<'a> {
    fn new(name: &'a str, expect: &Value) -> Self {
        let left = expect.as_object().expect("an expect object").clone();
        Self { name, left }
    }

    /// The recorded value of `key`; taking it twice fails.
    fn take(&mut self, key: &str) -> Value {
        match self.left.remove(key) {
            Some(value) => value,
            None => panic!(
                "{}: {key} is not recorded, or was compared twice",
                self.name
            ),
        }
    }

    /// `key` is what core gave.
    fn same(&mut self, key: &str, got: Value) {
        let want = self.take(key);
        assert!(got == want, "{}: {key}", self.name);
    }

    /// `key`, lowercase hex or null, holds core's bytes, or core gave none.
    fn bytes(&mut self, key: &str, got: Option<&[u8]>) {
        let want = self.take(key);
        let want = if want.is_null() {
            None
        } else {
            Some(hex(&want))
        };
        assert!(got.map(<[u8]>::to_vec) == want, "{}: {key}", self.name);
    }

    /// Every key was compared.
    fn done(self) {
        let left: Vec<&String> = self.left.keys().collect();
        assert!(left.is_empty(), "{}: not compared: {left:?}", self.name);
    }
}

fn seed_length(case: &Value) -> SeedLength {
    match case["length"].as_u64() {
        Some(12) => SeedLength::Words12,
        Some(24) => SeedLength::Words24,
        _ => panic!("{}: length", text(&case["name"])),
    }
}

fn mode(case: &Value) -> Mode {
    match text(&case["mode"]) {
        "mixed" => Mode::Mixed,
        "dice_only" => Mode::DiceOnly,
        _ => panic!("{}: mode", text(&case["name"])),
    }
}

fn platform(case: &Value) -> Platform {
    match text(&case["platform"]) {
        "pi" => Platform::Pi,
        "phone" => Platform::Phone,
        _ => panic!("{}: platform", text(&case["name"])),
    }
}

fn extra_source(name: &str, source: &str) -> ExtraSource {
    match source {
        "input_timing" => ExtraSource::InputTiming,
        "motion" => ExtraSource::Motion,
        "camera" => ExtraSource::Camera,
        "microphone" => ExtraSource::Microphone,
        _ => panic!("{name}: extra source"),
    }
}

/// The stub of a `{label, length}` object.
fn stub(stub: &Value, probe: &WipeProbe) -> StubSource {
    StubSource::new(StubEntropy::Fixed(labelled(stub)), probe)
}

/// A first ceremony for `case`, on `inputs`' own stub.
fn new_session(name: &str, case: &Value, inputs: &Value, probe: &WipeProbe) -> Session<Collecting> {
    let session = Session::new_with_stub(
        seed_length(case),
        mode(case),
        platform(case),
        stub(&inputs["stub"], probe),
        None,
    );
    must(name, "new_with_stub", session)
}

/// `inputs`' events in order (hwrng chunks from its hwrng stream, and extras), then `commit`.
fn commit(name: &str, mut session: Session<Collecting>, inputs: &Value) -> Session<Committed> {
    let hwrng = match &inputs["hwrng"] {
        Value::Null => Vec::new(),
        v => labelled(v),
    };
    let mut at = 0;
    for event in inputs["events"].as_array().expect("events") {
        match text(&event["kind"]) {
            "hwrng" => {
                let end = at + count(&event["length"]);
                let Some(chunk) = hwrng.get(at..end) else {
                    panic!("{name}: hwrng events");
                };
                session = must(name, "add_hw_samples", session.add_hw_samples(chunk));
                at = end;
            }
            "extra" => {
                let source = extra_source(name, text(&event["source"]));
                session.add_extra(source, &labelled(event));
            }
            _ => panic!("{name}: event kind"),
        }
    }
    assert!(at == hwrng.len(), "{name}: hwrng events");
    must(name, "commit", session.commit())
}

/// `inputs`' rolls in push order, with its undo (a face pushed after the first `after` rolls and
/// taken back), then `finish`; or where core refused.
fn roll(
    name: &str,
    mut rolling: Session<Rolling>,
    inputs: &Value,
) -> Result<Session<Sealed>, Refusal> {
    let faces: Vec<u8> = text(&inputs["rolls"])
        .bytes()
        .map(|b| {
            assert!(b.is_ascii_digit(), "{name}: rolls");
            b - b'0'
        })
        .collect();
    let undo = match &inputs["undo"] {
        Value::Null => None,
        u => Some((
            count(&u["after"]),
            u8::try_from(count(&u["face"])).expect("a face"),
        )),
    };
    for at in 0..=faces.len() {
        if let Some((after, face)) = undo
            && after == at
        {
            rolling = rolling
                .push_roll(face)
                .map_err(|e| (e, "push_roll", None))?;
            rolling.undo_roll();
        }
        if let Some(&face) = faces.get(at) {
            rolling = rolling
                .push_roll(face)
                .map_err(|e| (e, "push_roll", Some(at + 1)))?;
        }
    }
    rolling.finish().map_err(|e| (e, "finish", None))
}

/// A sealed session, or a panic naming the case and the call that refused.
fn finished(name: &str, rolled: Result<Session<Sealed>, Refusal>) -> Session<Sealed> {
    match rolled {
        Ok(sealed) => sealed,
        Err((e, call, _)) => panic!("{name}: {call}: {e:?}"),
    }
}

/// A restart's first ceremony on its own stub, through `start_check`, then "Match found".
fn discarded(name: &str, case: &Value, probe: &WipeProbe) -> Wiped {
    let first = &case["first"];
    let session = commit(name, new_session(name, case, first, probe), first);
    let sealed = finished(name, roll(name, session.start_dice(), first));
    must(name, "first start_check", sealed.start_check()).discard(Discard::Collision)
}

/// The case's session: a first ceremony, or the restart after its first ceremony's collision.
fn started(
    name: &str,
    case: &Value,
    wiped: Option<Wiped>,
    probe: &WipeProbe,
) -> Session<Collecting> {
    match wiped {
        None => new_session(name, case, case, probe),
        Some(wiped) => {
            let restart = wiped.restart_with_stub(
                seed_length(case),
                mode(case),
                stub(&case["stub"], probe),
                None,
            );
            must(name, "restart_with_stub", restart)
        }
    }
}

/// The seed bits the words carry: each word's BIP39 index (its SeedBook number - 1) as 11 bits,
/// most significant first, without the checksum (the last words / 3 bits).
fn seed_bits(seedbook_numbers: &[u16]) -> Vec<u8> {
    let bits: Vec<bool> = seedbook_numbers
        .iter()
        .flat_map(|&number| (0..11).rev().map(move |bit| ((number - 1) >> bit) & 1 == 1))
        .collect();
    bits[..seedbook_numbers.len() * 32 / 3]
        .chunks(8)
        .map(|byte| {
            byte.iter()
                .fold(0u8, |acc, &bit| (acc << 1) | u8::from(bit))
        })
        .collect()
}

/// An insert in the verifier's insert-line grammar, every token from core's accessors: position,
/// device and device count, sequence, SeedBook number and word | faces 1-5, each its cell then its
/// letter (`--` when blank), then `/` and the mirror partner, then `~` when drawn lighter | the
/// word's cells. A face's dots are its cell's code point minus U+2800.
fn insert_line(name: &str, insert: &Insert<'_>) -> String {
    let faces: Vec<String> = insert
        .faces()
        .iter()
        .map(|face| {
            let mut token = match (face.cell(), face.letter()) {
                (Some(cell), Some(letter)) if !face.is_blank() => {
                    assert!(
                        face.dots().map(|dots| u32::from(dots.bits()))
                            == u32::from(cell).checked_sub(0x2800),
                        "{name}: inserts dots"
                    );
                    format!("{cell}{letter}")
                }
                (None, None) if face.is_blank() && face.dots().is_none() => "--".to_owned(),
                _ => panic!("{name}: inserts face"),
            };
            if let Some(partner) = face.mirror_partner() {
                token.push('/');
                token.push(partner);
            }
            if face.is_lighter() {
                token.push('~');
            }
            token
        })
        .collect();
    format!(
        "{:02} device {}/{} seq {:02} seedbook {:04} {} | {} | {}",
        insert.position(),
        insert.device(),
        insert.device_count(),
        insert.sequence(),
        insert.seedbook_number(),
        insert.word(),
        faces.join(" "),
        insert.word_cells().collect::<String>()
    )
}

/// The words, insert lines, SeedBook numbers and first four letters of a ready session.
fn words_and_inserts(
    name: &str,
    ready: &Session<Ready>,
) -> (Vec<String>, Vec<String>, Vec<u16>, Vec<String>) {
    let words = ready.mnemonic().words().map(str::to_owned).collect();
    let braille = ready.braille();
    let lines = braille.iter().map(|i| insert_line(name, &i)).collect();
    let numbers = braille.iter().map(|i| i.seedbook_number()).collect();
    let letters = braille
        .iter()
        .map(|i| i.word().chars().take(4).collect())
        .collect();
    (words, lines, numbers, letters)
}

/// One ceremony from its stub to `Ready` and the exports, every `expect` key compared.
fn ceremony(case: &Value) {
    let name = text(&case["name"]);
    let mut expect = Expect::new(name, &case["expect"]);
    let probe = WipeProbe::new();
    let wiped = if case["first"].is_null() {
        expect.same("collision", Value::Null);
        None
    } else {
        let wiped = discarded(name, case, &probe);
        let Some(report) = wiped.collision_report() else {
            panic!("{name}: collision");
        };
        let got =
            serde_json::json!({"seal_code": report.grouped_code(), "register_url": report.url()});
        expect.same("collision", got);
        Some(wiped)
    };

    let committed = commit(name, started(name, case, wiped, &probe), case);
    expect.bytes("c_hex", committed.commitment().as_ref().map(|c| &c[..]));
    let sealed = finished(name, roll(name, committed.start_dice(), case));

    let seal = sealed.seal().clone();
    expect.bytes("seal_tag_hex", Some(seal.tag().as_bytes()));
    let seal_id = expect.take("seal_id");
    assert!(seal_id == seal.seal_id(), "{name}: seal_id");
    expect.same("seal_id_braille", Value::from(seal.seal_id_braille()));
    expect.same("lookup_prefix", Value::from(seal.lookup_prefix()));
    expect.same("bucket", Value::from(seal.bucket()));
    let grid: Vec<String> = seal
        .grid()
        .iter()
        .map(|row| {
            row.iter()
                .map(|&filled| if filled { '#' } else { '.' })
                .collect()
        })
        .collect();
    expect.same("grid", Value::from(grid));
    expect.same("colour_index", Value::from(seal.colour_index()));
    expect.same("colour_hex", Value::from(seal.colour_hex()));
    expect.same("recheck_url", Value::from(seal.recheck_url()));

    let mut ready = match text(&case["path"]) {
        "skip" => {
            assert!(case["wrong_go_ahead"].is_null(), "{name}: wrong_go_ahead");
            for key in ["nonce_hex", "check_url", "go_ahead"] {
                expect.same(key, Value::Null);
            }
            sealed.skip_check()
        }
        "check" => {
            let checking = must(name, "start_check", sealed.start_check());
            let url = checking.check_request().url().to_owned();
            expect.same("check_url", Value::from(url.as_str()));
            expect.same(
                "nonce_hex",
                Value::from(url.rsplit_once("&n=").map(|(_, n)| n)),
            );
            let checking = match &case["wrong_go_ahead"] {
                Value::Null => checking,
                wrong => match checking.reveal(GoAhead::Code(text(wrong))) {
                    Err(Rejected::Retry(checking, CheckError::WrongCode)) => {
                        assert!(
                            checking.check_request().url() == url,
                            "{name}: check_url after the wrong code"
                        );
                        checking
                    }
                    _ => panic!("{name}: wrong_go_ahead"),
                },
            };
            match checking.reveal(GoAhead::Code(text(&expect.take("go_ahead")))) {
                Ok(ready) => ready,
                Err(_) => panic!("{name}: go_ahead"),
            }
        }
        _ => panic!("{name}: path"),
    };

    let (words, lines, numbers, letters) = words_and_inserts(name, &ready);
    expect.same("words", Value::from(words));
    let want = expect.take("inserts");
    let want = want.as_array().expect("insert lines");
    assert!(want.len() == lines.len(), "{name}: inserts");
    for (n, (want, got)) in want.iter().zip(&lines).enumerate() {
        assert!(
            want.as_str() == Some(got.as_str()),
            "{name}: inserts line {}",
            n + 1
        );
    }
    expect.bytes("entropy_hex", Some(&seed_bits(&numbers)));
    let from_words = must(
        name,
        "seal_from_mnemonic",
        seal_from_mnemonic(ready.mnemonic()),
    );
    assert!(from_words == seal, "{name}: seal_from_mnemonic");

    for (position, letters) in (1u8..).zip(&letters) {
        assert!(
            matches!(
                ready.check_readback(position, letters),
                Ok(ReadbackResult::Match)
            ),
            "{name}: read-back of word {position}"
        );
    }
    let (ready, registration) = must(name, "registration", ready.registration());
    expect.same("seal_code", Value::from(registration.grouped_code()));
    expect.same("register_url", Value::from(registration.url()));
    assert!(
        seal_id == registration.seal_id(),
        "{name}: seal_id of the registration"
    );
    let d = must(name, "reveal_device_leg", ready.reveal_device_leg()).1;
    expect.bytes("d_hex", d.as_ref().map(|d| &d.expose_secret()[..]));
    expect.done();
}

/// Every ceremony of one combination: the names `<length>-<mode>-<platform>-000` to `-124`, each
/// recorded once, and no other.
fn combination(length: u64, mode: &str, platform: &str) {
    let ceremonies = &doc()["ceremonies"];
    let prefix = format!("{length}-{mode}-{platform}-");
    let recorded = ceremonies
        .as_array()
        .expect("ceremonies")
        .iter()
        .filter(|case| text(&case["name"]).starts_with(&prefix))
        .count();
    assert_eq!(recorded, CASES_PER_COMBINATION, "{prefix}: the case count");
    for n in 0..CASES_PER_COMBINATION {
        let case = named(ceremonies, &format!("{prefix}{n:03}"));
        assert!(
            case["length"] == length && case["mode"] == mode && case["platform"] == platform,
            "{}: combination",
            text(&case["name"])
        );
        ceremony(case);
    }
}

/// One refusal: core stops with the recorded error at the recorded step, and the verifier's verdict
/// is the one core's refusal and the mode call for.
fn refusal(case: &Value) {
    let name = text(&case["name"]);
    let mut expect = Expect::new(name, &case["expect"]);
    let probe = WipeProbe::new();
    let restart = !case["first"].is_null();
    let wiped = restart.then(|| discarded(name, case, &probe));
    let committed = commit(name, started(name, case, wiped, &probe), case);
    let Err((error, step, at)) = roll(name, committed.start_dice(), case) else {
        panic!("{name}: core accepted the rolls");
    };
    expect.same("error", Value::from(format!("{error:?}")));
    expect.same("step", Value::from(step));
    expect.same("roll", Value::from(at));
    expect.done();

    let verifier = &case["verifier"];
    let too_few_or_many = matches!(error, CoreError::TooFewRolls | CoreError::TooManyRolls);
    match text(&verifier["verdict"]) {
        "input-refused" => assert!(
            error == CoreError::InvalidRoll
                && verifier["field"] == "rolls"
                && verifier["position"]
                    .as_u64()
                    .map(|p| usize::try_from(p).expect("fits"))
                    == at,
            "{name}: verdict"
        ),
        "refused" => assert!(
            too_few_or_many && !restart && mode(case) == Mode::Mixed,
            "{name}: verdict"
        ),
        "warned" => assert!(
            too_few_or_many && !restart && mode(case) == Mode::DiceOnly,
            "{name}: verdict"
        ),
        "diverges" => {
            assert!(
                error == CoreError::TooFewRolls && restart,
                "{name}: verdict"
            );
            // The known divergence: the same inputs as a first ceremony give the verifier's words.
            let committed = commit(name, new_session(name, case, case, &probe), case);
            let ready = finished(name, roll(name, committed.start_dice(), case)).skip_check();
            let (words, _, numbers, _) = words_and_inserts(name, &ready);
            assert!(
                Value::from(words) == verifier["words"],
                "{name}: the verifier's words"
            );
            assert!(
                hex(&verifier["entropy_hex"]) == seed_bits(&numbers),
                "{name}: the verifier's seed bits"
            );
        }
        _ => panic!("{name}: verdict"),
    }
}

#[test]
fn words12_mixed_pi() {
    combination(12, "mixed", "pi");
}

#[test]
fn words12_mixed_phone() {
    combination(12, "mixed", "phone");
}

#[test]
fn words12_dice_only_pi() {
    combination(12, "dice_only", "pi");
}

#[test]
fn words12_dice_only_phone() {
    combination(12, "dice_only", "phone");
}

#[test]
fn words24_mixed_pi() {
    combination(24, "mixed", "pi");
}

#[test]
fn words24_mixed_phone() {
    combination(24, "mixed", "phone");
}

#[test]
fn words24_dice_only_pi() {
    combination(24, "dice_only", "pi");
}

#[test]
fn words24_dice_only_phone() {
    combination(24, "dice_only", "phone");
}

#[test]
fn refusals() {
    let refusals = doc()["refusals"].as_array().expect("refusals");
    assert_eq!(refusals.len(), REFUSALS, "the refusal count");
    for case in refusals {
        refusal(case);
    }
}
