//! The scenario driver and the mock checker (tasks/todo.md, M3 group 8, "Scenario driver", "Mock
//! checker"; Q30): scripted runs of the real app on `SimHal`, every present checked on the way.
//!
//! - A scenario is a name, the hwrng stream and its steps, built per configuration (`Config`).
//! - `Expect(id)` is matched in order against the presents since the last match, so transient
//!   screens are matched too. An unmet `Expect` fails the scenario and names its step.
//! - A key is pressed only while its `Expect` screen is showing and waits for input. Each press
//!   reaches the app through `SimHal`'s script, as a bounce train through pi/app's debouncer.
//! - On the first input-waiting showing of each screen in a scenario, every key its model does
//!   not offer is pressed once first, and none may present anything (the dead-key probe). Ticks
//!   between those presses may redraw.
//! - On every present with a QR code, the drawn modules equal a fresh drawing of the model's
//!   payload (`qr_drawn`). The mock checker takes T and n from the last check QR so checked and
//!   computes the go-ahead code G from them, as the registry page would (Q30 (d)).
//! - The entry grids are typed as a user would: the cursor read off the drawn grid, then the
//!   shortest wrapping path to each symbol (`Layout`, Q32 (a)'s layouts, stated here again). The
//!   presents a typing step makes are its own; only the result of its last key is left for the
//!   next `Expect`.
//! - The driver records what the screens showed (`Record`): each insert's word, the backup
//!   passphrase's words and every screen's last texts, for the read-back, the confirm and the
//!   assertions. All of it is public test data or a vector run's; none of it is printed.
//! - Secrets stay on Protected elements (rule 5). On a Protected screen, every word, braille, QR
//!   and hex element is the secret it shows, so it must be Protected. And no Public element of any
//!   present in a run may show a secret a Protected element showed in that run, before or after it
//!   (`Texts`): the Protected text, one of its words of three letters or more, or a line of a QR
//!   payload or of hex. A Public text may not equal one, nor contain one longer than any list
//!   word; a shorter one is matched only whole, since the screen copy is made of list words too,
//!   and a random seed's words would turn up inside it by chance.
//! - On request a run keeps each present's frame digest (`Keep::Digests`, for `drill_12_repeats`)
//!   or writes it as a PNG file (`Keep::Captures`, for `capture_set`), numbered on across power
//!   cycles, Protected frames as the scenario says (`Scenario::protected`).
//! - Nothing here prints screen text: `report` gets the scenario's name and counts.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

use keepcrypt_core::registry_key_is_test;
use keepcrypt_pi::App;
use keepcrypt_pi::hal::{Display, HalError, Zeroizing};
use keepcrypt_pi::input::Key;
use keepcrypt_pi::screen::{
    Banners, Class, Element, Item, KeyMap, Kind, QR_SIDE, STRIP_HEIGHT, Screen, ScreenId,
};
use keepcrypt_pi::ui::{Frame, Painter, SIDE};
use keepcrypt_pi_sim::{Fault, HwRngStream, Pixels, Present, ProtectedFrames, Shown, SimHal};
use sha2::{Digest, Sha256};

use crate::report::report;

const S: u64 = 1_000_000_000;
/// The go-ahead code's domain tag (CLAUDE.md "Go-ahead code").
const GO_DOMAIN: &[u8] = b"KCE/v1/go";
/// Crockford base32, the go-ahead code's alphabet and the entry grid's order: 8 columns, 4 rows.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The longest BIP39 word: a secret longer than this is looked for inside every Public text.
const LONGEST_WORD: usize = 8;

/// An entry grid as Q32 (a) lays it out: its symbols row by row and its columns. The cursor wraps
/// within its row and its column; a cell past the last symbol is empty.
#[derive(Clone, Copy)]
struct Layout {
    symbols: &'static [u8],
    columns: usize,
}

impl Layout {
    /// The grid of an entry screen.
    fn of(id: ScreenId) -> Layout {
        match id {
            ScreenId::CodeEntry => Layout {
                symbols: CROCKFORD,
                columns: 8,
            },
            ScreenId::ReadbackEntry | ScreenId::BackupCheckEntry => Layout {
                symbols: b"abcdefghijklmnopqrstuvwxyz_",
                columns: 7,
            },
            ScreenId::Bip39Entry => Layout {
                symbols: b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
                columns: 8,
            },
            other => panic!("{} has no entry grid", other.name()),
        }
    }

    fn rows(self) -> usize {
        self.symbols.len().div_ceil(self.columns)
    }

    /// The cell of the symbol drawn in brackets: `·` is the ASCII grid's space, a blank the empty
    /// cell after the last symbol.
    fn cell(self, drawn: char) -> usize {
        let symbol = match drawn {
            '·' => b' ',
            ' ' => return self.symbols.len(),
            other => u8::try_from(other).expect("an ASCII symbol"),
        };
        self.symbols
            .iter()
            .position(|&s| s == symbol)
            .expect("a symbol of this grid")
    }

    /// The presses from `from` to `to`: the shorter way round in each direction.
    fn path(self, from: usize, to: usize) -> Vec<Key> {
        let mut keys = Vec::new();
        let mut leg = |from: usize, to: usize, n: usize, forward: Key, back: Key| {
            let ahead = (to + n - from) % n;
            if ahead <= n / 2 {
                keys.extend(std::iter::repeat_n(forward, ahead));
            } else {
                keys.extend(std::iter::repeat_n(back, n - ahead));
            }
        };
        let columns = self.columns;
        leg(from % columns, to % columns, columns, Key::Right, Key::Left);
        leg(
            from / columns,
            to / columns,
            self.rows(),
            Key::Down,
            Key::Up,
        );
        keys
    }
}

/// The build under test: the release configuration, or the test registry key
/// (`cargo test -p keepcrypt-pi-sim --features keepcrypt-core/test-registry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Config {
    Release,
    Registry,
}

impl Config {
    pub fn of_this_build() -> Self {
        if registry_key_is_test() {
            Config::Registry
        } else {
            Config::Release
        }
    }

    /// The configuration's name, as the capture folder takes it.
    pub fn name(self) -> &'static str {
        match self {
            Config::Release => "release",
            Config::Registry => "registry",
        }
    }
}

/// What an assertion sees: the present the last `Expect` matched, the latest present, the app,
/// and what the run's screens showed.
pub struct Seen<'r> {
    pub matched: &'r Present,
    pub latest: &'r Present,
    pub app: &'r App<SimHal>,
    pub record: &'r Record,
}

/// What the screens of a run showed, as the driver read it from their models.
#[derive(Default)]
pub struct Record {
    /// Each insert's word, by position, from the insert view's header and word.
    pub words: BTreeMap<u8, Zeroizing<String>>,
    /// The backup passphrase's words, by number, from its pages.
    pub passphrase: BTreeMap<u8, Zeroizing<String>>,
    /// Every screen id presented in the run, power cycles included, in first-seen order.
    pub screens: Vec<ScreenId>,
    /// The texts of each screen's last present, by id.
    texts: Vec<(ScreenId, Vec<Zeroizing<String>>)>,
}

impl Record {
    /// The texts of the last present of `id`.
    pub fn texts_of(&self, id: ScreenId) -> &[Zeroizing<String>] {
        match self.texts.iter().find(|(seen, _)| *seen == id) {
            Some((_, texts)) => texts,
            None => panic!("{} was not presented", id.name()),
        }
    }

    /// The words of the inserts shown, in order.
    pub fn words(&self) -> Vec<&str> {
        self.words.values().map(|word| word.as_str()).collect()
    }

    /// The backup passphrase's words shown, in order.
    pub fn passphrase(&self) -> Vec<&str> {
        self.passphrase.values().map(|word| word.as_str()).collect()
    }

    fn note(&mut self, present: &Present) {
        if !self.screens.contains(&present.id) {
            self.screens.push(present.id);
        }
        let texts: Vec<Zeroizing<String>> = present
            .elements
            .iter()
            .filter_map(|element| element.item.text())
            .map(|text| Zeroizing::new(text.to_owned()))
            .collect();
        match present.id {
            ScreenId::WordsInsert => {
                let position = texts
                    .first()
                    .and_then(|header| number_after(header, "Insert "))
                    .expect("an insert's header");
                let word = present
                    .elements
                    .iter()
                    .find_map(|element| match &element.item {
                        Shown::Large { text, .. } => Some(text.clone()),
                        _ => None,
                    });
                self.words.insert(position, word.expect("an insert's word"));
            }
            ScreenId::BackupPassphrase => {
                for element in &present.elements {
                    if let (Class::Protected, Shown::Text(lines)) = (element.class, &element.item) {
                        for line in lines.split('\n') {
                            let (number, word) = line.split_once(' ').expect("N word");
                            self.passphrase.insert(
                                number.parse().expect("a word number"),
                                Zeroizing::new(word.to_owned()),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
        match self.texts.iter_mut().find(|(seen, _)| *seen == present.id) {
            Some((_, last)) => *last = texts,
            None => self.texts.push((present.id, texts)),
        }
    }
}

/// The two-digit number after `prefix` at the start of `text`.
fn number_after(text: &str, prefix: &str) -> Option<u8> {
    text.strip_prefix(prefix)?.get(..2)?.parse().ok()
}

/// One text and the screen that first showed it.
type FirstShown = (Zeroizing<String>, ScreenId);

/// The texts the elements of a run showed, for the secrets check: every Public text, and every
/// secret a Protected text holds (`secrets_in`), each once, sorted.
#[derive(Default)]
struct Texts {
    public: Vec<FirstShown>,
    secret: Vec<FirstShown>,
}

impl Texts {
    /// Takes in the texts of `present`, and returns the first secret shown in public, as the ids of
    /// the screen with the Public element and of the screen with the Protected one.
    fn add(&mut self, present: &Present) -> Option<(ScreenId, ScreenId)> {
        let mut leak = None;
        for element in &present.elements {
            let Some(text) = element.item.text() else {
                continue;
            };
            match element.class {
                Class::Public => {
                    if first_time(&mut self.public, text, present.id) && leak.is_none() {
                        leak = self
                            .secret
                            .iter()
                            .find(|(secret, _)| shows_secret(text, secret))
                            .map(|(_, on)| (present.id, *on));
                    }
                }
                Class::Protected => {
                    for secret in secrets_in(&element.item, text) {
                        if first_time(&mut self.secret, secret, present.id) && leak.is_none() {
                            leak = self
                                .public
                                .iter()
                                .find(|(public, _)| shows_secret(public, secret))
                                .map(|(_, on)| (*on, present.id));
                        }
                    }
                }
            }
        }
        leak
    }
}

/// Adds `text`, first shown on `id`, to the sorted `texts`; false when it is there already.
fn first_time(texts: &mut Vec<FirstShown>, text: &str, id: ScreenId) -> bool {
    match texts.binary_search_by(|(seen, _)| seen.as_str().cmp(text)) {
        Ok(_) => false,
        Err(at) => {
            texts.insert(at, (Zeroizing::new(text.to_owned()), id));
            true
        }
    }
}

/// The secrets a Protected element's `text` holds: the text, each of its runs of three ASCII
/// letters or more (an insert's word, a backup passphrase word, typed faces), and each line of a
/// QR payload or of hex (a descriptor, a row of D). The lines of an entry grid are no secret.
fn secrets_in<'t>(item: &Shown, text: &'t str) -> Vec<&'t str> {
    let mut secrets = vec![text];
    if let Shown::Qr(_) | Shown::Hex(_) = item {
        secrets.extend(text.split('\n'));
    }
    secrets.extend(
        text.split(|c: char| !c.is_ascii_alphabetic())
            .filter(|word| word.len() >= 3),
    );
    secrets.retain(|secret| !secret.trim().is_empty());
    secrets
}

/// True when the Public text `public` shows `secret`: it is the secret, or it contains a secret
/// longer than any list word.
fn shows_secret(public: &str, secret: &str) -> bool {
    public == secret || (secret.chars().count() > LONGEST_WORD && public.contains(secret))
}

/// What the stick does.
pub enum Stick {
    /// These files are put on it (names as given), and it is inserted.
    Insert(Vec<(String, Vec<u8>)>),
}

/// Which faces to read back on readback-entry.
pub enum Readback {
    /// The first four letters (or the whole three-letter word) of the insert being read back,
    /// as its insert view showed it.
    FromScreen,
    /// These faces, `_` a blank fourth face.
    Faces(&'static str),
}

/// Which choice to pick on backup-confirm.
pub enum Answer {
    /// The word the passphrase's pages showed at the asked position.
    Right,
    /// The first other choice.
    Wrong,
}

/// An assertion over what was seen. Its message is fixed: it never quotes screen text.
pub type Check = Box<dyn Fn(&Seen<'_>) -> bool>;

/// Which go-ahead code to type.
pub enum Code {
    /// The mock checker's G for the last check QR.
    FromCheck,
    /// That G with its last symbol changed: a well-formed code that does not match.
    Wrong,
}

/// One step of a scenario.
pub enum Step {
    /// The next present of this screen, in order.
    Expect(ScreenId),
    /// A press of a key the screen offers.
    Key(Key),
    /// A press of a key the screen does not offer: nothing may be presented.
    Dead(Key),
    /// A roll string on the dice screen: per face, Up that many times from the blank picker,
    /// then Press.
    Dice(String),
    /// Seconds with no key.
    Wait(u64),
    /// A fault armed for the next call it applies to.
    Fault(Fault),
    /// A go-ahead code typed on the grid, then Done.
    Code(Code),
    /// Text typed on the entry grid shown, without Done.
    Type(String),
    /// Faces read back on readback-entry, then Done.
    Readback(Readback),
    /// A pick on backup-confirm.
    Pick(Answer),
    /// Something done to the stick.
    Stick(Stick),
    /// An assertion, with its fixed message.
    Assert(&'static str, Check),
    /// A power cycle: a new app on new hardware with this hwrng stream, booted.
    PowerCycle(HwRngStream),
}

/// A scripted run.
pub struct Scenario {
    pub name: &'static str,
    pub hwrng: HwRngStream,
    /// How a capture writes the run's Protected frames (Q30 (g)): as drawn for a vector run,
    /// whose words come from public roll strings or files, and as the placeholder otherwise.
    pub protected: ProtectedFrames,
    pub steps: Vec<Step>,
}

/// What a run keeps of each present beyond its checks.
pub enum Keep {
    Nothing,
    /// The SHA-256 of each frame.
    Digests,
    /// Each present as a PNG file in this folder, and the SHA-256 of the file.
    Captures(PathBuf),
}

/// One present as a run keeps it (`Keep`): the step it came in (0 for the first boot, before any
/// step), its screen, and the SHA-256 of its frame, or of its PNG file with the file's name and
/// whether it holds the placeholder. No screen text.
#[derive(Debug, PartialEq, Eq)]
pub struct Shot {
    pub step: usize,
    pub id: ScreenId,
    pub sha256: [u8; 32],
    pub file: Option<(String, bool)>,
}

/// What a scenario did, for the count line, and the presents kept.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub steps: usize,
    pub presents: usize,
    pub screens: Vec<ScreenId>,
    pub dead_keys: usize,
    pub shots: Vec<Shot>,
}

/// Runs `scenario` to its end and prints its count line.
pub fn run(scenario: Scenario) -> Counts {
    run_keeping(scenario, Keep::Nothing)
}

/// Runs `scenario` to its end, keeping what `keep` says of each present, and prints its count
/// line.
pub fn run_keeping(scenario: Scenario, keep: Keep) -> Counts {
    let mut run = Run::new(scenario.hwrng, keep, scenario.protected);
    for step in scenario.steps {
        run.counts.steps += 1;
        run.step(step);
    }
    assert_eq!(
        run.app.hal().queued(),
        0,
        "the script was played to its end"
    );
    let counts = run.counts;
    report(format_args!(
        "{}: {} steps, {} screens, {} presents, {} dead keys",
        scenario.name,
        counts.steps,
        counts.screens.len(),
        counts.presents,
        counts.dead_keys
    ));
    counts
}

/// A run in progress.
struct Run {
    app: App<SimHal>,
    keep: Keep,
    protected: ProtectedFrames,
    /// Presents not yet matched by an `Expect`, oldest first.
    unmatched: VecDeque<Present>,
    /// The present the last `Expect` matched.
    matched: Option<Present>,
    expected: Option<ScreenId>,
    /// The screens whose dead keys were probed.
    probed: Vec<ScreenId>,
    /// The payload of the last check QR presented.
    check_url: Option<Zeroizing<String>>,
    /// The keys the latest present offered.
    latest_keys: KeyMap,
    record: Record,
    texts: Texts,
    counts: Counts,
}

impl Run {
    fn new(hwrng: HwRngStream, keep: Keep, protected: ProtectedFrames) -> Self {
        let hal = hardware(hwrng, &keep, protected, 0);
        let mut run = Run {
            app: App::new(hal),
            keep,
            protected,
            unmatched: VecDeque::new(),
            matched: None,
            expected: None,
            probed: Vec::new(),
            check_url: None,
            latest_keys: KeyMap::NONE,
            record: Record::default(),
            texts: Texts::default(),
            counts: Counts::default(),
        };
        run.app.start();
        run.collect();
        run
    }

    fn step(&mut self, step: Step) {
        match step {
            Step::Expect(id) => self.expect(id),
            Step::Key(key) => self.press(key),
            Step::Dead(key) => {
                self.refuse_unless_showing(key);
                self.dead(key);
            }
            Step::Dice(rolls) => {
                for face in rolls.bytes() {
                    for _ in b'0'..face {
                        self.press(Key::Up);
                    }
                    self.press(Key::Press);
                }
            }
            Step::Wait(seconds) => {
                self.app.hal_mut().wait_ns(seconds * S);
                self.play();
            }
            Step::Fault(fault) => self.app.hal_mut().fault(fault),
            Step::Code(code) => self.code(code),
            Step::Type(text) => self.type_text(&text),
            Step::Readback(readback) => self.read_back(readback),
            Step::Pick(answer) => self.pick(answer),
            Step::Stick(Stick::Insert(files)) => {
                let hal = self.app.hal_mut();
                for (name, bytes) in files {
                    hal.put_file(&name, bytes);
                }
                hal.insert_stick();
            }
            Step::Assert(what, check) => {
                let (Some(matched), Some(latest)) = (self.matched.as_ref(), self.latest()) else {
                    panic!("step {}: nothing to assert on", self.counts.steps);
                };
                let seen = Seen {
                    matched,
                    latest,
                    app: &self.app,
                    record: &self.record,
                };
                assert!(check(&seen), "step {}: {what}", self.counts.steps);
            }
            Step::PowerCycle(hwrng) => {
                self.collect();
                let hal = hardware(hwrng, &self.keep, self.protected, self.counts.shots.len());
                self.app = App::new(hal);
                self.expected = None;
                self.app.start();
                self.collect();
            }
        }
    }

    /// The latest present: the newest unmatched one, else the one the last `Expect` matched.
    fn latest(&self) -> Option<&Present> {
        match self.unmatched.back() {
            Some(present) => Some(present),
            None => self.matched.as_ref(),
        }
    }

    /// Takes the presents since the last call and checks each.
    fn collect(&mut self) {
        let presents = self.app.hal_mut().take_presents();
        self.absorb(presents);
    }

    fn absorb(&mut self, presents: Vec<Present>) {
        for present in presents {
            self.counts.presents += 1;
            if !self.counts.screens.contains(&present.id) {
                self.counts.screens.push(present.id);
            }
            for element in &present.elements {
                if let Shown::Qr(payload) = &element.item {
                    assert!(
                        qr_drawn(present.frame.raw(), element.at, payload),
                        "step {}: the QR on {} is not its payload's",
                        self.counts.steps,
                        present.id.name()
                    );
                    if present.id == ScreenId::SealQr {
                        self.check_url = Some(payload.clone());
                    }
                }
            }
            if present.id.class() == Class::Protected {
                for element in &present.elements {
                    let secret = matches!(
                        element.item,
                        Shown::Large { .. } | Shown::Cells(_) | Shown::Qr(_) | Shown::Hex(_)
                    );
                    assert!(
                        !secret || element.class == Class::Protected,
                        "step {}: a word, braille, QR or hex element on {} is not Protected",
                        self.counts.steps,
                        present.id.name()
                    );
                }
            }
            if let Some((public, protected)) = self.texts.add(&present) {
                panic!(
                    "step {}: a Public element on {} shows a secret a Protected element showed on {}",
                    self.counts.steps,
                    public.name(),
                    protected.name()
                );
            }
            self.keep_present(&present);
            self.record.note(&present);
            self.latest_keys = present.keys;
            self.unmatched.push_back(present);
        }
    }

    /// Keeps what `self.keep` says of `present`.
    fn keep_present(&mut self, present: &Present) {
        let (sha256, file) = match (&self.keep, &present.capture) {
            (Keep::Nothing, _) => return,
            (Keep::Digests, _) => (frame_sha256(&present.frame), None),
            (Keep::Captures(_), Some(captured)) => (
                Sha256::digest(&captured.png[..]).into(),
                Some((captured.file.clone(), captured.placeholder)),
            ),
            (Keep::Captures(_), None) => panic!(
                "step {}: a present of {} was not captured",
                self.counts.steps,
                present.id.name()
            ),
        };
        self.counts.shots.push(Shot {
            step: self.counts.steps,
            id: present.id,
            sha256,
            file,
        });
    }

    /// Steps the app until the script is played to its end.
    fn play(&mut self) {
        while self.app.hal().queued() > 0 {
            self.app.step();
            self.collect();
        }
    }

    fn expect(&mut self, id: ScreenId) {
        let Some(index) = self.unmatched.iter().position(|present| present.id == id) else {
            let shown: Vec<&str> = self.unmatched.iter().map(|p| p.id.name()).collect();
            panic!(
                "step {}: expected {}, presented since the last match: {shown:?}",
                self.counts.steps,
                id.name()
            );
        };
        self.matched = self.unmatched.drain(..=index).next_back();
        self.expected = Some(id);
        self.probe(id);
    }

    /// The dead-key probe on the first input-waiting showing of `id`.
    fn probe(&mut self, id: ScreenId) {
        if id.kind() != Kind::InputWaiting || self.probed.contains(&id) {
            return;
        }
        let offered = |keys: KeyMap| Key::ALL.into_iter().all(|key| keys.label(key).is_some());
        if self.matched.as_ref().is_some_and(|p| offered(p.keys)) {
            // Every key is live here (the cover, the warning): nothing to probe.
            self.probed.push(id);
            return;
        }
        if self.app.hal().showing() != Some(id) {
            // A timer moved on from it: a later showing is probed.
            return;
        }
        self.probed.push(id);
        for key in Key::ALL {
            if self.latest_keys.label(key).is_none() {
                self.dead(key);
            }
        }
    }

    /// Presses `key`, which the shown model does not offer, and checks that the step that took it
    /// presented nothing. Ticks before it may present.
    fn dead(&mut self, key: Key) {
        assert!(
            self.latest_keys.label(key).is_none(),
            "step {}: {key:?} is offered here",
            self.counts.steps
        );
        self.app.hal_mut().press(key);
        loop {
            let before = self.app.hal().queued();
            self.app.step();
            let presents = self.app.hal_mut().take_presents();
            if self.app.hal().queued() < before {
                assert_dead(self.counts.steps, key, &presents);
                break;
            }
            self.absorb(presents);
        }
        self.counts.dead_keys += 1;
    }

    fn refuse_unless_showing(&self, key: Key) {
        let showing = self.app.hal().showing();
        let waiting = showing.is_some_and(|id| id.kind() == Kind::InputWaiting);
        assert!(
            waiting && showing == self.expected,
            "step {}: {key:?} pressed on {}, not on its expected screen {}",
            self.counts.steps,
            showing.map_or("nothing", ScreenId::name),
            self.expected.map_or("(none)", ScreenId::name)
        );
    }

    fn press(&mut self, key: Key) {
        self.refuse_unless_showing(key);
        self.app.hal_mut().press(key);
        self.play();
    }

    /// Types a go-ahead code on the grid, then Done.
    fn code(&mut self, code: Code) {
        let Some(url) = self.check_url.as_ref() else {
            panic!("step {}: no check QR was shown", self.counts.steps);
        };
        let mut typed = go_ahead(url);
        if let Code::Wrong = code {
            let last = typed[7];
            typed[7] = if last == b'0' { b'1' } else { b'0' };
        }
        let typed = String::from_utf8(typed.to_vec()).expect("Crockford symbols");
        self.type_text(&typed);
        self.press(Key::Key3);
    }

    /// Types `text` on the entry grid showing: from the cursor drawn in brackets, the shortest
    /// path to each symbol, then Press. The presents this makes are consumed here, each of the
    /// grid's screen.
    fn type_text(&mut self, text: &str) {
        let Some(id) = self.expected else {
            panic!("step {}: typing on no expected screen", self.counts.steps);
        };
        let layout = Layout::of(id);
        let mut cursor = layout.cell(self.drawn_cursor());
        for symbol in text.bytes() {
            let target = layout
                .symbols
                .iter()
                .position(|&s| s == symbol)
                .expect("a symbol of this grid");
            for key in layout.path(cursor, target) {
                self.press(key);
            }
            self.press(Key::Press);
            cursor = target;
        }
        self.consume(id);
    }

    /// The symbol the latest present draws in brackets: the grid's cursor.
    fn drawn_cursor(&self) -> char {
        let latest = self.latest().expect("a present");
        // The grid is the model's last text: a typed passphrase above it may hold brackets too.
        latest
            .elements
            .iter()
            .rev()
            .filter_map(|element| element.item.text())
            .find_map(|text| {
                let chars: Vec<char> = text.chars().collect();
                chars
                    .windows(3)
                    .find(|w| w[0] == '[' && w[2] == ']')
                    .map(|w| w[1])
            })
            .expect("a grid with its cursor")
    }

    /// Takes the presents not yet matched as this step's own: each must be of `id`.
    fn consume(&mut self, id: ScreenId) {
        if let Some(last) = self.unmatched.back().map(|p| p.id) {
            let shown: Vec<&str> = self.unmatched.iter().map(|p| p.id.name()).collect();
            assert!(
                self.unmatched.iter().all(|p| p.id == id),
                "step {}: typing on {} presented {shown:?}",
                self.counts.steps,
                id.name()
            );
            debug_assert_eq!(last, id);
            self.matched = self.unmatched.drain(..).next_back();
        }
    }

    /// Reads faces back on readback-entry, then Done.
    fn read_back(&mut self, readback: Readback) {
        let faces: Zeroizing<String> = match readback {
            Readback::Faces(faces) => Zeroizing::new(faces.to_owned()),
            Readback::FromScreen => {
                let latest = self.latest().expect("a present");
                let position = latest
                    .elements
                    .iter()
                    .filter_map(|element| element.item.text())
                    .find_map(|text| number_after(text, "Read back insert "))
                    .expect("the insert being read back");
                let word = self
                    .record
                    .words
                    .get(&position)
                    .expect("its insert was shown");
                Zeroizing::new(word.chars().take(4).collect())
            }
        };
        self.type_text(&faces);
        self.press(Key::Key3);
    }

    /// Picks on backup-confirm: the question's position and the marked choices are read off the
    /// model, the right word off the passphrase's pages.
    fn pick(&mut self, answer: Answer) {
        let latest = self.latest().expect("a present");
        assert_eq!(
            latest.id,
            ScreenId::BackupConfirm,
            "step {}",
            self.counts.steps
        );
        let position: u8 = latest
            .elements
            .iter()
            .filter_map(|element| element.item.text())
            .find_map(|text| {
                text.strip_prefix("Which is word ")?
                    .strip_suffix('?')?
                    .parse()
                    .ok()
            })
            .expect("the question");
        let lines: Vec<Zeroizing<String>> = latest
            .elements
            .iter()
            .find_map(|element| match (&element.class, &element.item) {
                (Class::Protected, Shown::Text(text)) => Some(
                    text.split('\n')
                        .map(|line| Zeroizing::new(line.to_owned()))
                        .collect(),
                ),
                _ => None,
            })
            .expect("the choices");
        let cursor = lines
            .iter()
            .position(|line| line.starts_with('>'))
            .expect("the cursor");
        let right = self
            .record
            .passphrase
            .get(&position)
            .expect("the word shown");
        let target = lines
            .iter()
            .position(|line| match answer {
                Answer::Right => line[1..] == ***right,
                Answer::Wrong => line[1..] != ***right,
            })
            .expect("a choice");
        for _ in 0..(target + lines.len() - cursor) % lines.len() {
            self.press(Key::Down);
        }
        self.consume(ScreenId::BackupConfirm);
        self.press(Key::Press);
    }
}

/// New hardware with `hwrng`, capturing into the folder `keep` names, if any, numbered on from the
/// `written` files the run's earlier hardware wrote there.
fn hardware(hwrng: HwRngStream, keep: &Keep, protected: ProtectedFrames, written: usize) -> SimHal {
    let mut hal = SimHal::new(hwrng);
    if let Keep::Captures(dir) = keep {
        let written = u32::try_from(written).expect("fewer than 2^32 captures");
        hal.capture(dir.clone(), protected, written);
    }
    hal
}

/// The SHA-256 of a frame's RGB565 values, each little-endian, row by row.
fn frame_sha256(frame: &Pixels) -> [u8; 32] {
    let side = usize::try_from(SIDE).expect("the panel side");
    let mut hasher = Sha256::new();
    let mut row = vec![0u8; 2 * side];
    for pixels in frame.raw().chunks(side) {
        for (bytes, pixel) in row.chunks_mut(2).zip(pixels) {
            bytes.copy_from_slice(&pixel.to_le_bytes());
        }
        hasher.update(&row);
    }
    hasher.finalize().into()
}

/// Fails unless the step that took a dead key presented nothing.
pub fn assert_dead(step: usize, key: Key, presents: &[Present]) {
    let shown: Vec<&str> = presents.iter().map(|p| p.id.name()).collect();
    assert!(
        presents.is_empty(),
        "step {step}: the dead key {key:?} presented {shown:?}"
    );
}

/// A display that keeps a copy of the frame it is given.
struct Grab(Option<Zeroizing<Vec<u16>>>);

impl Display for Grab {
    fn present(&mut self, frame: &Frame, _screen: &Screen<'_>) -> Result<(), HalError> {
        self.0 = Some(Zeroizing::new(frame.raw().to_vec()));
        Ok(())
    }
}

/// True when the QR square at `at` (in the content area) of the frame `raw` equals a fresh
/// drawing of `payload` by pi/app's painter: every module drawn as its encoding says.
pub fn qr_drawn(raw: &[u16], at: (i32, i32), payload: &str) -> bool {
    let none = Banners {
        test_registry: false,
        simulator: false,
    };
    let model = Key::ALL
        .into_iter()
        .fold(Screen::new(ScreenId::SealQr, "", none), Screen::without)
        .with(Element::public(at.into(), Item::Qr(payload.into())));
    let mut grab = Grab(None);
    if let Err(error) = Painter::new().present(&mut grab, &model) {
        panic!("the reference QR does not draw: {}", error.text());
    }
    let reference = grab.0.expect("the reference was presented");
    let side = usize::try_from(SIDE).expect("the panel side");
    let qr = usize::try_from(QR_SIDE).expect("the QR side");
    let left = usize::try_from(at.0).expect("a QR inside the panel");
    let top = usize::try_from(at.1).expect("a QR inside the panel")
        + usize::try_from(STRIP_HEIGHT).expect("the strip height");
    (top..top + qr).all(|y| (left..left + qr).all(|x| raw[y * side + x] == reference[y * side + x]))
}

/// The mock checker (Q30 (d)): G for the check URL `.../check#t=<64 hex>&n=<16 hex>`, as 8
/// Crockford symbols without the dash.
pub fn go_ahead(check_url: &str) -> [u8; 8] {
    let (_, fragment) = check_url.split_once("#t=").expect("a check URL");
    let (t, n) = fragment
        .split_once("&n=")
        .expect("a check URL with a nonce");
    assert!(t.len() == 64 && n.len() == 16, "T and n in hex");
    let digest = Sha256::new()
        .chain_update(GO_DOMAIN)
        .chain_update(hex(t))
        .chain_update(hex(n))
        .finalize();
    let bits = digest[..5]
        .iter()
        .fold(0u64, |bits, &byte| (bits << 8) | u64::from(byte));
    let mut code = [0u8; 8];
    for (i, symbol) in code.iter_mut().enumerate() {
        let index = usize::try_from((bits >> (35 - 5 * i)) & 31).expect("5 bits");
        *symbol = CROCKFORD[index];
    }
    code
}

/// Lowercase hex to bytes.
fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

mod tests {
    use serde_json::Value;

    use super::*;

    /// The check URL of the seal test vector (CLAUDE.md, "Go-ahead vector").
    const VECTOR_1_URL: &str = "https://registry.invalid/check#t=2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c&n=0001020304050607";

    #[test]
    fn the_mock_checker_gives_every_kcr_go_ahead_code() {
        assert_eq!(&go_ahead(VECTOR_1_URL), b"CF94BCAJ");
        let kcr: Value =
            serde_json::from_str(include_str!("../../../../vectors/kcr.json")).expect("kcr.json");
        let seeds = kcr["seeds"].as_array().expect("seeds");
        assert_eq!(seeds.len(), 4);
        for seed in seeds {
            let url = format!(
                "https://registry.invalid/check#t={}&n={}",
                seed["seal_tag_hex"].as_str().expect("T"),
                seed["nonce_hex"].as_str().expect("n")
            );
            let compact = seed["go_ahead_compact"].as_str().expect("G");
            assert_eq!(go_ahead(&url), compact.as_bytes(), "{}", seed["name"]);
        }
    }

    #[test]
    #[should_panic(expected = "step 1: Press pressed on home, not on its expected screen (none)")]
    fn a_key_before_its_screen_fails() {
        run(Scenario {
            name: "key-before-its-screen",
            hwrng: HwRngStream::Counting,
            protected: ProtectedFrames::Placeholder,
            steps: vec![Step::Key(Key::Press)],
        });
    }

    #[test]
    #[should_panic(expected = "step 2: expected dice, presented since the last match: []")]
    fn an_unmet_expect_fails_and_names_its_step() {
        run(Scenario {
            name: "unmet-expect",
            hwrng: HwRngStream::Counting,
            protected: ProtectedFrames::Placeholder,
            steps: vec![Step::Expect(ScreenId::Home), Step::Expect(ScreenId::Dice)],
        });
    }

    /// One present of `screen`, through `SimHal`.
    fn presented(screen: &Screen<'_>) -> Present {
        let mut hal = SimHal::new(HwRngStream::Counting);
        Painter::new().present(&mut hal, screen).expect("drawn");
        let mut presents = hal.take_presents();
        assert_eq!(presents.len(), 1);
        presents.remove(0)
    }

    #[test]
    #[should_panic(expected = "step 3: the dead key Key2 presented [\"home\"]")]
    fn a_dead_key_that_presents_fails() {
        let none = Banners {
            test_registry: false,
            simulator: false,
        };
        assert_dead(3, Key::Key2, &[]);
        let home = presented(&Screen::new(ScreenId::Home, "Home", none));
        assert_dead(3, Key::Key2, &[home]);
    }

    #[test]
    fn a_qr_frame_with_one_flipped_module_fails() {
        let none = Banners {
            test_registry: false,
            simulator: false,
        };
        let at = (12, 0);
        let screen = Screen::new(ScreenId::SealQr, "", none)
            .with(Element::public(at.into(), Item::Qr(VECTOR_1_URL.into())));
        let present = presented(&screen);
        let Shown::Qr(payload) = &present.elements[0].item else {
            panic!("a QR element");
        };
        let mut raw = present.frame.raw().to_vec();
        assert!(qr_drawn(&raw, at, payload));
        assert!(!qr_drawn(&raw, at, "https://registry.invalid/check#t=00"));
        // The check URL is a version 6 code (41 modules) at 4 px a module, centred in the
        // 216 px square (ui::qr's measured values): module (0, 0), dark in the finder
        // pattern, starts 26 px in. Flip its 4×4 pixels.
        let left = 12 + 26;
        let top = 12 + 26;
        for y in top..top + 4 {
            for x in left..left + 4 {
                raw[y * 240 + x] = !raw[y * 240 + x];
            }
        }
        assert!(!qr_drawn(&raw, at, payload));
    }
}
