// Test support for the CeremonyModel's tests (tasks/todo.md, M6 item D2), ported from :screens'
// TestSupport.kt: the model runs on the test's own thread, its worker holds each long call until the
// test runs it (so the test can act while "Working..." shows), and the clock, the offline check and the
// motion source are fakes the test moves; the UTC date is vectors/kcr.json's. The tests reach the
// process's one slot through Core itself, as the JVM tests do through Core.kt.
//
// One difference from the JVM: Gradle runs each Kotlin test class in a JVM of its own, so a class may
// halt its slot for good; XCTest runs every class of this bundle in one process, on one slot. So every
// test here leaves the slot at home (wipeAll), and a test of the model on a halt runs over StandInCore,
// which forwards to Core and halts in its own place, never the slot's. CoreTests' last steps halt the
// real slot, which latches, so the classes that use the slot are named to run before it (XCTest runs a
// bundle's classes in name order): Ceremony*Tests and CoreDiscardTests; each checks the slot is live
// first (assertLiveSlot), so a run in another order fails by name instead of by a stray halt.

import Foundation
import XCTest

/// The slot answers: CoreTests' halt (or any other) has not latched it yet.
func assertLiveSlot(file: StaticString = #filePath, line: UInt = #line) {
    guard case .done = Core.shared.selfTest() else {
        XCTFail("the slot halted before this test: the tests that use it must run before CoreTests' halts", file: file, line: line)
        return
    }
}

/// The slot back at home after a test: wipeAll done.
func assertSlotEmptied(file: StaticString = #filePath, line: UInt = #line) {
    guard case .done = Core.shared.wipeAll() else {
        XCTFail("wipeAll was not done", file: file, line: line)
        return
    }
}

/// Whether the reply is done.
func isDone<T>(_ reply: Reply<T>) -> Bool {
    if case .done = reply { return true }
    return false
}

/// A clock the test sets.
final class FakeClock: MonotonicClock {
    var now: Int64 = 0

    func nowMillis() -> Int64 { now }

    func nowNanos() -> Int64 { now * 1_000_000 }
}

/// The UTC date the model reads: vectors/kcr.json's own (2026-03-01), or a day the test sets.
final class FakeDate: UtcDate {
    var day: UInt32?

    func today() -> UInt32 { day ?? KcrVectors.today }
}

/// A worker that keeps each long call until run, in order.
final class HeldWorker: Worker {
    private var held: [(job: () -> Void, main: () -> Void)] = []

    /// How many long calls wait.
    var waiting: Int { held.count }

    /// How many long calls it has run.
    private(set) var ran = 0

    func run(_ job: @escaping () -> Void, then main: @escaping () -> Void) {
        held.append((job, main))
    }

    /// Runs every long call waiting, and what each one's reply leads to.
    func run() {
        while !held.isEmpty {
            runNext()
        }
    }

    /// Runs the first long call waiting, and what its reply leads to (a long call its reply starts then waits).
    func runNext() {
        let next = held.removeFirst()
        next.job()
        next.main()
        ran += 1
    }

    /// Runs the first long call's worker part alone; its main part is handed back, for the test to run
    /// once it has acted between the two (Android's HeldMain).
    func runWorkerPart() -> () -> Void {
        let next = held.removeFirst()
        next.job()
        ran += 1
        return next.main
    }
}

/// The offline check as the test switches it; it starts offline (no usable path) once the app starts.
final class FakeOffline {
    var offline = true
    weak var model: CeremonyModel?

    /// The phone goes offline or online: the offline check's report.
    func set(_ offline: Bool) {
        self.offline = offline
        model?.pathReported(offline: offline)
    }
}

/// A motion source the test drives: it counts its starts and keeps its last receiver, for a late sample.
final class FakeMotion: MotionSource {
    var starts = 0
    private var report: ((Secret) -> Void)?
    private var last: ((Secret) -> Void)?

    var running: Bool { report != nil }

    func start(_ report: @escaping (Secret) -> Void) {
        starts += 1
        self.report = report
        last = report
    }

    func stop() {
        report = nil
    }

    /// A sample from the phone, if the model is listening; false when it is not.
    @discardableResult
    func sample(_ bytes: Secret) -> Bool {
        guard let report else { return false }
        report(bytes)
        return true
    }

    /// A sample that was on its way when the model stopped listening.
    func late(_ bytes: Secret) {
        last?(bytes)
    }
}

/// A model over fakes, and the fakes (Android's Rig).
final class Rig {
    let clock = FakeClock()
    let date = FakeDate()
    let worker = HeldWorker()
    let offline = FakeOffline()
    let motion = FakeMotion()
    let model: CeremonyModel

    init(core: CeremonyCore = Core.shared) {
        #if KC_WITH_TEST_REGISTRY
        let registry = true
        #else
        let registry = false
        #endif
        model = CeremonyModel(core: core, worker: worker, clock: clock, date: date, motion: motion, testRegistry: registry)
        offline.model = model
    }

    var screen: Screen { model.state.screen }

    /// The app's first start: First launch, the first screen, before any core call (lead decision M5-50),
    /// and the offline check's first report.
    @discardableResult
    func startUp() -> Rig {
        model.appReturned()
        offline.set(offline.offline)
        return self
    }

    /// Through the start and First launch's Continue, which runs the start-up self-test, to Go offline.
    @discardableResult
    func toGoOffline() -> Rig {
        startUp()
        model.firstLaunchDone()
        worker.run()
        return self
    }

    /// Through the start-up self-test and Go offline (the fake starts offline) to Home.
    @discardableResult
    func toHome() -> Rig {
        toGoOffline()
        model.startOffline()
        return self
    }

    /// A discard's landing: the start screen, saying why, with nothing held. The start screen is Home
    /// while the phone is still offline and Go offline once it went online (Q81).
    func assertDiscarded(_ notice: Notice?, _ what: String = "the discard", file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(screen, offline.offline ? .home : .goOffline, "\(what): the start screen", file: file, line: line)
        XCTAssertEqual(model.state.notice, notice, "\(what): the notice", file: file, line: line)
        XCTAssertFalse(model.held, "\(what): something is still held", file: file, line: line)
    }

    /// Every pad's entry, as its length.
    func padLengths() -> [Int] {
        [model.dicePick, model.goAheadCode, model.readbackLetters, model.backupLetters, model.bip39Letters].map(\.length)
    }

    /// After a discard: nothing of the session on show, and every pad's entry wiped.
    func assertNothingSecretShown(_ what: String, file: StaticString = #filePath, line: UInt = #line) {
        let state = model.state
        let shown: [Any?] = [
            state.seal, state.checkRequest, state.report, state.insert, state.overview, state.mismatch, state.summary,
            state.passphrase, state.challenge, state.opened, state.watch, state.registration, state.deviceLeg,
        ]
        XCTAssertTrue(shown.allSatisfy { $0 == nil }, "\(what): something of the session is still on show", file: file, line: line)
        XCTAssertEqual(padLengths(), [0, 0, 0, 0, 0], "\(what): a pad's entry outlived the discard", file: file, line: line)
    }

    /// A key pressed on the showing screen's pad, on its page, as its screens make the press.
    func press(_ key: Character) {
        model.padKey(screen: screen, page: model.state.page, key: key)
    }

    /// keys pressed in turn on the showing screen's pad.
    func press(_ keys: String) {
        for key in keys {
            press(key)
        }
    }

    /// The Delete beside the showing screen's pad, on its page.
    func pressDelete() {
        model.padDelete(screen: screen, page: model.state.page)
    }

    /// From Home through Length and the start (its long call run) to the ceremony's first screen.
    @discardableResult
    func begin(_ mode: Mode, _ words: Words) -> Rig {
        model.chooseMode(mode)
        model.chooseLength(words)
        worker.run()
        return self
    }

    /// n rolls through the dice pad's keys and Confirm, the faces 1 to 6 in turn from 1 on each call.
    func roll(_ n: Int) {
        let faces = Array(diceKeys)
        for index in 0..<n {
            press(faces[index % faces.count])
            model.confirmRoll()
        }
    }

    /// From Home: a dice-only seed of kcr.json's gate seed named seed (its rolls on the pad), the dice's
    /// Done, then Skip and its confirm: Skip's result.
    @discardableResult
    func toSkippedResult(_ seed: String) -> Rig {
        begin(.diceOnly, KcrVectors.words(seed).count == 24 ? .twentyFour : .twelve)
        for face in KcrVectors.rolls(seed) {
            press(face)
            model.confirmRoll()
        }
        model.diceDone()
        worker.run()
        model.skip()
        model.skipConfirmed()
        return self
    }

    /// Skip's result's Show words, then the privacy gate's "I'm alone, show words": insert 1's page.
    @discardableResult
    func toWords() -> Rig {
        model.showWords()
        model.passGate()
        return self
    }

    /// From Home: the 12-word dice-only seed named seed to its words, every insert read back, the
    /// read-back's end and the wallet summary.
    @discardableResult
    func toSummary(_ seed: String) -> Rig {
        let words = KcrVectors.words(seed)
        toSkippedResult(seed).toWords()
        for _ in 0..<(words.count - 1) {
            model.nextPage()
        }
        model.startReadback()
        for word in words {
            press(String(word.prefix(4)))
            model.readbackTyped()
            model.readbackNext()
        }
        model.showSummary()
        return self
    }

    /// The backup passphrase's words on the page on show, read in-process from its Secret (compared,
    /// never printed).
    func passphraseWords() -> [String] {
        guard let text = model.state.passphrase else {
            XCTFail("no passphrase page on show")
            return []
        }
        let bytes = (0..<text.count).map { text[$0] }
        return bytes.split(separator: 0x20).map { String(decoding: $0, as: UTF8.self) }
    }

    /// From the wallet summary: the offer's "Make an encrypted backup", the privacy gate, the passphrase's
    /// two pages read in-process, then "I wrote it down"; the eight words, in order.
    func toConfirm() -> [String] {
        model.summaryDone()
        model.makeBackup()
        model.passGate()
        var words = passphraseWords()
        model.nextPage()
        words += passphraseWords()
        model.passphraseWritten()
        return words
    }

    /// On the confirm, the answer to the question on show pressed on the letter pad, then Done.
    func answer(_ word: String) {
        press(String(word.prefix(4)))
        model.confirmTyped()
    }

    /// On the confirm, both questions answered from passphrase, and the encryption run: the save screen.
    func confirm(_ passphrase: [String]) {
        for _ in 0..<2 {
            let state = model.state
            guard let question = state.challenge?.questions[state.page] else {
                XCTFail("no question on show")
                return
            }
            answer(passphrase[question.position - 1])
        }
        worker.run()
    }

    /// From the watch-only offer, every export skipped: the checklist.
    func skipExports() {
        model.skipWatchOnly()
        model.skipRegistration()
        if screen == .revealDOffer { model.skipDeviceLeg() }
        XCTAssertEqual(screen, .checklist, "the exports skipped did not lead to the checklist")
    }

    /// From Home: Load registry snapshot with kcr.json's snapshot named name, its read and load run,
    /// then the result's Done: Home, with the snapshot loaded (the test-registry build alone).
    @discardableResult
    func loadSnapshot(_ name: String) -> Rig {
        let bytes = KcrVectors.snapshot(name)
        model.loadSnapshot(FakePickers())
        model.snapshotPicked(FakeFile(name: name + ".kcr", size: Int64(bytes.count), bytes: bytes))
        worker.run()
        XCTAssertTrue(screen == .snapshot && model.state.loaded != nil, "the snapshot did not load")
        model.snapshotDone()
        XCTAssertEqual(screen, .home, "the snapshot's result did not return Home")
        return self
    }

    /// From Home: a new seed (Mixed) of 12 words, its commitment, 50 rolls, the dice's Done, Skip and its
    /// confirm, the words read back from the pages the state holds, the read-back's end and the summary.
    /// C, as the commitment screen showed it (public).
    func toMixedSummary() -> String? {
        begin(.mixed, .twelve)
        model.deviceEntropyDone()
        let commitment = model.state.commitment
        model.commitmentDone()
        roll(50)
        model.diceDone()
        worker.run()
        model.skip()
        model.skipConfirmed()
        toWords()
        for _ in 0..<(insertsPerDevice - 1) {
            model.nextPage()
        }
        model.startReadback()
        for _ in 0..<insertsPerDevice {
            readBackShown()
            model.readbackNext()
        }
        model.showSummary()
        XCTAssertEqual(screen, .wallet, "the mixed seed did not reach its wallet summary")
        return commitment
    }

    /// On the read-back entry, the insert on show read back: its word's first four letters (a three-letter
    /// word's three), read from the page the state holds through a copy wiped at once, then Done.
    func readBackShown() {
        guard let insert = model.state.insert else {
            XCTFail("no insert on the read-back entry")
            return
        }
        let word = insert.word()
        let letters = String(decoding: (0..<min(4, word.count)).map { word[$0] }, as: UTF8.self)
        word.wipe()
        press(letters)
        model.readbackTyped()
    }
}

/// A backup a ceremony of its own saved: the file's bytes, the passphrase's words and the fingerprint.
final class SavedBackup {
    /// A backup's name as core suggests them.
    static let name = "keepcrypt-backup-0123abcd.age"

    let file: [UInt8]
    let passphrase: [String]
    let fingerprint: [UInt8]

    private init(file: [UInt8], passphrase: [String], fingerprint: [UInt8]) {
        self.file = file
        self.passphrase = passphrase
        self.fingerprint = fingerprint
    }

    /// kcr.json's dice-50-words12 backed up, saved once in this process by a ceremony of the first test
    /// that asks, which then ends it (Finish), so the slot is at home again.
    static let shared: SavedBackup = {
        let rig = Rig().toHome().toSummary("dice-50-words12")
        let fingerprint = rig.model.state.summary?.fingerprint ?? []
        let passphrase = rig.toConfirm()
        rig.confirm(passphrase)
        let place = FakePlace()
        rig.model.saveBackup(FakePickers())
        rig.model.backupPlaced(place)
        rig.worker.run()
        XCTAssertEqual(rig.screen, .backupVerified, "the shared backup was not verified")
        rig.model.backupVerifiedDone()
        rig.skipExports()
        rig.model.finishCeremony()
        return SavedBackup(file: place.saved ?? [], passphrase: passphrase, fingerprint: fingerprint)
    }()
}

/// The document pickers' fake: what the model asked of them, nothing opened.
final class FakePickers: DocumentPickers {
    var created: [String] = []
    var opens = 0
    var snapshotOpens = 0

    func create(name: String) {
        created.append(name)
    }

    func openBackup() {
        opens += 1
    }

    func openSnapshot() {
        snapshotOpens += 1
    }
}

/// A place the create-document picker gave, in memory: its write fails when told to, and its read-back
/// gives what was written (or what reads makes of it, or nil for a read that fails). It keeps the Secret
/// the model handed to write, and the one it handed back, so the tests see both wiped.
final class FakePlace: DocumentPlace {
    private let writes: Bool
    private let reads: ([UInt8]) -> [UInt8]?
    var writeCalls = 0
    var readCalls = 0
    var readLimit = -1
    /// The model's own Secret, as handed to write.
    var handed: Secret?
    /// What was written, copied as it came.
    var saved: [UInt8]?
    /// The Secret readBack gave the model.
    var given: Secret?

    init(writes: Bool = true, reads: @escaping ([UInt8]) -> [UInt8]? = { $0 }) {
        self.writes = writes
        self.reads = reads
    }

    func write(_ bytes: Secret) -> Bool {
        writeCalls += 1
        handed = bytes
        guard writes else { return false }
        saved = (0..<bytes.count).map { bytes[$0] }
        return true
    }

    func readBack(limit: Int) -> Secret? {
        readCalls += 1
        readLimit = limit
        guard let file = saved, let back = reads(file) else { return nil }
        let secret = Secret(taking: back)
        given = secret
        return secret
    }
}

/// A file the open-document picker gave, in memory: its name, its size and bytes (nil for a read that
/// fails); it counts its reads, and while it reads (on the model's worker) runs reading.
final class FakeFile: PickedFile {
    let name: String?
    let size: Int64?
    private let bytes: [UInt8]?
    private let reading: () -> Void
    var reads = 0
    var readLimit = -1
    /// The Secret read gave the model.
    var given: Secret?

    init(name: String?, size: Int64?, bytes: [UInt8]?, reading: @escaping () -> Void = {}) {
        self.name = name
        self.size = size
        self.bytes = bytes
        self.reading = reading
    }

    func read(limit: Int) -> Secret? {
        reads += 1
        readLimit = limit
        reading()
        guard let bytes else { return nil }
        let secret = Secret(taking: bytes)
        given = secret
        return secret
    }
}

/// Whether two states are the same (Android's UiState equality): each value equal and each Secret, QR
/// code, word page, verdicts, challenge, opened backup and export the same object.
func sameState(_ a: UiState, _ b: UiState) -> Bool {
    func same(_ x: AnyObject?, _ y: AnyObject?) -> Bool { x === y }
    let values = a.screen == b.screen && a.page == b.page && a.gate == b.gate && a.overlay == b.overlay
        && a.recording == b.recording && a.offline == b.offline && a.notice == b.notice && a.dice == b.dice
        && a.diceOnly == b.diceOnly && a.commitment == b.commitment && a.seal == b.seal && a.registry == b.registry
        && a.proof == b.proof && a.skipped == b.skipped && a.codeRefused == b.codeRefused && a.scanStop == b.scanStop
        && a.scanRefusal == b.scanRefusal && a.reviewing == b.reviewing && a.swapTo == b.swapTo && a.matched == b.matched
        && a.complete == b.complete && a.summary == b.summary && a.twoDevices == b.twoDevices
        && a.wrongConfirm == b.wrongConfirm && a.backupName == b.backupName && a.saveFailure == b.saveFailure
        && a.fileRefusal == b.fileRefusal && a.entryRefusal == b.entryRefusal && a.loaded == b.loaded
        && a.snapshotRefusal == b.snapshotRefusal && a.halt == b.halt
    let overview = (a.overview ?? []).count == (b.overview ?? []).count
        && zip(a.overview ?? [], b.overview ?? []).allSatisfy { $0 === $1 } && (a.overview == nil) == (b.overview == nil)
    let objects = same(a.checkRequest, b.checkRequest) && same(a.report, b.report) && same(a.insert, b.insert)
        && same(a.mismatch, b.mismatch) && same(a.passphrase, b.passphrase) && same(a.registration, b.registration)
        && same(a.deviceLeg, b.deviceLeg) && same(a.challenge?.questions.first?.choices.first, b.challenge?.questions.first?.choices.first)
        && same(a.opened?.recheck, b.opened?.recheck) && same(a.watch?.account, b.watch?.account)
    return values && overview && objects
}

/// Whether every byte of secret is zero.
func zeroed(_ secret: Secret?) -> Bool {
    guard let secret else { return false }
    return (0..<secret.count).allSatisfy { secret[$0] == 0 }
}

/// Whether insert's word is word: compared byte by byte, its copy wiped, nothing printed.
func sameWord(_ insert: WordPage, _ word: String) -> Bool {
    let bytes = insert.word()
    defer { bytes.wipe() }
    let letters = Array(word.utf8)
    return bytes.count == letters.count && letters.indices.allSatisfy { bytes[$0] == letters[$0] }
}

/// Whether insert's page was wiped: its Secret zeroed, so its position, count and word length read 0.
func wiped(_ insert: WordPage) -> Bool {
    insert.position == 0 && insert.count == 0 && insert.word().count == 0
}

/// The gate seeds, snapshots and proofs of vectors/kcr.json (rule 12: vectors/ only), read with
/// JSONSerialization once by load (each test class's setUp); each one asked for that is missing fails
/// its test.
enum KcrVectors {
    private static var kcr: [String: Any] = [:]

    /// Reads kcr.json, once.
    static func load() throws {
        if kcr.isEmpty {
            kcr = try XCTUnwrap(JSONSerialization.jsonObject(with: Vectors.resource("kcr", "json")) as? [String: Any])
        }
    }

    /// kcr.json's today (YYYYMMDD), the date its snapshots' freshness is pinned against.
    static var today: UInt32 { UInt32(kcr["today"] as? Int ?? 0) }

    private static func entry(_ list: String, _ name: String) -> [String: Any] {
        let found = (kcr[list] as? [[String: Any]] ?? []).filter { $0["name"] as? String == name }
        XCTAssertEqual(found.count, 1, "kcr.json's \(list) hold \(name) once")
        return found.first ?? [:]
    }

    /// The rolls of the gate seed named name, each a face 1-6.
    static func rolls(_ name: String) -> String { entry("seeds", name)["rolls"] as? String ?? "" }

    /// The words of the gate seed named name, in order (public vectors, never printed).
    static func words(_ name: String) -> [String] {
        (entry("seeds", name)["mnemonic"] as? String ?? "").split(separator: " ").map(String.init)
    }

    /// The bytes of the snapshot named name (its kcr_hex).
    static func snapshot(_ name: String) -> [UInt8] { hexBytes(entry("snapshots", name)["kcr_hex"] as? String ?? "") }

    /// The go-ahead QR text of the proof named name (its ur).
    static func proofUr(_ name: String) -> String { entry("proofs", name)["ur"] as? String ?? "" }

    /// The entries of list, each with its name, input field and expect block.
    static func all(_ list: String) -> [[String: Any]] { kcr[list] as? [[String: Any]] ?? [] }
}

/// hex's bytes, two digits each.
func hexBytes(_ hex: String) -> [UInt8] {
    let digits = Array(hex.utf8)
    XCTAssertEqual(digits.count % 2, 0, "an even number of hex digits")
    return stride(from: 0, to: digits.count - 1, by: 2).map { index in
        UInt8(String(decoding: digits[index...index + 1], as: UTF8.self), radix: 16) ?? 0
    }
}

/// Core for a test that needs the slot to halt, or a call to give another reply, without halting the
/// process's one slot (whose halt latches for every later test): every call goes to Core itself until
/// the stand-in halts (its shellHalt, a reply it was told to give as halted, or a halt core gave), and
/// from then on every call gives that halt, as the halted slot does, and none reaches Core. It counts
/// the self-tests and discards, and answers either with a reply of the test's when told to.
final class StandInCore: CeremonyCore {
    private let core = Core.shared
    /// The halt the stand-in latched, as the slot latches its first.
    private(set) var latched: HaltReason?
    var selfTests = 0
    var discards = 0
    /// The self-test's reply instead of Core's.
    var selfTestReply: Reply<Void>?
    /// The discard's reply instead of Core's (Core's discard is made first all the same, so the slot
    /// drops what it held).
    var discardReply: Reply<Void>?
    /// A discard took the slot home before the next call of one that core does not offer at home
    /// (finish, revealProof, encryptBackup, verifyBackup): that call halts, internal, as core's stage
    /// rule halts it (lead decision M5-54's residual; ffi/tests/ceremony.rs pins the rule itself).
    var haltsAtHome = false

    /// A call core does not offer at home: the halt core gives it there once haltsAtHome, else core's.
    private func notAtHome<T>(_ body: () -> Reply<T>) -> Reply<T> {
        if haltsAtHome, latched == nil { latched = .internal }
        return pass(body)
    }

    /// A call through the stand-in: the latched halt, or core's reply, whose halt latches.
    private func pass<T>(_ body: () -> Reply<T>) -> Reply<T> {
        if let latched { return .halted(latched) }
        let reply = body()
        if case .halted(let reason) = reply { latched = reason }
        return reply
    }

    func shellHalt() -> Reply<Void> {
        if latched == nil { latched = .internal }
        return pass { .done(()) }
    }

    func selfTest() -> Reply<Void> {
        pass {
            selfTests += 1
            return selfTestReply ?? core.selfTest()
        }
    }

    func discard() -> Reply<Void> {
        pass {
            discards += 1
            let real = core.discard()
            return discardReply ?? real
        }
    }

    func start(_ words: Words, _ mode: Mode) -> Reply<Void> { pass { core.start(words, mode) } }
    /// Each extra handed over: its source and a copy of its bytes, made as it came, before the model wipes it.
    var extras: [(Extra, [UInt8])] = []

    /// An extra is recorded and answered done without reaching the slot (D3's tests): an extra outside
    /// Collecting halts the slot, and that halt would latch for every later test; core's own answer to
    /// one, a zero-credit pool input, is keepcrypt-ffi's (ffi/tests).
    func addExtra(_ source: Extra, _ bytes: Secret) -> Reply<Void> {
        pass {
            extras.append((source, (0..<bytes.count).map { bytes[$0] }))
            return .done(())
        }
    }
    func commit() -> Reply<Void> { pass { core.commit() } }
    func startDice() -> Reply<Void> { pass { core.startDice() } }
    func pushRoll(_ face: Int) -> Reply<Void> { pass { core.pushRoll(face) } }
    func undoRoll() -> Reply<Void> { pass { core.undoRoll() } }
    func finish() -> Reply<Void> { notAtHome { core.finish() } }
    func skipCheck() -> Reply<Void> { pass { core.skipCheck() } }
    func startCheck() -> Reply<Void> { pass { core.startCheck() } }
    func matchFound() -> Reply<Void> { pass { core.matchFound() } }
    func cannotCheck() -> Reply<Void> { pass { core.cannotCheck() } }
    func generateBackupPassphrase() -> Reply<Void> { pass { core.generateBackupPassphrase() } }
    func end() -> Reply<Void> { pass { core.end() } }
    func wipeAll() -> Reply<Void> { pass { core.wipeAll() } }
    func commitment() -> Reply<Secret> { pass { core.commitment() } }
    func diceProgress() -> Reply<DiceProgress> { pass { core.diceProgress() } }
    func seal() -> Reply<SealCard> { pass { core.seal() } }
    func checkRequest() -> Reply<QrMatrix> { pass { core.checkRequest() } }
    func revealCode(_ code: Secret) -> Reply<Revealed> { pass { core.revealCode(code) } }
    func revealSnapshot(today: UInt32) -> Reply<Revealed> { pass { core.revealSnapshot(today: today) } }
    func revealProof(today: UInt32, text: String) -> Reply<Revealed> { notAtHome { core.revealProof(today: today, text: text) } }
    func collisionReport() -> Reply<QrMatrix> { pass { core.collisionReport() } }
    func wordPage(_ position: Int) -> Reply<WordPage> { pass { core.wordPage(position) } }
    func checkReadback(_ position: Int, letters: Secret) -> Reply<Readback> { pass { core.checkReadback(position, letters: letters) } }
    func summary() -> Reply<Summary> { pass { core.summary() } }
    func backupPassphrasePage(_ page: Int) -> Reply<Secret> { pass { core.backupPassphrasePage(page) } }
    func backupChallenge() -> Reply<Challenge> { pass { core.backupChallenge() } }
    func confirmBackup(_ first: Int, _ second: Int) -> Reply<Bool> { pass { core.confirmBackup(first, second) } }
    func encryptBackup() -> Reply<BackupFile> { notAtHome { core.encryptBackup() } }
    func verifyBackup(_ file: Secret) -> Reply<Void> { notAtHome { core.verifyBackup(file) } }
    func watchOnly(passphrase: Secret?) -> Reply<WatchOnly> { pass { core.watchOnly(passphrase: passphrase) } }
    func registration() -> Reply<QrMatrix> { pass { core.registration() } }
    func revealDeviceLeg() -> Reply<Secret> { pass { core.revealDeviceLeg() } }
    func loadSnapshot(today: UInt32, file: Secret) -> Reply<RegistryHeader> { pass { core.loadSnapshot(today: today, file: file) } }
    func openBackup(entries: [Secret], file: Secret) -> Reply<OpenedBackup> { pass { core.openBackup(entries: entries, file: file) } }
}
