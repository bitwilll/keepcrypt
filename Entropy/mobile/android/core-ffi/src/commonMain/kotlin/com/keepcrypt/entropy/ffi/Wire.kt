package com.keepcrypt.entropy.ffi

/**
 * The bridge's bytes, decoded once (tasks/todo.md, M5 groups 9 and 13; the re-plan's M5-21): every
 * reply starts with its status byte, and an OK reply goes on in its op's layout, each defined once in
 * keepcrypt-ffi's wire.rs (its module comment and each op's doc). This file copies wire.rs's tables,
 * the status bytes, the op numbers and the refusal codes, and WireTablesTest pins each copy against
 * wire.rs's own source, its PINNED table among them. A reply that does not fit its layout is the
 * bridge's bug: the slot is halted (Core.halt) and KcHalt thrown, so it fails closed (rule 3).
 */
internal object Wire {
    /** The call gave its result. */
    const val OK = 0

    /** What the user or a file supplied was refused; the stage is as it was. Its code follows. */
    const val REFUSED = 1

    /** A discard or a wipe came during a long call, whose result was dropped. */
    const val DISCARDED = 2

    /** The slot halted, now or before. */
    const val HALTED = 3

    /** An op the table does not hold, on which the slot halts (keepcrypt-jni's HALT). */
    const val HALT = 0
    const val SELF_TEST = 1
    const val START = 2
    const val ADD_EXTRA = 3
    const val COMMIT = 4
    const val START_DICE = 5
    const val PUSH_ROLL = 6
    const val UNDO_ROLL = 7
    const val FINISH = 8
    const val SKIP_CHECK = 9
    const val START_CHECK = 10
    const val MATCH_FOUND = 11
    const val CANNOT_CHECK = 12
    const val GENERATE_BACKUP_PASSPHRASE = 13
    const val END = 14
    const val DISCARD = 15
    const val WIPE_ALL = 16
    const val DEVICE_PROGRESS = 17
    const val COMMITMENT = 18
    const val DICE_PROGRESS = 19
    const val SEAL = 20
    const val CHECK_REQUEST = 21
    const val REVEAL_CODE = 22
    const val REVEAL_SNAPSHOT = 23
    const val REVEAL_PROOF = 24
    const val COLLISION_REPORT = 25
    const val WORD_PAGE = 26
    const val CHECK_READBACK = 27
    const val SUMMARY = 28
    const val BACKUP_PASSPHRASE_PAGE = 29
    const val BACKUP_CHALLENGE = 30
    const val CONFIRM_BACKUP = 31
    const val ENCRYPT_BACKUP = 32
    const val VERIFY_BACKUP = 33
    const val WATCH_ONLY = 34
    const val REGISTRATION = 35
    const val REVEAL_DEVICE_LEG = 36
    const val LOAD_SNAPSHOT = 37
    const val OPEN_BACKUP = 38

    /** The Seal ID's length: 8 Crockford characters. */
    const val SEAL_ID_LEN = 8

    /** C and D: 32 bytes each. */
    const val LEG_LEN = 32

    /** Crockford base32, the Seal ID's alphabet. */
    const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
}

/** Where a refusal comes from, as wire.rs's refusal codes group them. */
enum class RefusalGroup { Code, Core, Snapshot, Ur, Backup }

/**
 * The code byte after a refused status, one per refusal, as wire.rs's refusal_code gives it: 1-3 a
 * go-ahead that does not verify; 16-19 core's refusals of a passphrase, a read-back, an empty
 * BIP39 passphrase and a build with no registry key; 32-45 a snapshot or proof that does not
 * verify; 48-59 a go-ahead QR's text that is no proof's UR; 64-72 a backup file that does not read.
 * The names are core's (CheckError, CoreError, SnapshotError, UrError, BackupError), each in its
 * group, so WireTablesTest rebuilds wire.rs's PINNED names from them.
 */
enum class Refusal(val code: Int, val group: RefusalGroup) {
    MalformedCode(1, RefusalGroup.Code),
    WrongCode(2, RefusalGroup.Code),
    WrongBucket(3, RefusalGroup.Code),
    WrongPassphrase(16, RefusalGroup.Core),
    ReadbackMismatch(17, RefusalGroup.Core),
    EmptyPassphrase(18, RefusalGroup.Core),
    NoRegistryKey(19, RefusalGroup.Core),
    TooShort(32, RefusalGroup.Snapshot),
    BadMagic(33, RefusalGroup.Snapshot),
    BadVersion(34, RefusalGroup.Snapshot),
    BadSignature(35, RefusalGroup.Snapshot),
    BadDate(36, RefusalGroup.Snapshot),
    TooManyEntries(37, RefusalGroup.Snapshot),
    BadLength(38, RefusalGroup.Snapshot),
    Unsorted(39, RefusalGroup.Snapshot),
    Duplicate(40, RefusalGroup.Snapshot),
    ZeroCount(41, RefusalGroup.Snapshot),
    RootMismatch(42, RefusalGroup.Snapshot),
    BucketOutOfRange(43, RefusalGroup.Snapshot),
    EntryOutsideBucket(44, RefusalGroup.Snapshot),
    ProofCount(45, RefusalGroup.Snapshot),
    TooLong(48, RefusalGroup.Ur),
    MixedCase(49, RefusalGroup.Ur),
    NotUr(50, RefusalGroup.Ur),
    WrongType(51, RefusalGroup.Ur),
    MultiPart(52, RefusalGroup.Ur),
    OddLength(53, RefusalGroup.Ur),
    UnknownByteword(54, RefusalGroup.Ur),
    BadChecksum(55, RefusalGroup.Ur),
    NotByteString(56, RefusalGroup.Ur),
    NonShortestHead(57, RefusalGroup.Ur),
    IndefiniteLength(58, RefusalGroup.Ur),
    TrailingBytes(59, RefusalGroup.Ur),
    TooLarge(64, RefusalGroup.Backup),
    Armor(65, RefusalGroup.Backup),
    Header(66, RefusalGroup.Backup),
    WorkFactor(67, RefusalGroup.Backup),
    HeaderMac(68, RefusalGroup.Backup),
    Payload(69, RefusalGroup.Backup),
    Plaintext(70, RefusalGroup.Backup),
    UnsupportedVersion(71, RefusalGroup.Backup),
    PassphraseWords(72, RefusalGroup.Backup),
    ;

    internal companion object {
        /** The refusal whose code is code; any other code is the bridge's bug and halts. */
        fun of(code: Int): Refusal {
            for (refusal in entries) {
                if (refusal.code == code) return refusal
            }
            Core.halt()
        }
    }
}

/**
 * A reply's body, read field by field from at, as wire.rs's fields are laid out: integers big-endian,
 * a flag one byte 0 or 1, a text its length in one byte and then its bytes, a file the rest. Reading
 * past the end, a flag that is neither, or bytes left unread at the end halts, after the reply's
 * bytes and every copy already taken from them are zeroed, so a value decoded before the reply
 * proved malformed (a word page, a confirm choice, a QR matrix) leaves no secret behind (rule 5).
 */
internal class Reader(private val reply: ByteArray, private var at: Int) {
    /** Every array bytes() has copied out of the reply; the Secrets and matrices decoded hold them. */
    private val copies = ArrayList<ByteArray>()

    /** The reply is not its layout: zeroed with every copy taken from it, and the slot halted. */
    fun malformed(): Nothing {
        reply.fill(0)
        for (copy in copies) copy.fill(0)
        Core.halt()
    }

    fun byte(): Int {
        if (at >= reply.size) malformed()
        val value = reply[at].toInt() and 0xFF
        at += 1
        return value
    }

    fun flag(): Boolean = when (byte()) {
        0 -> false
        1 -> true
        else -> malformed()
    }

    fun u16(): Int {
        val high = byte()
        return (high shl 8) or byte()
    }

    fun u32(): Long {
        var value = 0L
        repeat(4) { value = (value shl 8) or byte().toLong() }
        return value
    }

    fun u64(): ULong {
        var value = 0UL
        repeat(8) { value = (value shl 8) or byte().toULong() }
        return value
    }

    /** The byte offset bytes ahead, left unread. */
    fun peek(offset: Int): Int {
        if (offset < 0 || offset >= reply.size - at) malformed()
        return reply[at + offset].toInt() and 0xFF
    }

    /** The next length bytes, copied out (and kept in copies). */
    fun bytes(length: Int): ByteArray {
        if (length < 0 || length > reply.size - at) malformed()
        val out = reply.copyOfRange(at, at + length)
        copies.add(out)
        at += length
        return out
    }

    /** A text field's bytes, copied out. */
    fun text(): ByteArray = bytes(byte())

    /** Every byte left, copied out. */
    fun rest(): ByteArray = bytes(reply.size - at)

    /** Halts unless every byte has been read. */
    fun end() {
        if (at != reply.size) malformed()
    }
}

/** A text field holding ASCII or UTF-8 that is no secret. */
internal fun Reader.publicText(): String = text().decodeToString()

/** The device leg's credit, in bits: a phone's quota is 256, so more than 2^16 is the bridge's bug. */
internal fun Reader.deviceProgress(): DeviceProgress {
    val credited = u64()
    val required = u64()
    if (credited > 65_536UL || required > 65_536UL) malformed()
    return DeviceProgress(credited.toInt(), required.toInt())
}

internal fun Reader.diceProgress(): DiceProgress {
    val rolls = u16()
    val minimum = u16()
    return DiceProgress(rolls, minimum, u32())
}

/** C, 32 bytes, or nothing in dice-only mode. */
internal fun Reader.commitment(): ByteArray? {
    val c = rest()
    return when (c.size) {
        0 -> null
        Wire.LEG_LEN -> c
        else -> malformed()
    }
}

internal fun Reader.sealCard(): SealCard {
    val grid = IntArray(8) { byte() }
    val colour = byte()
    if (colour > 7) malformed()
    val id = bytes(Wire.SEAL_ID_LEN).decodeToString()
    for (c in id) {
        if (c !in Wire.CROCKFORD) malformed()
    }
    return SealCard(grid, colour, id, publicText())
}

/** A QR matrix: its side, 21-61 (versions 1-11), then side x side bits, the last byte's spare bits 0. */
internal fun Reader.qrMatrix(): QrMatrix {
    val side = byte()
    if (side < 21 || side > 61 || (side - 17) % 4 != 0) malformed()
    val modules = side * side
    val bits = bytes((modules + 7) / 8)
    val spare = bits.size * 8 - modules
    if (spare > 0 && (bits[bits.size - 1].toInt() and ((1 shl spare) - 1)) != 0) malformed()
    return QrMatrix(side, Secret(bits))
}

internal fun Reader.registry(): RegistryHeader {
    val number = u64()
    val date = u32()
    val count = u32()
    val freshness = when (byte()) {
        0 -> Freshness.Current
        1 -> Freshness.Stale
        2 -> Freshness.Future
        else -> malformed()
    }
    return RegistryHeader(number, date.toInt(), count, freshness)
}

internal fun Reader.revealed(): Revealed {
    val outcome = byte()
    val header = if (flag()) registry() else null
    return when (outcome) {
        0 -> Revealed.Clear(header)
        1 -> Revealed.Collision(header)
        else -> malformed()
    }
}

/**
 * A word page, kept whole in a Secret: its seven fixed bytes, the word as a text (its length, then
 * its letters) and the 20 bytes of faces 1-5 lie in the reply as WordPage reads them, so the page is
 * one copy of that span, whose length the word's length byte gives.
 */
internal fun Reader.wordPage(): WordPage = WordPage(Secret(bytes(7 + 1 + peek(7) + 20)))

internal fun Reader.readback(): Readback = when (byte()) {
    0 -> Readback.Match(flag())
    1 -> Readback.Mismatch(
        List(4) {
            val verdict = when (byte()) {
                0 -> Verdict.Ok
                1 -> Verdict.MirrorMisread
                2 -> Verdict.ShouldBeBlank
                3 -> Verdict.ShouldHaveLetter
                4 -> Verdict.WrongLetter
                else -> malformed()
            }
            val missing = byte()
            FaceVerdict(verdict, missing, byte())
        },
    )
    else -> malformed()
}

internal fun Reader.summary(): Summary {
    val fingerprint = bytes(4)
    return Summary(fingerprint, publicText())
}

/** A backup passphrase page or a confirm choice: a text, as a Secret. */
internal fun Reader.secretText(): Secret = Secret(text())

internal fun Reader.challenge(): Challenge = Challenge(
    List(2) {
        val position = byte()
        Question(position, List(4) { secretText() })
    },
)

internal fun Reader.backupFile(): BackupFile {
    val name = publicText()
    return BackupFile(name, rest())
}

internal fun Reader.watchOnly(): WatchOnly {
    val summary = summary()
    val passphraseUsed = flag()
    val account = qrMatrix()
    return WatchOnly(summary, passphraseUsed, account, qrMatrix())
}

internal fun Reader.openedBackup(): OpenedBackup {
    val fingerprint = bytes(4)
    val seal = sealCard()
    return OpenedBackup(fingerprint, seal, qrMatrix())
}

/** D: its 32 bytes, as a Secret. */
internal fun Reader.deviceLeg(): Secret = Secret(bytes(Wire.LEG_LEN))
