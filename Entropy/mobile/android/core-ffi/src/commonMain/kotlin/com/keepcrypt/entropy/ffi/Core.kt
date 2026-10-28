package com.keepcrypt.entropy.ffi

/**
 * The halt status (tasks/todo.md, M5 "Built into this plan"; Q57): the slot has halted, now or
 * before, and has dropped everything it held. Only the stop screen follows, and the process's end.
 * An Error, so no ordinary catch takes it: the only catch of it in the app is CeremonyModel.call's
 * (the gate allows no other). Its text is fixed, never built from runtime values.
 */
class KcHalt : Error("The session halted.")

/**
 * A call's result (Q53's status byte): Done with the op's reply, Refused with what the user or a file
 * supplied that core refused (the stage is as it was), or Discarded when a discard or a wipe came
 * during a long call, whose result was dropped. The halt status is no Reply: Core throws KcHalt.
 */
sealed interface Reply<out T> {
    class Done<out T>(val value: T) : Reply<T>

    class Refused(val refusal: Refusal) : Reply<Nothing>

    object Discarded : Reply<Nothing>
}

/** The seed's length: 12 words (128 bits, one device) or 24 (256 bits, two devices). */
enum class Words(internal val byte: Byte) { Twelve(12), TwentyFour(24) }

/** New seed (dice with the device's own entropy) or Dice-only seed. */
enum class Mode(internal val byte: Byte) { Mixed(1), DiceOnly(2) }

/** The uncredited extras a phone gives while collecting (MA:139-140). */
enum class Extra(internal val byte: Byte) { InputTiming(1), Motion(2) }

/** The device leg's credit, in bits: what it has, and what the commitment needs. */
class DeviceProgress internal constructor(val creditedBits: Int, val requiredBits: Int)

/** The dice screen's counts: the rolls, the minimum, and the bits so far in thousandths. */
class DiceProgress internal constructor(val rolls: Int, val minimum: Int, val millibits: Long)

/**
 * The seal card (docs/seal-watchonly-braille.md, "The seal card"): the 8x8 grid, the colour index
 * into the Okabe-Ito palette (0-7), the Seal ID and the Seal ID in braille. Public values.
 */
class SealCard internal constructor(
    private val grid: IntArray,
    val colourIndex: Int,
    val sealId: String,
    val sealIdBraille: String,
) {
    /** Whether the cell at row, column (each 0-7) is filled. */
    fun isFilled(row: Int, column: Int): Boolean = ((grid[row] shr (7 - column)) and 1) == 1
}

/**
 * A QR code's modules, with no quiet zone (the screen draws it): side x side, row by row. The
 * bits are held in a Secret, since a registration or collision report carries a seal code and an
 * account or descriptor QR the xpub (lead decision M5-37); wipe() when the screen leaves.
 */
class QrMatrix internal constructor(val side: Int, private val bits: Secret) {
    /** Whether the module at column x, row y is dark. */
    fun isDark(x: Int, y: Int): Boolean {
        val i = y * side + x
        return ((bits.u8(i / 8) shr (7 - i % 8)) and 1) == 1
    }

    fun wipe() {
        bits.wipe()
    }

    override fun toString(): String = "QrMatrix"
}

/** A registry snapshot's or bucket proof's freshness against the phone's date (swb:120). */
enum class Freshness { Current, Stale, Future }

/**
 * A loaded snapshot's or a verified proof's header: its number, its date (YYYYMMDD), its count (a
 * snapshot's seals, or the entries in a proof's bucket) and its freshness.
 */
class RegistryHeader internal constructor(
    val number: ULong,
    val date: Int,
    val count: Long,
    val freshness: Freshness,
)

/**
 * A go-ahead's outcome: Clear, the words are available, or Collision, the seed was wiped unseen;
 * each with the snapshot's or proof's header, or none after a typed code.
 */
sealed interface Revealed {
    val registry: RegistryHeader?

    class Clear internal constructor(override val registry: RegistryHeader?) : Revealed

    class Collision internal constructor(override val registry: RegistryHeader?) : Revealed
}

/**
 * One insert's page (Q58: one page at a time), kept whole in a Secret and read from it on demand:
 * the position, the count, the device and devices ("device 1 of 2"), the sequence on face 6, the
 * SeedBook number, the word and faces 1-5. wipe() when the page leaves. The app's pages come from
 * Core.wordPage alone, whose reply's layout Reader checks; the constructor is public for the capture
 * control (CI only, never released), which draws a gate seed's page from vectors/ with the app's own
 * words composable and has no native library (tasks/todo.md, M5 group 6; lead decision M5-68 (f)).
 */
class WordPage(private val page: Secret) {
    val position: Int get() = page.u8(0)
    val count: Int get() = page.u8(1)
    val device: Int get() = page.u8(2)
    val devices: Int get() = page.u8(3)
    val sequence: Int get() = page.u8(4)
    val seedbook: Int get() = (page.u8(5) shl 8) or page.u8(6)
    private val wordLength: Int get() = page.u8(7)

    /** The word, as a Secret of its own that its owner wipes. */
    fun word(): Secret = page.slice(8, wordLength)

    /** Face n (1-5). */
    fun face(n: Int): Face {
        require(n in 1..5) { "faces 1-5" }
        val at = 8 + wordLength + 4 * (n - 1)
        return Face(page.u8(at), page.u8(at + 1), page.u8(at + 2) == 1, page.u8(at + 3))
    }

    fun wipe() {
        page.wipe()
    }

    override fun toString(): String = "WordPage"
}

/** A face of an insert: its letter (null for a blank face), its dots, the lighter flag, its mirror partner. */
class Face internal constructor(
    private val letterCode: Int,
    val dots: Int,
    val isLighter: Boolean,
    private val mirrorCode: Int,
) {
    val isBlank: Boolean get() = letterCode == 0
    val letter: Char? get() = if (letterCode == 0) null else Char(letterCode)
    val mirrorPartner: Char? get() = if (mirrorCode == 0) null else Char(mirrorCode)

    override fun toString(): String = "Face"
}

/** A face's read-back verdict, in wire.rs's order (its code is its ordinal). */
enum class Verdict { Ok, MirrorMisread, ShouldBeBlank, ShouldHaveLetter, WrongLetter }

/** One face of a mismatch: its verdict, and a wrong letter's missing and extra dots. */
class FaceVerdict internal constructor(val verdict: Verdict, val missingDots: Int, val extraDots: Int)

/** An insert read back: a match (and whether every insert has now matched), or a mismatch face by face. */
sealed interface Readback {
    class Match internal constructor(val complete: Boolean) : Readback

    /**
     * A mismatch: core's verdicts on faces 1-4, which with the letters read give the word's own (a
     * wrong letter's missing and extra dots are its letter's), so they are kept whole in a Secret and
     * read from it on demand, as WordPage is (M5-49). wipe() when its screen leaves; a wiped one reads
     * every face Ok.
     */
    class Mismatch internal constructor(private val verdicts: Secret) : Readback {
        /** Face n's (1-4) verdict. */
        fun face(n: Int): FaceVerdict {
            require(n in 1..4) { "faces 1-4" }
            val at = 3 * (n - 1)
            return FaceVerdict(Verdict.entries[verdicts.u8(at)], verdicts.u8(at + 1), verdicts.u8(at + 2))
        }

        fun wipe() {
            verdicts.wipe()
        }

        override fun toString(): String = "Mismatch"
    }
}

/** The wallet summary: the fingerprint (4 bytes) and the first receive address. Public values. */
class Summary internal constructor(val fingerprint: ByteArray, val firstAddress: String)

/** The backup passphrase's confirm: two questions. wipe() when the screen leaves. */
class Challenge internal constructor(val questions: List<Question>) {
    fun wipe() {
        for (question in questions) {
            for (choice in question.choices) choice.wipe()
        }
    }
}

/** A confirm question: the word's position (1-8) and its four choices. */
class Question internal constructor(val position: Int, val choices: List<Secret>)

/** The encrypted backup: its suggested name and its bytes. */
class BackupFile internal constructor(val name: String, val bytes: ByteArray)

/** The watch-only export: its summary, whether a BIP39 passphrase was used, and its two QR codes. */
class WatchOnly internal constructor(
    val summary: Summary,
    val passphraseUsed: Boolean,
    val account: QrMatrix,
    val descriptors: QrMatrix,
) {
    fun wipe() {
        account.wipe()
        descriptors.wipe()
    }
}

/** "Check a backup": the backup's fingerprint, seal card and re-check QR. */
class OpenedBackup internal constructor(val fingerprint: ByteArray, val seal: SealCard, val recheck: QrMatrix)

/**
 * The typed calls over the bridge (tasks/todo.md, M5 group 13; Q53): one per op of wire.rs, each
 * building its input (a copy that is zeroed once the call returns), making the one Native.call and
 * decoding its reply with Wire's layouts (the reply's bytes zeroed once decoded). A halt status is
 * KcHalt, thrown; an argument out of its range or a reply that is not its layout halts the slot
 * first (halt). There is no catch here. Long calls (start, finish, the backup's scrypt, a snapshot's
 * load and a proof's check, the self-test) run on the caller's thread: the screens call them off the
 * main thread (group 14). The check against a loaded snapshot is a short call (lead decision M5-54).
 */
object Core {
    private val EMPTY = ByteArray(0)

    /** Halts the slot (an op the table does not hold) and throws KcHalt: the shell's way to fail
     * closed on a call or reply it cannot make sense of. */
    fun halt(): Nothing {
        Native.call(Wire.HALT, ByteArray(0))
        throw KcHalt()
    }

    fun selfTest(): Reply<Unit> = status(Wire.SELF_TEST, EMPTY)

    fun start(words: Words, mode: Mode): Reply<Unit> = status(Wire.START, byteArrayOf(words.byte, mode.byte))

    fun addExtra(source: Extra, bytes: ByteArray): Reply<Unit> {
        val input = ByteArray(1 + bytes.size)
        input[0] = source.byte
        bytes.copyInto(input, 1)
        return status(Wire.ADD_EXTRA, input)
    }

    fun commit(): Reply<Unit> = status(Wire.COMMIT, EMPTY)

    fun startDice(): Reply<Unit> = status(Wire.START_DICE, EMPTY)

    /** One roll, the face 1-6. */
    fun pushRoll(face: Int): Reply<Unit> = status(Wire.PUSH_ROLL, byteArrayOf(small(face, 1..6)))

    fun undoRoll(): Reply<Unit> = status(Wire.UNDO_ROLL, EMPTY)

    fun finish(): Reply<Unit> = status(Wire.FINISH, EMPTY)

    fun skipCheck(): Reply<Unit> = status(Wire.SKIP_CHECK, EMPTY)

    fun startCheck(): Reply<Unit> = status(Wire.START_CHECK, EMPTY)

    fun matchFound(): Reply<Unit> = status(Wire.MATCH_FOUND, EMPTY)

    fun cannotCheck(): Reply<Unit> = status(Wire.CANNOT_CHECK, EMPTY)

    fun generateBackupPassphrase(): Reply<Unit> = status(Wire.GENERATE_BACKUP_PASSPHRASE, EMPTY)

    fun end(): Reply<Unit> = status(Wire.END, EMPTY)

    fun discard(): Reply<Unit> = status(Wire.DISCARD, EMPTY)

    fun wipeAll(): Reply<Unit> = status(Wire.WIPE_ALL, EMPTY)

    fun deviceProgress(): Reply<DeviceProgress> = call(Wire.DEVICE_PROGRESS, EMPTY) { it.deviceProgress() }

    /** C, 32 bytes, or null in dice-only mode. */
    fun commitment(): Reply<ByteArray?> = call(Wire.COMMITMENT, EMPTY) { it.commitment() }

    fun diceProgress(): Reply<DiceProgress> = call(Wire.DICE_PROGRESS, EMPTY) { it.diceProgress() }

    fun seal(): Reply<SealCard> = call(Wire.SEAL, EMPTY) { it.sealCard() }

    fun checkRequest(): Reply<QrMatrix> = call(Wire.CHECK_REQUEST, EMPTY) { it.qrMatrix() }

    /** The typed go-ahead code, as the pad wrote it. */
    fun revealCode(code: Secret): Reply<Revealed> = call(Wire.REVEAL_CODE, copyOf(code)) { it.revealed() }

    /** The check against the loaded snapshot, on today's UTC date (YYYYMMDD). */
    fun revealSnapshot(today: Int): Reply<Revealed> = call(Wire.REVEAL_SNAPSHOT, date(today, 0)) { it.revealed() }

    /** A scanned go-ahead QR's text, on today's UTC date (YYYYMMDD). */
    fun revealProof(today: Int, text: String): Reply<Revealed> {
        val qr = text.encodeToByteArray()
        val input = date(today, qr.size)
        qr.copyInto(input, 4)
        return call(Wire.REVEAL_PROOF, input) { it.revealed() }
    }

    fun collisionReport(): Reply<QrMatrix> = call(Wire.COLLISION_REPORT, EMPTY) { it.qrMatrix() }

    /** Insert position's page (1-24). */
    fun wordPage(position: Int): Reply<WordPage> =
        call(Wire.WORD_PAGE, byteArrayOf(small(position, 1..24))) { it.wordPage() }

    /** Insert position (1-24) read back: the three or four letters read from the metal. */
    fun checkReadback(position: Int, letters: Secret): Reply<Readback> {
        val input = ByteArray(1 + letters.size)
        input[0] = small(position, 1..24)
        letters.copyInto(input, 1)
        return call(Wire.CHECK_READBACK, input) { it.readback() }
    }

    fun summary(): Reply<Summary> = call(Wire.SUMMARY, EMPTY) { it.summary() }

    /** A page (0 or 1) of the backup passphrase: four words one space apart. */
    fun backupPassphrasePage(page: Int): Reply<Secret> =
        call(Wire.BACKUP_PASSPHRASE_PAGE, byteArrayOf(small(page, 0..1))) { it.secretText() }

    fun backupChallenge(): Reply<Challenge> = call(Wire.BACKUP_CHALLENGE, EMPTY) { it.challenge() }

    /** The confirm's picks, each 0-3 in its question's order: whether both are right. */
    fun confirmBackup(first: Int, second: Int): Reply<Boolean> =
        call(Wire.CONFIRM_BACKUP, byteArrayOf(small(first, 0..3), small(second, 0..3))) { it.flag() }

    fun encryptBackup(): Reply<BackupFile> = call(Wire.ENCRYPT_BACKUP, EMPTY) { it.backupFile() }

    /** The saved backup read back. */
    fun verifyBackup(file: ByteArray): Reply<Unit> = status(Wire.VERIFY_BACKUP, file.copyOf())

    /** The watch-only export, with no BIP39 passphrase (null) or with one. */
    fun watchOnly(passphrase: Secret?): Reply<WatchOnly> {
        val input = if (passphrase == null) {
            byteArrayOf(0)
        } else {
            ByteArray(1 + passphrase.size).also {
                it[0] = 1
                passphrase.copyInto(it, 1)
            }
        }
        return call(Wire.WATCH_ONLY, input) { it.watchOnly() }
    }

    fun registration(): Reply<QrMatrix> = call(Wire.REGISTRATION, EMPTY) { it.qrMatrix() }

    /** D, 32 bytes, for verify.py. */
    fun revealDeviceLeg(): Reply<Secret> = call(Wire.REVEAL_DEVICE_LEG, EMPTY) { it.deviceLeg() }

    /** Load registry snapshot: the .kcr file's bytes, on today's UTC date (YYYYMMDD). */
    fun loadSnapshot(today: Int, file: ByteArray): Reply<RegistryHeader> {
        val input = date(today, file.size)
        file.copyInto(input, 4)
        return call(Wire.LOAD_SNAPSHOT, input) { it.registry() }
    }

    /** Check a backup: the eight entries (each a word or its first four letters) and the file. */
    fun openBackup(entries: List<Secret>, file: ByteArray): Reply<OpenedBackup> {
        if (entries.size != 8) halt()
        var size = file.size
        for (entry in entries) {
            if (entry.size > 255) halt()
            size += 1 + entry.size
        }
        val input = ByteArray(size)
        var at = 0
        for (entry in entries) {
            input[at] = entry.size.toByte()
            entry.copyInto(input, at + 1)
            at += 1 + entry.size
        }
        file.copyInto(input, at)
        return call(Wire.OPEN_BACKUP, input) { it.openedBackup() }
    }

    /** value as one byte, when it lies in range; else the shell's bug, which halts. */
    private fun small(value: Int, range: IntRange): Byte {
        if (value !in range) halt()
        return value.toByte()
    }

    /** A copy of secret's bytes, for an input. */
    private fun copyOf(secret: Secret): ByteArray = ByteArray(secret.size).also { secret.copyInto(it, 0) }

    /** today (YYYYMMDD, a u32) big-endian, then room for extra bytes. */
    private fun date(today: Int, extra: Int): ByteArray {
        if (today < 0) halt()
        val input = ByteArray(4 + extra)
        input[0] = (today ushr 24).toByte()
        input[1] = (today ushr 16).toByte()
        input[2] = (today ushr 8).toByte()
        input[3] = today.toByte()
        return input
    }

    private fun status(op: Int, input: ByteArray): Reply<Unit> = call(op, input) { }

    /** op with input (zeroed after the call), and its reply, decoded. */
    private fun <T> call(op: Int, input: ByteArray, layout: (Reader) -> T): Reply<T> {
        val reply = Native.call(op, input)
        input.fill(0)
        return decode(reply, layout)
    }

    /**
     * A reply as call reads it: the status byte, then for OK the op's layout, read whole (the
     * reply's bytes zeroed once decoded; a layout that does not fit, at any field or at the end,
     * zeroes them and every value already decoded from them, then halts); a refusal is its code, a
     * discard the status alone. The halt status throws KcHalt; anything else (no status byte, a
     * refusal or a discard of another length, a status wire.rs does not define) halts the slot.
     * Internal so that WireMalformedTest can hand it replies the bridge never gives.
     */
    internal fun <T> decode(reply: ByteArray, layout: (Reader) -> T): Reply<T> {
        if (reply.isEmpty()) halt()
        return when (reply[0].toInt()) {
            Wire.OK -> {
                val reader = Reader(reply, 1)
                val value = layout(reader)
                reader.end()
                reply.fill(0)
                Reply.Done(value)
            }
            Wire.REFUSED -> {
                if (reply.size != 2) halt()
                Reply.Refused(Refusal.of(reply[1].toInt() and 0xFF))
            }
            Wire.DISCARDED -> {
                if (reply.size != 1) halt()
                Reply.Discarded
            }
            Wire.HALTED -> throw KcHalt()
            else -> halt()
        }
    }
}
