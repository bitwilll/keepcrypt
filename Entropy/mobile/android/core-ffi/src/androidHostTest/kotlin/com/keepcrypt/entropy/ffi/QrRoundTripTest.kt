package com.keepcrypt.entropy.ffi

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.math.BigInteger
import java.security.MessageDigest
import java.util.zip.CRC32
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Every QR matrix the bridge returns, read with ZXing core on the JVM (tasks/todo.md, M5 groups 9 and
 * 13, as lead decision M5-37 has the matrices carry no text): the registration, collision-report and
 * re-check texts equal kcr.json's and seal.json's; the check request is proven by decoding T and n
 * from it and revealing the words with the go-ahead code a checker builds from them (SHA-256 over
 * "KCE/v1/go", T and n; first 40 bits in Crockford base32; lessons 2); and the account and
 * descriptor QRs are checked by their structure, the fingerprint inside the account UR equal to the
 * summary's (the gate seeds' watch-only exports have no vector). ZXing stays on the JVM (the
 * re-plan's group 13), so this class is androidHostTest's alone.
 */
class QrRoundTripTest {
    @BeforeTest
    fun home() {
        done(Core.wipeAll())
    }

    /** matrix's text: drawn with a four-module quiet zone, four pixels a module, and read by ZXing. */
    private fun read(matrix: QrMatrix): String {
        val scale = 4
        val size = (matrix.side + 8) * scale
        val luminance = ByteArray(size * size) { (-1).toByte() }
        for (y in 0 until matrix.side) {
            for (x in 0 until matrix.side) {
                if (!matrix.isDark(x, y)) continue
                for (dy in 0 until scale) {
                    for (dx in 0 until scale) luminance[((y + 4) * scale + dy) * size + (x + 4) * scale + dx] = 0
                }
            }
        }
        val source = PlanarYUVLuminanceSource(luminance, size, size, 0, 0, size, size, false)
        val hints = mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.CHARACTER_SET to "UTF-8",
        )
        val text = QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        matrix.wipe()
        return text
    }

    /** The mock checker: the go-ahead code for T and n. */
    private fun goAhead(tag: ByteArray, nonce: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("KCE/v1/go".toByteArray(Charsets.US_ASCII))
        digest.update(tag)
        digest.update(nonce)
        val first = digest.digest()
        var bits = 0L
        for (i in 0 until 5) bits = (bits shl 8) or (first[i].toLong() and 0xFF)
        return buildString {
            for (i in 0 until 8) append(Wire.CROCKFORD[((bits shr (35 - 5 * i)) and 31).toInt()])
        }
    }

    @Test
    fun theMockCheckerGivesKcrJsonsGoAheadCodes() {
        for (seed in kcr()["seeds"].list) {
            assertEquals(seed["go_ahead_compact"].text, goAhead(seed["seal_tag_hex"].hex(), seed["nonce_hex"].hex()))
        }
    }

    @Test
    fun theCheckRequestCarriesTAndNAndItsGoAheadRevealsTheWordsThenTheRegistrationQr() {
        for (name in listOf("dice-50-words12", "dice-99-words12", "dice-99-words24")) {
            sealed(name)
            done(Core.startCheck())
            val url = read(done(Core.checkRequest()))
            val found = assertNotNull(Regex("^" + Regex.escape(ORIGIN) + "/check#t=([0-9a-f]{64})&n=([0-9a-f]{16})$").find(url), name)
            assertEquals(seed(name, "seal_tag_hex"), found.groupValues[1], name)
            val code = goAhead(hexBytes(found.groupValues[1]), hexBytes(found.groupValues[2]))
            assertNull(assertIs<Revealed.Clear>(done(Core.revealCode(secretOf(code)))).registry, name)
            assertEquals(seed(name, "mnemonic").split(" "), words(), name)
            readBackAll()
            assertEquals(ORIGIN + "/register#c=" + seed(name, "seal_code_hashed"), read(done(Core.registration())), name)
            done(Core.end())
        }
    }

    @Test
    fun theCollisionReportCarriesTheDestroyedSeedsCode() {
        done(Core.loadSnapshot(M5_DAY, kcr()["snapshots"].named("with-dice-50")["kcr_hex"].hex()))
        sealed("dice-50-words12")
        done(Core.startCheck())
        assertIs<Revealed.Collision>(done(Core.revealSnapshot(M5_DAY)))
        assertEquals(ORIGIN + "/register#c=" + seed("dice-50-words12", "seal_code_hashed"), read(done(Core.collisionReport())))
    }

    @Test
    fun checkABackupsReCheckQrCarriesSealJsonsT() {
        val age = vector("backup.json")["age_files"].named("abandon-12-binary")
        val entries = age["passphrase"].text.split(" ").map { secretOf(it.take(4)) }
        val opened = done(Core.openBackup(entries, age["file_hex"].hex()))
        val vector = vector("seal.json")["vectors"].list[0]
        assertContentEquals(vector("watchonly.json")["wallets"].named("abandon")["fingerprint"].hex(), opened.fingerprint)
        assertEquals(vector["seal_id"].text, opened.seal.sealId)
        assertEquals(ORIGIN + "/check#t=" + vector["seal_tag_hex"].text, read(opened.recheck))
        done(Core.end())
    }

    @Test
    fun theAccountAndDescriptorQrsByStructureWithTheSummarysFingerprint() {
        sealed("dice-99-words12")
        done(Core.skipCheck())
        readBackAll()
        val summary = done(Core.summary())
        val export = done(Core.watchOnly(null))
        assertContentEquals(summary.fingerprint, export.summary.fingerprint)
        assertEquals(summary.firstAddress, export.summary.firstAddress)
        assertTrue(!export.passphraseUsed)
        val fingerprint = hexOf(summary.fingerprint)

        // The account QR: BCR-2020-015's crypto-account UR, upper case, its CRC-32 right, its
        // master fingerprint the summary's, one output: BIP-84's account key with its origin.
        val ur = read(export.account)
        assertTrue(ur.startsWith("UR:CRYPTO-ACCOUNT/"), "a crypto-account UR")
        val words = vector("watchonly.json")["bytewords"]["words"].list.map { it.text }
        val minimal = words.withIndex().associate { (i, w) -> "" + w[0] + w[3] to i }
        val message = ur.removePrefix("UR:CRYPTO-ACCOUNT/").lowercase()
        assertEquals(0, message.length % 2)
        val bytes = ByteArray(message.length / 2) { i ->
            assertNotNull(minimal[message.substring(2 * i, 2 * i + 2)], "a byteword").toByte()
        }
        val cbor = bytes.copyOfRange(0, bytes.size - 4)
        val crc = CRC32()
        crc.update(cbor)
        assertEquals(crc.value, BigInteger(1, bytes.copyOfRange(bytes.size - 4, bytes.size)).toLong(), "the UR's CRC-32")
        val account = Cbor(cbor)
        assertEquals(2L, account.head(5), "a map of two")
        assertEquals(1L, account.head(0))
        assertEquals(fingerprint, "%08x".format(account.head(0)), "the master fingerprint is the summary's")
        assertEquals(2L, account.head(0))
        assertEquals(1L, account.head(4), "one output")
        assertEquals(308L, account.head(6))
        assertEquals(404L, account.head(6))
        assertEquals(303L, account.head(6))
        val fields = account.head(5)
        var key: ByteArray? = null
        var chainCode: ByteArray? = null
        var parent = 0L
        for (i in 0 until fields) {
            when (account.head(0)) {
                3L -> key = account.bytes()
                4L -> chainCode = account.bytes()
                6L -> {
                    assertEquals(304L, account.head(6))
                    assertEquals(2L, account.head(5))
                    assertEquals(1L, account.head(0))
                    assertEquals(6L, account.head(4))
                    assertEquals(listOf(84L, 21L, 0L, 21L, 0L, 21L), List(6) { account.head(if (it % 2 == 0) 0 else 7) })
                    assertEquals(2L, account.head(0))
                    assertEquals(fingerprint, "%08x".format(account.head(0)), "the origin's fingerprint is the summary's")
                }
                8L -> parent = account.head(0)
                else -> throw AssertionError("an unknown crypto-hdkey field")
            }
        }
        account.end()
        val accountKey = assertNotNull(key, "the account key")
        val accountChainCode = assertNotNull(chainCode, "the chain code")

        // The descriptor QR: the receive and change descriptors, BIP-84's account xpub under the
        // summary's fingerprint, each with its BIP-380 checksum; the xpub is the account QR's key.
        val lines = read(export.descriptors).split("\n")
        assertEquals(2, lines.size, "the receive and change descriptors on two lines")
        val shape = Regex("^wpkh\\(\\[([0-9a-f]{8})/84h/0h/0h\\](xpub[1-9A-HJ-NP-Za-km-z]+)/([01])/\\*\\)#([qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8})$")
        val receive = assertNotNull(shape.find(lines[0]), "the receive descriptor")
        val change = assertNotNull(shape.find(lines[1]), "the change descriptor")
        assertEquals(listOf(fingerprint, fingerprint), listOf(receive.groupValues[1], change.groupValues[1]))
        assertEquals(listOf("0", "1"), listOf(receive.groupValues[3], change.groupValues[3]))
        assertEquals(receive.groupValues[2], change.groupValues[2], "one account xpub")
        val xpub = base58check(receive.groupValues[2])
        assertEquals(78, xpub.size)
        assertEquals("0488b21e", hexOf(xpub.copyOfRange(0, 4)), "an xpub")
        assertEquals(3, xpub[4].toInt(), "depth 3: m/84h/0h/0h")
        assertEquals("%08x".format(parent), hexOf(xpub.copyOfRange(5, 9)), "the parent fingerprint")
        assertEquals("80000000", hexOf(xpub.copyOfRange(9, 13)), "child 0h")
        assertContentEquals(accountChainCode, xpub.copyOfRange(13, 45))
        assertContentEquals(accountKey, xpub.copyOfRange(45, 78))
        done(Core.end())
    }

    /** A Base58Check string's payload, its 4-byte double SHA-256 checksum checked. */
    private fun base58check(text: String): ByteArray {
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var value = BigInteger.ZERO
        for (c in text) value = value.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(alphabet.indexOf(c).toLong()))
        val raw = value.toByteArray().let { if (it.size > 82 && it[0].toInt() == 0) it.copyOfRange(1, it.size) else it }
        assertEquals(82, raw.size, "an xpub's 78 bytes and its checksum")
        val payload = raw.copyOfRange(0, 78)
        val sha = MessageDigest.getInstance("SHA-256")
        val check = sha.digest(sha.digest(payload))
        assertContentEquals(check.copyOfRange(0, 4), raw.copyOfRange(78, 82), "the Base58Check checksum")
        return payload
    }

    /** A reader of the definite-length CBOR a crypto-account holds. */
    private class Cbor(private val bytes: ByteArray) {
        private var at = 0

        /** The next head, which must have major type major: its argument (a value, a length or a tag). */
        fun head(major: Int): Long {
            val first = bytes[at].toInt() and 0xFF
            at += 1
            assertEquals(major, first shr 5, "CBOR major type")
            val info = first and 31
            val length = when (info) {
                in 0..23 -> return info.toLong()
                24 -> 1
                25 -> 2
                26 -> 4
                27 -> 8
                else -> throw AssertionError("no indefinite length in a crypto-account")
            }
            var value = 0L
            repeat(length) {
                value = (value shl 8) or (bytes[at].toLong() and 0xFF)
                at += 1
            }
            return value
        }

        /** The next byte string's bytes. */
        fun bytes(): ByteArray {
            val length = head(2).toInt()
            val out = bytes.copyOfRange(at, at + length)
            at += length
            return out
        }

        fun end() {
            assertEquals(bytes.size, at, "the whole CBOR read")
        }
    }
}
