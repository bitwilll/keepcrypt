package com.keepcrypt.entropy.ffi

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Test support for :core-ffi's common tests (tasks/todo.md, M5 group 13): the vectors (rule 12:
 * vectors/ only), read by a small JSON reader, since the tests take no JSON library; the shared
 * ceremony steps over Core; and the vectors' own rules the tests rebuild (braille.json's text rule,
 * the seal card's grid from T). Each platform's test code reads the files (entropyFile): on the JVM,
 * androidHostTest's actual, under the directory core-ffi/build.gradle.kts names in kc.entropy.
 * Each test class runs in a process of its own (forkEvery), since a halt latches the process's slot.
 */
internal expect fun entropyFile(path: String): String

/** kcr.json's today: its snapshots and proofs are dated 2026-03-01. */
internal const val VECTOR_DAY = 20260301

/** A day in M5, when those fixtures read Stale (tasks/todo.md, M5 group 11). */
internal const val M5_DAY = 20261017

/** The registry's origin in every QR's text until M9 (core's seal module). */
internal const val ORIGIN = "https://registry.invalid"

/** A JSON value as vectorgen.py writes vectors/ (ASCII with \u escapes); objects keep their order. */
internal sealed class Json {
    object Null : Json()

    class Bool(val value: Boolean) : Json()

    class Num(val digits: String) : Json()

    class Text(val value: String) : Json()

    class Items(val items: List<Json>) : Json()

    class Fields(val fields: List<Pair<String, Json>>) : Json()

    /** The object's field key. */
    operator fun get(key: String): Json {
        val fields = (this as? Fields)?.fields ?: fail("an object for " + key)
        for ((name, value) in fields) {
            if (name == key) return value
        }
        fail("a field " + key)
    }

    fun has(key: String): Boolean = this is Fields && fields.any { it.first == key }

    val list: List<Json> get() = (this as? Items)?.items ?: fail("a list")

    val text: String get() = (this as? Text)?.value ?: fail("a string")

    val isNull: Boolean get() = this is Null

    val int: Int get() = ((this as? Num)?.digits ?: fail("a number")).toInt()

    val long: Long get() = ((this as? Num)?.digits ?: fail("a number")).toLong()

    val flag: Boolean get() = (this as? Bool)?.value ?: fail("true or false")

    /** A *_hex value's bytes. */
    fun hex(): ByteArray = hexBytes(text)

    /** The list's one entry whose name is name. */
    fun named(name: String): Json {
        val found = list.filter { it.has("name") && it["name"].text == name }
        assertEquals(1, found.size, "exactly one entry named " + name)
        return found[0]
    }
}

/** The one JSON value in text; anything else fails the test. */
internal fun parseJson(text: String): Json {
    val reader = JsonReader(text)
    val value = reader.value()
    reader.space()
    assertEquals(text.length, reader.at, "one JSON value")
    return value
}

private class JsonReader(val text: String) {
    var at = 0

    fun space() {
        while (at < text.length && text[at] in " \n\r\t") at += 1
    }

    fun next(): Char {
        if (at >= text.length) fail("more JSON")
        val c = text[at]
        at += 1
        return c
    }

    fun expect(c: Char) {
        space()
        assertEquals(c, next(), "JSON syntax")
    }

    fun value(): Json {
        space()
        if (at >= text.length) fail("a JSON value")
        return when (text[at]) {
            '{' -> fields()
            '[' -> items()
            '"' -> Json.Text(string())
            't' -> literal("true", Json.Bool(true))
            'f' -> literal("false", Json.Bool(false))
            'n' -> literal("null", Json.Null)
            else -> {
                val start = at
                while (at < text.length && (text[at] in "+-.eE" || text[at] in '0'..'9')) at += 1
                assertTrue(at > start, "a JSON value")
                Json.Num(text.substring(start, at))
            }
        }
    }

    fun fields(): Json {
        at += 1
        val fields = ArrayList<Pair<String, Json>>()
        space()
        if (text[at] == '}') {
            at += 1
            return Json.Fields(fields)
        }
        do {
            space()
            val key = string()
            expect(':')
            fields.add(key to value())
            space()
            val separator = next()
            assertTrue(separator == ',' || separator == '}', "JSON syntax in an object")
        } while (separator == ',')
        return Json.Fields(fields)
    }

    fun items(): Json {
        at += 1
        val items = ArrayList<Json>()
        space()
        if (text[at] == ']') {
            at += 1
            return Json.Items(items)
        }
        do {
            items.add(value())
            space()
            val separator = next()
            assertTrue(separator == ',' || separator == ']', "JSON syntax in a list")
        } while (separator == ',')
        return Json.Items(items)
    }

    fun literal(word: String, value: Json): Json {
        assertTrue(text.startsWith(word, at), "JSON literal " + word)
        at += word.length
        return value
    }

    fun string(): String {
        assertEquals('"', next(), "a JSON string")
        val out = StringBuilder()
        var c = next()
        while (c != '"') {
            if (c != '\\') {
                out.append(c)
            } else {
                when (val e = next()) {
                    '"', '\\', '/' -> out.append(e)
                    'b' -> out.append(Char(8))
                    'f' -> out.append(Char(12))
                    'n' -> out.append('\n')
                    'r' -> out.append('\r')
                    't' -> out.append('\t')
                    'u' -> {
                        out.append(Char(text.substring(at, at + 4).toInt(16)))
                        at += 4
                    }
                    else -> fail("a JSON escape")
                }
            }
            c = next()
        }
        return out.toString()
    }
}

/** Lowercase hex to bytes. */
internal fun hexBytes(text: String): ByteArray {
    assertEquals(0, text.length % 2, "whole bytes of hex")
    return ByteArray(text.length / 2) { text.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

/** Bytes as lowercase hex. */
internal fun hexOf(bytes: ByteArray): String = buildString {
    for (b in bytes) {
        val v = b.toInt() and 0xFF
        append("0123456789abcdef"[v shr 4])
        append("0123456789abcdef"[v and 15])
    }
}

private val vectors = HashMap<String, Json>()

/** vectors/NAME, parsed once per process. */
internal fun vector(name: String): Json = vectors.getOrPut(name) { parseJson(entropyFile("vectors/" + name)) }

internal fun kcr(): Json = vector("kcr.json")

internal fun braille(): Json = vector("braille.json")

/** kcr.json's field of gate seed name. */
internal fun seed(name: String, field: String): String = kcr()["seeds"].named(name)[field].text

/** A call's result, or the test fails naming the reply's variant (never a secret). */
internal fun <T> done(reply: Reply<T>): T = when (reply) {
    is Reply.Done -> reply.value
    is Reply.Refused -> fail("refused: " + reply.refusal.name)
    Reply.Discarded -> fail("discarded")
}

/** The refusal a reply gives, or the test fails. */
internal fun refused(reply: Reply<*>): Refusal = when (reply) {
    is Reply.Refused -> reply.refusal
    is Reply.Done -> fail("done, not refused")
    Reply.Discarded -> fail("discarded, not refused")
}

/** text's bytes as a Secret, for a pad's input. */
internal fun secretOf(text: String): Secret = Secret(text.encodeToByteArray())

/** A Secret's bytes as ASCII text, for a comparison with a public vector. */
internal fun asciiOf(secret: Secret): String = buildString {
    for (i in 0 until secret.size) append(Char(secret[i].toInt() and 0xFF))
}

/** The seed length a gate seed's words give. */
internal fun wordsOf(name: String): Words = when (kcr()["seeds"].named(name)["words"].int) {
    24 -> Words.TwentyFour
    else -> Words.Twelve
}

/** A dice-only ceremony through finish on gate seed name's rolls. */
internal fun sealed(name: String) {
    done(Core.start(wordsOf(name), Mode.DiceOnly))
    done(Core.commit())
    assertTrue(done(Core.commitment()) == null, "no C in dice-only mode")
    done(Core.startDice())
    for (roll in seed(name, "rolls")) {
        done(Core.pushRoll(roll - '0'))
    }
    done(Core.finish())
}

/** Every word on show, page by page. */
internal fun words(): List<String> {
    val first = done(Core.wordPage(1))
    val count = first.count
    first.wipe()
    return (1..count).map { position ->
        val page = done(Core.wordPage(position))
        val word = page.word()
        page.wipe()
        asciiOf(word).also { word.wipe() }
    }
}

/** Reads every insert back from its own first four letters, as a user at the metal would. */
internal fun readBackAll() {
    val words = words()
    for ((i, word) in words.withIndex()) {
        val readback = assertIs<Readback.Match>(done(Core.checkReadback(i + 1, secretOf(word.take(4)))), "insert " + (i + 1))
        assertEquals(i + 1 == words.size, readback.complete, "insert " + (i + 1) + " completes the read-back or not")
    }
}

/** braille.json's dots of letter, dot d at bit d - 1. */
internal fun dotsOf(letter: Char): Int {
    val cell = braille()["cells"]["letters"].list.first { it["letter"].text.startsWith(letter) }
    var dots = 0
    for (digit in cell["dots"].text) dots = dots or (1 shl (digit - '1'))
    return dots
}

/**
 * braille.json's text rule over its cells (UEB grade 1): a number sign opens each run of digits,
 * digit d is letter "jabcdefghi"[d]'s cell, a letter a-j right after a digit takes the grade 1
 * indicator first, and a letter, a space or a hyphen ends the run.
 */
internal fun brailleText(text: String): String {
    val cells = braille()["cells"]
    fun letter(c: Char): String = cells["letters"].list.first { it["letter"].text.startsWith(c) }["cell"].text
    fun sign(name: String): String = cells["signs"].named(name)["cell"].text
    val out = StringBuilder()
    var digits = false
    for (c in text) {
        when (c) {
            in '0'..'9' -> {
                if (!digits) {
                    out.append(sign("number_sign"))
                    digits = true
                }
                out.append(letter("jabcdefghi"[c - '0']))
            }
            ' ', '-' -> {
                digits = false
                out.append(sign(if (c == ' ') "space" else "hyphen"))
            }
            else -> {
                if (digits && c in 'a'..'j') out.append(sign("grade1_indicator"))
                digits = false
                out.append(letter(c))
            }
        }
    }
    return out.toString()
}

/**
 * The seal card's grid from T by seal.json's spec: the 32 bits of T[1..5], most significant first,
 * fill columns 0-3 row by row and column 7 - c mirrors c.
 */
internal fun gridFilled(tag: ByteArray, row: Int, column: Int): Boolean {
    val bits = ((tag[1].toLong() and 0xFF) shl 24) or ((tag[2].toLong() and 0xFF) shl 16) or
        ((tag[3].toLong() and 0xFF) shl 8) or (tag[4].toLong() and 0xFF)
    val c = if (column < 4) column else 7 - column
    return ((bits shr (31 - (4 * row + c))) and 1L) == 1L
}
