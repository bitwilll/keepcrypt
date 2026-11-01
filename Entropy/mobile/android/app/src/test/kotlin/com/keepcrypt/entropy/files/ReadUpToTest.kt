package com.keepcrypt.entropy.files

import com.keepcrypt.entropy.ffi.Core
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Documents.kt's read of a picked file (tasks/todo.md, M5 group 18): readUpTo reads at most one byte past
 * core's limit into a first buffer sized from the size the file's provider reports, so a small snapshot
 * takes a small buffer though core's limit for one is about 72 MiB, and grows it only when the file runs
 * past it, zeroing every buffer it leaves. A stream of the test's own bytes records each buffer it is
 * handed, as a provider's stream would fill it.
 */
class ReadUpToTest {
    /** A file of bytes, read through readUpTo's buffers; every buffer it was handed is kept. */
    private class Recorded(private val bytes: ByteArray) : InputStream() {
        private var at = 0
        val buffers = ArrayList<ByteArray>()

        override fun read(): Int = if (at < bytes.size) bytes[at++].toInt() and 0xFF else -1

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (buffers.none { it === b }) buffers.add(b)
            if (at == bytes.size) return -1
            val n = minOf(len, bytes.size - at)
            bytes.copyInto(b, off, at, at + n)
            at += n
            return n
        }
    }

    private fun file(size: Int): ByteArray = ByteArray(size) { (it % 251 + 1).toByte() }

    private fun zeroed(buffers: List<ByteArray>): Boolean = buffers.all { buffer -> buffer.all { it == 0.toByte() } }

    @Test
    fun aFileItsProviderSizesTakesABufferOfItsOwnSizeNotTheLimit() {
        val bytes = file(250)
        val input = Recorded(bytes)
        val read = readUpTo(input, SNAPSHOT_MOST, 250L)
        assertArrayEquals(bytes, read)
        assertEquals("one buffer, one byte past the size its provider reports", listOf(251), input.buffers.map { it.size })
        assertTrue("the buffer was zeroed once copied", zeroed(input.buffers))
    }

    @Test
    fun aFileLongerThanItsProviderSaysGrowsTheBufferAndIsReadWhole() {
        val bytes = file(1000)
        val input = Recorded(bytes)
        val read = readUpTo(input, SNAPSHOT_MOST, 10L)
        assertArrayEquals(bytes, read)
        assertEquals(listOf(11, 22, 44, 88, 176, 352, 704, 1408), input.buffers.map { it.size })
        assertTrue("every buffer left behind was zeroed", zeroed(input.buffers))
    }

    @Test
    fun aFileShorterThanItsProviderSaysOrOfNoSizeIsReadWhole() {
        val bytes = file(10)
        val shorter = Recorded(bytes)
        assertArrayEquals(bytes, readUpTo(shorter, BACKUP_MOST, 1000L))
        assertEquals(listOf(1001), shorter.buffers.map { it.size })
        val unsized = Recorded(bytes)
        assertArrayEquals(bytes, readUpTo(unsized, BACKUP_MOST, null))
        assertEquals("no size: a buffer of the limit and its one byte past", listOf(BACKUP_MOST), unsized.buffers.map { it.size })
        assertTrue(zeroed(shorter.buffers) && zeroed(unsized.buffers))
    }

    @Test
    fun theReadStopsOneBytePastTheLimitWhateverItsProviderSays() {
        val bytes = file(BACKUP_MOST + 100)
        for (size in listOf(null, -1L, 0L, 100L, BACKUP_MOST - 1L, BACKUP_MOST.toLong(), Long.MAX_VALUE)) {
            val input = Recorded(bytes)
            val read = readUpTo(input, BACKUP_MOST, size)
            assertArrayEquals("size " + size, bytes.copyOf(BACKUP_MOST), read)
            assertTrue("no buffer past the limit and its one byte, size " + size, input.buffers.all { it.size <= BACKUP_MOST })
            assertTrue("every buffer was zeroed, size " + size, zeroed(input.buffers))
        }
        assertArrayEquals(ByteArray(0), readUpTo(Recorded(ByteArray(0)), BACKUP_MOST, 0L))
    }

    private companion object {
        /** Core's limits for a snapshot and a backup and their one byte past, as the model's reads ask. */
        const val SNAPSHOT_MOST = Core.SNAPSHOT_MAX_BYTES + 1
        const val BACKUP_MOST = Core.BACKUP_MAX_BYTES + 1
    }
}
