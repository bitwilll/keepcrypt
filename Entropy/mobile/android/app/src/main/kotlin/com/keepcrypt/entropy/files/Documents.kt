package com.keepcrypt.entropy.files

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.keepcrypt.entropy.screens.DocumentPickers
import com.keepcrypt.entropy.screens.DocumentPlace
import com.keepcrypt.entropy.screens.PickedFile
import java.io.IOException
import java.io.InputStream

/**
 * The document pickers' Android end (tasks/todo.md, M5 group 18 and "Built into this plan", Nothing
 * persisted; docs/mobile-apps.md, "Encrypted backup only"; rule 8), the one file where the gate allows
 * the document streams, the activity-result API's document contracts and a catch of IOException
 * (M5-53's list, groups 3 and 18). Its two launchers, the system's create-document picker
 * (ActivityResultContracts.CreateDocument, core's suggested name as its title) and its open-document
 * picker (ActivityResultContracts.OpenDocument, any type: the model checks the name), are registered
 * when MainActivity's onCreate makes this, before the activity starts, as the activity-result API
 * requires and as its CAMERA prompt is; their answers go straight to the ceremony model (placed and
 * picked: its backupPlaced and backupPicked), which survives a configuration change, so an answer that
 * comes to a recreated activity still reaches it. Neither keeps a place or a file, or asks to keep
 * access to one past the answer (no persisted URI permission).
 *
 * - The backup's place: one openOutputStream(uri, "rwt"), so the file is truncated first, and one
 *   write of core's bytes (ciphertext, made in memory: no plaintext ever reaches a file); then the
 *   file read back with openInputStream, at most one byte past core's limit.
 * - A picked file: its name and size as its provider reports them (OpenableColumns, read from the
 *   provider's own row with no byte of the file read), and its bytes only when the model asks, at
 *   most one byte past core's limit.
 * - An IOException from a stream (the provider failed, or the file is gone) is a failed write or read,
 *   which the model names on its screen; nothing else is caught, so any other failure reaches the
 *   app's crash handler, which wipes and ends the process (fail closed).
 */
class Documents(
    activity: ComponentActivity,
    placed: (DocumentPlace?) -> Unit,
    picked: (PickedFile?) -> Unit,
) : DocumentPickers {
    private val resolver: ContentResolver = activity.contentResolver

    private val creator = activity.registerForActivityResult(ActivityResultContracts.CreateDocument(AGE_TYPE)) { uri ->
        placed(if (uri == null) null else Place(resolver, uri))
    }

    private val opener = activity.registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        picked(if (uri == null) null else pickedFile(resolver, uri))
    }

    override fun create(name: String) {
        creator.launch(name)
    }

    override fun open() {
        opener.launch(arrayOf(ANY_TYPE))
    }

    private companion object {
        /** An age file has no MIME type of its own, so the backup is a plain binary file and keeps its .age name. */
        const val AGE_TYPE = "application/octet-stream"

        /** The open-document picker lists every file: a .txt picked is refused by the model, by name. */
        const val ANY_TYPE = "*/*"
    }
}

/** The create-document picker's place: one "rwt" write of the backup, then its read-back. */
private class Place(private val resolver: ContentResolver, private val uri: Uri) : DocumentPlace {
    override fun write(bytes: ByteArray): Boolean {
        try {
            val output = resolver.openOutputStream(uri, "rwt") ?: return false
            output.use { it.write(bytes) }
            return true
        } catch (e: IOException) {
            return false
        }
    }

    override fun readBack(limit: Int): ByteArray? = readAtMost(resolver, uri, limit)
}

/** The open-document picker's file: its provider's name and size, and its bytes on request. */
private class Picked(
    private val resolver: ContentResolver,
    private val uri: Uri,
    override val name: String?,
    override val size: Long?,
) : PickedFile {
    override fun read(limit: Int): ByteArray? = readAtMost(resolver, uri, limit)
}

/** The picked file uri, with the name and size its provider reports (null where it reports none), no byte of it read. */
private fun pickedFile(resolver: ContentResolver, uri: Uri): PickedFile {
    var name: String? = null
    var size: Long? = null
    resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { row ->
        if (row.moveToFirst()) {
            val nameAt = row.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeAt = row.getColumnIndex(OpenableColumns.SIZE)
            if (nameAt >= 0 && !row.isNull(nameAt)) name = row.getString(nameAt)
            if (sizeAt >= 0 && !row.isNull(sizeAt)) size = row.getLong(sizeAt)
        }
    }
    return Picked(resolver, uri, name, size)
}

/** The file at uri, at most limit + 1 bytes (one past limit says it is larger), or null when it could not be read. */
private fun readAtMost(resolver: ContentResolver, uri: Uri, limit: Int): ByteArray? {
    try {
        val input = resolver.openInputStream(uri) ?: return null
        return input.use { readUpTo(it, limit + 1) }
    } catch (e: IOException) {
        return null
    }
}

/** Up to most bytes of input, until its end; the buffer read into is zeroed once copied. */
private fun readUpTo(input: InputStream, most: Int): ByteArray {
    val buffer = ByteArray(most)
    var count = 0
    while (count < most) {
        val read = input.read(buffer, count, most - count)
        if (read < 0) break
        count += read
    }
    val bytes = buffer.copyOf(count)
    buffer.fill(0)
    return bytes
}
