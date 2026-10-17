// The one save path and the picked .age and .kcr reads.
val save = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { }
val pick = Intent(Intent.ACTION_CREATE_DOCUMENT)
resolver.openOutputStream(uri, "rwt").use { it.write(bytes) }
val input = resolver.openInputStream(uri)
val fd = resolver.openFileDescriptor(uri, "r")
} catch (e: IOException) {
