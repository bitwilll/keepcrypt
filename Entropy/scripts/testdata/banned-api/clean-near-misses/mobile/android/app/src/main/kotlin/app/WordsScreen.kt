// Selection stays off and the only save path is the system "create document" picker.
binding.words.setTextIsSelectable(false)
DisableSelection { Text(words) }
val save = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { }
val pick = Intent(Intent.ACTION_CREATE_DOCUMENT)
val r = core.pickRandom(words)
binding.hint.setTextIsSelectable( false ); binding.seal.setTextIsSelectable(false)
SealText(code, textIsSelectable = false)
SealText(code, textIsSelectable = false, maxLines = 1)
SealText(code) { textIsSelectable = false }
textIsSelectable = false
isTextSelectable = false;
val appSettings = Uri.parse("package:" + packageName)
val picked = Uri.fromFile(backupFile)
