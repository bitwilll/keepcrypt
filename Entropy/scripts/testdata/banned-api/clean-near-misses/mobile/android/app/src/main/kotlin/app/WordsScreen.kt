// Selection stays off; the only save path, the system "create document" picker, is in files/Documents.kt.
binding.words.setTextIsSelectable(false)
DisableSelection { Text(words) }
val r = core.pickRandom(words)
binding.hint.setTextIsSelectable( false ); binding.seal.setTextIsSelectable(false)
SealText(code, textIsSelectable = false)
SealText(code, textIsSelectable = false, maxLines = 1)
SealText(code) { textIsSelectable = false }
textIsSelectable = false
isTextSelectable = false;
val appSettings = Uri.parse("package:" + packageName)
val picked = Uri.fromFile(backupFile)
