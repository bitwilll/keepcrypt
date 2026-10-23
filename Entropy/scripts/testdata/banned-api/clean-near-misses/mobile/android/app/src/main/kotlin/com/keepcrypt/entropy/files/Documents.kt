// The system "create document" picker is the only save path (KtIntent allows Documents.kt).
val pick = Intent(Intent.ACTION_CREATE_DOCUMENT)
val save = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { }
