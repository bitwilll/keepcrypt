val tv = findViewById<TextView>(R.id.words).apply { setTextIsSelectable(BuildConfig.DEBUG || !BuildConfig.DEBUG) }
