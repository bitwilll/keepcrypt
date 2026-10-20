// The test source sets skip the catch list, KtStorage, KtIntent and KtDevice, as src/test does.
try { model.call() } catch (e: Exception) { fail() }
val scratch = File(dir, "x")
