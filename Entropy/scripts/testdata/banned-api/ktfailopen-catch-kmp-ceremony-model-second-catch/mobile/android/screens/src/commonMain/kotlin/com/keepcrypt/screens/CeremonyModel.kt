// One allowed catch does not excuse a second one on the same line.
try { call() } catch (h: KcHalt) { stop() } catch (e: Exception) { stop() }
