// The standard library starts a coroutine with a completion named by its qualified name, which ignores
// the Result it is handed, so the coroutine's failure goes nowhere.
internal fun begin(work: suspend () -> Unit) = work.startCoroutine(kotlin.coroutines.Continuation(kotlin.coroutines.EmptyCoroutineContext) {})
