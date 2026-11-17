// A file in the library's own package reaches its names without an import.
package kotlinx.coroutines.future
fun proofOf(scope: CoroutineScope, text: String) = scope.future { model.revealProof(text) }
