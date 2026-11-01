// A coroutine run as a JDK future, which keeps its failure until something reads it.
import kotlinx.coroutines.future.future
val proof = scope.future { model.revealProof(text) }
