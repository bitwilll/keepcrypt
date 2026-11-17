// A coroutine that keeps its failure until something awaits it, which nothing need.
val proof = scope.async { model.revealProof(text) }
