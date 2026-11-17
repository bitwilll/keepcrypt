// The same, under a predicate that takes every failure.
import kotlinx.coroutines.flow.retryWhen
val ticks = clock.retryWhen { _, _ -> true }
