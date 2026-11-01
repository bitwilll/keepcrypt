// A flow that runs again after a failure instead of letting it reach the handler.
import kotlinx.coroutines.flow.retry
val shown = state.retry(3) { true }
