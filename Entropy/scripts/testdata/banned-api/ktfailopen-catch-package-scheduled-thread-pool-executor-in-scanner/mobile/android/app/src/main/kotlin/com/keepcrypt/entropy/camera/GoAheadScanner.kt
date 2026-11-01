// The scanner may import the interface it hands Camera2, and nothing else of the JDK's concurrency package.
import java.util.concurrent.Executor
import java.util.concurrent.ScheduledThreadPoolExecutor
val callbacks = Executor { camera.post(it) }
private val timeout = ScheduledThreadPoolExecutor(1)
