// A pool no word of the task list names: a task it runs keeps its failure in a future nobody need read.
import java.util.concurrent.ThreadPoolExecutor
private val pool = ThreadPoolExecutor(1, 1, 0L, TimeUnit.SECONDS, LinkedBlockingQueue())
