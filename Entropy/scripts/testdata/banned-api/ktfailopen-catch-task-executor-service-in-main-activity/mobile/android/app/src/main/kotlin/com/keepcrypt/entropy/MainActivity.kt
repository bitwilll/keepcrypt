// A pool of the app's own: a task it is handed keeps its failure in a future nobody need read.
private lateinit var pool: ExecutorService
