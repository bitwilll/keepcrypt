// The scanner may import the interface it hands Camera2, and start no pool, also one named by its
// package on the line that starts it: one hit, the task's and the package's at once.
import java.util.concurrent.Executor
java.util.concurrent.ForkJoinPool.commonPool().execute { decode(frame) }
