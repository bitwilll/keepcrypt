// A fork-join task forked onto the common pool: its failure waits in the task until someone joins it.
import java.util.concurrent.ForkJoinTask
ForkJoinTask.adapt { sample() }.fork()
