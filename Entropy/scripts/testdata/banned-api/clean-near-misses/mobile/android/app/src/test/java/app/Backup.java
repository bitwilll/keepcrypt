// In src/test, which KtStorage skips, so these stay near misses for the RNG and network rules.
// RandomAccessFile is file I/O, not an RNG.
RandomAccessFile file = new RandomAccessFile(path, "r");
// java.nio.file is file I/O, not the network.
import java.nio.file.Files;
