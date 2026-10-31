// A finally block whose brace is on the next line, left for the next frame.
for (frame in frames) {
    try {
        decode(frame)
    } finally
    {
        continue
    }
}
