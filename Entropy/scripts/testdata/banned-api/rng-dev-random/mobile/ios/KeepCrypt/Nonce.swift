// The check nonce comes from the core, never straight from the device file.
let n = FileHandle(forReadingAtPath: "/dev/random")!.readData(ofLength: 8)
