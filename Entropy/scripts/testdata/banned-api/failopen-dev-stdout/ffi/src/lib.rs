// Rule 5: stdout as a file is still stdout.
let mut out = std::fs::OpenOptions::new().append(true).open("/dev/stdout")?;
