// Rule 5: the terminal (or a serial tty) is a print too.
std::fs::write("/dev/tty", words)?;
