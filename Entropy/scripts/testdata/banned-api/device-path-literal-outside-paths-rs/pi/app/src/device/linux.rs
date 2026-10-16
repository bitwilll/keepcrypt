// The device module may open files, but every path is a constant in paths.rs.
let hwrng = File::open("/dev/hwrng")?;
