// Games take their bytes from core, never from the OS.
unsafe { libc::getentropy(food.as_mut_ptr().cast(), food.len()) };
