// Games may call getrandom, nothing lower.
unsafe { libc::getentropy(food.as_mut_ptr().cast(), food.len()) };
