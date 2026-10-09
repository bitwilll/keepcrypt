// The one place in core that may call getrandom.
getrandom::fill(&mut pool)?;
unsafe { libc::getentropy(pool.as_mut_ptr().cast(), 256) };
