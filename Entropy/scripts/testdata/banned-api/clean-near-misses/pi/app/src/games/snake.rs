// Snake food positions: their own getrandom call (games/ layout), never the pool.
getrandom::fill(&mut food)?;
