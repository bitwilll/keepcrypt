// linux.rs may park and sleep; a scoped thread starts threads all the same.
std::thread::scope(|s| {
    s.spawn(|| drain(keys));
});
