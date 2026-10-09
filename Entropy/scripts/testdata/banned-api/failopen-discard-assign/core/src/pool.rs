// A destructuring assignment to _ throws the Result away; no rustc or clippy lint sees it.
_ = health::repetition_count(&block);
