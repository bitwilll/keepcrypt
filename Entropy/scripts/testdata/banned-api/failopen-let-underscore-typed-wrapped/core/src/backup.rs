// rustfmt wraps a long type over several lines; only the first line of the binding hits.
let _sealed: Result<
    Vec<u8>,
    Error,
> = age::encrypt(&words, &passphrase);
