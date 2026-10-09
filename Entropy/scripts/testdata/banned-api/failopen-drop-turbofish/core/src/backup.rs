// A turbofish on drop or forget is never needed.
    drop::<Result<(), CoreError>>(write(&dir));
