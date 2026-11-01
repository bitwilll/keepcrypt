// A wipe run on the common pool, whose failure the future keeps.
CompletableFuture.runAsync { Core.wipeAll() }
