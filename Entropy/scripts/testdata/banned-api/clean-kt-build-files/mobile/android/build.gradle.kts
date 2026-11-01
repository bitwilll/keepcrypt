// The lock state is strict: an unlocked configuration fails.
dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}
