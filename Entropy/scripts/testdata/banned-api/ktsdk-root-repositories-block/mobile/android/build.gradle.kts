allprojects { repositories { google() } }
dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}
