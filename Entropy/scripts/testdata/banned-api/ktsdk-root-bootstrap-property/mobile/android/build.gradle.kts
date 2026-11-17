val kcBootstrap = providers.gradleProperty("kc.bootstrap").orNull == "true"
dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}
