/* The Windows CNG RNG is an OS RNG outside core. */
BCryptGenRandom(NULL, buf, sizeof buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
