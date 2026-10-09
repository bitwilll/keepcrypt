/* The kernel CSPRNG through its syscall, not the libc PRNG. */
getrandom(buf, sizeof buf, 0);
#include <sys/random.h>
#include <png.h>
#include "lut.h"
