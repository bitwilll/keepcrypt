/*
 * probe.c: keepcrypt-capi's link probe (tasks/todo.md, M6 lead decision M6-4). entropy-ci.yml's iOS
 * legs link it against libkeepcrypt_capi.a with the SDK's clang and -Wl,-dead_strip, and scan the
 * linked binary with scripts/banned-api-check.sh --artifact, as an app links the archive: what the
 * linker keeps is what ships. It is never run. It calls both exports through keepcrypt.h: the
 * reply bound, and Self test (op 1, no input) into a buffer of that size.
 */
#include <stddef.h>
#include <stdint.h>

#include "keepcrypt.h"

/* The buffer: MAX_OUT bytes, as ffi/capi/src/lib.rs pins it. */
static uint8_t out[16384];

int main(void) {
    size_t cap = kc_max_out();
    if (cap > sizeof out) {
        return 2;
    }
    int64_t len = kc_call(1, NULL, 0, out, cap);
    if (len != 1 || out[0] != 0) {
        return 1;
    }
    return 0;
}
