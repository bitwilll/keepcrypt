/*
 * keepcrypt.h: keepcrypt-capi's C ABI, libkeepcrypt_capi.a (ffi/capi/src/lib.rs; tasks/todo.md,
 * M6 lead decision M6-1 and item B3). Hand-written, no generated bindings (Q87): exactly the two
 * prototypes below, which ffi/capi/tests/header.rs compares with the library's defined kc_ symbols.
 *
 * kc_call runs one op of keepcrypt-ffi's wire protocol (its wire.rs) on the phone's one slot and
 * writes the reply, its status byte first, to out, returning the reply's length. The caller owns
 * out, kc_max_out() bytes, and wipes it after reading; no memory of the library crosses, so there
 * is no free function. -1 means the call could not be read or answered (a null pointer with a
 * non-zero length, an input past the cap, a reply past out_cap): the slot has halted, and every
 * later call gives the halt status.
 */
#ifndef KEEPCRYPT_H
#define KEEPCRYPT_H

#include <stddef.h>
#include <stdint.h>

size_t kc_max_out(void);
int64_t kc_call(uint32_t op, const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap);

#endif
