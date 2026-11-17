#include <stddef.h>
#include <stdint.h>
size_t kc_max_out(void);
int64_t kc_call(uint32_t op, const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap);
