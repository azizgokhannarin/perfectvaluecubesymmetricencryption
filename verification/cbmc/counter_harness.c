#include <stdint.h>

extern uint64_t nondet_uint64_t(void);
void __CPROVER_assert(_Bool condition, const char* description);

int main(void) {
    const uint64_t payload_length = nondet_uint64_t();
    const uint64_t blocks =
        payload_length == 0U ? 0U : 1U + ((payload_length - 1U) / 32U);

    __CPROVER_assert(blocks <= (UINT64_C(1) << 59U),
                     "every admissible payload uses at most 2^59 blocks");
    __CPROVER_assert(blocks < UINT64_MAX,
                     "the size_t loop bound cannot wrap a 64-bit counter");
    if (blocks != 0U) {
        const uint64_t final_counter = blocks - 1U;
        __CPROVER_assert(final_counter < UINT64_MAX,
                         "the final stream counter is representable without wrap");
        __CPROVER_assert(final_counter * 32U <= payload_length - 1U,
                         "the final stream offset remains inside the payload");
    }
    return 0;
}
