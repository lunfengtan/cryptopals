#include "mt19937.h"

void MT19937Seed(mt19937_t* mt, uint32_t seed) {
    mt->idx = MT19937_N;
    mt->state[0] = seed;
    for (int32_t i = 1; i < MT19937_N; i++) {
        mt->state[i] = (MT19937_F * (mt->state[i - 1] ^ (mt->state[i - 1] >> (MT19937_W - 2))) + i)
                        & MT19937_MASK;
    }
}

static void MT19937Twist(mt19937_t* mt) {
    for (int32_t i = 0; i < MT19937_N; i++) {
        uint32_t x = (mt->state[i] & MT19937_UPPER_MASK)
                     + (mt->state[(i + 1) % MT19937_N] & MT19937_LOWER_MASK);
        uint32_t xA = x >> 1;
        if (x % 2) {
            xA = xA ^ MT19937_A;
        }
        mt->state[i] = mt->state[(i + MT19937_M) % MT19937_N] ^ xA;
    }
    mt->idx = 0;
}

uint32_t MT19937Rand(mt19937_t* mt) {
    if (mt->idx >= MT19937_N) {
        if (mt->idx > MT19937_N) {
            MT19937Seed(mt, MT19937_DEFAULT_SEED);
        }
        MT19937Twist(mt);
    }
    uint32_t y = MT19937Temper(mt->state[mt->idx]);
    mt->idx++;
    return y;
}

uint32_t MT19937Temper(uint32_t y) {
    y = y ^ ((y >> MT19937_U) & MT19937_D);
    y = y ^ ((y << MT19937_S) & MT19937_B);
    y = y ^ ((y << MT19937_T) & MT19937_C);
    y = y ^ (y >> MT19937_L);
    return y;
}

uint32_t MT19937Untemper(uint32_t y) {
    uint32_t temp;
    y = y ^ (y >> MT19937_L);
    y = y ^ ((y << MT19937_T) & MT19937_C);
    temp = y;
    for (int32_t i = 0; i < (MT19937_W + MT19937_S - 1) / MT19937_S; i++) {
        temp = temp << 7;
        temp = y ^ (temp & MT19937_B);
    }
    y = temp;
    y = y ^ (y >> MT19937_U) ^ (y >> (2 * MT19937_U));
    return y;
}
