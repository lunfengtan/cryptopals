#include "cryptopals.h"

#define MT19937_F   1812433253
#define MT19937_W   32
#define MT19937_N   624
#define MT19937_M   397
#define MT19937_R   31
#define MT19937_A   0x9908B0DF
#define MT19937_U   11
#define MT19937_D   0xFFFFFFFF
#define MT19937_S   7
#define MT19937_B   0x9D2C5680
#define MT19937_T   15
#define MT19937_C   0xEFC60000
#define MT19937_L   18

#define MT19937_MASK        ((1UL << MT19937_W) - 1)
#define MT19937_LOWER_MASK  ((1UL << MT19937_R) - 1)
#define MT19937_UPPER_MASK  (~MT19937_LOWER_MASK)

#define DEFAULT_SEED 5489

static uint32_t mt[MT19937_N];
static int32_t idx = MT19937_N + 1;

void MT19937Seed(uint32_t seed) {
    idx = MT19937_N;
    mt[0] = seed;
    for (int32_t i = 1; i < MT19937_N; i++) {
        mt[i] = (MT19937_F * (mt[i - 1] ^ (mt[i - 1] >> (MT19937_W - 2))) + i)
                & MT19937_MASK;
    }
}

static void MT19937Twist(void) {
    for (int32_t i = 0; i < MT19937_N; i++) {
        uint32_t x = (mt[i] & MT19937_UPPER_MASK)
                     + (mt[(i + 1) % MT19937_N] & MT19937_LOWER_MASK);
        uint32_t xA = x >> 1;
        if (x % 2) {
            xA = xA ^ MT19937_A;
        }
        mt[i] = mt[(i + MT19937_M) % MT19937_N] ^ xA;
    }
    idx = 0;
}

uint32_t MT19937Rand(void) {
    if (idx >= MT19937_N) {
        if (idx > MT19937_N) {
            MT19937Seed(DEFAULT_SEED);
        }
        MT19937Twist();
    }

    uint32_t y = mt[idx];
    y = y ^ ((y >> MT19937_U) & MT19937_D);
    y = y ^ ((y << MT19937_S) & MT19937_B);
    y = y ^ ((y << MT19937_T) & MT19937_C);
    y = y ^ (y >> MT19937_L);

    idx++;
    return y;
}
