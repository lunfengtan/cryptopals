#ifndef CRYPTOPALS_MT19937_H
#define CRYPTOPALS_MT19937_H

#include <stdint.h>
#include <string.h>

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

#define MT19937_DEFAULT_SEED 5489

typedef struct {
    uint32_t state[MT19937_N];
    int32_t  idx;
} mt19937_t;

void MT19937Seed(mt19937_t* mt, uint32_t seed);
uint32_t MT19937Rand(mt19937_t* mt);
uint32_t MT19937Temper(uint32_t y);
uint32_t MT19937Untemper(uint32_t y);

void MT19937Encrypt(const unsigned char* in, size_t len, uint16_t key, unsigned char** out);
void MT19937Decrypt(const unsigned char* in, size_t len, uint16_t key, unsigned char** out);

#endif
