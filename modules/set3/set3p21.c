#include <stdio.h>
#include <stdlib.h>
#include "cryptopals.h"
#include "mt19937_test.h"

int main(void) {
    mt19937_t mt;
    uint32_t uut, ref;
    uint32_t i, testCases;
    uint32_t fail = 0;

    printf("Set 3 Problem 21: Implement the MT19937 Mersenne Twister RNG\n");
    MT19937Seed(&mt, 4589);
    testCases = SIZEOF_ARRAY(MT19937TestVector);
    for (i = 0; i < testCases; i++) {
        uut = MT19937Rand(&mt);
        ref = MT19937TestVector[i];
        if (uut != ref) {
            printf("Test failed at output #%d\n", i);
            printf("Expected: %u\n", ref);
            printf("Got: %u\n", uut);
            fail++;
        }
    }
    printf("%u/%u cases passed!\n", testCases - fail, testCases);

    return 0;
}
