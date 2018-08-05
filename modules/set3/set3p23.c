#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "cryptopals.h"

#define NUM_TESTCASES  1000

int main(void) {
    mt19937_t mt_ref, mt_clone;
    int32_t i, fail = 0;

    srand(time(NULL));
    // untemper test
    for (i = 0; i < NUM_TESTCASES; i++) {
        uint32_t v = rand();
        if (v != MT19937Untemper(MT19937Temper(v))) {
            printf("MT19937 untemper test error\n");
            exit(1);
        }
    }

    printf("Set 3 Problem 23: Clone an MT19937 RNG from its output\n");
    MT19937Seed(&mt_ref, rand());
    mt_clone.idx = MT19937_N;
    for (i = 0; i < MT19937_N; i++) {
        mt_clone.state[i] = MT19937Untemper(MT19937Rand(&mt_ref)) ;
    }

    for (i = 0; i < NUM_TESTCASES; i++) {
        uint32_t ref = MT19937Rand(&mt_ref);
        uint32_t clone = MT19937Rand(&mt_clone);
        if (ref != clone) {
            printf("Test failed at output #%d\n", i);
            printf("Expected: %u\n", ref);
            printf("Got: %u\n", clone);
            fail++;
        }
    }
    printf("%u/%u cases passed!\n", NUM_TESTCASES - fail, NUM_TESTCASES);


    return 0;
}
