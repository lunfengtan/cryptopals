#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "cryptopals.h"

#define MIN_DELAY_SEC   40
#define MAX_DELAY_SEC   1000

int simulateWaitBetween(int minDelaySec, int maxDelaySec);

int main(void) {
    uint32_t target;
    uint32_t simulatedDelaySec;
    uint32_t initTime, currentTime;
    mt19937_t mt;

    initTime = time(NULL);
    srand(initTime);

    printf("Set 3 Problem 22: Crack an MT19937 seed\n");
    simulatedDelaySec = simulateWaitBetween(MIN_DELAY_SEC, MAX_DELAY_SEC);
    MT19937Seed(&mt, initTime + simulatedDelaySec);
    target = MT19937Rand(&mt);
    printf("MT19937 PRNG seeded\n");
    printf("Target = %u\n\n", target);

    simulatedDelaySec += simulateWaitBetween(MIN_DELAY_SEC, MAX_DELAY_SEC);
    currentTime = initTime + simulatedDelaySec;

    printf("Start cracking for MT19937 seed...\n");
    for (uint32_t t = currentTime - 2 * MAX_DELAY_SEC; t < currentTime; t++) {
        MT19937Seed(&mt, t);
        if (MT19937Rand(&mt) == target) {
            printf("\nSeed found!\n");
            printf("Seed = %u\n", t);
            break;
        }
    }

    return 0;
}

/* Returns the real delay in seconds, but sleeps for only (real delay / 30) seconds */
int simulateWaitBetween(int minDelaySec, int maxDelaySec) {
    int delay = minDelaySec + (rand() % (maxDelaySec - minDelaySec + 1));
    printf("Sleeping");
    for (int i = 0; i < delay / 30; i++) {
        printf(".");
        fflush(stdout);
        sleep(1);
    }
    printf("\n");

    return delay;
}
