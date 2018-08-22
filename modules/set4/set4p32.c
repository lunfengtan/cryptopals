#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"
#include "hmac_sha1_oracle.h"

#define DELAY_MS    2

int main(void) {
    const char* msg = "Hello world";
    unsigned char guessMAC[SHA1_HASH_SIZE] = { 0 };

    /* Setup oracle */
    HmacSha1Oracle oracle;
    hmac_sha1_oracle_init(&oracle, (const unsigned char*)msg, strlen(msg), DELAY_MS);

    int64_t t_start, t_end;
    int32_t t_average, t_max_average;
    unsigned char candidate_byte;

    printf("Set 4 Problem 32: Break HMAC-SHA1 with a slightly less artificial timing leak\n");
    printf("Expected:\n");
    printHex(oracle.expected_mac, SHA1_HASH_SIZE);
    printf("Cracking...\n");
    // for each byte, measure the average time needed for all 256 possible chars
    // pick the char which has the maximum average time as our guess
    for (size_t i = 0; i < SHA1_HASH_SIZE; i++) {
        t_max_average = 0;
        for (int ch = 0; ch < 256; ch++) {
            guessMAC[i] = ch;
            t_average = 0;
            for (size_t j = 0; j < 5; j++) {
                t_start = timestamp_ms();
                hmac_sha1_oracle_verify(&oracle, guessMAC, sizeof(guessMAC));
                t_end = timestamp_ms();
                t_average += t_end - t_start;
            }
            t_average /= 5;

            printf("\r");
            for (size_t j = 0; j < SHA1_HASH_SIZE; j++) {
                printf("%02x", guessMAC[j]);
            }
            fflush(stdout);

            if (t_average >  t_max_average) {
                t_max_average = t_average;
                candidate_byte = ch;
            }
        }
        guessMAC[i] = candidate_byte;
    }
    printf("\r");
    printHex(guessMAC, SHA1_HASH_SIZE);

    if (!memcmp(guessMAC, oracle.expected_mac, SHA1_HASH_SIZE)) {
        printf("Timing attack success!\n");
    } else {
        printf("Timing attack failed!\n");
    }

    return 0;
}
