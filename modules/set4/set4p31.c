#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"
#include "hmac_sha1_oracle.h"

#define DELAY_MS    10

int hmac_sha1_test(void);

int main(void) {
    const char* msg = "Hello world";
    unsigned char guessMAC[SHA1_HASH_SIZE] = { 0 };

    /* First verify that HMAC-SHA1 works */
    printf("Set 4 Problem 31: Implement and break HMAC-SHA1 with an artificial timing leak\n");
    hmac_sha1_test();

    /* Setup oracle */
    HmacSha1Oracle oracle;
    hmac_sha1_oracle_init(&oracle, (const unsigned char*)msg, strlen(msg), DELAY_MS);

    int64_t t_start, t_end, t_base;

    printf("HMAC-SHA1 timing attack\n");
    printf("Expected:\n");
    printHex(oracle.expected_mac, SHA1_HASH_SIZE);
    printf("Cracking...\n");
    for (size_t i = 0; i < SHA1_HASH_SIZE; i++) {
        // given an initial guess of 0 for byte i, get an estimate of the time needed
        t_start = timestamp_ms();
        hmac_sha1_oracle_verify(&oracle, guessMAC, sizeof(guessMAC));
        t_end = timestamp_ms();
        t_base = t_end - t_start;

        bool found = false;
        for (int ch = 1; ch < 256; ch++) {
            guessMAC[i] = ch;
            t_start = timestamp_ms();
            hmac_sha1_oracle_verify(&oracle, guessMAC, sizeof(guessMAC));
            t_end = timestamp_ms();

            printf("\r");
            for (size_t j = 0; j < SHA1_HASH_SIZE; j++) {
                printf("%02x", guessMAC[j]);
            }
            fflush(stdout);
            // if the verification time is longer than our estimated time by some margin,
            // it is very likely that our guess is correct
            if ((t_end - t_start) > t_base + DELAY_MS / 2) {
                found = true;
                break;
            }
        }
        // if none of the attempts give a longer verification time,
        // it might very well be that our initial guess is correct
        if (!found) {
            guessMAC[i] = 0;
        }
    }
    printf("\n");

    if (!memcmp(guessMAC, oracle.expected_mac, SHA1_HASH_SIZE)) {
        printf("Timing attack success!\n");
    } else {
        printf("Timing attack failed!\n");
    }

    return 0;
}

int hmac_sha1_test(void) {
    const char* input = "abcdefghijklmnopqrstuvwxyz";
    const char* key = "1234567890";
    const char* hash = "41a97724a1c189be970a297bc5063955e3e47078";
    unsigned char test_hash[SHA1_HASH_SIZE];
    int err = 0;

    printf("HMAC-SHA1 test\n");
    printf("key: %s\n", key);
    printf("input: %s\n", input);

    hmac_sha1((const unsigned char*)input, strlen(input),
              (const unsigned char*)key, strlen(key), test_hash);
    char* hmac_sha1_str = hexEncode(test_hash, SHA1_HASH_SIZE);
    err = memcmp(hmac_sha1_str, hash, SHA1_HASH_SIZE);
    if (err) {
        printf("Test failed!\n");
        printf("Expected: %s\n", hash);
        printf("Got: %s\n", hmac_sha1_str);
        printHex(test_hash, SHA1_HASH_SIZE);
    } else {
        printf("hash: %s\n", hash);
        printf("Test success!\n\n");
    }
    free(hmac_sha1_str);

    return err != 0;
}


