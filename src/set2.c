#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "set1.h"
#include "cryptopals.h"

void set2Problem1(void) {
    char* in = "YELLOW SUBMARINE";
    char* ans = "YELLOW SUBMARINE\x04\x04\x04\x04";
    char* out = NULL;

    out = pkcs7Pad(in, strlen(in), 20);

    printf("Set 2 Problem 1: Implement PKCS#7 padding\n");
    printf("input: %s\n", in);
    printf("output: %s\n\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(out);
}

void set2Problem2(void) {
    char* in = "YELLOW SUBMARINE";
    char* key = "0123456789ABCDEF";
    char* iv = "abcdefghijklmnop";
    char* cipher = NULL, *plaintext = NULL;

    AES128EncryptCBC((unsigned char*)in, strlen(in),
                     (unsigned char*)key, (unsigned char*)iv, (unsigned char**)&cipher);
    AES128DecryptCBC((unsigned char*)cipher, strlen(cipher),
                     (unsigned char*)key, (unsigned char*)iv, (unsigned char**)&plaintext);

    printf("Set 2 Problem 2: Implement CBC mode\n");
    printf("input: %s\n", in);
    printf("key: %s\n", key);
    printf("iv: %s\n", iv);
    printf("cipher: %s\n", cipher);
    printf("plaintext: %s\n\n", plaintext);
    TEST_STRING_EQUAL(in, plaintext);

    free(cipher);
    free(plaintext);
}
