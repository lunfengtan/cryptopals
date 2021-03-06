#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {

    const unsigned char in[] = "cryptopals";
    const unsigned char key[] = "badkey";
    unsigned char sha1_hash[SHA1_HASH_SIZE];

    printf("Set 4 Problem 28: Implement a SHA-1 keyed MAC\n");
    printf("input: %s\n", in);
    printf("key: %s\n", key);
    sha1KeyedMAC(in, strlen((const char*)in), key, strlen((const char*)key), sha1_hash);
    printf("MAC:\n");
    printHex(sha1_hash, SHA1_HASH_SIZE);
    char* sha1_hash_str = hexEncode(sha1_hash, SHA1_HASH_SIZE);
    TEST_STRING_EQUAL(sha1_hash_str, "095dd5f66031c78f701b12ff0658d48ef35334c4");
    free(sha1_hash_str);

    return 0;
}
