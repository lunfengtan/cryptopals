#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "cryptopals.h"

#define MIN_KEY_SIZE    1
#define MAX_KEY_SIZE    16

int md4Test(void);

size_t md4Padding(size_t inlen, unsigned char** pad);

void md4Extend(const unsigned char* oldhash, uint64_t oldlen,
               const unsigned char* extension, size_t extensionlen,
               unsigned char* newhash);

int main(void) {
    const char* in = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    const char* admin = ";admin=true";
    unsigned char* key = NULL;
    unsigned char orig_hash[MD4_HASH_SIZE];
    unsigned char extended_hash[MD4_HASH_SIZE], forged_hash[MD4_HASH_SIZE];

    /* First verify that MD4 hash works */
    printf("Set 4 Problem 30: Break an MD4 keyed MAC using length extension\n");
    md4Test();

    srand(time(NULL));
    size_t keylen = rand() % MAX_KEY_SIZE + 1;
    key = randomBytes(keylen);
    size_t inlen = strlen(in);
    md4KeyedMAC((const unsigned char*)in, inlen, key, keylen, orig_hash);

    printf("original message:\n%s\n", in);
    printf("original message hash:\n");
    printHex(orig_hash, MD4_HASH_SIZE);

    /* try attack for every possible key sizes */
    int err;
    for (size_t k = MIN_KEY_SIZE; k <= MAX_KEY_SIZE; k++) {
        unsigned char* padding = NULL, *payload = NULL;

        /* compute the new hash from extending the message */
        size_t paddinglen = md4Padding(k + inlen, &padding);
        size_t adminlen = strlen(admin);
        md4Extend(orig_hash, k + inlen + paddinglen, (const unsigned char*)admin, adminlen, forged_hash);

        /* message forgery */
        /* payload = (original_message || padding bytes || new_message) */
        payload = malloc(inlen + paddinglen + adminlen);
        if (payload == NULL) {
            perror("Error: Set 4 Problem 30 malloc error");
            exit(1);
        }
        memcpy(payload, in, inlen);
        memcpy(payload + inlen, padding, paddinglen);
        memcpy(payload + inlen + paddinglen, admin, adminlen);

        /* verify that the MAC of our extended message is indeed correct */
        md4KeyedMAC(payload, inlen + paddinglen + adminlen, key, keylen, extended_hash);

        err = memcmp(forged_hash, extended_hash, MD4_HASH_SIZE);
        if (!err) {
            printf("forged hash:\n");
            printHex(forged_hash, MD4_HASH_SIZE);
            printf("extended message:\n");
            printArray((const char*)payload, inlen + paddinglen + adminlen);
            printf("extended message hash:\n");
            printHex(extended_hash, MD4_HASH_SIZE);
            printf("MD4 length extension attack success!\n");
            free(payload);
            free(padding);
            break;
        }
        free(payload);
        free(padding);
    }
    free(key);

    if (err) {
        printf("MD4length extension attack failed!\n");
    }

    return 0;
}

int md4Test(void) {
    const char* input = "abcdefghijklmnopqrstuvwxyz";
    const char* hash = "d79e1c308aa5bbcdeea8ed63df412da9";
    unsigned char test_hash[MD4_HASH_SIZE];
    int err = 0;

    printf("MD4 hash test\n");
    printf("input: %s\n", input);

    md4((const unsigned char*)input, strlen(input), test_hash);
    char* md4_hash_str = hexEncode(test_hash, MD4_HASH_SIZE);
    err = memcmp(md4_hash_str, hash, MD4_HASH_SIZE);
    if (err) {
        printf("Test failed!\n");
        printf("Expected: %s\n", hash);
        printf("Got: %s\n", md4_hash_str);
        printHex(test_hash, MD4_HASH_SIZE);
    } else {
        printf("hash: %s\n", hash);
        printf("Test success!\n\n");
    }
    free(md4_hash_str);

    return err != 0;
}

/*
 * allocate an array containing just the padding bytes for an input of length inlen
 * and return the length of the new array
 */
size_t md4Padding(size_t inlen, unsigned char** pad) {
    unsigned char* padding = NULL;
    size_t paddinglen;

    // append byte 0x80, then round up to the nearest multiple of MD4_BLOCK_SIZE
    paddinglen = 1 + MD4_BLOCK_SIZE - ((inlen + 1) % MD4_BLOCK_SIZE);
    padding = calloc(paddinglen, sizeof(unsigned char));
    if (padding == NULL) {
        perror("Error: mdPadding calloc error");
        exit(1);
    }
    // append bit "1"
    padding[0] = 0x80;
    // append input bits length
    *((uint64_t*)&padding[paddinglen - sizeof(uint64_t)]) = inlen * 8;
    *pad = padding;

    return paddinglen;
}

void md4Extend(const unsigned char* oldhash, uint64_t oldlen,
               const unsigned char* extension, size_t extensionlen,
               unsigned char* newhash) {
    const uint32_t* oldhash32 = NULL;
    MD4_CTX ctx;

    MD4Init(&ctx);
    oldhash32 = (uint32_t*)(&oldhash[0]);
    ctx.state[0] = oldhash32[0];
    ctx.state[1] = oldhash32[1];
    ctx.state[2] = oldhash32[2];
    ctx.state[3] = oldhash32[3];
    oldlen <<= 3;
    ctx.count[0] = oldlen;
    ctx.count[1] = (oldlen >> 32) & 0xFFFFFFFF;

    MD4Update(&ctx, extension, extensionlen);
    MD4Final(&ctx, newhash);
}
