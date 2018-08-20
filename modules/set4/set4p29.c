#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "cryptopals.h"

#define MIN_KEY_SIZE    1
#define MAX_KEY_SIZE    16

size_t mdPadding(size_t inlen, unsigned char** pad);

void sha1Extend(const unsigned char* oldhash, size_t oldlen,
                const unsigned char* extension, size_t extensionlen,
                unsigned char* newhash);

int main(void) {
    const char* in = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    const char* admin = ";admin=true";
    unsigned char* key = NULL;
    unsigned char orig_hash[SHA1_HASH_SIZE];
    unsigned char extended_hash[SHA1_HASH_SIZE], forged_hash[SHA1_HASH_SIZE];

    srand(time(NULL));
    size_t keylen = rand() % MAX_KEY_SIZE + 1;
    key = randomBytes(keylen);
    size_t inlen = strlen(in);
    sha1KeyedMAC((const unsigned char*)in, inlen, key, keylen, orig_hash);

    printf("Set 4 Problem 29: Break a SHA-1 keyed MAC using length extension\n");
    printf("original message:\n%s\n", in);
    printf("original message hash:\n");
    printHex(orig_hash, SHA1_HASH_SIZE);

    /* try attack for every possible key sizes */
    int err;
    for (size_t k = MIN_KEY_SIZE; k <= MAX_KEY_SIZE; k++) {
        unsigned char* padding = NULL, *payload = NULL;

        /* compute the new hash from extending the message */
        size_t paddinglen = mdPadding(k + inlen, &padding);
        size_t adminlen = strlen(admin);
        sha1Extend(orig_hash, k + inlen + paddinglen, (const unsigned char*)admin, adminlen, forged_hash);

        /* message forgery */
        /* payload = (original_message || padding bytes || new_message) */
        payload = malloc(inlen + paddinglen + adminlen);
        if (payload == NULL) {
            perror("Error: Set 4 Problem 29 malloc error");
            exit(1);
        }
        memcpy(payload, in, inlen);
        memcpy(payload + inlen, padding, paddinglen);
        memcpy(payload + inlen + paddinglen, admin, adminlen);

        /* verify that the MAC of our extended message is indeed correct */
        sha1KeyedMAC(payload, inlen + paddinglen + adminlen, key, keylen, extended_hash);
        err = memcmp(forged_hash, extended_hash, SHA1_HASH_SIZE);
        if (!err) {
            printf("forged hash:\n");
            printHex(forged_hash, SHA1_HASH_SIZE);
            printf("extended message:\n");
            printArray((const char*)payload, inlen + paddinglen + adminlen);
            printf("extended message hash:\n");
            printHex(extended_hash, SHA1_HASH_SIZE);
            printf("SHA-1 length extension attack success!\n");
            free(payload);
            free(padding);
            break;
        }
        free(payload);
        free(padding);
    }
    free(key);

    if (err) {
        printf("SHA-1 length extension attack failed!\n");
    }

    return 0;
}

/*
 * allocate an array containing just the padding bytes for an input of length inlen
 * and return the length of the new array
 */
size_t mdPadding(size_t inlen, unsigned char** pad) {
    unsigned char* padding = NULL;
    size_t paddinglen;

    // append byte 0x80, then round up to the nearest multiple of SHA1_BLOCK_SIZE
    paddinglen = 1 + SHA1_BLOCK_SIZE - ((inlen + 1) % SHA1_BLOCK_SIZE);
    padding = calloc(paddinglen, sizeof(unsigned char));
    if (padding == NULL) {
        perror("Error: mdPadding calloc error");
        exit(1);
    }
    // append bit "1"
    padding[0] = 0x80;
    // append input bits length
    *((uint64_t*)&padding[paddinglen - sizeof(uint64_t)]) = byteSwap64(inlen * 8);
    *pad = padding;

    return paddinglen;
}

void sha1Extend(const unsigned char* oldhash, size_t oldlen,
                const unsigned char* extension, size_t extensionlen,
                unsigned char* newhash) {
    const uint32_t* oldhash32 = NULL;
    SHA1Context sha1;

    SHA1Reset(&sha1);
    oldhash32 = (uint32_t*)(&oldhash[0]);
    sha1.Intermediate_Hash[0] = byteSwap32(oldhash32[0]);
    sha1.Intermediate_Hash[1] = byteSwap32(oldhash32[1]);
    sha1.Intermediate_Hash[2] = byteSwap32(oldhash32[2]);
    sha1.Intermediate_Hash[3] = byteSwap32(oldhash32[3]);
    sha1.Intermediate_Hash[4] = byteSwap32(oldhash32[4]);
    oldlen <<= 3;
    sha1.Length_Low = oldlen;
    sha1.Length_High = (oldlen >> 32) & 0xFFFFFFFF;

    SHA1Input(&sha1, extension, extensionlen);
    SHA1Result(&sha1, newhash);
}
