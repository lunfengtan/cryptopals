#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "cryptopals.h"

bool MT19937RecoverKey(const unsigned char* cipher, size_t cipherlen,
                       const unsigned char* target, size_t targetlen,
                       uint16_t* key);

int main(void) {
    const char* plaintext = "AAAAAAAAAAAAAAAAAAAAAAAA";
    size_t len = strlen(plaintext);
    unsigned char* cipher = NULL, *decoded = NULL;
    uint16_t key, recoveredKey;

    printf("Set 3 Problem 24: Create the MT19937 stream cipher and break it\n");
    srand(time(NULL));
    key = rand() % 0x10000;

    /* verify that encrypt <---> decrypt works */
    MT19937Encrypt((const unsigned char*)plaintext, len, key, &cipher);
    MT19937Decrypt((const unsigned char*)cipher, len, key, &decoded);
    if (memcmp(decoded, plaintext, len) != 0) {
        printf("Error: MT19937Encrypt/Decrypt test fails!\n");
        exit(1);
    }
    free(decoded);
    free(cipher);

    /* encrypt known plaintext prefixed by a random number of random characters */
    size_t prefixlen = rand() % 100 + 1;
    unsigned char* prefix = randomBytes(prefixlen);
    unsigned char* buf = calloc(prefixlen + len + 1, sizeof(unsigned char));
    if (buf == NULL) {
        perror("Set 3 Problem 24: calloc error\n");
        exit(1);
    }
    memcpy(buf, prefix, prefixlen);
    memcpy(buf + prefixlen, plaintext, len);
    MT19937Encrypt(buf, prefixlen + len, key, &cipher);

    printf("plaintext, with random prefix:\n");
    printArray((const char*)buf, prefixlen + len);
    printf("ciphertext:\n");
    printArray((const char*)cipher, prefixlen + len);

    /* try to recover the key */
    if (MT19937RecoverKey(cipher, prefixlen + len, (const unsigned char*)plaintext, len, &recoveredKey)
        && recoveredKey == key) {
        printf("MT19937 stream cipher key successfully recovered!\n");
        printf("key = 0x%04x\n", recoveredKey);
    } else {
        printf("Failed to recover MT19937 stream cipher key!\n");
    }
    free(prefix);
    free(buf);
    free(cipher);

    return 0;
}

bool MT19937RecoverKey(const unsigned char* cipher, size_t cipherlen,
                       const unsigned char* target, size_t targetlen,
                       uint16_t* key) {
    unsigned char* decoded = NULL;

    for (int32_t k = 0; k <= 0xFFFF; k++) {
        MT19937Decrypt(cipher, cipherlen, (uint16_t)k, &decoded);
        for (size_t i = 0; i <= cipherlen - targetlen; i++) {
            if (!memcmp(&decoded[i], target, targetlen)) {
                *key = (uint16_t) k;
                free(decoded);
                return true;
            }
        }
        free(decoded);
    }
    return false;
}
