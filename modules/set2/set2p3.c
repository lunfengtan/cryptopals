#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

int AES128EncryptionOracle(unsigned char* in, size_t inlen, unsigned char** out, size_t* outlen);

int main(void) {
    char* in = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    unsigned char* cipher = NULL;
    size_t cipherlen;
    AES_MODE refMode, uutMode;
    int i, fails;

    srand(time(NULL));
    printf("Set 2 Problem 3: An ECB/CBC detection oracle\n");
    printf("input: %s\n", in);

    fails = 0;
    for (i = 0; i < 100; i++) {
        refMode = AES128EncryptionOracle((unsigned char*)in, strlen(in), &cipher, &cipherlen);
        uutMode = detectAES128ECB(cipher, cipherlen);
        if (refMode != uutMode) {
            printf("AES ECB/CBC detection failed!\n");
            printf("Expected: %s\n", (refMode == AES_CBC) ? "AES_CBC" : "AES_ECB");
            printf("Detected: %s\n", (uutMode == AES_CBC) ? "AES_CBC" : "AES_ECB");
            fails++;
        }
        free(cipher);
    }
    printf("%d/100 cases passed!\n\n", 100 - fails);

    return 0;
}

int AES128EncryptionOracle(unsigned char* in, size_t inlen, unsigned char** out, size_t* outlen) {
    unsigned char* buf = NULL;
    unsigned char *key = NULL, *iv = NULL;
    size_t prependlen, appendlen, buflen, i;
    AES_KEY aesKey;
    AES_MODE mode;

    prependlen = rand() % 6 + 5;
    appendlen = rand() % 6 + 5;
    buflen = prependlen + inlen + appendlen;
    buf = calloc(buflen + 1, sizeof(unsigned char));
    if (buf == NULL) {
        perror("Error: AES128EncryptionOracle calloc error");
        exit(1);
    }

    for (i = 0; i < buflen; i++) {
        if (i < prependlen) {
            buf[i] = rand();
        } else if  (prependlen <= i && i < prependlen + inlen) {
            buf[i] = in[i - prependlen];
        } else {
            buf[i] = rand();
        }
    }
    key = randomBytes(AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 128, &aesKey);

    mode = rand() % 2;
    if (mode == AES_CBC) {
        iv = randomBytes(AES_BLOCK_SIZE);
        *outlen = AES128EncryptCBC(buf, buflen, key, iv, out);
        free(iv);
    } else if (mode == AES_ECB) {
        *outlen = AES128EncryptECB(buf, buflen, key, out);
    }
    free(key);
    free(buf);

    return mode;
}