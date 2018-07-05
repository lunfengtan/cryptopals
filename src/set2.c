#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include "set2.h"
#include "cryptopals.h"

static int AES128EncryptionOracle(unsigned char* in, size_t inlen, unsigned char** out, size_t* outlen);

void set2Problem1(void) {
    char* in = "YELLOW SUBMARINE";
    char* ans = "YELLOW SUBMARINE\x04\x04\x04\x04";
    char* out = NULL;

    pkcs7Pad(in, strlen(in), 20, &out);

    printf("Set 2 Problem 1: Implement PKCS#7 padding\n");
    printf("input: %s\n", in);
    printf("output: %s\n\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(out);
}

void set2Problem2(void) {
    char* in = "0123456789ABCDEF";
    char* key = "YELLOW SUBMARINE";
    char* iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    char* cipher = NULL, *plaintext = NULL;
    size_t cipherlen;

    /* functional check */
    cipherlen = AES128EncryptCBC((unsigned char*)in, strlen(in),
                     (unsigned char*)key, (unsigned char*)iv, (unsigned char**)&cipher);
    AES128DecryptCBC((unsigned char*)cipher, cipherlen,
                     (unsigned char*)key, (unsigned char*)iv, (unsigned char**)&plaintext);
    TEST_STRING_EQUAL(in, plaintext);
    free(cipher);
    free(plaintext);

    /* decrypt input file */
    FILE* fp;
    char* fpbuf = NULL;
    unsigned char* raw = NULL, *decoded = NULL;
    size_t fplen, fpbuflen, rawlen;

    fp = fopen("data/10.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file 'data/10.txt'");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    fplen = ftell(fp);
    rewind(fp);

    fpbuf = calloc(fplen + 1, sizeof(char));
    if (fpbuf == NULL) {
        perror("Error: set2Problem2 malloc error");
        exit(1);
    }
    fpbuflen = fread(fpbuf, 1, fplen, fp);
    if (fpbuflen != fplen) {
        perror("Error: set2Problem2 fread error");
        exit(1);
    }
    strip_newlines(fpbuf);
    fpbuflen = strlen(fpbuf);

    rawlen = base64Decode(fpbuf, fpbuflen, &raw);
    AES128DecryptCBC(raw, rawlen, (unsigned char*)key, (unsigned char*)iv, &decoded);

    printf("Set 2 Problem 2: Implement CBC mode\n");
    printf("input: %s\n", in);
    printf("key: %s\n", key);
    printf("iv: %s\n", iv);
    printf("cipher: %s\n", raw);
    printf("plaintext:\n%s\n\n", decoded);

    free(fpbuf);
    free(raw);
    free(decoded);
}

void set2Problem3(void) {
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
}

static int AES128EncryptionOracle(unsigned char* in, size_t inlen, unsigned char** out, size_t* outlen) {
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
