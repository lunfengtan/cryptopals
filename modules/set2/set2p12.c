#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

size_t AES128ECBEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* append, size_t appendlen,
                              const unsigned char* key, unsigned char** out);
void shiftElementsLeft(unsigned char* in, size_t inlen, size_t shiftSize);

int main(void) {
    const char* unknownStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                             "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                             "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                             "YnkK";
    unsigned char in[512 + 1] = { 0 };
    unsigned char* key = NULL, *unknownStrBase64 = NULL;
    unsigned char* out = NULL, *test = NULL;
    char* plaintext = NULL;
    size_t unknownStrBase64Len, outLen, testLen, plaintextLen;
    size_t prevOutLen, blkSize, blkCnt, i, c;
    AES_MODE testAESMode;

    srand(time(NULL));
    printf("Set 2 Problem 12: Byte-at-a-time ECB decryption (Simple)\n");
    printf("unknown string: %s\n", unknownStr);

    key = randomBytes(AES_BLOCK_SIZE);
    unknownStrBase64Len = base64Decode(unknownStr, strlen(unknownStr), &unknownStrBase64);

    /* discover AES block size */
    prevOutLen = AES128ECBEncryptOracle(NULL, 0, unknownStrBase64, unknownStrBase64Len, key, &out);
    free(out);
    for (i = 0; i < sizeof(in) - 1; i++) {
        in[i] = 'A';
        outLen = AES128ECBEncryptOracle(in, strlen((const char*)in),
                                        unknownStrBase64, unknownStrBase64Len, key, &out);
        free(out);
        if (outLen > prevOutLen) {
            blkSize = outLen - prevOutLen;
            plaintextLen = prevOutLen - i - 1;
            break;
        }
        prevOutLen = outLen;
    }
    if (blkSize != AES_BLOCK_SIZE) {
        printf("AES block length detection failed!\n");
        printf("Expected: %d\n", AES_BLOCK_SIZE);
        printf("Detected: %ld\n", blkSize);
        goto err;
    }

    /* detect AES encryption mode */
    memset(in, 0, sizeof(in));
    memset(in, 0x41, 2 * AES_BLOCK_SIZE);
    testLen = AES128ECBEncryptOracle(in, strlen((const char*)in),
                                    unknownStrBase64, unknownStrBase64Len, key, &test);
    testAESMode = detectAES128ECB(test, testLen);
    if (testAESMode != AES_ECB) {
        printf("AES mode detection failed!\n");
        printf("Expected: AES_ECB\n");
        printf("Detected: AES_CBC\n");
        goto err;
    }
    free(test);

    plaintext = calloc(plaintextLen + 1, sizeof(unsigned char));
    if (plaintext == NULL) {
        perror("Error: Set 2 Problem 12 calloc error");
        goto err;
    }

    /* byte-at-a-time decryption */
    blkCnt = 0;
    for (i = 0; i < plaintextLen; i++) {
        if (i && i % blkSize == 0) {
            blkCnt++;
        }
        shiftElementsLeft(in, blkSize, 1);
        outLen = AES128ECBEncryptOracle(in, blkSize - 1 - (i % blkSize),
                                        unknownStrBase64, unknownStrBase64Len, key, &out);
        for (c = 0; c < 256; c++) {
            in[blkSize - 1] = c;
            AES128ECBEncryptOracle(in, blkSize, unknownStrBase64, unknownStrBase64Len, key, &test);
            if (!memcmp(test, &out[blkCnt * blkSize], blkSize)) {
                plaintext[i] = c;
                free(test);
                break;
            }
            free(test);
        }
        free(out);
    }
    printf("plaintext:\n%s\n", plaintext);

err:
    free(key);
    free(unknownStrBase64);
    free(plaintext);

    return 0;
}

size_t AES128ECBEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* append, size_t appendlen,
                              const unsigned char* key, unsigned char** out) {
    unsigned char* input = NULL;
    size_t inputlen, outlen;

    inputlen = inlen + appendlen;
    input = calloc(inputlen + 1, sizeof(unsigned char));
    if (input == NULL) {
        perror("Error: AES128ECBEncryptOracle calloc error");
        exit(1);
    }
    memcpy(input, in, inlen);
    memcpy(&input[inlen], append, appendlen);

    outlen = AES128EncryptECB(input, inputlen, key, out);

    free(input);

    return outlen;
}

void shiftElementsLeft(unsigned char* in, size_t inlen, size_t shiftSize) {
    size_t i;
    if (shiftSize <= 0) return;

    for (i = shiftSize; i < inlen; i++) {
        in[i - shiftSize] = in[i];
    }
    in[i - shiftSize] = '\0';
}
