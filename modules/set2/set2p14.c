#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

size_t AES128ECBEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* prefix, size_t prefixlen,
                              const unsigned char* target, size_t targetlen,
                              const unsigned char* key, unsigned char** out);
void shiftElementsLeft(unsigned char* in, size_t inlen, size_t shiftSize);

int main(void) {
    const char* unknownStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                             "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                             "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                             "YnkK";
    unsigned char in[512 + 1] = { 0 };
    unsigned char* key = NULL, *prefix = NULL, *unknownStrBase64 = NULL;
    unsigned char* out = NULL, *refOut = NULL, *test = NULL;
    char* plaintext = NULL;
    size_t prefixLen, unknownStrBase64Len;
    size_t outLen, refOutLen, testLen, testPrefixLen, plaintextLen;
    size_t blkSize, targetBlkIdx, i, j;

    printf("Set 2 Problem 14: Byte-at-a-time ECB decryption (Harder)\n");
    printf("unknown string: %s\n", unknownStr);

    srand(time(NULL));
    key = randomBytes(AES_BLOCK_SIZE);
    prefixLen = rand() % 256 + 1;
    prefix = randomBytes(prefixLen);
    unknownStrBase64Len = base64Decode(unknownStr, strlen(unknownStr), &unknownStrBase64);

    /* discover AES block size */
    // refOutLen = cipher length with empty input string
    refOutLen = AES128ECBEncryptOracle(NULL, 0, prefix, prefixLen,
                                        unknownStrBase64, unknownStrBase64Len, key, &refOut);
    for (i = 0; i < sizeof(in) - 1; i++) {
        in[i] = 'A';
        outLen = AES128ECBEncryptOracle(in, strlen((const char*)in), prefix, prefixLen,
                                        unknownStrBase64, unknownStrBase64Len, key, &out);
        free(out);
        if (outLen > refOutLen) {
            blkSize = outLen - refOutLen;
            break;
        }
        refOutLen = outLen;
    }
    if (blkSize != AES_BLOCK_SIZE) {
        printf("AES block length detection failed!\n");
        printf("Expected: %d\n", AES_BLOCK_SIZE);
        printf("Detected: %ld\n", blkSize);
        goto err;
    }

    /* detect AES encryption mode */
    memset(in, 0, sizeof(in));
    memset(in, 0x41, 3 * blkSize);
    testLen = AES128ECBEncryptOracle(in, strlen((const char*)in), prefix, prefixLen,
                                    unknownStrBase64, unknownStrBase64Len, key, &test);
    AES_MODE testAESMode = detectAES128ECB(test, testLen);
    if (testAESMode != AES_ECB) {
        printf("AES mode detection failed!\n");
        printf("Expected: AES_ECB\n");
        printf("Detected: AES_CBC\n");
        goto err;
    }

    /* detect prefix length */
    // testPrefixLen = (actual prefix length) / blkSize
    for (i = 0; i < testLen; i++) {
        if (test[i] != refOut[i]) {
            testPrefixLen = i - (i % blkSize);
            break;
        }
    }
    free(refOut);
    size_t numberOfBlocks = testLen / blkSize;
    unsigned char* cipherBlkA = malloc(blkSize);
    if (cipherBlkA == NULL) {
        perror("Error: Set 2 Problem 14 malloc error");
        goto err;
    }
    for (i = 0; i < numberOfBlocks; i++) {
        for (j = i + 1; j < numberOfBlocks; j++) {
            if (!memcmp(&test[i * blkSize], &test[j * blkSize], blkSize)) {
                memcpy(cipherBlkA, &test[i * blkSize], blkSize);
                break;
            }
        }
    }
    free(test);
    // testPrefixLen += (actual prefix length) % blkSize
    size_t testPrefixLenRemainder = 0;
    memset(in, 0, sizeof(in));
    for (i = 0; i < 2 * blkSize && !testPrefixLenRemainder; i++) {
        in[i] = 'A';
        testLen = AES128ECBEncryptOracle(in, strlen((const char*)in), prefix, prefixLen,
                                         unknownStrBase64, unknownStrBase64Len, key, &test);
        for (j = 0; j < testLen / blkSize; j++) {
            if (!memcmp(&test[j * blkSize], cipherBlkA, blkSize)) {
                testPrefixLenRemainder = blkSize - 1 - (i % blkSize);
                testPrefixLen += testPrefixLenRemainder;
                break;
            }
        }
        free(test);
    }
    free(cipherBlkA);

    /* detect plaintext length */
    // plaintextLen = (cipher length with empty input) - (prefixLen) - (plaintext padding )
    plaintextLen = refOutLen - testPrefixLen;
    memset(in, 0, sizeof(in));
    for (i = 0; i < blkSize; i++) {
        in[i] = 'A';
        testLen = AES128ECBEncryptOracle(in, strlen((const char*)in), prefix, prefixLen,
                                         unknownStrBase64, unknownStrBase64Len, key, &test);
        free(test);
        if (testLen > refOutLen) {
            plaintextLen -= i + 1;
            break;
        }
    }
    plaintext = calloc(plaintextLen + 1, sizeof(unsigned char));
    if (plaintext == NULL) {
        perror("Error: Set 2 Problem 14 calloc error");
        goto err;
    }

    /* byte-at-a-time decryption */
    targetBlkIdx = (testPrefixLen % blkSize) ? testPrefixLen / blkSize + 1 :
                                               testPrefixLen / blkSize;
    size_t testBlkIdx = targetBlkIdx;
    size_t payloadLen = 2 * blkSize - (testPrefixLen % blkSize);
    memset(in, 0x41, payloadLen);
    in[payloadLen] = '\0';
    for (i = 0; i < plaintextLen; i++) {
        if (i && i % blkSize == 0) {
            targetBlkIdx++;
        }
        shiftElementsLeft(in, payloadLen, 1);
        outLen = AES128ECBEncryptOracle(in, payloadLen - 1 - (i % blkSize), prefix, prefixLen,
                                        unknownStrBase64, unknownStrBase64Len, key, &out);
        for (int c = 0; c < 256; c++) {
            in[payloadLen - 1] = c;
            AES128ECBEncryptOracle(in, payloadLen, prefix, prefixLen,
                                   unknownStrBase64, unknownStrBase64Len, key, &test);
            if (!memcmp(&test[testBlkIdx * blkSize], &out[targetBlkIdx * blkSize], blkSize)) {
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
    free(prefix);
    free(unknownStrBase64);
    free(plaintext);

    return 0;
}

size_t AES128ECBEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* prefix, size_t prefixlen,
                              const unsigned char* target, size_t targetlen,
                              const unsigned char* key, unsigned char** out) {
    unsigned char* input = NULL;
    size_t inputlen, outlen;

    inputlen = prefixlen + inlen + targetlen;
    input = calloc(inputlen + 1, sizeof(unsigned char));
    if (input == NULL) {
        perror("Error: AES128ECBEncryptOracle calloc error");
        exit(1);
    }
    memcpy(input, prefix, prefixlen);
    memcpy(&input[prefixlen], in, inlen);
    memcpy(&input[prefixlen + inlen], target, targetlen);

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
