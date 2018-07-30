#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

size_t AES128CBCEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* prefix, size_t prefixlen,
                              const unsigned char* suffix, size_t suffixlen,
                              const unsigned char* key, const unsigned char* iv,
                              unsigned char** out);

int main(void) {
    const char* prefix = "comment1=cooking%20MCs;userdata=";           // len = 32
    const char* suffix = ";comment2=%20like%20a%20pound%20of%20bacon"; // len = 42
    unsigned char* key = NULL, *iv = NULL;
    unsigned char* cipher = NULL, *decoded = NULL;
    unsigned char payload[2 * AES_BLOCK_SIZE];
    size_t cipherLen, i;

    srand(time(NULL));
    key = randomBytes(AES_BLOCK_SIZE);
    iv = randomBytes(AES_BLOCK_SIZE);

    memset(payload, 0x41, sizeof(payload));
    cipherLen = AES128CBCEncryptOracle(payload, sizeof(payload),
                                       (const unsigned char*)prefix, strlen((const char*)prefix),
                                       (const unsigned char*)suffix, strlen((const char*)suffix),
                                       key, iv, &cipher);

    // new Ci-1 = desired_plaintext ^ D(k, Ci) = desired_plaintext ^ Pi ^ old Ci-1
    const unsigned char* desiredPlaintextBlock = (const unsigned char*)"12345;admin=true";
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        cipher[3 * AES_BLOCK_SIZE + i] = desiredPlaintextBlock[i]
                                         ^ payload[AES_BLOCK_SIZE + i]
                                         ^ cipher[3 * AES_BLOCK_SIZE + i];
    }
    AES128DecryptCBC(&cipher[AES_BLOCK_SIZE], cipherLen - AES_BLOCK_SIZE, key, &cipher[0], &decoded);

    printf("Set 2 Problem 16: CBC bitflipping attacks\n");
    printf("cipher: ");
    printArray((const char*)cipher, cipherLen);
    printf("\ndecoded: %s\n", decoded);
    if (strstr((const char*)decoded, ";admin=true;")) {
        printf("Success!\n");
    } else {
        printf("Failed!\n");
    }

    free(key);
    free(iv);
    free(cipher);
    free(decoded);

    return 0;
}

size_t AES128CBCEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* prefix, size_t prefixlen,
                              const unsigned char* suffix, size_t suffixlen,
                              const unsigned char* key, const unsigned char* iv,
                              unsigned char** out) {
    unsigned char buf[inlen + 1];
    unsigned char* input = NULL;
    size_t inputLen, outlen;
    size_t i, j;

    memcpy(buf, in, inlen);
    buf[inlen] = '\0';
    for (i = 0, j = 0; j < inlen; j++) {
        if (buf[j] != ';' && buf[j] != '=') {
            buf[i] = buf[j];
            i++;
        }
    }
    buf[i] = '\0';

    inputLen = prefixlen + strlen((const char*)buf) + suffixlen;
    input = calloc(inputLen + 1, sizeof(unsigned char));
    if (input == NULL) {
        perror("Error: AES128CBCEncryptOracle calloc error");
        exit(1);
    }
    memcpy(input, prefix, prefixlen);
    memcpy(&input[prefixlen], buf, strlen((const char*)buf));
    memcpy(&input[prefixlen + strlen((const char*)buf)], suffix, suffixlen);

    outlen = AES128EncryptCBC(input, inputLen, key, iv, out);
    free(input);

    return outlen;
}

