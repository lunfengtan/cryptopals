#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

size_t AES128CTREncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* prefix, size_t prefixlen,
                              const unsigned char* suffix, size_t suffixlen,
                              const unsigned char* key, uint64_t nonce,
                              unsigned char** out);

int main(void) {
    const char* prefix = "comment1=cooking%20MCs;userdata=";           // len = 32
    const char* suffix = ";comment2=%20like%20a%20pound%20of%20bacon"; // len = 42
    unsigned char* key = NULL;
    unsigned char* cipher = NULL, *decoded = NULL;
    unsigned char payload[AES_BLOCK_SIZE];
    size_t cipherLen, i;
    uint64_t nonce;

    srand(time(NULL));
    key = randomBytes(AES_BLOCK_SIZE);
    nonce = ((uint64_t)rand() << 32) | rand();

    /* encrypt input block AAAA...A */
    memset(payload, 0x41, sizeof(payload));
    cipherLen = AES128CTREncryptOracle(payload, sizeof(payload),
                                       (const unsigned char*)prefix, strlen((const char*)prefix),
                                       (const unsigned char*)suffix, strlen((const char*)suffix),
                                       key, nonce, &cipher);

    /* keystream = cipher ^ plaintext */
    /* cipher_new = desired_plaintext ^ keystream
                  = desired_plaintext ^ cipher ^ plaintext */
    const unsigned char* desiredPlaintextBlock = (const unsigned char*)"12345;admin=true";
    size_t offset = strlen(prefix);
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        cipher[offset + i] = desiredPlaintextBlock[i] ^ cipher[offset + i] ^ payload[i];
    }
    AES128DecryptCTR(cipher, cipherLen, key, nonce, &decoded);

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
    free(cipher);
    free(decoded);

    return 0;
}

size_t AES128CTREncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* prefix, size_t prefixlen,
                              const unsigned char* suffix, size_t suffixlen,
                              const unsigned char* key, uint64_t nonce,
                              unsigned char** out) {
    unsigned char buf[inlen + 1];
    unsigned char* input = NULL;
    size_t inputlen;
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

    inputlen = prefixlen + strlen((const char*)buf) + suffixlen;
    input = calloc(inputlen + 1, sizeof(unsigned char));
    if (input == NULL) {
        perror("Error: AES128CBCEncryptOracle calloc error");
        exit(1);
    }
    memcpy(input, prefix, prefixlen);
    memcpy(&input[prefixlen], buf, strlen((const char*)buf));
    memcpy(&input[prefixlen + strlen((const char*)buf)], suffix, suffixlen);

    AES128EncryptCTR(input, inputlen, key, nonce, out);
    free(input);

    return inputlen;
}

