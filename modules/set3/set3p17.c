#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

bool AES128CBCPaddingOracle(const unsigned char* in, size_t inlen,
                            const unsigned char* key, const unsigned char* iv);
void solveIntermediateBlock(const unsigned char* cipher,
                             const unsigned char* key, const unsigned char* iv,
                             unsigned char* out);

int main(void) {
    const char* base64Array[] = { "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                                  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                                  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                                  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                                  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                                  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                                  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                                  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                                  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                                  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
                                };
    unsigned char* key = NULL, *iv = NULL;
    unsigned char* bytes = NULL, *cipher = NULL, *decoded = NULL;
    unsigned char intermediateBlock[AES_BLOCK_SIZE];
    size_t bytesLen, cipherLen, decodedLen;

    printf("Set 3 Problem 17: The CBC padding oracle\n");
    srand(time(NULL));
    key = randomBytes(AES_BLOCK_SIZE);
    iv = randomBytes(AES_BLOCK_SIZE);

    for (size_t i = 0; i < SIZEOF_ARRAY(base64Array); i++) {
        bytesLen = base64Decode(base64Array[i], strlen(base64Array[i]), &bytes);
        cipherLen = AES128EncryptCBC(bytes, bytesLen, key, iv, &cipher);
        decodedLen = cipherLen;

        decoded = calloc(decodedLen + 1, sizeof(unsigned char));
        if (decoded == NULL) {
            perror("Error: Set 3 Problem 17 calloc error");
            goto exit;
        }
        size_t numberOfBlocks = cipherLen / AES_BLOCK_SIZE;
        for (size_t j = 0; j < numberOfBlocks - 1; j++) {
            size_t blkOffset = cipherLen - ((j + 1) * AES_BLOCK_SIZE);
            solveIntermediateBlock(&cipher[blkOffset], key, iv, intermediateBlock);
            for (size_t k = 0; k < AES_BLOCK_SIZE; k++) {
                decoded[blkOffset + k] =  cipher[blkOffset - AES_BLOCK_SIZE + k] ^ intermediateBlock[k];
            }
        }
        decoded = (unsigned char*)pkcs7Strip((char*)decoded, decodedLen);

        printf("cipher:\n%s\n", base64Array[i]);
        printf("decoded:\n");
        printArray((const char*)decoded, decodedLen);
        free(decoded);
        free(cipher);
        free(bytes);
    }

exit:
    free(key);
    free(iv);

    return 0;
}

void solveIntermediateBlock(const unsigned char* cipher,
                             const unsigned char* key, const unsigned char* iv,
                             unsigned char* out) {
    unsigned char buf[2 * AES_BLOCK_SIZE];
    memcpy(&buf[AES_BLOCK_SIZE], cipher, AES_BLOCK_SIZE);

    for (size_t i = 1; i <= AES_BLOCK_SIZE; i++) {
        for (int ch = 0; ch < 256; ch++) {
            buf[AES_BLOCK_SIZE - i] = ch;
            if (AES128CBCPaddingOracle(buf, sizeof(buf), key, iv)) {
                out[AES_BLOCK_SIZE - i] = i ^ buf[AES_BLOCK_SIZE - i];
                for (size_t j = AES_BLOCK_SIZE - i; j < AES_BLOCK_SIZE; j++) {
                    buf[j] = out[j] ^ (i + 1);
                }
                break;
            }
        }
    }
}

bool AES128CBCPaddingOracle(const unsigned char* in, size_t inlen,
                            const unsigned char* key, const unsigned char* iv) {
    AES_KEY aesKey;
    unsigned char* xored = NULL, *out = NULL;
    unsigned char decryptedOut[AES_BLOCK_SIZE];
    bool isPaddingValid;

    out = calloc(inlen + 1, sizeof(unsigned char));
    if (out == NULL) {
        perror("Error: AES128CBCPaddingOracle calloc error");
        exit(1);
    }
    AES_set_decrypt_key(key, 128, &aesKey);
    for (size_t i = 0; i < inlen; i += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(&in[i], &decryptedOut[0], &aesKey, AES_DECRYPT);
        if (i == 0) {
            xored = xor(decryptedOut, AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE);
        } else {
            xored = xor(decryptedOut, AES_BLOCK_SIZE, &in[i - AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        }
        memcpy(out + i, xored, AES_BLOCK_SIZE);
        free(xored);
    }

    isPaddingValid = pkcs7Validate((const char*)out, inlen);
    free(out);

    return isPaddingValid;
}

