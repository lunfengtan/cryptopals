#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

int AES128CBCValidateAsciiOracle(const unsigned char* in, size_t len,
                                 const unsigned char* key, const unsigned char* iv,
                                 unsigned char** out);

int main(void) {
    const char* plaintext = "1122334455667788"
                            "\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF"
                            "AABBCCDDEEFFGGHH"
                            "IIJJKKLLMMNNOOPP"
                            "QQRRSTT";         // len = 72
    unsigned char* cipher = NULL, *decoded = NULL, *buf = NULL;
    unsigned char* key = NULL, *iv = NULL, *extractedkey = NULL;
    size_t cipherlen;

    printf("Set 4 Problem 27: Recover the key from CBC with IV=Key\n");
    printf("plaintext:\n%s\n", plaintext);
    srand(time(NULL));
    key = randomBytes(AES_BLOCK_SIZE);
    iv = key;

    /* encrypt plaintext with iv = key */
    /* AES-CBC(P_1, P_2, P_3) ---> C_1, C_2, C_3 */
    cipherlen = AES128EncryptCBC((const unsigned char*)plaintext, strlen(plaintext), key, iv, &buf);
    // discards the 1st block (IV)
    cipherlen -= AES_BLOCK_SIZE;
    cipher = calloc(cipherlen + 1, sizeof(unsigned char));
    if (cipher == NULL) {
        perror("Error: Set 4 Problem 27 calloc error");
        exit(1);
    }
    memcpy(cipher, &buf[AES_BLOCK_SIZE], cipherlen);

    /* modify the ciphertext */
    /* C_1, C_2, C_3 ---> C_1, 0, C_1 */
    memset(&cipher[AES_BLOCK_SIZE], 0, AES_BLOCK_SIZE);
    memcpy(&cipher[2 * AES_BLOCK_SIZE], &cipher[0], AES_BLOCK_SIZE);

    /* send modified ciphertext to oracle and recover key */
    /* key = P'_1 XOR P'_3 */
    int err = AES128CBCValidateAsciiOracle(cipher, cipherlen, key, iv, &decoded);
    if (err != 0) {
        printf("AES128CBCValidateAsciiOracle:\n");
        printf("Decrypted plaintext is not ASCII compliant!\n");
        printf("decrypted plaintext:\n");
        printArray((const char*)decoded, cipherlen);
    }
    if (decoded != NULL) {
        extractedkey = xor(&decoded[0], AES_BLOCK_SIZE,
                           &decoded[2 * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        if (!memcmp(extractedkey, key, AES_BLOCK_SIZE)) {
            printf("Key successfully recovered!\n");
        } else {
            printf("Key recovery failed!\n");
        }
    }
    free(decoded);
    AES128DecryptCBC(&buf[AES_BLOCK_SIZE], cipherlen, extractedkey, extractedkey, &decoded);
    printf("Recovered plaintext:\n");
    printArray((const char*)decoded, cipherlen);

    free(buf);
    free(key);
    free(extractedkey);
    free(cipher);
    free(decoded);

    return 0;
}

int AES128CBCValidateAsciiOracle(const unsigned char* in, size_t len,
                                 const unsigned char* key, const unsigned char* iv,
                                 unsigned char** out) {
    AES128DecryptCBC(in, len, key, iv, out);
    for (size_t i = 0; i < len; i++) {
        if ((uint8_t)(*out)[i] > 127) {
            return -1;
        }
    }
    free(*out);
    *out  = NULL;
    return 0;
}

