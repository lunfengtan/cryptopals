#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/aes.h>
#include "cryptopals.h"

unsigned char* edit(const unsigned char* cipher, size_t cipherlen,
                    const unsigned char* key, uint64_t nonce, size_t offset,
                    unsigned char* newtext, size_t newtextlen);


int main(void) {
    FILE* fp;
    char* fpbuf = NULL;
    unsigned char* raw = NULL, *cipher = NULL;
    unsigned char* plaintext = NULL, *decoded = NULL;
    char* ecbkey = "YELLOW SUBMARINE";

    fp = fopen("../../../data/7.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file '7.txt'");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    int fplen = ftell(fp);
    rewind(fp);

    fpbuf = malloc(fplen + 1);
    if (fpbuf == NULL) {
        perror("Error: Set 4 Problem 25 malloc error");
        exit(1);
    }
    int fpbuflen = fread(fpbuf, 1, fplen, fp);
    if (fpbuflen != fplen) {
        perror("Error: Set 4 Problem 25 fread error");
        exit(1);
    }
    fpbuf[fpbuflen] = '\0';
    strip_newlines(fpbuf);
    int rawlen = base64Decode(fpbuf, strlen(fpbuf), &raw);
    AES128DecryptECB(raw, rawlen, (const unsigned char*)ecbkey, &plaintext);
    free(fpbuf);
    free(raw);
    fclose(fp);

    /* re-encrypt plaintext with random CTR key and nonce */
    printf("Set 4 Problem 25: Break random access read/write AES CTR\n");
    srand(time(NULL));
    unsigned char* ctrkey = randomBytes(AES_BLOCK_SIZE);
    uint64_t ctrnonce = ((uint64_t)rand() << 32) | rand();
    size_t len = strlen((const char*)plaintext);
    AES128EncryptCTR(plaintext, len, ctrkey, ctrnonce, &cipher);

    /* use edit() to obtain the encryption of an array of all 0's, this gives us the keystream */
    unsigned char* zeroArray = calloc(len, sizeof(unsigned char));
    if (zeroArray == NULL) {
        perror("Error: Set 4 Problem 25 calloc error");
        exit(1);
    }
    unsigned char* keystream = edit(cipher, len, ctrkey, ctrnonce, 0, zeroArray, len);

    /* plaintext = ciphertext ^ keystream */
    decoded = xor(cipher, len, keystream, len);
    printf("decoded:\n");
    printArray((const char*)decoded, len);

    free(cipher);
    free(plaintext);
    free(ctrkey);
    free(zeroArray);
    free(keystream);
    free(decoded);

    return 0;
}

unsigned char* edit(const unsigned char* cipher, size_t cipherlen,
                    const unsigned char* key, uint64_t nonce, size_t offset,
                    unsigned char* newtext, size_t newtextlen) {
    if (offset + newtextlen > cipherlen)
        return NULL;

    unsigned char* pt = NULL, *newcipher = NULL;

    AES128DecryptCTR(cipher, cipherlen, key, nonce, &pt);
    for (size_t i = 0; i < newtextlen; i++) {
        pt[offset + i] = newtext[i];
    }
    size_t ptlen = cipherlen;
    AES128EncryptCTR(pt, ptlen, key, nonce, &newcipher);
    free(pt);

    return newcipher;
}
