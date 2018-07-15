#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
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

    fp = fopen("../../../data/10.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file '10.txt'");
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

    return 0;
}