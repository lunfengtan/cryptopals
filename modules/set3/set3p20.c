#include <stdio.h>
#include <stdlib.h>
#include "cryptopals.h"

int main(void) {
    FILE* fp;
    char line[256];
    unsigned char* ciphers[64] = { 0 };
    unsigned char* buf = NULL, *key = NULL, *decoded = NULL;
    size_t numLines = 0, minLineLen = INT32_MAX, buflen;

    fp = fopen("../../../data/20.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file '20.txt'");
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = base64Decode(line, strlen(line), &ciphers[numLines]);
        minLineLen = MIN(len, minLineLen);
        numLines++;
    }

    buflen = numLines * minLineLen;
    buf = calloc(buflen + 1, sizeof(unsigned char));
    if (buf == NULL) {
        perror("Error: Set 3 Problem 20 calloc error");
        exit(1);
    }
    for (size_t i = 0; i < numLines; i++) {
        memcpy(&buf[i * minLineLen], ciphers[i], minLineLen);
    }
    key = malloc(minLineLen);
    if (key == NULL) {
        perror("Error: Set 3 Problem 20 malloc error");
        exit(1);
    }
    breakRepeatingKeyXor(buf, buflen, key, minLineLen, &decoded);

    printf("Set 3 Problem 20: Break fixed-nonce CTR statistically\n");
    printf("decoded:\n");
    printArray((const char*)decoded, buflen);

    fclose(fp);
    free(buf);
    free(key);
    free(decoded);
    for (size_t i = 0; i < numLines; i++) {
        free(ciphers[i]);
    }

    return 0;
}
