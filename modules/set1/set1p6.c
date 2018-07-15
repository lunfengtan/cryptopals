#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    FILE* fp;
    char* fpbuf = NULL;
    unsigned char* raw = NULL, *bestKey = NULL, *decoded = NULL;
    size_t fplen, fpbuflen, rawlen, bestKeySize;

    fp = fopen("../../../data/6.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file '6.txt'");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    fplen = ftell(fp);
    rewind(fp);

    fpbuf = malloc(fplen + 1);
    if (fpbuf == NULL) {
        perror("Error: set1Problem6 malloc error");
        goto err;
    }
    fpbuflen = fread(fpbuf, 1, fplen, fp);
    if (fpbuflen != fplen) {
        perror("Error: set1Problem6 fread error");
        goto err;
    }
    fpbuf[fpbuflen] = '\0';
    strip_newlines(fpbuf);
    fpbuflen = strlen(fpbuf);

    rawlen = base64Decode(fpbuf, fpbuflen, &raw);
    breakRepeatingKeyXor(raw, rawlen, &bestKey, &bestKeySize, 40, &decoded);

    printf("Set 1 Problem 6: Break repeating-key XOR\n");
    printf("key length: %ld\n", bestKeySize);
    printf("key:\n");
    printArray((char*)bestKey, bestKeySize);
    printf("plaintext:\n");
    printArray((char*)decoded, rawlen);

    fclose(fp);

err:
    free(fpbuf);
    free(raw);
    free(bestKey);
    free(decoded);

    return 0;
}