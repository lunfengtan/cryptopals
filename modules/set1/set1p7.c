#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    FILE* fp;
    char* fpbuf = NULL;
    unsigned char* raw = NULL, *decoded = NULL;
    int fplen, fpbuflen, rawlen;
    char* key = "YELLOW SUBMARINE";

    fp = fopen("../../../data/7.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file '7.txt'");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    fplen = ftell(fp);
    rewind(fp);

    fpbuf = malloc(fplen + 1);
    if (fpbuf == NULL) {
        perror("Error: set1Problem7 malloc error");
        goto err;
    }
    fpbuflen = fread(fpbuf, 1, fplen, fp);
    if (fpbuflen != fplen) {
        perror("Error: set1Problem7 fread error");
        goto err;
    }
    fpbuf[fpbuflen] = '\0';
    strip_newlines(fpbuf);
    fpbuflen = strlen(fpbuf);

    rawlen = base64Decode(fpbuf, fpbuflen, &raw);
    AES128DecryptECB(raw, rawlen, (const unsigned char*)key, &decoded);

    printf("Set 1 Problem 7: AES in ECB mode\n");
    printf("key: %s\n", key);
    printf("plaintext:\n");
    printArray((char*)decoded, rawlen);

    fclose(fp);

err:
    free(fpbuf);
    free(raw);
    free(decoded);

    return 0;
}