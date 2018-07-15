#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    FILE* fp;
    char line[64];
    unsigned char ans[64];
    unsigned char *inRaw = NULL, *xored = NULL;
    float score, maxScore = 0.f;
    int k, inRawLen;

    fp = fopen("../../../data/4.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file '4.txt'");
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        inRawLen = hexDecode(line, &inRaw);
        for (k = 0; k < 256; k++) {
            xored = xor(inRaw, inRawLen, (unsigned char*)&k, 1);
            score = scoreEnglish(xored, inRawLen);
            if (score > maxScore) {
                maxScore = score;
                memcpy(ans, xored, inRawLen);
            }
            free(xored);
        }
        free(inRaw);
    }
    fclose(fp);

    printf("Set 1 Problem 4: Detect single-character XOR\n");
    printf("plaintext:\n");
    printArray((char*)ans, inRawLen);

    return 0;
}