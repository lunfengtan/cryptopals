#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    FILE* fp;
    char line[512];
    unsigned char *inRaw = NULL;
    int lineNumber, inRawLen;

    fp = fopen("../../../data/8.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file '8.txt'");
        exit(1);
    }

    printf("Set 1 Problem 8: Detect AES in ECB mode\n");
    lineNumber = 1;
    while (fgets(line, sizeof(line), fp)) {
        inRawLen = hexDecode(line, &inRaw);
        if (detectAES128ECB(inRaw, inRawLen)) {
            printf("AES ECB encryption detected at line %d\n", lineNumber);
            printf("cipher:\n");
            printArray(line, strlen(line));
            free(inRaw);
            break;
        }
        lineNumber++;
        free(inRaw);
    }
    fclose(fp);

    return 0;
}