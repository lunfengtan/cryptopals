#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    char* in = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    unsigned char *inRaw = NULL, *out = NULL;
    int inRawLen;
    unsigned char key;

    inRawLen = hexDecode(in, &inRaw);
    key = findXorKey(inRaw, inRawLen);
    out = xor(inRaw, inRawLen, (unsigned char*)&key, 1);

    printf("Set 1 Problem 3: Single-byte XOR cipher\n");
    printf("plaintext:\n");
    printArray((char*)out, inRawLen);
    printf("\n");

    free(inRaw);
    free(out);

    return 0;
}