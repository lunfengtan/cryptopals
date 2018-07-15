#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    char* in = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    char* ans = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    unsigned char* inRaw;
    char* base64;
    int base64len;

    int inlen = hexDecode(in, &inRaw);
    base64len = base64Encode(inRaw, inlen, &base64);

    printf("Set 1 Problem 1: Convert hex to base64\n");
    printf("input: %s\n", in);
    printf("base64: ");
    printArray(base64, base64len);
    printf("\n");

    TEST_STRING_EQUAL(base64, ans);

    free(inRaw);
    free(base64);

    return 0;
}