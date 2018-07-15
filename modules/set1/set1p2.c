#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    char* in  = "1c0111001f010100061a024b53535009181c";
    char* key = "686974207468652062756c6c277320657965";
    char* ans = "746865206b696420646f6e277420706c6179";
    unsigned char *inRaw = NULL, *keyHex = NULL, *outHex = NULL;
    int inRawLen, keyHexLen;
    char *out;

    inRawLen = hexDecode(in, &inRaw);
    keyHexLen = hexDecode(key, &keyHex);
    outHex = xor(inRaw, inRawLen, keyHex, keyHexLen);
    out = hexEncode(outHex, inRawLen);

    printf("Set 1 Problem 2: Fixed XOR\n");
    printf("input: %s\n", in);
    printf("key: %s\n", key);
    printf("cipher: %s\n\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(inRaw);
    free(keyHex);
    free(outHex);
    free(out);

    return 0;
}