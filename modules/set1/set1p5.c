#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    char* in = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    char* key = "ICE";
    char* ans = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    unsigned char* outHex = NULL;
    char* out = NULL;

    outHex = xor((const unsigned char*)in, strlen(in), (const unsigned char*)key, strlen(key));
    out = hexEncode(outHex, strlen(in));

    printf("Set 1 Problem 5: Repeating-key XOR\n");
    printf("input: %s\n", in);
    printf("key: %s\n", key);
    printf("cipher: %s\n\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(outHex);
    free(out);

    return 0;
}