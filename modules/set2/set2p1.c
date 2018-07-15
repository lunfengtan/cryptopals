#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    char* in = "YELLOW SUBMARINE";
    char* ans = "YELLOW SUBMARINE\x04\x04\x04\x04";
    char* out = NULL;

    pkcs7Pad(in, strlen(in), 20, &out);

    printf("Set 2 Problem 1: Implement PKCS#7 padding\n");
    printf("input: %s\n", in);
    printf("output: %s\n\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(out);

    return 0;
}