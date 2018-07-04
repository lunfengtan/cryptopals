#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "set1.h"
#include "cryptopals.h"

void set2Problem1(void) {
    char* in = "YELLOW SUBMARINE";
    char* ans = "YELLOW SUBMARINE\x04\x04\x04\x04";
    char* out = NULL;

    out = pkcs7Pad(in, strlen(in), 20);

    printf("Set 2 Problem 1: Implement PKCS#7 padding\n");
    printf("input: %s\n", in);
    printf("output: %s\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(out);
}
