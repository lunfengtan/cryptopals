#include <stdio.h>
#include "cryptopals.h"

int main(void) {
    char validIn[] = "ICE ICE BABY\x04\x04\x04\x04";
    char validOut[] = "ICE ICE BABY";
    char invalidIn1[] = "ICE ICE BABY\x05\x05\x05\x05";
    char invalidIn2[] = "ICE ICE BABY\x01\x02\x03\x04";
    bool ispkcs7Valid;

    printf("Set 2 Problem 15: PKCS#7 padding validation\n");
    printf("input: %s\n", validIn);
    ispkcs7Valid = pkcs7Validate(validIn, strlen((const char*)validIn));
    if (ispkcs7Valid == true) {
        printf("pkcs7 validation success!\n");
        pkcs7Strip(validIn, strlen((const char*)validIn));
        printf("stripped output: %s\n", validIn);
        TEST_STRING_EQUAL(validIn, validOut);
    } else {
        printf("pkcs7 validation failed!\n");
    }

    printf("input: %s\n", invalidIn1);
    ispkcs7Valid = pkcs7Validate(invalidIn1, strlen((const char*)invalidIn1));
    if (ispkcs7Valid == false) {
        printf("pkcs7 validation success!\n");
    } else {
        printf("pkcs7 validation failed!\n");
    }

    printf("input: %s\n", invalidIn2);
    ispkcs7Valid = pkcs7Validate(invalidIn2, strlen((const char*)invalidIn2));
    if (ispkcs7Valid == false) {
        printf("pkcs7 validation success!\n");
    } else {
        printf("pkcs7 validation failed!\n");
    }
}
