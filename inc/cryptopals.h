#ifndef CRYPTOPALS_H
#define CRYPTOPALS_H

#include <stdlib.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define TEST_STRING_EQUAL(x, ans) \
    do { \
        if (strcmp(x, ans) != 0) \
            printf("Wrong answer!\n"); \
    } while (0)

int hexDecode(const char* in, unsigned char** out);
char* hexEncode(const unsigned char* in, int len);

int Base64Encode(const unsigned char* in, char** out);

unsigned char* xor(const unsigned char* in, int inlen, const unsigned char* key, int keylen);
unsigned char findXorKey(const unsigned char* in, int len);

float scoreEnglish(const unsigned char* in, int len);

void printHex(const char* arr, size_t len);
void printArray(const char* arr, size_t len);

#endif
