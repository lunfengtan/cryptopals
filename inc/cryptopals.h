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

int base64Encode(const unsigned char* in, int inlen, char** out);
int base64Decode(const char* in, int inlen, unsigned char** out);

unsigned char* xor(const unsigned char* in, int inlen, const unsigned char* key, int keylen);
unsigned char findXorKey(const unsigned char* in, int len);

float scoreEnglish(const unsigned char* in, int len);

int hammingDistance(const unsigned char* s1, const unsigned char* s2, int len);
int guessKeySize(const unsigned char* in, int len, int maxKeySize);
void breakRepeatingKeyXor(const unsigned char* in, int inlen,
                          unsigned char** key, int* keySize, int maxkeysize,
                          unsigned char** decoded);

void aes128DecryptECB(const unsigned char* in, int inlen, const unsigned char* key, unsigned char** out);

void strip_newlines(char* s);
void printHex(const char* arr, size_t len);
void printArray(const char* arr, size_t len);

#endif
