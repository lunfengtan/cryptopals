#include <stdlib.h>
#include <stdio.h>
#include "cryptopals.h"

int main(void)
{
    const char* cipher = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    const char* key = "YELLOW SUBMARINE";
    unsigned char* bytes = NULL, *decoded = NULL, *encrypted = NULL;
    size_t len;

    len = base64Decode(cipher, strlen(cipher), &bytes);
    AES128CTR(bytes, len, (const unsigned char*)key, 0, &decoded);

    printf("Set 3 Problem 18: Implement CTR, the stream cipher mode\n");
    printf("cipher: %s\n", cipher);
    printf("decoded: ");
    printArray((const char*)decoded, len);

    AES128CTR(decoded, len, (const unsigned char*)key, 0, &encrypted);
    free(bytes);
    base64Encode(encrypted, len, &bytes);
    TEST_STRING_EQUAL((const char*)bytes, cipher);

    free(encrypted);
    free(decoded);
    free(bytes);

    return 0;
}
