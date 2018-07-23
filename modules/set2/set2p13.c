#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>
#include "kvPairs.h"
#include "cryptopals.h"

size_t AES128ECBEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* key, unsigned char** out);
profile_t* AES128ECBDecryptAndParse(const unsigned char* in, size_t inlen, const unsigned char* key);

int main(void) {
    const char* evilEmail = "12345@bar."
                            "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                            "com";
    char* evilProfileStr = NULL;
    unsigned char* payload = NULL;
    profile_t* adminProfile = NULL;
    unsigned char* out = NULL, *key = NULL;

    srand(time(NULL));
    key = randomBytes(AES_BLOCK_SIZE);

    //      blk #0      |      blk #1      |      blk #2      |      blk #3
    // email=12345@bar. | admin\x0b...\x0b | com&uid=10&role= | user...
    profileFor(evilEmail, strlen(evilEmail), &evilProfileStr);
    AES128ECBEncryptOracle((unsigned char*)evilProfileStr, strlen(evilProfileStr), key, &out);

    payload = calloc(3 * AES_BLOCK_SIZE + 1, sizeof(char));
    if (payload == NULL) {
        perror("Error: Set 2 Problem 13 calloc error");
        exit(1);
    }

    //      blk #0      |      blk #1      |      blk #2      |
    // email=12345@bar. | com&uid=10&role= | admin\x0b...\x0b |
    memcpy(payload, out, AES_BLOCK_SIZE);
    memcpy(&payload[AES_BLOCK_SIZE], &out[2 * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
    memcpy(&payload[2 * AES_BLOCK_SIZE], &out[AES_BLOCK_SIZE], AES_BLOCK_SIZE);

    printf("Set 2 Problem 13: ECB cut-and-paste\n");
    printf("evil email: %s\n", evilEmail);
    adminProfile = AES128ECBDecryptAndParse(payload, strlen((const char*)payload), key);
    kvPair_t* kv = adminProfile->kvPairListHead;
    while (kv) {
        if (!strcmp(kv->key, "role") && !strcmp(kv->value, "admin")) {
            printf("admin profile successfully constructed!\n");
            goto exit;
        }
        kv = kv->next;
    }
    printf("Failed to construct admin profile!\n");

exit:
    free(evilProfileStr);
    free(payload);
    freeProfile(&adminProfile);
    free(out);
    free(key);

    return 0;
}

size_t AES128ECBEncryptOracle(const unsigned char* in, size_t inlen,
                              const unsigned char* key, unsigned char** out) {
    return AES128EncryptECB(in, inlen, key, out);
}

profile_t* AES128ECBDecryptAndParse(const unsigned char* in, size_t inlen, const unsigned char* key) {
    unsigned char* out = NULL;
    profile_t* p = NULL;

    AES128DecryptECB(in, inlen, key, &out);
    p = parseProfileString((char*)out, strlen((const char*)out));
    printf("profile string: %s\n", out);
    free(out);

    return p;
}
