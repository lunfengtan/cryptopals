#ifndef HMAC_SHA1_ORACLE_H
#define HMAC_SHA1_ORACLE_H

#include "cryptopals.h"

#define MIN_KEY_SIZE    1
#define MAX_KEY_SIZE    16

typedef struct {
    unsigned char key[MAX_KEY_SIZE];
    size_t keylen;
    unsigned char expected_mac[SHA1_BLOCK_SIZE];
    unsigned int delay_ms;
} HmacSha1Oracle;

void hmac_sha1_oracle_init(HmacSha1Oracle* self,
                           const unsigned char* msg, size_t msglen,
                           unsigned int ms);
bool hmac_sha1_oracle_verify(HmacSha1Oracle* self,
                             const unsigned char* mac, size_t maclen);

long timestamp_ms(void);

#endif
