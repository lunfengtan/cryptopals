#include <math.h>
#include <time.h>
#include <unistd.h>
#include "hmac_sha1_oracle.h"

static int milisleep(unsigned int ms) {
    const struct timespec ts = {
        ms / 1000,                    /* seconds */
        (ms % 1000) * 1000 * 1000     /* nano seconds */
    };
    return nanosleep(&ts, NULL);
}

static bool insecure_compare_eq(const unsigned char* x, size_t xlen,
                                const unsigned char* y, size_t ylen,
                                unsigned int delay_ms) {
    if (xlen != ylen) {
        return false;
    }
    for (size_t i = 0; i < xlen; i++) {
        if (x[i] != y[i]) {
            return false;
        }
        milisleep(delay_ms);
    }
    return true;
}

void hmac_sha1_oracle_init(HmacSha1Oracle* self,
                           const unsigned char* msg, size_t msglen,
                           unsigned int ms) {
    srand(time(NULL));
    self->keylen = rand() % MAX_KEY_SIZE + 1;
    for (size_t i = 0; i < self->keylen; i++) {
        self->key[i] = rand();
    }
    hmac_sha1(msg, msglen, self->key, self->keylen, self->expected_mac);
    self->delay_ms = ms;
}

bool hmac_sha1_oracle_verify(HmacSha1Oracle* self,
                             const unsigned char* mac, size_t maclen) {
    return insecure_compare_eq(mac, maclen, self->expected_mac, SHA1_HASH_SIZE, self->delay_ms);
}

long timestamp_ms(void) {
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return spec.tv_sec * 1000 + round(spec.tv_nsec / 1.0e6);
}
