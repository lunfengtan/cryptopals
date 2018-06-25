#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/aes.h>
#include "cryptopals.h"

const static char base64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const static float letterFreq[] = { 8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074 };

/* Decode hex into raw bytes */
int hexDecode(const char* in, unsigned char** out) {
    size_t inlen = strlen(in);
    unsigned char *outbuf;
    int outlen, i;

    if (inlen == 0) {
        *out = NULL;
        return 0;
    }

    outlen = inlen >> 1;
    outbuf = malloc(outlen);
    if (outbuf == NULL) {
        perror("Error: hexDecode malloc error");
        goto err;
    }

    for (i = 0; i < outlen; i++) {
        sscanf(in, "%02hhx", &outbuf[i]);
        in += 2;
    }

    *out = outbuf;
    return outlen;

err:
    free(outbuf);
    return -1;
}

/* Encode raw bytes into hex */
char* hexEncode(const unsigned char* in, int len) {
    char* out = NULL;
    int outlen, i;

    outlen = len * 2;
    out = malloc(outlen + 1);
    if (out == NULL) {
        perror("Error: hexEncode malloc error");
        goto exit;
    }

    for (i = 0; i < len; i++) {
        sprintf(&out[2 * i], "%02x", in[i]);
    }
    out[outlen] = '\0';

exit:
    return out;
}

/* Encode raw bytes into base64 */
int Base64Encode(const unsigned char* in, char** out) {
    size_t inlen = strlen((const char *) in);
    int outlen, i, j, idx;
    char *outbuf = NULL;

    if (inlen == 0) {
        *out = NULL;
        return 0;
    }

    outlen = inlen * 4 / 3;
    outbuf = malloc(outlen);
    if (outbuf == NULL) {
        perror("Error: Base64Encode malloc error");
        goto err;
    }

    for (i = 0, j = 0; i < outlen; i++) {
        switch (i % 4) {
            case 0:
                idx = in[j] >> 2;
                break;
            case 1:
                idx = (in[j] << 4) | (in[j + 1] >> 4);
                idx &= 0x3F;
                j++;
                break;
            case 2:
                idx = (in[j] << 2) | (in[j + 1] >> 6);
                idx &= 0x3F;
                j++;
                break;
            case 3:
                idx = in[j++];
                idx &= 0x3F;
                break;
        }
        outbuf[i] = base64Table[idx];
    }

    *out = outbuf;
    return outlen;

err:
    free(outbuf);
    return -1;
}

/* XORs message with key */
unsigned char* xor(const unsigned char* in, int inlen, const unsigned char* key, int keylen) {
    int i;
    unsigned char* out = NULL;

    out = malloc(inlen);
    if (out == NULL) {
        perror("Error: xor malloc error");
        goto err;
    }

    for (i = 0; i < inlen; i++) {
        out[i] = in[i] ^ key[i % keylen];
    }
    return out;

err:
    free(out);
    return NULL;
}

/* Find the single-byte XOR key which decrypts message into plaintext English */
unsigned char findXorKey(const unsigned char* in, int len) {
    unsigned char key;
    unsigned char *xored;
    float score, maxScore = 0.f;
    int k;

    for (k = 0; k < 256; k++) {
        xored = xor(in, len, (unsigned char*)&k, 1);
        score = scoreEnglish(xored, len);
        if (score > maxScore) {
            maxScore = score;
            key = k;
        }
        free(xored);
    }
    return key;
}

/* Scores message based on the character frequency in English */
float scoreEnglish(const unsigned char* in, int len) {
    int i;
    float score = 0.f;

    for (i = 0; i < len; i++) {
        if (isalpha(in[i])) {
            score += letterFreq[ toupper(in[i]) - 'A' ];
        }
        else if (in[i] == ' ') {
            score += 0.20f;
        }
        else
            score -= 20.0;
    }
    return score;
}


void printHex(const char* arr, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%0x", arr[i]);
    }
    printf("\n");
}

void printArray(const char* arr, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%c", arr[i]);
    }
    printf("\n");
}
