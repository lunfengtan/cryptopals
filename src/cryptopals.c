#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <float.h>
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
int base64Encode(const unsigned char* in, int inlen, char** out) {
    int outlen, i, j, idx;
    char *outbuf = NULL;

    if (inlen == 0) {
        *out = NULL;
        return 0;
    }

    outlen = ((inlen + 2) / 3) * 4;
    outbuf = malloc(outlen + 1);
    if (outbuf == NULL) {
        perror("Error: base64Encode malloc error");
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
    if (inlen % 3) {
        int padding = 3 - (inlen % 3);
        for (i = 0; i < padding; i++) {
            outbuf[outlen - 1 - i] = '=';
        }
    }
    outbuf[outlen] = '\0';
    *out = outbuf;
    return outlen;

err:
    free(outbuf);
    return -1;
}

/* Decode base64 into raw bytes */
int base64Decode(const char* in, int inlen, unsigned char** out) {
    // size_t inlen = strlen(in);
    int outlen, i, j;
    unsigned char* outbuf = NULL;
    unsigned char byteH, byteL;

    while (inlen >= 0 && in[inlen - 1] == '=') {
        inlen--;
    }

    outlen = inlen * 3 / 4;
    outbuf = malloc(outlen);
    if (outbuf == NULL) {
        perror("Error: base64Decode malloc error");
        goto err;
    }

    for (i = 0, j = 0; i < outlen; i++) {
        byteH = strchr(base64Table, in[j]) - base64Table;
        byteL = strchr(base64Table, in[j + 1]) - base64Table;

        switch (i % 3) {
            case 0:
                outbuf[i] = (byteH << 2) | ((byteL >> 4) & 0x03);
                j++;
                break;
            case 1:
                outbuf[i] = (byteH << 4) | ((byteL >> 2) & 0x0F) ;
                j++;
                break;
            case 2:
                outbuf[i] = (byteH << 6) | (byteL & 0x3F);
                j += 2;
                break;
        }
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

int hammingDistance(const unsigned char* s1, const unsigned char* s2, int len) {
    int i, dist = 0;
    unsigned char xored;

    for (i = 0; i < len; i++) {
        xored = s1[i] ^ s2[i];
        while (xored) {
            xored &= (xored - 1);
            dist++;
        }
    }
    return dist;
}

int guessKeySize(const unsigned char* in, int len, int maxKeySize) {
    int keysize, guessKeySize, dist;
    int nblocks, blk1, blk2;
    float avgDist, minDist = FLT_MAX;

    for (keysize = 2; keysize < maxKeySize; keysize++) {
        dist = 0;
        nblocks = len / keysize;
        for (blk1 = 0; blk1 < nblocks; blk1++) {
            for (blk2 = blk1 + 1; blk2 < nblocks; blk2++) {
                dist += hammingDistance(&in[blk1 * keysize], &in[blk2 * keysize], keysize);
            }
        }
        avgDist = (float)dist / (keysize * nblocks * (nblocks - 1) / 2);
        if (avgDist < minDist) {
            minDist = avgDist;
            guessKeySize = keysize;
        }
    }
    return guessKeySize;
}

void breakRepeatingKeyXor(const unsigned char* in, int inlen,
                          unsigned char** key, int* keySize, int maxKeySize,
                          unsigned char** decoded) {

    unsigned char* transposed = NULL;
    int transposedSize, i, j;

    *key = NULL;
    *keySize = guessKeySize(in, inlen, maxKeySize);
    *key = malloc(*keySize);
    if (*key == NULL) {
        perror("Error: breakRepeatingKeyXor malloc error");
        goto err;
    }
    transposedSize = inlen / (*keySize);    // ignore last line
    transposed = malloc(transposedSize);
    if (transposed == NULL) {
        perror("Error: breakRepeatingKeyXor malloc error");
        goto err;
    }

    for (i = 0; i < *keySize; i++) {
        for (j = 0; j < transposedSize; j++) {
            transposed[j] = in[j * (*keySize) + i];
        }
        (*key)[i] = findXorKey(transposed, transposedSize);
    }
    *decoded = xor(in, inlen, *key, *keySize);

err:
    free(transposed);
}

void AES128DecryptECB(const unsigned char* in, int inlen, const unsigned char* key, unsigned char** out) {
    int offset;
    AES_KEY aesKey;

    *out = calloc((inlen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, sizeof(unsigned char));
    if (*out == NULL) {
        perror("Error: AES128DecryptECB calloc error");
        exit(1);
    }

    AES_set_decrypt_key(key, 128, &aesKey);
    for (offset = 0; offset < inlen; offset += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(in + offset, (*out) + offset, &aesKey, AES_DECRYPT);
    }
}

/* Returns TRUE if the ciphertext is encrypted with AES in ECB mode */
bool detectAES128ECB(const unsigned char* in, int inlen) {
    int numberOfAESBlocks, i, j;

    numberOfAESBlocks = inlen / AES_BLOCK_SIZE;
    for (i = 0; i < numberOfAESBlocks; i++) {
        for (j = i + 1; j < numberOfAESBlocks; j++) {
            if (!memcmp(&in[i * AES_BLOCK_SIZE], &in[j * AES_BLOCK_SIZE], AES_BLOCK_SIZE)) {
                return true;
            }
        }
    }
    return false;
}

void strip_newlines(char* s) {
    char* ptr = s;

    while (ptr != 0 && *ptr != '\0') {
        if (*ptr == '\n') {
            ptr++;
        }
        else {
            *s++ = *ptr++;
        }
    }
    *s = '\0';
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
