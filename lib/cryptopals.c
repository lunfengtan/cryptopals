#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <float.h>
#include <openssl/aes.h>
#include "cryptopals.h"

const static char base64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const static float letterFreq[] = { 8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074 };

/* Decode hex into raw bytes */
size_t hexDecode(const char* in, unsigned char** out) {
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
char* hexEncode(const unsigned char* in, size_t len) {
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
size_t base64Encode(const unsigned char* in, size_t inlen, char** out) {
    size_t outlen, i, j, idx;
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
size_t base64Decode(const char* in, size_t inlen, unsigned char** out) {
    int outlen, i, j;
    unsigned char* outbuf = NULL;
    unsigned char byteH, byteL;

    while (inlen >= 0 && in[inlen - 1] == '=') {
        inlen--;
    }

    outlen = inlen * 3 / 4;
    outbuf = calloc(outlen + 1, sizeof(unsigned char));
    if (outbuf == NULL) {
        perror("Error: base64Decode calloc error");
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
unsigned char* xor(const unsigned char* in, size_t inlen, const unsigned char* key, size_t keylen) {
    size_t i;
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
unsigned char findXorKey(const unsigned char* in, size_t len) {
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
float scoreEnglish(const unsigned char* in, size_t len) {
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

int hammingDistance(const unsigned char* s1, const unsigned char* s2, size_t len) {
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

size_t guessKeySize(const unsigned char* in, size_t len, size_t maxKeySize) {
    size_t keysize, guessKeySize;
    int dist, nblocks, blk1, blk2;
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

void breakRepeatingKeyXor(const unsigned char* in, size_t inlen,
                          unsigned char** key, size_t* keySize, size_t maxKeySize,
                          unsigned char** decoded) {

    unsigned char* transposed = NULL;
    size_t transposedSize, i, j;

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

size_t AES128EncryptECB(const unsigned char* in, size_t len, const unsigned char* key, unsigned char** out) {
    size_t outlen, offset;
    AES_KEY aesKey;
    char* padded = NULL;

    outlen = pkcs7Pad((const char*)in, len, AES_BLOCK_SIZE, &padded);
    *out = calloc(outlen + 1, sizeof(unsigned char));
    if (*out == NULL) {
        perror("Error: AES128EncryptECB calloc error");
        exit(1);
    }

    AES_set_encrypt_key(key, 128, &aesKey);
    for (offset = 0; offset < outlen; offset += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(in + offset, (*out) + offset, &aesKey, AES_ENCRYPT);
    }
    free(padded);

    return outlen;
}

void AES128DecryptECB(const unsigned char* in, size_t len, const unsigned char* key, unsigned char** out) {
    size_t offset;
    AES_KEY aesKey;

    *out = calloc(len + 1, sizeof(unsigned char));
    if (*out == NULL) {
        perror("Error: AES128DecryptECB calloc error");
        exit(1);
    }

    AES_set_decrypt_key(key, 128, &aesKey);
    for (offset = 0; offset < len; offset += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(in + offset, (*out) + offset, &aesKey, AES_DECRYPT);
    }
    *out = (unsigned char*)pkcs7Strip((char*)*out, len);
}

size_t AES128EncryptCBC(const unsigned char* in, size_t inlen,
                      const unsigned char* key, const unsigned char* iv, unsigned char** out) {

    unsigned char* padded = NULL, *xored = NULL;
    AES_KEY aesKey;
    size_t outlen, i;

    outlen = AES_BLOCK_SIZE + pkcs7Pad((const char*)in, inlen, AES_BLOCK_SIZE, (char**)&padded);
    *out = calloc(outlen + 1, sizeof(unsigned char));
    if (*out == NULL) {
        perror("Error: AES128EncryptCBC calloc error");
        exit(1);
    }

    memcpy(*out, iv, AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 128, &aesKey);
    for (i = 0; i < outlen; i += AES_BLOCK_SIZE) {
        xored = xor(&padded[i], AES_BLOCK_SIZE, (*out) + i, AES_BLOCK_SIZE);
        AES_ecb_encrypt(xored, &(*out)[i + AES_BLOCK_SIZE], &aesKey, AES_ENCRYPT);
        free(xored);
    }
    free(padded);

    return outlen;
}

void AES128DecryptCBC(const unsigned char* in, size_t inlen,
                      const unsigned char* key, const unsigned char* iv, unsigned char** out) {
    AES_KEY aesKey;
    size_t i;
    unsigned char* xored = NULL;
    unsigned char decryptedOut[AES_BLOCK_SIZE];

    *out = calloc(inlen + 1, sizeof(unsigned char));
    if (*out == NULL) {
        perror("Error: AES128DecryptCBC calloc error");
        exit(1);
    }

    AES_set_decrypt_key(key, 128, &aesKey);
    for (i = 0; i < inlen; i += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(&in[i], &decryptedOut[0], &aesKey, AES_DECRYPT);
        if (i == 0) {
            xored = xor(decryptedOut, AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE);
        } else {
            xored = xor(decryptedOut, AES_BLOCK_SIZE, &in[i - AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        }
        memcpy((*out) + i, xored, AES_BLOCK_SIZE);
        free(xored);
    }

    *out = (unsigned char*)pkcs7Strip((char*)*out, inlen);
}

void AES128CTR(const unsigned char* in, size_t len,
               const unsigned char* key, uint64_t nonce, unsigned char** out) {
    unsigned char buf[AES_BLOCK_SIZE];
    unsigned char enc[AES_BLOCK_SIZE];
    uint64_t counter;
    AES_KEY aesKey;
    int inlen = len;

    *out = calloc(len + 1, sizeof(unsigned char));
    if (*out == NULL) {
        perror("Error: AES128EncryptCTR calloc error");
        exit(1);
    }

    *((uint64_t*)&buf[0]) = nonce;
    counter = 0;
    AES_set_encrypt_key(key, 128, &aesKey);
    while (inlen > 0) {
        size_t base = counter * AES_BLOCK_SIZE;
        *((uint64_t*)&buf[AES_BLOCK_SIZE/2]) = counter;
        AES_ecb_encrypt(buf, enc, &aesKey, AES_ENCRYPT);
        for (size_t i = 0; i < MIN(inlen, AES_BLOCK_SIZE); i++) {
            (*out)[base + i] = in[base + i] ^ enc[i];
        }
        counter++;
        inlen -= AES_BLOCK_SIZE;
    }
}

/* Returns TRUE if the ciphertext is encrypted with AES in ECB mode */
bool detectAES128ECB(const unsigned char* in, size_t inlen) {
    size_t numberOfAESBlocks, i, j;

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

size_t pkcs7Pad(const char* in, size_t inlen, size_t blklen, char** out) {
    size_t i;
    size_t padlen = blklen - (inlen % blklen);
    size_t newlen = inlen + padlen;

    *out = calloc(newlen + 1, sizeof(char));
    if (*out == NULL) {
        perror("Error: pkcs7Pad calloc error");
        exit(1);
    }
    memcpy(*out, in, inlen);

    for (i = inlen; i < newlen; i++) {
        (*out)[i] = padlen;
    }
    return newlen;
}

char* pkcs7Strip(char* in, size_t inlen) {
    size_t padlen = in[inlen - 1];
    size_t outlen = inlen - padlen;
    memset(&in[outlen], 0, padlen);
    return in;
}

bool pkcs7Validate(const char* in, size_t inlen) {
    size_t padlen = in[inlen - 1];
    if (inlen <= 1 || padlen >= inlen) return false;

    size_t i = inlen - 2;
    while (--padlen) {
        if (in[i--] != in[inlen - 1]) {
            return false;
        }
    }
    return true;
}

unsigned char* randomBytes(size_t len) {
    unsigned char* out = NULL;
    size_t i;

    out = calloc(len + 1, sizeof(unsigned char));
    if (out == NULL) {
        perror("Error: randomBytes calloc error");
        exit(1);
    }
    for (i = 0; i < len; i++) {
        out[i] = rand();
    }
    return out;
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
