#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "cryptopals.h"

void set1Problem1(void) {
    char* in = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    char* ans = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    unsigned char* inRaw;
    char* base64;
    int base64len;

    int inlen = hexDecode(in, &inRaw);
    base64len = base64Encode(inRaw, inlen, &base64);

    printf("Set 1 Problem 1: Convert hex to base64\n");
    printf("input: %s\n", in);
    printf("base64: ");
    printArray(base64, base64len);
    printf("\n");

    TEST_STRING_EQUAL(base64, ans);

    free(inRaw);
    free(base64);
}

void set1Problem2(void) {
    char* in  = "1c0111001f010100061a024b53535009181c";
    char* key = "686974207468652062756c6c277320657965";
    char* ans = "746865206b696420646f6e277420706c6179";
    unsigned char *inRaw = NULL, *keyHex = NULL, *outHex = NULL;
    int inRawLen, keyHexLen;
    char *out;

    inRawLen = hexDecode(in, &inRaw);
    keyHexLen = hexDecode(key, &keyHex);
    outHex = xor(inRaw, inRawLen, keyHex, keyHexLen);
    out = hexEncode(outHex, inRawLen);

    printf("Set 1 Problem 2: Fixed XOR\n");
    printf("input: %s\n", in);
    printf("key: %s\n", key);
    printf("cipher: %s\n\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(inRaw);
    free(keyHex);
    free(outHex);
    free(out);
}

void set1Problem3(void) {
    char* in = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    unsigned char *inRaw = NULL, *out = NULL;
    int inRawLen;
    unsigned char key;

    inRawLen = hexDecode(in, &inRaw);
    key = findXorKey(inRaw, inRawLen);
    out = xor(inRaw, inRawLen, (unsigned char*)&key, 1);

    printf("Set 1 Problem 3: Single-byte XOR cipher\n");
    printf("plaintext: %s\n\n", out);

    free(inRaw);
    free(out);
}

void set1Problem4(void) {
    FILE* fp;
    char line[60];
    unsigned char ans[60];
    unsigned char *inRaw = NULL, *xored = NULL;
    float score, maxScore = 0.f;
    int k, inRawLen;

    fp = fopen("data/4.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file 'data/4.txt'");
        exit(1);
    }

    while (fgets(line, sizeof(line), fp)) {
        inRawLen = hexDecode(line, &inRaw);
        for (k = 0; k < 256; k++) {
            xored = xor(inRaw, inRawLen, (unsigned char*)&k, 1);
            score = scoreEnglish(xored, strlen((char*)xored));
            if (score > maxScore) {
                maxScore = score;
                memcpy(ans, xored, sizeof(ans));
            }
            free(xored);
        }
    }
    fclose(fp);

    printf("Set 1 Problem 4: Detect single-character XOR\n");
    printf("plaintext: %s\n\n", ans);
}

void set1Problem5(void) {
    char* in = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    char* key = "ICE";
    char* ans = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    unsigned char* outHex = NULL;
    char* out = NULL;

    outHex = xor((const unsigned char*)in, strlen(in), (const unsigned char*)key, strlen(key));
    out = hexEncode(outHex, strlen(in));

    printf("Set 1 Problem 5: Repeating-key XOR\n");
    printf("input: %s\n", in);
    printf("key: %s\n", key);
    printf("cipher: %s\n\n", out);

    TEST_STRING_EQUAL(out, ans);

    free(outHex);
    free(out);
}

void set1Problem6(void) {
    FILE* fp;
    char* fpbuf = NULL;
    unsigned char* raw = NULL, *bestKey = NULL, *decoded = NULL;
    int fplen, fpbuflen, rawlen, bestKeySize;

    fp = fopen("data/6.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file 'data/6.txt'");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    fplen = ftell(fp);
    rewind(fp);

    fpbuf = malloc(fplen + 1);
    if (fpbuf == NULL) {
        perror("Error: set1Problem6 malloc error");
        goto err;
    }
    fpbuflen = fread(fpbuf, 1, fplen, fp);
    if (fpbuflen != fplen) {
        perror("Error: set1Problem6 fread error");
        goto err;
    }
    fpbuf[fpbuflen] = '\0';
    strip_newlines(fpbuf);
    fpbuflen = strlen(fpbuf);

    rawlen = base64Decode(fpbuf, fpbuflen, &raw);
    breakRepeatingKeyXor(raw, rawlen, &bestKey, &bestKeySize, 40, &decoded);

    printf("Set 1 Problem 6: Break repeating-key XOR\n");
    printf("key length: %d\n", bestKeySize);
    printf("key:\n");
    printArray((char*)bestKey, bestKeySize);
    printf("plaintext:\n");
    printArray((char*)decoded, rawlen);

    fclose(fp);

err:
    free(fpbuf);
    free(raw);
    free(bestKey);
    free(decoded);
}

void set1Problem7(void) {
    FILE* fp;
    char* fpbuf = NULL;
    unsigned char* raw = NULL, *decoded = NULL;
    int fplen, fpbuflen, rawlen;
    char* key = "YELLOW SUBMARINE";

    fp = fopen("data/7.txt", "r");
    if (fp == NULL) {
        perror("Error: Failed to open file 'data/6.txt'");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    fplen = ftell(fp);
    rewind(fp);

    fpbuf = malloc(fplen + 1);
    if (fpbuf == NULL) {
        perror("Error: set1Problem6 malloc error");
        goto err;
    }
    fpbuflen = fread(fpbuf, 1, fplen, fp);
    if (fpbuflen != fplen) {
        perror("Error: set1Problem6 fread error");
        goto err;
    }
    fpbuf[fpbuflen] = '\0';
    strip_newlines(fpbuf);
    fpbuflen = strlen(fpbuf);

    rawlen = base64Decode(fpbuf, fpbuflen, &raw);
    aes128DecryptECB(raw, rawlen, (const unsigned char*)key, &decoded);

    printf("Set 1 Problem 7: AES in ECB mode\n");
    printf("key: %s\n", key);
    printf("plaintext:\n");
    printArray((char*)decoded, rawlen);

    fclose(fp);

err:
    free(fpbuf);
    free(raw);
    free(decoded);
}
