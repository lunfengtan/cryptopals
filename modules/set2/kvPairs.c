#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kvPairs.h"

void addkvPair(profile_t* p, char* k, char* v) {
    kvPair_t* kv = NULL;

    if (p == NULL || k == NULL || v == NULL)
        return;

    kv = calloc(1, sizeof(kvPair_t));
    if (kv == NULL) {
        perror("Error: parseProfile calloc error");
        exit(1);
    }
    if (p->kvPairListHead == NULL) {
        p->kvPairListHead = kv;
        p->kvPairListTail = kv;
    } else {
        p->kvPairListTail->next = kv;
        p->kvPairListTail = kv;
    }

    if (strlen(k) >= MAX_KEY_LENGTH) {
        perror("Error: addkvPair key exceeds maximum length limit");
        exit(-1);
    }
    strcpy(kv->key, k);

    if (strlen(v) >= MAX_VALUE_LENGTH) {
        perror("Error: addkvPair value exceeds maximum length limit");
    }
    strcpy(kv->value, v);

    p->numberOfkvPairs++;
}

profile_t* parseProfileString(const char* s, size_t len) {
    profile_t* p;
    char buf[len + 1];
    char* k = NULL, *v = NULL;

    p = calloc(1, sizeof(profile_t));
    if (p == NULL) {
        perror("Error: parseProfile calloc error");
        goto exit;
    }

    memcpy(buf, s, len);
    buf[len] = '\0';
    k = strtok(buf, "=&");
    v = strtok(NULL, "=&");
    addkvPair(p, k, v);

    while ((k = strtok(NULL, "=&"))) {
        v = strtok(NULL, "=&");
        addkvPair(p, k, v);
    }

exit:
    return p;
}

size_t profileFor(const char* email, size_t len, char** out) {
    const char* prefix = "email=";
    const char* suffix = "&uid=10&role=user";

    *out = calloc(len + strlen(prefix) + strlen(suffix) + 1, sizeof(char));
    if (*out == NULL) {
        perror("Error: profileFor calloc error");
        exit(1);
    }

    strcpy(*out, prefix);
    while (email[0]) {
        char ch = email[0];
        if (ch != '=' && ch != '&') {
            strncat(*out, &ch, 1);
        }
        email++;
    }
    strcat(*out, suffix);

    return strlen(*out);
}

void freeProfile(profile_t** p) {
    profile_t* prof = *p;
    kvPair_t* curr = NULL, *next = NULL;

    if (prof == NULL)  return;

    curr = prof->kvPairListHead;
    while (curr) {
        next = curr->next;
        free(curr);
        curr = next;
    }
    free(*p);
    *p = NULL;
}
