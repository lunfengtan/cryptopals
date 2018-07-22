#ifndef KVPAIRS_H
#define KVPAIRS_H

#define MAX_KEY_LENGTH      64
#define MAX_VALUE_LENGTH    64

typedef struct kvPair {
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];
    struct kvPair* next;
} kvPair_t;

typedef struct {
    kvPair_t* kvPairListHead;
    kvPair_t* kvPairListTail;
    int numberOfkvPairs;
} profile_t;

void addkvPair(profile_t* p, char* k, char* v);
profile_t* parseProfileString(const char* s, size_t len);
size_t profileFor(const char* email, size_t len, char** out);
void freeProfile(profile_t** p);

#endif
