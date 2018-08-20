/* MD4.H - header file for MD4C.C */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991.

All rights reserved.

License to copy and use this software is granted provided that it is identified as the "RSA Data Security, Inc. MD4 Message-Digest Algorithm" in all material mentioning or referencing this software or this function.
License is also granted to make and use derivative works provided that such works are identified as "derived from the RSA Data Security, Inc. MD4 Message-Digest Algorithm" in all material mentioning or referencing the derived work.
RSA Data Security, Inc. makes no representations concerning either the merchantability of this software or the suitability of this software for any particular purpose. It is provided ï¿½as isï¿½ without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this documentation and/or software. */

#ifndef MD4_H
#define MD4_H

#include <string.h>

#define MD4_HASH_SIZE	(128 / 8)
#define MD4_BLOCK_SIZE	(512 / 8)

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short UINT2;

/* UINT4 defines a four byte word */
typedef unsigned int UINT4;


/* MD4 context. */
typedef struct {
	UINT4 state[4];				/* state (ABCD) */
	UINT4 count[2];				/* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64]; 	/* input buffer */
} MD4_CTX;

void MD4Init (MD4_CTX *context);
void MD4Update (MD4_CTX *context, const unsigned char *input, unsigned int inputLen);
void MD4Final (MD4_CTX *context, unsigned char digest[16]);

#endif
