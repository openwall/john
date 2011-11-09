#ifndef _G_SHA1_H
#define _G_SHA1_H

#include <openssl/sha.h>

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

typedef SHA_CTX sha1_ctx;

#define sha1_begin SHA1_Init

#define sha1_hash(data, len, ctx) \
	SHA1_Update(ctx, data, len)

#define sha1_end SHA1_Final

#endif
