#include "../opencl_sha2_ctx.h"

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, in, inlen);
	SHA512_Final(hash, &ctx);
}
