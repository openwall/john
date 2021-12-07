#include "../opencl_sha2_ctx.h"

typedef SHA512_CTX ed25519_hash_context;

static void
ed25519_hash_init(ed25519_hash_context *ctx) {
	SHA512_Init(ctx);
}

static void
ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
	SHA512_Update(ctx, in, inlen);
}

static void
ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
	SHA512_Final(hash, ctx);
}

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, in, inlen);
	SHA512_Final(hash, &ctx);
}
