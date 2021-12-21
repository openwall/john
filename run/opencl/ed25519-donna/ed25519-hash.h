#if 0
#include "../opencl_sha2_ctx.h"

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, in, inlen);
	SHA512_Final(hash, &ctx);
}
#else
#include "../opencl_sha2.h"

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	ulong W[16];
	ulong A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	/* Assume inlen is 32 */
	GET_UINT64BE(W[0], in, 0);
	GET_UINT64BE(W[1], in, 8);
	GET_UINT64BE(W[2], in, 16);
	GET_UINT64BE(W[3], in, 24);
	W[4] = 0x8000000000000000UL;
	W[5] = 0;
	W[6] = 0;
	W[7] = 0;
	W[8] = 0;
	W[15] = 32 << 3;

	SHA512_ZEROS(A, B, C, D, E, F, G, H, W);

	PUT_UINT64BE(A + SHA2_INIT_A, hash, 0);
	PUT_UINT64BE(B + SHA2_INIT_B, hash, 8);
	PUT_UINT64BE(C + SHA2_INIT_C, hash, 16);
	PUT_UINT64BE(D + SHA2_INIT_D, hash, 24);
	PUT_UINT64BE(E + SHA2_INIT_E, hash, 32);
	PUT_UINT64BE(F + SHA2_INIT_F, hash, 40);
	PUT_UINT64BE(G + SHA2_INIT_G, hash, 48);
	PUT_UINT64BE(H + SHA2_INIT_H, hash, 56);
}
#endif
