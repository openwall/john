/* July, 2012, the oSSL PKCS5_PBKDF2_HMAC function was replaced with a much faster
 * function pbkdf2() designed by JimF.  Originally this function was designed for
 * the mscash2 (DCC2).  The same pbkdf2 function, is used, and simply required small
 * changes to use SHA256.
 *
 * This new code is 3x to 4x FASTER than the original oSSL code. Even though it is
 * only useing oSSL functions.  A lot of the high level stuff in oSSL sux for speed.
 */


#include <string.h>

#include "arch.h"
#include "sha2.h"

#ifndef SHA256_CBLOCK
#define SHA256_CBLOCK 64
#endif
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

static void pbkdf2_sha256(unsigned char *K, int KL, unsigned char *S, int SL, int R, ARCH_WORD_32 *dgst)
{
	SHA256_CTX ctx, tmp_ctx1, tmp_ctx2;
	unsigned char ipad[SHA256_CBLOCK], opad[SHA256_CBLOCK], tmp_hash[SHA256_DIGEST_LENGTH];
	unsigned i, j;

	memset(ipad, 0x36, SHA256_CBLOCK);
	memset(opad, 0x5C, SHA256_CBLOCK);

	for(i = 0; i < KL; i++) {
		ipad[i] ^= K[i];
		opad[i] ^= K[i];
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ipad, SHA256_CBLOCK);
	// save off the first 1/2 of the ipad hash.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/4 the SHA256's
	memcpy(&tmp_ctx1, &ctx, sizeof(SHA256_CTX));
	SHA256_Update(&ctx, S, SL);
	// this BE 1 appended to the salt, allows us to do passwords up
	// to and including 64 bytes long.  If we wanted longer passwords,
	// then we would have to call the HMAC multiple times (with the
	// rounds between, but each chunk of password we would use a larger
	// BE number appended to the salt. The first roung (64 byte pw), and
	// we simply append the first number (0001 in BE)
	SHA256_Update(&ctx, "\x0\x0\x0\x1", 4);
	SHA256_Final(tmp_hash, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, opad, SHA256_CBLOCK);
	// save off the first 1/2 of the opad hash.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/4 the SHA256's
	memcpy(&tmp_ctx2, &ctx, sizeof(SHA256_CTX));
	SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
	SHA256_Final(tmp_hash, &ctx);

	memcpy(dgst, tmp_hash, SHA256_DIGEST_LENGTH);

	for(i = 1; i < R; i++) {
		memcpy(&ctx, &tmp_ctx1, sizeof(SHA256_CTX));
		SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
		SHA256_Final(tmp_hash, &ctx);

		memcpy(&ctx, &tmp_ctx2, sizeof(SHA256_CTX));
		SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
		SHA256_Final(tmp_hash, &ctx);

		for(j = 0; j < SHA256_DIGEST_LENGTH/sizeof(ARCH_WORD_32); j++)
			dgst[j] ^= ((ARCH_WORD_32*)tmp_hash)[j];
	}
}
