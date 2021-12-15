/*
	Public domain by Andrew M. <liquidsun@gmail.com>

	Ed25519 reference implementation using Ed25519-donna
*/

#include "ed25519-donna.h"
#include "ed25519.h"
#include "ed25519-hash.h"

/*
	Generates a (extsk[0..31]) and aExt (extsk[32..63])
*/

static void
ed25519_extsk(hash_512bits_p extsk, const ed25519_secret_key sk) {
	ed25519_hash(extsk, sk, 32);
	extsk[0] &= 248;
	extsk[31] &= 127;
	extsk[31] |= 64;
}

void
ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk) {
	bignum256modm a;
	ge25519 ALIGN(16) A;
	hash_512bits extsk;

	/* A = aB */
	ed25519_extsk(extsk, sk);
	expand256_modm(a, extsk, 32);
	ge25519_scalarmult_base_niels(&A, a);
	ge25519_pack(pk, &A);
}
