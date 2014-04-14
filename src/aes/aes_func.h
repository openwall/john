/*
 * (c) 2014 Harrison Neal. Licensed under GPLv2.
 * A set of convenience functions that return a function pointer to an
 * appropriate AES implementation depending on your platform.
 *
 * NOTE: These functions are intended to be used by algorithms that
 * continuously switch out AES keys - with each computation, state is
 * built, used and torn down.
 * Consider using straight OpenSSL EVP methods if your algorithm would
 * do a lot of work with any single key.
 */

// For the moment, only CBC stuff is implemented in both sources, so we won't expose more than that.

#define FUNC_BITS(n) \
	/*FUNC(vanilla,	AES_enc##n)*/ \
	FUNC(cbc,	AES_enc##n##_CBC) \
	/*FUNC(vanilla,	AES_dec##n)*/ \
	FUNC(cbc,	AES_dec##n##_CBC) \
	/*FUNC(ctr,	AES_encdec##n##_CTR)*/

FUNC_BITS(128)
FUNC_BITS(192)
FUNC_BITS(256)

#undef FUNC_BITS
