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

#include <stdio.h>
#include <string.h>

#include "../aes.h"

#if HAVE_AES_ENCRYPT || !defined(AC_BUILT)
#include "openssl/ossl_aes.h"
const char *get_AES_type_string() { if (using_aes_asm()) return "AES-NI"; return "AES-oSSL"; }
#else
const char *get_AES_type_string() { if (using_aes_asm()) return "AES-NI"; return "AES-JtR"; }
#endif


#ifdef AESNI_IN_USE
	#include "aesni/iaesni.h"
	#define FUNC(r,p) aes_fptr_##r get_##p() { return check_for_aes_instructions() ? intel_##p : openssl_##p; }
	int using_aes_asm() {
		if (check_for_aes_instructions())
			return 1;
		return 0;
	}
#else
	#define FUNC(r,p) aes_fptr_##r get_##p() { return openssl_##p; }
	int using_aes_asm() {
		return 0;
	}
#endif

#include "aes_func.h"

#undef FUNC
