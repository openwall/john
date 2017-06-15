/*
 * These defines work around some LOCAL builds of oSSL. For some systems, even though
 * oSSL version 'allows' certain ciphers, etc, the actual build for that archeture
 * was done using #define OPENSSL_NO_something and thus, that part of oSSL is NOT
 * installed. SO, checking by version only is NOT adequate.  This file here has
 * to be hand tuned BY the user, for his specific system.  The linker will tell
 * you which of these defines need uncommented.  If SHA384/SHA512 (or SHA224/SHA256)
 * are NOT defined, then uncomment FORCE_GENERIC_SHA2.  At current time, it is all
 * or nothing.  Some systems may have oSSL SHA224/256 defined, but not the other.
 * we may split this up in the end, but right now it is oSSL or generic for SHA2.
 */

/* #define HAVE_NO_SSL_WHIRLPOOL		1 */
/* #define FORCE_GENERIC_SHA2			1 */
