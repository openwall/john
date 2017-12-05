/* src/libsecp256k1-config.h.  Generated from libsecp256k1-config.h.in by configure.  */
/* src/libsecp256k1-config.h.in.  Generated from configure.ac by autoheader.  */

#ifndef LIBSECP256K1_CONFIG_H

#define LIBSECP256K1_CONFIG_H

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define this symbol to compile out all VERIFY code */
/* #undef COVERAGE */

/* Define this symbol to enable the ECDH module */
#define ENABLE_MODULE_ECDH 1

/* Define this symbol to enable the ECDSA pubkey recovery module */
/* #undef ENABLE_MODULE_RECOVERY */

/* Define this symbol if OpenSSL EC functions are available */
#define ENABLE_OPENSSL_TESTS 1

/* Define this symbol if __builtin_expect is available */
#define HAVE_BUILTIN_EXPECT 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define this symbol if libcrypto is installed */
#define HAVE_LIBCRYPTO 1

/* Define this symbol if libgmp is installed */
// #define HAVE_LIBGMP 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the system has the type `__int128'. */
// #define HAVE___INT128 1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define this symbol to enable x86_64 assembly optimizations */
// #define USE_ASM_X86_64 1

/* Define this symbol to use a statically generated ecmult table */
#define USE_ECMULT_STATIC_PRECOMPUTATION 1

/* Define this symbol to use endomorphism optimization */
/* #undef USE_ENDOMORPHISM */

/* Define this symbol if an external (non-inline) assembly implementation is
   used */
/* #undef USE_EXTERNAL_ASM */

/* Define this symbol to use the FIELD_10X26 implementation */
/* #undef USE_FIELD_10X26 */

/* Define this symbol to use the FIELD_5X52 implementation */
#define USE_FIELD_5X52 1

/* Define this symbol to use the native field inverse implementation */
/* #undef USE_FIELD_INV_BUILTIN */

/* Define this symbol to use the num-based field inverse implementation */
#define USE_FIELD_INV_NUM 1

/* Define this symbol to use the gmp implementation for num */
#define USE_NUM_GMP 1

/* Define this symbol to use no num implementation */
/* #undef USE_NUM_NONE */

/* Define this symbol to use the 4x64 scalar implementation */
#define USE_SCALAR_4X64 1

/* Define this symbol to use the 8x32 scalar implementation */
/* #undef USE_SCALAR_8X32 */

/* Define this symbol to use the native scalar inverse implementation */
/* #undef USE_SCALAR_INV_BUILTIN */

/* Define this symbol to use the num-based scalar inverse implementation */
#define USE_SCALAR_INV_NUM 1

/* Version number of package */
#define VERSION "0.1"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

// dirty hack
#undef USE_ASM_X86_64
#undef USE_ENDOMORPHISM
#undef USE_FIELD_10X26
#undef USE_FIELD_5X52
#undef USE_FIELD_INV_BUILTIN
#undef USE_FIELD_INV_NUM
#undef USE_NUM_GMP
#undef USE_NUM_NONE
#undef USE_SCALAR_4X64
#undef USE_SCALAR_8X32
#undef USE_SCALAR_INV_BUILTIN
#undef USE_SCALAR_INV_NUM

#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define USE_FIELD_10X26 1
#define USE_SCALAR_8X32 1

#endif /*LIBSECP256K1_CONFIG_H*/
