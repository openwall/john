#if !defined __JOHN_SWAP_H__
#define __JOHN_SWAP_H__

/* reqired for the john_bswap_32 ARCH_WORD_32 declaration */
#include "common.h"

#if defined __GNUC__ && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 4))
#	define JOHNSWAP(x)	__builtin_bswap32((x))
#elif defined (__linux__)
#	include <byteswap.h>
#	define JOHNSWAP(x)	bswap_32((x))
#elif _MSC_VER
//#	if !defined (MD5_SSE_PARA)
//#		include <intrin.h>
//#	endif
#	define JOHNSWAP(x)	_byteswap_ulong((x))
#else
#	define JOHNSWAP(x)	john_bswap_32((x))
#	define ROTATE_LEFT(x, n) (x) = (((x)<<(n))|((ARCH_WORD_32)(x)>>(32-(n))))
	/* Note, the name bswap_32 clashed with a less efficient bswap_32 in gcc 3.4. */
	/* Thus, we now call it john_bswap_32 to take 'ownership' */
	static inline ARCH_WORD_32 john_bswap_32(ARCH_WORD_32 x)
	{
		/* Since this is an inline function, we do not have to worry about */
		/* multiple reference of x.  Even though we are called from a macro */
		/* this inline hides problems even with usage like  n=SWAP(*cp++); */
		ROTATE_LEFT(x, 16);
		return ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF);
	}
#endif

#endif // __JOHN_SWAP_H__
