#if !defined __JOHN_SWAP_H__
#define __JOHN_SWAP_H__

#if defined __GNUC__ && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 4))
#	define JOHNSWAP(x)	__builtin_bswap32((x))
#elif defined (__linux__)
#	include <byteswap.h>
#	define JOHNSWAP(x)	bswap_32((x))
#elif _MSC_VER
#	if !defined (MD5_SSE_PARA)
#		include <intrin.h>
#	endif
#	define JOHNSWAP(x)	_byteswap_ulong((x))
#else
#	define JOHNSWAP(x)	bswap_32((x))
#	define ROTATE_LEFT(x, n) (x) = (((x)<<(n))|((ARCH_WORD_32)(x)>>(32-(n))))
	static inline ARCH_WORD_32 bswap_32(ARCH_WORD_32 x)
	{
		/* since called in a macro, we only want to reference x 1 time, 'for safety' */
		/* we could avoid this temp, if we KNEW that all callers gave us a proper */
		/* safe lparam, but we have no way of knowing if code will be written correctly */
		/* so the safe way is to use a temp in this inline function. Then things like: */
		/* *y++ = JOHNSWAP(*x++);   work as we think they 'should' work. */
		ARCH_WORD_32 tmp=x;
		ROTATE_LEFT(tmp, 16);
		return ((tmp & 0x00FF00FF) << 8) | ((tmp >> 8) & 0x00FF00FF);
	}
#endif

#endif // __JOHN_SWAP_H__
