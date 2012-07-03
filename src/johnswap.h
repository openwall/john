#if !defined __JOHN_SWAP_H__
#define __JOHN_SWAP_H__

/* reqired for the john_bswap_32 ARCH_WORD_32 declaration */
#include "common.h"

#if defined __GNUC__ && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 4))
#	define JOHNSWAP(x)		__builtin_bswap32((x))
#	define JOHNSWAP64(x)	__builtin_bswap64((x))
#elif defined (__linux__)
#	include <byteswap.h>
#	define JOHNSWAP(x)		bswap_32((x))
#	define JOHNSWAP64(x)	bswap_64((x))
#elif (_MSC_VER > 1300) && (_M_IX86 >= 400 || defined(CPU_IA32) ||  defined(CPU_X64)) /* MS VC */
#	define JOHNSWAP(x)		_byteswap_ulong((x))
#	define JOHNSWAP64(x)	_byteswap_uint64 (((unsigned __int64)x))
#elif !defined(__STRICT_ANSI__)
#	define JOHNSWAP(x)	john_bswap_32((x))
#	define JOHNSWAP64(x)	john_bswap_64((x))
#	define ROTATE_LEFT(x, n) (x) = (((x)<<(n))|((ARCH_WORD_32)(x)>>(32-(n))))
#	define ROTATE_LEFT64(x, n) (x) = (((x)<<(n))|((unsigned long long)(x)>>(64-(n))))
#if defined(__GNUC__) && defined(CPU_IA32) && !defined(__i386__)
	/* for intel x86 CPU */
	static inline ARCH_WORD_32 __attribute__((const)) john_bswap_32(ARCH_WORD_32 val) {
		register ARCH_WORD_32 res;
		__asm("bswap\t%0" : "=r" (res) : "0" (val));
		return res;
	}
#else
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
	static inline unsigned long long john_bswap_64(unsigned long long x)
	{
#if ARCH_BITS == 32
		union {
			unsigned long long ll;
			ARCH_WORD_32 l[2];
			} w, r;
		w.ll = x;
		r.l[0] = john_bswap_32(w.l[1]);
		r.l[1] = john_bswap_32(w.l[0]);
		return r.ll;
#else
		// Someone should write a 'proper' 64 bit bswap, for 64 bit arch
		// for now, I am using the '32 bit' version I wrote above.
		union {
			unsigned long long ll;
			ARCH_WORD_32 l[2];
			} w, r;
		w.ll = x;
		r.l[0] = john_bswap_32(w.l[1]);
		r.l[1] = john_bswap_32(w.l[0]);
		return r.ll;
#endif
	}
#endif

#endif // __JOHN_SWAP_H__
