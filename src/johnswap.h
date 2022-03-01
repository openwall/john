#if !defined __JOHN_SWAP_H__
#define __JOHN_SWAP_H__

#include "common.h"

/* if x86 compatible cpu */
#if defined(i386) || defined(__i386__) || defined(__i486__) || \
	defined(__i586__) || defined(__i686__) || defined(__pentium__) || \
	defined(__pentiumpro__) || defined(__pentium4__) || \
	defined(__nocona__) || defined(prescott) || defined(__core2__) || \
	defined(__k6__) || defined(__k8__) || defined(__athlon__) || \
	defined(__amd64) || defined(__amd64__) || \
	defined(__x86_64) || defined(__x86_64__) || defined(_M_IX86) || \
	defined(_M_AMD64) || defined(_M_IA64) || defined(_M_X64)
/* detect if x86-64 instruction set is supported */
 #if defined(_LP64) || defined(__LP64__) || defined(__x86_64) || \
	defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
  #undef CPU_X64
  #define CPU_X64 1
 #else
  #undef CPU_IA32
  #define CPU_IA32 1
 #endif
 #undef CPU_INTEL_LE
 #define CPU_INTEL_LE 1
#endif

#if defined __GNUC__ && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 4))
	#define JOHNSWAP(x)		__builtin_bswap32((x))
	#define JOHNSWAP64(x)	__builtin_bswap64((x))
/* UNSAFE for things like JOHNSWAP64(*x++)
   #elif defined (__linux__)
   #include <byteswap.h>
   #define JOHNSWAP(x)		bswap_32((x))
   #define JOHNSWAP64(x)	bswap_64((x))
*/
#elif (_MSC_VER > 1300) && (_M_IX86 >= 400 || defined(CPU_IA32) ||  defined(CPU_X64)) /* MS VC */
	#define JOHNSWAP(x)		_byteswap_ulong((x))
	#define JOHNSWAP64(x)	_byteswap_uint64 (((unsigned __int64)x))
#elif !defined(__STRICT_ANSI__)
	#define JOHNSWAP(x)	john_bswap_32((x))
	#define JOHNSWAP64(x)	john_bswap_64((x))
	#define ROTATE_LEFT(x, n) (x) = (((x)<<(n))|((uint32_t)(x)>>(32-(n))))
	#define ROTATE_LEFT64(x, n) (x) = (((x)<<(n))|((unsigned long long)(x)>>(64-(n))))
#if defined(__GNUC__) && defined(CPU_IA32) && !defined(__i386__)
	/* for intel x86 CPU */
	inline static uint32_t __attribute__((const)) john_bswap_32(uint32_t val) {
		register uint32_t res;
		__asm("bswap\t%0" : "=r" (res) : "0" (val));
		return res;
	}
#else
	/* Note, the name bswap_32 clashed with a less efficient bswap_32 in gcc 3.4. */
	/* Thus, we now call it john_bswap_32 to take 'ownership' */
	inline static uint32_t john_bswap_32(uint32_t x)
	{
		/* Since this is an inline function, we do not have to worry about */
		/* multiple reference of x.  Even though we are called from a macro */
		/* this inline hides problems even with usage like  n=SWAP(*cp++); */
		ROTATE_LEFT(x, 16);
		return ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF);
	}
#endif
	inline static uint64_t john_bswap_64(uint64_t x)
	{
#if ARCH_BITS == 32
		union {
			uint64_t ll;
			uint32_t l[2];
			} w, r;
		w.ll = x;
		r.l[0] = john_bswap_32(w.l[1]);
		r.l[1] = john_bswap_32(w.l[0]);
		return r.ll;
#else
		// Someone should write a 'proper' 64 bit bswap, for 64 bit arch
		// for now, I am using the '32 bit' version I wrote above.
		union {
			uint64_t ll;
			uint32_t l[2];
			} w, r;
		w.ll = x;
		r.l[0] = john_bswap_32(w.l[1]);
		r.l[1] = john_bswap_32(w.l[0]);
		return r.ll;
#endif
	}
#endif

#if ARCH_LITTLE_ENDIAN
#define john_htonl(x) JOHNSWAP((x))
#define john_ntohl(x) JOHNSWAP((x))
#define john_htonll(x) JOHNSWAP64((x))
#define john_ntohll(x) JOHNSWAP64((x))
#else
#define john_htonl(x) (x)
#define john_ntohl(x) (x)
#define john_htonll(x) (x)
#define john_ntohll(x) (x)
#endif

#endif // __JOHN_SWAP_H__
