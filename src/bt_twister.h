//
// mt_uint32 must be an unsigned integer type capable of holding at least 32
// bits; exactly 32 should be fastest, but 64 is better on an Alpha with
// GCC at -O3 optimization so try your options and see what's best for you
//

#ifdef HAVE_OPENCL

typedef unsigned long mt_uint32;

extern mt_uint32 randomMT(void);
extern void seedMT(mt_uint32 seed);

#endif
