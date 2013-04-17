#include "arch.h"

#if defined(__XOP__)
#define UseXOP
#elif defined(__AVX__)
#define UseSSE
#elif defined(__SSE2__)
#define UseBebigokimisa
#else
#define UseBebigokimisa
#endif

#define Unrolling 24
//#define UseBebigokimisa
//#define UseSSE
//#define UseOnlySIMD64
//#define UseMMX
//#define UseSHLD
//#define UseXOP
