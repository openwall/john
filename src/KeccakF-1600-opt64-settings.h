#include "arch.h"

#if defined(__AVX__)
#define UseXOP
#elif defined(__XOP__)
#define UseXOP
#elif defined(__SSE2__)
//#define UseSSE
#else
#define UseBebigokimisa
#endif

#define Unrolling 24
#define UseBebigokimisa
//#define UseSSE
//#define UseOnlySIMD64
//#define UseMMX
//#define UseSHLD
//#define UseXOP
