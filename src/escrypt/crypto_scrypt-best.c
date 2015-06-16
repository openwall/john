#if defined (__SSE2__) || defined (_MSC_VER)
#include "crypto_scrypt-sse.c"
#else
#include "crypto_scrypt-nosse.c"
#endif
