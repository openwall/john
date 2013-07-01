#ifdef __SSE2__
#include "crypto_scrypt-sse.c"
#else
#include "crypto_scrypt-nosse.c"
#endif
