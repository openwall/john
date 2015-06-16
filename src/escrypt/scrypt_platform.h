#ifndef _SCRYPT_PLATFORM_H_
#define _SCRYPT_PLATFORM_H_

#if AC_BUILT
#include "../autoconfig.h"
#else
#ifndef _MSC_VER
#ifndef __MINGW32__
#define HAVE_POSIX_MEMALIGN
#endif
#endif
#endif

#endif
