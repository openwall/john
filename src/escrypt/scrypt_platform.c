/*-
 * Copyright 2013 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _MSC_VER
#ifndef __MINGW32__
#include <sys/mman.h>
#endif
#endif

#include "scrypt_platform.h"

#include "../memdbg.h"

static void *
alloc_region(escrypt_region_t * region, size_t size)
{
	uint8_t * base, * aligned;
#if defined(MAP_ANON) && !defined (MEMDBG_ON)
	if ((base = mmap(NULL, size, PROT_READ | PROT_WRITE,
#ifdef MAP_NOCORE
	    MAP_ANON | MAP_PRIVATE | MAP_NOCORE,
#else
	    MAP_ANON | MAP_PRIVATE,
#endif
	    -1, 0)) == MAP_FAILED)
		base = NULL;
	aligned = base;
#elif defined(HAVE_POSIX_MEMALIGN) && !defined (MEMDBG_ON)
	if ((errno = posix_memalign(&base, 64, size)) != 0)
		base = NULL;
	aligned = base;
#else
	base = aligned = NULL;
	if (size + 63 < size)
		errno = ENOMEM;
	else if ((base = malloc(size + 63)) != NULL) {
		aligned = base + 63;
		aligned -= (uintptr_t)aligned & 63;
	}
#endif
	region->base = base;
	region->aligned = aligned;
	region->size = base ? size : 0;
	return aligned;
}

static inline void
init_region(escrypt_region_t * region)
{
	region->base = region->aligned = NULL;
	region->size = 0;
}

static int
free_region(escrypt_region_t * region)
{
	if (region->base) {
#if defined(MAP_ANON) && !defined (MEMDBG_ON)
		if (munmap(region->base, region->size))
			return -1;
#elif defined(HAVE_POSIX_MEMALIGN) && !defined (MEMDBG_ON)
		libc_free(region->base);
#else
		free(region->base);
#endif
	}
	init_region(region);
	return 0;
}

int
escrypt_init_local(escrypt_local_t * local)
{
	init_region(local);
	return 0;
}

int
escrypt_free_local(escrypt_local_t * local)
{
	return free_region(local);
}
