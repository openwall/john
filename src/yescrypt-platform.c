/*-
 * Copyright 2013-2015 Alexander Peslyak
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

#include "memory.h"

int
yescrypt_init_shared(yescrypt_shared_t * shared,
    const uint8_t * param, size_t paramlen,
    uint64_t N, uint32_t r, uint32_t p,
    yescrypt_init_shared_flags_t flags,
    uint8_t * buf, size_t buflen)
{
	yescrypt_shared_t half1, half2;
	uint8_t salt[32];
	if (flags & YESCRYPT_SHARED_PREALLOCATED) {
		if (!shared->aligned || !shared->aligned_size)
			return -1;
	} else {
		init_region(shared);
	}
	if (!param && !paramlen && !N && !r && !p && !buf && !buflen)
		return 0;

	if (yescrypt_kdf(NULL, shared,
	    param, paramlen, NULL, 0, N, r, p, 0, 0,
	    YESCRYPT_RW | __YESCRYPT_INIT_SHARED_1,
	    salt, sizeof(salt)))
		goto out;

	half1 = half2 = *shared;
	half1.aligned_size /= 2;
	half2.aligned += half1.aligned_size;
	half2.aligned_size = half1.aligned_size;
	N /= 2;

	if (p > 1 && yescrypt_kdf(&half1, &half2,
	    param, paramlen, salt, sizeof(salt), N, r, p, 0, 0,
	    YESCRYPT_RW | __YESCRYPT_INIT_SHARED_2,
	    salt, sizeof(salt)))
		goto out;

	if (yescrypt_kdf(&half2, &half1,
	    param, paramlen, salt, sizeof(salt), N, r, p, 0, 0,
	    YESCRYPT_RW | __YESCRYPT_INIT_SHARED_1,
	    salt, sizeof(salt)))
		goto out;

	if (yescrypt_kdf(&half1, &half2,
	    param, paramlen, salt, sizeof(salt), N, r, p, 0, 0,
	    YESCRYPT_RW | __YESCRYPT_INIT_SHARED_1,
	    buf, buflen))
		goto out;

	return 0;

out:
	if (!(flags & YESCRYPT_SHARED_PREALLOCATED))
		free_region(shared);
	return -1;
}

int
yescrypt_free_shared(yescrypt_shared_t * shared)
{
	return free_region(shared);
}

int
yescrypt_init_local(yescrypt_local_t * local)
{
	init_region(local);
	return 0;
}

int
yescrypt_free_local(yescrypt_local_t * local)
{
	return free_region(local);
}
