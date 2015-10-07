/*
   Unix SMB/CIFS implementation.
   Interface header: Scheduler service
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Andrew Tridgell 1992-1999

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _HMAC_MD5_H

#include "aligned.h"
#include "md5.h"

#if defined(__SUNPRO_C)
// In this case, align is for memcpy, not strictly needed
//#warning INFO: using Solaris CC align pragma for HMACMD5Context
#pragma align ARCH_SIZE (k_ipad, k_opad)
#endif
typedef struct {
	JTR_ALIGN(ARCH_SIZE) unsigned char k_ipad[64];
	JTR_ALIGN(ARCH_SIZE) unsigned char k_opad[64];
	MD5_CTX ctx;
} HMACMD5Context;

extern void hmac_md5_init_rfc2104(const unsigned char *key, int key_len, HMACMD5Context *ctx);
extern void hmac_md5_init_limK_to_64(const unsigned char*, int, HMACMD5Context*);
extern void hmac_md5_init_K16(const unsigned char*, HMACMD5Context*);
extern void hmac_md5_update(const unsigned char*, int, HMACMD5Context*);
extern void hmac_md5_final(unsigned char*, HMACMD5Context*);
extern void hmac_md5(const unsigned char *key, const unsigned char *data, int data_len, unsigned char *digest);

#endif /* _HMAC_MD5_H */
