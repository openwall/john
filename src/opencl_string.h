/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _OPENCL_STRING_H_
#define _OPENCL_STRING_H_

static void memset(void *dst, uchar what, uint size)
{
	uint i;
	uchar *ptr=(uchar*)dst;
	for(i=0; i<size; i++)
		ptr[i]=what;
}

static void memcpy(void *dst, const void *src, uint size)
{
	uint i;
	uchar *d=(uchar*)dst;
	uchar *s=(uchar*)src;
	for(i=0; i<size; i++)
		d[i]=s[i];
}

static void memcpy_g(__global void *dst, const void *src, uint size)
{
	uint i;
	__global uchar *d=(__global uchar*)dst;
	uchar *s=(uchar*)src;
	for(i=0; i<size; i++)
		d[i]=s[i];
}

#endif
