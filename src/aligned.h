/*
 * This software was written by JimF jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#ifndef _JTR_ALIGNED_H_
#define _JTR_ALIGNED_H_

#if defined(__GNUC__)
#define JTR_ALIGN(n) __attribute__ ((aligned(n)))
#elif defined(_MSC_VER)
#define JTR_ALIGN(n) __declspec(align(n))
#else
#define JTR_ALIGN(n)
#endif


#endif
