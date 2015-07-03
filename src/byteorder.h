/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB Byte handling
   Copyright (C) Andrew Tridgell 1992-1998

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

#ifndef _BYTEORDER_H
#define _BYTEORDER_H

/*
   This file implements macros for machine independent short and
   int manipulation

Here is a description of this file that I emailed to the samba list once:

> I am confused about the way that byteorder.h works in Samba. I have
> looked at it, and I would have thought that you might make a distinction
> between LE and BE machines, but you only seem to distinguish between 386
> and all other architectures.
>
> Can you give me a clue?

sure.

The distinction between 386 and other architectures is only there as
an optimisation. You can take it out completely and it will make no
difference. The routines (macros) in byteorder.h are totally byteorder
independent. The 386 optimsation just takes advantage of the fact that
the x86 processors don't care about alignment, so we don't have to
align ints on int boundaries etc. If there are other processors out
there that aren't alignment sensitive then you could also define
CAREFUL_ALIGNMENT=0 on those processors as well.

Ok, now to the macros themselves. I'll take a simple example, say we
want to extract a 2 byte integer from a SMB packet and put it into a
type called uint16_t that is in the local machines byte order, and you
want to do it with only the assumption that uint16_t is _at_least_ 16
bits long (this last condition is very important for architectures
that don't have any int types that are 2 bytes long)

You do this:

#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)

then to extract a uint16_t value at offset 25 in a buffer you do this:

char *buffer = foo_bar();
uint16_t xx = SVAL(buffer,25);

We are using the byteoder independence of the ANSI C bitshifts to do
the work. A good optimising compiler should turn this into efficient
code, especially if it happens to have the right byteorder :-)

I know these macros can be made a bit tidier by removing some of the
casts, but you need to look at byteorder.h as a whole to see the
reasoning behind them. byteorder.h defines the following macros:

SVAL(buf,pos) - extract a 2 byte SMB value
IVAL(buf,pos) - extract a 4 byte SMB value
SVALS(buf,pos) signed version of SVAL()
IVALS(buf,pos) signed version of IVAL()

SSVAL(buf,pos,val) - put a 2 byte SMB value into a buffer
SIVAL(buf,pos,val) - put a 4 byte SMB value into a buffer
SSVALS(buf,pos,val) - signed version of SSVAL()
SIVALS(buf,pos,val) - signed version of SIVAL()

RSVAL(buf,pos) - like SVAL() but for NMB byte ordering
RSVALS(buf,pos) - like SVALS() but for NMB byte ordering
RIVAL(buf,pos) - like IVAL() but for NMB byte ordering
RIVALS(buf,pos) - like IVALS() but for NMB byte ordering
RSSVAL(buf,pos,val) - like SSVAL() but for NMB ordering
RSIVAL(buf,pos,val) - like SIVAL() but for NMB ordering
RSIVALS(buf,pos,val) - like SIVALS() but for NMB ordering

it also defines lots of intermediate macros, just ignore those :-)

*/

/* some switch macros that do both store and read to and from SMB buffers */

#define RW_PCVAL(read,inbuf,outbuf,len) \
	{ if (read) { PCVAL (inbuf,0,outbuf,len); } \
	else      { PSCVAL(inbuf,0,outbuf,len); } }

#define RW_PIVAL(read,big_endian,inbuf,outbuf,len) \
	{ if (read) { if (big_endian) { RPIVAL(inbuf,0,outbuf,len); } else { PIVAL(inbuf,0,outbuf,len); } } \
	else      { if (big_endian) { RPSIVAL(inbuf,0,outbuf,len); } else { PSIVAL(inbuf,0,outbuf,len); } } }

#define RW_PSVAL(read,big_endian,inbuf,outbuf,len) \
	{ if (read) { if (big_endian) { RPSVAL(inbuf,0,outbuf,len); } else { PSVAL(inbuf,0,outbuf,len); } } \
	else      { if (big_endian) { RPSSVAL(inbuf,0,outbuf,len); } else { PSSVAL(inbuf,0,outbuf,len); } } }

#define RW_CVAL(read, inbuf, outbuf, offset) \
	{ if (read) { (outbuf) = CVAL (inbuf,offset); } \
	else      { SCVAL(inbuf,offset,outbuf); } }

#define RW_IVAL(read, big_endian, inbuf, outbuf, offset) \
	{ if (read) { (outbuf) = ((big_endian) ? RIVAL(inbuf,offset) : IVAL (inbuf,offset)); } \
	else      { if (big_endian) { RSIVAL(inbuf,offset,outbuf); } else { SIVAL(inbuf,offset,outbuf); } } }

#define RW_SVAL(read, big_endian, inbuf, outbuf, offset) \
	{ if (read) { (outbuf) = ((big_endian) ? RSVAL(inbuf,offset) : SVAL (inbuf,offset)); } \
	else      { if (big_endian) { RSSVAL(inbuf,offset,outbuf); } else { SSVAL(inbuf,offset,outbuf); } } }

#undef CAREFUL_ALIGNMENT

/* we know that the 386 can handle misalignment and has the "right"
   byteorder */
#ifdef __i386__
#define CAREFUL_ALIGNMENT 0
#endif

#ifndef CAREFUL_ALIGNMENT
#define CAREFUL_ALIGNMENT 1
#endif

#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SCVAL(buf,pos,val) (CVAL(buf,pos) = (val))


#if CAREFUL_ALIGNMENT

#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define SSVALX(buf,pos,val) (CVAL(buf,pos)=(val)&0xFF,CVAL(buf,pos+1)=(val)>>8)
#define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SVALS(buf,pos) ((int16_t)SVAL(buf,pos))
#define IVALS(buf,pos) ((int32_t)IVAL(buf,pos))
#define SSVAL(buf,pos,val) SSVALX((buf),(pos),((uint16_t)(val)))
#define SIVAL(buf,pos,val) SIVALX((buf),(pos),((uint32_t)(val)))
#define SSVALS(buf,pos,val) SSVALX((buf),(pos),((int16_t)(val)))
#define SIVALS(buf,pos,val) SIVALX((buf),(pos),((int32_t)(val)))

#else /* CAREFUL_ALIGNMENT */

/* this handles things for architectures like the 386 that can handle
   alignment errors */
/*
   WARNING: This section is dependent on the length of int16_t and int32_t
   being correct
*/

/* get single value from an SMB buffer */
#define SVAL(buf,pos) (*(const uint16_t *)((const char *)(buf) + (pos)))
#define IVAL(buf,pos) (*(const uint32_t *)((const char *)(buf) + (pos)))
#define SVALS(buf,pos) (*(const int16_t *)((const char *)(buf) + (pos)))
#define IVALS(buf,pos) (*(const int32_t *)((const char *)(buf) + (pos)))

/* store single value in an SMB buffer */
#define SVALMOD(buf,pos) (*(uint16_t *)((char *)(buf) + (pos)))
#define IVALMOD(buf,pos) (*(uint32_t *)((char *)(buf) + (pos)))
#define SVALSMOD(buf,pos) (*(int16_t *)((char *)(buf) + (pos)))
#define IVALSMOD(buf,pos) (*(int32_t *)((char *)(buf) + (pos)))

#define SSVAL(buf,pos,val) SVALMOD(buf,pos)=((uint16_t)(val))
#define SIVAL(buf,pos,val) IVALMOD(buf,pos)=((uint32_t)(val))
#define SSVALS(buf,pos,val) SVALSMOD(buf,pos)=((int16_t)(val))
#define SIVALS(buf,pos,val) IVALSMOD(buf,pos)=((int32_t)(val))

#endif /* CAREFUL_ALIGNMENT */

/* macros for reading / writing arrays */

#define SMBMACRO(macro,buf,pos,val,len,size) \
{ uint32_t l; for (l = 0; l < (uint32_t)(len); l++) (val)[l] = macro((buf), (pos) + (size)*l); }

#define SSMBMACRO(macro,buf,pos,val,len,size) \
{ uint32_t l; for (l = 0; l < (uint32_t)(len); l++) macro((buf), (pos) + (size)*l, (val)[l]); }

/* reads multiple data from an SMB buffer */
#define PCVAL(buf,pos,val,len) SMBMACRO(CVAL,buf,pos,val,len,1)
#define PSVAL(buf,pos,val,len) SMBMACRO(SVAL,buf,pos,val,len,2)
#define PIVAL(buf,pos,val,len) SMBMACRO(IVAL,buf,pos,val,len,4)
#define PCVALS(buf,pos,val,len) SMBMACRO(CVALS,buf,pos,val,len,1)
#define PSVALS(buf,pos,val,len) SMBMACRO(SVALS,buf,pos,val,len,2)
#define PIVALS(buf,pos,val,len) SMBMACRO(IVALS,buf,pos,val,len,4)

/* stores multiple data in an SMB buffer */
#define PSCVAL(buf,pos,val,len) SSMBMACRO(SCVAL,buf,pos,val,len,1)
#define PSSVAL(buf,pos,val,len) SSMBMACRO(SSVAL,buf,pos,val,len,2)
#define PSIVAL(buf,pos,val,len) SSMBMACRO(SIVAL,buf,pos,val,len,4)
#define PSCVALS(buf,pos,val,len) SSMBMACRO(SCVALS,buf,pos,val,len,1)
#define PSSVALS(buf,pos,val,len) SSMBMACRO(SSVALS,buf,pos,val,len,2)
#define PSIVALS(buf,pos,val,len) SSMBMACRO(SIVALS,buf,pos,val,len,4)


/* now the reverse routines - these are used in nmb packets (mostly) */
#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
#define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))

#define RSVAL(buf,pos) SREV(SVAL(buf,pos))
#define RSVALS(buf,pos) SREV(SVALS(buf,pos))
#define RIVAL(buf,pos) IREV(IVAL(buf,pos))
#define RIVALS(buf,pos) IREV(IVALS(buf,pos))
#define RSSVAL(buf,pos,val) SSVAL(buf,pos,SREV(val))
#define RSSVALS(buf,pos,val) SSVALS(buf,pos,SREV(val))
#define RSIVAL(buf,pos,val) SIVAL(buf,pos,IREV(val))
#define RSIVALS(buf,pos,val) SIVALS(buf,pos,IREV(val))

/* reads multiple data from an SMB buffer (big-endian) */
#define RPSVAL(buf,pos,val,len) SMBMACRO(RSVAL,buf,pos,val,len,2)
#define RPIVAL(buf,pos,val,len) SMBMACRO(RIVAL,buf,pos,val,len,4)
#define RPSVALS(buf,pos,val,len) SMBMACRO(RSVALS,buf,pos,val,len,2)
#define RPIVALS(buf,pos,val,len) SMBMACRO(RIVALS,buf,pos,val,len,4)

/* stores multiple data in an SMB buffer (big-endian) */
#define RPSSVAL(buf,pos,val,len) SSMBMACRO(RSSVAL,buf,pos,val,len,2)
#define RPSIVAL(buf,pos,val,len) SSMBMACRO(RSIVAL,buf,pos,val,len,4)
#define RPSSVALS(buf,pos,val,len) SSMBMACRO(RSSVALS,buf,pos,val,len,2)
#define RPSIVALS(buf,pos,val,len) SSMBMACRO(RSIVALS,buf,pos,val,len,4)

#define DBG_RW_PCVAL(charmode,string,depth,base,read,inbuf,outbuf,len) \
	{ RW_PCVAL(read,inbuf,outbuf,len) \
	DEBUG(5,("%s%04x %s: ", \
             tab_depth(depth), base,string)); \
    if (charmode) print_asc(5, (unsigned char*)(outbuf), (len)); else \
	{ uint32_t idx; for (idx = 0; idx < len; idx++) { DEBUG(5,("%02x ", (outbuf)[idx])); } } \
	DEBUG(5,("\n")); }

#define DBG_RW_PSVAL(charmode,string,depth,base,read,big_endian,inbuf,outbuf,len) \
	{ RW_PSVAL(read,big_endian,inbuf,outbuf,len) \
	DEBUG(5,("%s%04x %s: ", \
             tab_depth(depth), base,string)); \
    if (charmode) print_asc(5, (unsigned char*)(outbuf), 2*(len)); else \
	{ uint32_t idx; for (idx = 0; idx < len; idx++) { DEBUG(5,("%04x ", (outbuf)[idx])); } } \
	DEBUG(5,("\n")); }

#define DBG_RW_PIVAL(charmode,string,depth,base,read,big_endian,inbuf,outbuf,len) \
	{ RW_PIVAL(read,big_endian,inbuf,outbuf,len) \
	DEBUG(5,("%s%04x %s: ", \
             tab_depth(depth), base,string)); \
    if (charmode) print_asc(5, (unsigned char*)(outbuf), 4*(len)); else \
	{ uint32_t idx; for (idx = 0; idx < len; idx++) { DEBUG(5,("%08x ", (outbuf)[idx])); } } \
	DEBUG(5,("\n")); }

#define DBG_RW_CVAL(string,depth,base,read,inbuf,outbuf) \
	{ RW_CVAL(read,inbuf,outbuf,0) \
	DEBUG(5,("%s%04x %s: %02x\n", \
             tab_depth(depth), base, string, outbuf)); }

#define DBG_RW_SVAL(string,depth,base,read,big_endian,inbuf,outbuf) \
	{ RW_SVAL(read,big_endian,inbuf,outbuf,0) \
	DEBUG(5,("%s%04x %s: %04x\n", \
             tab_depth(depth), base, string, outbuf)); }

#define DBG_RW_IVAL(string,depth,base,read,big_endian,inbuf,outbuf) \
	{ RW_IVAL(read,big_endian,inbuf,outbuf,0) \
	DEBUG(5,("%s%04x %s: %08x\n", \
             tab_depth(depth), base, string, outbuf)); }

/* Alignment macros. */
#define ALIGN4(p,base) ((p) + ((4 - (PTR_DIFF((p), (base)) & 3)) & 3))
#define ALIGN2(p,base) ((p) + ((2 - (PTR_DIFF((p), (base)) & 1)) & 1))

#endif /* _BYTEORDER_H */
