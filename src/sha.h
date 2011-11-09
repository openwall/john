#ifndef JOHN_SHA_H
#define JOHN_SHA_H

#include <openssl/sha.h>

#ifdef MMX_COEF
#ifdef _MSC_VER
// NOTE, in VC, void __fastcall f(unsigned char *out, unsigned char *in, int n)
//
// puts these registers:
//  n   -> pushed on stack
//  ECX -> out
//  EDX -> in
//  Thus to get into this code, we ECX -> EAX and get ECX from the stack (minusthe return push)
//  Also do a ret 4 after the emms in the mdfivemmx_noinit (to pop the push of eax)
int __fastcall shammx_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall shammx_nofinalbyteswap_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall shammx_nosizeupdate_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall shammx_nosizeupdate_nofinalbyteswap_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall shammx_noinit_uniformsizeupdate_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall shammx_reloadinit_nosizeupdate_nofinalbyteswap_VC(unsigned char *out, unsigned char *in, unsigned char *reload);
int __fastcall shammx_reloadinit_nosizeupdate_VC(unsigned char *out, unsigned char *in, unsigned char *reload);
#define shammx                              shammx_VC
#define shammx_nofinalbyteswap              shammx_nofinalbyteswap_VC
#define shammx_nosizeupdate                 shammx_nosizeupdate_VC
#define shammx_nosizeupdate_nofinalbyteswap shammx_nosizeupdate_nofinalbyteswap_VC
#define shammx_noinit_uniformsizeupdate     shammx_noinit_uniformsizeupdate_VC
#define shammx_reloadinit_nosizeupdate_nofinalbyteswap shammx_reloadinit_nosizeupdate_nofinalbyteswap_VC
#define shammx_reloadinit_nosizeupdate shammx_reloadinit_nosizeupdate_VC
#else
extern int shammx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int shammx_nofinalbyteswap(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int shammx_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int shammx_nosizeupdate_nofinalbyteswap(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int shammx_noinit_uniformsizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int shammx_reloadinit_nosizeupdate_nofinalbyteswap(unsigned char *out, unsigned char *in, unsigned char *reload) __attribute__((regparm(3)));
extern int shammx_reloadinit_nosizeupdate(unsigned char *out, unsigned char *in, unsigned char *reload) __attribute__((regparm(3)));
#endif
#endif

#endif
