/*
 ---------------------------------------------------------------------------
 Copyright (c) 2002, Dr Brian Gladman <                 >, Worcester, UK.
 All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 24/01/2003

 This is an implementation of RFC2898, which specifies key derivation from
 a password and a salt value.
*/

#ifndef PWD2KEY_H
#define PWD2KEY_H

#if defined(__cplusplus)
extern "C"
{
#endif

void derive_key(
        const unsigned char pwd[],   /* the PASSWORD, and   */
        unsigned int pwd_len,        /*    its length       */
        const unsigned char salt[],  /* the SALT and its    */
        unsigned int salt_len,       /*    length           */
        unsigned int iter,      /* the number of iterations */
        unsigned char key[],    /* space for the output key */
        unsigned int key_len);  /* and its required length  */

#if defined(__cplusplus)
}
#endif

#endif
