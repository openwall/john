/*
 * This file is intended to be included into the uaf_encode.c source file
 * via a #include preprocessor directive and will not compile if compiled
 * directly.  Function must be thread safe.
 *
 * Revised: 22-JUL-2009			Re-factor exponent to improve speed.
 * Revised: 14-AUG-2009			Re-locate 'P' initialization.
 * Revised: 25-AUG-2011			Misc. code cleanup.
 *
 * Copyright (c) 2011 by David L. Jones <jonesd/at/columbus.rr.com>, and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 *
 * Original hash algorithm by Shawn Clifford in February 1993.
 */
#ifndef _uaf_hash_
#define _uaf_hash_
#include "uaf_encode.c"

#ifdef VMS
#include <ssdef.h>
#define SSs_ABORT SS$_ABORT
#define SSs_BADPARAM SS$_BADPARAM
#define SSs_NORMAL SS$_NORMAL
#else
/*
 * Emulate symbols defined for VMS services.
 */
#define SSs_ABORT        44
#define SSs_BADPARAM     20
#define SSs_NORMAL        1
#endif


/***************************************************************************/
/*

Title:		hash_password (originaly LGI$HPWD)
Author:		Shawn A. Clifford		(sysop@robot.nuceng.ufl.edu)
Date:		19-FEB-1993
Revised:	7-JUL-2009	Rework by David Jones for John the Ripper
Purpose:	Portable C version of the last 3 encryption methods for DEC's
		password hashing algorithms.

Usage:		status = lgi$hpwd(&out_buf, &uaf_buf, encrypt, salt, &unam_buf);

		int lgi$hpwd2(
		    unsigned long long *output_hash,
		    string *password,
		    unsigned char *encrypt,
		    unsigned short *salt,
		    string *username)

		Where:
			output_hash = 8 byte output buffer descriptor
			   password = n character password string descriptor
			    encrypt = 1 byte; value determines algorithm to use
				      0 -> CRC algorithm   (not supported)
				      1 -> Purdy algorithm
				      2 -> Purdy_V
				      3 -> Purdy_S (Hickory algorithm)
			       salt = 2 byte (word) random number
			   username = up to 31 character username descriptor

			status is either SS$_NORMAL (1) or SS$_ABORT (44)

Compilation:	VAXC compiler, or 'gcc -traditional -c' to get hpwd.o file
		on a Un*x machine.

Comments:	The overall speed of this routine is not great.  This is
		dictated by the performance of the EMULQ routine which emulates
		the VAX EMULQ instruction (see notes in the EMULQ routine).
		If anyone can improve performance, or finds bugs in this
		program, please send me e-mail at the above address.

*/

typedef struct dsc_descriptor_s string;


/*
 *	Create a quadword data type as successive longwords.
 */
#undef quad
#define quad john_quad
typedef union {
    uaf_lword ulw[2];
    uaf_qword uqw;
    char b[8];
} quad;
#define l_low ulw[0]	/* Low order longword in the quadword */
#define l_high ulw[1]	/* High order longword in the quadword */


/*
 *	The following table of coefficients is used by the Purdy polynmial
 *	algorithm.  They are prime, but the algorithm does not require this.
 */
static const struct {
	quad	C1,
		C2,
		C3,
		C4,
		C5;
	} C = { {{-83,  -1}}, {{-179, -1}}, {{-257, -1}}, {{-323, -1}},
		{{-363, -1}} };



/** Function prototypes **/

static void COLLAPSE_R2 (string *r3, quad *r4, char r7);
						/* r3 -> input descriptor
						   r4 -> output buffer
						   r7 : Method 3 flag */
static void Purdy (quad *U);			/* U -> output buffer */
static void PQEXP_pair (quad *U, int higbits, uaf_lword n0,
	uaf_lword n1, quad *result0, quad *result1 );
/* static void PQADD_R0 (quad *U,
		      quad *Y,
		      quad *result); */		/* U + Y MOD P   */
static void PQMUL_ADD (quad *U,
		      quad *Y, quad *X,
		      quad *result);		/* U * Y MOD P   */
static void EMULQ    (uaf_lword a,
		      uaf_lword b,
		      quad *result);		/*  (a * b)	 */
static void PQLSH_R0 (quad *U,
		      quad *result); 		/* 2^32*U MOD P  */


/** RELATIVELY GLOBAL variables **/

static uaf_lword	MAXINT = 4294967295U;	/* Largest 32 bit number */
static uaf_lword	a = 59;	/* 2^64 - 59 is the biggest quadword prime */
static quad	P;	/* P = 2^64 - 59 */

/*
 * Initialize P as 2^64 - a = MAXINT.MAXINT - 1 + 1  Assume called from
 * main thread.
 */
int uaf_init ( void )
{
    static int initialized = 0;
    if ( !enc_map_ready ) init_enc_map ( );
    if ( initialized ) return 0;
    /* since MAXINT.MAXINT = 2^64 - 1		*/
    P.l_high = MAXINT;
    P.l_low = MAXINT - a + 1;
    initialized = 1;
    return 1;
}

/** LGI$HPWD entry point **/

static int hash_password (
	uaf_qword *output_hash,
	string *password,
	unsigned char encrypt,
	unsigned short salt,
	string *username)
{
    string	    *r3;	/* Holds descriptors for COLLAPSE_R2 */
    quad	    *r4;	/* Address of the output buffer */
    uaf_lword   r5;		/* Length of username */
    char	r7 = 0,		/* Flag for encryption method # 3 */
		*bytptr;	/* Pointer for adding in random salt */
    quad	qword;		/* Quadword form of the output buffer */
    char	uname[13];	/* buffer for padded username (PURDY) */

    /* ------------------------------------------------------------------------ */


    /* Check for invalid parameters */
    if ((encrypt < 1) || (encrypt > 3)) {
	  puts("BAD BAD!");
	    return -1;
//         exit(SSs_BADPARAM);
    }
    if (username->dsc_w_length > 31) {
	    puts("2");
	printf("Internal coding error, username is more than 31 bytes long.\n");
	exit(SSs_ABORT);
    }


    /* Setup pointer references */
    r3 = password;			/* 1st COLLAPSE uses the password desc.   */
    r4 = &qword;			/* @r4..@r4+7 equals obuf */
    r5 = username->dsc_w_length;
    r7 = (encrypt == 3);

    /* Clear the output buffer (zero the quadword) */
    r4->ulw[0] = 0;
    r4->ulw[1] = 0;
    UAF_QW_SET(*output_hash,0);

    /* Check for the null password and return zero as the hash value if so */
    if (password->dsc_w_length == 0) {
	return SSs_NORMAL;
    }

    switch (encrypt) {
      int ulen;
      case UAIsC_AD_II:		/* CRC algorithm with Autodin II poly */
	/* As yet unsupported */
	return SSs_BADPARAM;

      case UAIsC_PURDY:		/* Purdy algorithm */

	/* Use a blank padded username */
	strncpy(uname,"            ",sizeof(uname));
	strncpy(uname, username->dsc_a_pointer, r5);
	username->dsc_a_pointer = (char *)&uname;
	username->dsc_w_length = 12;
	break;

      case UAIsC_PURDY_V:		/* Purdy with blanks stripped */
      case UAIsC_PURDY_S:		/* Hickory algorithm; Purdy_V with rotation */

	/* Check padding.  Don't count blanks in the string length.
	* Remember:  r6->username_descriptor   the first word is length, then
	* 2 bytes of class information (4 bytes total), then the address of the
	* buffer.  Usernames can not be longer than 31 characters.
	*/
	for ( ulen = username->dsc_w_length; ulen > 0; ulen-- ) {
	    if ( username->dsc_a_pointer[ulen-1] != ' ' ) break;
	    username->dsc_w_length--;
	}

	/* If Purdy_S:  Bytes 0-1 => plaintext length */
	if (r7) {
	   r4->ulw[0] = password->dsc_w_length;
	}

	break;
    }


    /* Collapse the password to a quadword U; buffer pointed to by r4 */
    COLLAPSE_R2 (r3, r4, r7);
				/* r3 already points to password descriptor */


    /* Add random salt into the middle of U */
    /* This has to be done byte-wise because the Sun will not allow you */
    /* to add unaligned words, or it will give you a bus error and core dump :) */
    bytptr = &r4->b[3+1];
    *bytptr += (char)(salt>>8);			/* Add the high byte */

    /* Check for carry out of the low byte */
    bytptr--;
    if ( (short)((unsigned char)*bytptr + (unsigned char)(salt & 0xff)) > 255) {
	*(bytptr + 1) += 1;			/* Account for the carry */
    }
    *bytptr += (char)(salt & 0xff);			/* Add the low byte */



    /* Collapse the username into the quadword */
    r3 = username;		/* Point r3 to the valid username descriptor */
    COLLAPSE_R2 (r3, r4, r7);

    /* U (qword) contains the 8 character output buffer in quadword format */

    /* Run U through the polynomial mod P */
    Purdy (r4);

    /* Write qword (*r4) back into the output buffer */
    *((quad *) output_hash) = qword;

    /* Normal exit */
    return SSs_NORMAL;

} /* LGI$HPWD */




/***************	Functions Section	*******************/


/***************
   COLLAPSE_R2
 ***************/

static void COLLAPSE_R2 (string *r3, quad *r4, char r7)
/*
 *    r3 :  input string descriptor
 *    r4 :  output buffer (quadword)
 *    r7 :  flag (1) if using Hickory method (encrypt = 3)
 *
 * This routine takes a string of bytes (the descriptor for which is pointed
 * to by r3) and collapses them into a quadword (pointed to by r4).  It does
 * this by cycling around the bytes of the output buffer adding in the bytes of
 * the input string.  Additionally, after every 8 characters, each longword in
 * the resultant hash is rotated by one bit (PURDY_S only).
 *
 */

{
    unsigned short r0, r1;
    uaf_lword rotate;
    char *r2, mask = -8;

    /* --------------------------------------------------------------------- */

    r0 = r3->dsc_w_length;		/* Obtain the number of input bytes */

    if (r0 == 0) return;		/* Do nothing with empty string */

    r2 = r3->dsc_a_pointer;		/* Obtain pointer to input string */

    for (; (r0 != 0); r0--) {		/* Loop until input string exhausted */

	r1 = (~mask & r0);		/* Obtain cyclic index into out buff */
	r4->b[r1] += *r2++;		/* Add in this character */

	if ((r7) && (r1 == 7))		/* If Purdy_S and last byte ... */
	{
	   /* Rotate first longword one bit */
	   rotate = r4->ulw[0] & 0x80000000;
	   r4->ulw[0] <<= 1;
	   rotate >>=31;
	   r4->ulw[0] |= rotate;

	   /* Rotate second longword one bit */
	   rotate = r4->ulw[1] & 0x80000000;
	   r4->ulw[1] <<= 1;
	   rotate >>=31;
	   r4->ulw[1] |= rotate;
	} /* if Purdy_S */

     } /* for loop */

    return;

} /* COLLAPSE_R2 */


/************
   PQADD_R0
 ************/

static void PQADD_R0 (quad *U, quad *Y, quad *result)

/*
 * U, Y : quadwords that we want to add
 *
 *
 * Computes the sum U + Y MOD P where P is of the form P = 2^64 - a.
 * U, Y are quadwords less than P.
 *
 * Fixed with the help of the code written by Terence Lee (DEC/HKO).
 */

{
    uaf_lword carry = 0;
#ifndef NOLONGLONG
    static const unsigned long long maxqw = 0xffffffffffffffffLL;
    static const unsigned long long modulus = (0xffffffffffffffffLL - 59 + 1);

    if ( (maxqw-U->uqw) < Y->uqw ) carry = 1;
    result->uqw = U->uqw + Y->uqw;
    if ( !carry ) {
	if ( result->uqw < modulus ) return;
	result->uqw -= (modulus);
    } else {
        UAF_QW_ADD(result->uqw,a);	/* missing case of uqw > max-a */
    }
#else /* Compiler doesn't support long long */


    /* Add the low longwords, checking for carry out */
    if ( (MAXINT - U->l_low) < Y->l_low ) carry = 1;
    result->l_low = U->l_low + Y->l_low;

    /* Add the high longwords */
    result->l_high = U->l_high + Y->l_high + carry;

    /* Test for carry out of high bit in the quadword */
    if ( (MAXINT - U->l_high) < (Y->l_high + carry) )
	carry = 1;
    else
	carry = 0;

    /* Check if we have to MOD P the result */
    if (!carry && Y->l_high != MAXINT) return;	/* Outta here? */
    if ( Y->l_low > (MAXINT - a) )
	carry = 1;
    else
	carry = 0;
    result->l_low += a;				/* U + Y MOD P */
    result->l_high += carry;
#endif

    return;					/* Outta here! */
} /* PQADD_R0 */


/*********
   EMULQ
 *********/

static void EMULQ (uaf_lword a, uaf_lword b, quad *result)

/*
 * a, b   : longwords that we want to multiply (quadword result)
 * result : the quadword result
 *
 * This routine knows how to multiply two unsigned longwords, returning the
 * unsigned quadword product.
 *
 * Originally I wrote this using a much faster routine based on a
 * divide-and-conquer strategy put forth in Knuth's "The Art of Computer
 * Programming, Vol. 2, Seminumerical Algorithms" but I could not make the routine
 * reliable.  There is some sort of fixup for sign compensation, much like for the
 * VAX EMULQ instruction (where for each signed argument you must add the other
 * argument to the high longword).
 *
 * If anyone can improve this routine, please send me source code.
 *
 * The original idea behind this algorithm was to build a 2n-by-n matrix for the
 * n-bit arguments to fill, shifting over each row like you would do by hand.  I
 * found a simple way to account for the carries and then get the final result,
 * but the routine was about 4 to 5 times slower than it is now.  Then I realized
 * that if I made the variables global, that would save a little time on
 * allocating space for the vectors and matrices.  Last, I removed the matrix, and
 * added all the values to the 'temp' vector on the fly.  This greatly increased
 * the speed, but still nowhere near Knuth or calling LIB$EMULQ.
 */

{
#ifndef NOLONGLONG
    uaf_qword qw_a, qw_b;

    qw_a = a;		/* promote to long long */
    qw_b = b;
    result->uqw = qw_a * qw_b;
#else
    char bin_a[32], bin_b[32];
    char temp[64], i, j;
    char retbuf[8];


    /* Initialize */
    for (i=0; i<=63; i++) temp[i] = 0;
    for (i=0; i<=31; i++) bin_a[i] = bin_b[i] = 0;
    for (i=0; i<=7; retbuf[i]=0, i++);


    /* Store the binary representation of a & b */
    for (i=0; i<=31; i++) {
	bin_a[i] = a & 1;
	bin_b[i] = b & 1;
	a >>= 1;
	b >>= 1;
    }


    /* Add in the shifted multiplicand */
    for (i=0; i<=31; i++) {

        /* For each 1 in bin_b, add in bin_a, starting in the ith position */
	if (bin_b[i] == 1) {
		for (j=i; j<=i+31; j++)
			temp[j] += bin_a[j-i];
	}
    }


    /* Carry into the next position and set the binary value */
    for (j=0; j<=62; j++) {
	temp[j+1] += temp[j] / 2;
	temp[j] = temp[j] % 2;
    }
    temp[63] = temp[63] % 2;


    /* Convert binary bytes back into 8 packed bytes. */
    /* LEAST SIGNIFICANT BYTE FIRST!!!  This is LITTLE ENDIAN format. */
    for (i=0; i<=7; i++) {
	for (j=0; j<=7; j++) retbuf[i] += temp[i*8 + j] * (1<<j);
    }


    /* Copy the 8 byte buffer into result */
    memcpy ((char *)result, retbuf, 8);
#endif

    return;

} /* EMULQ */



/************
   PQMOD_R0
 ************/
#ifdef NOLONGLONG
static void PQMOD_R0 (quad *U)
/*
 * U : output buffer (quadword)
 *
 * This routine replaces the quadword U with U MOD P, where P is of the form
 * P = 2^64 - a			(RELATIVELY GLOBAL a = 59)
 *   = FFFFFFFF.FFFFFFFF - 3B + 1	(MAXINT = FFFFFFFF = 4,294,967,295)
 *   = FFFFFFFF.FFFFFFC5
 *
 * Method:  Since P is very nearly the maximum integer you can specify in a
 * quadword (ie. P = FFFFFFFFFFFFFFC5, there will be only 58 choices for
 * U that are larger than P (ie. U MOD P > 0).  So we check the high longword in
 * the quadword and see if all its bits are set (-1).  If not, then U can not
 * possibly be larger than P, and U MOD P = U.  If U is larger than MAXINT - 59,
 * then U MOD P is the differential between (MAXINT - 59) and U, else
 * U MOD P = U.  If U equals P, then U MOD P = 0 = (P + 59).
 */

{

    /* Check if U is larger/equal to P.  If not, then leave U alone. */

    if (U->l_high == P.l_high && U->l_low >= P.l_low) {
	U->l_low += a;		/* This will have a carry out, and ...	*/
	U->l_high = 0;		/* the carry will make l_high go to 0   */
    }

    return;

} /* PQMOD_R0 */
#else			/* Replace function with macro */
#define PQMOD_R0(x) if ( (x)->uqw < P.uqw ); else (x)->uqw += a;
#endif


static void PQEXP_pair (quad *U, int highbit, uaf_lword n0,
	uaf_lword n1, quad *result0, quad *result1 )
/*
 * U        : pointer to output buffer (quadword)
 * highbit  : Highest bit set in n0/n1 +1
 * n0,n1    : unsigned longword (exponent for U)
 *
 * The routine returns U^n MOD P where P is of the form P = 2^64-a.
 * U is a quadword, n is an unsigned longword, P is a RELATIVELY GLOBAL quad.
 * We optimize operation by generating two results for a single U re-using
 * the powers of 2 vector.
 *
 * The method comes from Knuth, "The Art of Computer Programing, Vol. 2", section
 * 4.6.3, "Evaluation of Powers."  This algorithm is for calculating U^n with
 * fewer than (n-1) multiplies.  The result is U^n MOD P only because the
 * multiplication routine is MOD P.  Knuth's example is from Pingala's Hindu
 * algorithm in the Chandah-sutra.
 */

{
    quad b2[32], *b2ptr;		/* sucessive squaring of base.  */
    int is_one;				/* True if  intermediate value== 1 */
    /*
     * Build series where b2[i] = U^(2^i) through repeated squaring.
     */
    b2[0] = *U;
    for ( b2ptr = b2; highbit > 1; highbit-- ) {
	PQMUL_ADD (b2ptr, b2ptr, 0, b2ptr+1);	   /* b2[i] = U ^ (2^i) */
	b2ptr++;
    }
    /*
     * Compute U^n0 by multiply the factors corresponding to set bits in the
     * the exponent (U^(a+b) = U^a * U^b).  Assume exponent non-zero.
     */
    is_one = 1;			/* Skip initializing result, set flag instead.*/
    for ( b2ptr = b2; n0 != 0; b2ptr++ ) {
	if ( n0 % 2 ) {		/* Test low bit */
	    if ( is_one ) {	/* Use assign instead of multiply */
		is_one = 0;
		*result0 = *b2ptr;
	    } else PQMUL_ADD ( result0, b2ptr, 0, result0 );
	}
	n0 /= 2;		/* Shift right to test next bit next round */
    }
    /*
     * Compute U^n1, but only if supplied by caller.
     */
    if ( !result1 ) return;
    is_one = 1;
    for ( b2ptr = b2; n1 != 0; b2ptr++ ) {
	if ( n1 % 2 ) {
	    if ( is_one ) {
		is_one = 0;
		*result1 = *b2ptr;
	    } else PQMUL_ADD ( result1, b2ptr, 0, result1 );
	}
	n1 /= 2;
    }
    return;

} /* PQEXP_pair */



/************
   PQMUL_ADD
 ************/

static void PQMUL_ADD (quad *U, quad *Y, quad *X, quad *result)

/*
 * U, Y, A : Input values, A optional.
 * result  : Output, result = (U*Y)+A
 *
 * Computes the product U*Y+X MOD P where P is of the form P = 2^64 - a.
 * U, Y, X are quadwords less than P.  The result is returned in result.
 *
 * The product may be formed as the sum of four longword multiplications
 * which are scaled by powers of 2^32 by evaluating:
 *
 *	2^64*v*z + 2^32*(v*y + u*z) + u*y
 *      ^^^^^^^^   ^^^^^^^^^^^^^^^^   ^^^
 *      part1       part2 & part3     part4
 *
 * The result is computed such that division by the modulus P is avoided.
 *
 * u is the low longword of  U;	u = U.l_low
 * v is the high longword of U;	v = U.l_high
 * y is the low longword of  Y;	y = Y.l_low
 * z is the high longword of Y;	z = Y.l_high
 */

{
    quad stack, part1, part2, part3;

    EMULQ(U->l_high, Y->l_high, &stack);	/* Multiply   v*z      */

    PQMOD_R0(&stack);				/* Get   (v*z) MOD P   */


    /*** 1st term ***/
    PQLSH_R0(&stack, &part1);			/* Get   2^32*(v*z) MOD P  */


    EMULQ(U->l_high, Y->l_low, &stack);		/* Multiply   v*y      */

    PQMOD_R0(&stack);				/* Get   (v*y) MOD P   */

    EMULQ(U->l_low, Y->l_high, &part2);		/* Multiply   u*z      */

    PQMOD_R0(&part2);				/* Get   (u*z) MOD P   */

    PQADD_R0 (&stack, &part2, &part3);		/* Get   (v*y + u*z)   */

    PQADD_R0 (&part1, &part3, &stack);   /* Get   2^32*(v*z) + (v*y + u*z) */


    /*** 1st & 2nd terms ***/
    PQLSH_R0(&stack, &part1);	/* Get   2^64*(v*z) + 2^32*(v*y + u*z) */


    EMULQ(U->l_low, Y->l_low, &stack);		/* Multiply   u*y      */


    /*** Last term ***/
    PQMOD_R0(&stack);

    if ( X ) PQADD_R0 ( &stack, X, &stack );

    PQADD_R0(&part1, &stack, result);		/* Whole thing */


    return;

} /* PQMUL_R2 */



/************
   PQLSH_R0
 ************/

static void PQLSH_R0 (quad *U, quad *result)

/*
 * Computes the product 2^32*U MOD P where P is of the form P = 2^64 - a.
 * U is a quadword less than P.
 *
 * This routine is used by PQMUL in the formation of quadword products in
 * such a way as to avoid division by modulus the P.
 * The product 2^64*v + 2^32*u is congruent a*v + 2^32*U MOD P.
 *
 * u is the low longword in U
 * v is the high longword in U
 */

{
    quad stack;


    /* Get	a*v   */
    EMULQ(U->l_high, a, &stack);

    /* Form  Y = 2^32*u  */
    U->l_high = U->l_low;
    U->l_low = 0;

    /* Get	U + Y MOD P  */
    PQADD_R0 (U, &stack, result);

    return;

} /* PQLSH_R0 */


/*********
   Purdy
 *********/

static void Purdy (quad *U)

/*
 * U : input/output buffer (quadword)
 *
 * This routine computes  f(U) = p(U) MOD P.  Where P is a prime of the form
 * P = 2^64 - a.  The function p is the following polynomial:
 *
 * 		X^n0 + X^n1*C1 + X^3*C2 + X^2*C3 + X*C4 + C5
 *                ^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *		    part1		  part2
 *
 * Note:  Part1 is calculated by its congruence  (X^(n0-n1) + C1)*X^n1
 *        finding X^n1, X^(n0-n1), X^(n0-n1)+C1, then
 *        (X^(n0-n1) + C1)*X^n1  which equals  X^n0 + X^n1*C1
 *
 *  To minimize the number of multiplications, we evaluate
 *
 *  f(U) =  ((U^(n0-n1) + C1)*U^(n1-1)*U + (U*C2 + C3)*U + C4)*U + C5
 *          ^^^^^^^^^^^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^^^^^^^^
 *                    part1                         part2
 *
 * The number of multiplies needed for an exponentiation is equal to
 * the bit position of the most signficant bit + the number of other set
 * bits in the binary expansion of the exponent.  By treating U^n1 as
 * U*U^(n1-1), we can replace n1-1 with 448*37449 to compute the
 * value in (1+15+5+8+2)=31 multiplies rather than (23+18)=41 multiplies used
 * for a direct U^n1.  Note that because of the pqexp_pair optimization, the
 * U^(n0-n1) calculation is done with just 3 multiplies.
 *
 */

{
    quad     *Cptr = (quad *)&C;	/* Address of table (C) */
    static const uaf_lword n0 = 16777213,/* These exponents are prime, but this is  */
	      n1 = 16777153;	/* not required by the algorithm 	   */
    static const uaf_lword na = 37449,
	      nb = 448;		/* U^n1 = (U^na)^nb * U  */
				/* n0 = 2^24 - 3;  n1 = 2^24 - 63;  n0-n1 = 60*/
    quad      X,		/* The variable X in the polynomial */
	      X_n1, X_n0Mn1,
	      X_na, X_na_nb,	/* X raised to na, na*nb */
	      part1,		/* Collect the polynomial ... */
	      part2;		/* ... in two parts */


    /* --------------------------------------------------------------------- */


    /* Ensure U less than P by taking U MOD P  */
    /* Save copy of result:  X = U MOD P       */
    X.l_low = U->l_low;
    X.l_high = U->l_high;

    if ( UAF_QW_GEQ(X.uqw, P.uqw) ) UAF_QW_ADD(X.uqw,a); /* Take X mod P    */

    PQEXP_pair ( &X, 16, (n0-n1), na, &X_n0Mn1, &X_na );
    PQADD_R0 ( &X_n0Mn1, Cptr, &part1 );		/* X^(n1-n0) + C1   */

    PQEXP_pair ( &X_na, 9, nb, 0, &X_na_nb, 0 );	/* X^na^nb 	    */
    PQMUL_ADD ( &X_na_nb, &X, 0, &X_n1 );		/* X^na^nb*X = X^n1 */

    /* Part 1 complete except for multiply by X^n1 */

    Cptr++;					/* Point to C2		*/

    PQMUL_ADD (&X, Cptr, Cptr+1, &part2);	/* part2= X*C2 + C3	*/

    Cptr += 2;				/* C4				*/
    PQMUL_ADD (&X, &part2, Cptr, &part2);   	/* part2 = part2*X + C4 */
						/* (X^2*C2 + X*C3 + C4)	*/

    Cptr++;					/* C5			*/
    PQMUL_ADD (&X, &part2, Cptr, &part2);/* part2=part2*X + C5       	*/
					/* X^3*C2 + X^2*C3 + X*C4 + C5	*/
    /* Part 2 complete */


   /* Do final multiply for part1 and add in part2 to get final result.  */

   PQMUL_ADD ( &part1, &X_n1, &part2, (quad *) U );

    /* Outta here... */
    return;

} /* Purdy */
#endif
