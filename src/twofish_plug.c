/*
 * Fast, portable, and easy-to-use Twofish implementation,
 * Version 0.3.
 * Copyright (c) 2002 by Niels Ferguson.
 * (See further down for the almost-unrestricted licensing terms.)
 *
 * --------------------------------------------------------------------------
 * There are two files for this implementation:
 * - twofish.h, the header file.
 * - twofish.c, the code file.
 *
 * To incorporate this code into your program you should:
 * - Check the licensing terms further down in this comment.
 * - Fix the two type definitions in twofish.h to suit your platform.
 * - Fix a few definitions in twofish.c in the section marked
 *   PLATFORM FIXES. There is one important ones that affects
 *   functionality, and then a few definitions that you can optimise
 *   for efficiency but those have no effect on the functionality.
 *   Don't change anything else.
 * - Put the code in your project and compile it.
 *
 * To use this library you should:
 * - Call Twofish_initialise() in your program before any other function in
 *   this library.
 * - Use Twofish_prepare_key(...) to convert a key to internal form.
 * - Use Twofish_encrypt(...) and Twofish_decrypt(...) to encrypt and decrypt
 *   data.
 * See the comments in the header file for details on these functions.
 * --------------------------------------------------------------------------
 *
 * There are many Twofish implementation available for free on the web.
 * Most of them are hard to integrate into your own program.
 * As we like people to use our cipher, I thought I would make it easier.
 * Here is a free and easy-to-integrate Twofish implementation in C.
 * The latest version is always available from my personal home page at
 *    http://niels.ferguson.net/
 *
 * Integrating library code into a project is difficult because the library
 * header files interfere with the project's header files and code.
 * And of course the project's header files interfere with the library code.
 * I've tried to resolve these problems here.
 * The header file of this implementation is very light-weight.
 * It contains two typedefs, a structure, and a few function declarations.
 * All names it defines start with "Twofish_".
 * The header file is therefore unlikely to cause problems in your project.
 * The code file of this implementation doesn't need to include the header
 * files of the project. There is thus no danger of the project interfering
 * with all the definitions and macros of the Twofish code.
 * In most situations, all you need to do is fill in a few platform-specific
 * definitions in the header file and code file,
 * and you should be able to run the Twofish code in your project.
 * I estimate it should take you less than an hour to integrate this code
 * into your project, most of it spent reading the comments telling you what
 * to do.
 *
 * For people using C++: it is very easy to wrap this library into a
 * TwofishKey class. One of the big advantages is that you can automate the
 * wiping of the key material in the destructor. I have not provided a C++
 * class because the interface depends too much on the abstract base class
 * you use for block ciphers in your program, which I don't know about.
 *
 * This implementation is designed for use on PC-class machines. It uses the
 * Twofish 'full' keying option which uses large tables. Total table size is
 * around 5-6 kB for static tables plus 4.5 kB for each pre-processed key.
 * If you need an implementation that uses less memory,
 * take a look at Brian Gladman's code on his web site:
 *     http://fp.gladman.plus.com/cryptography_technology/aes/
 * He has code for all AES candidates.
 * His Twofish code has lots of options trading off table size vs. speed.
 * You can also take a look at the optimised code by Doug Whiting on the
 * Twofish web site
 *      http://www.counterpane.com/twofish.html
 * which has loads of options.
 * I believe these existing implementations are harder to re-use because they
 * are not clean libraries and they impose requirements on the environment.
 * This implementation is very careful to minimise those,
 * and should be easier to integrate into any larger program.
 *
 * The default mode of this implementation is fully portable as it uses no
 * behaviour not defined in the C standard. (This is harder than you think.)
 * If you have any problems porting the default mode, please let me know
 * so that I can fix the problem. (But only if this code is at fault, I
 * don't fix compilers.)
 * Most of the platform fixes are related to non-portable but faster ways
 * of implementing certain functions.
 *
 * In general I've tried to make the code as fast as possible, at the expense
 * of memory and code size. However, C does impose limits, and this
 * implementation will be slower than an optimised assembler implementation.
 * But beware of assembler implementations: a good Pentium implementation
 * uses completely different code than a good Pentium II implementation.
 * You basically have to re-write the assembly code for every generation of
 * processor. Unless you are severely pressed for speed, stick with C.
 *
 * The initialisation routine of this implementation contains a self-test.
 * If initialisation succeeds without calling the fatal routine, then
 * the implementation works. I don't think you can break the implementation
 * in such a way that it still passes the tests, unless you are malicious.
 * In other words: if the initialisation routine returns,
 * you have successfully ported the implementation.
 * (Or not implemented the fatal routine properly, but that is your problem.)
 *
 * I'm indebted to many people who helped me in one way or another to write
 * this code. During the design of Twofish and the AES process I had very
 * extensive discussions of all implementation issues with various people.
 * Doug Whiting in particular provided a wealth of information. The Twofish
 * team spent untold hours discussion various cipher features, and their
 * implementation. Brian Gladman implemented all AES candidates in C,
 * and we had some fruitful discussions on how to implement Twofish in C.
 * Jan Nieuwenhuizen tested this code on Linux using GCC.
 *
 * Now for the license:
 * The author hereby grants a perpetual license to everybody to
 * use this code for any purpose as long as the copyright message is included
 * in the source code of this or any derived work.
 *
 * Yes, this means that you, your company, your club, and anyone else
 * can use this code anywhere you want. You can change it and distribute it
 * under the GPL, include it in your commercial product without releasing
 * the source code, put it on the web, etc.
 * The only thing you cannot do is remove my copyright message,
 * or distribute any source code based on this implementation that does not
 * include my copyright message.
 *
 * I appreciate a mention in the documentation or credits,
 * but I understand if that is difficult to do.
 * I also appreciate it if you tell me where and why you used my code.
 *
 * Please send any questions or comments to niels@ferguson.net
 *
 * Have Fun!
 *
 * Niels
 */

/*
 * DISCLAIMER: As I'm giving away my work for free, I'm of course not going
 * to accept any liability of any form. This code, or the Twofish cipher,
 * might very well be flawed; you have been warned.
 * This software is provided as-is, without any kind of warrenty or
 * guarantee. And that is really all you can expect when you download
 * code for free from the Internet.
 *
 * I think it is really sad that disclaimers like this seem to be necessary.
 * If people only had a little bit more common sense, and didn't come
 * whining like little children every time something happens....
 */

/*
 * Version history:
 * Version 0.0, 2002-08-30
 *      First written.
 * Version 0.1, 2002-09-03
 *      Added disclaimer. Improved self-tests.
 * Version 0.2, 2002-09-09
 *      Removed last non-portabilities. Default now works completely within
 *      the C standard. UInt32 can be larger than 32 bits without problems.
 * Version 0.3, 2002-09-28
 *      Bugfix: use <string.h> instead of <memory.h> to adhere to ANSI/ISO.
 *      Rename BIG_ENDIAN macro to CPU_IS_BIG_ENDIAN. The gcc library
 *      header <string.h> already defines BIG_ENDIAN, even though it is not
 *      supposed to.
 */


/*
 * Minimum set of include files.
 * You should not need any application-specific include files for this code.
 * In fact, adding you own header files could break one of the many macros or
 * functions in this file. Be very careful.
 * Standard include files will probably be ok.
 */
#include <string.h>     /* for memset(), memcpy(), and memcmp() */
#include "twofish.h"


/*
 * PLATFORM FIXES
 * ==============
 *
 * Fix the type definitions in twofish.h first!
 *
 * The following definitions have to be fixed for each particular platform
 * you work on. If you have a multi-platform program, you no doubt have
 * portable definitions that you can substitute here without changing the
 * rest of the code.
 */

/*
 * Function called if something is fatally wrong with the implementation.
 * This fatal function is called when a coding error is detected in the
 * Twofish implementation, or when somebody passes an obviously erroneous
 * parameter to this implementation. There is not much you can do when
 * the code contains bugs, so we just stop.
 *
 * The argument is a string. Ideally the fatal function prints this string
 * as an error message. Whatever else this function does, it should never
 * return. A typical implementation would stop the program completely after
 * printing the error message.
 *
 * This default implementation is not very useful,
 * but does not assume anything about your environment.
 * It will at least let you know something is wrong....
 * I didn't want to include any libraries to print and error or so,
 * as this makes the code much harder to integrate in a project.
 *
 * Note that the Twofish_fatal function may not return to the caller.
 * Unfortunately this is not something the self-test can test for,
 * so you have to make sure of this yourself.
 *
 * If you want to call an external function, be careful about including
 * your own header files here. This code uses a lot of macros, and your
 * header file could easily break it. Maybe the best solution is to use
 * a separate extern statement for your fatal function.
 */

#include <stdio.h> // this sucks!
#define Twofish_fatal( msg )      {puts(msg);}


/*
 * The rest of the settings are not important for the functionality
 * of this Twofish implementation. That is, their default settings
 * work on all platforms. You can change them to improve the
 * speed of the implementation on your platform. Erroneous settings
 * will result in erroneous implementations, but the self-test should
 * catch those.
 */


/*
 * Macros to rotate a Twofish_UInt32 value left or right by the
 * specified number of bits. This should be a 32-bit rotation,
 * and not rotation of, say, 64-bit values.
 *
 * Every encryption or decryption operation uses 32 of these rotations,
 * so it is a good idea to make these macros efficient.
 *
 * This fully portable definition has one piece of tricky stuff.
 * The UInt32 might be larger than 32 bits, so we have to mask
 * any higher bits off. The simplest way to do this is to 'and' the
 * value first with 0xffffffff and then shift it right. An optimising
 * compiler that has a 32-bit type can optimise this 'and' away.
 *
 * Unfortunately there is no portable way of writing the constant
 * 0xffffffff. You don't know which suffix to use (U, or UL?)
 * The UINT32_MASK definition uses a bit of trickery. Shift-left
 * is only defined if the shift amount is strictly less than the size
 * of the UInt32, so we can't use (1<<32). The answer it to take the value
 * 2, cast it to a UInt32, shift it left 31 positions, and subtract one.
 * Another example of how to make something very simple extremely difficult.
 * I hate C.
 *
 * The rotation macros are straightforward.
 * They are only applied to UInt32 values, which are _unsigned_
 * so the >> operator must do a logical shift that brings in zeroes.
 * On most platforms you will only need to optimise the ROL32 macro; the
 * ROR32 macro is not inefficient on an optimising compiler as all rotation
 * amounts in this code are known at compile time.
 *
 * On many platforms there is a faster solution.
 * For example, MS compilers have the __rotl and __rotr functions
 * that generate x86 rotation instructions.
 */
#define UINT32_MASK    ( (((UInt32)2)<<31) - 1 )
#define ROL32( x, n )  ( (x)<<(n) | ((x) & UINT32_MASK) >> (32-(n)) )
#define ROR32( x, n )  ROL32( (x), 32-(n) )


/*
 * Select data type for q-table entries.
 *
 * Larger entry types cost more memory (1.5 kB), and might be faster
 * or slower depending on the CPU and compiler details.
 *
 * This choice only affects the static data size and the key setup speed.
 * Functionality, expanded key size, or encryption speed are not affected.
 * Define to 1 to get large q-table entries.
 */
#define LARGE_Q_TABLE   0    /* default = 0 */


/*
 * Method to select a single byte from a UInt32.
 * WARNING: non-portable code if set; might not work on all platforms.
 *
 * Inside the inner loop of Twofish it is necessary to access the 4
 * individual bytes of a UInt32. This can be done using either shifts
 * and masks, or memory accesses.
 *
 * Set to 0 to use shift and mask operations for the byte selection.
 * This is more ALU intensive. It is also fully portable.
 *
 * Set to 1 to use memory accesses. The UInt32 is stored in memory and
 * the individual bytes are read from memory one at a time.
 * This solution is more memory-intensive, and not fully portable.
 * It might be faster on your platform, or not. If you use this option,
 * make sure you set the CPU_IS_BIG_ENDIAN flag appropriately.
 *
 * This macro does not affect the conversion of the inputs and outputs
 * of the cipher. See the CONVERT_USING_CASTS macro for that.
 */
#define SELECT_BYTE_FROM_UINT32_IN_MEMORY    0    /* default = 0 */


/*
 * Method used to read the input and write the output.
 * WARNING: non-portable code if set; might not work on all platforms.
 *
 * Twofish operates on 32-bit words. The input to the cipher is
 * a byte array, as is the output. The portable method of doing the
 * conversion is a bunch of rotate and mask operations, but on many
 * platforms it can be done faster using a cast.
 * This only works if your CPU allows UInt32 accesses to arbitrary Byte
 * addresses.
 *
 * Set to 0 to use the shift and mask operations. This is fully
 * portable. .
 *
 * Set to 1 to use a cast. The Byte * is cast to a UInt32 *, and a
 * UInt32 is read. If necessary (as indicated by the CPU_IS_BIG_ENDIAN
 * macro) the byte order in the UInt32 is swapped. The reverse is done
 * to write the output of the encryption/decryption. Make sure you set
 * the CPU_IS_BIG_ENDIAN flag appropriately.
 * This option does not work unless a UInt32 is exactly 32 bits.
 *
 * This macro only changes the reading/writing of the plaintext/ciphertext.
 * See the SELECT_BYTE_FROM_UINT32_IN_MEMORY to affect the way in which
 * a UInt32 is split into 4 bytes for the S-box selection.
 */
#define CONVERT_USING_CASTS    0    /* default = 0 */


/*
 * Endianness switch.
 * Only relevant if SELECT_BYTE_FROM_UINT32_IN_MEMORY or
 * CONVERT_USING_CASTS is set.
 *
 * Set to 1 on a big-endian machine, and to 0 on a little-endian machine.
 * Twofish uses the little-endian convention (least significant byte first)
 * and big-endian machines (using most significant byte first)
 * have to do a few conversions.
 *
 * CAUTION: This code has never been tested on a big-endian machine,
 * because I don't have access to one. Feedback appreciated.
 */
#define CPU_IS_BIG_ENDIAN    0


/*
 * Macro to reverse the order of the bytes in a UInt32.
 * Used to convert to little-endian on big-endian machines.
 * This macro is always tested, but only used in the encryption and
 * decryption if CONVERT_USING_CASTS, and CPU_IS_BIG_ENDIAN
 * are both set. In other words: this macro is only speed-critical if
 * both these flags have been set.
 *
 * This default definition of SWAP works, but on many platforms there is a
 * more efficient implementation.
 */
#define BSWAP(x) ((ROL32((x),8) & 0x00ff00ff) | (ROR32((x),8) & 0xff00ff00))


/*
 * END OF PLATFORM FIXES
 * =====================
 *
 * You should not have to touch the rest of this file.
 */


/*
 * Convert the external type names to some that are easier to use inside
 * this file. I didn't want to use the names Byte and UInt32 in the
 * header file, because many programs already define them and using two
 * conventions at once can be very difficult.
 * Don't change these definitions! Change the originals
 * in twofish.h instead.
 */
/* A Byte must be an unsigned integer, 8 bits long. */
typedef Twofish_Byte    Byte;
/* A UInt32 must be an unsigned integer at least 32 bits long. */
typedef Twofish_UInt32  UInt32;


/*
 * Define a macro ENDIAN_CONVERT.
 *
 * We define a macro ENDIAN_CONVERT that performs a BSWAP on big-endian
 * machines, and is the identity function on little-endian machines.
 * The code then uses this macro without considering the endianness.
 */
#if CPU_IS_BIG_ENDIAN
#define ENDIAN_CONVERT(x)    BSWAP(x)
#else
#define ENDIAN_CONVERT(x)    (x)
#endif


/*
 * Compute byte offset within a UInt32 stored in memory.
 *
 * This is only used when SELECT_BYTE_FROM_UINT32_IN_MEMORY is set.
 *
 * The input is the byte number 0..3, 0 for least significant.
 * Note the use of sizeof() to support UInt32 types that are larger
 * than 4 bytes.
 */
#if CPU_IS_BIG_ENDIAN
#define BYTE_OFFSET( n )  (sizeof(UInt32) - 1 - (n) )
#else
#define BYTE_OFFSET( n )  (n)
#endif


/*
 * Macro to get Byte no. b from UInt32 value X.
 * We use two different definition, depending on the settings.
 */
#if SELECT_BYTE_FROM_UINT32_IN_MEMORY
    /* Pick the byte from the memory in which X is stored. */
#define SELECT_BYTE( X, b ) (((Byte *)(&(X)))[BYTE_OFFSET(b)])
#else
    /* Portable solution: Pick the byte directly from the X value. */
#define SELECT_BYTE( X, b ) (((X) >> 8*(b)) & 0xff)
#endif


/* Some shorthands because we use byte selection in large formulae. */
#define b0(X)   SELECT_BYTE((X),0)
#define b1(X)   SELECT_BYTE((X),1)
#define b2(X)   SELECT_BYTE((X),2)
#define b3(X)   SELECT_BYTE((X),3)


/*
 * We need macros to load and store UInt32 from/to byte arrays
 * using the least-significant-byte-first convention.
 *
 * GET32( p ) gets a UInt32 in lsb-first form from four bytes pointed to
 * by p.
 * PUT32( v, p ) writes the UInt32 value v at address p in lsb-first form.
 */
#if CONVERT_USING_CASTS

    /* Get UInt32 from four bytes pointed to by p. */
#define GET32( p )    ENDIAN_CONVERT( *((UInt32 *)(p)) )
    /* Put UInt32 into four bytes pointed to by p */
#define PUT32( v, p ) *((UInt32 *)(p)) = ENDIAN_CONVERT(v)

#else

    /* Get UInt32 from four bytes pointed to by p. */
#define GET32( p ) \
    ( \
      (UInt32)((p)[0])    \
    | (UInt32)((p)[1])<< 8\
    | (UInt32)((p)[2])<<16\
    | (UInt32)((p)[3])<<24\
    )
    /* Put UInt32 into four bytes pointed to by p */
#define PUT32( v, p ) \
    (p)[0] = (Byte)(((v)      ) & 0xff);\
    (p)[1] = (Byte)(((v) >>  8) & 0xff);\
    (p)[2] = (Byte)(((v) >> 16) & 0xff);\
    (p)[3] = (Byte)(((v) >> 24) & 0xff)

#endif

#if 0
/*
 * Test the platform-specific macros.
 * This function tests the macros defined so far to make sure the
 * definitions are appropriate for this platform.
 * If you make any mistake in the platform configuration, this should detect
 * that and inform you what went wrong.
 * Somewhere, someday, this is going to save somebody a lot of time,
 * because misbehaving macros are hard to debug.
 */
static void test_platform()
    {
    /* Buffer with test values. */
    Byte buf[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0};
    UInt32 C;
    UInt32 x,y;
    int i;

    /*
     * Some sanity checks on the types that can't be done in compile time.
     * A smart compiler will just optimise these tests away.
     * The pre-processor doesn't understand different types, so we cannot
     * do these checks in compile-time.
     *
     * I hate C.
     *
     * The first check in each case is to make sure the size is correct.
     * The second check is to ensure that it is an unsigned type.
     */
    if ( ((UInt32) ((UInt32)1 << 31) == 0) || ((UInt32)-1 < 0) )
        {
        Twofish_fatal( "Twofish code: Twofish_UInt32 type not suitable" );
        }
    if ( (sizeof( Byte ) != 1) || ((Byte)-1 < 0) )
        {
        Twofish_fatal( "Twofish code: Twofish_Byte type not suitable" );
        }

    /*
     * Sanity-check the endianness conversions.
     * This is just an aid to find problems. If you do the endianness
     * conversion macros wrong you will fail the full cipher test,
     * but that does not help you find the error.
     * Always make it easy to find the bugs!
     *
     * Detail: There is no fully portable way of writing UInt32 constants,
     * as you don't know whether to use the U or UL suffix. Using only U you
     * might only be allowed 16-bit constants. Using UL you might get 64-bit
     * constants which cannot be stored in a UInt32 without warnings, and
     * which generally behave subtly different from a true UInt32.
     * As long as we're just comparing with the constant,
     * we can always use the UL suffix and at worst lose some efficiency.
     * I use a separate '32-bit constant' macro in most of my other code.
     *
     * I hate C.
     *
     * Start with testing GET32. We test it on all positions modulo 4
     * to make sure we can handly any position of inputs. (Some CPUs
     * do not allow non-aligned accesses which we would do if you used
     * the CONVERT_USING_CASTS option.
     */
    if ( GET32( buf ) != 0x78563412UL || GET32(buf+1) != 0x9a785634UL
        || GET32( buf+2 ) != 0xbc9a7856UL || GET32(buf+3) != 0xdebc9a78UL )
        {
        Twofish_fatal( "Twofish code: GET32 not implemented properly" );
        }

    /*
     * We can now use GET32 to test PUT32.
     * We don't test the shifted versions. If GET32 can do that then
     * so should PUT32.
     */
    C = GET32( buf );
    PUT32( 3*C, buf );
    if ( GET32( buf ) != 0x69029c36UL )
        {
        Twofish_fatal( "Twofish code: PUT32 not implemented properly" );
        }


    /* Test ROL and ROR */
    for ( i=1; i<32; i++ )
        {
        /* Just a simple test. */
        x = ROR32( C, i );
        y = ROL32( C, i );
        x ^= (C>>i) ^ (C<<(32-i));
        y ^= (C<<i) ^ (C>>(32-i));
        x |= y;
        /*
         * Now all we check is that x is zero in the least significant
         * 32 bits. Using the UL suffix is safe here, as it doesn't matter
         * if we get a larger type.
         */
        if ( (x & 0xffffffffUL) != 0 )
            {
            Twofish_fatal( "Twofish ROL or ROR not properly defined." );
            }
        }

    /* Test the BSWAP macro */
    if ( (BSWAP(C)) != 0x12345678UL )
        {
        /*
         * The BSWAP macro should always work, even if you are not using it.
         * A smart optimising compiler will just remove this entire test.
         */
        Twofish_fatal( "BSWAP not properly defined." );
        }

    /* And we can test the b<i> macros which use SELECT_BYTE. */
    if ( (b0(C)!=0x12) || (b1(C) != 0x34) || (b2(C) != 0x56) || (b3(C) != 0x78) )
        {
        /*
         * There are many reasons why this could fail.
         * Most likely is that CPU_IS_BIG_ENDIAN has the wrong value.
         */
        Twofish_fatal( "Twofish code: SELECT_BYTE not implemented properly" );
        }
    }
#endif

/*
 * Finally, we can start on the Twofish-related code.
 * You really need the Twofish specifications to understand this code. The
 * best source is the Twofish book:
 *     "The Twofish Encryption Algorithm", by Bruce Schneier, John Kelsey,
 *     Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson.
 * you can also use the AES submission document of Twofish, which is
 * available from my list of publications on my personal web site at
 *    http://niels.ferguson.net/.
 *
 * The first thing we do is write the testing routines. This is what the
 * implementation has to satisfy in the end. We only test the external
 * behaviour of the implementation of course.
 */


/*
 * Perform a single self test on a (plaintext,ciphertext,key) triple.
 * Arguments:
 *  key     array of key bytes
 *  key_len length of key in bytes
 *  p       plaintext
 *  c       ciphertext
 */
static void test_vector( Byte key[], int key_len, Byte p[16], Byte c[16] )
    {
    Byte tmp[16];               /* scratch pad. */
    Twofish_key xkey;           /* The expanded key */
    int i;


    /* Prepare the key */
    Twofish_prepare_key( key, key_len, &xkey );

    /*
     * We run the test twice to ensure that the xkey structure
     * is not damaged by the first encryption.
     * Those are hideous bugs to find if you get them in an application.
     */
    for ( i=0; i<2; i++ )
        {
        /* Encrypt and test */
        Twofish_encrypt( &xkey, p, tmp );
        if ( memcmp( c, tmp, 16 ) != 0 )
            {
            Twofish_fatal( "Twofish encryption failure" );
            }

        /* Decrypt and test */
        Twofish_decrypt( &xkey, c, tmp );
        if ( memcmp( p, tmp, 16 ) != 0 )
            {
            Twofish_fatal( "Twofish decryption failure" );
            }
        }

    /* The test keys are not secret, so we don't need to wipe xkey. */
    }


/*
 * Check implementation using three (key,plaintext,ciphertext)
 * test vectors, one for each major key length.
 *
 * This is an absolutely minimal self-test.
 * This routine does not test odd-sized keys.
 */
static void test_vectors()
    {
    /*
     * We run three tests, one for each major key length.
     * These test vectors come from the Twofish specification.
     * One encryption and one decryption using randomish data and key
     * will detect almost any error, especially since we generate the
     * tables ourselves, so we don't have the problem of a single
     * damaged table entry in the source.
     */

    /* 128-bit test is the I=3 case of section B.2 of the Twofish book. */
    static Byte k128[] = {
        0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
        0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
        };
    static Byte p128[] = {
        0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
        0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
        };
    static Byte c128[] = {
        0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
        0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3
        };

    /* 192-bit test is the I=4 case of section B.2 of the Twofish book. */
    static Byte k192[] = {
        0x88, 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36,
        0xB4, 0x46, 0xBB, 0x6D, 0x73, 0x1A, 0x1E, 0x88,
        0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44
        };
    static Byte p192[] = {
        0x39, 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5,
        0x85, 0xB6, 0xDC, 0x07, 0x3C, 0xA3, 0x41, 0xB2
        };
    static Byte c192[] = {
        0x18, 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45,
        0xF9, 0xDA, 0xAC, 0xDC, 0x29, 0x19, 0x3A, 0x65
        };

    /* 256-bit test is the I=4 case of section B.2 of the Twofish book. */
    static Byte k256[] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
        };
    static Byte p256[] = {
        0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
        0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
        };
    static Byte c256[] = {
        0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
        0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA
        };

    /* Run the actual tests. */
    test_vector( k128, 16, p128, c128 );
    test_vector( k192, 24, p192, c192 );
    test_vector( k256, 32, p256, c256 );
    }


/*
 * Perform extensive test for a single key size.
 *
 * Test a single key size against the test vectors from section
 * B.2 in the Twofish book. This is a sequence of 49 encryptions
 * and decryptions. Each plaintext is equal to the ciphertext of
 * the previous encryption. The key is made up from the ciphertext
 * two and three encryptions ago. Both plaintext and key start
 * at the zero value.
 * We should have designed a cleaner recurrence relation for
 * these tests, but it is too late for that now. At least we learned
 * how to do it better next time.
 * For details see appendix B of the book.
 *
 * Arguments:
 * key_len      Number of bytes of key
 * final_value  Final plaintext value after 49 iterations
 */
static void test_sequence( int key_len, Byte final_value[] )
    {
    Byte buf[ (50+3)*16 ];      /* Buffer to hold our computation values. */
    Byte tmp[16];               /* Temp for testing the decryption. */
    Twofish_key xkey;           /* The expanded key */
    int i;
    Byte * p;

    /* Wipe the buffer */
    memset( buf, 0, sizeof( buf ) );

    /*
     * Because the recurrence relation is done in an inconvenient manner
     * we end up looping backwards over the buffer.
     */

    /* Pointer in buffer points to current plaintext. */
    p = &buf[50*16];
    for ( i=1; i<50; i++ )
        {
        /*
         * Prepare a key.
         * This automatically checks that key_len is valid.
         */
        Twofish_prepare_key( p+16, key_len, &xkey );

        /* Compute the next 16 bytes in the buffer */
        Twofish_encrypt( &xkey, p, p-16 );

        /* Check that the decryption is correct. */
        Twofish_decrypt( &xkey, p-16, tmp );
        if ( memcmp( tmp, p, 16 ) != 0 )
            {
            Twofish_fatal( "Twofish decryption failure in sequence" );
            }
        /* Move on to next 16 bytes in the buffer. */
        p -= 16;
        }

    /* And check the final value. */
    if ( memcmp( p, final_value, 16 ) != 0 )
        {
        Twofish_fatal( "Twofish encryption failure in sequence" );
        }

    /* None of the data was secret, so there is no need to wipe anything. */
    }


/*
 * Run all three sequence tests from the Twofish test vectors.
 *
 * This checks the most extensive test vectors currently available
 * for Twofish. The data is from the Twofish book, appendix B.2.
 */
static void test_sequences()
    {
    static Byte r128[] = {
        0x5D, 0x9D, 0x4E, 0xEF, 0xFA, 0x91, 0x51, 0x57,
        0x55, 0x24, 0xF1, 0x15, 0x81, 0x5A, 0x12, 0xE0
        };
    static Byte r192[] = {
        0xE7, 0x54, 0x49, 0x21, 0x2B, 0xEE, 0xF9, 0xF4,
        0xA3, 0x90, 0xBD, 0x86, 0x0A, 0x64, 0x09, 0x41
        };
    static Byte r256[] = {
        0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75,
        0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05
        };

    /* Run the three sequence test vectors */
    test_sequence( 16, r128 );
    test_sequence( 24, r192 );
    test_sequence( 32, r256 );
    }


/*
 * Test the odd-sized keys.
 *
 * Every odd-sized key is equivalent to a one of 128, 192, or 256 bits.
 * The equivalent key is found by padding at the end with zero bytes
 * until a regular key size is reached.
 *
 * We just test that the key expansion routine behaves properly.
 * If the expanded keys are identical, then the encryptions and decryptions
 * will behave the same.
 */
static void test_odd_sized_keys()
    {
    Byte buf[32];
    Twofish_key xkey;
    Twofish_key xkey_two;
    int i;

    /*
     * We first create an all-zero key to use as PRNG key.
     * Normally we would not have to fill the buffer with zeroes, as we could
     * just pass a zero key length to the Twofish_prepare_key function.
     * However, this relies on using odd-sized keys, and those are just the
     * ones we are testing here. We can't use an untested function to test
     * itself.
     */
    memset( buf, 0, sizeof( buf ) );
    Twofish_prepare_key( buf, 16, &xkey );

    /* Fill buffer with pseudo-random data derived from two encryptions */
    Twofish_encrypt( &xkey, buf, buf );
    Twofish_encrypt( &xkey, buf, buf+16 );

    /* Create all possible shorter keys that are prefixes of the buffer. */
    for ( i=31; i>=0; i-- )
        {
        /* Set a byte to zero. This is the new padding byte */
        buf[i] = 0;

        /* Expand the key with only i bytes of length */
        Twofish_prepare_key( buf, i, &xkey );

        /* Expand the corresponding padded key of regular length */
        Twofish_prepare_key( buf, i<=16 ? 16 : (i<= 24 ? 24 : 32), &xkey_two );

        /* Compare the two */
        if ( memcmp( &xkey, &xkey_two, sizeof( xkey ) ) != 0 )
            {
            Twofish_fatal( "Odd sized keys do not expand properly" );
            }
        }

    /* None of the key values are secret, so we don't need to wipe them. */
    }


/*
 * Test the Twofish implementation.
 *
 * This routine runs all the self tests, in order of importance.
 * It is called by the Twofish_initialise routine.
 *
 * In almost all applications the cost of running the self tests during
 * initialisation is insignificant, especially
 * compared to the time it takes to load the application from disk.
 * If you are very pressed for initialisation performance,
 * you could remove some of the tests. Make sure you did run them
 * once in the software and hardware configuration you are using.
 */
static void self_test()
    {
    /* The three test vectors form an absolute minimal test set. */
    test_vectors();

    /*
     * If at all possible you should run these tests too. They take
     * more time, but provide a more thorough coverage.
     */
    test_sequences();

    /* Test the odd-sized keys. */
    test_odd_sized_keys();
    }


/*
 * And now, the actual Twofish implementation.
 *
 * This implementation generates all the tables during initialisation.
 * I don't like large tables in the code, especially since they are easily
 * damaged in the source without anyone noticing it. You need code to
 * generate them anyway, and this way all the code is close together.
 * Generating them in the application leads to a smaller executable
 * (the code is smaller than the tables it generates) and a
 * larger static memory footprint.
 *
 * Twofish can be implemented in many ways. I have chosen to
 * use large tables with a relatively long key setup time.
 * If you encrypt more than a few blocks of data it pays to pre-compute
 * as much as possible. This implementation is relatively inefficient for
 * applications that need to re-key every block or so.
 */

/*
 * We start with the t-tables, directly from the Twofish definition.
 * These are nibble-tables, but merging them and putting them two nibbles
 * in one byte is more work than it is worth.
 */
static Byte t_table[2][4][16] = {
    {
        {0x8,0x1,0x7,0xD,0x6,0xF,0x3,0x2,0x0,0xB,0x5,0x9,0xE,0xC,0xA,0x4},
        {0xE,0xC,0xB,0x8,0x1,0x2,0x3,0x5,0xF,0x4,0xA,0x6,0x7,0x0,0x9,0xD},
        {0xB,0xA,0x5,0xE,0x6,0xD,0x9,0x0,0xC,0x8,0xF,0x3,0x2,0x4,0x7,0x1},
        {0xD,0x7,0xF,0x4,0x1,0x2,0x6,0xE,0x9,0xB,0x3,0x0,0x8,0x5,0xC,0xA}
    },
    {
        {0x2,0x8,0xB,0xD,0xF,0x7,0x6,0xE,0x3,0x1,0x9,0x4,0x0,0xA,0xC,0x5},
        {0x1,0xE,0x2,0xB,0x4,0xC,0x3,0x7,0x6,0xD,0xA,0x5,0xF,0x9,0x0,0x8},
        {0x4,0xC,0x7,0x5,0x1,0x6,0x9,0xA,0x0,0xE,0xD,0x8,0x2,0xB,0x3,0xF},
        {0xB,0x9,0x5,0x1,0xC,0x3,0xD,0xE,0x6,0x4,0x7,0xF,0x2,0x0,0x8,0xA}
    }
};


/* A 1-bit rotation of 4-bit values. Input must be in range 0..15 */
#define ROR4BY1( x ) (((x)>>1) | (((x)<<3) & 0x8) )

/*
 * The q-boxes are only used during the key schedule computations.
 * These are 8->8 bit lookup tables. Some CPUs prefer to have 8->32 bit
 * lookup tables as it is faster to load a 32-bit value than to load an
 * 8-bit value and zero the rest of the register.
 * The LARGE_Q_TABLE switch allows you to choose 32-bit entries in
 * the q-tables. Here we just define the Qtype which is used to store
 * the entries of the q-tables.
 */
#if LARGE_Q_TABLE
typedef UInt32      Qtype;
#else
typedef Byte        Qtype;
#endif

/*
 * The actual q-box tables.
 * There are two q-boxes, each having 256 entries.
 */
static Qtype q_table[2][256];


/*
 * Now the function that converts a single t-table into a q-table.
 *
 * Arguments:
 * t[4][16] : four 4->4bit lookup tables that define the q-box
 * q[256]   : output parameter: the resulting q-box as a lookup table.
 */
static void make_q_table( Byte t[4][16], Qtype q[256] )
    {
    int ae,be,ao,bo;        /* Some temporaries. */
    int i;
    /* Loop over all input values and compute the q-box result. */
    for ( i=0; i<256; i++ ) {
        /*
         * This is straight from the Twofish specifications.
         *
         * The ae variable is used for the a_i values from the specs
         * with even i, and ao for the odd i's. Similarly for the b's.
         */
        ae = i>>4; be = i&0xf;
        ao = ae ^ be; bo = ae ^ ROR4BY1(be) ^ ((ae<<3)&8);
        ae = t[0][ao]; be = t[1][bo];
        ao = ae ^ be; bo = ae ^ ROR4BY1(be) ^ ((ae<<3)&8);
        ae = t[2][ao]; be = t[3][bo];

        /* Store the result in the q-box table, the cast avoids a warning. */
        q[i] = (Qtype) ((be<<4) | ae);
        }
    }


/*
 * Initialise both q-box tables.
 */
static void initialise_q_boxes() {
    /* Initialise each of the q-boxes using the t-tables */
    make_q_table( t_table[0], q_table[0] );
    make_q_table( t_table[1], q_table[1] );
    }


/*
 * Next up is the MDS matrix multiplication.
 * The MDS matrix multiplication operates in the field
 * GF(2)[x]/p(x) with p(x)=x^8+x^6+x^5+x^3+1.
 * If you don't understand this, read a book on finite fields. You cannot
 * follow the finite-field computations without some background.
 *
 * In this field, multiplication by x is easy: shift left one bit
 * and if bit 8 is set then xor the result with 0x169.
 *
 * The MDS coefficients use a multiplication by 1/x,
 * or rather a division by x. This is easy too: first make the
 * value 'even' (i.e. bit 0 is zero) by xorring with 0x169 if necessary,
 * and then shift right one position.
 * Even easier: shift right and xor with 0xb4 if the lsbit was set.
 *
 * The MDS coefficients are 1, EF, and 5B, and we use the fact that
 *   EF = 1 + 1/x + 1/x^2
 *   5B = 1       + 1/x^2
 * in this field. This makes multiplication by EF and 5B relatively easy.
 *
 * This property is no accident, the MDS matrix was designed to allow
 * this implementation technique to be used.
 *
 * We have four MDS tables, each mapping 8 bits to 32 bits.
 * Each table performs one column of the matrix multiplication.
 * As the MDS is always preceded by q-boxes, each of these tables
 * also implements the q-box just previous to that column.
 */

/* The actual MDS tables. */
static UInt32 MDS_table[4][256];

/* A small table to get easy conditional access to the 0xb4 constant. */
static UInt32 mds_poly_divx_const[] = {0,0xb4};

/* Function to initialise the MDS tables. */
static void initialise_mds_tables()
    {
    int i;
    UInt32 q,qef,q5b;       /* Temporary variables. */

    /* Loop over all 8-bit input values */
    for ( i=0; i<256; i++ )
        {
        /*
         * To save some work during the key expansion we include the last
         * of the q-box layers from the h() function in these MDS tables.
         */

        /* We first do the inputs that are mapped through the q0 table. */
        q = q_table[0][i];
        /*
         * Here we divide by x, note the table to get 0xb4 only if the
         * lsbit is set.
         * This sets qef = (1/x)*q in the finite field
         */
        qef = (q >> 1) ^ mds_poly_divx_const[ q & 1 ];
        /*
         * Divide by x again, and add q to get (1+1/x^2)*q.
         * Note that (1+1/x^2) =  5B in the field, and addition in the field
         * is exclusive or on the bits.
         */
        q5b = (qef >> 1) ^ mds_poly_divx_const[ qef & 1 ] ^ q;
        /*
         * Add q5b to qef to set qef = (1+1/x+1/x^2)*q.
         * Again, (1+1/x+1/x^2) = EF in the field.
         */
        qef ^= q5b;

        /*
         * Now that we have q5b = 5B * q and qef = EF * q
         * we can fill two of the entries in the MDS matrix table.
         * See the Twofish specifications for the order of the constants.
         */
        MDS_table[1][i] = (q  <<24) | (q5b<<16) | (qef<<8) | qef;
        MDS_table[3][i] = (q5b<<24) | (qef<<16) | (q  <<8) | q5b;

        /* Now we do it all again for the two columns that have a q1 box. */
        q = q_table[1][i];
        qef = (q >> 1) ^ mds_poly_divx_const[ q & 1 ];
        q5b = (qef >> 1) ^ mds_poly_divx_const[ qef & 1 ] ^ q;
        qef ^= q5b;

        /* The other two columns use the coefficient in a different order. */
        MDS_table[0][i] = (qef<<24) | (qef<<16) | (q5b<<8) | q  ;
        MDS_table[2][i] = (qef<<24) | (q  <<16) | (qef<<8) | q5b;
        }
    }


/*
 * The h() function is the heart of the Twofish cipher.
 * It is a complicated sequence of q-box lookups, key material xors,
 * and finally the MDS matrix.
 * We use lots of macros to make this reasonably fast.
 */

/* First a shorthand for the two q-tables */
#define q0  q_table[0]
#define q1  q_table[1]

/*
 * Each macro computes one column of the h for either 2, 3, or 4 stages.
 * As there are 4 columns, we have 12 macros in all.
 *
 * The key bytes are stored in the Byte array L at offset
 * 0,1,2,3,  8,9,10,11,  [16,17,18,19,   [24,25,26,27]] as this is the
 * order we get the bytes from the user. If you look at the Twofish
 * specs, you'll see that h() is applied to the even key words or the
 * odd key words. The bytes of the even words appear in this spacing,
 * and those of the odd key words too.
 *
 * These macros are the only place where the q-boxes and the MDS table
 * are used.
 */
#define H02( y, L )  MDS_table[0][q0[q0[y]^L[ 8]]^L[0]]
#define H12( y, L )  MDS_table[1][q0[q1[y]^L[ 9]]^L[1]]
#define H22( y, L )  MDS_table[2][q1[q0[y]^L[10]]^L[2]]
#define H32( y, L )  MDS_table[3][q1[q1[y]^L[11]]^L[3]]
#define H03( y, L )  H02( q1[y]^L[16], L )
#define H13( y, L )  H12( q1[y]^L[17], L )
#define H23( y, L )  H22( q0[y]^L[18], L )
#define H33( y, L )  H32( q0[y]^L[19], L )
#define H04( y, L )  H03( q1[y]^L[24], L )
#define H14( y, L )  H13( q0[y]^L[25], L )
#define H24( y, L )  H23( q0[y]^L[26], L )
#define H34( y, L )  H33( q1[y]^L[27], L )

/*
 * Now we can define the h() function given an array of key bytes.
 * This function is only used in the key schedule, and not to pre-compute
 * the keyed S-boxes.
 *
 * In the key schedule, the input is always of the form k*(1+2^8+2^16+2^24)
 * so we only provide k as an argument.
 *
 * Arguments:
 * k        input to the h() function.
 * L        pointer to array of key bytes at
 *          offsets 0,1,2,3, ... 8,9,10,11, [16,17,18,19, [24,25,26,27]]
 * kCycles  # key cycles, 2, 3, or 4.
 */
static UInt32 h( int k, Byte L[], int kCycles )
    {
    switch( kCycles ) {
        /* We code all 3 cases separately for speed reasons. */
    case 2:
        return H02(k,L) ^ H12(k,L) ^ H22(k,L) ^ H32(k,L);
    case 3:
        return H03(k,L) ^ H13(k,L) ^ H23(k,L) ^ H33(k,L);
    case 4:
        return H04(k,L) ^ H14(k,L) ^ H24(k,L) ^ H34(k,L);
    default:
        /* This is always a coding error, which is fatal. */
        Twofish_fatal( "Twofish h(): Illegal argument" );
		return 0;
        }
    }


/*
 * Pre-compute the keyed S-boxes.
 * Fill the pre-computed S-box array in the expanded key structure.
 * Each pre-computed S-box maps 8 bits to 32 bits.
 *
 * The S argument contains half the number of bytes of the full key, but is
 * derived from the full key. (See Twofish specifications for details.)
 * S has the weird byte input order used by the Hxx macros.
 *
 * This function takes most of the time of a key expansion.
 *
 * Arguments:
 * S        pointer to array of 8*kCycles Bytes containing the S vector.
 * kCycles  number of key words, must be in the set {2,3,4}
 * xkey     pointer to Twofish_key structure that will contain the S-boxes.
 */
static void fill_keyed_sboxes( Byte S[], int kCycles, Twofish_key * xkey )
    {
    int i;
    switch( kCycles ) {
        /* We code all 3 cases separately for speed reasons. */
    case 2:
        for ( i=0; i<256; i++ )
            {
            xkey->s[0][i]= H02( i, S );
            xkey->s[1][i]= H12( i, S );
            xkey->s[2][i]= H22( i, S );
            xkey->s[3][i]= H32( i, S );
            }
        break;
    case 3:
        for ( i=0; i<256; i++ )
            {
            xkey->s[0][i]= H03( i, S );
            xkey->s[1][i]= H13( i, S );
            xkey->s[2][i]= H23( i, S );
            xkey->s[3][i]= H33( i, S );
            }
        break;
    case 4:
        for ( i=0; i<256; i++ )
            {
            xkey->s[0][i]= H04( i, S );
            xkey->s[1][i]= H14( i, S );
            xkey->s[2][i]= H24( i, S );
            xkey->s[3][i]= H34( i, S );
            }
        break;
    default:
        /* This is always a coding error, which is fatal. */
        Twofish_fatal( "Twofish fill_keyed_sboxes(): Illegal argument" );
        }
    }


/* A flag to keep track of whether we have been initialised or not. */
static int Twofish_initialised = 0;

/*
 * Initialise the Twofish implementation.
 * This function must be called before any other function in the
 * Twofish implementation is called.
 * This routine also does some sanity checks, to make sure that
 * all the macros behave, and it tests the whole cipher.
 */
void Twofish_initialise()
    {
    /* First test the various platform-specific definitions. */
    /* test_platform(); */

    /* We can now generate our tables, in the right order of course. */
    initialise_q_boxes();
    initialise_mds_tables();

    /* We're finished with the initialisation itself. */
    Twofish_initialised = 1;

    /*
     * And run some tests on the whole cipher.
     * Yes, you need to do this every time you start your program.
     * It is called assurance; you have to be certain that your program
     * still works properly.
     */
    self_test();
    }


/*
 * The Twofish key schedule uses an Reed-Solomon code matrix multiply.
 * Just like the MDS matrix, the RS-matrix is designed to be easy
 * to implement. Details are below in the code.
 *
 * These constants make it easy to compute in the finite field used
 * for the RS code.
 *
 * We use Bytes for the RS computation, but these are automatically
 * widened to unsigned integers in the expressions. Having unsigned
 * ints in these tables therefore provides the fastest access.
 */
static unsigned int rs_poly_const[] = {0, 0x14d};
static unsigned int rs_poly_div_const[] = {0, 0xa6 };


/*
 * Prepare a key for use in encryption and decryption.
 * Like most block ciphers, Twofish allows the key schedule
 * to be pre-computed given only the key.
 * Twofish has a fairly 'heavy' key schedule that takes a lot of time
 * to compute. The main work is pre-computing the S-boxes used in the
 * encryption and decryption. We feel that this makes the cipher much
 * harder to attack. The attacker doesn't even know what the S-boxes
 * contain without including the entire key schedule in the analysis.
 *
 * Unlike most Twofish implementations, this one allows any key size from
 * 0 to 32 bytes. Odd key sizes are defined for Twofish (see the
 * specifications); the key is simply padded with zeroes to the next real
 * key size of 16, 24, or 32 bytes.
 * Each odd-sized key is thus equivalent to a single normal-sized key.
 *
 * Arguments:
 * key      array of key bytes
 * key_len  number of bytes in the key, must be in the range 0,...,32.
 * xkey     Pointer to an Twofish_key structure that will be filled
 *             with the internal form of the cipher key.
 */
void Twofish_prepare_key( Byte key[], int key_len, Twofish_key * xkey )
    {
    /* We use a single array to store all key material in,
     * to simplify the wiping of the key material at the end.
     * The first 32 bytes contain the actual (padded) cipher key.
     * The next 32 bytes contain the S-vector in its weird format,
     * and we have 4 bytes of overrun necessary for the RS-reduction.
     */
    Byte K[32+32+4];

    int kCycles;        /* # key cycles, 2,3, or 4. */

    int i;
    UInt32 A, B;        /* Used to compute the round keys. */

    Byte * kptr;        /* Three pointers for the RS computation. */
    Byte * sptr;
    Byte * t;

    Byte b,bx,bxx;      /* Some more temporaries for the RS computation. */

    /* Check that the Twofish implementation was initialised. */
    if ( Twofish_initialised == 0 )
        {
        /*
         * You didn't call Twofish_initialise before calling this routine.
         * This is a programming error, and therefore we call the fatal
         * routine.
         *
         * I could of course call the initialisation routine here,
         * but there are a few reasons why I don't. First of all, the
         * self-tests have to be done at startup. It is no good to inform
         * the user that the cipher implementation fails when he wants to
         * write his data to disk in encrypted form. You have to warn him
         * before he spends time typing his data. Second, the initialisation
         * and self test are much slower than a single key expansion.
         * Calling the initialisation here makes the performance of the
         * cipher unpredictable. This can lead to really weird problems
         * if you use the cipher for a real-time task. Suddenly it fails
         * once in a while the first time you try to use it. Things like
         * that are almost impossible to debug.
         */
        Twofish_fatal( "Twofish implementation was not initialised." );

        /*
         * There is always a danger that the Twofish_fatal routine returns,
         * in spite of the specifications that it should not.
         * (A good programming rule: don't trust the rest of the code.)
         * This would be disasterous. If the q-tables and MDS-tables have
         * not been initialised, they are probably still filled with zeroes.
         * Suppose the MDS-tables are all zero. The key expansion would then
         * generate all-zero round keys, and all-zero s-boxes. The danger
         * is that nobody would notice as the encryption function still
         * mangles the input, and the decryption still 'decrypts' it,
         * but now in a completely key-independent manner.
         * To stop such security disasters, we use blunt force.
         * If your program hangs here: fix the fatal routine!
         */
        for (;;);        /* Infinite loop, which beats being insecure. */
        }

    /* Check for valid key length. */
    if ( key_len < 0 || key_len > 32 )
        {
        /*
         * This can only happen if a programmer didn't read the limitations
         * on the key size.
         */
        Twofish_fatal( "Twofish_prepare_key: illegal key length" );
        /*
         * A return statement just in case the fatal macro returns.
         * The rest of the code assumes that key_len is in range, and would
         * buffer-overflow if it wasn't.
         *
         * Why do we still use a programming language that has problems like
         * buffer overflows, when these problems were solved in 1960 with
         * the development of Algol? Have we not leared anything?
         */
        return;
        }

    /* Pad the key with zeroes to the next suitable key length. */
    memcpy( K, key, key_len );
    memset( K+key_len, 0, sizeof(K)-key_len );

    /*
     * Compute kCycles: the number of key cycles used in the cipher.
     * 2 for 128-bit keys, 3 for 192-bit keys, and 4 for 256-bit keys.
     */
    kCycles = (key_len + 7) >> 3;
    /* Handle the special case of very short keys: minimum 2 cycles. */
    if ( kCycles < 2 )
        {
        kCycles = 2;
        }

    /*
     * From now on we just pretend to have 8*kCycles bytes of
     * key material in K. This handles all the key size cases.
     */

    /*
     * We first compute the 40 expanded key words,
     * formulas straight from the Twofish specifications.
     */
    for ( i=0; i<40; i+=2 )
        {
        /*
         * Due to the byte spacing expected by the h() function
         * we can pick the bytes directly from the key K.
         * As we use bytes, we never have the little/big endian
         * problem.
         *
         * Note that we apply the rotation function only to simple
         * variables, as the rotation macro might evaluate its argument
         * more than once.
         */
        A = h( i  , K  , kCycles );
        B = h( i+1, K+4, kCycles );
        B = ROL32( B, 8 );

        /* Compute and store the round keys. */
        A += B;
        B += A;
        xkey->K[i]   = A;
        xkey->K[i+1] = ROL32( B, 9 );
        }

    /* Wipe variables that contained key material. */
#if 0
    A=B=0;
#endif

    /*
     * And now the dreaded RS multiplication that few seem to understand.
     * The RS matrix is not random, and is specially designed to compute the
     * RS matrix multiplication in a simple way.
     *
     * We work in the field GF(2)[x]/x^8+x^6+x^3+x^2+1. Note that this is a
     * different field than used for the MDS matrix.
     * (At least, it is a different representation because all GF(2^8)
     * representations are equivalent in some form.)
     *
     * We take 8 consecutive bytes of the key and interpret them as
     * a polynomial k_0 + k_1 y + k_2 y^2 + ... + k_7 y^7 where
     * the k_i bytes are the key bytes and are elements of the finite field.
     * We multiply this polynomial by y^4 and reduce it modulo
     *     y^4 + (x + 1/x)y^3 + (x)y^2 + (x + 1/x)y + 1.
     * using straightforward polynomial modulo reduction.
     * The coefficients of the result are the result of the RS
     * matrix multiplication. When we wrote the Twofish specification,
     * the original RS definition used the polynomials,
     * but that requires much more mathematical knowledge.
     * We were already using matrix multiplication in a finite field for
     * the MDS matrix, so I re-wrote the RS operation as a matrix
     * multiplication to reduce the difficulty of understanding it.
     * Some implementors have not picked up on this simpler method of
     * computing the RS operation, even though it is mentioned in the
     * specifications.
     *
     * It is possible to perform these computations faster by using 32-bit
     * word operations, but that is not portable and this is not a speed-
     * critical area.
     *
     * We explained the 1/x computation when we did the MDS matrix.
     *
     * The S vector is stored in K[32..64].
     * The S vector has to be reversed, so we loop cross-wise.
     *
     * Note the weird byte spacing of the S-vector, to match the even
     * or odd key words arrays. See the discussion at the Hxx macros for
     * details.
     */
    kptr = K + 8*kCycles;           /* Start at end of key */
    sptr = K + 32;                  /* Start at start of S */

    /* Loop over all key material */
    while( kptr > K )
        {
        kptr -= 8;
        /*
         * Initialise the polynimial in sptr[0..12]
         * The first four coefficients are 0 as we have to multiply by y^4.
         * The next 8 coefficients are from the key material.
         */
        memset( sptr, 0, 4 );
        memcpy( sptr+4, kptr, 8 );

        /*
         * The 12 bytes starting at sptr are now the coefficients of
         * the polynomial we need to reduce.
         */

        /* Loop over the polynomial coefficients from high to low */
        t = sptr+11;
        /* Keep looping until polynomial is degree 3; */
        while( t > sptr+3 )
            {
            /* Pick up the highest coefficient of the poly. */
            b = *t;

            /*
             * Compute x and (x+1/x) times this coefficient.
             * See the MDS matrix implementation for a discussion of
             * multiplication by x and 1/x. We just use different
             * constants here as we are in a
             * different finite field representation.
             *
             * These two statements set
             * bx = (x) * b
             * bxx= (x + 1/x) * b
             */
            bx = (Byte)((b<<1) ^ rs_poly_const[ b>>7 ]);
            bxx= (Byte)((b>>1) ^ rs_poly_div_const[ b&1 ] ^ bx);

            /*
             * Subtract suitable multiple of
             * y^4 + (x + 1/x)y^3 + (x)y^2 + (x + 1/x)y + 1
             * from the polynomial, except that we don't bother
             * updating t[0] as it will become zero anyway.
             */
            t[-1] ^= bxx;
            t[-2] ^= bx;
            t[-3] ^= bxx;
            t[-4] ^= b;

            /* Go to the next coefficient. */
            t--;
            }

        /* Go to next S-vector word, obeying the weird spacing rules. */
        sptr += 8;
        }

    /* Wipe variables that contained key material. */
#if 0
    b = bx = bxx = 0;
#endif

    /* And finally, we can compute the key-dependent S-boxes. */
    fill_keyed_sboxes( &K[32], kCycles, xkey );

    /* Wipe array that contained key material. */
#if 0
    memset( K, 0, sizeof( K ) );
#endif
    }


/*
 * We can now start on the actual encryption and decryption code.
 * As these are often speed-critical we will use a lot of macros.
 */

/*
 * The g() function is the heart of the round function.
 * We have two versions of the g() function, one without an input
 * rotation and one with.
 * The pre-computed S-boxes make this pretty simple.
 */
#define g0(X,xkey) \
 (xkey->s[0][b0(X)]^xkey->s[1][b1(X)]^xkey->s[2][b2(X)]^xkey->s[3][b3(X)])

#define g1(X,xkey) \
 (xkey->s[0][b3(X)]^xkey->s[1][b0(X)]^xkey->s[2][b1(X)]^xkey->s[3][b2(X)])

/*
 * A single round of Twofish. The A,B,C,D are the four state variables,
 * T0 and T1 are temporaries, xkey is the expanded key, and r the
 * round number.
 *
 * Note that this macro does not implement the swap at the end of the round.
 */
#define ENCRYPT_RND( A,B,C,D, T0, T1, xkey, r ) \
    T0 = g0(A,xkey); T1 = g1(B,xkey);\
    C ^= T0+T1+xkey->K[8+2*(r)]; C = ROR32(C,1);\
    D = ROL32(D,1); D ^= T0+2*T1+xkey->K[8+2*(r)+1]

/*
 * Encrypt a single cycle, consisting of two rounds.
 * This avoids the swapping of the two halves.
 * Parameter r is now the cycle number.
 */
#define ENCRYPT_CYCLE( A, B, C, D, T0, T1, xkey, r ) \
    ENCRYPT_RND( A,B,C,D,T0,T1,xkey,2*(r)   );\
    ENCRYPT_RND( C,D,A,B,T0,T1,xkey,2*(r)+1 )

/* Full 16-round encryption */
#define ENCRYPT( A,B,C,D,T0,T1,xkey ) \
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 0 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 1 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 2 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 3 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 4 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 5 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 6 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 7 )

/*
 * A single round of Twofish for decryption. It differs from
 * ENCRYTP_RND only because of the 1-bit rotations.
 */
#define DECRYPT_RND( A,B,C,D, T0, T1, xkey, r ) \
    T0 = g0(A,xkey); T1 = g1(B,xkey);\
    C = ROL32(C,1); C ^= T0+T1+xkey->K[8+2*(r)];\
    D ^= T0+2*T1+xkey->K[8+2*(r)+1]; D = ROR32(D,1)

/*
 * Decrypt a single cycle, consisting of two rounds.
 * This avoids the swapping of the two halves.
 * Parameter r is now the cycle number.
 */
#define DECRYPT_CYCLE( A, B, C, D, T0, T1, xkey, r ) \
    DECRYPT_RND( A,B,C,D,T0,T1,xkey,2*(r)+1 );\
    DECRYPT_RND( C,D,A,B,T0,T1,xkey,2*(r)   )

/* Full 16-round decryption. */
#define DECRYPT( A,B,C,D,T0,T1, xkey ) \
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 7 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 6 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 5 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 4 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 3 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 2 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 1 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 0 )

/*
 * A macro to read the state from the plaintext and do the initial key xors.
 * The koff argument allows us to use the same macro
 * for the decryption which uses different key words at the start.
 */
#define GET_INPUT( src, A,B,C,D, xkey, koff ) \
    A = GET32(src   )^xkey->K[  koff]; B = GET32(src+ 4)^xkey->K[1+koff]; \
    C = GET32(src+ 8)^xkey->K[2+koff]; D = GET32(src+12)^xkey->K[3+koff]

/*
 * Similar macro to put the ciphertext in the output buffer.
 * We xor the keys into the state variables before we use the PUT32
 * macro as the macro might use its argument multiple times.
 */
#define PUT_OUTPUT( A,B,C,D, dst, xkey, koff ) \
    A ^= xkey->K[  koff]; B ^= xkey->K[1+koff]; \
    C ^= xkey->K[2+koff]; D ^= xkey->K[3+koff]; \
    PUT32( A, dst   ); PUT32( B, dst+ 4 ); \
    PUT32( C, dst+8 ); PUT32( D, dst+12 )


/*
 * Twofish block encryption
 *
 * Arguments:
 * xkey         expanded key array
 * p            16 bytes of plaintext
 * c            16 bytes in which to store the ciphertext
 */
void Twofish_encrypt( Twofish_key * xkey, Byte p[16], Byte c[16])
    {
    UInt32 A,B,C,D,T0,T1;       /* Working variables */

    /* Get the four plaintext words xorred with the key */
    GET_INPUT( p, A,B,C,D, xkey, 0 );

    /* Do 8 cycles (= 16 rounds) */
    ENCRYPT( A,B,C,D,T0,T1,xkey );

    /* Store them with the final swap and the output whitening. */
    PUT_OUTPUT( C,D,A,B, c, xkey, 4 );
    }


/*
 * Twofish block decryption.
 *
 * Arguments:
 * xkey         expanded key array
 * p            16 bytes of plaintext
 * c            16 bytes in which to store the ciphertext
 */
void Twofish_decrypt( Twofish_key * xkey, Byte c[16], Byte p[16])
    {
    UInt32 A,B,C,D,T0,T1;       /* Working variables */

    /* Get the four plaintext words xorred with the key */
    GET_INPUT( c, A,B,C,D, xkey, 4 );

    /* Do 8 cycles (= 16 rounds) */
    DECRYPT( A,B,C,D,T0,T1,xkey );

    /* Store them with the final swap and the output whitening. */
    PUT_OUTPUT( C,D,A,B, p, xkey, 0 );
    }

/*
 * Using the macros it is easy to make special routines for
 * CBC mode, CTR mode etc. The only thing you might want to
 * add is a XOR_PUT_OUTPUT which xors the outputs into the
 * destinationa instead of overwriting the data. This requires
 * a XOR_PUT32 macro as well, but that should all be trivial.
 *
 * I thought about including routines for the separate cipher
 * modes here, but it is unclear which modes should be included,
 * and each encryption or decryption routine takes up a lot of code space.
 * Also, I don't have any test vectors for any cipher modes
 * with Twofish.
 */


/***************************************************************************
 *   Copyright (C) 2005-2007 Tarek Saidi <tarek.saidi@arcor.de>            *
 *   Copyright (c) 2003,2004 Dominik Reichl <dominik.reichl@t-online.de>   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; version 2 of the License.               *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

int Twofish_Encrypt(Twofish_key *m_key, Byte *pInput,  Byte *pOutBuffer, int nInputOctets, Byte *m_pInitVector)
{
	int i, numBlocks, padLen;
	Byte *iv;
	union {
		Byte block[16];
		UInt32 p32[4];	// needed for 'requires aligned' machines
	} x;
	UInt32 *p;
	Byte *block;

	p = x.p32;
	block = x.block;
	if ((pInput == NULL) || (nInputOctets <= 0) || (pOutBuffer == NULL)) return 0;

	numBlocks = nInputOctets / 16;

	iv = m_pInitVector;
	for (i = numBlocks; i > 0; i--)
	{
		p[0] = ((UInt32*)pInput)[0] ^ ((UInt32*)iv)[0];
		p[1] = ((UInt32*)pInput)[1] ^ ((UInt32*)iv)[1];
		// ((UInt32*)block)[2] = ((UInt32*)pInput)[2] ^ ((UInt32*)iv)[2];
		p[2] = ((UInt32*)pInput)[2] ^ ((UInt32*)iv)[2];
		p[3] = ((UInt32*)pInput)[3] ^ ((UInt32*)iv)[3];

		Twofish_encrypt(m_key, (Twofish_Byte *)block, (Twofish_Byte *)pOutBuffer);

		iv = pOutBuffer;
		pInput += 16;
		pOutBuffer += 16;
	}

	padLen = 16 - (nInputOctets - (16 * numBlocks));

	for (i = 0; i < 16 - padLen; i++)
	{
		block[i] = (Byte)(pInput[i] ^ iv[i]);
	}

	for (i = 16 - padLen; i < 16; i++)
	{
		block[i] = (Byte)((Byte)padLen ^ iv[i]);
	}

	Twofish_encrypt(m_key, (Twofish_Byte *)block, (Twofish_Byte *)pOutBuffer);

	return 16 * (numBlocks + 1);
}

int Twofish_Decrypt(Twofish_key *m_key, Byte *pInput, Byte *pOutBuffer, int nInputOctets, Byte *m_pInitVector)
{
	int i, numBlocks, padLen;
	UInt32 iv[4];
	union {
		Byte block[16];
		UInt32 p32[4];	// needed for 'requires aligned' machines
	} x;
	UInt32 *p;
	Byte *block;

	p = x.p32;
	block = x.block;
	if ((pInput == NULL) || (nInputOctets <= 0) || (pOutBuffer == NULL)) return 0;

	if ((nInputOctets % 16) != 0) { return -1; }

	numBlocks = nInputOctets / 16;

	memcpy(iv, m_pInitVector, 16);

	for (i = numBlocks - 1; i > 0; i--)
	{
		Twofish_decrypt(m_key, (Twofish_Byte *)pInput, (Twofish_Byte *)block);
		p[0] ^= iv[0];
		p[1] ^= iv[1];
		p[2] ^= iv[2];
		p[3] ^= iv[3];
		memcpy(iv, pInput, 16);
		memcpy(pOutBuffer, block, 16);
		pInput += 16;
		pOutBuffer += 16;
	}

	Twofish_decrypt(m_key, (Twofish_Byte *)pInput, (Twofish_Byte *)block);
	p[0] ^= iv[0];
	p[1] ^= iv[1];
	p[2] ^= iv[2];
	p[3] ^= iv[3];
	padLen = block[15];
	if (padLen <= 0 || padLen > 16) return -1;
	for (i = 16 - padLen; i < 16; i++)
	{
		if (block[i] != padLen) return -1;
	}
	memcpy(pOutBuffer, block, 16 - padLen);

	return 16*numBlocks - padLen;
}

int Twofish_Decrypt_cfb128(Twofish_key *m_key, Twofish_Byte *pInput, Twofish_Byte *pOutBuffer, int nInputOctets, Twofish_Byte *m_pInitVector)
{
	int i, numBlocks, ex;
	UInt32 iv[4];
	union {
		Byte block[16];
		UInt32 p32[4];	// needed for 'requires aligned' machines
	} x;
	UInt32 *p;
	Byte *block;

	p = x.p32;
	block = x.block;
	if ((pInput == NULL) || (nInputOctets <= 0) || (pOutBuffer == NULL)) return 0;

	numBlocks = nInputOctets / 16;
	ex = nInputOctets % 16;

	memcpy(iv, m_pInitVector, 16);

	for (i = numBlocks; i > 0; i--)
	{
		Twofish_encrypt(m_key, (Twofish_Byte *)iv, (Twofish_Byte *)block);
		memcpy(iv, pInput, 16);
		p[0] ^= iv[0];
		p[1] ^= iv[1];
		p[2] ^= iv[2];
		p[3] ^= iv[3];
		memcpy(pOutBuffer, block, 16);
		pInput += 16;
		pOutBuffer += 16;
	}
	/* less than full block for last block. Only put in that many bytes */
	if (ex) {
		Twofish_encrypt(m_key, (Twofish_Byte *)iv, (Twofish_Byte *)block);
		for (i = 0; i < ex; ++i)
			pOutBuffer[i] = pInput[i] ^ block[i];
	}

	return nInputOctets;
}
