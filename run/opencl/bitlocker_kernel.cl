/*
 * BitLocker-OpenCL format developed by Elenago
 * <elena dot ago at gmail dot com> in 2015
 *
 * Copyright (c) 2015-2017 Elenago <elena dot ago at gmail dot com>
 * and Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor
 * implied. See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * More info here: https://openwall.info/wiki/john/OpenCL-BitLocker
 *
 * A standalone CUDA implementation is available here: https://github.com/e-ago/bitcracker
 */

#include "opencl_misc.h"
#include "opencl_bitlocker.h"

#include "opencl_aes_tables.h"
#define TS0 Te0
#define TS1 Te1
#define TS2 Te2
#define TS3 Te3

INLINE unsigned int OPT3_XOR(unsigned int a, unsigned int b, unsigned int c)
{
#if HAVE_LUT3
	return lut3(a, b, c, 0x96);
#else
	return a ^ b ^ c;
#endif
}

INLINE unsigned int OPT3_XORAND(unsigned int a, unsigned int b, unsigned int c)
{
#if HAVE_LUT3
	return lut3(a, b, c, 0xb8);
#else
	return (a ^ (b & (c ^ a)));
#endif
}

INLINE unsigned int OPT3_ANDOR(unsigned int a, unsigned int b, unsigned int c)
{
#if HAVE_LUT3
	return lut3(a, b, c, 0xe8);
#elif USE_BITSELECT
	return bitselect(a, b, c ^ a);
#else
	return ((a & (b | c)) | (b & c));
#endif
}


void encrypt(
        unsigned int k0, unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4, unsigned int k5, unsigned int k6, unsigned int k7,
        unsigned int m0, unsigned int m1, unsigned int m2, unsigned int m3,
        unsigned int * output0, unsigned int * output1, unsigned int * output2, unsigned int * output3
);

int enableMacVerification(
    unsigned int IV0, unsigned int IV4, unsigned int IV8, unsigned int IV12,
    unsigned int macIV0, unsigned int macIV4, unsigned int macIV8, unsigned int macIV12,
    unsigned int cMacIV0, unsigned int cMacIV4, unsigned int cMacIV8, unsigned int cMacIV12,
    unsigned int hash0, unsigned int hash1, unsigned int hash2, unsigned int hash3,
    unsigned int hash4, unsigned int hash5, unsigned int hash6, unsigned int hash7,
    __global unsigned char * vmkKey, __global unsigned char * mac, int gIndex
);


#define BITLOCKER_PSW_CHAR_SIZE 	64
#define BITLOCKER_PSW_INT_SIZE 		32
#define BITLOCKER_FIRST_LENGHT 		27
#define BITLOCKER_SECOND_LENGHT 	55
#define SINGLE_BLOCK_W_SIZE         64
#define ITERATION_NUMBER            0x100000
#define SALT_SIZE                   16
#define INT_HASH_SIZE               8
#define BITLOCKER_HASH_UP 			0
#define BITLOCKER_HASH_UP_MAC		1
#define BITLOCKER_HASH_RP 			2
#define BITLOCKER_HASH_RP_MAC		3

void encrypt(
        unsigned int k0, unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4, unsigned int k5, unsigned int k6, unsigned int k7,
        unsigned int m0, unsigned int m1, unsigned int m2, unsigned int m3,
        unsigned int * output0, unsigned int * output1, unsigned int * output2, unsigned int * output3
)
{
        unsigned int enc_schedule0, enc_schedule1, enc_schedule2, enc_schedule3, enc_schedule4, enc_schedule5, enc_schedule6, enc_schedule7;
        unsigned int local_key0, local_key1, local_key2, local_key3, local_key4, local_key5, local_key6, local_key7;

        local_key0=k0;
        local_key1=k1;
        local_key2=k2;
        local_key3=k3;
        local_key4=k4;
        local_key5=k5;
        local_key6=k6;
        local_key7=k7;

        enc_schedule0=(unsigned int )(((unsigned int )(m0 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(m0 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(m0 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(m0 & 0x000000ff) << 24);
        enc_schedule0 = enc_schedule0 ^ local_key0;

        enc_schedule1=(unsigned int )(((unsigned int )(m1 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(m1 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(m1 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(m1 & 0x000000ff) << 24);
        enc_schedule1 = enc_schedule1 ^ local_key1;

        enc_schedule2=(unsigned int )(((unsigned int )(m2 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(m2 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(m2 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(m2 & 0x000000ff) << 24);
        enc_schedule2 = enc_schedule2 ^ local_key2;

        enc_schedule3=(unsigned int )(((unsigned int )(m3 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(m3 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(m3 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(m3 & 0x000000ff) << 24);
        enc_schedule3 = enc_schedule3 ^ local_key3;

        enc_schedule4 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
        enc_schedule5 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
        enc_schedule6 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
        enc_schedule7 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

        local_key0 ^= OPT3_XOR(
                                        OPT3_XOR( (TS2[(local_key7 >> 24) ] & 0x000000FF), (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000), (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000)),
                                                (TS1[(local_key7 ) & 0xFF] & 0x0000FF00), 0x01000000
                                ); //RCON[0];
        local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

        enc_schedule0 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
        enc_schedule1 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
        enc_schedule2 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
        enc_schedule3 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

        local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                          (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                          (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
        local_key5 ^= local_key4;
        local_key6 ^= local_key5;
        local_key7 ^= local_key6;

        enc_schedule4 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
        enc_schedule5 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
        enc_schedule6 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
        enc_schedule7 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

        local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                          (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                          (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x02000000; //RCON[1];
        local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

        enc_schedule0 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
        enc_schedule1 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
        enc_schedule2 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
        enc_schedule3 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

        local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                          (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                          (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
        local_key5 ^= local_key4;
        local_key6 ^= local_key5;
        local_key7 ^= local_key6;

        enc_schedule4 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
        enc_schedule5 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
        enc_schedule6 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
        enc_schedule7 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);


        local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                          (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                          (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x04000000; //RCON[2];
        local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

        enc_schedule0 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
        enc_schedule1 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
        enc_schedule2 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
        enc_schedule3 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);


        local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                          (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                          (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
        local_key5 ^= local_key4;
        local_key6 ^= local_key5;
        local_key7 ^= local_key6;

        enc_schedule4 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
        enc_schedule5 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
        enc_schedule6 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
        enc_schedule7 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

        local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                          (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                          (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x08000000; //RCON[3];
        local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

        enc_schedule0 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
        enc_schedule1 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
        enc_schedule2 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
        enc_schedule3 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

        local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                          (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                          (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
        local_key5 ^= local_key4;
        local_key6 ^= local_key5;
        local_key7 ^= local_key6;

        enc_schedule4 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
        enc_schedule5 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
        enc_schedule6 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
        enc_schedule7 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

        local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                          (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                          (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x10000000; //RCON[4];
        local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

        enc_schedule0 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
        enc_schedule1 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
        enc_schedule2 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
        enc_schedule3 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

        local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                          (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                          (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
        local_key5 ^= local_key4;
        local_key6 ^= local_key5;
        local_key7 ^= local_key6;

        enc_schedule4 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
        enc_schedule5 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
        enc_schedule6 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
        enc_schedule7 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);


        local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                          (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                          (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x20000000; //RCON[5];
        local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

        enc_schedule0 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
        enc_schedule1 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
        enc_schedule2 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
        enc_schedule3 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

        local_key4 ^= (TS3[(local_key3 >> 24)] & 0xFF000000) ^
                          (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                          (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                          (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
        local_key5 ^= local_key4;
        local_key6 ^= local_key5;
        local_key7 ^= local_key6;

        enc_schedule4 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
        enc_schedule5 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
        enc_schedule6 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
        enc_schedule7 = OPT3_XOR(OPT3_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

        local_key0 ^= (TS2[(local_key7 >> 24)] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x40000000; //RCON[6];
        local_key1 ^= local_key0;
        local_key2 ^= local_key1;
        local_key3 ^= local_key2;

        enc_schedule0 = (TS2[(enc_schedule4 >> 24)       ] & 0xFF000000) ^
                 (TS3[(enc_schedule5 >> 16) & 0xFF] & 0x00FF0000) ^
                 (TS0[(enc_schedule6 >>  8) & 0xFF] & 0x0000FF00) ^
                 (TS1[(enc_schedule7      ) & 0xFF] & 0x000000FF) ^ local_key0;

        enc_schedule1 = (TS2[(enc_schedule5 >> 24)       ] & 0xFF000000) ^
                 (TS3[(enc_schedule6 >> 16) & 0xFF] & 0x00FF0000) ^
                 (TS0[(enc_schedule7 >>  8) & 0xFF] & 0x0000FF00) ^
                 (TS1[(enc_schedule4      ) & 0xFF] & 0x000000FF) ^ local_key1;

        enc_schedule2 = (TS2[(enc_schedule6 >> 24)       ] & 0xFF000000) ^
                 (TS3[(enc_schedule7 >> 16) & 0xFF] & 0x00FF0000) ^
                 (TS0[(enc_schedule4 >>  8) & 0xFF] & 0x0000FF00) ^
                 (TS1[(enc_schedule5      ) & 0xFF] & 0x000000FF) ^ local_key2;

        enc_schedule3 = (TS2[(enc_schedule7 >> 24)       ] & 0xFF000000) ^
                 (TS3[(enc_schedule4 >> 16) & 0xFF] & 0x00FF0000) ^
                 (TS0[(enc_schedule5 >>  8) & 0xFF] & 0x0000FF00) ^
                 (TS1[(enc_schedule6      ) & 0xFF] & 0x000000FF) ^ local_key3;

        output0[0]=(unsigned int )(((unsigned int )(enc_schedule0 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(enc_schedule0 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(enc_schedule0 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(enc_schedule0 & 0x000000ff) << 24);
        output1[0]=(unsigned int )(((unsigned int )(enc_schedule1 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(enc_schedule1 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(enc_schedule1 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(enc_schedule1 & 0x000000ff) << 24);
        output2[0]=(unsigned int )(((unsigned int )(enc_schedule2 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(enc_schedule2 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(enc_schedule2 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(enc_schedule2 & 0x000000ff) << 24);
        output3[0]=(unsigned int )(((unsigned int )(enc_schedule3 & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(enc_schedule3 & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(enc_schedule3 & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(enc_schedule3 & 0x000000ff) << 24);
}

int enableMacVerification(
    unsigned int IV0, unsigned int IV4, unsigned int IV8, unsigned int IV12,
    unsigned int macIV0, unsigned int macIV4, unsigned int macIV8, unsigned int macIV12,
    unsigned int cMacIV0, unsigned int cMacIV4, unsigned int cMacIV8, unsigned int cMacIV12,
    unsigned int hash0, unsigned int hash1, unsigned int hash2, unsigned int hash3,
    unsigned int hash4, unsigned int hash5, unsigned int hash6, unsigned int hash7,
    __global unsigned char * vmkKey, __global unsigned char * mac, int gIndex
)
{
    unsigned int a,b,c,d;
	unsigned int local0, local1, local2, local3, local4, local5, local6, local7, local8, local9;
	unsigned int local10, local11, local12, local13, local14, local15, local16, local17, local18, local19;
	unsigned int local28, local29, local30, local31;

	a = IV0;
    b = IV4;
    c = IV8;
    d = IV12;

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            a, b, c, d,
            &(local0), &(local1), &(local2), &(local3)
    );

    local0=
            (((unsigned int)(vmkKey[3] ^ ((unsigned char) (local0 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[2] ^ ((unsigned char) (local0 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[1] ^ ((unsigned char) (local0 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[0] ^ ((unsigned char) (local0)))) << 0);

    local1=
            (((unsigned int)(vmkKey[7] ^ ((unsigned char) (local1 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[6] ^ ((unsigned char) (local1 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[5] ^ ((unsigned char) (local1 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[4] ^ ((unsigned char) (local1)))) << 0);

    local2=
            (((unsigned int)(vmkKey[11] ^ ((unsigned char) (local2 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[10] ^ ((unsigned char) (local2 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[9] ^ ((unsigned char) (local2 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[8] ^ ((unsigned char) (local2)))) << 0);

    local3=
            (((unsigned int)(vmkKey[15] ^ ((unsigned char) (local3 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[14] ^ ((unsigned char) (local3 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[13] ^ ((unsigned char) (local3 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[12] ^ ((unsigned char) (local3)))) << 0);

    d += 0x01000000;

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            a, b, c, d,
            &(local4), &(local5), &(local6), &(local7)
    );

    local4=
            (((unsigned int)(vmkKey[19] ^ ((unsigned char) (local4 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[18] ^ ((unsigned char) (local4 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[17] ^ ((unsigned char) (local4 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[16] ^ ((unsigned char) (local4)))) << 0);

    local5=
            (((unsigned int)(vmkKey[23] ^ ((unsigned char) (local5 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[22] ^ ((unsigned char) (local5 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[21] ^ ((unsigned char) (local5 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[20] ^ ((unsigned char) (local5)))) << 0);

    local6=
            (((unsigned int)(vmkKey[27] ^ ((unsigned char) (local6 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[26] ^ ((unsigned char) (local6 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[25] ^ ((unsigned char) (local6 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[24] ^ ((unsigned char) (local6)))) << 0);

    local7=
            (((unsigned int)(vmkKey[31] ^ ((unsigned char) (local7 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[30] ^ ((unsigned char) (local7 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[29] ^ ((unsigned char) (local7 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[28] ^ ((unsigned char) (local7)))) << 0);


    d += 0x01000000;

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            a, b, c, d,
            &(local8), &(local9), &(local10), &(local11)
    );

    local8=
            (((unsigned int)(vmkKey[35] ^ ((unsigned char) (local8 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[34] ^ ((unsigned char) (local8 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[33] ^ ((unsigned char) (local8 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[32] ^ ((unsigned char) (local8)))) << 0);

    local9=
            (((unsigned int)(vmkKey[39] ^ ((unsigned char) (local9 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[38] ^ ((unsigned char) (local9 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[37] ^ ((unsigned char) (local9 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[36] ^ ((unsigned char) (local9)))) << 0);

    local10=
            (((unsigned int)(vmkKey[43] ^ ((unsigned char) (local10 >> 24) ))) << 24) |
            (((unsigned int)(vmkKey[42] ^ ((unsigned char) (local10 >> 16) ))) << 16) |
            (((unsigned int)(vmkKey[41] ^ ((unsigned char) (local10 >> 8) ))) << 8) |
            (((unsigned int)(vmkKey[40] ^ ((unsigned char) (local10)))) << 0);

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            macIV0, macIV4, macIV8, macIV12,
            &(local16), &(local17), &(local18), &(local19)
    );

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            cMacIV0, cMacIV4, cMacIV8, cMacIV12,
            &(local12), &(local13), &(local14), &(local15)
    );

    local28 = local0 ^ local12;
    local29 = local1 ^ local13;
    local30 = local2 ^ local14;
    local31 = local3 ^ local15;

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            local28, local29, local30, local31,
            &(local12), &(local13), &(local14), &(local15)
    );

    local28 = local4 ^ local12;
    local29 = local5 ^ local13;
    local30 = local6 ^ local14;
    local31 = local7 ^ local15;

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            local28, local29, local30, local31,
            &(local12), &(local13), &(local14), &(local15)
    );

    local28 = local8 ^ local12;
    local29 = local9 ^ local13;
    local30 = local10 ^ local14;
    local31 = local15;

    encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            local28, local29, local30, local31,
            &(local12), &(local13), &(local14), &(local15)
    );

    if (

            (
                local12 == ( (unsigned int)
                                (((unsigned int)(mac[3] ^ ((unsigned char) (local16 >> 24) ))) << 24) |
                                (((unsigned int)(mac[2] ^ ((unsigned char) (local16 >> 16) ))) << 16) |
                                (((unsigned int)(mac[1] ^ ((unsigned char) (local16 >> 8) ))) << 8) |
                                (((unsigned int)(mac[0] ^ ((unsigned char) (local16)))) << 0) )
            )
            &&
            (
                local13 == ( (unsigned int)
                                (((unsigned int)(mac[7] ^ ((unsigned char) (local17 >> 24) ))) << 24) |
                                (((unsigned int)(mac[6] ^ ((unsigned char) (local17 >> 16) ))) << 16) |
                                (((unsigned int)(mac[5] ^ ((unsigned char) (local17 >> 8) ))) << 8) |
                                (((unsigned int)(mac[4] ^ ((unsigned char) (local17)))) << 0) )
            )
            &&
            (
                local14 == ( (unsigned int)
                                (((unsigned int)(mac[11] ^ ((unsigned char) (local18 >> 24) ))) << 24) |
                                (((unsigned int)(mac[10] ^ ((unsigned char) (local18 >> 16) ))) << 16) |
                                (((unsigned int)(mac[9] ^ ((unsigned char) (local18 >> 8) ))) << 8) |
                                (((unsigned int)(mac[8] ^ ((unsigned char) (local18)))) << 0) )
            )
            &&
            (
                local15 == ( (unsigned int)
                                (((unsigned int)(mac[15] ^ ((unsigned char) (local19 >> 24) ))) << 24) |
                                (((unsigned int)(mac[14] ^ ((unsigned char) (local19 >> 16) ))) << 16) |
                                (((unsigned int)(mac[13] ^ ((unsigned char) (local19 >> 8) ))) << 8) |
                                (((unsigned int)(mac[12] ^ ((unsigned char) (local19)))) << 0) )
            )
    )
    {
		return gIndex;
    }
    return -1;
}



__kernel void opencl_bitlocker_wblocks(
			__global unsigned char *salt_d,
			__global unsigned char *padding_d,
			__global unsigned int *d_wblocks)
{
        unsigned long loop = get_global_id(0);
        unsigned char block[SINGLE_BLOCK_W_SIZE];
        int i, j;

        for (i = 0; i < SALT_SIZE; i++)
                block[i] = salt_d[i];

        i += 8;

        for (j = 0; j < 40; i++, j++)
                block[i] = padding_d[j];

        while(loop < ITERATION_NUMBER)
        {
                block[16] = (unsigned char) (loop >> (0*8));
                block[17] = (unsigned char) (loop >> (1*8));
                block[18] = (unsigned char) (loop >> (2*8));
                block[19] = (unsigned char) (loop >> (3*8));
                block[20] = (unsigned char) (loop >> (4*8));
                block[21] = (unsigned char) (loop >> (5*8));
                block[22] = (unsigned char) (loop >> (6*8));
                block[23] = (unsigned char) (loop >> (7*8));

                LOADSCHEDULE_WPRE( 0, (SINGLE_BLOCK_W_SIZE*loop)+0)
                LOADSCHEDULE_WPRE( 1, (SINGLE_BLOCK_W_SIZE*loop)+1)
                LOADSCHEDULE_WPRE( 2, (SINGLE_BLOCK_W_SIZE*loop)+2)
                LOADSCHEDULE_WPRE( 3, (SINGLE_BLOCK_W_SIZE*loop)+3)
                LOADSCHEDULE_WPRE( 4, (SINGLE_BLOCK_W_SIZE*loop)+4)
                LOADSCHEDULE_WPRE( 5, (SINGLE_BLOCK_W_SIZE*loop)+5)
                LOADSCHEDULE_WPRE( 6, (SINGLE_BLOCK_W_SIZE*loop)+6)
                LOADSCHEDULE_WPRE( 7, (SINGLE_BLOCK_W_SIZE*loop)+7)
                LOADSCHEDULE_WPRE( 8, (SINGLE_BLOCK_W_SIZE*loop)+8)
                LOADSCHEDULE_WPRE( 9, (SINGLE_BLOCK_W_SIZE*loop)+9)
                LOADSCHEDULE_WPRE(10, (SINGLE_BLOCK_W_SIZE*loop)+10)
                LOADSCHEDULE_WPRE(11, (SINGLE_BLOCK_W_SIZE*loop)+11)
                LOADSCHEDULE_WPRE(12, (SINGLE_BLOCK_W_SIZE*loop)+12)
                LOADSCHEDULE_WPRE(13, (SINGLE_BLOCK_W_SIZE*loop)+13)
                LOADSCHEDULE_WPRE(14, (SINGLE_BLOCK_W_SIZE*loop)+14)
                LOADSCHEDULE_WPRE(15, (SINGLE_BLOCK_W_SIZE*loop)+15)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+16)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+17)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+18)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+19)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+20)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+21)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+22)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+23)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+24)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+25)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+26)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+27)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+28)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+29)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+30)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+31)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+32)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+33)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+34)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+35)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+36)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+37)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+38)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+39)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+40)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+41)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+42)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+43)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+44)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+45)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+46)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+47)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+48)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+49)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+50)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+51)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+52)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+53)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+54)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+55)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+56)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+57)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+58)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+59)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+60)

                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+61)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+62)
                SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+63)

                loop += get_global_size(0);
        }
}


__kernel void opencl_bitlocker_attack_init(__global int *nPswPtr,
                                      __global unsigned int *d_pswI,
                                      __global int *d_pswSize,
                                      __global int *first_hash,
                                      __global int *output_hash,
                                      __global int *attack_type
                                      )
{
	unsigned int schedule0, schedule1, schedule2, schedule3, schedule4, schedule5, schedule6, schedule7, schedule8, schedule9;
	unsigned int schedule10, schedule11, schedule12, schedule13, schedule14, schedule15, schedule16, schedule17, schedule18, schedule19;
	unsigned int schedule20, schedule21, schedule22, schedule23, schedule24, schedule25, schedule26, schedule27, schedule28, schedule29;
	unsigned int schedule30, schedule31;
	unsigned int first_hash0, first_hash1, first_hash2, first_hash3, first_hash4, first_hash5, first_hash6, first_hash7;
	unsigned int a, b, c, d, e, f, g, h;
	int nPsw = 0, indexW=0;
	int gIndex = (int)get_global_id(0);

	nPsw = nPswPtr[0];

	while (gIndex < nPsw) {

                first_hash0 = 0x6A09E667;
                first_hash1 = 0xBB67AE85;
                first_hash2 = 0x3C6EF372;
                first_hash3 = 0xA54FF53A;
                first_hash4 = 0x510E527F;
                first_hash5 = 0x9B05688C;
                first_hash6 = 0x1F83D9AB;
                first_hash7 = 0x5BE0CD19;

                a = 0x6A09E667;
                b = 0xBB67AE85;
                c = 0x3C6EF372;
                d = 0xA54FF53A;
                e = 0x510E527F;
                f = 0x9B05688C;
                g = 0x1F83D9AB;
                h = 0x5BE0CD19;

                indexW=(gIndex*BITLOCKER_PSW_INT_SIZE);

                //--------------------- INPUT -------------------
                schedule0 = (unsigned int) (d_pswI[indexW+0]);
                schedule1 = (unsigned int) (d_pswI[indexW+1]);
                schedule2 = (unsigned int) (d_pswI[indexW+2]);
                schedule3 = (unsigned int) (d_pswI[indexW+3]);
                schedule4 = (unsigned int) (d_pswI[indexW+4]);
                schedule5 = (unsigned int) (d_pswI[indexW+5]);
                schedule6 = (unsigned int) (d_pswI[indexW+6]);
                schedule7 = (unsigned int) (d_pswI[indexW+7]);
                schedule8 = (unsigned int) (d_pswI[indexW+8]);
                schedule9 = (unsigned int) (d_pswI[indexW+9]);
                schedule10 = (unsigned int) (d_pswI[indexW+10]);
                schedule11 = (unsigned int) (d_pswI[indexW+11]);
                schedule12 = (unsigned int) (d_pswI[indexW+12]);
                schedule13 = (unsigned int) (d_pswI[indexW+13]);
                schedule14 = (unsigned int) (d_pswI[indexW+14]);
                schedule15 = (unsigned int) (d_pswI[indexW+15]);

                //-----------------------------------------------

		ALL_SCHEDULE_LAST16()

		ROUND(a, b, c, d, e, f, g, h, schedule0, 0x428A2F98)
		ROUND(h, a, b, c, d, e, f, g, schedule1, 0x71374491)
		ROUND(g, h, a, b, c, d, e, f, schedule2, 0xB5C0FBCF)
		ROUND(f, g, h, a, b, c, d, e, schedule3, 0xE9B5DBA5)
		ROUND(e, f, g, h, a, b, c, d, schedule4, 0x3956C25B)
		ROUND(d, e, f, g, h, a, b, c, schedule5, 0x59F111F1)
		ROUND(c, d, e, f, g, h, a, b, schedule6, 0x923F82A4)
		ROUND(b, c, d, e, f, g, h, a, schedule7, 0xAB1C5ED5)
		ROUND(a, b, c, d, e, f, g, h, schedule8, 0xD807AA98)
		ROUND(h, a, b, c, d, e, f, g, schedule9, 0x12835B01)
		ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
		ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
		ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
		ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
		ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
		ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
		ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
		ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
		ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
		ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
		ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
		ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
		ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
		ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
		ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
		ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
		ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
		ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
		ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
		ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
		ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
		ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

		ALL_SCHEDULE32()

		ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
		ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
		ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
		ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
		ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
		ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
		ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
		ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
		ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
		ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
		ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
		ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
		ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
		ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
		ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
		ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
		ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
		ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
		ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
		ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
		ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
		ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
		ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
		ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
		ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
		ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
		ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
		ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
		ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
		ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
		ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
		ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)

		first_hash0 += a;
		first_hash1 += b;
		first_hash2 += c;
		first_hash3 += d;
		first_hash4 += e;
		first_hash5 += f;
		first_hash6 += g;
		first_hash7 += h;

		if(attack_type[0] == BITLOCKER_HASH_UP || attack_type[0] == BITLOCKER_HASH_UP_MAC)
		{
			if(d_pswSize[gIndex] == 2)
			{
				//--------------------- INPUT -------------------
		                schedule0 = (unsigned int) d_pswI[indexW+16];
				schedule1 = (unsigned int) d_pswI[indexW+17];
				schedule2 = (unsigned int) d_pswI[indexW+18];
				schedule3 = (unsigned int) d_pswI[indexW+19];
				schedule4 = (unsigned int) d_pswI[indexW+20];
				schedule5 = (unsigned int) d_pswI[indexW+21];
				schedule6 = (unsigned int) d_pswI[indexW+22];
				schedule7 = (unsigned int) d_pswI[indexW+23];
				schedule8 = (unsigned int) d_pswI[indexW+24];
				schedule9 = (unsigned int) d_pswI[indexW+25];
				schedule10 = (unsigned int) d_pswI[indexW+26];
				schedule11 = (unsigned int) d_pswI[indexW+27];
				schedule12 = (unsigned int) d_pswI[indexW+28];
				schedule13 = (unsigned int) d_pswI[indexW+29];
				schedule14 = (unsigned int) d_pswI[indexW+30];
				schedule15 = (unsigned int) d_pswI[indexW+31];
		                //-----------------------------------------------

				a = first_hash0;
				b = first_hash1;
				c = first_hash2;
				d = first_hash3;
				e = first_hash4;
				f = first_hash5;
				g = first_hash6;
				h = first_hash7;

				ALL_SCHEDULE_LAST16()

				ROUND(a, b, c, d, e, f, g, h, schedule0, 0x428A2F98)
				ROUND(h, a, b, c, d, e, f, g, schedule1, 0x71374491)
				ROUND(g, h, a, b, c, d, e, f, schedule2, 0xB5C0FBCF)
				ROUND(f, g, h, a, b, c, d, e, schedule3, 0xE9B5DBA5)
				ROUND(e, f, g, h, a, b, c, d, schedule4, 0x3956C25B)
				ROUND(d, e, f, g, h, a, b, c, schedule5, 0x59F111F1)
				ROUND(c, d, e, f, g, h, a, b, schedule6, 0x923F82A4)
				ROUND(b, c, d, e, f, g, h, a, schedule7, 0xAB1C5ED5)
				ROUND(a, b, c, d, e, f, g, h, schedule8, 0xD807AA98)
				ROUND(h, a, b, c, d, e, f, g, schedule9, 0x12835B01)
				ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
				ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
				ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
				ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
				ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
				ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
				ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
				ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
				ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
				ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
				ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
				ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
				ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
				ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
				ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
				ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
				ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
				ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
				ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
				ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
				ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
				ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

				ALL_SCHEDULE32()

				ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
				ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
				ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
				ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
				ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
				ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
				ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
				ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
				ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
				ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
				ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
				ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
				ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
				ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
				ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
				ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
				ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
				ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
				ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
				ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
				ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
				ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
				ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
				ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
				ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
				ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
				ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
				ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
				ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
				ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
				ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
				ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)

				first_hash0 += a;
				first_hash1 += b;
				first_hash2 += c;
				first_hash3 += d;
				first_hash4 += e;
				first_hash5 += f;
				first_hash6 += g;
				first_hash7 += h;
			}

			schedule0 = first_hash0;
			schedule1 = first_hash1;
			schedule2 = first_hash2;
			schedule3 = first_hash3;
			schedule4 = first_hash4;
			schedule5 = first_hash5;
			schedule6 = first_hash6;
			schedule7 = first_hash7;
			schedule8 = 0x80000000;
			schedule9 = 0;
			schedule10 = 0;
			schedule11 = 0;
			schedule12 = 0;
			schedule13 = 0;
			schedule14 = 0;
			schedule15 = 0x100;

			first_hash0 = 0x6A09E667;
			first_hash1 = 0xBB67AE85;
			first_hash2 = 0x3C6EF372;
			first_hash3 = 0xA54FF53A;
			first_hash4 = 0x510E527F;
			first_hash5 = 0x9B05688C;
			first_hash6 = 0x1F83D9AB;
			first_hash7 = 0x5BE0CD19;

			a = first_hash0;
			b = first_hash1;
			c = first_hash2;
			d = first_hash3;
			e = first_hash4;
			f = first_hash5;
			g = first_hash6;
			h = first_hash7;

			ALL_SCHEDULE_LAST16()

			ROUND(a, b, c, d, e, f, g, h, schedule0, 0x428A2F98)
			ROUND(h, a, b, c, d, e, f, g, schedule1, 0x71374491)
			ROUND(g, h, a, b, c, d, e, f, schedule2, 0xB5C0FBCF)
			ROUND(f, g, h, a, b, c, d, e, schedule3, 0xE9B5DBA5)
			ROUND(e, f, g, h, a, b, c, d, schedule4, 0x3956C25B)
			ROUND(d, e, f, g, h, a, b, c, schedule5, 0x59F111F1)
			ROUND(c, d, e, f, g, h, a, b, schedule6, 0x923F82A4)
			ROUND(b, c, d, e, f, g, h, a, schedule7, 0xAB1C5ED5)
			ROUND(a, b, c, d, e, f, g, h, schedule8, 0xD807AA98)
			ROUND(h, a, b, c, d, e, f, g, schedule9, 0x12835B01)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

			ALL_SCHEDULE32()

			ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
			ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
			ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
			ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
			ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
			ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
			ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
			ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
			ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
			ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)

			first_hash0 += a;
			first_hash1 += b;
			first_hash2 += c;
			first_hash3 += d;
			first_hash4 += e;
			first_hash5 += f;
			first_hash6 += g;
			first_hash7 += h;
		}

		first_hash[(gIndex*INT_HASH_SIZE) + 0] = first_hash0;
		first_hash[(gIndex*INT_HASH_SIZE) + 1] = first_hash1;
		first_hash[(gIndex*INT_HASH_SIZE) + 2] = first_hash2;
		first_hash[(gIndex*INT_HASH_SIZE) + 3] = first_hash3;
		first_hash[(gIndex*INT_HASH_SIZE) + 4] = first_hash4;
		first_hash[(gIndex*INT_HASH_SIZE) + 5] = first_hash5;
		first_hash[(gIndex*INT_HASH_SIZE) + 6] = first_hash6;
		first_hash[(gIndex*INT_HASH_SIZE) + 7] = first_hash7;

		gIndex += get_global_size(0);
	}
}

// ----- Main SHA-256 loop
__kernel void opencl_bitlocker_attack_loop(__global int *nPswPtr,
                                      __global unsigned int *d_wblocks,
                                      __global int *first_hash,
                                      __global int *output_hash,
                                      __global int *startIndex,
                                      __global int *hashLoops
                                      )
{
	unsigned int schedule0, schedule1, schedule2, schedule3, schedule4, schedule5, schedule6, schedule7, schedule8, schedule9;
	unsigned int schedule10, schedule11, schedule12, schedule13, schedule14, schedule15, schedule16, schedule17, schedule18, schedule19;
	unsigned int schedule20, schedule21, schedule22, schedule23, schedule24, schedule25, schedule26, schedule27, schedule28, schedule29;
	unsigned int schedule30, schedule31;
	unsigned int first_hash0, first_hash1, first_hash2, first_hash3, first_hash4, first_hash5, first_hash6, first_hash7;
	unsigned int hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
	unsigned int a, b, c, d, e, f, g, h;

	int index, nPsw = 0, indexW=0;
	int gIndex = (int)get_global_id(0);
	int nIter = startIndex[0];

	nPsw = nPswPtr[0];

	while (gIndex < nPsw)
	{
		indexW = (SINGLE_BLOCK_W_SIZE * nIter);

		first_hash0 = first_hash[(gIndex*INT_HASH_SIZE) + 0];
		first_hash1 = first_hash[(gIndex*INT_HASH_SIZE) + 1];
		first_hash2 = first_hash[(gIndex*INT_HASH_SIZE) + 2];
		first_hash3 = first_hash[(gIndex*INT_HASH_SIZE) + 3];
		first_hash4 = first_hash[(gIndex*INT_HASH_SIZE) + 4];
		first_hash5 = first_hash[(gIndex*INT_HASH_SIZE) + 5];
		first_hash6 = first_hash[(gIndex*INT_HASH_SIZE) + 6];
		first_hash7 = first_hash[(gIndex*INT_HASH_SIZE) + 7];

		hash0 = output_hash[(gIndex*INT_HASH_SIZE) + 0];
		hash1 = output_hash[(gIndex*INT_HASH_SIZE) + 1];
		hash2 = output_hash[(gIndex*INT_HASH_SIZE) + 2];
		hash3 = output_hash[(gIndex*INT_HASH_SIZE) + 3];
		hash4 = output_hash[(gIndex*INT_HASH_SIZE) + 4];
		hash5 = output_hash[(gIndex*INT_HASH_SIZE) + 5];
		hash6 = output_hash[(gIndex*INT_HASH_SIZE) + 6];
		hash7 = output_hash[(gIndex*INT_HASH_SIZE) + 7];

		for (index = 0; index < hashLoops[0]; index++)
		{
			a = 0x6A09E667;
			b = 0xBB67AE85;
			c = 0x3C6EF372;
			d = 0xA54FF53A;
			e = 0x510E527F;
			f = 0x9B05688C;
			g = 0x1F83D9AB;
			h = 0x5BE0CD19;

			schedule0 = hash0;
			schedule1 = hash1;
			schedule2 = hash2;
			schedule3 = hash3;
			schedule4 = hash4;
			schedule5 = hash5;
			schedule6 = hash6;
			schedule7 = hash7;

			schedule8 = first_hash0;
			schedule9 = first_hash1;
			schedule10 = first_hash2;
			schedule11 = first_hash3;
			schedule12 = first_hash4;
			schedule13 = first_hash5;
			schedule14 = first_hash6;
			schedule15 = first_hash7;

			ALL_SCHEDULE_LAST16()

			ROUND(a, b, c, d, e, f, g, h, schedule0, 0x428A2F98)
			ROUND(h, a, b, c, d, e, f, g, schedule1, 0x71374491)
			ROUND(g, h, a, b, c, d, e, f, schedule2, 0xB5C0FBCF)
			ROUND(f, g, h, a, b, c, d, e, schedule3, 0xE9B5DBA5)
			ROUND(e, f, g, h, a, b, c, d, schedule4, 0x3956C25B)
			ROUND(d, e, f, g, h, a, b, c, schedule5, 0x59F111F1)
			ROUND(c, d, e, f, g, h, a, b, schedule6, 0x923F82A4)
			ROUND(b, c, d, e, f, g, h, a, schedule7, 0xAB1C5ED5)
			ROUND(a, b, c, d, e, f, g, h, schedule8, 0xD807AA98)
			ROUND(h, a, b, c, d, e, f, g, schedule9, 0x12835B01)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

			ALL_SCHEDULE32()

			ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
			ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
			ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
			ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
			ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
			ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
			ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
			ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
			ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
			ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)

			hash0 = 0x6A09E667 + a;
			hash1 = 0xBB67AE85 + b;
			hash2 = 0x3C6EF372 + c;
			hash3 = 0xA54FF53A + d;
			hash4 = 0x510E527F + e;
			hash5 = 0x9B05688C + f;
			hash6 = 0x1F83D9AB + g;
			hash7 = 0x5BE0CD19 + h;

			a = hash0;
			b = hash1;
			c = hash2;
			d = hash3;
			e = hash4;
			f = hash5;
			g = hash6;
			h = hash7;

			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 0, 0x428A2F98, 0)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 1, 0x71374491, 0)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 2, 0xB5C0FBCF, 0)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 3, 0xE9B5DBA5, 0)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 4, 0x3956C25B, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 5, 0x59F111F1, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 6, 0x923F82A4, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 7, 0xAB1C5ED5, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 8, 0xD807AA98, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 9, 0x12835B01, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 10, 0x243185BE, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 11, 0x550C7DC3, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 12, 0x72BE5D74, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 13, 0x80DEB1FE, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 14, 0x9BDC06A7, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 15, 0xC19BF174, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 16, 0xE49B69C1, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 17, 0xEFBE4786, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 18, 0x0FC19DC6, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 19, 0x240CA1CC, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 20, 0x2DE92C6F, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 21, 0x4A7484AA, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 22, 0x5CB0A9DC, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 23, 0x76F988DA, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 24, 0x983E5152, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 25, 0xA831C66D, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 26, 0xB00327C8, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 27, 0xBF597FC7, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 28, 0xC6E00BF3, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 29, 0xD5A79147, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 30, 0x06CA6351, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 31, 0x14292967, indexW)

			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 32, 0x27B70A85, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 33, 0x2E1B2138, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 34, 0x4D2C6DFC, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 35, 0x53380D13, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 36, 0x650A7354, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 37, 0x766A0ABB, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 38, 0x81C2C92E, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 39, 0x92722C85, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 40, 0xA2BFE8A1, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 41, 0xA81A664B, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 42, 0xC24B8B70, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 43, 0xC76C51A3, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 44, 0xD192E819, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 45, 0xD6990624, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 46, 0xF40E3585, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 47, 0x106AA070, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 48, 0x19A4C116, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 49, 0x1E376C08, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 50, 0x2748774C, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 51, 0x34B0BCB5, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 52, 0x391C0CB3, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 53, 0x4ED8AA4A, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 54, 0x5B9CCA4F, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 55, 0x682E6FF3, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 56, 0x748F82EE, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 57, 0x78A5636F, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 58, 0x84C87814, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 59, 0x8CC70208, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 60, 0x90BEFFFA, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 61, 0xA4506CEB, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 62, 0xBEF9A3F7, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 63, 0xC67178F2, indexW)

			hash0 += a;
			hash1 += b;
			hash2 += c;
			hash3 += d;
			hash4 += e;
			hash5 += f;
			hash6 += g;
			hash7 += h;

			indexW += (SINGLE_BLOCK_W_SIZE);
		}

		output_hash[(gIndex*INT_HASH_SIZE) + 0] = hash0;
		output_hash[(gIndex*INT_HASH_SIZE) + 1] = hash1;
		output_hash[(gIndex*INT_HASH_SIZE) + 2] = hash2;
		output_hash[(gIndex*INT_HASH_SIZE) + 3] = hash3;
		output_hash[(gIndex*INT_HASH_SIZE) + 4] = hash4;
		output_hash[(gIndex*INT_HASH_SIZE) + 5] = hash5;
		output_hash[(gIndex*INT_HASH_SIZE) + 6] = hash6;
		output_hash[(gIndex*INT_HASH_SIZE) + 7] = hash7;

		gIndex += get_global_size(0);
	}
}

// ----- Final AES
__kernel void opencl_bitlocker_attack_final(__global int *nPswPtr,
					__global int *found,
					__global unsigned char *d_vmk,
					__global int *output_hash,
					__global int *attack_type,
					__global unsigned int *vmkIV0, __global unsigned int *vmkIV4,
					__global unsigned int *vmkIV8, __global unsigned int *vmkIV12,
					__global unsigned int *macIV0, __global unsigned int *macIV4,
					__global unsigned int *macIV8, __global unsigned int *macIV12,
					__global unsigned int *cMacIV0, __global unsigned int *cMacIV4,
					__global unsigned int *cMacIV8, __global unsigned int *cMacIV12,
					__global unsigned char *mac
					)
{
	unsigned int schedule0, schedule1, schedule2, schedule3, schedule4, schedule5, schedule6, schedule7;
	unsigned int hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
	int gIndex = get_global_id(0);
	int nPsw = nPswPtr[0];
	int returnVal=-1;

	while (gIndex < nPsw) {

		hash0 = output_hash[(gIndex*INT_HASH_SIZE) + 0];
		hash1 = output_hash[(gIndex*INT_HASH_SIZE) + 1];
		hash2 = output_hash[(gIndex*INT_HASH_SIZE) + 2];
		hash3 = output_hash[(gIndex*INT_HASH_SIZE) + 3];
		hash4 = output_hash[(gIndex*INT_HASH_SIZE) + 4];
		hash5 = output_hash[(gIndex*INT_HASH_SIZE) + 5];
		hash6 = output_hash[(gIndex*INT_HASH_SIZE) + 6];
		hash7 = output_hash[(gIndex*INT_HASH_SIZE) + 7];

		if(attack_type[0] == BITLOCKER_HASH_UP_MAC || attack_type[0] == BITLOCKER_HASH_RP_MAC)
		{
			returnVal = enableMacVerification(
						vmkIV0[0], vmkIV4[0], vmkIV8[0], vmkIV12[0],
						macIV0[0], macIV4[0], macIV8[0], macIV12[0],
						cMacIV0[0], cMacIV4[0], cMacIV8[0], cMacIV12[0],
						hash0, hash1, hash2, hash3,
						hash4, hash5, hash6, hash7,
						d_vmk, mac, gIndex);

			if(returnVal >= 0)
			{
				found[0] = returnVal;
				break;
			}
		}
		else
		{
			schedule0=
	                (
	                        (unsigned int )(((unsigned int )(vmkIV0[0] & 0xff000000)) >> 24) |
	                        (unsigned int )((unsigned int )(vmkIV0[0] & 0x00ff0000) >> 8) |
	                        (unsigned int )((unsigned int )(vmkIV0[0] & 0x0000ff00) << 8) |
	                        (unsigned int )((unsigned int )(vmkIV0[0] & 0x000000ff) << 24)
	                ) ^ hash0;

			schedule1=
	                (
	                        (unsigned int )(((unsigned int )(vmkIV4[0] & 0xff000000)) >> 24) |
	                        (unsigned int )((unsigned int )(vmkIV4[0] & 0x00ff0000) >> 8) |
	                        (unsigned int )((unsigned int )(vmkIV4[0] & 0x0000ff00) << 8) |
	                        (unsigned int )((unsigned int )(vmkIV4[0] & 0x000000ff) << 24)
	                ) ^ hash1;

			schedule2=
	                (
	                        (unsigned int )(((unsigned int )(vmkIV8[0] & 0xff000000)) >> 24) |
	                        (unsigned int )((unsigned int )(vmkIV8[0] & 0x00ff0000) >> 8) |
	                        (unsigned int )((unsigned int )(vmkIV8[0] & 0x0000ff00) << 8) |
	                        (unsigned int )((unsigned int )(vmkIV8[0] & 0x000000ff) << 24)
	                ) ^ hash2;

			schedule3=
	                (
	                        (unsigned int )(((unsigned int )(vmkIV12[0] & 0xff000000)) >> 24) |
	                        (unsigned int )((unsigned int )(vmkIV12[0] & 0x00ff0000) >> 8) |
	                        (unsigned int )((unsigned int )(vmkIV12[0] & 0x0000ff00) << 8) |
	                        (unsigned int )((unsigned int )(vmkIV12[0] & 0x000000ff) << 24)
	                ) ^ hash3;

			schedule4 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule0 >> 24],
			                            TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]),
			                TS3[schedule3 & 0xFF], hash4);
			schedule5 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule1 >> 24],
			                            TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]),
			                TS3[schedule0 & 0xFF], hash5);
			schedule6 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule2 >> 24],
			                            TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]),
			                TS3[schedule1 & 0xFF], hash6);
			schedule7 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule3 >> 24],
			                            TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]),
			                TS3[schedule2 & 0xFF], hash7);

			hash0 ^=
			    OPT3_XOR(OPT3_XOR((TS2[(hash7 >> 24)] & 0x000000FF),
			                            (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000),
			                            (TS0[(hash7 >> 8) & 0xFF] & 0x00FF0000)),
			                (TS1[(hash7) & 0xFF] & 0x0000FF00), 0x01000000);
			hash1 ^= hash0;
			hash2 ^= hash1;
			hash3 ^= hash2;

			schedule0 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule4 >> 24],
			                            TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]),
			                TS3[schedule7 & 0xFF], hash0);
			schedule1 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule5 >> 24],
			                            TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]),
			                TS3[schedule4 & 0xFF], hash1);
			schedule2 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule6 >> 24],
			                            TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]),
			                TS3[schedule5 & 0xFF], hash2);
			schedule3 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule7 >> 24],
			                            TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]),
			                TS3[schedule6 & 0xFF], hash3);

			hash4 ^= (TS3[(hash3 >> 24)] & 0xFF000000) ^
			         (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash3 >> 8) & 0xFF] & 0x0000FF00) ^
			         (TS2[(hash3) & 0xFF] & 0x000000FF);
			hash5 ^= hash4;
			hash6 ^= hash5;
			hash7 ^= hash6;

			schedule4 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule0 >> 24],
			                            TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]),
			                TS3[schedule3 & 0xFF], hash4);
			schedule5 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule1 >> 24],
			                            TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]),
			                TS3[schedule0 & 0xFF], hash5);
			schedule6 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule2 >> 24],
			                            TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]),
			                TS3[schedule1 & 0xFF], hash6);
			schedule7 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule3 >> 24],
			                            TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]),
			                TS3[schedule2 & 0xFF], hash7);

			hash0 ^= (TS2[(hash7 >> 24)] & 0x000000FF) ^
			         (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
			         (TS0[(hash7 >> 8) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash7) & 0xFF] & 0x0000FF00) ^ 0x02000000;
			hash1 ^= hash0;
			hash2 ^= hash1;
			hash3 ^= hash2;

			schedule0 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule4 >> 24],
			                            TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]),
			                TS3[schedule7 & 0xFF], hash0);
			schedule1 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule5 >> 24],
			                            TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]),
			                TS3[schedule4 & 0xFF], hash1);
			schedule2 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule6 >> 24],
			                            TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]),
			                TS3[schedule5 & 0xFF], hash2);
			schedule3 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule7 >> 24],
			                            TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]),
			                TS3[schedule6 & 0xFF], hash3);

			hash4 ^= (TS3[(hash3 >> 24)] & 0xFF000000) ^
			         (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash3 >> 8) & 0xFF] & 0x0000FF00) ^
			         (TS2[(hash3) & 0xFF] & 0x000000FF);
			hash5 ^= hash4;
			hash6 ^= hash5;
			hash7 ^= hash6;

			schedule4 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule0 >> 24],
			                            TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]),
			                TS3[schedule3 & 0xFF], hash4);
			schedule5 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule1 >> 24],
			                            TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]),
			                TS3[schedule0 & 0xFF], hash5);
			schedule6 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule2 >> 24],
			                            TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]),
			                TS3[schedule1 & 0xFF], hash6);
			schedule7 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule3 >> 24],
			                            TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]),
			                TS3[schedule2 & 0xFF], hash7);


			hash0 ^= (TS2[(hash7 >> 24)] & 0x000000FF) ^
			         (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
			         (TS0[(hash7 >> 8) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash7) & 0xFF] & 0x0000FF00) ^ 0x04000000;
			hash1 ^= hash0;
			hash2 ^= hash1;
			hash3 ^= hash2;

			schedule0 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule4 >> 24],
			                            TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]),
			                TS3[schedule7 & 0xFF], hash0);
			schedule1 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule5 >> 24],
			                            TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]),
			                TS3[schedule4 & 0xFF], hash1);
			schedule2 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule6 >> 24],
			                            TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]),
			                TS3[schedule5 & 0xFF], hash2);
			schedule3 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule7 >> 24],
			                            TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]),
			                TS3[schedule6 & 0xFF], hash3);


			hash4 ^= (TS3[(hash3 >> 24)] & 0xFF000000) ^
			         (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash3 >> 8) & 0xFF] & 0x0000FF00) ^
			         (TS2[(hash3) & 0xFF] & 0x000000FF);
			hash5 ^= hash4;
			hash6 ^= hash5;
			hash7 ^= hash6;

			schedule4 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule0 >> 24],
			                            TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]),
			                TS3[schedule3 & 0xFF], hash4);
			schedule5 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule1 >> 24],
			                            TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]),
			                TS3[schedule0 & 0xFF], hash5);
			schedule6 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule2 >> 24],
			                            TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]),
			                TS3[schedule1 & 0xFF], hash6);
			schedule7 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule3 >> 24],
			                            TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]),
			                TS3[schedule2 & 0xFF], hash7);

			hash0 ^= (TS2[(hash7 >> 24)] & 0x000000FF) ^
			         (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
			         (TS0[(hash7 >> 8) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash7) & 0xFF] & 0x0000FF00) ^ 0x08000000;
			hash1 ^= hash0;
			hash2 ^= hash1;
			hash3 ^= hash2;

			schedule0 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule4 >> 24],
			                            TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]),
			                TS3[schedule7 & 0xFF], hash0);
			schedule1 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule5 >> 24],
			                            TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]),
			                TS3[schedule4 & 0xFF], hash1);
			schedule2 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule6 >> 24],
			                            TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]),
			                TS3[schedule5 & 0xFF], hash2);
			schedule3 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule7 >> 24],
			                            TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]),
			                TS3[schedule6 & 0xFF], hash3);

			hash4 ^= (TS3[(hash3 >> 24)] & 0xFF000000) ^
			         (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash3 >> 8) & 0xFF] & 0x0000FF00) ^
			         (TS2[(hash3) & 0xFF] & 0x000000FF);
			hash5 ^= hash4;
			hash6 ^= hash5;
			hash7 ^= hash6;

			schedule4 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule0 >> 24],
			                            TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]),
			                TS3[schedule3 & 0xFF], hash4);
			schedule5 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule1 >> 24],
			                            TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]),
			                TS3[schedule0 & 0xFF], hash5);
			schedule6 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule2 >> 24],
			                            TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]),
			                TS3[schedule1 & 0xFF], hash6);
			schedule7 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule3 >> 24],
			                            TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]),
			                TS3[schedule2 & 0xFF], hash7);

			hash0 ^= (TS2[(hash7 >> 24)] & 0x000000FF) ^
			         (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
			         (TS0[(hash7 >> 8) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash7) & 0xFF] & 0x0000FF00) ^ 0x10000000;
			hash1 ^= hash0;
			hash2 ^= hash1;
			hash3 ^= hash2;

			schedule0 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule4 >> 24],
			                            TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]),
			                TS3[schedule7 & 0xFF], hash0);
			schedule1 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule5 >> 24],
			                            TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]),
			                TS3[schedule4 & 0xFF], hash1);
			schedule2 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule6 >> 24],
			                            TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]),
			                TS3[schedule5 & 0xFF], hash2);
			schedule3 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule7 >> 24],
			                            TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]),
			                TS3[schedule6 & 0xFF], hash3);

			hash4 ^= (TS3[(hash3 >> 24)] & 0xFF000000) ^
			         (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash3 >> 8) & 0xFF] & 0x0000FF00) ^
			         (TS2[(hash3) & 0xFF] & 0x000000FF);
			hash5 ^= hash4;
			hash6 ^= hash5;
			hash7 ^= hash6;

			schedule4 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule0 >> 24],
			                            TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]),
			                TS3[schedule3 & 0xFF], hash4);
			schedule5 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule1 >> 24],
			                            TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]),
			                TS3[schedule0 & 0xFF], hash5);
			schedule6 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule2 >> 24],
			                            TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]),
			                TS3[schedule1 & 0xFF], hash6);
			schedule7 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule3 >> 24],
			                            TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]),
			                TS3[schedule2 & 0xFF], hash7);

			hash0 ^= (TS2[(hash7 >> 24)] & 0x000000FF) ^
			         (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
			         (TS0[(hash7 >> 8) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash7) & 0xFF] & 0x0000FF00) ^ 0x20000000;
			hash1 ^= hash0;
			hash2 ^= hash1;
			hash3 ^= hash2;

			schedule0 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule4 >> 24],
			                            TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]),
			                TS3[schedule7 & 0xFF], hash0);
			schedule1 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule5 >> 24],
			                            TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]),
			                TS3[schedule4 & 0xFF], hash1);
			schedule2 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule6 >> 24],
			                            TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]),
			                TS3[schedule5 & 0xFF], hash2);
			schedule3 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule7 >> 24],
			                            TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]),
			                TS3[schedule6 & 0xFF], hash3);

			hash4 ^= (TS3[(hash3 >> 24)] & 0xFF000000) ^
			         (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash3 >> 8) & 0xFF] & 0x0000FF00) ^
			         (TS2[(hash3) & 0xFF] & 0x000000FF);
			hash5 ^= hash4;
			hash6 ^= hash5;
			hash7 ^= hash6;

			schedule4 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule0 >> 24],
			                            TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]),
			                TS3[schedule3 & 0xFF], hash4);
			schedule5 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule1 >> 24],
			                            TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]),
			                TS3[schedule0 & 0xFF], hash5);
			schedule6 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule2 >> 24],
			                            TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]),
			                TS3[schedule1 & 0xFF], hash6);
			schedule7 =
			    OPT3_XOR(OPT3_XOR(TS0[schedule3 >> 24],
			                            TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]),
			                TS3[schedule2 & 0xFF], hash7);

			hash0 ^= (TS2[(hash7 >> 24)] & 0x000000FF) ^
			         (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
			         (TS0[(hash7 >> 8) & 0xFF] & 0x00FF0000) ^
			         (TS1[(hash7) & 0xFF] & 0x0000FF00) ^ 0x40000000;
			hash1 ^= hash0;
			hash2 ^= hash1;
			hash3 ^= hash2;

			schedule0 = (TS2[(schedule4 >> 24)] & 0xFF000000) ^
			            (TS3[(schedule5 >> 16) & 0xFF] & 0x00FF0000) ^
			            (TS0[(schedule6 >> 8) & 0xFF] & 0x0000FF00) ^
			            (TS1[(schedule7) & 0xFF] & 0x000000FF) ^ hash0;

			schedule1 = (TS2[(schedule5 >> 24)] & 0xFF000000) ^
			            (TS3[(schedule6 >> 16) & 0xFF] & 0x00FF0000) ^
			            (TS0[(schedule7 >> 8) & 0xFF] & 0x0000FF00) ^
			            (TS1[(schedule4) & 0xFF] & 0x000000FF) ^ hash1;

			schedule2 = (TS2[(schedule6 >> 24)] & 0xFF000000) ^
			            (TS3[(schedule7 >> 16) & 0xFF] & 0x00FF0000) ^
			            (TS0[(schedule4 >> 8) & 0xFF] & 0x0000FF00) ^
			            (TS1[(schedule5) & 0xFF] & 0x000000FF) ^ hash2;

			schedule3 = (TS2[(schedule7 >> 24)] & 0xFF000000) ^
			            (TS3[(schedule4 >> 16) & 0xFF] & 0x00FF0000) ^
			            (TS0[(schedule5 >> 8) & 0xFF] & 0x0000FF00) ^
			            (TS1[(schedule6) & 0xFF] & 0x000000FF) ^ hash3;

			schedule4 =
			    (unsigned int)(((unsigned int)(schedule0 & 0xff000000)) >> 24) |
			    (unsigned int)((unsigned int)(schedule0 & 0x00ff0000) >> 8) |
			    (unsigned int)((unsigned int)(schedule0 & 0x0000ff00) << 8) |
			    (unsigned int)((unsigned int)(schedule0 & 0x000000ff) << 24);

			schedule5 =
			    (unsigned int)(((unsigned int)(schedule1 & 0xff000000)) >> 24) |
			    (unsigned int)((unsigned int)(schedule1 & 0x00ff0000) >> 8) |
			    (unsigned int)((unsigned int)(schedule1 & 0x0000ff00) << 8) |
			    (unsigned int)((unsigned int)(schedule1 & 0x000000ff) << 24);

			schedule6 =
			    (unsigned int)(((unsigned int)(schedule2 & 0xff000000)) >> 24) |
			    (unsigned int)((unsigned int)(schedule2 & 0x00ff0000) >> 8) |
			    (unsigned int)((unsigned int)(schedule2 & 0x0000ff00) << 8) |
			    (unsigned int)((unsigned int)(schedule2 & 0x000000ff) << 24);

			if (
				((d_vmk[0] ^ ((unsigned char)schedule4)) == 0x2c) &&
				((d_vmk[1] ^ ((unsigned char)(schedule4 >> 8))) == 0x00) &&
				((d_vmk[4] ^ ((unsigned char) schedule5)) == 0x01) &&
				((d_vmk[5] ^ ((unsigned char) (schedule5 >> 8))) == 0x00) &&
				((d_vmk[8] ^ ((unsigned char) schedule6)) <= 0x05) &&
				((d_vmk[9] ^ ((unsigned char)(schedule6 >> 8))) == 0x20)
			   )
			{
				found[0] = gIndex;
				break;
			}
		}
		gIndex += get_global_size(0);
	}
}
