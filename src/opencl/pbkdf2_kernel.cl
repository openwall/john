/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/

#define ITERATIONS                  10240
 
#define INIT_MD4_A                  0x67452301
#define INIT_MD4_B                  0xefcdab89
#define INIT_MD4_C                  0x98badcfe
#define INIT_MD4_D                  0x10325476
 
#define SQRT_2                      0x5a827999
#define SQRT_3                      0x6ed9eba1
 
#define SHA1_DIGEST_LENGTH          20
 
#define INIT_SHA1_A                 0x67452301
#define INIT_SHA1_B                 0xEFCDAB89
#define INIT_SHA1_C                 0x98BADCFE
#define INIT_SHA1_D                 0x10325476
#define INIT_SHA1_E                 0xC3D2E1F0
 
#ifndef GET_WORD_32_BE
#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (unsigned long) ((b)[(i) ]&0x000000ff) <<24 )\
        | ( (unsigned long) ((b)[(i) ]&0x0000ff00) << 8 )\
        | ( (unsigned long) ((b)[(i) ]&0x00ff0000) >> 8 )\
        | ( (unsigned long) ((b)[(i) ]&0xff000000) >>24 );\
}
#endif
 
#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = ((unsigned char) ( (n) >> 24 ))|((unsigned char) ( (n) >> 16 ))<<8|((unsigned char) ( (n) >>  8 ))<<16|((unsigned char) ( (n) ))<<24;       \
}
#endif
 
#define S(x,n) ((x << n) | ((x ) >> (32 - n)))
 
#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)
 
#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}
__kernel void PBKDF2(const __global unsigned int *pass_global, const __global unsigned int *salt, int usrlen, __global unsigned int *out_global)
{   int id=get_local_id(0);
    __local unsigned int salt_local[32];
    if(id==0)  for(id=0;id<=usrlen/2;++id)     salt_local[id]=salt[id];
    barrier(CLK_LOCAL_MEM_FENCE);
    id=get_global_id(0);
    unsigned int temp_char[SHA1_DIGEST_LENGTH/4],pass[4],out[4];
    unsigned  int buf[16]={0};
    unsigned int i,j;
    unsigned int temp, W[16];
    unsigned int A, B, C, D, E, state[5];
    unsigned int ipad[16];
    unsigned int opad[16];
    for(i=4*id,j=0;i<4*id+4;i++,j++)
     { pass[j]=pass_global[i];
       out[j]=out_global[i];
     }
    
   if(usrlen%2==1)
    {   for(i=0;i<=usrlen/2;i++)
            buf[i]=salt_local[i];
                   buf[(usrlen/2)+1] = 0x01<<8;
    }
    else   
    {  for(i=0;i<usrlen/2;i++)
            buf[i]=salt_local[i];
     buf[usrlen/2 ] = 0x01<<24;
    }
     
 ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
   for(i=0;i<16;i++)
    { ipad[i]=0x36363636;
      opad[i]=0x5C5C5C5C;               
    }

       // step 1: append zeros to the end of K to create a B Byte string
   
    if(usrlen%2==1)
    buf[usrlen/2 + 1] = 0x80<<16|buf[usrlen/2 +1];
    else
    buf[usrlen/2+ 1]=0x80|buf[usrlen/2 +1];
  
    PUT_WORD_32_BE((64 + usrlen*2 +4) << 3, buf, 60/4);

    // step 2: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with ipad
    // step 5: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with opad    
 
   for(i = 0; i < 4; i++)
    {
        ipad[i] = ipad[i] ^ pass[i];
        opad[i] = opad[i] ^ pass[i];
    }
 
    // step 3: append the stream of data 'text' to the B byte sting resulting from step 2
    // first part of stream (64 bytes) is ipad, second part of stream (64 bytes) is buf
    // step 4: apply H to the stream (ipad & buf) generated in step 3
   
    GET_WORD_32_BE(W[ 0], ipad,  0);
    GET_WORD_32_BE(W[ 1], ipad,  1);
    GET_WORD_32_BE(W[ 2], ipad,  2);
    GET_WORD_32_BE(W[ 3], ipad, 3);
    GET_WORD_32_BE(W[ 4], ipad, 4);
    GET_WORD_32_BE(W[ 5], ipad, 5);
    GET_WORD_32_BE(W[ 6], ipad, 6);
    GET_WORD_32_BE(W[ 7], ipad, 7);
    GET_WORD_32_BE(W[ 8], ipad, 8);
    GET_WORD_32_BE(W[ 9], ipad, 9);
    GET_WORD_32_BE(W[10], ipad, 10);
    GET_WORD_32_BE(W[11], ipad, 11);
    GET_WORD_32_BE(W[12], ipad, 12);
    GET_WORD_32_BE(W[13], ipad, 13);
    GET_WORD_32_BE(W[14], ipad, 14);
    GET_WORD_32_BE(W[15], ipad, 15);
   
 
    A = INIT_SHA1_A;
    B = INIT_SHA1_B;
    C = INIT_SHA1_C;
    D = INIT_SHA1_D;
    E = INIT_SHA1_E;
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
    
  
#undef K
#undef F
 
    A += INIT_SHA1_A;
    B += INIT_SHA1_B;
    C += INIT_SHA1_C;
    D += INIT_SHA1_D;
    E += INIT_SHA1_E;
 
    state[0] = A;
    state[1] = B;
    state[2] = C;
    state[3] = D;
    state[4] = E;
 
    // process buf (2nd part of stream)
    GET_WORD_32_BE(W[ 0], buf,  0);
    GET_WORD_32_BE(W[ 1], buf,  1);
    GET_WORD_32_BE(W[ 2], buf,  2);
    GET_WORD_32_BE(W[ 3], buf, 3);
    GET_WORD_32_BE(W[ 4], buf, 4);
    GET_WORD_32_BE(W[ 5], buf, 5);
    GET_WORD_32_BE(W[ 6], buf, 6);
    GET_WORD_32_BE(W[ 7], buf, 7);
    GET_WORD_32_BE(W[ 8], buf, 8);
    GET_WORD_32_BE(W[ 9], buf, 9);
    GET_WORD_32_BE(W[10], buf, 10);
    GET_WORD_32_BE(W[11], buf, 11);
    GET_WORD_32_BE(W[12], buf, 12);
    GET_WORD_32_BE(W[13], buf, 13);
    GET_WORD_32_BE(W[14], buf, 14);
    GET_WORD_32_BE(W[15], buf, 15);
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
  
 
#undef K
#undef F
 
    A += state[0];
    B += state[1];
    C += state[2];
    D += state[3];
    E += state[4];
 
    PUT_WORD_32_BE(A, buf,  0);
    PUT_WORD_32_BE(B, buf,  1);
    PUT_WORD_32_BE(C, buf,  2);
    PUT_WORD_32_BE(D, buf,  3);
    PUT_WORD_32_BE(E, buf,  4);
 
    buf[5] = 0x80|(buf[5]& 0xffffff00);
 
    PUT_WORD_32_BE(0x2A0, buf, 15);
  
    // step 6: append the stream of data 'text' to the B byte sting resulting from step 2
    // first part of stream (64 bytes) is opad, second part of stream (64 bytes) is the H result from step 4
     // step 7: apply H to the stream (opad & buf) generated in step 6 and output the result
   
    GET_WORD_32_BE(W[ 0], opad,  0);
    GET_WORD_32_BE(W[ 1], opad,  1);
    GET_WORD_32_BE(W[ 2], opad,  2);
    GET_WORD_32_BE(W[ 3], opad, 3);
    GET_WORD_32_BE(W[ 4], opad, 4);
    GET_WORD_32_BE(W[ 5], opad, 5);
    GET_WORD_32_BE(W[ 6], opad, 6);
    GET_WORD_32_BE(W[ 7], opad, 7);
    GET_WORD_32_BE(W[ 8], opad, 8);
    GET_WORD_32_BE(W[ 9], opad, 9);
    GET_WORD_32_BE(W[10], opad, 10);
    GET_WORD_32_BE(W[11], opad, 11);
    GET_WORD_32_BE(W[12], opad, 12);
    GET_WORD_32_BE(W[13], opad, 13);
    GET_WORD_32_BE(W[14], opad, 14);
    GET_WORD_32_BE(W[15], opad, 15);
   
  
    A = INIT_SHA1_A;
    B = INIT_SHA1_B;
    C = INIT_SHA1_C;
    D = INIT_SHA1_D;
    E = INIT_SHA1_E;
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
    
  
 
#undef K
#undef F
 
    A += INIT_SHA1_A;
    B += INIT_SHA1_B;
    C += INIT_SHA1_C;
    D += INIT_SHA1_D;
    E += INIT_SHA1_E;
 
    // store state for 2nd part
    state[0] = A;
    state[1] = B;
    state[2] = C;
    state[3] = D;
    state[4] = E;
 
    GET_WORD_32_BE(W[ 0], buf,  0);
    GET_WORD_32_BE(W[ 1], buf,  1);
    GET_WORD_32_BE(W[ 2], buf,  2);
    GET_WORD_32_BE(W[ 3], buf, 3);
    GET_WORD_32_BE(W[ 4], buf, 4);
    GET_WORD_32_BE(W[ 5], buf, 5);
    GET_WORD_32_BE(W[ 6], buf, 6);
    GET_WORD_32_BE(W[ 7], buf, 7);
    GET_WORD_32_BE(W[ 8], buf, 8);
    GET_WORD_32_BE(W[ 9], buf, 9);
    GET_WORD_32_BE(W[10], buf, 10);
    GET_WORD_32_BE(W[11], buf, 11);
    GET_WORD_32_BE(W[12], buf, 12);
    GET_WORD_32_BE(W[13], buf, 13);
    GET_WORD_32_BE(W[14], buf, 14);
    GET_WORD_32_BE(W[15], buf, 15);
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
 
#undef K
#undef F
 
    A += state[0];
    B += state[1];
    C += state[2];
    D += state[3];
    E += state[4];
 
    PUT_WORD_32_BE(A, temp_char,  0);
    PUT_WORD_32_BE(B, temp_char,  1);
    PUT_WORD_32_BE(C, temp_char,  2);
    PUT_WORD_32_BE(D, temp_char,  3);
    PUT_WORD_32_BE(E, temp_char,  4);
    
    
 //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
      
      for(j=0;j<4;++j)
      out[j]=temp_char[j];
    
 
   for (i = 1; i < ITERATIONS; i++)
    {  
 ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        for(j=0;j<16;j++)
       { ipad[j]=0x36363636;
         opad[j]=0x5C5C5C5C;
         buf[j]=0;               
       }
    
 // step 1: append zeros to the end of K to create a B Byte string
  
     for(j=0;j<SHA1_DIGEST_LENGTH/4;j++)
        buf[j]=temp_char[j];
        
    buf[SHA1_DIGEST_LENGTH/4] = 0x80| buf[SHA1_DIGEST_LENGTH/4];
    PUT_WORD_32_BE((64 + SHA1_DIGEST_LENGTH) << 3, buf, 15);
 
    // step 2: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with ipad
    // step 5: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with opad    
   
  for(j = 0; j < 4; j++)
    {
        ipad[j] = ipad[j] ^ pass[j];
        opad[j] = opad[j] ^ pass[j];
    }
      
    // step 3: append the stream of data 'text' to the B byte sting resulting from step 2
    // first part of stream (64 bytes) is ipad, second part of stream (64 bytes) is buf
    // step 4: apply H to the stream (ipad & buf) generated in step 3
   
    GET_WORD_32_BE(W[ 0], ipad,  0);
    GET_WORD_32_BE(W[ 1], ipad,  1);
    GET_WORD_32_BE(W[ 2], ipad,  2);
    GET_WORD_32_BE(W[ 3], ipad,  3);
    GET_WORD_32_BE(W[ 4], ipad,  4);
    GET_WORD_32_BE(W[ 5], ipad,  5);
    GET_WORD_32_BE(W[ 6], ipad,  6);
    GET_WORD_32_BE(W[ 7], ipad,  7);
    GET_WORD_32_BE(W[ 8], ipad,  8);
    GET_WORD_32_BE(W[ 9], ipad,  9);
    GET_WORD_32_BE(W[10], ipad, 10);
    GET_WORD_32_BE(W[11], ipad, 11);
    GET_WORD_32_BE(W[12], ipad, 12);
    GET_WORD_32_BE(W[13], ipad, 13);
    GET_WORD_32_BE(W[14], ipad, 14);
    GET_WORD_32_BE(W[15], ipad, 15);
 
    A = INIT_SHA1_A;
    B = INIT_SHA1_B;
    C = INIT_SHA1_C;
    D = INIT_SHA1_D;
    E = INIT_SHA1_E;
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
 
#undef K
#undef F
 
    A += INIT_SHA1_A;
    B += INIT_SHA1_B;
    C += INIT_SHA1_C;
    D += INIT_SHA1_D;
    E += INIT_SHA1_E;
 
    state[0] = A;
    state[1] = B;
    state[2] = C;
    state[3] = D;
    state[4] = E;
 
    // process buf (2nd part of stream)
    GET_WORD_32_BE(W[ 0], buf,  0);
    GET_WORD_32_BE(W[ 1], buf,  1);
    GET_WORD_32_BE(W[ 2], buf,  2);
    GET_WORD_32_BE(W[ 3], buf, 3);
    GET_WORD_32_BE(W[ 4], buf, 4);
    GET_WORD_32_BE(W[ 5], buf, 5);
    GET_WORD_32_BE(W[ 6], buf, 6);
    GET_WORD_32_BE(W[ 7], buf, 7);
    GET_WORD_32_BE(W[ 8], buf, 8);
    GET_WORD_32_BE(W[ 9], buf, 9);
    GET_WORD_32_BE(W[10], buf, 10);
    GET_WORD_32_BE(W[11], buf, 11);
    GET_WORD_32_BE(W[12], buf, 12);
    GET_WORD_32_BE(W[13], buf, 13);
    GET_WORD_32_BE(W[14], buf, 14);
    GET_WORD_32_BE(W[15], buf, 15);
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
 
#undef K
#undef F
 
    A += state[0];
    B += state[1];
    C += state[2];
    D += state[3];
    E += state[4];
 
    PUT_WORD_32_BE(A, buf,  0);
    PUT_WORD_32_BE(B, buf,  1);
    PUT_WORD_32_BE(C, buf,  2);
    PUT_WORD_32_BE(D, buf,  3);
    PUT_WORD_32_BE(E, buf,  4);
 
   buf[5] = 0x80|(buf[5]& 0xffffff00);
    PUT_WORD_32_BE(0x2A0, buf, 15);
 
    // step 6: append the stream of data 'text' to the B byte sting resulting from step 2
    // first part of stream (64 bytes) is opad, second part of stream (64 bytes) is the H result from step 4
 
    // step 7: apply H to the stream (opad & buf) generated in step 6 and output the result
    GET_WORD_32_BE(W[ 0], opad,  0);
    GET_WORD_32_BE(W[ 1], opad,  1);
    GET_WORD_32_BE(W[ 2], opad,  2);
    GET_WORD_32_BE(W[ 3], opad, 3);
    GET_WORD_32_BE(W[ 4], opad, 4);
    GET_WORD_32_BE(W[ 5], opad, 5);
    GET_WORD_32_BE(W[ 6], opad, 6);
    GET_WORD_32_BE(W[ 7], opad, 7);
    GET_WORD_32_BE(W[ 8], opad, 8);
    GET_WORD_32_BE(W[ 9], opad, 9);
    GET_WORD_32_BE(W[10], opad, 10);
    GET_WORD_32_BE(W[11], opad, 11);
    GET_WORD_32_BE(W[12], opad, 12);
    GET_WORD_32_BE(W[13], opad, 13);
    GET_WORD_32_BE(W[14], opad, 14);
    GET_WORD_32_BE(W[15], opad, 15);
 
    A = INIT_SHA1_A;
    B = INIT_SHA1_B;
    C = INIT_SHA1_C;
    D = INIT_SHA1_D;
    E = INIT_SHA1_E;
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
 
#undef K
#undef F
 
    A += INIT_SHA1_A;
    B += INIT_SHA1_B;
    C += INIT_SHA1_C;
    D += INIT_SHA1_D;
    E += INIT_SHA1_E;
 
    // store state for 2nd part
    state[0] = A;
    state[1] = B;
    state[2] = C;
    state[3] = D;
    state[4] = E;
 
    GET_WORD_32_BE(W[ 0], buf,  0);
    GET_WORD_32_BE(W[ 1], buf,  1);
    GET_WORD_32_BE(W[ 2], buf,  2);
    GET_WORD_32_BE(W[ 3], buf, 3);
    GET_WORD_32_BE(W[ 4], buf, 4);
    GET_WORD_32_BE(W[ 5], buf, 5);
    GET_WORD_32_BE(W[ 6], buf, 6);
    GET_WORD_32_BE(W[ 7], buf, 7);
    GET_WORD_32_BE(W[ 8], buf, 8);
    GET_WORD_32_BE(W[ 9], buf, 9);
    GET_WORD_32_BE(W[10], buf, 10);
    GET_WORD_32_BE(W[11], buf, 11);
    GET_WORD_32_BE(W[12], buf, 12);
    GET_WORD_32_BE(W[13], buf, 13);
    GET_WORD_32_BE(W[14], buf, 14);
    GET_WORD_32_BE(W[15], buf, 15);
 
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
 
    P(A, B, C, D, E, W[0] );
    P(E, A, B, C, D, W[1] );
    P(D, E, A, B, C, W[2] );
    P(C, D, E, A, B, W[3] );
    P(B, C, D, E, A, W[4] );
    P(A, B, C, D, E, W[5] );
    P(E, A, B, C, D, W[6] );
    P(D, E, A, B, C, W[7] );
    P(C, D, E, A, B, W[8] );
    P(B, C, D, E, A, W[9] );
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
 
    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));
 
#undef K
#undef F
 
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
 
    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));
 
#undef K
#undef F
 
#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
 
    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));
 
#undef K
#undef F
 
    A += state[0];
    B += state[1];
    C += state[2];
    D += state[3];
    E += state[4];
 
    PUT_WORD_32_BE(A, temp_char,  0);
    PUT_WORD_32_BE(B, temp_char,  1);
    PUT_WORD_32_BE(C, temp_char,  2);
    PUT_WORD_32_BE(D, temp_char, 3);
    PUT_WORD_32_BE(E, temp_char, 4);
       

 /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
        out[ 0] ^= temp_char[0];
        out[ 1] ^= temp_char[1];
        out[ 2] ^= temp_char[2];
        out[ 3] ^= temp_char[3];
    
    }

for(i=4*id,j=0;i<4*id+4;i++,j++)
     { 
       out_global[i]=out[j];
     } 

}



 
