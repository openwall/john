/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall.net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#define PLAINTEXT_LENGTH        15
#define SALT_SIZE               8
//#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable

typedef struct {
        uchar v[PLAINTEXT_LENGTH];
        uchar length;
} phpass_password;

typedef struct {
        uint v[4];
} phpass_hash;


#define H(x, y, z)              ((x) ^ (y) ^ (z))
#define I(x, y, z)              ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, s)       rotate(x,(uint)s)
#define F(x, y, z) bitselect((z), (y), (x))
#define G(x, y, z) bitselect((y), (x), (z))


#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT ((a), (s)) + (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT ((a), (s)) + (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT ((a), (s)) + (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT ((a), (s)) + (b); \
  }

#define S11                             7
#define S12                             12
#define S13                             17
#define S14                             22
#define S21                             5
#define S22                             9
#define S23                             14
#define S24                             20
#define S31                             4
#define S32                             11
#define S33                             16
#define S34                             23
#define S41                             6
#define S42                             10
#define S43                             15
#define S44                             21

#define AC1                             (uint8) 0xd76aa477
#define AC2pCd                          (uint8) 0xf8fa0bcc
#define AC3pCc                          (uint8) 0xbcdb4dd9
#define AC4pCb                          (uint8) 0xb18b7a77
#define MASK1                           (uint8) 0x77777777



inline void md5(uint8 len,__private uint8 * internal_ret,__private uint8 * x)
{
        uint8 x14 = len << 3;

        uint8 a;
        uint8 b = (uint8)0xefcdab89;
        uint8 c = (uint8)0x98badcfe;
        uint8 d = (uint8)0x10325476;

        a = AC1 + x[0];
        a = ROTATE_LEFT(a, S11);
        a += b;                 /* 1 */
        d = (c ^ (a & MASK1)) + x[1] + AC2pCd;
        d = ROTATE_LEFT(d, S12);
        d += a;                 /* 2 */
        c = F(d, a, b) + x[2] + AC3pCc;
        c = ROTATE_LEFT(c, S13);
        c += d;                 /* 3 */
        b = F(c, d, a) + x[3] + AC4pCb;
        b = ROTATE_LEFT(b, S14);
        b += c;
        FF(a, b, c, d, x[4], S11,(uint8) 0xf57c0faf);
        FF(d, a, b, c, x[5], S12,(uint8) 0x4787c62a);
        FF(c, d, a, b, x[6], S13,(uint8) 0xa8304613);
        FF(b, c, d, a, x[7], S14,(uint8) 0xfd469501);
        FF(a, b, c, d, 0, S11,(uint8) 0x698098d8);
        FF(d, a, b, c, 0, S12,(uint8) 0x8b44f7af);
        FF(c, d, a, b, 0, S13,(uint8) 0xffff5bb1);
        FF(b, c, d, a, 0, S14,(uint8) 0x895cd7be);
        FF(a, b, c, d, 0, S11,(uint8) 0x6b901122);
        FF(d, a, b, c, 0, S12,(uint8) 0xfd987193);
        FF(c, d, a, b, x14, S13,(uint8) 0xa679438e);
        FF(b, c, d, a, 0, S14,(uint8) 0x49b40821);

        GG(a, b, c, d, x[1], S21,(uint8) 0xf61e2562);
        GG(d, a, b, c, x[6], S22,(uint8) 0xc040b340);
        GG(c, d, a, b, 0, S23,(uint8) 0x265e5a51);
        GG(b, c, d, a, x[0], S24,(uint8) 0xe9b6c7aa);
        GG(a, b, c, d, x[5], S21,(uint8) 0xd62f105d);
        GG(d, a, b, c, 0, S22,(uint8) 0x2441453);
        GG(c, d, a, b, 0, S23,(uint8) 0xd8a1e681);
        GG(b, c, d, a, x[4], S24,(uint8) 0xe7d3fbc8);
        GG(a, b, c, d, 0, S21,(uint8) 0x21e1cde6);
        GG(d, a, b, c, x14, S22,(uint8) 0xc33707d6);
        GG(c, d, a, b, x[3], S23,(uint8) 0xf4d50d87);
        GG(b, c, d, a, 0, S24,(uint8) 0x455a14ed);
        GG(a, b, c, d, 0, S21,(uint8) 0xa9e3e905);
        GG(d, a, b, c, x[2], S22,(uint8) 0xfcefa3f8);
        GG(c, d, a, b, x[7], S23,(uint8) 0x676f02d9);
        GG(b, c, d, a, 0, S24,(uint8) 0x8d2a4c8a);

        HH(a, b, c, d, x[5], S31,(uint8) 0xfffa3942);
        HH(d, a, b, c, 0, S32,(uint8) 0x8771f681);
        HH(c, d, a, b, 0, S33,(uint8) 0x6d9d6122);
        HH(b, c, d, a, x14, S34,(uint8) 0xfde5380c);
        HH(a, b, c, d, x[1], S31,(uint8) 0xa4beea44);
        HH(d, a, b, c, x[4], S32,(uint8) 0x4bdecfa9);
        HH(c, d, a, b, x[7], S33,(uint8) 0xf6bb4b60);
        HH(b, c, d, a, 0, S34,(uint8) 0xbebfbc70);
        HH(a, b, c, d, 0, S31,(uint8) 0x289b7ec6);
        HH(d, a, b, c, x[0], S32,(uint8) 0xeaa127fa);
        HH(c, d, a, b, x[3], S33,(uint8) 0xd4ef3085);
        HH(b, c, d, a, x[6], S34,(uint8) 0x4881d05);
        HH(a, b, c, d, 0, S31,(uint8) 0xd9d4d039);
        HH(d, a, b, c, 0, S32,(uint8) 0xe6db99e5);
        HH(c, d, a, b, 0, S33,(uint8) 0x1fa27cf8);
        HH(b, c, d, a, x[2], S34,(uint8) 0xc4ac5665);

        II(a, b, c, d, x[0], S41,(uint8) 0xf4292244);
        II(d, a, b, c, x[7], S42,(uint8) 0x432aff97);
        II(c, d, a, b, x14, S43,(uint8) 0xab9423a7);
        II(b, c, d, a, x[5], S44,(uint8) 0xfc93a039);
        II(a, b, c, d, 0, S41,(uint8) 0x655b59c3);
        II(d, a, b, c, x[3], S42,(uint8) 0x8f0ccc92);
        II(c, d, a, b, 0, S43,(uint8) 0xffeff47d);
        II(b, c, d, a, x[1], S44,(uint8) 0x85845dd1);
        II(a, b, c, d, 0, S41,(uint8) 0x6fa87e4f);
        II(d, a, b, c, 0, S42,(uint8) 0xfe2ce6e0);
        II(c, d, a, b, x[6], S43,(uint8) 0xa3014314);
        II(b, c, d, a, 0, S44,(uint8) 0x4e0811a1);
        II(a, b, c, d, x[4],S41,(uint8) 0xf7537e82);
        II(d, a, b, c, 0, S42,(uint8) 0xbd3af235);
        II(c, d, a, b, x[2], S43,(uint8) 0x2ad7d2bb);
        II(b, c, d, a, 0, S44,(uint8) 0xeb86d391);

        internal_ret[0] = a +(uint8) 0x67452301;
        internal_ret[1] = b +(uint8) 0xefcdab89;
        internal_ret[2] = c + (uint8)0x98badcfe;
        internal_ret[3] = d +(uint8) 0x10325476;
}

inline void clear_ctx(__private uint8 * x)
{
        uint8 zero = (uint8) (0, 0,0,0,0,0,0,0);
        for (int i = 0; i < 8; i++)
                x[i] = zero;
}
inline void clean_ctx(__private uint *x){
        for(int i=0;i<8;i++)
                x[i]=0;
}


__kernel void phpass
    (   __global    const   phpass_password*    data
    ,   __global            phpass_hash*        data_out
    ,   __global    const   char*               setting
    )
{
        uint8 x[8],length;
        uint sx[8],i,idx = get_global_id(0);
        uint count = 1 << setting[SALT_SIZE+3];

        clear_ctx(x);

        __global const uchar *password0=data[idx*8+0].v;
        __global const uchar *password1=data[idx*8+1].v;
        __global const uchar *password2=data[idx*8+2].v;
        __global const uchar *password3=data[idx*8+3].v;

        __global const uchar *password4=data[idx*8+4].v;
        __global const uchar *password5=data[idx*8+5].v;
        __global const uchar *password6=data[idx*8+6].v;
        __global const uchar *password7=data[idx*8+7].v;


        length.s0=(uint)data[idx*8+0].length;
        length.s1=(uint)data[idx*8+1].length;
        length.s2=(uint)data[idx*8+2].length;
        length.s3=(uint)data[idx*8+3].length;

        length.s4=(uint)data[idx*8+4].length;
        length.s5=(uint)data[idx*8+5].length;
        length.s6=(uint)data[idx*8+6].length;
        length.s7=(uint)data[idx*8+7].length;

__private uchar *buff = (uchar *) sx;

        #define K1(q)\
                clean_ctx(sx);\
                for (i = 0; i < 8; i++)\
                        buff[i] = setting[i];\
                for (i = 8; i < 8 + length.s##q; i++)\
                        buff[i] = password##q[i - 8];\
                for ( i = 0; i < 8; i++)\
                        x[i].s##q=sx[i];
                K1(0);
                K1(1);
                K1(2);
                K1(3);
                K1(4);
                K1(5);
                K1(6);
                K1(7);
        #undef K1


        uint8 len=length+(uint8)(8);


        x[len.s0 / 4].s0 |= (((uint) 0x80) << ((len.s0 & 0x3) << 3));
        x[len.s1 / 4].s1 |= (((uint) 0x80) << ((len.s1 & 0x3) << 3));
        x[len.s2 / 4].s2 |= (((uint) 0x80) << ((len.s2 & 0x3) << 3));
        x[len.s3 / 4].s3 |= (((uint) 0x80) << ((len.s3 & 0x3) << 3));
        x[len.s4 / 4].s4 |= (((uint) 0x80) << ((len.s4 & 0x3) << 3));
        x[len.s5 / 4].s5 |= (((uint) 0x80) << ((len.s5 & 0x3) << 3));
        x[len.s6 / 4].s6 |= (((uint) 0x80) << ((len.s6 & 0x3) << 3));
        x[len.s7 / 4].s7 |= (((uint) 0x80) << ((len.s7 & 0x3) << 3));


        md5(len, x, x);



#define K2(q)\
                clean_ctx(sx);\
                for(i=0;i<length.s##q;i++)\
                        buff[i]=password##q[i];\
                for(i=0;i<4;i++)\
                        x[i+4].s##q=sx[i];
        K2(0);
        K2(1);
        K2(2);
        K2(3);
        K2(4);
        K2(5);
        K2(6);
        K2(7);
#undef K2

        len = (uint8)(16) + length;
        x[len.s0 / 4].s0 |= (((uint) 0x80) << ((len.s0 & 0x3) << 3));
        x[len.s1 / 4].s1 |= (((uint) 0x80) << ((len.s1 & 0x3) << 3));
        x[len.s2 / 4].s2 |= (((uint) 0x80) << ((len.s2 & 0x3) << 3));
        x[len.s3 / 4].s3 |= (((uint) 0x80) << ((len.s3 & 0x3) << 3));
        x[len.s4 / 4].s4 |= (((uint) 0x80) << ((len.s4 & 0x3) << 3));
        x[len.s5 / 4].s5 |= (((uint) 0x80) << ((len.s5 & 0x3) << 3));
        x[len.s6 / 4].s6 |= (((uint) 0x80) << ((len.s6 & 0x3) << 3));
        x[len.s7 / 4].s7 |= (((uint) 0x80) << ((len.s7 & 0x3) << 3));



#define FF2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + F(w, x, y), s) + w; \
 }
#define GG2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + G(w, x, y), s) + w; \
 }
#define HH2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + H(w, x, y), s) + w; \
 }
#define II2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + I(w, x, y), s) + w; \
 }

uint8 a, b, c, d, x0, x1, x2, x3, x4, x5, x6, x7;
uint8 x14 = len << 3;
        x0 = x[0];
        x1 = x[1];
        x2 = x[2];
        x3 = x[3];
        x4 = x[4];
        x5 = x[5];
        x6 = x[6];
        x7 = x[7];
        do{

        b = (uint8)0xefcdab89;
        c = (uint8)0x98badcfe;
        d = (uint8)0x10325476;

        a = AC1 + x0;
        a = ROTATE_LEFT(a, S11);
        a += b;                 /* 1 */
        d = (c ^ (a & MASK1)) + x1 + AC2pCd;
        d = ROTATE_LEFT(d, S12);
        d += a;                 /* 2 */
        c = F(d, a, b) + x2 + AC3pCc;
        c = ROTATE_LEFT(c, S13);
        c += d;                 /* 3 */
        b = F(c, d, a) + x3 + AC4pCb;
        b = ROTATE_LEFT(b, S14);
        b += c;
        FF(a, b, c, d, x4, S11,(uint8) 0xf57c0faf);
        FF(d, a, b, c, x5, S12,(uint8) 0x4787c62a);
        FF(c, d, a, b, x6, S13,(uint8) 0xa8304613);
        FF(b, c, d, a, x7, S14,(uint8) 0xfd469501);
        FF2(a, b, c, d,  S11,(uint8) 0x698098d8);
        FF2(d, a, b, c,  S12,(uint8) 0x8b44f7af);
        FF2(c, d, a, b,  S13,(uint8) 0xffff5bb1);
        FF2(b, c, d, a,  S14,(uint8) 0x895cd7be);
        FF2(a, b, c, d,  S11,(uint8) 0x6b901122);
        FF2(d, a, b, c, S12,(uint8) 0xfd987193);
        FF(c, d, a, b, x14, S13,(uint8) 0xa679438e);
        FF2(b, c, d, a,  S14,(uint8) 0x49b40821);

        GG(a, b, c, d, x1, S21,(uint8) 0xf61e2562);
        GG(d, a, b, c, x6, S22,(uint8) 0xc040b340);
        GG2(c, d, a, b,  S23,(uint8) 0x265e5a51);
        GG(b, c, d, a, x0, S24,(uint8) 0xe9b6c7aa);
        GG(a, b, c, d, x5, S21,(uint8) 0xd62f105d);
        GG2(d, a, b, c,  S22,(uint8) 0x2441453);
        GG2(c, d, a, b,  S23,(uint8) 0xd8a1e681);
        GG(b, c, d, a, x4, S24,(uint8) 0xe7d3fbc8);
        GG2(a, b, c, d,  S21,(uint8) 0x21e1cde6);
        GG(d, a, b, c, x14, S22,(uint8) 0xc33707d6);
        GG(c, d, a, b, x3, S23,(uint8) 0xf4d50d87);
        GG2(b, c, d, a,  S24,(uint8) 0x455a14ed);
        GG2(a, b, c, d,  S21,(uint8) 0xa9e3e905);
        GG(d, a, b, c, x2, S22,(uint8) 0xfcefa3f8);
        GG(c, d, a, b, x7, S23,(uint8) 0x676f02d9);
        GG2(b, c, d, a,  S24,(uint8) 0x8d2a4c8a);

        HH(a, b, c, d, x5, S31,(uint8) 0xfffa3942);
        HH2(d, a, b, c,  S32,(uint8) 0x8771f681);
        HH2(c, d, a, b,  S33,(uint8) 0x6d9d6122);
        HH(b, c, d, a, x14, S34,(uint8) 0xfde5380c);
        HH(a, b, c, d, x1, S31,(uint8) 0xa4beea44);
        HH(d, a, b, c, x4, S32,(uint8) 0x4bdecfa9);
        HH(c, d, a, b, x7, S33,(uint8) 0xf6bb4b60);
        HH2(b, c, d, a,  S34,(uint8) 0xbebfbc70);
        HH2(a, b, c, d,  S31,(uint8) 0x289b7ec6);
        HH(d, a, b, c, x0, S32,(uint8) 0xeaa127fa);
        HH(c, d, a, b, x3, S33,(uint8) 0xd4ef3085);
        HH(b, c, d, a, x6, S34,(uint8) 0x4881d05);
        HH2(a, b, c, d,  S31,(uint8) 0xd9d4d039);
        HH2(d, a, b, c,  S32,(uint8) 0xe6db99e5);
        HH2(c, d, a, b,  S33,(uint8) 0x1fa27cf8);
        HH(b, c, d, a, x2, S34,(uint8) 0xc4ac5665);

        II(a, b, c, d, x0, S41,(uint8) 0xf4292244);
        II(d, a, b, c, x7, S42,(uint8) 0x432aff97);
        II(c, d, a, b, x14, S43,(uint8) 0xab9423a7);
        II(b, c, d, a, x5, S44,(uint8) 0xfc93a039);
        II2(a, b, c, d,  S41,(uint8) 0x655b59c3);
        II(d, a, b, c, x3, S42,(uint8) 0x8f0ccc92);
        II2(c, d, a, b,  S43,(uint8) 0xffeff47d);
        II(b, c, d, a, x1, S44,(uint8) 0x85845dd1);
        II2(a, b, c, d,  S41,(uint8) 0x6fa87e4f);
        II2(d, a, b, c,  S42,(uint8) 0xfe2ce6e0);
        II(c, d, a, b, x6, S43,(uint8) 0xa3014314);
        II2(b, c, d, a,  S44,(uint8) 0x4e0811a1);
        II(a, b, c, d, x4, S41,(uint8) 0xf7537e82);
        II2(d, a, b, c,  S42,(uint8) 0xbd3af235);
        II(c, d, a, b, x2, S43,(uint8) 0x2ad7d2bb);
        II2(b, c, d, a,  S44,(uint8) 0xeb86d391);

        x0 = a +(uint8) 0x67452301;
        x1 = b +(uint8) 0xefcdab89;
        x2 = c +(uint8)0x98badcfe;
        x3 = d +(uint8) 0x10325476;
        }while(--count);


#define K3(q)\
        data_out[idx*8+q].v[0]=x0.s##q;\
        data_out[idx*8+q].v[1]=x1.s##q;\
        data_out[idx*8+q].v[2]=x2.s##q;\
        data_out[idx*8+q].v[3]=x3.s##q;

        K3(0)
        K3(1)
        K3(2)
        K3(3)
        K3(4)
        K3(5)
        K3(6)
        K3(7)

#undef K3
}
