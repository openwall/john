
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		8

typedef struct {
	uchar v[PLAINTEXT_LENGTH];
	uchar length;
} phpass_password;

typedef struct {
	uint v[4];
} phpass_hash;


#define ROTATE_LEFT(x, s)	rotate(x,s)
//#define F(x, y, z)		((z) ^ ((x) & ((y) ^ (z))))
//#define G(x, y, z)		((y) ^ ((z) & ((x) ^ (y))))

#define F(x, y, z) bitselect((z), (y), (x))
#define G(x, y, z) bitselect((y), (x), (z))
#define H(x, y, z)		((x) ^ (y) ^ (z))
#define I(x, y, z)		((y) ^ ((x) | (~z)))


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

#define S11				7
#define S12				12
#define S13				17
#define S14				22
#define S21				5
#define S22				9
#define S23				14
#define S24				20
#define S31				4
#define S32				11
#define S33				16
#define S34				23
#define S41				6
#define S42				10
#define S43				15
#define S44				21

#define AC1				0xd76aa477
#define AC2pCd				0xf8fa0bcc
#define AC3pCc				0xbcdb4dd9
#define AC4pCb				0xb18b7a77
#define MASK1				0x77777777



inline void md5(uint4 len,__private uint4 * internal_ret,__private uint4 * x)
{
	uint4 x14 = len << 3;

	uint4 a;
	uint4 b = 0xefcdab89;
	uint4 c = 0x98badcfe;
	uint4 d = 0x10325476;

	a = AC1 + x[0];
	a = ROTATE_LEFT(a, S11);
	a += b;			/* 1 */
	d = (c ^ (a & MASK1)) + x[1] + AC2pCd;
	d = ROTATE_LEFT(d, S12);
	d += a;			/* 2 */
	c = F(d, a, b) + x[2] + AC3pCc;
	c = ROTATE_LEFT(c, S13);
	c += d;			/* 3 */
	b = F(c, d, a) + x[3] + AC4pCb;
	b = ROTATE_LEFT(b, S14);
	b += c;
	FF(a, b, c, d, x[4], S11, 0xf57c0faf);
	FF(d, a, b, c, x[5], S12, 0x4787c62a);
	FF(c, d, a, b, x[6], S13, 0xa8304613);
	FF(b, c, d, a, x[7], S14, 0xfd469501);
	FF(a, b, c, d, 0, S11, 0x698098d8);
	FF(d, a, b, c, 0, S12, 0x8b44f7af);
	FF(c, d, a, b, 0, S13, 0xffff5bb1);
	FF(b, c, d, a, 0, S14, 0x895cd7be);
	FF(a, b, c, d, 0, S11, 0x6b901122);
	FF(d, a, b, c, 0, S12, 0xfd987193);
	FF(c, d, a, b, x14, S13, 0xa679438e);
	FF(b, c, d, a, 0, S14, 0x49b40821);

	GG(a, b, c, d, x[1], S21, 0xf61e2562);
	GG(d, a, b, c, x[6], S22, 0xc040b340);
	GG(c, d, a, b, 0, S23, 0x265e5a51);
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
	GG(a, b, c, d, x[5], S21, 0xd62f105d);
	GG(d, a, b, c, 0, S22, 0x2441453);
	GG(c, d, a, b, 0, S23, 0xd8a1e681);
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
	GG(a, b, c, d, 0, S21, 0x21e1cde6);
	GG(d, a, b, c, x14, S22, 0xc33707d6);
	GG(c, d, a, b, x[3], S23, 0xf4d50d87);
	GG(b, c, d, a, 0, S24, 0x455a14ed);
	GG(a, b, c, d, 0, S21, 0xa9e3e905);
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
	GG(c, d, a, b, x[7], S23, 0x676f02d9);
	GG(b, c, d, a, 0, S24, 0x8d2a4c8a);

	HH(a, b, c, d, x[5], S31, 0xfffa3942);
	HH(d, a, b, c, 0, S32, 0x8771f681);
	HH(c, d, a, b, 0, S33, 0x6d9d6122);
	HH(b, c, d, a, x14, S34, 0xfde5380c);
	HH(a, b, c, d, x[1], S31, 0xa4beea44);
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
	HH(b, c, d, a, 0, S34, 0xbebfbc70);
	HH(a, b, c, d, 0, S31, 0x289b7ec6);
	HH(d, a, b, c, x[0], S32, 0xeaa127fa);
	HH(c, d, a, b, x[3], S33, 0xd4ef3085);
	HH(b, c, d, a, x[6], S34, 0x4881d05);
	HH(a, b, c, d, 0, S31, 0xd9d4d039);
	HH(d, a, b, c, 0, S32, 0xe6db99e5);
	HH(c, d, a, b, 0, S33, 0x1fa27cf8);
	HH(b, c, d, a, x[2], S34, 0xc4ac5665);

	II(a, b, c, d, x[0], S41, 0xf4292244);
	II(d, a, b, c, x[7], S42, 0x432aff97);
	II(c, d, a, b, x14, S43, 0xab9423a7);
	II(b, c, d, a, x[5], S44, 0xfc93a039);
	II(a, b, c, d, 0, S41, 0x655b59c3);
	II(d, a, b, c, x[3], S42, 0x8f0ccc92);
	II(c, d, a, b, 0, S43, 0xffeff47d);
	II(b, c, d, a, x[1], S44, 0x85845dd1);
	II(a, b, c, d, 0, S41, 0x6fa87e4f);
	II(d, a, b, c, 0, S42, 0xfe2ce6e0);
	II(c, d, a, b, x[6], S43, 0xa3014314);
	II(b, c, d, a, 0, S44, 0x4e0811a1);
	II(a, b, c, d, x[4], S41, 0xf7537e82);
	II(d, a, b, c, 0, S42, 0xbd3af235);
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
	II(b, c, d, a, 0, S44, 0xeb86d391);

	internal_ret[0] = a + 0x67452301;
	internal_ret[1] = b + 0xefcdab89;
	internal_ret[2] = c + 0x98badcfe;
	internal_ret[3] = d + 0x10325476;
}

inline void clear_ctx(__private uint4 * x)
{
	uint4 zero = (uint4) (0, 0,0,0);
	for (int i = 0; i < 8; i++)
		x[i] = zero;
}
inline void clean_ctx(__private uint *x){
	for(int i=0;i<8;i++)
		x[i]=0;
}


__kernel void phpass
    (   __global    const   phpass_password*    data
    ,   __global            phpass_hash*    	data_out
    ,   __global    const   char* 		setting
    )
{
	uint4 x[8],length;
	uint sx[8],i,idx = get_global_id(0);
	uint count = 1 << setting[SALT_SIZE+3];

	clear_ctx(x);

	__global const uchar *password0=data[idx*4+0].v;
	__global const uchar *password1=data[idx*4+1].v;
	__global const uchar *password2=data[idx*4+2].v;
	__global const uchar *password3=data[idx*4+3].v;

	length.s0=data[idx*4+0].length;
	length.s1=data[idx*4+1].length;
	length.s2=data[idx*4+2].length;
	length.s3=data[idx*4+3].length;

	__private uchar *buff = (uchar *) sx;
 	#define K(q)\
		clean_ctx(sx);\
		for (i = 0; i < 8; i++)\
			buff[i] = setting[i];\
		for (i = 8; i < 8 + length.s##q; i++)\
			buff[i] = password##q[i - 8];\
		for ( i = 0; i < 8; i++)\
			x[i].s##q=sx[i];
		K(0);
		K(1);
		K(2);
		K(3);
	#undef K

	uint4 len=length+(uint4)(8);

	x[len.s0 / 4].s0 |= (((uint) 0x80) << ((len.s0 & 0x3) << 3));
	x[len.s1 / 4].s1 |= (((uint) 0x80) << ((len.s1 & 0x3) << 3));
	x[len.s2 / 4].s2 |= (((uint) 0x80) << ((len.s2 & 0x3) << 3));
	x[len.s3 / 4].s3 |= (((uint) 0x80) << ((len.s3 & 0x3) << 3));

	md5(len, x, x);

#define K(q)\
		clean_ctx(sx);\
		for(i=0;i<length.s##q;i++)\
			buff[i]=password##q[i];\
		for(i=0;i<2;i++)\
			x[i+4].s##q=sx[i];
	K(0);
	K(1);
	K(2);
	K(3);
#undef K

	len = 16 + length;
	x[len.s0 / 4].s0 |= (((uint) 0x80) << ((len.s0 & 0x3) << 3));
	x[len.s1 / 4].s1 |= (((uint) 0x80) << ((len.s1 & 0x3) << 3));
	x[len.s2 / 4].s2 |= (((uint) 0x80) << ((len.s2 & 0x3) << 3));
	x[len.s3 / 4].s3 |= (((uint) 0x80) << ((len.s3 & 0x3) << 3));

	do {
	  md5(len, x, x);
	} while (--count);

#define K(q)\
	data_out[idx*4+q].v[0]=x[0].s##q;\
	data_out[idx*4+q].v[1]=x[1].s##q;\
	data_out[idx*4+q].v[2]=x[2].s##q;\
	data_out[idx*4+q].v[3]=x[3].s##q;
	K(0)
	K(1)
	K(2)
	K(3)
#undef K
}