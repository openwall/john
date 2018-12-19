/* $Id: md2.c 182 2010-05-08 19:04:55Z tp $ */
/*
 * MD2 implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>

#include "sph_md2.h"


/*
 * The MD2 magic table.
 */
static const unsigned char S[256] = {
	 41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161,
	236, 240,   6,  19,  98, 167,   5, 243, 192, 199, 115, 140,
	152, 147,  43, 217, 188,  76, 130, 202,  30, 155,  87,  60,
	253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
	190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142,
	187,  47, 238, 122, 169, 104, 121, 145,  21, 178,   7,  63,
	148, 194,  16, 137,  11,  34,  95,  33, 128, 127,  93, 154,
	 90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
	255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42,
	172,  86, 170, 198,  79, 184,  56, 210, 150, 164, 125, 182,
	118, 252, 107, 226, 156, 116,   4, 241,  69, 157, 112,  89,
	100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
	 27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,
	 52,  64, 126,  15,  85,  71, 163,  35, 221,  81, 175,  58,
	195,  92, 249, 206, 186, 197, 234,  38,  44,  83,  13, 110,
	133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
	106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,
	 12, 189, 177,  74, 120, 136, 149, 139, 227,  99, 232, 109,
	233, 203, 213, 254,  59,   0,  29,  57, 242, 239, 183,  14,
	102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
	 49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51,
	159,  17, 131, 20
};

/*
 * One round of MD2. The round operates on the provided (aligned)
 * 16-byte buffer.
 */
static void
md2_round(sph_md2_context *mc)
{
	int j;
	unsigned t, L;

	L = mc->L;
	for (j = 0; j < 16; j ++) {
		/*
		 * WARNING: RFC 1319 pseudo-code in chapter 3.2 is
		 * incorrect. This implementation matches the reference
		 * implementation and the reference test vectors. The
		 * RFC 1319 flaw is documented in the official errata:
		 * http://www.rfc-editor.org/errata.html
		 */
		L = mc->C[j] = mc->C[j] ^ S[mc->u.X[j + 16] ^ L];
	}
	mc->L = L;

#ifdef SPH_UPTR
	mc->u.W[ 8] = mc->u.W[4] ^ mc->u.W[0];
	mc->u.W[ 9] = mc->u.W[5] ^ mc->u.W[1];
	mc->u.W[10] = mc->u.W[6] ^ mc->u.W[2];
	mc->u.W[11] = mc->u.W[7] ^ mc->u.W[3];
#else
	mc->u.X[32] = mc->u.X[16] ^ mc->u.X[ 0];
	mc->u.X[33] = mc->u.X[17] ^ mc->u.X[ 1];
	mc->u.X[34] = mc->u.X[18] ^ mc->u.X[ 2];
	mc->u.X[35] = mc->u.X[19] ^ mc->u.X[ 3];
	mc->u.X[36] = mc->u.X[20] ^ mc->u.X[ 4];
	mc->u.X[37] = mc->u.X[21] ^ mc->u.X[ 5];
	mc->u.X[38] = mc->u.X[22] ^ mc->u.X[ 6];
	mc->u.X[39] = mc->u.X[23] ^ mc->u.X[ 7];
	mc->u.X[40] = mc->u.X[24] ^ mc->u.X[ 8];
	mc->u.X[41] = mc->u.X[25] ^ mc->u.X[ 9];
	mc->u.X[42] = mc->u.X[26] ^ mc->u.X[10];
	mc->u.X[43] = mc->u.X[27] ^ mc->u.X[11];
	mc->u.X[44] = mc->u.X[28] ^ mc->u.X[12];
	mc->u.X[45] = mc->u.X[29] ^ mc->u.X[13];
	mc->u.X[46] = mc->u.X[30] ^ mc->u.X[14];
	mc->u.X[47] = mc->u.X[31] ^ mc->u.X[15];
#endif
	t = 0;
	for (j = 0; j < 18; j ++) {
		int k;

		/*
		 * We unroll 8 steps. 8 steps are good; this has been
		 * empirically determined to be the right unroll length
		 * (6 steps yield slightly worse performance; 16 steps
		 * are no better than 8).
		 */
		for (k = 0; k < 48; k += 8) {
			t = (mc->u.X[k + 0] ^= S[t]);
			t = (mc->u.X[k + 1] ^= S[t]);
			t = (mc->u.X[k + 2] ^= S[t]);
			t = (mc->u.X[k + 3] ^= S[t]);
			t = (mc->u.X[k + 4] ^= S[t]);
			t = (mc->u.X[k + 5] ^= S[t]);
			t = (mc->u.X[k + 6] ^= S[t]);
			t = (mc->u.X[k + 7] ^= S[t]);
		}
		t = (t + j) & 0xFF;
	}
}

/* see sph_md2.h */
void
sph_md2_init(void *cc)
{
	sph_md2_context *mc;

	mc = cc;
	memset(&mc->u.X, 0, 16);
	memset(&mc->C, 0, 16);
	mc->L = 0;
	mc->count = 0;
}

/* see sph_md2.h */
void
sph_md2(void *cc, const void *data, size_t len)
{
	sph_md2_context *mc;
	unsigned current;

	mc = cc;
	current = mc->count;
	if (current > 0) {
		unsigned clen;

		clen = 16U - current;
		if (clen > len)
			clen = len;
		memcpy(mc->u.X + 16 + current, data, clen);
		data = (const unsigned char *)data + clen;
		current += clen;
		len -= clen;
		if (current == 16) {
			md2_round(mc);
			current = 0;
		}
	}
	while (len >= 16) {
		memcpy(mc->u.X + 16, data, 16);
		md2_round(mc);
		data = (const unsigned char *)data + 16;
		len -= 16;
	}
	memcpy(mc->u.X + 16, data, len);
	mc->count = len;
}

/* see sph_md2.h */
void
sph_md2_close(void *cc, void *dst)
{
	sph_md2_context *mc;
	unsigned u, v;

	mc = cc;
	u = mc->count;
	v = 16 - u;
	memset(mc->u.X + 16 + u, v, v);
	md2_round(mc);
	memcpy(mc->u.X + 16, mc->C, 16);
	md2_round(mc);
	memcpy(dst, mc->u.X, 16);
	sph_md2_init(mc);
}
