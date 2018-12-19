/*
 * Our own RC4 based on the "original" as posted to sci.crypt in 1994 and
 * tweaked for  performance  on  x86-64.   OpenSSL is probably faster for
 * decrypting larger amounts of data but we are more interested in a very
 * fast key setup.  On Intel and AMD x64, I have seen up to 50% speedups.
 *
 * The speed  improvement  (if you see one) is due to OpenSSL's  (or your
 * distributor's) choice of type for RC4_INT. Some systems perform bad if
 * this is defined as char. Others perform bad if it's not. If needed, we
 * could move JOHN_RC4_INT to arch.h
 *
 * Syntax is same as OpenSSL;
 * just #include "rc4.h"  instead of  <openssl/rc4.h>
 *
 * Put together by magnum in 2011, 2013. No Rights Reserved.
 */

#include "rc4.h"

#define swap_byte(a, b) { RC4_INT tmp = (*a); (*a) = (*b); (*b) = tmp; }

#define swap_state(n) { \
	index2 = (kp[index1] + state[(n)] + index2) & 255; \
	swap_byte(&state[(n)], &state[index2]); \
	if (++index1 == keylen) index1 = 0; \
}

void RC4_set_key(RC4_KEY *ctx, RC4_INT keylen, const unsigned char *kp)
{
	RC4_INT index1;
	RC4_INT index2;
	RC4_INT *state;
	int counter;

	state = &ctx->state[0];
	for (counter = 0; counter < 256; counter++)
		state[counter] = counter;
	ctx->x = 0;
	ctx->y = 0;
	index1 = 0;
	index2 = 0;
	for (counter = 0; counter < 256; counter += 4) {
		swap_state(counter);
		swap_state(counter + 1);
		swap_state(counter + 2);
		swap_state(counter + 3);
	}
}

void RC4(RC4_KEY *ctx, RC4_INT len, const unsigned char *in, unsigned char *out)
{
	RC4_INT x;
	RC4_INT y;
	RC4_INT *state;
	RC4_INT counter;

	x = ctx->x;
	y = ctx->y;

	state = &ctx->state[0];
	for (counter = 0; counter < len; counter ++) {
		x = (x + 1) & 255;
		y = (state[x] + y) & 255;
		swap_byte(&state[x], &state[y]);
		*out++ = *in++ ^ state[(state[x] + state[y]) & 255];
	}
	ctx->x = x;
	ctx->y = y;
}

void RC4_single(void *key, int keylen, const unsigned char *in, int len, unsigned char *out)
{
	unsigned char *kp = (unsigned char*)key;
	int i;
	RC4_INT x = 0;
	RC4_INT y = 0;
	RC4_INT index1 = 0;
	RC4_INT index2 = 0;
	RC4_INT state[256];

	for (i = 0; i < 256; i += 4) {
		state[i] = i;
		state[i + 1] = i + 1;
		state[i + 2] = i + 2;
		state[i + 3] = i + 3;
	}

	for (i = 0; i < 256; i += 4) {
		swap_state(i);
		swap_state(i + 1);
		swap_state(i + 2);
		swap_state(i + 3);
	}

	while (len--) {
		x = (x + 1) & 255;
		y = (state[x] + y) & 255;
		swap_byte(&state[x], &state[y]);
		*out++ = *in++ ^ state[(state[x] + state[y]) & 255];
	}
}
