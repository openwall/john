/*
 * This software is Copyright (c) 2013 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * This is a direct port of mscash-cuda format by Lukas Odzioba
 * <lukas dot odzioba at gmail dot com>
 */

#include "opencl_mscash.h"

void md4_crypt(__private uint *output, __private uint *nt_buffer)
{
	unsigned int a = INIT_A;
	unsigned int b = INIT_B;
	unsigned int c = INIT_C;
	unsigned int d = INIT_D;

	/* Round 1 */
	a += (d ^ (b & (c ^ d))) + nt_buffer[0];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[1];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[2];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[3];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[4];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[5];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[6];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[7];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[8];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[9];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[10];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[11];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[12];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[13];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[14];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[15];
	b = (b << 19) | (b >> 13);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2;
	b = (b << 13) | (b >> 19);

	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3;
	b = (b << 15) | (b >> 17);

	output[0] = a + INIT_A;
	output[1] = b + INIT_B;
	output[2] = c + INIT_C;
	output[3] = d + INIT_D;
}

void prepare_key(uchar * key, int length, uint * nt_buffer)
{
	int i = 0;
	for (i = 0; i < 16; i++)
		nt_buffer[i] = 0;
	for (i = 0; i < length / 2; i++)
		nt_buffer[i] = key[2 * i] | (key[2 * i + 1] << 16);
	if (length % 2 == 1)
		nt_buffer[i] = key[length - 1] | 0x800000;
	else
		nt_buffer[i] = 0x80;
	nt_buffer[14] = length << 4;
}

void prepare_login(uchar * login, int length,
    uint * login_buffer)
{
	int i = 0;
	for (i = 0; i < 12; i++)
		login_buffer[i] = 0;
	for (i = 0; i < length / 2; i++)
		login_buffer[i] = login[2 * i] | (login[2 * i + 1] << 16);
	if (length % 2 == 1)
		login_buffer[i] = login[length - 1] | 0x800000;
	else
		login_buffer[i] = 0x80;
	login_buffer[10] = (length << 4) + 128;
}

__kernel void mscash(__global mscash_password *inBuffer, __global mscash_salt *salt, __global mscash_hash *outBuffer) {

	int gid = get_global_id(0), i;
	uchar login[19] = { 0 };
	uchar password[23] = { 0 };
	uint nt_buffer[16] = { 0 };
	uint login_buffer[12] = { 0 };
	uint output[4] = { 0 };
	uchar loginlength = salt[0].length;
	uchar passwordlength = inBuffer[gid].length;

	for(i = 0; i < loginlength; i++)
		login[i] = salt[0].salt[i];

	for(i = 0; i < passwordlength; i++)
		password[i] = inBuffer[gid].v[i];

	prepare_key(password, passwordlength, nt_buffer);
	md4_crypt(output, nt_buffer);
	nt_buffer[0] = output[0];
	nt_buffer[1] = output[1];
	nt_buffer[2] = output[2];
	nt_buffer[3] = output[3];

	prepare_login(login, loginlength, login_buffer);
	for(i = 0; i < 12; i++)
		nt_buffer[i + 4] = login_buffer[i];
	md4_crypt(output, nt_buffer);

	for (i = 0; i < 4; i++)
		outBuffer[gid].v[i] = output[i];
}