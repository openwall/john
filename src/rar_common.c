/*
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "misc.h"	// error()
#include "md5.h"
#include "base64_convert.h"
#include "assert.h"

static int omp_t = 1;
static unsigned char *saved_salt;
static unsigned char *saved_key;
static int (*cracked);
static unpack_data_t (*unpack_data);

static unsigned int *saved_len;
static unsigned char *aes_key;
static unsigned char *aes_iv;

// perl -ne 'use Digest::MD5 qw(md5_hex); @l = split(/\*/, $_); $b = pack("H*", $l[7]); $h = md5_hex($b); printf("%s*%s*%s*%s*%s*%s*%s*%s*%s\n", $l[0], $l[1], $l[2], $l[3], $l[4], $l[5], $l[8], $h, $l[7]);'

// perl -ne 'use Digest::MD5 qw(md5_hex); use MIME::Base64; chomp; @l = split(/\*/, $_); $b = pack("H*", $l[7]); $h = md5_hex($b); $t = substr($l[8], 2); $l[8] = substr($l[8], 0, 2); printf("%s*2*%s*%s*%s*%s*%s*%s*%s%s\n", $l[0], $l[2], $l[3], $l[4], $l[5], $l[8], $h, encode_base64($b, ""), $t);'

/* cRARk use 4-char passwords for CPU benchmark */
static struct fmt_tests cpu_tests[] = {
	{"$RAR3$*0*b109105f5fe0b899*d4f96690b1a8fe1f120b0290a85a2121", "test"},
	{"$RAR3$*0*42ff7e92f24fb2f8*9d8516c8c847f1b941a0feef064aaf0d", "1234"},
	{"$RAR3$*0*56ce6de6ddee17fb*4c957e533e00b0e18dfad6accc490ad9", "john"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*2*c47c5bef0bbd1e98*965f1453*48*47*30*8ebae16a58e3973dab2c7e537da96bf3*xemH+B0xbZ3P22obJxBc5j/KLFlNpaovb98vZfUPDWYxT4oJ2oda4Z1sFWNrZcgV", "test"},
	{"$RAR3$*2*b4eee1a48dc95d12*965f1453*64*47*33*7048bb5213ae0e591b2bd639c53a46cb*D+UpR4eYwJYN2Io4oFRR+VWeFfDPILTKxYJgsOW1ZpnVhxvcw1vuCZzBMes1uaEWra7fXswmscCcrfUYWzCS5g==", "test"},
#ifdef DEBUG
	/* Various lengths, these should be in self-test but not benchmark */
	/* from CMIYC 2012 */
	{"$RAR3$*2*0f263dd52eead558*834015cd*384*693*33*6711cf520831cfdea151361f06b0b869*4o6WSPUbWeMvVzswLw6Uqt8QUGeLkMON1OdQx90oHUOatMzOxfG9GsQLah6tYMdWJWZjBxceD+JjnSOX1faLl6Kh9zMonqwAOLUuxsNZP/BymPzgkRjCVbJ0egLC+jF1q4EWbr/y8fEEufYoSmb1mHZL0B8JNWK17rlHHZd789M5Aaz9lkOv5GDh0QuQ4Om8i3fcmsQNQMLSEd+bDsvK6nLJ2PFYWdWbPIUUm1u19W8CGMu9nyh5B3fDnj5Jm8IHKJcnr7Ky4CVBtybprAKPTwWk15MO+/+X0f/XhsShlbvtdJl0aYAhWfOwrgW3AyONomQIe2wnKdkCP2fELFy+QLbGfuu/xGWN+5m/y1I/YhMxE3NehiwUMK31nINzBURujjT6wAYguZ9XT6vrLNNNxydSAUy/S9ZNNfF8721AdHyBsS2MDNRHIImImlP02BCyEvsxS/WMPdNnlt4P7u+vJr4gxqL9AFFxUsWNCxqVd172oTdMYI9V9Ba3i4yBdh8d:1::to-submit-challenges.txt", "wachtwoord"},
	{"$RAR3$*2*9759543e04fe3a22*834015cd*384*693*33*4a14d0d023a344d954ed105cace4e8e9*zdLiR45RU6WBxHogFJD12baeAVhK5IiipAID2puoxSce2O3I+Rp70mK7Xl3gfsvp4gA9BUoxTRbK8uod6fVDA6ve4e0EQ5b34pxAw45jj2JkQu/Z9RG0dDdYzUpgJcWvgdElJHWWSTfYC/1Q0QwXHn5AQaZsAqdLK0Ua6DtoB5kPsGUqjNq1MMWgxJdXWm5svi2yA1IX/oSdLguGk7cPP5e3VyKbTonIJzGXYCwjzAT/XySr89PH62hvw+3c4b/nEMwLbovQEpKBJ9o4w43Y8FYJWYKvrLRXj2KA1RxnOXOeAzZ0qUE8qIBT+CZMUTfUrAGBJcBBo0idqvF173XpKC0kW5KUjBu88cXyW3Ao9tIH2H/pWYwsfM0VU+hCqRq4ypJhpRsUYBp1YHA4jQgDlGbfo28LTH6n3Z/yXJ2YaHIDxY+eyHV8r+TS7XhdWp5tXqg45Mwkap5tPDCXnczlazgLBfkQPmRDs1NXVQtQIpxH+EWpOkhgJ5AJaCjZ1r7w:1::to-submit-challenges.txt", "Sleepingbaby210"},
	{"$RAR3$*2*79e17c26407a7d52*834015cd*384*693*33*aa5fe464a67f74df5b73345a742431d5*aEShiecy6TkLWpWLYjWJ1UI/pDLXVv0AlArDHiRSFJg1B6A11ODuCUaUkVUXWaZsEhUP5sXQXzNPsNgwKpbUjvTaBJVCIuBwVQeqqE+LE38oTb7DRO7pzqayxPY1QMZN8+6L4wE0ZtI4xZmempjrY3XsVGKGm7pDQB7JUHfQxZM1IzmQLCSjMkF44I/mlNEb/sZGxlL/6vvdqSkFLDcP/YkWjIMZT+33xQ/H2aH75kMyBj0mehgesHtdcKWFQGfbm2bBJwP95ico02gM8/25kzoPAr/JTzpoKtXnxCjX7UTV/1VKikRd6ii4HjomMYcOF/PzwMAgQTaALAcBWQzD5MDM2fFei+JFzpyqaWn6uehEOsmtnnPnRGgRrulxgINQw4wWwNM3LH9EF0Zm13Dj3TIeiwj7LcXopqWyoXILrWblSrwZT6q8XyQiXdj+4Te6XUwu1IxkYmGOYzMwCluN/HXGVgiSXnhusJiPezpasQalUWjRABrcR86Vu6d7OMNb:1::to-submit-challenges.txt", "P-i-r-A-T-E"},
	{"$RAR3$*2*e1df79fd9ee1dadf*771a163b*64*39*33*54de35dce4c8b65ddceb3c216d93287b*7cSD1nuUqyKgqbg3WkYeBvoRCPpylw4W2WIJLDEZcNJuuSoDOkL1MCe9wLtHIxoS7ZaMjVMKlIapDLvAAEBWmw==", "333"},
	{"$RAR3$*2*c83c00534d4af2db*771a163b*64*39*33*28ef95f732a3c9f71f80392e0270f050*BSRFJtazLLnFJKFcedGbumhff8MAepFxxl/IJkgfLc5wvmFI8sNJfw1UmqToZPc9Tk9pf9tm/1KO0VA9lxKkFA==", "11eleven111"},
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif
	{NULL}
};

#ifdef RAR_OPENCL_FORMAT
/* cRARk use 5-char passwords for GPU benchmark */
static struct fmt_tests gpu_tests[] = {
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*2*c47c5bef0bbd1e98*965f1453*48*47*30*8ebae16a58e3973dab2c7e537da96bf3*xemH+B0xbZ3P22obJxBc5j/KLFlNpaovb98vZfUPDWYxT4oJ2oda4Z1sFWNrZcgV", "test"},
	{"$RAR3$*2*b4eee1a48dc95d12*965f1453*64*47*33*7048bb5213ae0e591b2bd639c53a46cb*D+UpR4eYwJYN2Io4oFRR+VWeFfDPILTKxYJgsOW1ZpnVhxvcw1vuCZzBMes1uaEWra7fXswmscCcrfUYWzCS5g==", "test"},
#ifdef DEBUG
	{"$RAR3$*0*af24c0c95e9cafc7*e7f207f30dec96a5ad6f917a69d0209e", "magnum"},
	{"$RAR3$*0*2653b9204daa2a8e*39b11a475f486206e2ec6070698d9bbc", "123456"},
	{"$RAR3$*0*63f1649f16c2b687*8a89f6453297bcdb66bd756fa10ddd98", "abc123"},
	{"$RAR3$*2*575b083d78672e85*965f1453*48*47*30*29eb44d122ce495402565f61e240db61*zT2HVkOPQ6tw5mh5LigFPwrXRJrxxmhj4+VTMr+jBLLAgrnyOzbNSo68C3Q2GMWy", "magnum"},
	{"$RAR3$*2*6f5954680c87535a*965f1453*64*47*33*820d92932e8d268a9ed62f3ec5e38836*ybs5i5pdVPA1/SK+VLxtx1gi9Vgz8w60+4zAuCGOQebQGCTjRnR1uQuZSl3bf+GTZtKTye4wUxbCpgw6frPOWg==", "magnum"},
	/* Various lengths, these should be in self-test but not benchmark */
	/* from CMIYC 2012 */
	{"$RAR3$*2*0f263dd52eead558*834015cd*384*693*33*6711cf520831cfdea151361f06b0b869*4o6WSPUbWeMvVzswLw6Uqt8QUGeLkMON1OdQx90oHUOatMzOxfG9GsQLah6tYMdWJWZjBxceD+JjnSOX1faLl6Kh9zMonqwAOLUuxsNZP/BymPzgkRjCVbJ0egLC+jF1q4EWbr/y8fEEufYoSmb1mHZL0B8JNWK17rlHHZd789M5Aaz9lkOv5GDh0QuQ4Om8i3fcmsQNQMLSEd+bDsvK6nLJ2PFYWdWbPIUUm1u19W8CGMu9nyh5B3fDnj5Jm8IHKJcnr7Ky4CVBtybprAKPTwWk15MO+/+X0f/XhsShlbvtdJl0aYAhWfOwrgW3AyONomQIe2wnKdkCP2fELFy+QLbGfuu/xGWN+5m/y1I/YhMxE3NehiwUMK31nINzBURujjT6wAYguZ9XT6vrLNNNxydSAUy/S9ZNNfF8721AdHyBsS2MDNRHIImImlP02BCyEvsxS/WMPdNnlt4P7u+vJr4gxqL9AFFxUsWNCxqVd172oTdMYI9V9Ba3i4yBdh8d:1::to-submit-challenges.txt", "wachtwoord"},
	{"$RAR3$*2*9759543e04fe3a22*834015cd*384*693*33*4a14d0d023a344d954ed105cace4e8e9*zdLiR45RU6WBxHogFJD12baeAVhK5IiipAID2puoxSce2O3I+Rp70mK7Xl3gfsvp4gA9BUoxTRbK8uod6fVDA6ve4e0EQ5b34pxAw45jj2JkQu/Z9RG0dDdYzUpgJcWvgdElJHWWSTfYC/1Q0QwXHn5AQaZsAqdLK0Ua6DtoB5kPsGUqjNq1MMWgxJdXWm5svi2yA1IX/oSdLguGk7cPP5e3VyKbTonIJzGXYCwjzAT/XySr89PH62hvw+3c4b/nEMwLbovQEpKBJ9o4w43Y8FYJWYKvrLRXj2KA1RxnOXOeAzZ0qUE8qIBT+CZMUTfUrAGBJcBBo0idqvF173XpKC0kW5KUjBu88cXyW3Ao9tIH2H/pWYwsfM0VU+hCqRq4ypJhpRsUYBp1YHA4jQgDlGbfo28LTH6n3Z/yXJ2YaHIDxY+eyHV8r+TS7XhdWp5tXqg45Mwkap5tPDCXnczlazgLBfkQPmRDs1NXVQtQIpxH+EWpOkhgJ5AJaCjZ1r7w:1::to-submit-challenges.txt", "Sleepingbaby210"},
	{"$RAR3$*2*79e17c26407a7d52*834015cd*384*693*33*aa5fe464a67f74df5b73345a742431d5*aEShiecy6TkLWpWLYjWJ1UI/pDLXVv0AlArDHiRSFJg1B6A11ODuCUaUkVUXWaZsEhUP5sXQXzNPsNgwKpbUjvTaBJVCIuBwVQeqqE+LE38oTb7DRO7pzqayxPY1QMZN8+6L4wE0ZtI4xZmempjrY3XsVGKGm7pDQB7JUHfQxZM1IzmQLCSjMkF44I/mlNEb/sZGxlL/6vvdqSkFLDcP/YkWjIMZT+33xQ/H2aH75kMyBj0mehgesHtdcKWFQGfbm2bBJwP95ico02gM8/25kzoPAr/JTzpoKtXnxCjX7UTV/1VKikRd6ii4HjomMYcOF/PzwMAgQTaALAcBWQzD5MDM2fFei+JFzpyqaWn6uehEOsmtnnPnRGgRrulxgINQw4wWwNM3LH9EF0Zm13Dj3TIeiwj7LcXopqWyoXILrWblSrwZT6q8XyQiXdj+4Te6XUwu1IxkYmGOYzMwCluN/HXGVgiSXnhusJiPezpasQalUWjRABrcR86Vu6d7OMNb:1::to-submit-challenges.txt", "P-i-r-A-T-E"},
	{"$RAR3$*2*e1df79fd9ee1dadf*771a163b*64*39*33*54de35dce4c8b65ddceb3c216d93287b*7cSD1nuUqyKgqbg3WkYeBvoRCPpylw4W2WIJLDEZcNJuuSoDOkL1MCe9wLtHIxoS7ZaMjVMKlIapDLvAAEBWmw==", "333"},
	{"$RAR3$*2*c83c00534d4af2db*771a163b*64*39*33*28ef95f732a3c9f71f80392e0270f050*BSRFJtazLLnFJKFcedGbumhff8MAepFxxl/IJkgfLc5wvmFI8sNJfw1UmqToZPc9Tk9pf9tm/1KO0VA9lxKkFA==", "11eleven111"},
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif
	{NULL}
};
#endif

typedef struct {
	dyna_salt dsalt; /* must be first. allows dyna_salt to work */
	/* place all items we are NOT going to use for salt comparison, first */
	unsigned char *blob;
	/* data from this point on, is part of the salt for compare reasons */
	unsigned char salt[8];
	int type;	/* 0 = -hp, 1 = -p */
	/* for rar -p mode only: */
	union {
		unsigned int w;
		unsigned char c[4];
	} crc;
	unsigned long long pack_size;
	unsigned long long unp_size;
	int method;
	// raw_data should be word aligned, and 'ok'
	unsigned char raw_data[1];
} rarfile;

static rarfile *cur_file;
static size_t split_size;
static void *split_blob;

#undef set_key
static void set_key(char *key, int index)
{
	int plen;
	UTF16 buf[PLAINTEXT_LENGTH + 1];

	/* UTF-16LE encode the password, encoding aware */
	plen = enc_to_utf16(buf, PLAINTEXT_LENGTH, (UTF8*) key, strlen(key));

	if (plen < 0)
		plen = strlen16(buf);

	memcpy(&saved_key[UNICODE_LENGTH * index], buf, UNICODE_LENGTH);

	saved_len[index] = plen << 1;

#ifdef RAR_OPENCL_FORMAT
	new_keys = 1;
#endif
}

static void *get_salt(char *ciphertext)
{
	unsigned int i, type, ex_len;
	static unsigned char *ptr;
	/* extract data from "salt" */
	char *encoded_salt;
	char *saltcopy = strdup(ciphertext);
	char *keep_ptr = saltcopy;
	rarfile *psalt;
	unsigned char tmp_salt[8];

	if (!ptr) ptr = mem_alloc_tiny(sizeof(rarfile*),sizeof(rarfile*));
	saltcopy += 7;		/* skip over "$RAR3$*" */
	type = atoi(strtokm(saltcopy, "*"));
	encoded_salt = strtokm(NULL, "*");
	for (i = 0; i < 8; i++)
		tmp_salt[i] = atoi16[ARCH_INDEX(encoded_salt[i * 2])] * 16 + atoi16[ARCH_INDEX(encoded_salt[i * 2 + 1])];
	if (type == 0) {	/* rar-hp mode */
		char *encoded_ct = strtokm(NULL, "*");
		psalt = mem_calloc(1, sizeof(*psalt)+16);
		psalt->type = type;
		ex_len = 16;
		memcpy(psalt->salt, tmp_salt, 8);
		for (i = 0; i < 16; i++)
			psalt->raw_data[i] = atoi16[ARCH_INDEX(encoded_ct[i * 2])] * 16 + atoi16[ARCH_INDEX(encoded_ct[i * 2 + 1])];
		psalt->blob = psalt->raw_data;
		psalt->pack_size = 16;
	} else {
		char *p = strtokm(NULL, "*");
		char crc_c[4];
		unsigned long long pack_size;
		unsigned long long unp_size;

		for (i = 0; i < 4; i++)
			crc_c[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		pack_size = atoll(strtokm(NULL, "*"));
		unp_size = atoll(strtokm(NULL, "*"));
		ex_len = pack_size;

		/* load ciphertext. We allocate and load all files
		   here, and they are freed when password found. */
		psalt = mem_calloc(1, sizeof(*psalt) + ex_len);

		psalt->type = type;
		memcpy(psalt->salt, tmp_salt, 8);
		psalt->pack_size = pack_size;
		psalt->unp_size = unp_size;
		memcpy(psalt->crc.c, crc_c, 4);

		p = strtokm(NULL, "*");
		psalt->method = atoi16[ARCH_INDEX(p[0])] * 16 +
			atoi16[ARCH_INDEX(p[1])];
		if (psalt->method != 0x30) {
#if ARCH_LITTLE_ENDIAN
			psalt->crc.w = ~psalt->crc.w;
#else
			psalt->crc.w = JOHNSWAP(~psalt->crc.w);
#endif
		}

		p = strtokm(NULL, "*");	/* blob hash */

		assert(pack_size <= split_size);
		memcpy(psalt->raw_data, split_blob, psalt->pack_size);
		{
			MD5_CTX ctx;
			unsigned char blob_hash[16], hash[16];
			int i;

			MD5_Init(&ctx);
			MD5_Update(&ctx, psalt->raw_data, psalt->pack_size);
			MD5_Final(hash, &ctx);

			for (i = 0; i < 16; i++) {
				blob_hash[i] = atoi16[ARCH_INDEX(*p++)] << 4;
				blob_hash[i] |=	atoi16[ARCH_INDEX(*p++)];
			}
			dump_stuff_msg("\nstored", blob_hash, 16);
			dump_stuff_msg("found ", hash, 16);
			assert(!memcmp(blob_hash, hash, 16));
		}
		psalt->blob = psalt->raw_data;
	}
	MEM_FREE(keep_ptr);

	psalt->dsalt.salt_alloc_needs_free = 1;
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(rarfile, salt);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(rarfile, salt, raw_data, 0);
	memcpy(ptr, &psalt, sizeof(rarfile*));
	return (void*)ptr;
}

static void set_salt(void *salt)
{
	cur_file = *((rarfile**)salt);
	memcpy(saved_salt, cur_file->salt, 8);
#ifdef RAR_OPENCL_FORMAT
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE,
	                                    0, 8, saved_salt, 0, NULL, NULL),
	               "failed in clEnqueueWriteBuffer saved_salt");
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int mode;

	if (strncmp(ciphertext, "$RAR3$*", 7))
		return 0;
	if (!(ctcopy = strdup(ciphertext))) {
		fprintf(stderr, "Memory allocation failed in %s, unable to check if hash is valid!", FORMAT_LABEL);
		return 0;
	}
	keeptr = ctcopy;
	ctcopy += 7;
	if (!(ptr = strtokm(ctcopy, "*"))) /* -p or -h mode */
		goto error;
	if (strlen(ptr) != 1 || !isdec(ptr))
		goto error;
	mode = atoi(ptr);
	if (mode > 2)
		goto error;
	if (mode == 1 && !ldr_in_pot) {
		static int is_warned;

		if (!is_warned++)
			fprintf(stderr, "RAR type '$RAR3$1' is no longer supported. Re-run"
			        " rar2john on this file!\n");
	}
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (hexlenl(ptr) != 16) /* 8 bytes of salt */
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (mode == 0) {
		if (hexlenl(ptr) != 32) /* 16 bytes of encrypted known plain */
			goto error;
		MEM_FREE(keeptr);
		return 1;
	} else {
		long long plen, ulen;

		if (hexlenl(ptr) != 8) /* 4 bytes of CRC */
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* pack_size */
			goto error;
		if (strlen(ptr) > 12) { // pack_size > 1 TB? Really?
			static int warn_once_pack_size = 1;
			if (warn_once_pack_size) {
				fprintf(stderr, "pack_size > 1TB not supported (%s)\n", FORMAT_NAME);
				warn_once_pack_size = 0;
			}
			goto error;
		}
		if ((plen = atoll(ptr)) < 16)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* unp_size */
			goto error;
		if (strlen(ptr) > 12) {
			static int warn_once_unp_size = 1;
			if (warn_once_unp_size) {
				fprintf(stderr, "unp_size > 1TB not supported (%s)\n", FORMAT_NAME);
				warn_once_unp_size = 0;
			}
			goto error;
		}
		if ((ulen = atoll(ptr)) < 1)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* method */
			goto error;
		if (strlen(ptr) != 2 || !isdec(ptr))
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* blob hash */
			goto error;
		if (hexlenl(ptr) != 32)
			goto error;
		if (!ldr_in_pot) {
			if (!(ptr = strtokm(NULL, "*"))) /* blob */
				goto error;
			if (mode == 0) {
				if (hexlenl(ptr) != plen * 2)
					goto error;
			} else {
				if (base64_valid_length(ptr, e_b64_mime, flg_Base64_NO_FLAGS) != (plen * 4 + 2) / 3)
					goto error;
			}
		}
	}

	if (strtokm(NULL, "*")) /* should be no more field */
		goto error;

	MEM_FREE(keeptr);
	return 1;

error:
#ifdef RAR_DEBUG
	{
		char buf[68];
		strnzcpy(buf, ciphertext, sizeof(buf));
		fprintf(stderr, "rejecting %s\n", buf);
	}
#endif
	MEM_FREE(keeptr);
	return 0;
}

/* Drop the blob from the ciphertext */
static char* split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[128];
	char *d, *p = strrchr(ciphertext, '*');
	size_t len = p - ciphertext;

	if (ciphertext[7] != '2' || ldr_in_pot)
		return ciphertext;

	MEM_FREE(split_blob);

	split_size = strlen(++p) * 3 / 4;
	split_blob = d = mem_alloc(split_size);
	base64_convert(p, e_b64_mime, split_size * 4 / 3,
	               d, e_b64_raw, split_size, flg_Base64_NO_FLAGS);
	assert(len < sizeof(out));

	strnzcpy(out, ciphertext, len + 1);

	return out;
}


static char *get_key(int index)
{
	UTF16 tmpbuf[PLAINTEXT_LENGTH + 1];

	memcpy(tmpbuf, &((UTF16*) saved_key)[index * PLAINTEXT_LENGTH], saved_len[index]);
	memset(&tmpbuf[saved_len[index] >> 1], 0, 2);
	return (char*) utf16_to_enc(tmpbuf);
}

#define ADD_BITS(n)	\
	{ \
		if (bits < 9) { \
			hold |= ((unsigned int)*next++ << (24 - bits)); \
			bits += 8; \
		} \
		hold <<= n; \
		bits -= n; \
	}

/*
 * This function is loosely based on JimF's check_inflate_CODE2() from
 * pkzip_fmt. Together with the other bit-checks, we are rejecting over 96%
 * of the candidates without resorting to a slow full check (which in turn
 * may reject semi-early, especially if it's a PPM block)
 *
 * Input is first 16 bytes of RAR buffer decrypted, as-is. It also contain the
 * first 2 bits, which have already been decoded, and have told us we had an
 * LZ block (RAR always use dynamic Huffman table) and keepOldTable was not set.
 *
 * RAR use 20 x (4 bits length, optionally 4 bits zerocount), and reversed
 * byte order.
 */
static MAYBE_INLINE int check_huffman(unsigned char *next) {
	unsigned int bits, hold, i;
	int left;
	unsigned int ncount[4];
	unsigned char *count = (unsigned char*)ncount;
	unsigned char bit_length[20];
#ifdef DEBUG
	unsigned char *was = next;
#endif

#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
	hold = JOHNSWAP(*(unsigned int*)next);
#else
	hold = next[3] + (((unsigned int)next[2]) << 8) +
		(((unsigned int)next[1]) << 16) +
		(((unsigned int)next[0]) << 24);
#endif
	next += 4;	// we already have the first 32 bits
	hold <<= 2;	// we already processed 2 bits, PPM and keepOldTable
	bits = 32 - 2;

	/* First, read 20 pairs of (bitlength[, zerocount]) */
	for (i = 0 ; i < 20 ; i++) {
		int length, zero_count;

		length = hold >> 28;
		ADD_BITS(4);
		if (length == 15) {
			zero_count = hold >> 28;
			ADD_BITS(4);
			if (zero_count == 0) {
				bit_length[i] = 15;
			} else {
				zero_count += 2;
				while (zero_count-- > 0 &&
				       i < sizeof(bit_length) /
				       sizeof(bit_length[0]))
					bit_length[i++] = 0;
				i--;
			}
		} else {
			bit_length[i] = length;
		}
	}

#ifdef DEBUG
	if (next - was > 16) {
		fprintf(stderr, "*** (possible) BUG: check_huffman() needed %u bytes, we only have 16 (bits=%d, hold=0x%08x)\n", (int)(next - was), bits, hold);
		dump_stuff_msg("complete buffer", was, 16);
		error();
	}
#endif

	/* Count the number of codes for each code length */
	memset(count, 0, 16);
	for (i = 0; i < 20; i++) {
		++count[bit_length[i]];
	}

	count[0] = 0;
	if (!ncount[0] && !ncount[1] && !ncount[2] && !ncount[3])
		return 0; /* No codes at all */

	left = 1;
	for (i = 1; i < 16; ++i) {
		left <<= 1;
		left -= count[i];
		if (left < 0) {
			return 0; /* over-subscribed */
		}
	}
	if (left) {
		return 0; /* incomplete set */
	}
	return 1; /* Passed this check! */
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static inline void check_rar(int count)
{
	unsigned int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		AES_KEY aes_ctx;
		unsigned char *key = &aes_key[index * 16];
		unsigned char *iv = &aes_iv[index * 16];

		AES_set_decrypt_key(key, 128, &aes_ctx);

		/* AES decrypt, uses aes_iv, aes_key and blob */
		if (cur_file->type == 0) {	/* rar-hp mode */
			unsigned char plain[16];

			AES_cbc_encrypt(cur_file->blob, plain, 16,
			                &aes_ctx, iv, AES_DECRYPT);

			cracked[index] = !memcmp(plain, "\xc4\x3d\x7b\x00\x40\x07\x00", 7);
		} else {
			if (cur_file->method == 0x30) {	/* stored, not deflated */
				CRC32_t crc;
				unsigned char crc_out[4];
				unsigned char plain[0x8000];
				unsigned long long size = cur_file->unp_size;
				unsigned char *cipher = cur_file->blob;

				/* Use full decryption with CRC check.
				   Compute CRC of the decompressed plaintext */
				CRC32_Init(&crc);

				while (size) {
					unsigned int inlen = (size > 0x8000) ? 0x8000 : size;

					AES_cbc_encrypt(cipher, plain, inlen,
					                &aes_ctx, iv, AES_DECRYPT);

					CRC32_Update(&crc, plain, inlen);
					size -= inlen;
					cipher += inlen;
				}
				CRC32_Final(crc_out, crc);

				/* Compare computed CRC with stored CRC */
				cracked[index] = !memcmp(crc_out, &cur_file->crc.c, 4);
			} else {
				const int solid = 0;
				unpack_data_t *unpack_t;
				unsigned char plain[20];
				unsigned char pre_iv[16];

				cracked[index] = 0;

				memcpy(pre_iv, iv, 16);

				/* Decrypt just one block for early rejection */
				AES_cbc_encrypt(cur_file->blob, plain, 16,
				                &aes_ctx, pre_iv, AES_DECRYPT);

				/* Early rejection */
				if (plain[0] & 0x80) {
					// PPM checks here.
					if (!(plain[0] & 0x20) ||  // Reset bit must be set
					    (plain[1] & 0x80))     // MaxMB must be < 128
						goto bailOut;
				} else {
					// LZ checks here.
					if ((plain[0] & 0x40) ||   // KeepOldTable can't be set
					    !check_huffman(plain)) // Huffman table check
						goto bailOut;
				}

				/* Reset stuff for full check */
				AES_set_decrypt_key(key, 128, &aes_ctx);

#ifdef _OPENMP
				unpack_t = &unpack_data[omp_get_thread_num()];
#else
				unpack_t = unpack_data;
#endif
				unpack_t->max_size = cur_file->unp_size;
				unpack_t->dest_unp_size = cur_file->unp_size;
				unpack_t->pack_size = cur_file->pack_size;
				unpack_t->iv = iv;
				unpack_t->ctx = &aes_ctx;
				unpack_t->key = key;

				if (rar_unpack29(cur_file->blob, solid, unpack_t))
					cracked[index] = !memcmp(&unpack_t->unp_crc, &cur_file->crc.c, 4);
bailOut:;
			}
		}
	}
}
