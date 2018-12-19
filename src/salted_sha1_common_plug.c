/*
 * salted_sha1 cracker patch for JtR, common code. 2015 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#include "arch.h"
#include "formats.h"
#include "base64_convert.h"
#include "salted_sha1_common.h"

struct fmt_tests salted_sha1_common_tests[] = {
// Test hashes originally(?) in OPENLDAPS_fmt (openssha) (salt length 4)
	{"{SSHA}bPXG4M1KkwZh2Hbgnuoszvpat0T/OS86", "thales"},
	{"{SSHA}hHSEPW3qeiOo5Pl2MpHQCXh0vgfyVR/X", "test1"},
	{"{SSHA}pXp4yIiRmppvKYn7cKCT+lngG4qELq4h", "test2"},
	{"{SSHA}Bv8tu3wB8WTMJj3tcOsl1usm5HzGwEmv", "test3"},
	{"{SSHA}kXyh8wLCKbN+QRbL2F2aUbkP62BJ/bRg", "lapin"},
	{"{SSHA}rnMVxsf1YJPg0L5CBhbVLIsJF+o/vkoE", "canard"},
	{"{SSHA}Uf2x9YxSWZZNAi2t1QXbG2PmT07AtURl", "chien"},
	{"{SSHA}XXGLZ7iKpYSBpF6EwoeTl27U0L/kYYsY", "hibou"},
	{"{SSHA}HYRPmcQIIzIIg/c1L8cZKlYdNpyeZeml", "genou"},
	{"{SSHA}Zm/0Wll7rLNpBU4HFUKhbASpXr94eSTc", "caillou"},
	{"{SSHA}Qc9OB+aEFA/mJ5MNy0AB4hRIkNiAbqDb", "doudou"},

// Test vectors originally in NSLDAPS_fmt (ssha) (salt length 8)
	{"{SSHA}WTT3B9Jjr8gOt0Q7WMs9/XvukyhTQj0Ns0jMKQ==", "Password9"},
	{"{SSHA}ypkVeJKLzbXakEpuPYbn+YBnQvFmNmB+kQhmWQ==", "qVv3uQ45"},
	{"{SSHA}cKFVqtf358j0FGpPsEIK1xh3T0mtDNV1kAaBNg==", "salles"},
	{"{SSHA}W3ipFGmzS3+j6/FhT7ZC39MIfqFcct9Ep0KEGA==", "asddsa123"},
	{"{SSHA}YbB2R1D2AlzYc9wk/YPtslG7NoiOWaoMOztLHA==", "ripthispassword"},

/*
 * These two were found in john-1.6-nsldaps4.diff.gz
 */
	{"{SSHA}/EExmSfmhQSPHDJaTxwQSdb/uPpzYWx0ZXI=", "secret"},
	{"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0", "secret"},

	{"{SSHA}zTYIHsq8ygmPTPPjoeNVXfKtEthEMXNCMU9jcURy", ""},
	// from opencl_nsldaps_fmt_plug.c
	{"{SSHA}8VKmzf3SqceSL8/CJ0bGz7ij+L0SQCxcHHYzBw==", "mabelove"},
	{"{SSHA}91PzTv0Wjs/QVzbQ9douCG3HK8gpV1ocqgbZUg==", "12345678"},
	{"{SSHA}DNPSSyXT0wzh4JiiX1D8RnltILQzUlFBuhKFcA==", "wildstar"},
	{"{SSHA}yVEfRVwCJqVUBgLvgM89ExKgcfZ9QEFQgmobJg==", "zanzibar"},
	{"{SSHA}y9Nc5vOnK12ppTjHo35lxM1pMFnLZMwqqwH6Eg==", "00000000"},
	{NULL}
};

int salted_sha1_common_valid(char *ciphertext, struct fmt_main *self)
{
	int len, real_len;
	char buf[MAX_SALT_LEN+BINARY_SIZE+8];

	if (strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH))
		return 0;
	ciphertext += NSLDAP_MAGIC_LENGTH;

	len = base64_valid_length(ciphertext, e_b64_mime, 0, 0);
	if (len > CIPHERTEXT_LENGTH)
		return 0;
	if (len <= CIPHERTEXT_LEN_MIN)
		return 0;
	// Note, the +4 here allows us to decode something larger, so that we know the salt is too long.
	real_len = base64_convert(ciphertext, e_b64_mime, strlen(ciphertext), buf, e_b64_raw, MAX_SALT_LEN+BINARY_SIZE+4, 0, 0);
	if (real_len <= BINARY_SIZE || real_len > MAX_SALT_LEN+BINARY_SIZE)
		return 0;
	// there should be NOTHING following the base64 string.
	while (ciphertext[len] == '=')
		++ len;
	if (ciphertext[len])
		return 0;

	return 1;
}
