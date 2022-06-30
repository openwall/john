/*
 * Common "variable" code for the BitLocker format.
 */

#define BITLOCKER_ITERATION_NUMBER              0x100000  // duplicated here

static struct fmt_tests bitlocker_tests[] = {
	// Two artificial hashes to ease development and testing work
	//{"$bitlocker$0$16$134bd2634ba580adc3758ca5a84d8666$500$12$9080903a0d9dd20103000000$60$99919e1e955b55f75f2f16eb0af96f2d605630a49879d8f2458e390ef87722ae346e391be3e1c6d9af425a576dac155ad306e9ce7a407dd2ab431102", "openwall@123"},
	//{"$bitlocker$0$16$73926f843bbb41ea2a89a28b114a1a24$500$12$30a81ef90c9dd20103000000$60$96461b121c7a42c454492162042586ea7848c5b09fdb58234f60c06ebf74b2e1ca6dec0b7f3958e32fa2c50f8772ca0a2227bad8ea10fce03fe07b6c", "password@123"},
	// Windows 10 generated BitLocker image
	{"$bitlocker$0$16$134bd2634ba580adc3758ca5a84d8666$1048576$12$9080903a0d9dd20103000000$60$0c52fdd87f17ac55d4f4b82a00b264070f36a84ead6d4cd330368f7dddfde1bdc9f5d08fa526dae361b3d64875f76a077fe9c67f44e08d56f0131bb2", "openwall@123"},
	// Same test with MAC verification
	{"$bitlocker$1$16$134bd2634ba580adc3758ca5a84d8666$1048576$12$9080903a0d9dd20103000000$60$0c52fdd87f17ac55d4f4b82a00b264070f36a84ead6d4cd330368f7dddfde1bdc9f5d08fa526dae361b3d64875f76a077fe9c67f44e08d56f0131bb2", "openwall@123"},
	// Windows 10
	{"$bitlocker$0$16$73926f843bbb41ea2a89a28b114a1a24$1048576$12$30a81ef90c9dd20103000000$60$942f852f2dc4ba8a589f35e750f33a5838d3bdc1ed77893e02ae1ac866f396f8635301f36010e0fcef0949078338f549ddb70e15c9a598e80c905baa", "password@123"},
	// Windows 8.1
	{"$bitlocker$0$16$5e0686b4e7ce8a861b75bab3e8f1d424$1048576$12$90928da8c019d00103000000$60$ee5ce06cdc89b9fcdcd24bb854842fc8b715bb36c86c19e73ddb8a409718cac412f0416a51b1e0472fad8edb34d9208dd874dcadbf4779aaf01dfa74", "openwall@123"},
	// Windows 8.1
	{"$bitlocker$0$16$7b5c9407857f6d590a0d4dcf56d503a6$1048576$12$b02d06c0c019d00103000000$60$1af24981790bd0cc0d00b86b9893c0fdc63b20f0631e85f206b2af3c2c64f77bac2ec9379a4df51967c82033ed9661bace0e63c7dec4f9ef0cc27c5a", "openwall@12345"},
	// Windows 10 "BitLocker To Go"
	{"$bitlocker$0$16$9079aaee7be0923b529f069012f30b13$1048576$12$40ea50c2b79fd20103000000$60$caca601f042fae0eb697593e559760f8209d495ed0b61eda9c83a79f0abb3f598853b6f89cdffd3b5b66b90b321b822c90c8ef5dac464ef6edd06881", "weakpassword12345"},
	// Windows 10 "BitLocker To Go", XTS-AES disk encryption mode
	{"$bitlocker$0$16$c971c02f4f7bb07a196ff8cdf6a3f588$1048576$12$00bf2f62c726d30103000000$60$000000000000000000000000000000001f7b4f5bfb33b1261d9134e2b37039b1a6955748f43207cccb1adfe14c2347e288d36b5384df57099f57cd41", "aaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 27 a's
#ifdef CPU_FORMAT
	{"$bitlocker$0$16$c7258b6a1824c5f57e7456d8304c9bb2$1048576$12$f0b876adc826d30103000000$60$00000000000000000000000000000000695f6c513124321aaf9d27fa1330c03445a34401a430b0fcfb258cbb53d1af466f06ef8127ef37bef2787c81", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 64 a's
#endif
#ifndef CPU_FORMAT
	// Windows 10, Recovery Password attack
	{"$bitlocker$2$16$432dd19f37dd413a88552225628c8ae5$1048576$12$a0da3fc75f6cd30106000000$60$3e57c68216ef3d2b8139fdb0ec74254bdf453e688401e89b41cae7c250739a8b36edd4fe86a597b5823cf3e0f41c98f623b528960a4bee00c42131ef", "111683-110022-683298-209352-468105-648483-571252-334455"},
	// Same test with MAC verification
	{"$bitlocker$3$16$432dd19f37dd413a88552225628c8ae5$1048576$12$a0da3fc75f6cd30106000000$60$3e57c68216ef3d2b8139fdb0ec74254bdf453e688401e89b41cae7c250739a8b36edd4fe86a597b5823cf3e0f41c98f623b528960a4bee00c42131ef", "111683-110022-683298-209352-468105-648483-571252-334455"},
#endif
	{NULL}
};

static void *bitlocker_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i, j;
	char *p;
	static bitlocker_custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(bitlocker_custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // version
	// UP or RP with or without MAC verification
	cs->attack_type = atoi(p);
	p = strtokm(NULL, "$"); // salt length
	cs->salt_length = atoi(p);
	p = strtokm(NULL, "$"); // salt
	for (i = 0; i < cs->salt_length; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // iterations
	cs->iterations = atoi(p);
	p = strtokm(NULL, "$"); // nonce length
	p = strtokm(NULL, "$"); // nonce
	for (i = 0; i < IVLEN; i++)
		cs->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // data_size
	cs->data_size = atoi(p);
	p = strtokm(NULL, "$"); // data
	for (j = 0; j < MACLEN; j++)
		cs->mac[j] = atoi16[ARCH_INDEX(p[j * 2])] * 16
			+ atoi16[ARCH_INDEX(p[j * 2 + 1])];
#ifdef CPU_FORMAT  // just modifying the offsets of the decrypted data doesn't work => maybe our first block decryption is wrong?
	for (i = 0; i < cs->data_size; i++)
		cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
#else
	for (j = 0, i = MACLEN; i < cs->data_size; j++, i++)
		cs->data[j] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
#endif

	MEM_FREE(keeptr);

	return (void *)cs;
}

static int bitlocker_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;
	int salt_length;
	unsigned int iterations;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version, for future purposes
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
#ifdef CPU_FORMAT
	if (
		value != BITLOCKER_HASH_UP      &&
		value != BITLOCKER_HASH_UP_MAC
	)
		goto err;
#else
	if (
		value != BITLOCKER_HASH_UP      &&
		value != BITLOCKER_HASH_UP_MAC  &&
		value != BITLOCKER_HASH_RP      &&
		value != BITLOCKER_HASH_RP_MAC
	)
		goto err;
#endif
	if ((p = strtokm(NULL, "$")) == NULL)   // salt length
		goto err;
	if (!isdec(p))
		goto err;
	salt_length = atoi(p);
	if (salt_length != SALTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != salt_length * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	iterations = atoi(p);
	if (iterations > BITLOCKER_ITERATION_NUMBER)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // nonce length
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 12) // iv or nonce length is known to be 12 for aes-ccm mode in bitlocker
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // nonce
		goto err;
	if (hexlenl(p, &extra) != value * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // length of data encrypted by aes_ccm key
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)   // data encrypted by aes_ccm key, contains encrypted volume master key (vmk)
		goto err;
	if (value > MAX_DATALEN)
		goto err;
	if (hexlenl(p, &extra) != value * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}
