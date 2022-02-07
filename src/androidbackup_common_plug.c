/*
 * Common code for the Android Backup format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "arch.h"
#include "androidbackup_common.h"
#include "jumbo.h"

struct fmt_tests ab_tests[] = {
	// Android 6.0 device
	{"$ab$3*0*10000*2a7c948fd7124307bca8d7ac921a9f019f32b0f74f484cfe9266f3ee0da064fc8a57b1c9e2edf66b8425448d064ef121a453c8941a024dbdfc7481bfbc47437e*3bbd3f57551336c7db480cbdc3dc5ce3da4e185a586a3fd45b816007c2c41889149fbf0e292f88b1207d070d10e577c021dabd0ed8ba8ea6849b0d311942eb37*469920775ce354235ad62500184754d7*749ae8a777d30ea4913084a8266f9f740dfc0a78d545aafb0a39051519a610db5f3d5f68cdaff7f04a74645e8a7b0c5c965d978f4a2fa0650854ab120bb9f683b494a6dcb84d3b74960a6a413fe83648f118e152bad23ab1be294912e357b3b9", "openwall"},
	{"$ab$3*0*10000*dc4e8723d6c1ac065878dc6428e8ad08d3912cf7f1757007a6c6793ee0c6af57c4604a0e2afb4d201d98f7cab1f24927f9319344aa25e28782b2ea8e627f1cc9*d1eb72793eae5d7e28c20e3d142c2c7cdb363e92fb03c3a6444152f83f0edbfc31a8447761074e85ecf6e07341893b9864861015139b9cd20b9474b9a96bf0c7*862f63c48ef68b0f28d784bd81f28f68*6a185cd6b9d4a44470845b9366f10881d7549b0e5d353309ac3b155ca22d8f0064a10c16919472fc6540a49472d1d9adc7f510fdc5906719b8c8aaac492433f7242186314384fd013c37cb4bc646bcb184a37c7091273ff5b54f5485a30eabe0", "password"},
	{"$ab$3*0*10000*6a2b625432affe69b7bec924c643462c1bb47f8270ea32c3f4fe371f7646b51fa5bd3b13592143bd1a03f67bb73f17c0edbaa68f9de8d88190dbf2bc1a51e121*4b8a71cb21ab4510ddf0fbcfa049c4f046baa492b51efbc7d12499c6d2d794443c8d1f19dee8bef088dd7e1951d1215207594f828e53dd5734a9c1be1c0b350c*161cc825bb9c3025b8f81b9a1dccd1d9*9424dfd7d445e3be505a8905565ed3c4359492b0f8b079a8d4ba57d72a9489c0be6e87f51d20c6544152fded3de91bdc5a74966a54d6261190f6379bc8d0a39b2eb6ebeb1768478fdbdf241cc15137111caa00efe8e07ba2c5efcac71f91c101", "åbc"},
	// Android 8.0 device
	{"$ab$5*0*10000*ff4b9c083784b63e1724700f18fad0fac41e9a82fb4fad6b2a2efc35d77359af0e7604f83b011660724159469f2ea5206bd3dce0f7b7fe4b9be1d2bfdb5d4c72*a5ee2fb150351a4882630f71111c4619b31391069241665c81efbcd9d6696018cdbcfb412bfcc24d7e31a7fca2055892b4e64d263a5f47073177c35257b99b41*0b6b9f4463420eb0dbfeb37a90cdc362*238058ca186ffc15b1f8c16d8057cb8ebca600b2971f264a31964a786ebb8af47f9e15244c3aca5403db4481c2f268d36062b929eff12abb87b87a6f4da4de8ef76345777f99c806277123a1d9d3442a4ec7ed9669d5e237425f67454428555c", "hello"},
	// Android 4.4.4 device
	{"$ab$2*0*10000*4acaf4f77074d002b3bcf012def362f9bea95c74b7fbf5447f2f285c4652012152ef0fef4610fa8ed94cd4cb37fa0b4a8b010d40f5ebedff3f76c01a826b10ff*df94321d7554eb9c502b810367933d14f6b9102986e985764bcaffc5b1228c2b610db8315e12bdc852e012d99f0cdc94880ef24a5bdfd0c281b68db25e8b517d*374ef92b1ebddf250420946a64173c0e*fd23ea1d32d23456891a1d101e130d2c7384813c82cfa53928042adc8bf681f70c7e5d8eafe100798dbad34b87470aad54ad4b9d937ae5c5c873adcffcdede502986013ad08914723a21467ff45a7de14b37c808b93ccd9143d2a042055958fe", "old"},
	{"$ab$2*0*10000*3c3915681a460670d7511ddb0c080b838f1d25a473a82544d0b11d10eca66f92c182df30d576f388b2b800003ea06af55cbd59bd59cd236c99a945486f0a7c7b*b1afc57259df27ff5e88acba5eaa8a92bde1a189f6eb9a865b3ba73e1b78f4eb514bfa7e67f98be6715647a708c7b0c78b2be0b263d8fae66bddbf3bceb6eb7e*fb7bc820e2880c48bfd1fd8877ad2e5f*3a1deab93e3d6e0a8689adfcae9ee85a5131147e878f720d4265d9d9b3ce269a1cc01b3634f0dfed2463839b0725a586594d76654bf22e9caf411eed2437f6d7fddd0afa30e797145574b8f13659123665f2a94d21071607811b388714fae728", "åbc"},
	{NULL}
};

int ab_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL)  // version / type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value < 1 || value > 5)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // cipher
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // rounds
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // user_salt
		goto err;
	if (hexlenl(p, &extra) > SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // ck_salt
		goto err;
	if (hexlenl(p, &extra) > SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // user_iv
		goto err;
	if (hexlenl(p, &extra) > IVLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // masterkey_blob
		goto err;
	if (hexlenl(p, &extra) > MAX_MASTERKEYBLOB_LEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *ab_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	p = strtokm(NULL, "*");
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.user_salt_length = strlen(p) / 2;
	for (i = 0; i < cs.user_salt_length; i++)
		cs.user_salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.ck_salt_length = strlen(p) / 2;
	for (i = 0; i < cs.ck_salt_length; i++)
		cs.ck_salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.iv_length = strlen(p) / 2;
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.masterkey_blob_length = strlen(p) / 2;
	for (i = 0; i < cs.masterkey_blob_length; i++)
		cs.masterkey_blob[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

unsigned int ab_iteration_count(void *salt)
{
	struct custom_salt *cs = (struct custom_salt*)salt;

	return cs->iterations;
}
