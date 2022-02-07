/*
 * Common code for the STRIP format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "strip_common.h"

struct fmt_tests strip_tests[] = {
	/* test vector created by STRIP for Windows */
	{"$strip$*66cd7a4ff7716f7b86cf587ce18eb39518e096eb152615ada8d007d9f035c20c711e62cbde96d8c3aad2a4658497a6119addc97ed3c970580cd666f301c63ce041a1748ee5c3861ada3cd6ee75b5d68891f731b3c2e3294b08e10ce3c23c2bfac158f8c45d0332791f64d1e3ad55e936d17a42fef5228e713b8188050c9a61c7f026af6203172cf2fc54c8b439e2260d7a00a4156713f92f8466de5c05cd8701e0d3d9cb3f392ae918e6900d5363886d4e1ed7e90da76b180ef9555c1cd358f6d1ee3755a208fee4d5aa1c776a0888200b21a3da6614d5fe2303e78c09563d862d19deecdc9f0ec7fbc015689a74f4eb477d9f22298b1b3f866ca4cb772d74821a1f8d03fd5fd0d020ffd41dd449b431ddf3bbfba3399311d9827be428202ee56e2c2a4e91f3415b4282c691f16cd447cf877b576ab963ea4ea3dc7d8c433febdc36607fd2372c4165abb59e3e75c28142f1f2575ecca6d97a9f782c3410151f8bbcbc65a42fdc59fdc4ecd8214a2bbd3a4562fac21c48f7fc69a4ecbcf664b4e435d7734fde5494e4d80019a0302e22565ed6a49b29cecf81077fd92f0105d18a421e04ee0deaca6389214abc7182db7003da7e267816531010b236eadfea20509718ff743ed5ad2828b6501dd84a371feed26f0514bbda69118a69048ebb71e3e2c54fb918422f1320724a353fe8d81a562197454d2c67443be8a4008a756aec0998386a5fd48e379befe966b42dfa6684ff049a61b51de5f874a12ab7d9ab33dc84738e036e294c22a07bebcc95be9999ab988a1fa1c944ab95be970045accb661249be8cc34fcc0680cb1aff8dfee21f586c571b1d09bf370c6fc131418201e0414acb2e4005b0b6fda1f3d73b7865823a008d1d3f45492a960dbdd6331d78d9e2e6a368f08ee3456b6d78df1d5630f825c536fff60bad23fb164d151d80a03b0c78edbfdee5c7183d7527e289428cf554ad05c9d75011f6b233744f12cd85fbb62f5d1ae22f43946f24a483a64377bf3fa16bf32cea1ab4363ef36206a5989e97ff847e5d645791571b9ecd1db194119b7663897b9175dd9cc123bcc7192eaf56d4a2779c502700e88c5c20b962943084bcdf024dc4f19ca649a860bdbd8f8f9b4a9d03027ae80f4a3168fc030859acb08a871950b024d27306cdc1a408b2b3799bb8c1f4b6ac3593aab42c962c979cd9e6f59d029f8d392315830cfcf4066bf03e0fc5c0f3630e9c796ddb38f51a2992b0a61d6ef115cb34d36c7d94b6c9d49dfe8d064d92b483f12c14fa10bf1170a575e4571836cef0a1fbf9f8b6968abda5e964bb16fd62fde1d1df0f5ee9c68ce568014f46f1717b6cd948b0da9a6f4128da338960dbbcbc9c9c3b486859c06e5e2338db3458646054ccd59bb940c7fc60cda34f633c26dde83bb717b75fefcbd09163f147d59a6524752a47cd94", "openwall"},
	/* test vector created by STRIP Password Manager (for Android) */
	{"$strip$*78adb0052203efa1bd1b02cac098cc9af1bf7e84ee2eaebaaba156bdcfe729ab12ee7ba8a84e79d11dbd67eee82bcb24be99dbd5db7f4c3a62f188ce4b48edf4ebf6cbf5a5869a61f83fbdb3cb4bf79b3c2c898f422d71eab31afdf3a8d4e97204dedbe7bd8b5e4c891f4880ca917c8b2f67ca06035e7f8db1fae91c45db6a08adf96ec5ddcb9e60b648acf883a7550ea5b67e2d27623e8de315f29cba48b8b1d1bde62283615ab88293b29ad73ae404a42b13e35a95770a504d81e335c00328a6290e411fa2708a697fab7c2d17ff5d0a3fe508118bb43c3d5e72ef563e0ffd337f559085a1373651ca2b8444f4437d8ac0c19aa0a24b248d1d283062afbc3b4ccc9b1861f59518eba771f1d9707affe0222ff946da7c014265ab4ba1f6417dd22d92e4adf5b7e462588f0a42e061a3dad041cbb312d8862aed3cf490df50b710a695517b0c8771a01f82db09231d392d825f5667012e349d2ed787edf8448bbb1ff548bee3a33392cd209e8b6c1de8202f6527d354c3858b5e93790c4807a8967b4c0321ed3a1d09280921650ac33308bd04f35fb72d12ff64a05300053358c5d018a62841290f600f7df0a7371b6fac9b41133e2509cb90f774d02e7202185b9641d063ed38535afb81590bfd5ad9a90107e4ff6d097ac8f35435f307a727f5021f190fc157956414bfce4818a1e5c6af187485683498dcc1d56c074c534a99125c6cfbf5242087c6b0ae10971b0ff6114a93616e1a346a22fcac4c8f6e5c4a19f049bbc7a02d2a31d39548f12440c36dbb253299a11b630e8fd88e7bfe58545d60dce5e8566a0a190d816cb775bd859b8623a7b076bce82c52e9cff6a2d221f9d3fd888ac30c7e3000ba8ed326881ffe911e27bb8982b56caa9a12065721269976517d2862e4a486b7ed143ee42c6566bba04c41c3371220f4843f26e328c33a5fb8450dadc466202ffc5c49cc95827916771e49e0602c3f8468537a81cf2fa1db34c090fccab6254436c05657cf29c3c415bb22a42adeac7870858bf96039b81c42c3d772509fdbe9a94eaf99ee9c59bac3ea97da31e9feac14ed53a0af5c5ebd2e81e40a5140da4f8a44048d5f414b0ba9bfb8024c7abaf5346fde6368162a045d1196f81d55ed746cc6cbd7a7c9cdbfa392279169626437da15a62730c2990772e106a5b84a60edaa6c5b8030e1840aa6361f39a12121a1e33b9e63fb2867d6241de1fb6e2cd1bd9a78c7122258d052ea53a4bff4e097ed49fc17b9ec196780f4c6506e74a5abb10c2545e6f7608d2eefad179d54ad31034576be517affeb3964c65562538dd6ea7566a52c75e4df593895539609a44097cb6d31f438e8f7717ce2bf777c76c22d60b15affeb89f08084e8f316be3f4aefa4fba8ec2cc1dc845c7affbc0ce5ebccdbfde5ebab080a285f02bdfb76c6dbd243e5ee1e5d", "p@$$w0rD"},
	{NULL}
};

int strip_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$strip$" and first '*' */
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt + data */
		goto err;
	if (hexlenl(p, &extra) != 2048 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *strip_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$strip$" and first '*' */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < 16; i++)
			cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		for (; i < 1024; i++)
			cs.data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

/* Verify validity of a page */
int strip_verify_page(unsigned char *page1)
{
	uint32_t pageSize;
	uint32_t usableSize;

	//if (memcmp(page1, SQLITE_FILE_HEADER, 16) != 0) {
	//	return -1;
	//}

	if (page1[19] > 2) {
		return -1;
	}
	if (memcmp(&page1[21], "\100\040\040", 3) != 0) {
		return -1;
	}
	pageSize = (page1[16] << 8) | (page1[17] << 16);
	if (((pageSize - 1) & pageSize) != 0 || pageSize > SQLITE_MAX_PAGE_SIZE || pageSize <= 256) {
		return -1;
	}

	if ((pageSize & 7) != 0) {
		return -1;
	}
	usableSize = pageSize - page1[20];

	if (usableSize < 480) {
		return -1;
	}
	return 0;
}
