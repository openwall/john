/*
 * This software is Copyright (c) 2025 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#include "o5logon_common.h"

struct fmt_tests o5logon_tests[] = {
	{"$o5logon$566499330E8896301A1D2711EFB59E756D41AF7A550488D82FE7C8A418E5BE08B4052C0DC404A805C1D7D43FE3350873*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$3BB71A77E1DBB5FFCCC8FC8C4537F16584CB5113E4CCE3BAFF7B66D527E32D29DF5A69FA747C4E2C18C1837F750E5BA6*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$ED91B97A04000F326F17430A65DACB30CD1EF788E6EC310742B811E32112C0C9CC39554C9C01A090CB95E95C94140C28*7FD52BC80AA5836695D4", "test1"},
	{"$o5logon$B7711CC7E805520CEAE8C1AC459F745639E6C9338F192F92204A9518B226ED39851C154CB384E4A58C444A6DF26146E4*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$76F9BBAEEA9CF70F2A660A909F85F374F16F0A4B1BE1126A062AE9F0D3268821EF361BF08EBEF392F782F2D6D0192FD6*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$C35A36EA7FF7293EF828B2BD5A2830CA28A57BF621EAE14B605D41A88FC2CF7EFE7C73495FB22F06D6D98317D63DDA71*406813CBAEED2FD4AD23", "MDDATA"},
	{"$o5logon$B9AC30E3CD7E1D7C95FA17E1C62D061289C36FD5A6C45C098FF7572AB9AD2B684FB7E131E03CE1543A5A99A30D68DD13*447BED5BE70F7067D646", "sys"},
	// the following hash (from HITCON 2014 CTF) revealed multiple bugs in this format (false positives)!
	// m3odbe
	// m3o3rt
	{"$o5logon$A10D52C1A432B61834F4B0D9592F55BD0DA2B440AEEE1858515A646683240D24A61F0C9366C63E93D629292B7891F44A*878C0B92D61A594F2680", "m3ow00"},
	{"$o5logon$52696131746C356643796B6D716F46474444787745543263764B725A6D756A69E46DE32AFBB33E385C6D9C7031F4F2B9*3131316D557239736A65", "123456"},
	{"$o5logon$4336396C304B684638634450576B30397867704F54766D71494F676F5A5A386F09F4A10B5908B3ED5B1D6878A6C78751*573167557661774E7271", ""},

	// The below are Oracle 12 hashes
	{"$o5logon$4D04DBD23D103F05D9B57EB6EC14D83A0A468AB906EAC907D3A8C796573E5F34BC15F0ECBC9EAC0350A38A663A368233*442192E518F6F43D7CF7*D3963B6AAED39C231BD5C92A10C0F146CA4784D1503A9B97598B31D33406390B7CA4F8B3EE5406A54C1842E4E63D1220*192AB7C9BA21C883824CF3D5BA073AC1129FD841E0AF6DF522C7EBDC52783CB8B97B792BFB6D9D743C7F4376FF0E7F93", "password1234567890"},
	{"$o5logon$475FEF5BD6E8BCD9972935CE0A857B0B928438B0E4662588384F164801E59373490674B58039AEA2FDBB814C2496EA35*3D14D54520BC9E6511F4*BD0B6E2FD58320CA4B0516A21EF2AF70B61E5ACFC3EE4D5D6E5C492A7932D09C*80A1EADECBD79D1F70221AD8081FD201B92699151735499F42AD36A028A6A836D46AA81F0E27AC7E68CC66619F1F4D56", "openwall"},
	{"$o5logon$8D032D2C3AAB74E34ADABE9D4E62A3B19029DB37054665A004435DAF0B6C571A16DFE69C232923A1685414307DC01D88*681D0B32B396420D5914*EA974D3A9D7ECDC7316E03772847A9960E7DE5D86D416781072A36A6B7DBB430*0B8297E48756AA562F369651C18B73A5FEAA89151787298A4116E66090B6B72535154AE28B5D29DFA8740706D74FC49A", "password"},
	{NULL}
};

int o5logon_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*"); /* server's sesskey */
	if (!p)
		goto err;
	if (hexlenu(p, &extra) != CIPHERTEXT_LENGTH * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenu(p, &extra) != SALT_LENGTH * 2 || extra)
		goto err;
	/* optional fields follow */
	if ((p = strtokm(NULL, "*"))) {	/* client's encrypted password */
		int len = hexlenu(p, &extra);

		if (extra || len < 64 || len % 32 || len > 2 * (PLAINTEXT_LENGTH + 16))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* client's sesskey */
			goto err;
		if (hexlenu(p, &extra) != CIPHERTEXT_LENGTH * 2 || extra)
			goto err;
	}
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *o5logon_get_salt(char *ciphertext)
{
	static o5logon_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$o5logon$" */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < SALT_LENGTH; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs.salt[SALT_LENGTH] = 0x80;
	memset(&cs.salt[SALT_LENGTH + 1], 0, sizeof(cs.salt) - (SALT_LENGTH + 1));

	/* Oracle 12 hashes may have more fields (optional for older ver) */
	if ((p = strtokm(NULL, "*"))) {
		cs.pw_len = hexlenu(p, 0) / 2 / 16 - 1;
		for (i = 0; p[i * 2]; i++)
			cs.pw[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < CIPHERTEXT_LENGTH; i++)
			cs.csk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);
	return (void *)&cs;
}
