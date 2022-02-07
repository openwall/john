#include "arch.h"
#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "common.h"
#include "memory.h"
#include "formats.h"
#include "pkzip.h"
#include "loader.h"

/* helper functions for reading binary data of known little endian */
/* format from a file. Works whether BE or LE system.              */
u64 fget64LE(FILE *fp)
{
	u64 v = (u64)fgetc(fp);
	v |= (u64)fgetc(fp) << 8;
	v |= (u64)fgetc(fp) << 16;
	v |= (u64)fgetc(fp) << 24;
	v |= (u64)fgetc(fp) << 32;
	v |= (u64)fgetc(fp) << 40;
	v |= (u64)fgetc(fp) << 48;
	v |= (u64)fgetc(fp) << 56;
	return v;
}

u32 fget32LE(FILE *fp)
{
	u32 v = (u32)fgetc(fp);
	v |= (u32)fgetc(fp) << 8;
	v |= (u32)fgetc(fp) << 16;
	v |= (u32)fgetc(fp) << 24;
	return v;
}

u16 fget16LE(FILE *fp)
{
	u16 v = fgetc(fp);
	v |= fgetc(fp) << 8;
	return v;
}

struct fmt_tests winzip_common_tests[] = {
	{"$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$", "hashcat"},
	{"$zip2$*0*1*0*9ffba76344938a7d*cc41*210*fb28d3fd983302058c5296c07442502ae05bb59adb9eb2378cb0841efa227cd58f7076ec00bb5faaee24c3433763d715461d4e714cdd9d933f621d2cf6ae73d824414ca2126cfc608d8fc7641d2869afa90f28be7113c71c6b6a3ad6d6633173cde9d7c1bb449cc0a1f8cbab8639255684cd25cb363234f865d9224f4065c0c62e5e60c2500bc78fa903630ccbb5816be2ef5230d411051d7bc54ecdf9dcbe500e742da2a699de0ec1f20b256dbcd506f926e91a1066a74b690f9dd50bd186d799deca428e6230957e2c6fcdcec73927d77bb49699a80e9c1540a13899ecb0b635fb728e1ade737895d3ff9babd4927bbbc296ec92bab87fd7930db6d55e74d610aef2b6ad19b7db519c0e7a257f9f78538bb0e9081c8700f7e8cd887f15a212ecb3d5a221cb8fe82a22a3258703f3c7af77ef5ecf25b4e6fb4118b00547c271d9b778b825247a4cd151bff81436997818f9d3c95155910ff152ad28b0857dcfc943e32729379c634d29a50655dc05fb63fa5f20c9c8cbdc630833a97f4f02792fcd6b1b73bfb4d333485bb0eb257b9db0481d11abfa06c2e0b82817d432341f9bdf2385ede8ca5d94917fa0bab9c2ed9d26ce58f83a93d418aa27a88697a177187e63f89904c0b9053151e30a7855252dab709aee47a2a8c098447160c8f96c56102067d9c8ffc4a74cd9011a2522998da342448b78452c6670eb7eb80ae37a96ca15f13018e16c93d515d75e792f49*bd2e946811c4c5b09694*$/zip2$", "hello1"},
	{"$zip2$*0*2*0*c702895e204a15d8016cd436*7688*32*f1e0c797182c9231ebbdfb23111203131d9c949b45396f6ea233ac41c056f938a68869400bc25123bd61f8d7bd4930a6440c*3f229b45b30739ab4867*$/zip2$", "magnum"},
	{"$zip2$*0*3*0*855f69693734c7be8c1093ea5bae6114*f035*210*c02aa1d42cc7623c0746979c6c2ce78e8492e9ab1d0954b76d328c52c4d555fbdc2af52822c7b6f4548fc5cca615cd0510f699d4b6007551c38b4183cafba7b073a5ba86745f0c3842896b87425d5247d3b09e0f9f701b50866e1636ef62ee20343ea6982222434fdaf2e52fe1c90f0c30cf2b4528b79abd2824e14869846c26614d9cbc156964d63041bfab66260821bedc151663adcb2c9ac8399d921ddac06c9a4cd8b442472409356cfe0655c9dbbec36b142611ad5604b68108be3321b2324d5783938e52e5c15ec4d8beb2b5010fad66d8cf6a490370ec86878ad2b393c5aa4523b95ae21f8dd5f0ae9f24581e94793a01246a4cc5a0f772e041b3a604ae334e43fe41d32058f857c227cee567254e9c760d472af416abedf8a87e67b309d30bc94d77ef6617b0867976a4b3824c0c1c4aa2b2668f9eb70c493d20d7fab69436c59e47db40f343d98a3b7503e07969d26afa92552d15009542bf2af9b47f2cfa0c2283883e99d0966e5165850663a2deed557fb8554a16f3a9cb04b9010c4b70576b18695dfea973aa4bc607069a1d90e890973825415b717c7bdf183937fa8a3aa985be1eadc8303f756ebd07f864082b775d7788ee8901bb212e69f01836d45db320ff1ea741fa8a3c13fa49ebc34418442e6bd8b1845c56d5c798767c92a503228148a6db44a08fc4a1c1d55eea73dbb2bd4f2ab09f00b043ee0df740681f5c5579ecbb1dbb7f7f3f67ffe2*c6b781ef18c5ccd83869*$/zip2$", "hello1"},
	{NULL}
};

int winzip_common_valid(char *ciphertext, struct fmt_main *self)
{
	c8 *ctcopy, *keeptr, *p, *cp;
#ifdef ZIP_DEBUG
	const char *sFailStr="Truncated hash, strtokm() returned NULL";
#endif
	uint64_t val;
	int ret = 0;
	static int old_warn = 1;

	if (!strncmp(ciphertext, "$zip$", 5)) {
		if (!old_warn)
			fprintf(stderr, "Warning, Older unhandled WinZip format hash seen. This hash can not be processed\n");
		old_warn = 1;
		return 0;
	}

	if (strncmp(ciphertext, WINZIP_FORMAT_TAG, WINZIP_TAG_LENGTH) || ciphertext[WINZIP_TAG_LENGTH] != '*')
		return 0;
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;

	p = &ctcopy[WINZIP_TAG_LENGTH+1];

	// type
	if ((cp = strtokm(p, "*")) == NULL || !cp || *cp != '0') {
#ifdef ZIP_DEBUG
		sFailStr = "Out of data, reading count of hashes field";
#endif
		goto Bail;
	}

	// mode
	if ((cp = strtokm(NULL, "*")) == NULL || cp[1] || *cp < '1' || *cp > '3') {
#ifdef ZIP_DEBUG
		sFailStr = "Invalid aes mode (only valid for 1 to 3)";
#endif
		goto Bail;
	}
	val = *cp - '0';

	if ((cp = strtokm(NULL, "*")) == NULL)		// file_magic enum (ignored for now, just a place holder)
		goto Bail;
	if (!isdec(cp) || atoi(cp) < 0 || atoi(cp) > 11)
		goto Bail;

	// salt
	if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen((char*)cp) != SALT_LENGTH(val)<<1) {
#ifdef ZIP_DEBUG
		sFailStr = "Salt invalid or wrong length";
#endif
		goto Bail;
	}

	// validator
	if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen((char*)cp) != 4) {
#ifdef ZIP_DEBUG
		sFailStr = "Validator invalid or wrong length (4 bytes hex)";
#endif
		goto Bail;
	}

	// Data len.
	if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
#ifdef ZIP_DEBUG
		sFailStr = "Data length invalid (not hex number)";
#endif
		goto Bail;
	}
	sscanf((const char*)cp, "%"PRIx64, &val);

	if ((cp = strtokm(NULL, "*")) == NULL)		// data blob
		goto Bail;
	if ((*cp && !ishexlc(cp)) || strlen((char*)cp) != val<<1) {
#ifdef ZIP_DEBUG
		sFailStr = "Inline data blob invalid (not hex number), or wrong length";
#endif
		goto Bail;
	}

	// authentication_code
	if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen((char*)cp) != WINZIP_BINARY_SIZE<<1) {
#ifdef ZIP_DEBUG
		sFailStr = "Authentication data invalid (not hex number), or not 20 hex characters";
#endif
		goto Bail;
	}

	// Trailing signature
	if ((cp = strtokm(NULL, "*")) == NULL || strcmp((char*)cp, WINZIP_FORMAT_CLOSE_TAG)) {
#ifdef ZIP_DEBUG
		sFailStr = "Invalid trailing zip2 signature";
#endif
		goto Bail;
	}
	if ((strtokm(NULL, "*")) != NULL) {
#ifdef ZIP_DEBUG
		sFailStr = "Trailing crap after pkzip hash, ignored";
#endif
		goto Bail;
	}

	ret = 1;

Bail:;
#ifdef ZIP_DEBUG
	fprintf(stderr, "pkzip validation failed [%s]  Hash is %s\n", sFailStr, ciphertext);
#endif
	MEM_FREE(keeptr);
	return ret;
}

char *winzip_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static uint64_t len;
	static char *buf = NULL;
	char *cp, *cp2;

	if (strncmp(ciphertext, WINZIP_FORMAT_TAG, WINZIP_TAG_LENGTH) || ciphertext[WINZIP_TAG_LENGTH] != '*')
		return ciphertext;
	cp = ciphertext + WINZIP_TAG_LENGTH + 1;
	cp = strchr(cp, '*');
	if (!cp) return ciphertext;
	cp = strchr(cp+1, '*');
	if (!cp) return ciphertext;
	if (!strncmp(cp, "*0*", 3)) return ciphertext;
	if (!buf || len < strlen(ciphertext)+1) {
		len = strlen(ciphertext)+1;
		buf = mem_alloc_tiny(len, 1);
	}
	++cp;
	cp2 = strchr(cp, '*');
	sprintf(buf, "%*.*s0%s", (int)(cp-ciphertext), (int)(cp-ciphertext), ciphertext, cp2);
	return buf;
}

void *winzip_common_get_salt(char *ciphertext)
{
	uint64_t i;
	winzip_salt salt, *psalt;
	static unsigned char *ptr;
	c8 *copy_mem = xstrdup(ciphertext);
	c8 *cp, *p;

	if (!ptr)
		ptr = mem_alloc_tiny(sizeof(winzip_salt*),sizeof(winzip_salt*));

	p = copy_mem + WINZIP_TAG_LENGTH + 1; /* skip over "$zip2$*" */
	memset(&salt, 0, sizeof(salt));
	cp = strtokm(p, "*"); // type
	salt.v.type = atoi((const char*)cp);
	cp = strtokm(NULL, "*"); // mode
	salt.v.mode = atoi((const char*)cp);
	cp = strtokm(NULL, "*"); // file_magic enum (ignored)
	cp = strtokm(NULL, "*"); // salt
	for (i = 0; i < SALT_LENGTH(salt.v.mode); i++)
		salt.salt[i] = (atoi16[ARCH_INDEX(cp[i << 1])] << 4) | atoi16[ARCH_INDEX(cp[(i << 1) + 1])];
	cp = strtokm(NULL, "*");	// validator
	salt.passverify[0] = (atoi16[ARCH_INDEX(cp[0])] << 4) | atoi16[ARCH_INDEX(cp[1])];
	salt.passverify[1] = (atoi16[ARCH_INDEX(cp[2])] << 4) | atoi16[ARCH_INDEX(cp[3])];
	cp = strtokm(NULL, "*");	// data len
	sscanf((const char *)cp, "%"PRIx64, &salt.comp_len);
	cp = strtokm(NULL, "*");	// data blob

	// Ok, now create the allocated salt record we are going to return back to John, using the dynamic
	// sized data buffer.
	psalt = (winzip_salt*)mem_calloc(1, sizeof(winzip_salt) + salt.comp_len);
	psalt->v.type = salt.v.type;
	psalt->v.mode = salt.v.mode;
	psalt->comp_len = salt.comp_len;
	psalt->dsalt.salt_alloc_needs_free = 1;  // we used mem_calloc, so JtR CAN free our pointer when done with them.
	memcpy(psalt->salt, salt.salt, sizeof(salt.salt));
	psalt->passverify[0] = salt.passverify[0];
	psalt->passverify[1] = salt.passverify[1];

	// set the JtR core linkage stuff for this dyna_salt
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(winzip_salt, comp_len);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(winzip_salt, comp_len, datablob, psalt->comp_len);

	// Copy the datablob
	for (i = 0; i < psalt->comp_len; i++)
		psalt->datablob[i] = (atoi16[ARCH_INDEX(cp[i << 1])] << 4) | atoi16[ARCH_INDEX(cp[(i << 1) + 1])];

	MEM_FREE(copy_mem);

	memcpy(ptr, &psalt, sizeof(winzip_salt*));
	return (void*)ptr;
}

void *winzip_common_binary(char *ciphertext) {
	static union {
		unsigned char buf[WINZIP_BINARY_SIZE];
		unsigned x;
	} x;
	unsigned char *bin = x.buf;
	char *c = strrchr(ciphertext, '*')-2*WINZIP_BINARY_SIZE;
	int i;

	for (i = 0; i < WINZIP_BINARY_SIZE; ++i) {
		bin[i] = atoi16[ARCH_INDEX(c[i<<1])] << 4 | atoi16[ARCH_INDEX(c[(i<<1)+1])];
	}
	return bin;
}
