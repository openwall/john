/* mozilla2john.py processes input Mozilla profile paths into a format
 * suitable for use with JtR.
 *
 * Usage: mozilla2john [key3.db files] */

#ifdef HAVE_NSS
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include <openssl/sha.h>
#include "lowpbe.h"
#include "KeyDBCracker.h"

static SHA_CTX pctx;
static SECItem saltItem;
static unsigned char encString[128];
static struct NSSPKCS5PBEParameter *paramPKCS5 = NULL;
static struct KeyCrackData keyCrackData;

static int CheckMasterPassword(char *password, SECItem *pkcs5_pfxpbe, SECItem *secPreHash)
{
	unsigned char passwordHash[SHA1_LENGTH+1];
	SHA_CTX ctx;
	memcpy(&ctx, &pctx, sizeof(SHA_CTX) );
	SHA1_Update(&ctx, (unsigned char *)password, strlen(password));
	SHA1_Final(passwordHash, &ctx);
	return nsspkcs5_CipherData(paramPKCS5, passwordHash, encString, pkcs5_pfxpbe, secPreHash);
}

static void process_path(char *path)
{
	int i;
	struct stat sb;
	if(stat(path, &sb) == 0) {
		if(S_ISDIR(sb.st_mode)) {
			fprintf (stderr, "%s : is a directory, expecting key3.db file!\n", path);
			return;
		}
	}
	if(CrackKeyData(path, &keyCrackData) == false) {
		return;
	}
	// initialize the pkcs5 structure
	saltItem.type = (SECItemType) 0;
	saltItem.len  = keyCrackData.saltLen;
	assert(keyCrackData.saltLen < 32);
	assert(keyCrackData.oidLen < 32);
	saltItem.data = keyCrackData.salt;
	paramPKCS5 = nsspkcs5_NewParam(0, &saltItem, 1);
	if(paramPKCS5 == NULL) {
		fprintf(stderr, "Failed to initialize NSSPKCS5 structure\n");
		return;
	}
	// Current algorithm is
	// SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC
	// Setup the encrypted password-check string
	memcpy(encString, keyCrackData.encData, keyCrackData.encDataLen);
	// Calculate partial sha1 data for password hashing
	SHA1_Init(&pctx);
	SHA1_Update(&pctx, keyCrackData.globalSalt, keyCrackData.globalSaltLen);
	unsigned char data1[256];
	unsigned char data2[512];
	SECItem secPreHash;
	secPreHash.data = data1;
	memcpy(secPreHash.data + SHA1_LENGTH, saltItem.data, saltItem.len);
	secPreHash.len = saltItem.len + SHA1_LENGTH;
	SECItem pkcs5_pfxpbe;
	pkcs5_pfxpbe.data = data2;
	if(CheckMasterPassword("", &pkcs5_pfxpbe, &secPreHash)) {
		fprintf (stderr, "%s : no Master Password set!\n", path);
		return;
	}
	printf("%s:$mozilla$*%d*%d*%d*",path, keyCrackData.version, keyCrackData.saltLen, keyCrackData.nnLen);
	for (i = 0; i < keyCrackData.saltLen; i++)
		printf("%c%c", itoa16[ARCH_INDEX(keyCrackData.salt[i] >> 4)],
				itoa16[ARCH_INDEX(keyCrackData.salt[i] & 0x0f)]);
	printf("*%d*", keyCrackData.oidLen);
	for (i = 0; i < keyCrackData.oidLen; i++)
		printf("%c%c", itoa16[ARCH_INDEX(keyCrackData.oidData[i] >> 4)],
				itoa16[ARCH_INDEX(keyCrackData.oidData[i] & 0x0f)]);

	printf("*%d*", keyCrackData.encDataLen);
	for (i = 0; i < keyCrackData.encDataLen; i++)
		printf("%c%c", itoa16[ARCH_INDEX(keyCrackData.encData[i] >> 4)],
				itoa16[ARCH_INDEX(keyCrackData.encData[i] & 0x0f)]);
	printf("*%d*", keyCrackData.globalSaltLen);
	for (i = 0; i < keyCrackData.globalSaltLen; i++)
		printf("%c%c", itoa16[ARCH_INDEX(keyCrackData.globalSalt[i] >> 4)],
				itoa16[ARCH_INDEX(keyCrackData.globalSalt[i] & 0x0f)]);
	printf("\n");
}

int mozilla2john(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		fprintf(stderr, "Usage: mozilla2john [key3.db files]\n");
		return -1;
	}
	for (i = 1; i < argc; i++)
		process_path(argv[i]);

	return 0;
}

#endif
