/* keepass2john utility (modified KeeCrack) written in March of 2012
 * by Dhiru Kholia. keepass2john processes input KeePass 2.x database
 * files into a format suitable for use with JtR. KeePass 1.x support is
 * currently TODO.
 *
 * KeeCrack - The KeePass 2 Database Cracker, http://keecracker.zxq.net/ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

// KeePass 1.x signature
uint32_t FileSignatureOld1 = 0x9AA2D903;
uint32_t FileSignatureOld2 = 0xB54BFB65;
/// <summary>
/// File identifier, first 32-bit value.
/// </summary>
uint32_t FileSignature1 = 0x9AA2D903;
/// <summary>
/// File identifier, second 32-bit value.
/// </summary>
uint32_t FileSignature2 = 0xB54BFB67;
// KeePass 2.x pre-release (alpha and beta) signature
uint32_t FileSignaturePreRelease1 = 0x9AA2D903;
uint32_t FileSignaturePreRelease2 = 0xB54BFB66;
uint32_t FileVersionCriticalMask = 0xFFFF0000;
/// <summary>
/// File version of files saved by the current <c>Kdb4File</c> class.
/// KeePass 2.07 has version 1.01, 2.08 has 1.02, 2.09 has 2.00,
/// 2.10 has 2.02, 2.11 has 2.04, 2.15 has 3.00.
/// The first 2 bytes are critical (i.e. loading will fail, if the
/// file version is too high), the last 2 bytes are informational.
/// </summary>
uint32_t FileVersion32 = 0x00030000;

enum Kdb4HeaderFieldID
{
	EndOfHeader = 0,
	MasterSeed = 4,
	TransformSeed = 5,
	TransformRounds = 6,
	EncryptionIV = 7,
	StreamStartBytes = 9,
};

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static uint64_t BytesToUInt64(unsigned char * s)
{
	uint64_t v = s[0];
	v |= (uint64_t)s[1] << 8;
	v |= (uint64_t)s[2] << 16;
	v |= (uint64_t)s[3] << 24;
	v |= (uint64_t)s[4] << 32;
	v |= (uint64_t)s[5] << 40;
	v |= (uint64_t)s[6] << 48;
	v |= (uint64_t)s[7] << 56;
	return v;
}

static uint32_t fget32(FILE * fp)
{
	uint32_t v = fgetc(fp);
	v |= fgetc(fp) << 8;
	v |= fgetc(fp) << 16;
	v |= fgetc(fp) << 24;
	return v;
}

static uint16_t fget16(FILE * fp)
{
	uint32_t v = fgetc(fp);
	v |= fgetc(fp) << 8;
	return v;
}

void process_database(char* encryptedDatabase)
{
	long dataStartOffset;
	unsigned long transformRounds;
	unsigned char *masterSeed;
	int masterSeedLength;
	unsigned char *transformSeed;
	int transformSeedLength;
	unsigned char *initializationVectors;
	int initializationVectorsLength;
	unsigned char *expectedStartBytes;
	int expectedStartBytesLength;

	FILE *fp = fopen(encryptedDatabase, "rb");
	if (!fp) {
		fprintf(stderr, "! %s : %s\n", encryptedDatabase, strerror(errno));
		return;
	}
	uint32_t uSig1 = fget32(fp);
	uint32_t uSig2 = fget32(fp);
	if ((uSig1 == FileSignatureOld1) && (uSig2 == FileSignatureOld2)) {
		fprintf(stderr, "! %s : Old format, not supported currently\n", encryptedDatabase);
		fclose(fp);
		return;
	}
	if ((uSig1 == FileSignature1) && (uSig2 == FileSignature2)) {
	}
	else if ((uSig1 == FileSignaturePreRelease1) && (uSig2 == FileSignaturePreRelease2)) {
	}
	else {
		fprintf(stderr, "! %s : Unknown format: File signature invalid\n", encryptedDatabase);
		fclose(fp);
		return;
	}
        uint32_t uVersion = fget32(fp);
	if ((uVersion & FileVersionCriticalMask) > (FileVersion32 & FileVersionCriticalMask)) {
		fprintf(stderr, "! %s : Unknown format: File version unsupported\n", encryptedDatabase);
		fclose(fp);
		return;
	}
	int endReached = 0;
	while (!endReached)
	{
		unsigned char btFieldID = fgetc(fp);
                uint16_t uSize = fget16(fp);

		unsigned char *pbData = NULL;
		if (uSize > 0)
		{
			pbData = (unsigned char*)malloc(uSize);
			fread(pbData, uSize, 1, fp);
		}
		enum Kdb4HeaderFieldID kdbID = btFieldID;
		switch (kdbID)
		{
			case EndOfHeader:
				endReached = 1;  // end of header
				free(pbData);
				break;

                        case MasterSeed:
				masterSeed = pbData;
				masterSeedLength = uSize;
				break;

                        case TransformSeed:
				transformSeed = pbData;
				transformSeedLength = uSize;
				break;

                        case TransformRounds:
				transformRounds = BytesToUInt64(pbData);
				free(pbData);
				break;

                        case EncryptionIV:
				initializationVectors = pbData;
				initializationVectorsLength = uSize;
				break;

                        case StreamStartBytes:
				expectedStartBytes = pbData;
				expectedStartBytesLength = uSize;
				break;

			default:
				free(pbData);
				break;
		}
	}
	dataStartOffset = ftell(fp);
	if(transformRounds == 0) {
		fprintf(stderr, "! %s : transformRounds can't be 0\n", encryptedDatabase);
		return;
	}
#ifdef KEEPASS_DEBUG
	fprintf(stderr, "%d, %d, %d, %d\n", masterSeedLength, transformSeedLength, initializationVectorsLength, expectedStartBytesLength);
#endif
	printf("%s:$keepass$*2*%ld*%ld*",encryptedDatabase, transformRounds, dataStartOffset);
	print_hex(masterSeed, masterSeedLength);
	printf("*");
	print_hex(transformSeed, transformSeedLength);
	printf("*");
	print_hex(initializationVectors, initializationVectorsLength);
	printf("*");
	print_hex(expectedStartBytes, expectedStartBytesLength);
	printf("\n");
	free(masterSeed);
	free(transformSeed);
	free(initializationVectors);
	free(expectedStartBytes);
	fclose(fp);
}

int main(int argc, char **argv)
{
	int i;

	if(argc < 2) {
		fprintf(stderr, "Usage: %s <KeePass 2 databases>\n", argv[0]);
		return -1;
	}
	for(i = 1; i < argc; i++) {
		process_database(argv[i]);
	}

	return 0;
}
