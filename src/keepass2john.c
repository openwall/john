/*
 * keepass2john utility (modified KeeCracker) written in March of 2012
 * by Dhiru Kholia. keepass2john processes input KeePass 1.x and 2.x
 * database files into a format suitable for use with JtR. This software
 * is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com> and it
 * is hereby released under GPL license.
 *
 * KDBX4 support Copyright (c) 2023-2024 magnum and hereby released to the
 * general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * KeePass 2.x support is based on KeeCracker - The KeePass 2 Database
 * Cracker, http://keecracker.mbw.name/
 *
 * KeePass 1.x support is based on kppy -  A Python-module to provide
 * an API to KeePass 1.x files. https://github.com/raymontag/kppy
 * Copyright (C) 2012 Karsten-Kai König <kkoenig@posteo.de>
 *
 * Keyfile support for Keepass 1.x and Keepass 2.x was added by Fist0urs
 * <eddy.maaalou at gmail.com>
 *
 * kppy is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or at your option) any later version.
 *
 * kppy is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * kppy. If not, see <http://www.gnu.org/licenses/>.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include "missing_getopt.h"
#endif
#include <errno.h>
// needs to be above sys/types.h and sys/stat.h for mingw, if -std=c99 used.
#include "jumbo.h"
#include <sys/stat.h>
#include <sys/types.h>
#if  (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>	// getopt defined here for unix
#endif

#include "params.h"
#include "memory.h"
#include "sha2.h"
#include "hmac_sha.h"
#include "aes.h"
#include "base64_convert.h"
#include "johnswap.h"

//#define KEEPASS_DEBUG

const char *extension[] = {".kdbx"};
static char *keyfile = NULL;

// KeePass 1.x signature
uint32_t FileSignatureOld1 = 0x9AA2D903;
uint32_t FileSignatureOld2 = 0xB54BFB65;
// KeePass File identifier
uint32_t FileSignature1 = 0x9AA2D903;
uint32_t FileSignature2 = 0xB54BFB67;
// KeePass 2.x pre-release (alpha and beta) signature
uint32_t FileSignaturePreRelease1 = 0x9AA2D903;
uint32_t FileSignaturePreRelease2 = 0xB54BFB66;
uint32_t FileVersionCriticalMask = 0xFFFF0000;
/// <summary>
/// File version of files saved by the current <c>Kdb4File</c> class.
/// KeePass 2.07 has version 1.01, 2.08 has 1.02, 2.09 has 2.00,
/// 2.10 has 2.02, 2.11 has 2.04, 2.15 has 3.00, 2.20 has 3.01.
/// The first 2 bytes are critical (i.e. loading will fail, if the
/// file version is too high), the last 2 bytes are informational.
/// </summary>
uint32_t FileVersion32_3_1 = 0x00030001;
uint32_t FileVersion32 = 0x00040001;
uint32_t FileVersion32_4 = 0x00040000;  // from KeePass 2.36 sources
uint32_t FileVersion32_4_1 = 0x00040001;  // from KeePass 2.54 sources

// We currently support database formats up to KDBX v4.  See "KdbxFile.cs"
// in KeePass >= 2.54 for more information on KDBX 4.x format.

enum Kdb4HeaderFieldID {
	EndOfHeader = 0,
	Comment = 1,
	CipherID = 2,
	CompressionFlags = 3,
	MasterSeed = 4,
	TransformSeed = 5, // KDBX 3.1, for backward compatibility only
	TransformRounds = 6, // KDBX 3.1, for backward compatibility only
	EncryptionIV = 7,
	InnerRandomStreamKey = 8, // KDBX 3.1, for backward compatibility only
	StreamStartBytes = 9, // KDBX 3.1, for backward compatibility only
	InnerRandomStreamID = 10, // KDBX 3.1, for backward compatibility only
	KdfParameters = 11, // KDBX 4, superseding Transform*
	PublicCustomData = 12 // KDBX 4
};

// Inner header in KDBX >= 4 files
// TIL: in plain C, all enums share one namespace - thus the x prefix here
enum KdbxInnerHeaderFieldID {
	xEndOfHeader = 0,
	xInnerRandomStreamID = 1, // Supersedes KdbxHeaderFieldID.InnerRandomStreamID
	xInnerRandomStreamKey = 2, // Supersedes KdbxHeaderFieldID.InnerRandomStreamKey
	Binary = 3
};

#if KEEPASS_DEBUG
static char *kdbId2name[16] = { "EndOfHeader", "Comment", "CipherID",
	"CompressionFlags", "MasterSeed", "TransformSeed", "TransformRounds",
	"EncryptionIV", "InnerRandomStreamKey", "StreamStartBytes",
	"InnerRandomStreamID", "KdfParameters", "PublicCustomData" };
#endif

static off_t get_file_size(char *filename)
{
	struct stat sb;
	if (stat(filename, & sb) != 0) {
		fprintf(stderr, "! %s : stat failed, %s\n", filename, strerror(errno));
		exit(-2);
	}
	return sb.st_size;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static uint64_t BytesToInt(unsigned char *s, const int s_size)
{
	int i;
	uint64_t v = 0;

	for (i = 0; i < 8 && i < s_size; i++)
		v |= (uint64_t)s[i] << 8 * i;
	return v;
}

static uint32_t fget32(FILE *fp)
{
	uint32_t v = (uint32_t)fgetc(fp);
	v |= (uint32_t)fgetc(fp) << 8;
	v |= (uint32_t)fgetc(fp) << 16;
	v |= (uint32_t)fgetc(fp) << 24;
	return v;
}

static uint16_t fget16(FILE *fp)
{
	uint32_t v = fgetc(fp);
	v |= fgetc(fp) << 8;
	return v;
}

static void warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	// exit(EXIT_FAILURE);
}

/* process KeePass 1.x databases */
static void process_KDBX2_database(FILE *fp, char* encryptedDatabase)
{
	uint32_t enc_flag;
	uint32_t version;
	unsigned char final_randomseed[16];
	unsigned char enc_iv[16];
	unsigned char contents_hash[32];
	unsigned char transf_randomseed[32];
	uint32_t num_groups;
	uint32_t num_entries;
	uint32_t key_transf_rounds;
	unsigned char *buffer;
	int64_t filesize = 0;
	int64_t datasize;
	int algorithm = -1;
	char *dbname;
	FILE *kfp = NULL;

	/* specific to keyfile handling */
	int64_t filesize_keyfile = 0;
	SHA256_CTX ctx;
	unsigned char hash[32];
	int counter;

	enc_flag = fget32(fp);
	version = fget32(fp);

	if (fread(final_randomseed, 16, 1, fp) != 1) {
		warn("%s: Error: read failed: %s.", encryptedDatabase,
			feof(fp) ? "Unexpected end of file" : strerror(errno));
		return;
	}
	if (fread(enc_iv, 16, 1, fp) != 1) {
		warn("%s: Error: read failed: %s.", encryptedDatabase,
			feof(fp) ? "Unexpected end of file" : strerror(errno));
		return;
	}

	num_groups = fget32(fp);
	num_entries = fget32(fp);
	(void)num_groups;
	(void)num_entries;

	if (fread(contents_hash, 32, 1, fp) != 1) {
		warn("%s: Error: read failed: %s.", encryptedDatabase,
			feof(fp) ? "Unexpected end of file" : strerror(errno));
		return;
	}
	if (fread(transf_randomseed, 32, 1, fp) != 1) {
		warn("%s: Error: read failed: %s.", encryptedDatabase,
			feof(fp) ? "Unexpected end of file" : strerror(errno));
		return;
	}

	key_transf_rounds = fget32(fp);
	/* Check if the database is supported */
	if ((version & FileVersionCriticalMask) != (FileVersion32_3_1 & FileVersionCriticalMask)) {
		fprintf(stderr, "! %s : Unsupported file version (%u)!\n", encryptedDatabase, version);
		return;
	}
	/* src/Kdb3Database.cpp from KeePass 0.4.3 is authoritative */
	if (enc_flag & 2) {
		algorithm = 0; // AES
	} else if (enc_flag & 8) {
		algorithm = 1; // Twofish
	} else {
		fprintf(stderr, "! %s : Unsupported file encryption (%u)!\n", encryptedDatabase, enc_flag);
		return;
	}

	/* keyfile processing */
	if (keyfile) {
		kfp = fopen(keyfile, "rb");
		if (!kfp) {
			fprintf(stderr, "! %s : %s\n", keyfile, strerror(errno));
			return;
		}
		filesize_keyfile = (int64_t)get_file_size(keyfile);
	}

	dbname = strip_suffixes(basename(encryptedDatabase), extension, 1);
	filesize = (int64_t)get_file_size(encryptedDatabase);
	datasize = filesize - 124;
	if (datasize < 0) {
		warn("%s: Error in validating datasize.", encryptedDatabase);
		if (kfp) fclose(kfp);
		return;
	}
	printf("%s:$keepass$*1*%d*%d*", dbname, key_transf_rounds, algorithm);
	print_hex(final_randomseed, 16);
	printf("*");
	print_hex(transf_randomseed, 32);
	printf("*");
	print_hex(enc_iv, 16);
	printf("*");
	print_hex(contents_hash, 32);

	buffer = mem_alloc(datasize * sizeof(char));

	/* we inline the content with the hash */
#if KEEPASS_DEBUG
	fprintf(stderr, "Inlining %s\n", encryptedDatabase);
#endif
	printf("*1*%"PRId64"*", datasize);
	fseek(fp, 124, SEEK_SET);
	if (fread(buffer, datasize, 1, fp) != 1) {
		warn("%s: Error: read failed: %s.",
		          encryptedDatabase, feof(fp) ? "Unexpected end of file" : strerror(errno));
		MEM_FREE(buffer);
		return;
	}

	print_hex(buffer, datasize);
	MEM_FREE(buffer);

	if (keyfile) {
		buffer = mem_alloc(filesize_keyfile * sizeof(char));
		printf("*1*64*"); /* inline keyfile content or hash - always 32 bytes */
		if (fread(buffer, filesize_keyfile, 1, kfp) != 1) {
			warn("%s: Error: read failed: %s.",
				encryptedDatabase, feof(kfp) ? "Unexpected end of file" : strerror(errno));
			return;
		}

		/*
		 * As in Keepass 1.x implementation:
		 *  if filesize_keyfile == 32 then assume byte_array
		 *  if filesize_keyfile == 64 then assume hex(byte_array)
		 *  else byte_array = sha256(keyfile_content)
		 */

		if (filesize_keyfile == 32)
			print_hex(buffer, filesize_keyfile);
		else if (filesize_keyfile == 64){
			for (counter = 0; counter <64; counter++)
				printf("%c", buffer[counter]);
		}
		else{
		  /* precompute sha256 to speed-up cracking */
		  SHA256_Init(&ctx);
		  SHA256_Update(&ctx, buffer, filesize_keyfile);
		  SHA256_Final(hash, &ctx);
		  print_hex(hash, 32);
		}
		MEM_FREE(buffer);
	}
	printf("\n");
}

/*
 * https://keepass.info/help/kb/kdbx_4.html
 * https://github.com/scubajorgen/KeepassDecrypt
 * https://blog.studioblueplanet.net/archives/1053
 *
 * Up to KDBX 3.1, header field lengths were 2 bytes wide. As of KDBX 4,
 * they are 4 bytes wide.
 *
 * The Argon2 implementation can be found in Argon2Kdf.Core.cs. The file
 * Argon2Kdf.cs defines default values for parameters
 *
 * A VariantDictionary is a key-value dictionary (with the key being a string
 * and the value being an object), which is serialized as follows:
 *
 * 1. [2 bytes] Version, as UInt16, little-endian, currently 0x0100 (version
 *    1.0). The high byte is critical (i.e. the loading code should refuse to
 *    load the data if the high byte is too high), the low byte is informational
 *    (i.e. it can be ignored).
 * 2. [n items] n serialized items (see below).
 * 3. [1 byte] Null terminator byte.
 *
 * Each of the n serialized items has the following form:
 *
 * 1. [1 byte] Value type, can be one of the following:
 *    0x04: UInt32.
 *    0x05: UInt64.
 *    0x08: Bool.
 *    0x0C: Int32.
 *    0x0D: Int64.
 *    0x18: String (UTF-8, without BOM, without null terminator).
 *    0x42: Byte array.
 * 2. [4 bytes] Length k of the key name in bytes, Int32, little-endian.
 * 3. [k bytes] Key name (string, UTF-8, without BOM, without null terminator).
 * 4. [4 bytes] Length v of the value in bytes, Int32, little-endian.
 * 5. [v bytes] Value. Integers are stored in little-endian encoding, and a
 *    Bool is one byte (false = 0, true = 1); the other types are clear.
 *
 * In KDBX 4, the HeaderHash element in the XML part is now obsolete and is
 * not stored anymore. The new header authentication using HMAC-SHA-256 is
 * mandatory:
 * Directly after the header, a (non-encrypted) SHA-256 hash of the header is
 * stored (which allows the detection of unintentional corruptions, without
 * knowing the master key). Directly after the hash, the HMAC-SHA-256 value of
 * the header is stored.
 *
 * For the stream that loads/saves data blocks authenticated using
 * HMAC-SHA-256, see the new file HmacBlockStream.cs. This stream is similar
 * to the HashedBlockStream used for KDBX 3.1, but uses a HMAC instead of just
 * a hash. Furthermore, in KDBX 4 the HMAC is computed over the ciphertext,
 * whereas in KDBX 3.1 plaintext hashes were computed (and then encrypted
 * together with the plaintext).
 *
 * The ith block produced by HmacBlockStream looks as follows:
 * 1. [32 bytes] HMAC-SHA-256 value (see below).
 * 2. [4 bytes] Block size n (in bytes, minimum 0, maximum 231-1, 0 indicates
 *    the last block, little-endian encoding).
 * 3. [n bytes] Block data C (ciphertext).
 *
 * The HMAC is computed over i ‖ n ‖ C (where little-endian encoding is used
 * for the 64-bit sequence number i and the 32-bit block size n; i is implicit
 * and does not need to be stored). The key for the HMAC is different for each
 * block; it is computed as Ki := SHA-512(i ‖ K), where K is a 512-bit key
 * derived from the user's master key and the master seed stored in the KDBX
 * header.
 * After the header and its HMAC, the encrypted data follows, splitted into
 * arbitrarily many blocks of the form above. When KeePass 2.35 writes a KDBX
 * file, it uses n = 220, i.e. the encrypted data is splitted into 1 MB blocks.
 *
 * Up to KDBX 3.1, the encryption IV stored in the KDBX header (field with
 * ID 7, EncryptionIV) was always 16 bytes (128 bits) long. As of KDBX 4, the
 * encryption IV length is retrieved from the cipher implementation and the
 * KDBX header field stores an encryption IV of exactly this length. For
 * ChaCha20, that is 12 bytes (96 bits).
 *
 * AES (Rijndael) and ChaCha20 are supported. There exist various plugins that
 * provide support for additional encryption algorithms, including but not
 * limited to Twofish, Serpent and GOST.
 */

// Synchronize with KdbxFile.Read.cs from KeePass 2.x
// This function handles KDBX3 and KDBX4, or falls back to process_KDBX2_database() for older
static void process_database(char* encryptedDatabase)
{
	// long dataStartOffset;
	uint32_t transformRounds = 0; /* Also used for Argon2_T */
	unsigned char *masterSeed = NULL;
	int masterSeedLength = 0;
	unsigned char *transformSeed = NULL;
	int transformSeedLength = 0;
	unsigned char *initializationVectors = NULL;
	int initializationVectorsLength = 0;
	unsigned char *expectedStartBytes = NULL;
	int endReached, expectedStartBytesLength = 0;
	uint32_t uSig1, uSig2, uVersion;
	FILE *fp;
	char *dbname;
	uint32_t algorithm = 0;  // 0 -> AES, 1 -> TwoFish, 2 -> ChaCha20
	size_t fsize = 0;
	uint32_t KdfUuid = 0;
	uint32_t Argon2_P = 0;
	uint32_t Argon2_V = 0;
	uint64_t Argon2_M = 0;

	/* specific to keyfile handling */
	unsigned char *buffer;
	int64_t filesize_keyfile = 0;
	char *p;
	char *data;
	char b64_decoded[128+1];
	FILE *kfp = NULL;
	int counter;

	fp = fopen(encryptedDatabase, "rb");
	if (!fp) {
		fprintf(stderr, "! %s : %s\n", encryptedDatabase, strerror(errno));
		return;
	}
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uSig1 = fget32(fp);
	uSig2 = fget32(fp);
	if ((uSig1 == FileSignatureOld1) && (uSig2 == FileSignatureOld2)) {
		process_KDBX2_database(fp, encryptedDatabase);
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
	uVersion = fget32(fp);
	if ((uVersion & FileVersionCriticalMask) > (FileVersion32 & FileVersionCriticalMask)) {
		fprintf(stderr, "! %s : Unknown format: File version '%x' unsupported\n", encryptedDatabase, uVersion);
		fclose(fp);
		return;
	}

#if KEEPASS_DEBUG
	fprintf(stderr, "\n%s\n", encryptedDatabase);
#endif
	endReached = 0;
	while (!endReached) {
		uint32_t uSize;
		unsigned char btFieldID = fgetc(fp);
		enum Kdb4HeaderFieldID kdbID = btFieldID;
		unsigned char *pbData = NULL;

		if (uVersion < FileVersion32_4)
			uSize = fget16(fp);
		else
			uSize = fget32(fp);

		if (uSize > fsize - ftell(fp)) {
			fprintf(stderr, "uSize too large, is the database corrupt?\n");
			goto bailout;
		}
		if (uSize == 0 && (kdbID != EndOfHeader)) {
			fprintf(stderr, "error validating uSize for EndOfHeader, is the database corrupt?\n");
			goto bailout;
		}
		if (uSize > 0) {
			pbData = mem_alloc(uSize);
			if (!pbData || fread(pbData, uSize, 1, fp) != 1) {
				fprintf(stderr, "error allocating / reading pbData, is the database corrupt?\n");
				MEM_FREE(pbData);
				goto bailout;
			}
		}
		switch (kdbID)
		{
			case EndOfHeader:
				endReached = 1;  // end of header
				MEM_FREE(pbData);
				break;

			case MasterSeed:
				if (masterSeed)
					MEM_FREE(masterSeed);
#if KEEPASS_DEBUG
				dump_stderr_msg("MasterSeed", pbData, uSize);
#endif
				masterSeed = pbData;
				masterSeedLength = uSize;
				break;

			case TransformSeed: // Obsolete in FileVersion32_4
				if (transformSeed)
					MEM_FREE(transformSeed);

#if KEEPASS_DEBUG
				dump_stderr_msg("TransformSeed", pbData, uSize);
#endif
				transformSeed = pbData;
				transformSeedLength = uSize;
				break;

			case TransformRounds:  // Obsolete in FileVersion32_4
				if (uSize < 4) {
					fprintf(stderr, "error validating uSize for TransformRounds, is the database corrupt?\n");
					MEM_FREE(pbData);
					goto bailout;
				}
				if (!pbData) {
					fprintf(stderr, "! %s : parsing failed (pbData is NULL), please open a bug if target is valid KeepPass database.\n", encryptedDatabase);
					goto bailout;
				}
				else {
					transformRounds = (uint32_t)BytesToInt(pbData, uSize);
#if KEEPASS_DEBUG
					fprintf(stderr, "TransformRounds : %u\n", transformRounds);
#endif
					MEM_FREE(pbData);
				}
				break;

			case EncryptionIV:
				if (initializationVectors)
					MEM_FREE(initializationVectors);
				initializationVectors = pbData;
				initializationVectorsLength = uSize;
#if KEEPASS_DEBUG
				dump_stderr_msg("EncryptionIV", pbData, uSize);
#endif
				break;

			case StreamStartBytes:  // Not present in FileVersion32_4
				if (expectedStartBytes)
					MEM_FREE(expectedStartBytes);
				expectedStartBytes = pbData;
				expectedStartBytesLength = uSize;
#if KEEPASS_DEBUG
				dump_stderr_msg("StreamStartBytes", pbData, uSize);
#endif
				break;

			case CipherID:
				// 31c1f2e6bf714350be5805216afc5aff => AES ("Standard" KDBX 3.1)
				// ad68f29f576f4bb9a36ad47af965346c => TwoFish
				// d6038a2b8b6f4cb5a524339a31dbb59a => ChaCha20
				if (uSize < 4) {
					fprintf(stderr, "! %s : Incorrect uSize %u for CipherID, is the database corrupt?\n", encryptedDatabase, uSize);
					MEM_FREE(pbData);
					goto bailout;
				}
#if KEEPASS_DEBUG
				dump_stderr_msg("CipherUUID", pbData, uSize);
#endif
				if (!memcmp(pbData, "\x31\xc1\xf2\xe6", 4)) {
					// AES
					algorithm = 0;
				} else
				if (!memcmp(pbData, "\xad\x68\xf2\x9f", 4)) {
					// TwoFish
					algorithm = 1;
				} else
				if (!memcmp(pbData, "\xd6\x03\x8a\x2b", 4)) {
					// ChaCha20
					algorithm = 2;
				}
				else {
					fprintf(stderr, "! %s : Unsupported CipherID found!\n", encryptedDatabase);
					dump_stderr_msg("CipherID", pbData, 16);
				}
				MEM_FREE(pbData);
				break;

				fprintf(stderr, "%s - KDBX Comment: %s\n", encryptedDatabase, pbData);
				MEM_FREE(pbData);
				break;

			case CompressionFlags:
#if KEEPASS_DEBUG
				;
				unsigned int compressionFlags = (unsigned int)BytesToInt(pbData, uSize);
				fprintf(stderr, "CompressionFlags %d", compressionFlags);
				dump_stderr_msg("", &compressionFlags, uSize);
#endif
				MEM_FREE(pbData);
				break;

			case KdfParameters:
				;
				unsigned char *pos = pbData;
				uint16_t version = (uint16_t)BytesToInt(pos, 2); pos += 2;
#if KEEPASS_DEBUG
				fprintf(stderr, "VariantDictionary version %u.%u\n", version >> 8, version & 0xff);
#endif
				if ((version >> 8) != 1) {
					fprintf(stderr, "! %s : Unsupported VariantDictionary version (%04x)!\n",
					        encryptedDatabase, version);
					return;
				}
				uint8_t type;
				while ((type = *pos++)) {
					uint32_t k = (uint32_t)BytesToInt(pos, 4); pos += 4;
					char *keyName = mem_calloc(k + 1, 1);
					memcpy(keyName, pos, k); pos += k;
#if KEEPASS_DEBUG
					fprintf(stderr, "\tKeyName %s\t", keyName);
#endif
					uint32_t v = (uint32_t)BytesToInt(pos, 4); pos += 4;

					switch (type)
					{
					case 0x04:
					{
						uint32_t value = (uint32_t)BytesToInt(pos, v); pos += v;
						if (!strcmp(keyName, "P"))
							Argon2_P = value;
						else if (!strcmp(keyName, "V"))
							Argon2_V = value;
#if KEEPASS_DEBUG
						fprintf(stderr, "UInt32 : %u\n", value);
#endif
						break;
					}
					case 0x05:
					{
						uint64_t value = (uint64_t)BytesToInt(pos, v); pos += v;
						if (!strcmp(keyName, "R") || !strcmp(keyName, "I"))
							transformRounds = (uint32_t)value;
						else if (!strcmp(keyName, "M"))
							Argon2_M = value;
#if KEEPASS_DEBUG
						fprintf(stderr, "UInt64 : %"PRIu64"\n", value);
#endif
						break;
					}
					case 0x08:
					{
#if KEEPASS_DEBUG
						uint8_t value = *pos;
						fprintf(stderr, "Bool : %u\n", value);
#endif
						pos += v;
						break;
					}
					case 0x0C:
					{
#if KEEPASS_DEBUG
						int32_t value = (int32_t)BytesToInt(pos, v);
						fprintf(stderr, "Int32 : %d\n", value);
#endif
						pos += v;
						break;
					}
					case 0x0D:
					{
#if KEEPASS_DEBUG
						int64_t value = BytesToInt(pos, v);
						fprintf(stderr, "Int64 : %"PRId64"\n", value);
#endif
						pos += v;
						break;
					}
					case 0x18:
					{
#if KEEPASS_DEBUG
						char *string = mem_calloc(v + 1, 1);
						memcpy(string, pos, v);
						fprintf(stderr, "String : \"%s\"\n", string);
						MEM_FREE(string);
#endif
						pos += v;
						break;
					}
					case 0x42:
						if (!strcmp(keyName, "S")) {
							transformSeed = mem_calloc(v, 1);
							memcpy(transformSeed, pos, v);
							transformSeedLength = v;
						} else if (!strcmp(keyName, "$UUID")) {
							// UUIDs:
							// AES      c9d9f39a 628a4460 bf740d08 c18a4fea
							// Argon2d  ef636ddf 8c29444b 91f7a9a4 03e30a0c
							// Argon2id 9e298b19 56db4773 b23dfc3e c6f0a1e6
							KdfUuid = JOHNSWAP((uint32_t)BytesToInt(pos, 4));
						}
#if KEEPASS_DEBUG
						dump_stderr_msg("Byte array", pos, v);
#endif
						pos += v;
						break;
					default:
#if KEEPASS_DEBUG
						fprintf(stderr, "\tUnknown type %02x length %u\n", type, v);
#endif
						pos += v;
					}
					MEM_FREE(keyName);
				}
				MEM_FREE(pbData);
				break;

			case Comment:
			case InnerRandomStreamKey:
			case InnerRandomStreamID:
			case PublicCustomData:
#if KEEPASS_DEBUG
				fprintf(stderr, "Unused: ");
				dump_stderr_msg(kdbId2name[(uint32_t)kdbID], pbData, uSize);
#endif
				MEM_FREE(pbData);
				break;

			default:
#if KEEPASS_DEBUG
				fprintf(stderr, "Not recognized: 0x%02u ", kdbID);
				dump_stderr_msg("", pbData, uSize);
#endif
				MEM_FREE(pbData);
		}
	}

	// dataStartOffset = ftell(fp);
	if (transformRounds == 0) {
		fprintf(stderr, "! %s : transformRounds can't be 0\n", encryptedDatabase);
		goto bailout;
	}
	if ((uVersion < FileVersion32_4) && (!masterSeed || !transformSeed || !initializationVectors || !expectedStartBytes)) {
		fprintf(stderr, "! %s : parsing failed, please open a bug if target is valid KeepPass database.\n", encryptedDatabase);
		goto bailout;
	}

	if ((uVersion & FileVersionCriticalMask) > (FileVersion32_4 & FileVersionCriticalMask)) {
		fprintf(stderr, "! %s : File version '%x' is currently not supported!\n", encryptedDatabase, uVersion);
		goto bailout;
	}

	if (keyfile) {
		kfp = fopen(keyfile, "rb");
		if (!kfp) {
			fprintf(stderr, "! %s : %s\n", keyfile, strerror(errno));
			return;
		}
		filesize_keyfile = (int64_t)get_file_size(keyfile);
	}

	dbname = strip_suffixes(basename(encryptedDatabase),extension, 1);

	uint32_t kdbx_ver = uVersion >> 16;

	if (kdbx_ver < 4) {
		unsigned char out[32];

		if (fread(out, 32, 1, fp) != 1) {
			fprintf(stderr, "error reading encrypted data!\n");
			goto bailout;
		}
#if KEEPASS_DEBUG
		dump_stderr_msg("Encrypted Data", out, 32);
#endif
		// dataStartOffset field is now used to convey algorithm information
		printf("%s:$keepass$*2*%u*%u*", dbname, transformRounds, algorithm);
		print_hex(masterSeed, masterSeedLength);
		printf("*");
		print_hex(transformSeed, transformSeedLength);
		printf("*");
		print_hex(initializationVectors, initializationVectorsLength);
		printf("*");
		print_hex(expectedStartBytes, expectedStartBytesLength);
		printf("*");
		print_hex(out, 32);
	} else {
		size_t content_size = ftell(fp);
		unsigned char calc_hash[32];
		fseek(fp, 0, SEEK_SET);
		unsigned char *header = mem_alloc(content_size);
		SHA256_CTX ctx;

		if (fread(header, content_size, 1, fp) != 1) {
			fprintf(stderr, "error reading header!\n");
			goto bailout;
		}

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, header, content_size);
		SHA256_Final(calc_hash, &ctx);

		unsigned char header_hash[32];
		if (fread(header_hash, 32, 1, fp) != 1) {
			fprintf(stderr, "%s: error reading header hash!\n", dbname);
			goto bailout;
		}
		if (memcmp(calc_hash, header_hash, 32)) {
			fprintf(stderr, "%s: header hash mismatch - database corrupt?\n", dbname);
			//goto bailout;
		}

		unsigned char header_hmac[32];
		if (fread(header_hmac, 32, 1, fp) != 1) {
			fprintf(stderr, "error reading header HMAC!\n");
			goto bailout;
		}
#if KEEPASS_DEBUG
		dump_stderr_msg("    Header HMAC-SHA256", header_hmac, 32);
#endif

		printf("%s:$keepass$*%u*%u*%08x*%"PRIu64"*%u*%u*", dbname, kdbx_ver, transformRounds,
		       KdfUuid, Argon2_M, Argon2_V, Argon2_P);
		print_hex(masterSeed, masterSeedLength);
		printf("*");
		print_hex(transformSeed, transformSeedLength);
		printf("*");
		print_hex(header, content_size);
		printf("*");
		print_hex(header_hmac, 32);

		MEM_FREE(header);
	}

	if (keyfile) {
		buffer = mem_alloc(filesize_keyfile * sizeof(char));
		printf("*1*64*"); /* inline keyfile content or hash - always 32 bytes */
		if (fread(buffer, filesize_keyfile, 1, kfp) != 1) {
			warn("%s: Error: read failed: %s.",
				encryptedDatabase, feof(kfp) ? "Unexpected end of file" : strerror(errno));
			return;
		}

		/*
		 * As in Keepass 2.x implementation:
		 *  if keyfile is an xml, get <Data> content
		 *  if filesize_keyfile == 32 then assume byte_array
		 *  if filesize_keyfile == 64 then assume hex(byte_array)
		 *  else byte_array = sha256(keyfile_content)
		 */

		if (!memcmp((char*) buffer, "<?xml", 5) &&
		    ((p = strstr((char*) buffer, "<Key>")) != NULL) &&
		    ((p = strstr(p, "<Data>")) != NULL)) {
			p += strlen("<Data>");
			data = p;
			p = strstr(p, "</Data>");
			printf ("%s", base64_convert_cp(data, e_b64_mime, p - data, b64_decoded, e_b64_hex, sizeof(b64_decoded), flg_Base64_NO_FLAGS, 0));
		}
		else if (filesize_keyfile == 32)
			print_hex(buffer, filesize_keyfile);
		else if (filesize_keyfile == 64)
		{
			for (counter = 0; counter <64; counter++)
				printf("%c", buffer[counter]);
		}
		else
		{
			SHA256_CTX ctx;
			unsigned char hash[32];

			/* precompute sha256 to speed-up cracking */
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, buffer, filesize_keyfile);
			SHA256_Final(hash, &ctx);
			print_hex(hash, 32);
		}
		MEM_FREE(buffer);
	}
	printf("\n");

bailout:
	MEM_FREE(masterSeed);
	MEM_FREE(transformSeed);
	MEM_FREE(initializationVectors);
	MEM_FREE(expectedStartBytes);
	fclose(fp);
}

#ifndef HAVE_LIBFUZZER
static int usage(char *name)
{
	fprintf(stderr, "Usage: %s [-k <keyfile>] <.kdbx database(s)>\n", name);

	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	int c;

	errno = 0;
	/* Parse command line */
	while ((c = getopt(argc, argv, "k:")) != -1) {
		switch (c) {
		case 'k':
			keyfile = mem_alloc(strlen(optarg) + 1);
			strcpy(keyfile, optarg);
			break;
		case '?':
		default:
			return usage(argv[0]);
		}
	}
	argc -= optind;
	if (argc == 0)
		return usage(argv[0]);
	argv += optind;

	while (argc--)
		process_database(*argv++);

	return 0;
}
#endif

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	char name[] = "/tmp/libFuzzer-XXXXXX";

	fd = mkstemp(name);  // this approach is somehow faster than the fmemopen way
	if (fd < 0) {
		fprintf(stderr, "Problem detected while creating the input file, %s, aborting!\n", strerror(errno));
		exit(-1);
	}
	write(fd, data, size);
	close(fd);
	process_database(name);
	remove(name);

	return 0;
}
#endif
