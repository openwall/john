/*
 * Common code for cracking Cardano 128-byte length legacy secret Keys (a.k.a XPrv).
 *
 * This software is Copyright (c) 2022, Pal Dorogi <pal dot dorogi at gmail.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 *
 * This file is common for its future use, and currently there isn't an OpenCL format
 * implementing this feature.
 *
 */

#include "common.h"
#include "cardano_common.h"

struct fmt_tests cardano_tests[] = {
	//
	// https://github.com/CardanoSolutions/ByronWalletRecovery/blob/63ac66ee3532b2a1c72a88c0aa726d0f1ce3ed7a/tools/inspect-keystore/index.js#L34
	// XPrv is BIP32-Ed25519 key, derived from an extended Ed25519 key (64-byte sk + 32-byte pk)
	// by appending a 32-byte length chaincode to it, and clear and extra bit ( esk[31] &= 0x20).
	//      +---------------------------------+-----------------------+-----------------------+
	//      | Extended Private Key (64 bytes) | Public Key (32 bytes) | Chain Code (32 bytes) |
	//      +---------------------------------+-----------------------+-----------------------+
	//      <------------ ENCRYPTED ---------->
	// Initial version only accepts v1 scheme identified as "$1$", which means the payload is a
	// single 128-byte length legacy encrypted master secret key.
	{ "$cardano$1$b57361ebe335fa171a260fea7d3277579c212dc74fc2a408d6cbd8a6e7a847cab3c44c5fb190705ddd2698f2d5390798893349b4321e7474b1ce06c9d410b3d6055b42d4a95f19cb34b516a160a306c0eaef398e70ea91da450ccb2a7819e95b0102030405060708091011121314151617181920212223242526272829303132", "Secret1234" },
	{ NULL }
};

int cardano_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += FORMAT_TAG_LEN;

	if ((p = strtokm(ctcopy, "$")) == NULL) // scheme
		goto err;
	if (strcmp(p, "1")) // only "1" is supported at the moment.
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // 128-byte long esk
		goto err;

	len = strlen(p) ;
	if (len != 2 * ESK_LEN)
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *cardano_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN; // skip over "$cardano$"
	p = strtokm(ctcopy, "$"); // skip over "$1$"
	p = strtokm(NULL, "$");
	for (i = 0; i < ESK_LEN; i++)
		cs.esk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}
