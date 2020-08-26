/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2015. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2015 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Expression to Generic 'scriptable' compiler/builder for the
 * existing dynamic format.
 *
 * This is a 'library' where optimized formats can be placed. This will
 * allow hashes which are more optimal than the current parser/compiler
 * can generate.
 */

#include "arch.h"

#ifndef DYNAMIC_DISABLED
#include "formats.h"
#include "dynamic.h"
#include "dynamic_compiler.h"


typedef struct LIB_struct {
	int nlegacy_types;
	int outer_hash_len;
	int legacy_types[10];
	DC_struct code;
} LIB_struct;

static LIB_struct lib[] = {
	// might want to add a extra param of ,MaxInputLen=55 ??

	// Dyna-lib for md5($p)
	{ 1, 16, {0}, {DC_MAGIC, 0x09ABB6B4, NULL, "md5($p)", "", "Expression=dynamic=md5($p)\nFlag=MGF_KEYS_INPUT\nFunc=DynamicFunc__crypt_md5\nMaxInputLenX86=110\nMaxInputLen=55\nTest=@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72:abc\nTest=@dynamic=md5($p)@527bd5b5d689e2c32ae974c6229ff785:john\nTest=@dynamic=md5($p)@9dc1dc3f8499ab3bbc744557acf0a7fb:passweird", "@dynamic=md5($p)@", { "@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72", "@dynamic=md5($p)@527bd5b5d689e2c32ae974c6229ff785","@dynamic=md5($p)@9dc1dc3f8499ab3bbc744557acf0a7fb",
#if SIMD_COEF_32 < 4
	"@dynamic=md5($p)@fc58a609d0358176385b00970bfb2b49", // Len 110
#else
	"@dynamic=md5($p)@142a42ffcb282cf8087dd4dfebacdec2", // Len 55
#endif
	"@dynamic=md5($p)@d41d8cd98f00b204e9800998ecf8427e"} } },

	// Dyna-lib for md5(md5($p).$s)
	{ 1, 16, {6}, {DC_MAGIC, 0x49FD36B6, NULL, "md5(md5($p).$s)", "",
	"Expression=dynamic=md5(md5($p).$s)\nSaltLen=-23\nFlag=MGF_KEYS_BASE16_IN1_MD5\nFlag=MGF_SALTED\nTest=@dynamic=md5(md5($p).$s)@9c4f5b8c75fbabfd2f139ab34fb9da48$df694488:abc\nTest=@dynamic=md5(md5($p).$s)@bba77a29ae019330fc2794fb989526cc$87ffb1c9:john\nTest=@dynamic=md5(md5($p).$s)@59a41226b09eaab88854047448cef789$a69c5744:passweird\nSaltLen=-23\n" // no comma, this string continues into the next one
#if ARCH_LITTLE_ENDIAN
	"Func=DynamicFunc__set_input_len_32_cleartop\nFunc=DynamicFunc__append_salt\nFunc=DynamicFunc__crypt_md5\nMaxInputLenX86=110\nMaxInputLen=55", "@dynamic=md5(md5($p).$s)@",
#else
	"Func=DynamicFunc__clean_input2\nFunc=DynamicFunc__append_input2_from_input\nFunc=DynamicFunc__append_salt2\nFunc=DynamicFunc__crypt_md5_in2_to_out1\nMaxInputLenX86=110\nMaxInputLen=55", "@dynamic=md5(md5($p).$s)@",
#endif
	{ "@dynamic=md5(md5($p).$s)@9c4f5b8c75fbabfd2f139ab34fb9da48$df694488", "@dynamic=md5(md5($p).$s)@bba77a29ae019330fc2794fb989526cc$87ffb1c9","@dynamic=md5(md5($p).$s)@59a41226b09eaab88854047448cef789$a69c5744",
#if SIMD_COEF_32 < 4
	"@dynamic=md5(md5($p).$s)@7ecb1438b93ee0490ec1d5d8c58c5057$df694488", // Len 110
#else
	"@dynamic=md5(md5($p).$s)@8cc5478f107414b41a58a384816e91fb$df694488", // Len 55
#endif
	"@dynamic=md5(md5($p).$s)@5b0f39523f93d7a23d8ad54911694a12$df694488"} } },

	// Dyna-lib for md5($s.md5($p))
	{ 1, 16, {9}, {DC_MAGIC, 0x0CC08FA8, NULL, "md5($s.md5($p))", "",
	"Expression=dynamic=md5($s.md5($p))\nFlag=MGF_KEYS_BASE16_IN1_MD5\nFlag=MGF_SALTED\nTest=@dynamic=md5($s.md5($p))@4ac7a233c22986bf46c0ba86ab4e3093$df694488:abc\nTest=@dynamic=md5($s.md5($p))@1eb3946ca63041050350452764f43a04$87ffb1c9:john\nTest=@dynamic=md5($s.md5($p))@5a42d38d303330a82b3b1bc4da60c76f$a69c5744:passweird\nSaltLen=-23\n" // no comma, this string continues into the next one
#if defined (SIMD_COEF_32)
	"Func=DynamicFunc__clean_input\nFunc=DynamicFunc__append_salt\nFunc=DynamicFunc__append_from_last_output2_to_input1_as_base16\nFunc=DynamicFunc__crypt_md5\nMaxInputLenX86=110\nMaxInputLen=55", "@dynamic=md5($s.md5($p))@",
#else
	"Func=DynamicFunc__clean_input2\nFunc=DynamicFunc__append_salt2\nFunc=DynamicFunc__append_input2_from_input\nFunc=DynamicFunc__crypt_md5_in2_to_out1\nMaxInputLenX86=110\nMaxInputLen=55", "@dynamic=md5($s.md5($p))@",
#endif
	{ "@dynamic=md5($s.md5($p))@4ac7a233c22986bf46c0ba86ab4e3093$df694488", "@dynamic=md5($s.md5($p))@1eb3946ca63041050350452764f43a04$87ffb1c9","@dynamic=md5($s.md5($p))@5a42d38d303330a82b3b1bc4da60c76f$a69c5744",
#if SIMD_COEF_32 < 4
	"@dynamic=md5($s.md5($p))@84f1945f0febce87764d67703f3880c4$df694488", // Len 110
#else
	"@dynamic=md5($s.md5($p))@4bfb888b3365948db17f40b7c63d6123$df694488", // Len 55
#endif
	"@dynamic=md5($s.md5($p))@9fd5767e78e00d1c947b4e055831ef9c$df694488"} } },

	// Dyna-lib for md5(md5($p))
	{ 1, 16, {2}, {DC_MAGIC, 0x840226DA, NULL, "md5(md5($p))", "",
	"Expression=dynamic=md5(md5($p))\nFlag=MGF_KEYS_INPUT\nFlag=MGF_SET_INP2LEN32\nTest=@dynamic=md5(md5($p))@ec0405c5aef93e771cd80e0db180b88b:abc\nTest=@dynamic=md5(md5($p))@5111a834f08cb69faccade1084c8617f:john\nTest=@dynamic=md5(md5($p))@36a8d53b3a2326a1f0d452a26966ec82:passweird\nFunc=DynamicFunc__crypt_md5\nFunc=DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix\n" // no comma, this string continues into the next one
#if ARCH_LITTLE_ENDIAN
	"Func=DynamicFunc__crypt_md5_in2_to_out1\nMaxInputLenX86=110\nMaxInputLen=55", "@dynamic=md5(md5($p))@",
#else
	"Func=DynamicFunc__set_input2_len_32_cleartop\nFunc=DynamicFunc__crypt_md5_in2_to_out1\nMaxInputLenX86=110\nMaxInputLen=55", "@dynamic=md5(md5($p))@",
#endif
	 { "@dynamic=md5(md5($p))@ec0405c5aef93e771cd80e0db180b88b", "@dynamic=md5(md5($p))@5111a834f08cb69faccade1084c8617f","@dynamic=md5(md5($p))@36a8d53b3a2326a1f0d452a26966ec82",
#if SIMD_COEF_32 < 4
	"@dynamic=md5(md5($p))@1ecf10956a0e6b248651f375f5c6e2f3", // Len 110
#else
	"@dynamic=md5(md5($p))@91aa9bfd8070202f208cf529aa68ed2d", // Len 55
#endif
	"@dynamic=md5(md5($p))@74be16979710d4c4e7c6647856088456"} } },

	// Dyna-lib for md5(md5(md5($p)))
	{ 1, 16, {3}, {DC_MAGIC, 0x9583E219, NULL, "md5(md5(md5($p)))", "",
	"Expression=dynamic=md5(md5(md5($p)))\nFlag=MGF_KEYS_INPUT\nFlag=MGF_SET_INP2LEN32\nTest=@dynamic=md5(md5(md5($p)))@beeac7b932b2d5e23b905c5e6aa5614d:abc\nTest=@dynamic=md5(md5(md5($p)))@e0d1f3b96585ebafa8e49b51b73e51d1:john\nTest=@dynamic=md5(md5(md5($p)))@4e99f555ec1d2139802d9b0834e2a2bd:passweird\nFunc=DynamicFunc__crypt_md5\nFunc=DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix\n" // no comma, this string continues into the next one
#if ARCH_LITTLE_ENDIAN
	"Func=DynamicFunc__crypt2_md5\nFunc=DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix\nFunc=DynamicFunc__crypt_md5_in2_to_out1\nMaxInputLenX86=110\nMaxInputLen=55\n", "@dynamic=md5(md5(md5($p)))@",
#else
	"Func=DynamicFunc__set_input2_len_32_cleartop\nFunc=DynamicFunc__crypt2_md5\nFunc=DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix\nFunc=DynamicFunc__set_input2_len_32_cleartop\nFunc=DynamicFunc__crypt_md5_in2_to_out1\nMaxInputLenX86=110\nMaxInputLen=55\n", "@dynamic=md5(md5(md5($p)))@",
#endif
	{ "@dynamic=md5(md5(md5($p)))@beeac7b932b2d5e23b905c5e6aa5614d","@dynamic=md5(md5(md5($p)))@e0d1f3b96585ebafa8e49b51b73e51d1","@dynamic=md5(md5(md5($p)))@4e99f555ec1d2139802d9b0834e2a2bd",
#if SIMD_COEF_32 < 4
	"@dynamic=md5(md5(md5($p)))@7080951206526e0516b07b530d9580ab", // Len 110
#else
	"@dynamic=md5(md5(md5($p)))@92515f4625f430f840bda592360a6280", // Len 55
#endif
	"@dynamic=md5(md5(md5($p)))@acf7ef943fdeb3cbfed8dd0d8f584731"} } },

	// Dyna-lib for md5($s.md5($p).$s)
	{ 1, 16, {14}, {DC_MAGIC, 0x14272E3C, NULL, "md5($s.md5($p).$s)", "",
	"Expression=dynamic=md5($s.md5($p).$s)\nFlag=MGF_SALTED\nTest=@dynamic=md5($s.md5($p).$s)@7326756adc36bbbbe45429a3c37f545f$df694488:abc\nTest=@dynamic=md5($s.md5($p).$s)@694322b9b83447ba07317e4551be214d$87ffb1c9:john\nTest=@dynamic=md5($s.md5($p).$s)@af66cec476219779e4a91a2d99f5baa8$a69c5744:passweird\n" // no comma, this string continues into the next one
	"Flag=MGF_KEYS_CRYPT_IN2\nSaltLen=-11\nFunc=DynamicFunc__clean_input\nFunc=DynamicFunc__append_salt\nFunc=DynamicFunc__append_from_last_output2_to_input1_as_base16\nFunc=DynamicFunc__append_salt\nFunc=DynamicFunc__crypt_md5\nMaxInputLenX86=110\nMaxInputLen=55\n", "@dynamic=md5($s.md5($p).$s)@",
	 { "@dynamic=md5($s.md5($p).$s)@7326756adc36bbbbe45429a3c37f545f$df694488","@dynamic=md5($s.md5($p).$s)@694322b9b83447ba07317e4551be214d$87ffb1c9","@dynamic=md5($s.md5($p).$s)@af66cec476219779e4a91a2d99f5baa8$a69c5744",
#if SIMD_COEF_32 < 4
	"@dynamic=md5($s.md5($p).$s)@14a920d439709444d92eca7c75571dc5$df694488", // Len 110
#else
	"@dynamic=md5($s.md5($p).$s)@a98bc8ebcf2f700df1f0b0c5e8bd4f68$df694488", // Len 55
#endif
	"@dynamic=md5($s.md5($p).$s)@ee7b612798267cf011403a5790f0e3f4$df694488"} } },

	// Dyna-lib for md5($u.md5($p).$s)
	{ 1, 16, {15}, {DC_MAGIC, 0xB4C2F1E1, NULL, "md5($u.md5($p).$s)", "",
	"Expression=dynamic=md5($u.md5($p).$s)\nFlag=MGF_FLAT_BUFFERS\nFlag=MGF_SALTED\nFlag=MGF_USERNAME\nFlag=MGF_KEYS_BASE16_IN1_MD5\nTest=@dynamic=md5($u.md5($p).$s)@7b59795313273b8140b902a9e6f2ce21$df694488$$U87ffb1c9:abc\nTest=@dynamic=md5($u.md5($p).$s)@6b6caa2274bcf02a72332cce52fa353c$a69c5744$$U4f58497b:john\nTest=@dynamic=md5($u.md5($p).$s)@8d9f0f655927662e4612b1ba189f62f4$e0b88e64$$U35644f9d:passweird\nSaltLen=-32\nFunc=DynamicFunc__clean_input2_kwik\nFunc=DynamicFunc__append_userid2\nFunc=DynamicFunc__append_input2_from_input\nFunc=DynamicFunc__append_salt2\nFunc=DynamicFunc__MD5_crypt_input2_to_output1_FINAL\nMaxInputLenX86=110\nMaxInputLen=110\n", "@dynamic=md5($u.md5($p).$s)@",
	{ "@dynamic=md5($u.md5($p).$s)@7b59795313273b8140b902a9e6f2ce21$df694488$$U87ffb1c9","@dynamic=md5($u.md5($p).$s)@6b6caa2274bcf02a72332cce52fa353c$a69c5744$$U4f58497b","@dynamic=md5($u.md5($p).$s)@8d9f0f655927662e4612b1ba189f62f4$e0b88e64$$U35644f9d",
#if SIMD_COEF_32 < 4
	"@dynamic=md5($u.md5($p).$s)@cbb8bbd8fb3df95ade40d9224fb981c2$df694488$$U87ffb1c9", // Len 110
#else
	"@dynamic=md5($u.md5($p).$s)@cbb8bbd8fb3df95ade40d9224fb981c2$df694488$$U87ffb1c9", // Len 55
#endif
	"@dynamic=md5($u.md5($p).$s)@3407227a74083a604c5749877bae831f$df694488$$U87ffb1c9"} } },


	{ 0, 0, {0}, {0} }
};

// NOTE, dyna_9 is now a candidate to remove from the lib.  Optimizations have brought it up close to normal speed.

char *copy_str(const char *_p) {
	char *p;
	if (!_p)
		return mem_calloc(1,1);
	p = mem_alloc(strlen(_p)+1);
	strcpy(p,_p);
	return p;
}

DC_HANDLE dynamic_compile_library(const char *expr, uint32_t crc32, int *outer_hash_len) {
	int i = 0;
	while (lib[i].code.magic == DC_MAGIC) {
		if (crc32 == lib[i].code.crc32) {
			*outer_hash_len = lib[i].outer_hash_len;
			return (DC_HANDLE)&(lib[i].code);
		}
		++i;
	}
	return NULL;
}

#endif /* DYNAMIC_DISABLED */
