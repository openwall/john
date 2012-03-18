/* "SSH private key cracker" patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 *
 * This software is Copyright © 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This patch is inspired by the ssh-privkey-crack program.
 * http://neophob.com/2007/10/ssh-private-key-cracker/
 *
 * PEM_read_bio_PrivateKey and related OpenSSL functions are too high
 * level for brute-forcing purposes. So we drill down and find suitable
 * low-level OpenSSL functions. */

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#undef MEM_FREE
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif
#include <string.h>
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "misc.h"

#define FORMAT_LABEL        "ssh"
#define FORMAT_NAME         "ssh"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1001
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE           4224
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static int omp_t = 1;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;

static struct custom_salt {
	long len;
	char data[4096];
	EVP_CIPHER_INFO cipher;
	EVP_PKEY pk;
} *restored_custom_salt;

static struct fmt_tests ssh_tests[] = {
	{"$ssh2$2d2d2d2d2d424547494e204453412050524956415445204b45592d2d2d2d2d0a50726f632d547970653a20342c454e435259505445440a44454b2d496e666f3a204145532d3132382d4342432c35413830363832373943304634364539383230373135304133433245433631340a0a2f756954696e4a3452556a6f5a76302b705931694d763163695661724369347a2f62365a694c4161565970794a31685854327463692b593266334c61614578630a6f357772316141464d3437786d526d476f3832492f76434847413952786735776147433970574f475a5675555172447355367463556b434d422b325a344753390a354f44474364444b32674e6574446e62324a764873714154736d3443633633476468695a30734346594c71796d2b576531774359616c78734f3231572b4f676f0a42336f6746464977327232462b714a7a714d37415543794c466869357a476d7536534e6558765534477a784750464a4e47306d414f55497761614e3161446a630a4e326b3462437266796271337a366e436533444273384b3232694e2b3875526e534162434f717a5a5845645971555959354b6b6a326e654354525458494e64670a512b61535359673379355937626f4b6b6a494f727650555748654f796475512b74657273414577376e43564a7a72394e387452673271563450557631434b66700a4f49467742372f39736f6d6a59496a71576f61537a6a784b30633852777a305331706d722b7571726277792b50656f75354d3373656d486c426b4769553237660a776f684b792b4d554e4862734e6a7973535a53456c4e4b734d4950715449567a5a45316d5646412f30754d477164705133627a424f6a58325a6f36656446434f0a6d4a34775961765735774d2b6a6d75564b5056564e7939395a78796570304645644c50354b623263345a6c3053396631342f62366836415069785665377a75760a5662536b4279664a6e797a68494f5942497954374d64773134723441584a56362b5a6f457730397769774d3d0a2d2d2d2d2d454e44204453412050524956415445204b45592d2d2d2d2d0a*771", "12345"},
	{NULL}
};

struct fmt_main fmt_ssh;

static void init(struct fmt_main *pFmt)
{
	/* OpenSSL init, cleanup part is left to OS */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
	if (SSLeay() < 0x10000000) {
		fprintf(stderr, "Warning: compiled against OpenSSL 1.0+, "
		    "but running with an older version -\n"
		    "disabling OpenMP for SSH because of thread-safety issues "
		    "of older OpenSSL\n");
		fmt_ssh.params.min_keys_per_crypt =
		    fmt_ssh.params.max_keys_per_crypt = 1;
		fmt_ssh.params.flags &= ~FMT_OMP;
	}
	else {
		omp_t = omp_get_max_threads();
		pFmt->params.min_keys_per_crypt *= omp_t;
		omp_t *= OMP_SCALE;
		pFmt->params.max_keys_per_crypt *= omp_t;
	}
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$ssh2$", 6);
}

#define M_do_cipher(ctx, out, in, inl) ctx->cipher->do_cipher(ctx, out, in, inl)
int EVP_DecryptFinal_ex_safe(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
	int i,n;
        unsigned int b;
        *outl=0;


#ifndef EVP_CIPH_FLAG_CUSTOM_CIPHER
#define EVP_CIPH_FLAG_CUSTOM_CIPHER 0x100000
#endif
	if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
		i = M_do_cipher(ctx, out, NULL, 0);
                if (i < 0)
                        return 0;
                else
                        *outl = i;
                return 1;
	}

        b=ctx->cipher->block_size;
#ifndef EVP_CIPH_NO_PADDING
#define EVP_CIPH_NO_PADDING 0x100
#endif
        if (ctx->flags & EVP_CIPH_NO_PADDING) {
		if(ctx->buf_len) {
			return 0;
		}
		*outl = 0;
		return 1;
	}
        if (b > 1) {
		if (ctx->buf_len || !ctx->final_used) {
			return(0);
		}
		OPENSSL_assert(b <= sizeof ctx->final);
                n=ctx->final[b-1];
                if (n == 0 || n > (int)b) {
			return(0);
		}
                for (i=0; i<n; i++) {
			if (ctx->final[--b] != n) {
				return(0);
			}
		}
                n=ctx->cipher->block_size-n;
		for (i=0; i<n; i++)
			out[i]=ctx->final[i];
                *outl=n;
	}
	else
		*outl=0;
	return(1);
}

int PEM_do_header_safe(EVP_CIPHER_INFO *cipher, unsigned char *data, long *plen,
             pem_password_cb *callback,void *u)
{
	int i,j,o,klen;
	long len;
        EVP_CIPHER_CTX ctx;
        unsigned char key[EVP_MAX_KEY_LENGTH];
        char buf[PEM_BUFSIZE];

        len= *plen;

        if (cipher->cipher == NULL) return(1);
        if (callback == NULL)
                klen=PEM_def_callback(buf,PEM_BUFSIZE,0,u);
        else
                klen=callback(buf,PEM_BUFSIZE,0,u);
        if (klen <= 0) {
		return(0);
	}

        EVP_BytesToKey(cipher->cipher,EVP_md5(),&(cipher->iv[0]),
                (unsigned char *)buf,klen,1,key,NULL);

        j=(int)len;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit_ex(&ctx,cipher->cipher,NULL, key,&(cipher->iv[0]));
        EVP_DecryptUpdate(&ctx,data,&i,data,j);
        o=EVP_DecryptFinal_ex_safe(&ctx,&(data[i]),&j);
        EVP_CIPHER_CTX_cleanup(&ctx);
        OPENSSL_cleanse((char *)buf,sizeof(buf));
        OPENSSL_cleanse((char *)key,sizeof(key));
        j+=i;
        if (!o) {
		return(0);
	}
	*plen=j;
	return(1);
}


static void *get_salt(char *ciphertext)
{
	int i, filelength;
	char *decoded_data;
	char *copy = strdup(ciphertext);
	char *encoded_data = strtok(copy, "*");
	BIO *bp;
	char *nm = NULL, *header = NULL;
	unsigned char *data = NULL;
	EVP_CIPHER_INFO cipher;
	EVP_PKEY pk;
	long len;
	static struct custom_salt cs;

	if (!copy || !encoded_data) {
		fprintf(stderr, "BUG in parsing ciphertext, aborting!\n");
		exit(-1);
	}
	filelength = atoi(strtok(NULL, "*"));
	encoded_data += 6;	/* skip over "$ssh2$ marker */
	/* decode base64 data */
	decoded_data = (char *) malloc(filelength + 1);
	for (i = 0; i < filelength; i++)
		decoded_data[i] =
		    atoi16[ARCH_INDEX(encoded_data[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(encoded_data[i * 2 + 1])];
	decoded_data[filelength] = 0;

	/* load decoded data into OpenSSL structures */
	bp = BIO_new(BIO_s_mem());
	if (!bp) {
		fprintf(stderr, "OpenSSL BIO allocation failure\n");
		exit(-2);
	}
	BIO_puts(bp, decoded_data);

	/* PEM_bytes_read_bio function in crypto/pem/pem_lib.c
	 * check_pem function in crypto/pem/pem_lib.c */
	for (;;) {
		if (!PEM_read_bio(bp, &nm, &header, &data, &len)) {
			if (ERR_GET_REASON(ERR_peek_error()) ==
			    PEM_R_NO_START_LINE) {
				ERR_print_errors_fp(stderr);
				exit(-3);
			}
		}
		/* only PEM encoded DSA and RSA private keys are supported. */
		if (!strcmp(nm, PEM_STRING_DSA)) {
			pk.save_type = EVP_PKEY_DSA;
			pk.type = EVP_PKEY_type(EVP_PKEY_DSA);
			break;
		}
		if (!strcmp(nm, PEM_STRING_RSA)) {
			pk.save_type = EVP_PKEY_RSA;
			pk.type = EVP_PKEY_type(EVP_PKEY_RSA);
			break;
		}
		OPENSSL_free(nm);
		OPENSSL_free(header);
		OPENSSL_free(data);
		OPENSSL_free(bp);
	}
	if (!PEM_get_EVP_CIPHER_INFO(header, &cipher)) {
		ERR_print_errors_fp(stderr);
		exit(-4);
	}
#ifdef SSH_FMT_DEBUG
	printf("Header Information:\n%s\n", header);
#endif

	/* save custom_salt information */
	memset(&cs, 0, sizeof(cs));
	memcpy(&cs.cipher, &cipher, sizeof(cipher));
	memcpy(&cs.pk, &pk, sizeof(pk));
	memcpy(cs.data, data, len);
	cs.len = len;

	OPENSSL_free(nm);
	OPENSSL_free(header);
	OPENSSL_free(data);
	BIO_free(bp);
	if (copy)
		free(copy);
	if (decoded_data)
		free(decoded_data);
	return (void *) &cs;
}

static void set_salt(void *salt)
{
	/* restore custom_salt back */
	restored_custom_salt = (struct custom_salt *) salt;
	if (any_cracked) {
		memset(cracked, 0,
		    sizeof(*cracked) * omp_t * MAX_KEYS_PER_CRYPT);
		any_cracked = 0;
	}
}

static void ssh_set_key(char *key, int index)
{
	int len = strlen(key);
	if (len > PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
	saved_key[index][len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void crypt_all(int count)
{
	int index = 0;
#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
#pragma omp parallel for default(none) private(index) shared(count, any_cracked, cracked, saved_key, restored_custom_salt)
	for (index = 0; index < count; index++)
#endif
	{
		/* copy restored items into working copy */
		unsigned char working_data[4096];
		long working_len = restored_custom_salt->len;
		EVP_CIPHER_INFO cipher = restored_custom_salt->cipher;
		EVP_PKEY pk = restored_custom_salt->pk;
		const char unsigned *dc = working_data;
		DSA *dsapkc = NULL;
		RSA *rsapkc = NULL;

		memcpy(working_data, restored_custom_salt->data, working_len);
		if (PEM_do_header_safe(&cipher, working_data, &working_len, NULL,
			(char *) saved_key[index])) {
			if (pk.save_type == EVP_PKEY_DSA) {
				if ((dsapkc =
					d2i_DSAPrivateKey(NULL, &dc,
					    working_len)) != NULL) {
					DSA_free(dsapkc);
#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
#pragma omp critical
#endif
					any_cracked = cracked[index] = 1;
				}
			} else if (pk.save_type == EVP_PKEY_RSA) {
				if ((rsapkc =
					d2i_RSAPrivateKey(NULL, &dc,
					    working_len)) != NULL) {
					RSA_free(rsapkc);
#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
#pragma omp critical
#endif
					any_cracked = cracked[index] = 1;
				}
			}
		}
	}
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

struct fmt_main fmt_ssh = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		ssh_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		ssh_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
