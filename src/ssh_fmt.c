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
#define FORMAT_NAME         "SSH"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   " - one 2048-bit and one 1024-bit key"
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
	{"$ssh2$2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a50726f632d547970653a20342c454e435259505445440a44454b2d496e666f3a204445532d454445332d4342432c464446343843343633303936433641360a0a2f4f6548434273304156786472773771564d646e2b68624a524f4f7454446f3376503371436678426c534b54627547676d4d39726b387866756b4f394b706a560a4a513136676a4a35366976375558393345486e466873454264706371395441544e3574733741655973374d73687961346532496f78616c634a377053427362670a5a2f69344f67327954317477586c4f655464716f413354444f68382b5750496d47426133785a412b4e334a4947354e306e526b6757466263354a554a46767a6f0a766c2f3545437466324143455a37744b39325a56556e59464f6c2b6a59525a665a456f664f38725169496f3236594668547a6c694258384b6b566777575756440a344a31797563427576675365583046574b566f6554306f574232353379316e686a386a6150784262663930664b5a666e394945764438482f4a4c4e4c38736a790a53787965557a356d714372695a44786254796d6153697348704b61464d2f63627743625a2f764954384a486a69555657543531715871484e61522f63617764610a647a6b7a6e4d516b57475645377947613476484c56417166764c77362b4e56475950474170614a5668414a5132423235356362526e454e496c356466544437760a717348684b6a78387a2b43453976326270754c516e7179746e6c654638414f2b764d39426e4667306d4e5169585a75584a54305833425152706b4845724a435a0a4f4f736f6e6c6c6a32684f46764b3479504468694c453672394b386a6a44766b58554339375755663742303751536362576871386b64566c43355532493341680a6e50515035354d66452f52535a544837306159562b64647278526f62543768506a44306332394e7666313745314e793437776c696b567072742f352b516c36310a67336e52454c786662664c67517451434673566c4b454f6c32356a57786c6c526759522f794e3165767a4a333673516231574d4747417239386e6a346f7646310a2b34705152616b6d6c58784f535335362b754b58365255434b62534635764b50516e49364b33745871545a36314e487a726254456469554c635a54507a6769730a37564f3064786e317a34437343415a4975634c69645547744d6d6c615953686a547843432f2f5247645a442b46597054666a73592b76473932793436314c536b0a4d4c705034686d436f34705a31644e636c594f716d614b68483553357459496a69617970576d63784f34524f4432707132335337785a71394e467a4948676a660a4e5064322f5671696274516c6a326f6a6335476d32784b73777243356334785759735978376a766c3369706a7168385269516d3478536c43505376304e6765540a6a77374979754b3847785233714a4641506f42516968506c7663692f794b544e6d456d6e2b733850566d70394d70725a6c496952365345502f453044385748760a794862462f6e56534a484b674252584f2f694f6a526e5576416b6f38557254353043687046513746734a384e695255386b586c4f434c59714778594e484a4d700a543042706159506343312b704d5345744675516c513277797a6473784574574a69306c55666335465331516c7a3870646d4659744e4a66794f7252356b502f4e0a4570424833792b795939704279386b62466b71526e6d55564477686768454f33654c6c564e4e566438324e5a7a464a4a32617777776a31794e345a3042617a660a4e455839543146684c496e634c4e7241696e4c4c32474f42737036533379426f5474796c477a5264326b4b484a74686c6261674b73336a3138375571673652350a53376c6b2b3269366c787344574d7a6772312f4e782b77662b3479572b622f506663747a4637716e68695441563473576e63304e5175476732494f74613875760a494d32456c474675684c465335636a49333875644c32384d2f4354376b4c436b5658342b622b5a444551472f5956697a4f6d4f704d5842594f4c6658586751390a534c6f2b323278555548744c4a434e2b66384d7154395a3141677043484270315a6c4b73357831464d7267433771666c4a73667a4d6e5a63534764706538766b0a46743954593756396a6e4132424a5a4f6f46717a6634533059676c477458545358376c6b4566506355475739696d6463777a554772626170334b2b687a6b4c4a0a4e2b4b4f4830772f46537143312f63436857646b7167767131497465773373716d7854477739446e575a35666735726b4f504f5670673d3d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a*1743", "kingdom"},
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
		cmp_exact,
		fmt_default_get_source
	}
};
