/*  HTTP Digest access authentication patch for john
 *
 * Written by Romain Raboin - romain.raboin at gmail.com
 *
 */

#include <string.h>

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

#ifdef	__MMX__
#include <mmintrin.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

#include "stdint.h"

#define FORMAT_LABEL			"hdaa"
#define FORMAT_NAME			"HTTP Digest access authentication"
#define ALGORITHM_NAME			"HDAA-MD5"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define	SEPARATOR			'$'

#define MAGIC				"$response$"
#define SIZE_TAB			12

#define HTMP				512

typedef struct
{
	char 	**request;
	char	h3tmp[HTMP + 1];
	char	h1tmp[HTMP + 1];
	size_t	h3tmplen;
	size_t	h1tmplen;
}      		reqinfo_t;

#define SALT_SIZE			sizeof(reqinfo_t)


/*
  digest authentication scheme :
  h1 = md5(user:realm:password)
  h2 = md5(method:digestURI)
  response = h3 = md5(h1:nonce:nonceCount:ClientNonce:qop:h2)
*/

/* request information */
enum e_req {
	R_RESPONSE,
	R_USER,
	R_REALM,
	R_METHOD,
	R_URI,
	R_NONCE,
	R_NONCECOUNT,
	R_CLIENTNONCE,
	R_QOP
};

/* response:user:realm:method:uri:nonce:nonceCount:ClientNonce:qop */
static struct fmt_tests hdaa_tests[] = {
	{"$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth", "nocode"},
	{"$response$faa6cb7d676e5b7c17fcbf966436aa0c$moi$myrealm$GET$/$af32592775d27b1cd06356b3a0db9ddf$00000001$8e1d49754a25aea7$auth", "kikou"},
	{NULL}
};


static MD5_CTX ctx;

/* used by set_key */
static char saved_key[PLAINTEXT_LENGTH + 1];

/* store the ciphertext for value currently being tested */
static unsigned char crypt_key[BINARY_SIZE + 1];

/* Store information about the request ()*/
static reqinfo_t *rinfo = NULL;

/* Store the hash convertion (binary to ascii)*/
#ifdef __MMX__
static __m64 conv[4 + 1];
#else
static uint32_t conv[(CIPHERTEXT_LENGTH / 4) + 1];
#endif

static int 	hdaa_valid(char *ciphertext, struct fmt_main *pFmt)
{
	int	nb = 0;
	int	i;

	if (strncmp(ciphertext, MAGIC, strlen(MAGIC)) != 0)
		return 0;
	for (i = 0; ciphertext[i] != 0; i++) {
		if (ciphertext[i] == SEPARATOR) {
			nb++;
		}
	}
	if (nb == 10)
		return 1;
	return 0;
}

static void	hdaa_set_salt(void *salt)
{
	rinfo = salt;
}

static void	hdaa_set_key(char *key, int index)
{
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH + 1);
}

static char	*hdaa_get_key(int index)
{
	return saved_key;
}

static int	hdaa_cmp_all(void *binary, int index)
{
	return !(memcmp((char *)binary, (char *)crypt_key, BINARY_SIZE));
}

static int	hdaa_cmp_exact(char *source, int count)
{
	return 1;
}


/* convert hash from binary to ascii */

#ifdef __MMX__

static void	bin2ascii(__m64 src[2])
{
	unsigned int	i = 0;

	while (i != 4) {
		__m64	l;
		__m64	r;
		__m64	t;
		__m64	u;
		__m64	v;

		/* 32 bits to 64 bits */
		t = _mm_set1_pi32(0x0f0f0f0f);

		/* Bit-wise AND the 64-bit values in M1 and M2.  */
		u = _mm_and_si64(_mm_srli_si64(src[(i / 2)], 4), t);
		v = _mm_and_si64(src[(i / 2)], t);

		/* interleaving */
		l = _mm_unpacklo_pi8(u, v);
		r = _mm_unpackhi_pi8(u, v);

		t = _mm_set1_pi32(0x06060606);
		l = _mm_add_pi32(l, t);
		r = _mm_add_pi32(r, t);

		t = _mm_set1_pi32(0x01010101);
		/* u = (l << 4) & t */
		u = _mm_and_si64(_mm_srli_si64(l, 4), t);
		/* v = (r << 4) & t */
		v = _mm_and_si64(_mm_srli_si64(r, 4), t);

		t = _mm_set1_pi32(0x00270027);
		/* Multiply four 16-bit values in M1 by four 16-bit values in M2 and produce
		   the low 16 bits of the results.  */
		u = _mm_mullo_pi16(u, t);
		v = _mm_mullo_pi16(v, t);

		t = _mm_set1_pi32(0x2a2a2a2a);
		u = _mm_add_pi32(u, t);
		v = _mm_add_pi32(v, t);

		conv[(i++)] = _mm_add_pi32(l, u);
		conv[(i++)] = _mm_add_pi32(r, v);
	}
}

#else

static void		bin2ascii(unsigned char *src)
{
	unsigned int	i;
	unsigned int	j = 0;
	uint32_t	t = 0;

	for (i = 0; i < BINARY_SIZE; i += 2) {
#if (ARCH_LITTLE_ENDIAN == 0)
		t = (src[i] & 0xf0);
		t *= 0x10;
		t += (src[i] & 0x0f);
		t *= 0x1000;
		t += (src[(i + 1)] & 0xf0);
		t *= 0x10;
		t += (src[(i + 1)] & 0x0f);
#else
		t = (src[(i + 1)] & 0x0f);
		t *= 0x1000;
		t += (src[(i + 1)] & 0xf0);
		t *= 0x10;
		t += (src[i] & 0x0f);
		t *= 0x100;
		t += ((src[i] & 0xf0) >> 4);
#endif
		t += 0x06060606;
		t += ((((t >> 4) & 0x01010101) * 0x27) + 0x2a2a2a2a);
		conv[(j++)] = t;
	}
}

#endif /* MMX */

static void		hdaa_crypt_all(int count)
{
	int		len;
	char	*h1tmp, *h3tmp;
	size_t	tmp;
#ifdef __MMX__
	__m64		h1[2];
#else
	static unsigned char *h1;
	if (!h1) h1 = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);
#endif

	h3tmp = rinfo->h3tmp;
	h1tmp = rinfo->h1tmp;
	tmp = rinfo->h1tmplen;
	len = strlen(saved_key);
	memcpy(&h1tmp[tmp], saved_key, len + 1);

	MD5_Init(&ctx);
	MD5_Update(&ctx, h1tmp, len + tmp);
	MD5_Final((unsigned char*)h1, &ctx);
	bin2ascii(h1);

	memcpy(h3tmp, conv, CIPHERTEXT_LENGTH);
	MD5_Init(&ctx);
	MD5_Update(&ctx, h3tmp, rinfo->h3tmplen);
	MD5_Final(crypt_key, &ctx);
}

static char		*mystrndup(const char *s, size_t n)
{
	size_t	tmp;
	size_t	size;
	char	*ret;

	for (tmp = 0; s[tmp] != 0 && tmp <= n; tmp++);
	size = n;
	if (tmp < size)
		size = tmp;
	if ((ret = mem_alloc_tiny(sizeof(char) * size + 1, MEM_ALIGN_WORD)) == NULL)
		return NULL;
	memmove(ret, s, size);
	ret[size] = 0;
	return ret;
}

static size_t		reqlen(char *str)
{
	size_t	len;

	for (len = 0; str[len] != 0 && str[len] != SEPARATOR; len++);
	return len;
}

static void			*hdaa_salt(char *ciphertext)
{

	int		nb;
	int		i;
	char		**request;
	char		*str;
	reqinfo_t	*r;
#ifdef __MMX__
	__m64		h2[2];
#else
	static unsigned char	*h2;
	if (!h2) h2 = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);
#endif
	/* parse the password string */
	request = mem_alloc_tiny(sizeof(char *) * SIZE_TAB,MEM_ALIGN_WORD);
	r = mem_alloc_tiny(sizeof(*r),MEM_ALIGN_WORD);
	memset(r, 0, sizeof(*r));
	for (nb = 0, i = 1; ciphertext[i] != 0; i++) {
		if (ciphertext[i] == SEPARATOR) {
			i++;
			request[nb] = mystrndup(&ciphertext[i], reqlen(&ciphertext[i]));
			nb++;
		}
	}

	/* calculate h2 (h2 = md5(method:digestURI))*/
	str = mem_alloc(strlen(request[R_METHOD]) + strlen(request[R_URI]) + 2);
	sprintf(str, "%s:%s", request[R_METHOD], request[R_URI]);
	MD5_Init(&ctx);
	MD5_Update(&ctx, str, strlen(str));
	MD5_Final((unsigned char *)h2, &ctx);

	memset(conv, 0, sizeof(conv));
	bin2ascii(h2);
	MEM_FREE(str);

	/* create a part of h1 (h1tmp = request:realm:)*/
	snprintf(r->h1tmp, HTMP - PLAINTEXT_LENGTH, "%s:%s:", request[R_USER], request[R_REALM]);

	/* create a part of h3 (h3tmp = nonce:noncecount:clientnonce:qop:h2)*/
	snprintf(&r->h3tmp[CIPHERTEXT_LENGTH], HTMP - CIPHERTEXT_LENGTH, ":%s:%s:%s:%s:%s",
		request[R_NONCE], request[R_NONCECOUNT], request[R_CLIENTNONCE],
		request[R_QOP], (char*)conv);
	r->request = request;
	r->h1tmplen = strlen(r->h1tmp);
	r->h3tmplen = strlen(&r->h3tmp[CIPHERTEXT_LENGTH]) + CIPHERTEXT_LENGTH;
	return r;
}

/* convert response in binary form */
static void		*hdaa_binary(char *ciphertext)
{
	static char	*realcipher;
	int		i;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	ciphertext += 10;
	for (i = 0; i < BINARY_SIZE; i++) {
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void *) realcipher;
}

struct fmt_main fmt_HDAA = {
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
		FMT_CASE | FMT_8_BIT,
		hdaa_tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		hdaa_valid,
		fmt_default_split,
		hdaa_binary,
		hdaa_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		hdaa_set_salt,
		hdaa_set_key,
		hdaa_get_key,
		fmt_default_clear_keys,
		hdaa_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		hdaa_cmp_all,
		hdaa_cmp_all,
		hdaa_cmp_exact
	}
};
