/* Modified in July 2012 by Dhiru Kholia <dhiru at openwall.com> to be
 * standalone and compilable.
 *
 * p-ppk-crack v0.5 made by michu@neophob.com — PuTTY private key cracker
 *
 * Source code based on putty svn version, check
 * http://chiark.greenend.org.uk/~sgtatham/putty/licence.html. */

#ifndef PUTTY_COMMON_H
#define PUTTY_COMMON_H

#include <stddef.h>		       /* for size_t */
#include <string.h>		       /* for memcpy() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <fcntl.h>
#include "memory.h"

#define smalloc(z) safemalloc(z,1)
#define snmalloc safemalloc
#define srealloc(y,z) saferealloc(y,z,1)
#define snrealloc saferealloc

/*
 * Direct use of smalloc within the code should be avoided where
 * possible, in favour of these type-casting macros which ensure
 * you don't mistakenly allocate enough space for one sort of
 * structure and assign it to a different sort of pointer.
 */
#define snew(type) ((type *)snmalloc(1, sizeof(type)))
#define snewn(n, type) ((type *)snmalloc((n), sizeof(type)))
#define sresize(ptr, n, type) \
    ((type *)snrealloc((sizeof((type *)0 == (ptr)), (ptr)), (n), sizeof(type)))

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

typedef struct Filename Filename;

#ifndef lenof
#define lenof(x) ( (sizeof((x))) / (sizeof(*(x))))
#endif

#ifndef min
#define min(x,y) ( (x) < (y) ? (x) : (y) )
#endif
#ifndef max
#define max(x,y) ( (x) > (y) ? (x) : (y) )
#endif

#define GET_32BIT_LSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0]) | \
  ((unsigned long)(unsigned char)(cp)[1] << 8) | \
  ((unsigned long)(unsigned char)(cp)[2] << 16) | \
  ((unsigned long)(unsigned char)(cp)[3] << 24))

#define PUT_32BIT_LSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)(value), \
  (cp)[1] = (unsigned char)((value) >> 8), \
  (cp)[2] = (unsigned char)((value) >> 16), \
  (cp)[3] = (unsigned char)((value) >> 24) )

#define GET_16BIT_LSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0]) | \
  ((unsigned long)(unsigned char)(cp)[1] << 8))

#define PUT_16BIT_LSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)(value), \
  (cp)[1] = (unsigned char)((value) >> 8) )

#define GET_32BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0] << 24) | \
  ((unsigned long)(unsigned char)(cp)[1] << 16) | \
  ((unsigned long)(unsigned char)(cp)[2] << 8) | \
  ((unsigned long)(unsigned char)(cp)[3]))

#define GET_32BIT(cp) GET_32BIT_MSB_FIRST(cp)

#define PUT_32BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)((value) >> 24), \
  (cp)[1] = (unsigned char)((value) >> 16), \
  (cp)[2] = (unsigned char)((value) >> 8), \
  (cp)[3] = (unsigned char)(value) )

#define PUT_32BIT(cp, value) PUT_32BIT_MSB_FIRST(cp, value)

#define GET_16BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0] << 8) | \
  ((unsigned long)(unsigned char)(cp)[1]))

#define PUT_16BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)((value) >> 8), \
  (cp)[1] = (unsigned char)(value) )

#define SSH_CIPHER_IDEA		1
#define SSH_CIPHER_DES		2
#define SSH_CIPHER_3DES		3
#define SSH_CIPHER_BLOWFISH	6

typedef unsigned int uint32;
typedef uint32 word32;

struct ssh2_userkey {
    const struct ssh_signkey *alg;     /* the key algorithm */
    void *data;			       /* the key data */
    char *comment;		       /* the key comment */
};

enum {
    SSH_KEYTYPE_UNOPENABLE,
    SSH_KEYTYPE_UNKNOWN,
    SSH_KEYTYPE_SSH1, SSH_KEYTYPE_SSH2,
    SSH_KEYTYPE_OPENSSH, SSH_KEYTYPE_SSHCOM
};

static int base64_decode_atom(char *atom, unsigned char *out);
#endif

typedef struct Filename {
    char path[4096];
} Filename;

#define PASSPHRASE_MAXLEN 512

static char header[40], *b, *encryption, *comment, *mac;
static const char *error = NULL;
static int i, is_mac, old_fmt;
static char alg[8];
static int cipher, cipherblk;
static unsigned char *public_blob, *private_blob;
static unsigned char *public_blobXX, *private_blobXX;
static int public_blob_len, private_blob_len;

static char *read_body(FILE * fp)
{
	char *text;
	int len;
	int size;
	int c;

	size = 128;
	text = (char*)malloc(size);
	len = 0;
	text[len] = '\0';

	while (1) {
		c = fgetc(fp);
		if (c == '\r' || c == '\n') {
			c = fgetc(fp);
			if (c != '\r' && c != '\n' && c != EOF)
				ungetc(c, fp);
			return text;
		}
		if (c == EOF) {
			return NULL;
		}
		if (len + 1 >= size) {
			size += 128;
			// text = sresize(text, size, char);
		}
		text[len++] = c;
		text[len] = '\0';
	}
}


static unsigned char *read_blob(FILE * fp, int nlines, int *bloblen)
{
	unsigned char *blob;
	char *line;
	int linelen, len;
	int i, j, k;

	/* We expect at most 64 base64 characters, ie 48 real bytes, per line. */
	blob = (unsigned char*)malloc(48 * nlines);
	len = 0;
	for (i = 0; i < nlines; i++) {
		line = read_body(fp);
		if (!line) {
			MEM_FREE(blob);
			return NULL;
		}
		linelen = strlen(line);
		if (linelen % 4 != 0 || linelen > 64) {
			MEM_FREE(blob);
			MEM_FREE(line);
			return NULL;
		}
		for (j = 0; j < linelen; j += 4) {
			k = base64_decode_atom(line + j, blob + len);
			if (!k) {
				return NULL;
			}
			len += k;
		}
	}
	*bloblen = len;
	return blob;
}


static int read_header(FILE * fp, char *header)
{
	int len = 39;
	int c;

	while (len > 0) {
		c = fgetc(fp);
		if (c == '\n' || c == '\r' || c == EOF)
			return 0;		       /* failure */
		if (c == ':') {
			c = fgetc(fp);
			if (c != ' ')
				return 0;
			*header = '\0';
			return 1;		       /* success! */
		}
		if (len == 0)
			return 0;		       /* failure */
		*header++ = c;
		len--;
	}
	return 0;			       /* failure */
}


static int init_LAME(const Filename *filename) {
	FILE *fp;

	encryption = comment = mac = NULL;
	public_blob = private_blob = NULL;

	fp = fopen(filename->path, "rb" );
	if (!fp) {
		error = "can't open file";
		goto error;
	}

	/* Read the first header line which contains the key type. */
	if (!read_header(fp, header))
		goto error;
	if (0 == strcmp(header, "PuTTY-User-Key-File-2")) {
		old_fmt = 0;
	} else if (0 == strcmp(header, "PuTTY-User-Key-File-1")) {
		/* this is an old key file; warn and then continue */
		// old_keyfile_warning();
		old_fmt = 1;
	} else {
		error = "not a PuTTY SSH-2 private key";
		goto error;
	}
	error = "file format error";
	if ((b = read_body(fp)) == NULL)
		goto error;
	/* Select key algorithm structure. */
	if (!strcmp(b, "ssh-rsa"))
		strcpy(alg, "ssh-rsa");
    	else if (!strcmp(b, "ssh-dss"))
		strcpy(alg, "ssh-dss");

	/* Read the Encryption header line. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Encryption"))
		goto error;
	if ((encryption = read_body(fp)) == NULL)
		goto error;
	if (!strcmp(encryption, "aes256-cbc")) {
		cipher = 1;
		cipherblk = 16;
	} else if (!strcmp(encryption, "none")) {
		cipher = 0;
		cipherblk = 1;
	} else {
		MEM_FREE(encryption);
		goto error;
	}

	/* Read the Comment header line. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Comment"))
		goto error;
	if ((comment = read_body(fp)) == NULL)
		goto error;

	/* Read the Public-Lines header line and the public blob. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Public-Lines"))
		goto error;
	if ((b = read_body(fp)) == NULL)
		goto error;
	i = atoi(b);
	MEM_FREE(b);
	if ((public_blob = read_blob(fp, i, &public_blob_len)) == NULL)
		goto error;

	/* Read the Private-Lines header line and the Private blob. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Private-Lines"))
		goto error;
	if ((b = read_body(fp)) == NULL)
		goto error;
	i = atoi(b);
	MEM_FREE(b);
	if ((private_blob = read_blob(fp, i, &private_blob_len)) == NULL)
		goto error;

	/* Read the Private-MAC or Private-Hash header line. */
	if (!read_header(fp, header))
		goto error;
	if (0 == strcmp(header, "Private-MAC")) {
		if ((mac = read_body(fp)) == NULL)
			goto error;
		is_mac = 1;
	} else if (0 == strcmp(header, "Private-Hash") && old_fmt) {
		if ((mac = read_body(fp)) == NULL)
			goto error;
		is_mac = 0;
	} else
		goto error;

	fclose(fp);
	fp = NULL;
	return 0;

error:
	if (fp)
		fclose(fp);
	MEM_FREE(comment);
	MEM_FREE(encryption);
	MEM_FREE(mac);
	MEM_FREE(public_blob);
	MEM_FREE(private_blob);
	return 1;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static void LAME_ssh2_load_userkey(char *filename, const char **errorstr)
{
	/*
	* Decrypt the private blob.
	*/
	if (cipher) {
		if (private_blob_len % cipherblk)
			goto error;
	}

	{
		printf("%s:$putty$%d*%d*%d*%d*%s*%d*", filename, cipher,cipherblk, is_mac, old_fmt, mac, public_blob_len);
		print_hex(public_blob, public_blob_len);
		printf("*%d*", private_blob_len);
		print_hex(private_blob, private_blob_len);
		if(!old_fmt) {
			printf("*%s*%s*%s\n", alg, encryption, comment);
		}
		else {
			printf("\n");
		}
		return;
	}
error:
	fprintf(stderr, "Something failed!");

}

static FILE *f_open(const Filename *filename, char const *mode, int is_private)
{
    if (!is_private) {
        return fopen(filename->path, mode);
    } else {
        int fd;
        fd = open(filename->path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            return NULL;
        return fdopen(fd, mode);
    }
}



/* ----------------------------------------------------------------------
 * A function to determine the type of a private key file. Returns
 * 0 on failure, 1 or 2 on success.
 */
#define rsa_signature "SSH PRIVATE KEY FILE FORMAT 1.1\n"

static int key_type(const Filename *filename)
{
    FILE *fp;
    char buf[32];
    const char putty2_sig[] = "PuTTY-User-Key-File-";
    const char sshcom_sig[] = "---- BEGIN SSH2 ENCRYPTED PRIVAT";
    const char openssh_sig[] = "-----BEGIN ";
    int i;

    fp = f_open(filename, "r", FALSE);
    if (!fp)
	return SSH_KEYTYPE_UNOPENABLE;
    i = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (i < 0)
	return SSH_KEYTYPE_UNOPENABLE;
    if (i < 32)
	return SSH_KEYTYPE_UNKNOWN;
    if (!memcmp(buf, rsa_signature, sizeof(rsa_signature)-1))
	return SSH_KEYTYPE_SSH1;
    if (!memcmp(buf, putty2_sig, sizeof(putty2_sig)-1))
	return SSH_KEYTYPE_SSH2;
    if (!memcmp(buf, openssh_sig, sizeof(openssh_sig)-1))
	return SSH_KEYTYPE_OPENSSH;
    if (!memcmp(buf, sshcom_sig, sizeof(sshcom_sig)-1))
	return SSH_KEYTYPE_SSHCOM;
    return SSH_KEYTYPE_UNKNOWN;	       /* unrecognised or EOF */
}

static int ssh2_userkey_encrypted(const Filename *filename, char **commentptr)
{
    FILE *fp;
    char header[40], *b, *comment;
    int ret;

    if (commentptr)
	*commentptr = NULL;

    fp = f_open(filename, "rb", FALSE);
    if (!fp)
	return 0;
    if (!read_header(fp, header)
	|| (0 != strcmp(header, "PuTTY-User-Key-File-2") &&
	    0 != strcmp(header, "PuTTY-User-Key-File-1"))) {
	fclose(fp);
	return 0;
    }
    if ((b = read_body(fp)) == NULL) {
	fclose(fp);
	return 0;
    }
    MEM_FREE(b);			       /* we don't care about key type here */
    /* Read the Encryption header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Encryption")) {
	fclose(fp);
	return 0;
    }
    if ((b = read_body(fp)) == NULL) {
	fclose(fp);
	return 0;
    }

    /* Read the Comment header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Comment")) {
	fclose(fp);
	MEM_FREE(b);
	return 1;
    }
    if ((comment = read_body(fp)) == NULL) {
	fclose(fp);
	MEM_FREE(b);
	return 1;
    }

    if (commentptr)
	*commentptr = comment;

    fclose(fp);
    if (!strcmp(b, "aes256-cbc"))
	ret = 1;
    else
	ret = 0;
    MEM_FREE(b);
    return ret;
}

static int base64_decode_atom(char *atom, unsigned char *out)
{
    int vals[4];
    int i, v, len;
    unsigned word;
    char c;

    for (i = 0; i < 4; i++) {
        c = atom[i];
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= 'a' && c <= 'z')
            v = c - 'a' + 26;
        else if (c >= '0' && c <= '9')
            v = c - '0' + 52;
        else if (c == '+')
            v = 62;
        else if (c == '/')
            v = 63;
        else if (c == '=')
            v = -1;
        else
            return 0;                  /* invalid atom */
        vals[i] = v;
    }

    if (vals[0] == -1 || vals[1] == -1)
        return 0;
    if (vals[2] == -1 && vals[3] != -1)
        return 0;

    if (vals[3] != -1)
        len = 3;
    else if (vals[2] != -1)
        len = 2;
    else
        len = 1;

    word = ((vals[0] << 18) |
            (vals[1] << 12) | ((vals[2] & 0x3F) << 6) | (vals[3] & 0x3F));
    out[0] = (word >> 16) & 0xFF;
    if (len > 1)
        out[1] = (word >> 8) & 0xFF;
    if (len > 2)
        out[2] = word & 0xFF;
    return len;
}

int main(int argc, char **argv)
{
	FILE *fp;

	int type, realtype;
	char *comment;
	Filename filename;
	int needs_pass = 0;
	const char *errmsg = NULL;

	// printf( "%s - made by michu@neophob.com - PuTTY private key cracker\n", argv[0]);

	if (argc < 2) {
		printf( "Usage: %s [PuTTY-Private-Key-File]\n", argv[0]);
		printf( "Example:\n");
		printf( " $ john -stdout -incremental | %s id_dsa\n",argv[0]);
		printf( " $ %s id_dsa < dictionary\n", argv[0]);
		printf( "\n");
		exit(1);
	}

	/*
	* check if file exist
	*/
	if ((fp = fopen(argv[1], "r")) == NULL) {
		printf( "Error: Cannot open %s.\n", argv[1]);
		return 2;
	}
	fclose(fp);

	strcpy(filename.path, argv[1]);

	//src: winpgen.c
	type = realtype = key_type(&filename);
	if (type != SSH_KEYTYPE_SSH1 && type != SSH_KEYTYPE_SSH2) {
		fprintf(stderr, "Error: Couldn't load private key (%s)\n", filename.path);
		return 2;
	}

	if (type != SSH_KEYTYPE_SSH1 && type != SSH_KEYTYPE_SSH2) {
		realtype = type;
		//type = import_target_type(type);
	}

	comment = NULL;
	if (realtype == SSH_KEYTYPE_SSH2) {
		needs_pass = ssh2_userkey_encrypted(&filename, &comment);
	}
	if (needs_pass==0) {
		printf("this private key doesn't need a passphrase - exit now!\n");
		return 0;
	}

	if (init_LAME(&filename)==1) {
		printf("error, not valid private key!\n");
		return 1;
	}
	// printf("len: %i/%i\n", public_blob_len, private_blob_len);
	private_blobXX=(unsigned char*)malloc(private_blob_len);
	public_blobXX=(unsigned char*)malloc(public_blob_len);

	if (type == SSH_KEYTYPE_SSH1) {
		fprintf(stderr, "SSH1 key type not supported!\n");
		return 3;
	} else { //SSH_KEYTYPE_SSH2
		if (realtype == type) {
			LAME_ssh2_load_userkey(filename.path, &errmsg);
		}
	}

	MEM_FREE(comment);
	MEM_FREE(encryption);
	MEM_FREE(mac);
	MEM_FREE(public_blob);
	MEM_FREE(private_blob);
	MEM_FREE(private_blobXX);

	return 0;
}
