/*
 * Modified in July 2012 by Dhiru Kholia <dhiru at openwall.com> to be
 * standalone and compilable.
 *
 * p-ppk-crack v0.5 made by michu@neophob.com -- PuTTY private key cracker
 *
 * Source code based on putty svn version, see [1] for licensing information.
 *
 * [1] http://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html
 */

#ifndef PUTTY_COMMON_H
#define PUTTY_COMMON_H
#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdint.h>
#include <stddef.h>  /* for size_t */
#include <string.h>  /* for memcpy() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <fcntl.h>

#if !AC_BUILT || HAVE_LIMITS_H
#include <limits.h>
#endif

#include "memory.h"
#include "jumbo.h"
#if _MSC_VER
#include <io.h>
#endif

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

struct ssh2_userkey {
	const struct ssh_signkey *alg;  /* the key algorithm */
	void *data;  /* the key data */
	char *comment;  /* the key comment */
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

static char header[40], *b, *encryption, *comment, *mac;
static const char *putty_error = NULL;
static int i, is_mac, old_fmt;
static char alg[32];
static int cipher, cipherblk;
static unsigned char *public_blob, *private_blob;
static int public_blob_len, private_blob_len;

static char *read_body(FILE * fp)
{
	char *text;
	int len;
	int size;
	int c;

	size = 128 * 1024;
	text = (char*)malloc(size);
	if (!text) {
		fprintf(stderr, "malloc failed in read_body, exiting!\n");
		exit(-1);
	}
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
			MEM_FREE(text);
			return NULL;
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

	/* Sanity check nlines */
	if (nlines < 0 || nlines > (1024 * 1024))
		return NULL;

	/* We expect at most 64 base64 characters, ie 48 real bytes, per line. */
	blob = (unsigned char*)malloc(48 * nlines);
	if (!blob) {
		fprintf(stderr, "malloc failed in read_blob, exiting!\n");
		exit(-1);
	}
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
			line = NULL;
			return NULL;
		}
		for (j = 0; j < linelen; j += 4) {
			k = base64_decode_atom(line + j, blob + len);
			if (!k) {
				MEM_FREE(blob);
				MEM_FREE(line);
				return NULL;
			}
			len += k;
		}
		MEM_FREE(line);
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
			return 0;  /* failure */
		if (c == ':') {
			c = fgetc(fp);
			if (c != ' ')
				return 0;
			*header = '\0';
			return 1;  /* success! */
		}
		if (len == 0)
			return 0;  /* failure */
		*header++ = c;
		len--;
	}
	return 0;  /* failure */
}


static int init_LAME(const Filename *filename) {
	FILE *fp;

	encryption = comment = mac = NULL;
	public_blob = private_blob = NULL;

	fp = fopen(filename->path, "rb" );
	if (!fp) {
		putty_error = "can't open file";
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
		putty_error = "not a PuTTY SSH-2 private key";
		goto error;
	}
	putty_error = "file format error";
	if ((b = read_body(fp)) == NULL)
		goto error;
	/* Select key algorithm structure. */
	if (!strcmp(b, "ssh-rsa"))
		strcpy(alg, "ssh-rsa");
	else if (!strcmp(b, "ssh-dss"))
		strcpy(alg, "ssh-dss");
	else if (!strcmp(b, "ecdsa-sha2-nistp256"))
		strcpy(alg, "ecdsa-sha2-nistp256");
	else if (strlen(b) < sizeof(alg) - 1)
		strcpy(alg, b);
	MEM_FREE(b);

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

static void LAME_ssh2_load_userkey(char *path, const char **errorstr)
{
	const char *ext[] = {".ppk"};
	char *fname;
	/*
	* Decrypt the private blob.
	*/
	if (cipher) {
		if (private_blob_len % cipherblk)
			goto error;
	}

	{
		fname = strip_suffixes(basename(path), ext, 1);
		printf("%s:$putty$%d*%d*%d*%d*%s*%d*", fname, cipher, cipherblk, is_mac, old_fmt, mac, public_blob_len);
		print_hex(public_blob, public_blob_len);
		printf("*%d*", private_blob_len);
		print_hex(private_blob, private_blob_len);
		if (!old_fmt) {
			printf("*%s*%s*%s\n", alg, encryption, comment);
		}
		else {
			printf("\n");
		}
		MEM_FREE(comment);
		return;
	}
error:
	fprintf(stderr, "Something failed!\n");
	MEM_FREE(comment);
	MEM_FREE(encryption);
	MEM_FREE(mac);
	MEM_FREE(public_blob);
	MEM_FREE(private_blob);
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
	MEM_FREE(b);  /* we don't care about key type here */
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
			return 0;  /* invalid atom */
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

static void process_file(const char *fname)
{
	FILE *fp;
	int type, realtype;
	char *comment;
	Filename filename;
	int needs_pass = 0;
	const char *errmsg = NULL;

	/* check if file exists */
	if ((fp = fopen(fname, "r")) == NULL) {
		fprintf(stderr, "Error: Cannot open %s.\n", fname);
		return;
	}
	fclose(fp);

	strcpy(filename.path, fname);

	// src: winpgen.c
	type = realtype = key_type(&filename);
	if (type != SSH_KEYTYPE_SSH1 && type != SSH_KEYTYPE_SSH2) {
		fprintf(stderr, "Error: Couldn't load private key (%s)\n", filename.path);
		return;
	}
	if (type == SSH_KEYTYPE_SSH1) {
		fprintf(stderr, "%s : SSH1 RSA private keys are not supported currently!\n", filename.path);
		return;

	}
	if (type != SSH_KEYTYPE_SSH1 && type != SSH_KEYTYPE_SSH2) {
		realtype = type;
	}

	comment = NULL;
	if (realtype == SSH_KEYTYPE_SSH2) {
		needs_pass = ssh2_userkey_encrypted(&filename, &comment);
		if (needs_pass == 0) {
			fprintf(stderr, "%s : this private key doesn't need a passphrase!\n", fname);
			goto out;
		}
	}

	if (init_LAME(&filename)==1) {
		fprintf(stderr, "error, not valid private key!\n");
		goto out;
	}
	if (type == SSH_KEYTYPE_SSH1) {
		fprintf(stderr, "SSH1 key type not supported!\n");
		goto out;
	} else { // SSH_KEYTYPE_SSH2
		if (realtype == type) {
			LAME_ssh2_load_userkey(filename.path, &errmsg);
		}
	}

out:

	MEM_FREE(comment);
	MEM_FREE(encryption);
	MEM_FREE(mac);
	MEM_FREE(public_blob);
	MEM_FREE(private_blob);
}

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	char name[] = "/tmp/libFuzzer-XXXXXX";

	fd = mkstemp(name);
	if (fd < 0) {
		fprintf(stderr, "Problem detected while creating the input file, %s, aborting!\n", strerror(errno));
		exit(-1);
	}
	write(fd, data, size);
	close(fd);
	process_file(name);
	remove(name);

	return 0;
}
#else
int main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		printf( "Usage: putty2john [.ppk PuTTY-Private-Key-File(s)]\n");
		printf( "\nKey types supported: RSA, DSA, ECDSA, ED25519\n");
		exit(1);
	}

	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}
#endif
