#ifndef	SIPDUMP_H
#define SIPDUMP_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/*
 * Copyright (C) 2007  Martin J. Muench <mjm@codito.de>
 *
 * See doc/SIPcrack-LICENSE
 *
 * Debug function that is activated through "-DDEBUG" switch
 */

void ic_debug(const char *fmt, ...)
{
	char buffer[4096];
	va_list ap;

	memset(buffer, 0, sizeof(buffer));
	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer) - 1, fmt, ap);
	va_end(ap);

	fprintf(stderr, "+ %s\n", buffer);
}

#ifdef DEBUG
#define debug(x) ic_debug x;
#else
#define debug(x) do { } while(1!=1);
#endif

void ic_debug(const char *fmt, ...);

#define VERSION             "0.3"	/* sipdump/sipcrack version */
#define DEFAULT_PCAP_FILTER "tcp or udp or vlan"	/* default packet capture filter */

/* sip field sizes */
#define HOST_MAXLEN       256	/* Max len of hostnames      */
#define USER_MAXLEN       128	/* Max len of user names     */
#define URI_MAXLEN        256	/* Max len of uri            */
#define NONCE_MAXLEN      128	/* Max len of nonce value    */
#define CNONCE_MAXLEN     128	/* Max len for cnonce value  */
#define NONCECOUNT_MAXLEN   8	/* Max len for nonce count   */
#define QOP_MAXLEN         12	/* Max len for qop value     */
#define LOGIN_MAXLEN     1024	/* Max len of login entry    */
#define ALG_MAXLEN          8	/* Max len of algorithm name */
#define METHOD_MAXLEN      16	/* Max len of method string  */

/* Hash stuff */
#define MD5_LEN            16	/* Len of MD5 binary hash    */
#define MD5_LEN_HEX        32	/* Len of MD5 hex hash       */
#define PW_MAXLEN          32	/* Max len of password       */

#define DYNAMIC_HASH_SIZE USER_MAXLEN + HOST_MAXLEN + 3
#define STATIC_HASH_SIZE  NONCE_MAXLEN + CNONCE_MAXLEN + NONCECOUNT_MAXLEN \
                          + QOP_MAXLEN + MD5_LEN_HEX + 6

/* Structure to hold login information */
typedef struct {
	char server[HOST_MAXLEN];
	char client[HOST_MAXLEN];
	char user[USER_MAXLEN];
	char realm[HOST_MAXLEN];
	char method[METHOD_MAXLEN];
	char uri[URI_MAXLEN];
	char nonce[NONCE_MAXLEN];
	char cnonce[NONCE_MAXLEN];
	char nonce_count[CNONCE_MAXLEN];
	char qop[QOP_MAXLEN];
	char algorithm[ALG_MAXLEN];
	char hash[MD5_LEN_HEX + 1];
} login_t;

#include <stdio.h>

void *Calloc(size_t);
void *Realloc(void *, size_t);
char **stringtoarray(char *, char, int *);
void get_string_input(char *, size_t, const char *, ...);
int is_binary(const unsigned char *, size_t);
void init_bin2hex(char[256][2]);
void bin_to_hex(char[256][2], const unsigned char *, size_t, char *, size_t);
void write_login_data(login_t *, const char *);
void update_login_data(login_t *, const char *, const char *);
int find_value(const char *, const char *, char *, size_t);
void Toupper(char *, size_t);
void extract_method(char *, const char *, size_t);

/*
 * Copyright (C) 2007  Martin J. Muench <mjm@codito.de>
 *
 * Some small hacked wrapper functions
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

/* malloc() wrapper */
void *Calloc(size_t size)
{
	void *buffer;

	buffer = calloc(size, 1);

	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: malloc failed\n", __FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}

	return (buffer);
}

/* realloc() wrapper */
void *Realloc(void *buffer, size_t size)
{

	buffer = realloc(buffer, size);

	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: malloc failed\n", __FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}

	return (buffer);
}

/* convert string to array */
char **stringtoarray(char *string, char delimiter, int *size)
{
	char **array = NULL;
	char *ptr, *oldptr;
	int flag = 1;
	int count;

	*size = 0;
	ptr = string;

	for (count = 0; flag; count++) {
		for (oldptr = ptr; *ptr && *ptr != delimiter; (void)*ptr++);
		if (!*ptr)
			flag = 0;
		*ptr++ = 0x00;
		(*size)++;

		if (!(array = realloc(array, (count + 1) * sizeof(char *)))) {
			fprintf(stderr, "realloc failed\n");
			exit(1);
		}
		array[count] = strdup(oldptr);
	}
	return array;
}

/* read input from stdin */
void get_string_input(char *outbuf, size_t outbuf_len, const char *fmt, ...)
{
	char msg[128];
	va_list ap;

	memset(msg, 0, sizeof(msg));
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	do {
		printf("%s", msg);
		fflush(stdout);
	} while (!fgets(outbuf, outbuf_len, stdin));

	/* Remove newline */
	outbuf[strcspn(outbuf, "\r\n")] = 0x00; // works for LF, CR, CRLF, LFCR, ...

	return;
}

/* check whether buffer contains binary characters */
int is_binary(const unsigned char *buffer, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!isascii(buffer[i]))
			return 1;
	}

	return 0;
}

/* init bin 2 hex table */
void init_bin2hex(char bin2hex_table[256][2])
{
	unsigned i = 0;

	for (i = 0; i < 256; i++) {
		bin2hex_table[i][0] =
		    (((i >> 4) & 0x0F) <=
		    0x09) ? (((i >> 4) & 0x0F) + '0') : (((i >> 4) & 0x0F) +
		    'a' - 10);
		bin2hex_table[i][1] =
		    (((i) & 0x0F) <=
		    0x09) ? (((i) & 0x0F) + '0') : (((i) & 0x0F) + 'a' - 10);
	}

	return;
}

/* convert bin to hex */
void bin_to_hex(char bin2hex_table[256][2],
    const unsigned char *bin_buffer,
    size_t bin_buffer_size, char *hex_buffer, size_t hex_buffer_size)
{
	unsigned i;

	for (i = 0; i < bin_buffer_size; ++i) {
		hex_buffer[i * 2] = bin2hex_table[bin_buffer[i]][0];
		hex_buffer[i * 2 + 1] = bin2hex_table[bin_buffer[i]][1];
	}

	hex_buffer[bin_buffer_size * 2] = 0x00;

	return;
}

/* write login data struct to dump file */
void write_login_data(login_t * data, const char *file)
{
	FILE *lfile;

	debug(("write_login_data() %s", file));

	if ((lfile = fopen(file, "a")) == NULL) {
		fprintf(stderr, "* Cannot open dump file: %s\n",
		    strerror(errno));
		return;
	}

	fprintf(lfile, "%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\n",
	    data->server,
	    data->client,
	    data->user,
	    data->realm,
	    data->method,
	    data->uri,
	    data->nonce,
	    data->cnonce,
	    data->nonce_count, data->qop, data->algorithm, data->hash);

	fclose(lfile);

	debug(("write_login_data() done"));

	return;
}

/* Update line in dump file with password */
void update_login_data(login_t * data, const char *pw, const char *file)
{
	FILE *login_file, *temp_file;
	char buffer[2048], orig_string[2048];
	char *tempfile;
	size_t tempfile_len;

	debug(("update_login_data(): %s", file));

	tempfile_len = (strlen(file) + strlen(".tmp") + 1);
	tempfile = (char *) Calloc(tempfile_len);

	snprintf(tempfile, tempfile_len, "%s.tmp", file);

	if ((login_file = fopen(file, "r")) == NULL) {
		fprintf(stderr, "* Cannot open dump file: %s\n",
		    strerror(errno));
		free(tempfile);
		return;
	}

	if ((temp_file = fopen(tempfile, "w")) == NULL) {
		fprintf(stderr, "* Cannot open temp file: %s\n",
		    strerror(errno));
		fclose(login_file);
		free(tempfile);
		return;
	}

	snprintf(orig_string, sizeof(orig_string),
	    "%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\n", data->server,
	    data->client, data->user, data->realm, data->method, data->uri,
	    data->nonce, data->cnonce, data->nonce_count, data->qop,
	    data->algorithm, data->hash);

	while ((fgets(buffer, sizeof(buffer), login_file)) != NULL) {
		if (!strncmp(buffer, orig_string, sizeof(buffer))) {
			fprintf(temp_file,
			    "%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\"%s\n",
			    data->server, data->client, data->user,
			    data->realm, data->method, data->uri, data->nonce,
			    data->cnonce, data->nonce_count, data->qop,
			    "PLAIN", pw);
		} else {
			fprintf(temp_file, "%s", buffer);
		}
	}

	fclose(login_file);
	fclose(temp_file);

	/* rename */
	if (rename(tempfile, file) < 0) {
		fprintf(stderr, "* Cannot rename tempfile to dump file: %s\n",
		    strerror(errno));
		free(tempfile);
		return;
	}

	free(tempfile);

	debug(("update_login_data() done"));
}

/* find value in buffer */
int find_value(const char *value, const char *buffer, char *outbuf,
    size_t outbuf_len)
{
	char *ptr1, *tempbuf;
	int i, b;

	/* debug(("find_value() %s", value)); */

	ptr1 = strstr(buffer, value);
	if (ptr1 == NULL)
		return -1;
	ptr1 += strlen(value);

	b = strlen(ptr1);
	tempbuf = Calloc(b + 1);

	/* value is quoted */
	if (ptr1[0] == '"') {
		for (i = 1; i < b; i++) {
			ptr1++;
			if (ptr1[0] == '"')
				break;
			tempbuf[i - 1] = ptr1[0];
		}
	}
	/* copy till ',', '\r' or '\n' */
	else {
		for (i = 0; i < b; i++) {
			if (ptr1[0] == ',' || ptr1[0] == 0x0d ||
			    ptr1[0] == 0x0a)
				break;
			tempbuf[i] = ptr1[0];
			ptr1++;
		}
	}

	strncpy(outbuf, tempbuf, outbuf_len - 1);
	outbuf[outbuf_len - 1] = 0;
	free(tempbuf);

	debug(("find_value: %s'%s'", value, outbuf));

	return 0;
}

void Toupper(char *buffer, size_t buffer_len)
{
	int i;

	for (i = 0; i < buffer_len; i++)
		buffer[i] = toupper(ARCH_INDEX(buffer[i]));

	return;
}

void extract_method(char *out, const char *in, size_t out_len)
{
	int i;

	debug(("extract_method() begin"));

	for (i = 0; i < out_len; i++) {
		if (in[i] == ' ')
			break;
		out[i] = in[i];
	}

	out[i] = 0x00;

	debug(("extract_method(): %s", out));

	return;
}

#endif
