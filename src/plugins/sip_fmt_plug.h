/*
 * Copyright (C) 2007  Martin J. Muench <mjm@codito.de>
 *
 * See doc/SIPcrack-LICENSE */

#ifndef SIP_FMT_PLUG_H
#define SIP_FMT_PLUG_H

/* sip field sizes */
#define HOST_MAXLEN       256    /* Max len of hostnames      */
#define USER_MAXLEN       128    /* Max len of user names     */
#define URI_MAXLEN        256    /* Max len of uri            */
#define NONCE_MAXLEN      128    /* Max len of nonce value    */
#define CNONCE_MAXLEN     128    /* Max len for cnonce value  */
#define NONCECOUNT_MAXLEN   9    /* Max len for nonce count   */
#define QOP_MAXLEN         12    /* Max len for qop value     */
#define LOGIN_MAXLEN     1024    /* Max len of login entry    */
#define ALG_MAXLEN          8    /* Max len of algorithm name */
#define METHOD_MAXLEN      16    /* Max len of method string  */

/* Hash stuff */
#define MD5_LEN            16    /* Len of MD5 binary hash    */
#define MD5_LEN_HEX        32    /* Len of MD5 hex hash       */
#define PW_MAXLEN          32    /* Max len of password       */

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
	char cnonce[CNONCE_MAXLEN];
	char nonce_count[NONCECOUNT_MAXLEN];
	char qop[QOP_MAXLEN];
	char algorithm[ALG_MAXLEN];
	char hash[MD5_LEN_HEX+1];
} login_t;

int stringtoarray(char **array, char *string, char delimiter)
{
	char *ptr, *oldptr;
	int flag = 1;
	int count;
	int size = 0;
	ptr = string;
	for (count=0 ; flag ; count++) {
		for (oldptr=ptr;*ptr&&*ptr!=delimiter;(void)*ptr++)
			;
		if (!*ptr) flag = 0;
		*ptr++ = 0x00;
		size++;
		array[count] = oldptr;
	}
	return size;
}

/* init bin 2 hex table */
void init_bin2hex(char bin2hex_table[256][2])
{
	unsigned i=0;
	for (i=0;i<256;i++) {
		bin2hex_table[i][0] = ( ((i >> 4) & 0x0F) <= 0x09) ? (((i >> 4) & 0x0F) + '0') : (((i >> 4) & 0x0F) + 'a' - 10);
		bin2hex_table[i][1] = ( ((i)      & 0x0F) <= 0x09) ? (((i)      & 0x0F) + '0') : (((i)      & 0x0F) + 'a' - 10);
	}
	return;
}

/* convert bin to hex */
void bin_to_hex(char bin2hex_table[256][2],
		const unsigned char *bin_buffer,
		size_t bin_buffer_size,
		char * hex_buffer,
		size_t hex_buffer_size)
{
	unsigned i;
	for (i=0;i<bin_buffer_size; ++i) {
		hex_buffer[i*2  ] = bin2hex_table[bin_buffer[i]][0];
		hex_buffer[i*2+1] = bin2hex_table[bin_buffer[i]][1];
	}
	hex_buffer[bin_buffer_size*2] = 0x00;
	return;
}

#endif
