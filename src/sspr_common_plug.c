/*
 * Common code for the NetIQ SSPR format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "sspr_common.h"

struct fmt_tests sspr_tests[] = {
	// NetIQ SSPR hashes
	{"$sspr$1$100000$NONE$64840051a425cbc0b4e2d3750d9e0de3e800de18", "password@12345"},
	{"$sspr$1$100000$NONE$5cd2aeb3adf2baeca485672f01486775a208a40e", "openwall@12345"},
	{"$sspr$2$100000$tMR6sNepv6M6nOqOy3SWnAUWo22p0GI7$f0ae3140ce2cf46c13d0b6c4bd4fab65b45b27c0", "openwall@123"},
	{"$sspr$2$100000$BrWV47lSy3Mwpp8pb60ZlJS85YS242bo$1f71c58c8dfc16c9037d3cd1cf21d1139cad4fa4", "password@123"},
	{"$sspr$3$100000$blwmhFBUiq67iEX9WFc8EG8mCxWL4tCR$c0706a057dfdb5d31d6dd40f060c8982e1e134fdf1e7eb0d299009c2f56c1936", "hello@12345"},
	{"$sspr$3$100000$lNInqvnmbv9x65N2ltQeCialILG8Fr47$6bd508dcc2a5626c9d7ab3296bcce0538ca0ba24bf43cd2aebe2f58705814a00", "abc@123"},
	{"$sspr$4$100000$ZP3ftUBQwrovglISxt9ujUtwslsSMCjj$a2a89e0e185f2a32f18512415e4dfc379629f0222ead58f0207e9c9f7424c36fe9c7a615be6035849c11da1293da78e50e725a664b7f5fe123ede7871f13ae7f", "hello@123"},
	{"$sspr$4$100000$ZzhxK3gHP8HVkcELqIeybuRWvZjDirtg$ca5608befc50075bc4a1441de23beb4a034197d70df670addabc62a4a4d26b2e78ee38c50e9d18ce55d31b00fbb9916af12e80bf3e395ff38e58f8a958427602", "hello@12345"},
	{"$sspr$0$100000$NONE$1e6172e71e6af1c15f4c5ca658815835", "abc@12345"},
	{"$sspr$0$100000$NONE$1117af8ec9f70e8eed192c6c01776b6b", "abc@123"},
	{"$sspr$2$100000$4YtbuUHaTSHBuE1licTV16KjSZuMMMCn$23b3cf4e1a951b2ed9d5df43632f77092fa93128", "\xe4""bc@123"},  // original password was "äbc@123", application uses a code page
	// Adobe AEM hashes
	{"$sspr$3$1000$a9d4b340cb43807b$33b8875ff3f9619e6ae984add262fb6b6f043e8ff9b065f4fb0863021aada275", "admin"},
	{"$sspr$3$1000$fe90d85cdcd7e79c$ef182cdc47e60b472784e42a6e167d26242648c6b2e063dfd9e27eec9aa38912", "Aa12345678!@"},
	{NULL}
};

int sspr_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)  // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0 && value != 1 && value != 2 && value != 3 && value != 4)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // salt
		goto err;
	if (strlen(p) > MAX_SALT_LEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // binary
		goto err;
	value = hexlenl(p, &extra);
	if (value < BINARY_SIZE_MIN * 2 || value > BINARY_SIZE * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *sspr_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.fmt = atoi(p);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = strlen(p);
	strncpy(cs.salt, p, MAX_SALT_LEN);

	MEM_FREE(keeptr);

	return &cs;
}

void *sspr_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	memset(buf.c, 0, BINARY_SIZE);
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE_MIN; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

unsigned int sspr_get_kdf_type(void *salt)
{
	return ((struct custom_salt *)salt)->fmt;
}

unsigned int sspr_get_iteration_count(void *salt)
{
	struct custom_salt *ctx = salt;

	return (unsigned int) ctx->iterations;
}
