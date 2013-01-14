// convert a 'raw' file of hash:salt or hash$salt or $dynamic_n$hash$salt into JtR dynamic format.
// It will make sure the salt does not contain any 'bad' characters, and if so, it will convert
// the salt into the $HEX$ format.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// isatty() in different locations, for VC, vs *unix.
#ifdef _MSC_VER
#include <io.h>
#else
#include <unistd.h>
#endif

int dyna_num=12;
int hash_len=32;
int all_hex=0;
int leading_salt=0;
char salt_sep=':';
int salt_len=5;
char itoa16[16] = "0123456789abcdef";
int atoi16[256];
int simple_to_from_hex=0;
char *raw_str=NULL; // used for simple hex convert

void ParseOptions(int argc, char **argv);
char *GetSalt(char*);
int simple_convert();

void usage(char *proc_name) {
	fprintf(stderr, "\
usage %s [options] < input > output\n\
\tOptions:\n\
\t\t-d=#   dyna number (-d=12 and $dynamic_12$hash$salt is used)\n\
\t\t-a     ALL hashes get $HEX$ and not simply hashes which have problems\n\
\t\t-ls=#  The salt is the leading data, and it is # bytes long\n\
\t\t-ss=b  The salt separator char is b  a blank -ss= means no separator char\n\
\t\t-hl=n  The length of hash.  SHA1 is 40, MD4/5 is 32, SHA256 is 64, etc\n\
\t\t-2h=r  perform a simple convert to hex.  the string r is converted to $HEX$hhhh...\n\
\t\t-2r=h  perform a simple convert out of hex.  the hex string h is converted to raw data\n\
\t\t       if either -2h or -2r are used, then the convert is done and the program exits\n\
\tdefaults are -d=12 -ss=: -hl=32\n", proc_name);
	exit(1);
}

#define FGETS(s, size, stream)	if (!fgets(s, size, stream)) if (ferror(stream)) { fprintf(stderr, "error\n"); exit(1); }

void Setup() {
	int i;
	memset(atoi16, 0x7F, sizeof(atoi16));
	for (i = 0; i < 10; ++i)
		atoi16[i+'0'] = i;
	atoi16['a'] = atoi16['A'] = 10;
	atoi16['b'] = atoi16['B'] = 11;
	atoi16['c'] = atoi16['C'] = 12;
	atoi16['d'] = atoi16['D'] = 13;
	atoi16['e'] = atoi16['E'] = 14;
	atoi16['f'] = atoi16['F'] = 15;
}

int main(int argc, char **argv) {
	char Buf[256], *cps, *cph;

	Setup();
	ParseOptions(argc, argv);
	if (simple_to_from_hex)
		return simple_convert();

	// if no input redirection then give usage. I 'guess' we could allow
	// a user to type in hashes, but is that really likely?  It is almost
	// certain that if there is no input redirection, the user does not
	// know how to use the tool, so tell him how.
	if (isatty(fileno(stdin)))
		usage(argv[0]);

	FGETS(Buf, sizeof(Buf), stdin);
	while (!feof(stdin)) {
		strtok(Buf, "\r\n");
		if (!leading_salt) {
			cph = Buf;
			cps = &Buf[hash_len];
			if (salt_sep && *cps == salt_sep) ++cps;
		} else {
			cps = Buf;
			cph = &Buf[leading_salt];
			if (salt_sep && *cph == salt_sep) {*cph++ = 0;}
		}
		printf("$dynamic_%d$%*.*s$%s\n", dyna_num, hash_len,hash_len, cph, GetSalt(cps));
		FGETS(Buf, sizeof(Buf), stdin);
	}
	return 0;
}


char *GetSalt(char *s) {
	static char hexbuf[256];
	char *cpo=hexbuf, *cp;
	int tohex=0;
	int max = leading_salt;
	if (all_hex) tohex=1;
	else {
		cp = s;
		while (*cp) {
			// NOTE, some of these chars will never be seen in this app, due to strtok taking them out, or
			// due to the C language not allowing them (i.e. null).  But they are listed here for documenation
			if (*cp == ':' || *cp == '\\' || *cp == '\n' || *cp == '\r' || *cp == '\x0') { tohex=1; break; }
			++cp;
		}
	}
	if (!tohex) return s;
	cpo += sprintf(hexbuf, "HEX$");
	while (*s) {
		*cpo++ = itoa16[(((unsigned char)*s)>>4)&0xF];
		*cpo++ = itoa16[((unsigned char)*s)&0xF];
		++s;
		if (max) {
			if (--max == 0) break;
		}
	}
	*cpo = 0;
	return hexbuf;
}

void ParseOptions(int argc, char **argv) {
	int i;
	for (i = 1; i < argc; ++i) {
		if (!strncmp(argv[i], "-d=", 3)) { dyna_num=strtol(&argv[i][3],NULL,10); continue; }
		if (!strcmp(argv[i], "-a"))      { all_hex=1; continue; }
		if (!strncmp(argv[i], "-ls=",4)) { leading_salt=strtol(&argv[i][4],NULL,10); continue; }
		if (!strncmp(argv[i], "-ss=",4)) { salt_sep=argv[i][4]; continue; }
		if (!strncmp(argv[i], "-hl=",4)) { hash_len=strtol(&argv[i][4],NULL,10); continue; }
		if (!strncmp(argv[i], "-2h=",4)) { simple_to_from_hex=1; raw_str = &argv[i][4]; continue; }
		if (!strncmp(argv[i], "-2r=",4)) { simple_to_from_hex=2; raw_str = &argv[i][4]; continue; }
		usage(argv[0]);
	}
}

int simple_convert() {
	unsigned char *p = (unsigned char*)raw_str;
	if (simple_to_from_hex==1) {
		// convert a raw value into hex
		printf ("$HEX$");
		while (*p)
			printf("%02x", *p++);
	} else {
		if (!strncmp(raw_str, "$HEX$", 5))
			p += 5;
		while (p[0] && p[1] && atoi16[p[0]] != 0x7f && atoi16[p[1]] != 0x7f) {
			printf("%c", atoi16[p[0]]*16+atoi16[p[1]]);
			p += 2;
		}
	}
	return 0;
}
