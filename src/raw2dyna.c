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
int all_hex=0;
int leading_salt=0;
char salt_sep=':';
int salt_len=5;
char itoa16[16] = "0123456789abcdef";

void ParseOptions(int argc, char **argv);
char *GetSalt(char*);

void usage(char *proc_name) {
  fprintf(stderr, "\
usage %s [options] < input > output\n\
\tOptions:\n\
\t\t-d=#   dyna number (-d=12 and $dynamic_12$hash$salt is used)\n\
\t\t-a     ALL hashes get $HEX$ and not simply hashes which have problems\n\
\t\t-ls=#  The salt is the leading data, and it is # bytes long\n\
\t\t-ss=b  The salt separator char is b  a blank -ss= means no separator char\n\
\tdefaults are -d=12 -ss=:\n", proc_name);
  exit(1);
}

int main(int argc, char **argv) {
	char Buf[256], *cps, *cph, *dummy;

	// if no input redirection then give usage. I 'guess' we could allow
	// a user to type in hashes, but is that really likely?  It is almost
	// certain that if there is no input redirection, the user does not
	// know how to use the tool, so tell him how.
	if (isatty(fileno(stdin)))
		usage(argv[0]);

	ParseOptions(argc, argv);
	dummy = fgets(Buf, sizeof(Buf), stdin);
	while (!feof(stdin)) {
		strtok(Buf, "\r\n");
		if (!leading_salt) {
			cph = Buf;
			cps = &Buf[32];
			if (salt_sep && *cps == salt_sep) ++cps;
		} else {
			cps = Buf;
			cph = &Buf[leading_salt];
			if (salt_sep && *cph == salt_sep) {*cph++ = 0;}
		}
		printf("$dynamic_%d$%32.32s$%s\n", dyna_num, cph, GetSalt(cps));
		dummy = fgets(Buf, sizeof(Buf), stdin);
	}
	(void) dummy;
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
		usage(argv[0]);
	}
}
