/*
 * This is MIME Base64 (as opposed to crypt(3) encoding found in common.[ch])
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "memdbg.h"

void base64_unmap(char *in_block) {
  int i;
  char *c;

  for(i=0; i<4; i++) {
    c = in_block + i;

    if(*c>='A' && *c<='Z') {
      *c -= 'A';
      continue;
    }

    if(*c>='a' && *c<='z') {
      *c -= 'a';
      *c += 26;
      continue;
    }

    if(*c == '+') {
      *c = 62;
      continue;
    }

    if(*c == '/') {
      *c = 63;
      continue;
    }

    if(*c == '=') {
      *c = 0;
    }

    *c -= '0';
    *c += 52;
  }
}

int base64_decode(char *in, int inlen, char *out) {
  int i;
  char *in_block;
  char *out_block;
  char temp[4];

  out_block = out;
  in_block = in;

  for(i=0; i<inlen; i+=4) {

    if(*in_block == '=')
      return 0;

    memcpy(temp, in_block, 4);
    memset(out_block, 0, 3);
    base64_unmap(temp);

    out_block[0] =
      ((temp[0]<<2) & 0xfc) | ((temp[1]>>4) & 3);
    out_block[1] =
      ((temp[1]<<4) & 0xf0) | ((temp[2]>>2) & 0xf);
    out_block[2] =
      ((temp[2]<<6) & 0xc0) | ((temp[3]   ) & 0x3f);

    out_block += 3;
    in_block += 4;
  }

  return 0;
}


static const char *cr64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const char *mi64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

char *mime64_to_crypt64(const char *in, char *out, int len) {
	int i;
	char *cp;
	for (i = 0; i < len; ++i) {
		cp = strchr(mi64, in[i]);
		if (!cp) {
			out[i] = 0;
			return out;
		}
		out[i] = cr64[cp-mi64];
	}
	out[i] = 0;
	return out;
}

char *crypt64_to_mime64(const char *in, char *out, int len) {
	int i;
	char *cp;
	for (i = 0; i < len; ++i) {
		cp = strchr(cr64, in[i]);
		if (!cp) {
			out[i] = 0;
			return out;
		}
		out[i] = mi64[cp-cr64];
	}
	out[i] = 0;
	return out;
}
