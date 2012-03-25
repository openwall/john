/* mozilla2john.py processes input Mozilla profile paths into a format
 * suitable for use with JtR.
 *
 * Usage: mozilla2john [key3.db files] */

#ifdef HAVE_NSS
#include <string.h>
#include <libgen.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <nss.h>
#include <pk11pub.h>
#include <nssb64.h>
#include <pk11sdr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static void process_path(char *path)
{
	void *keySlot;
	char certpath[4096];
	char *mpath = strdup(path);
	char *keep_ptr = mpath;
	struct stat psb, csb;
	char *basepath = dirname(mpath);
	sprintf(certpath, "%s/%s", basepath, "cert8.db");

	if(stat(path, &psb) == 0 && stat(certpath, &csb) == -1) {
		/* we can't verify if Master Password is set or not, so warn user */
		if(S_ISDIR(psb.st_mode)) {
			fprintf (stderr, "%s is a directory, expecting key3.db file!\n", path);
			free(keep_ptr);
			return;
		}
		fprintf(stderr, "%s missing, can't verify if no Master Password is set!\n", certpath);
    		printf("%s:$mozilla$*%s\n",path, path);
		free(keep_ptr);
		return;
	}

	if (NSS_Init(basepath) != SECSuccess) {
		fprintf(stderr, "%s : NSS_Init failed, check if the given directory contains cert8.db and key3.db files.\n", basepath);
		free(keep_ptr);
		return;
	}

	if ((keySlot = PK11_GetInternalKeySlot()) == NULL) {
		fprintf(stderr, "PK11_GetInternalKeySlot failed, bug?\n");
		free(keep_ptr);
		NSS_Shutdown();
		return;
	}

	if (PK11_CheckUserPassword(keySlot, "") == SECSuccess) {
		fprintf(stderr, "%s : Master Password is not set!\n", path);
		free(keep_ptr);
		PK11_FreeSlot(keySlot);
		NSS_Shutdown();
		return;
	}

	free(keep_ptr);
	PK11_FreeSlot(keySlot);
	NSS_Shutdown();
    	printf("%s:$mozilla$*%s\n",path, path);
}

int mozilla2john(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		fprintf(stderr, "Usage: mozilla2john [key3.db files]");
		return 0;
	}
	for (i = 1; i < argc; i++)
		process_path(argv[i]);

	return 0;
}

#endif
