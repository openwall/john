/* TrueCrypt volume importion to a format usable by John The Ripper
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2012.  No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2012 Alain Espinosa and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */
#include <stdio.h>

#include "misc.h"

static void print_help()
{
	printf("\nUtility to import TrueCrypt volume to a format crackeable by John The Ripper\n");
	printf("\nUsage: truecrypt_volume2john.exe volume_filename > output_file\n");
}

static void process_file(char * filename)
{
	int i;
	FILE* truecrypt_volume_file = NULL;// Volume file to read
	unsigned char header[512];// Encrypted header of the volume

	truecrypt_volume_file = fopen(filename, "rb");
	if(truecrypt_volume_file)
	{
		if( fread(header, 1, 512, truecrypt_volume_file) != 512 )
			fprintf(stderr, "%s : Truecrypt volume file to short: Need at least 512 bytes\n", filename);
		else
		{
			printf("%s:truecrypt_RIPEMD_160$", basename(filename));
			for(i = 0;i < 512; i++)
				printf("%02x", (int)(header[i]));
			printf(":normal::::%s\n", filename);

			printf("%s:truecrypt_SHA_512$", basename(filename));
			for(i = 0;i < 512; i++)
				printf("%02x", (int)(header[i]));
			printf(":normal::::%s\n", filename);

			printf("%s:truecrypt_WHIRLPOOL$", basename(filename));
			for(i = 0;i < 512; i++)
				printf("%02x", (int)(header[i]));
			printf(":normal::::%s\n", filename);

			// Try hidden volume if any
			if(!fseek(truecrypt_volume_file, 65536, SEEK_SET))
				if( fread(header, 1, 512, truecrypt_volume_file) == 512 )
				{
					printf("%s:truecrypt_RIPEMD_160$", basename(filename));
					for(i = 0;i < 512; i++)
						printf("%02x", (int)(header[i]));
					printf(":hidden::::%s\n", filename);

					printf("%s:truecrypt_SHA_512$", basename(filename));
					for(i = 0;i < 512; i++)
						printf("%02x", (int)(header[i]));
					printf(":hidden::::%s\n", filename);

					printf("%s:truecrypt_WHIRLPOOL$", basename(filename));
					for(i = 0;i < 512; i++)
						printf("%02x", (int)(header[i]));
					printf(":hidden::::%s\n", filename);
				}
		}

		fclose(truecrypt_volume_file);
		return;
	}
	fprintf(stderr, "%s : No truecrypt volume found", filename);
}

int truecrypt_volume2john(int argc, char **argv)
{
	int i;

	if(argc < 2)
	{
		fprintf(stderr, "Error: No truecrypt volume file specified.\n");
		print_help();
		return 1;
	}

	for (i = 1; i < argc; i++) {
		process_file(argv[i]);
	}

	return 0;
}
