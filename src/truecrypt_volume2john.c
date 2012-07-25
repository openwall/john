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

void print_help()
{
	printf("/////////////////////////////////////////////////////////////////////////////\n");
	printf("Utility to import TrueCrypt volume to a format crackeable by John The Ripper\n");
	printf("/////////////////////////////////////////////////////////////////////////////\n");
	printf("Usage: truecrypt_volume2john.exe volume_filename > output_file\n");
}

int main(int argc, char **argv)
{
	FILE* truecrypt_volume_file = NULL;// Volume file to read
	unsigned char header[512];// Encrypted header of the volume
	int i;

	if(argc != 2)
	{
		printf("Error: No truecrypt volume file specified.\n");
		print_help();
		return 0;
	}

	truecrypt_volume_file = fopen(argv[1], "rb");
	if(truecrypt_volume_file)
	{
		if( fread(header, 1, 512, truecrypt_volume_file) != 512 )
			printf("Truecrypt volume file to short: Need at least 512 bytes\n");
		else
		{
			printf("truecrypt_normal_volume:truecrypt_RIPEMD_160$");
			for(i = 0;i < 512; i++)
				printf("%02x", (int)(header[i]));
			printf("\n");

			printf("truecrypt_normal_volume:truecrypt_SHA_512$");
			for(i = 0;i < 512; i++)
				printf("%02x", (int)(header[i]));
			printf("\n");

			printf("truecrypt_normal_volume:truecrypt_WHIRLPOOL$");
			for(i = 0;i < 512; i++)
				printf("%02x", (int)(header[i]));
			printf("\n");

			// Try hidden volume if any
			if(!fseek(truecrypt_volume_file, 65536, SEEK_SET))
				if( fread(header, 1, 512, truecrypt_volume_file) == 512 )
				{
					printf("truecrypt_hidden_volume:truecrypt_RIPEMD_160$");
					for(i = 0;i < 512; i++)
						printf("%02x", (int)(header[i]));
					printf("\n");

					printf("truecrypt_hidden_volume:truecrypt_SHA_512$");
					for(i = 0;i < 512; i++)
						printf("%02x", (int)(header[i]));
					printf("\n");

					printf("truecrypt_hidden_volume:truecrypt_WHIRLPOOL$");
					for(i = 0;i < 512; i++)
						printf("%02x", (int)(header[i]));
					printf("\n");
				}
		}

		fclose(truecrypt_volume_file);
		return 0;
	}

	printf("No truecrypt volume found");
	return -1;
}