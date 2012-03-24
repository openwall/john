/**************************************************************************************

	FireMaster :  Firefox Master Password Recovery Tool
	Copyright (C) 2006  Nagareshwar Y Talekar ( tnagareshwar@gmail.com )

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

**************************************************************************************/

#ifdef HAVE_NSS
#include "KeyDBCracker.h"

/*
  What may go wrong ????
=========================================
 *) Instead of NSS_init ..more optimized secoid_init is used.
	If something goes wrong..use NSS_INIT and comment out section below it.
 *) Softoken optimized library is used. If you suspect just specify softoken.lib
    instead of softoken_opt lib without any hesitation
 *) Some of the sizes in KeyCrackData structure are assumed based on observation.
    In future this sizes may vary depending upon algo used.
*/


FILE *keyFile = NULL;


bool OpenKeyDBFile(char *keydbFileName)
{
	keyFile = fopen(keydbFileName, "rb");

	if( keyFile == NULL ) {
		printf("Failed to open file %s\n", keydbFileName);
		return FALSE;
	}
	return TRUE;
}


bool CrackKeyData(char *profilePath, struct KeyCrackData *keyCrackData)
{
	unsigned char buffer[KEYDB_MAX_BLOCK_SIZE];
	int index = 0;
	int globalSaltOffset;
	int mainOffset;
	struct KeyCrackOffset offData;
	int KEYDB_MAGIC_OFFSET;
	char off[2] = {0, 0};

	if(OpenKeyDBFile( profilePath ) == FALSE){
		return FALSE;
	}

	// First read the magic offset
	// This offset is present at offset 0x000f from the file..
	fseek(keyFile, 0x000e, SEEK_SET);

	if( fread(&off, 2, 1, keyFile) < 1) {
		printf("Error in reading magic data from %s file\n",KEYDB_FILENAME);
		return FALSE;
	}

	//printf("\n The magic offset part1 is : 0x%.8x ", off[0]);
	//printf("\n The magic offset part2 is : 0x%.8x ", off[1]);

	KEYDB_MAGIC_OFFSET = ( (off[0] << 8) + off[1] ) & 0xffff;

	//printf("\n The magic offset is : 0x%.8x ", KEYDB_MAGIC_OFFSET);

	// Go to magic offset and read the offset information block
	fseek(keyFile, KEYDB_MAGIC_OFFSET, SEEK_SET);

	if( fread(&offData, sizeof(struct KeyCrackOffset), 1, keyFile) < 1) {
		printf("Error in reading actual data from %s file\n",KEYDB_FILENAME);
		return FALSE;
	}

	//printf("\n read the offset data..succesfully ..");

	//Read and find the global salt offset and main offset

	globalSaltOffset =  (offData.glbSaltOff[0] << 8) + offData.glbSaltOff[1] + KEYDB_MAGIC_OFFSET;

	//printf("\n final offset for global salt is : 0x%.8x ", globalSaltOffset);

	fseek(keyFile, globalSaltOffset, SEEK_SET);

	keyCrackData->globalSaltLen = 20;
	if( fread(&keyCrackData->globalSalt, keyCrackData->globalSaltLen, 1, keyFile) < 1) {
		printf("Error in reading salt data from %s file\n",KEYDB_FILENAME);
		return FALSE;
	}

	keyCrackData->globalSalt[keyCrackData->globalSaltLen]=0;

	//For Firefox version 3 onwards the globalSaltOffset and mainOffset are interchanged,
	//One way to verify is to check if the globalSaltOffset data begins with pattern
	//03 ** 01 which implies it is mainOffset rather than globalSaltOffset

	if( ( keyCrackData->globalSalt[0] == 0x03 ) && ( keyCrackData->globalSalt[2] == 0x01 ) ) {
		//So this is mainOffset not the global offset
		//Let us interchange the offsets
		mainOffset = globalSaltOffset;
		globalSaltOffset = (offData.mainOff[0] << 8) + offData.mainOff[1] + KEYDB_MAGIC_OFFSET;

		//Read the global salt again...
		fseek(keyFile, globalSaltOffset, SEEK_SET);

		keyCrackData->globalSaltLen = 24;
		if( fread(&keyCrackData->globalSalt, keyCrackData->globalSaltLen, 1, keyFile) < 1) {
			printf("\n Error in reading salt data from %s file",KEYDB_FILENAME);
			return FALSE;
		}

		//For version 3.5 onwards global salt length is changed to 20 from 16
		//One simple way to check this is to verify where the global-salt string
		//begins which follows immediately after the global salt data....
		if( keyCrackData->globalSalt[20] == 'g' && keyCrackData->globalSalt[21] == 'l' )
			keyCrackData->globalSaltLen = 20;
		else
			keyCrackData->globalSaltLen = 16;

		//printf("\n Global salt length after adjustment %d", keyCrackData->globalSaltLen);

		keyCrackData->globalSalt[keyCrackData->globalSaltLen]=0;
	}
	else {
		mainOffset =  (offData.mainOff[0] << 8) + offData.mainOff[1] + KEYDB_MAGIC_OFFSET;
	}

	//Now read the main block of information...
	fseek(keyFile, mainOffset, SEEK_SET);

	//printf("\n final offset for main block is : 0x%.8x ", mainOffset);

	if( fread(buffer, KEYDB_MAX_BLOCK_SIZE, 1, keyFile) < 1) {
		printf("\n Error in reading main block data from %s file",KEYDB_FILENAME);
		return FALSE;
	}

	// Now extract the data and fill up the structure...

	// Read the version, salt length, nn length
	keyCrackData->version = buffer[index++];
	keyCrackData->saltLen = buffer[index++];
	keyCrackData->nnLen   = buffer[index++];

	// Copy the salt
	unsigned char *salt = (unsigned char*)malloc(keyCrackData->saltLen+1);
	memcpy(salt, &buffer[index], keyCrackData->saltLen);
	salt[keyCrackData->saltLen] =0;
	keyCrackData->salt = salt;

	index += keyCrackData->saltLen;

	// copy nick name
	unsigned char *nickName =  (unsigned char*) malloc(keyCrackData->nnLen+1);
	memcpy(nickName, &buffer[index], keyCrackData->nnLen);
	nickName[keyCrackData->nnLen] =0;
	keyCrackData->nickName = nickName;

	index +=keyCrackData->nnLen;

	// Copy OID stuff
	keyCrackData->oidLen = buffer[index++];
	unsigned char *oidData =  (unsigned char*) malloc(keyCrackData->oidLen+1);
	memcpy(oidData, &buffer[index], keyCrackData->oidLen);
	oidData[keyCrackData->oidLen] =0;
	keyCrackData->oidData = oidData;

	index +=keyCrackData->oidLen;

	// Copy encrypted string
	memcpy(keyCrackData->encData, &buffer[index], 16 );
	keyCrackData->encData[16] = 0;
	keyCrackData->encDataLen = 16;
	index += 16;

	// copy password check string .. currently not used
	unsigned char *pwCheckStr =  (unsigned char*) malloc( strlen(KEYDB_PW_CHECK_STR) + 1);
	memcpy(pwCheckStr, KEYDB_PW_CHECK_STR, strlen(KEYDB_PW_CHECK_STR));
	pwCheckStr[strlen(KEYDB_PW_CHECK_STR)] =0;
	keyCrackData->pwCheckStr = pwCheckStr;

	index += strlen(KEYDB_PW_CHECK_STR);



	//=== Just print here what he have got ....====
	/*
	int i;
	printf("\n Magic offset = 0x%x ", KEYDB_MAGIC_OFFSET);
	printf("\n Version : %d ", keyCrackData->version);

	printf("\n Global salt is \n");
	for(i=0; i < 16 ; i++)
		printf("%.2x ",keyCrackData->globalSalt[i]);

	printf("\n Salt is \n");
	for(i=0; i < 16 ; i++)
		printf("%.2x ",keyCrackData->salt[i]);


	printf("\n Encrypted data  is \n");
	for(i=0; i < 16 ; i++)
		printf("%.2x ",keyCrackData->encData[i]);

	printf("\n Algorithm is : \n ");
	for(i=0; i < keyCrackData->oidLen ; i++)
		printf("%.2x ",keyCrackData->oidData[i]);

	*/
	fclose(keyFile);

	return TRUE;
}
#endif
