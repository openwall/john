/**
 * Copyright (C) 2006 Henning Norén
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef _PDFCOMMON_H_
#define _PDFCOMMON_H_

#include "stdint.h"
#include "stdbool.h"

/**
    EncData holds all the information regarding the encryption-setting of a
    specific pdf.
    s_handler - Security handler string.
    o_string - Owner-string, 32 bytes, not null-terminated
    u_string - User-string, 32 bytes, not null-terminated
    fileID - file ID in fileIDLen bytes, not null-terminated
*/
typedef struct EncData {
	char s_handler[33];
	uint8_t o_string[33];
	uint8_t u_string[33];
	uint8_t fileID[33];
	bool encryptMetaData;
	bool work_with_user;
	bool have_userpassword;
	unsigned int fileIDLen;
	unsigned int version_major;
	unsigned int version_minor;
	int length;
	int permissions;
	int revision;
	int version;
} EncData;

void freeEncData(EncData * e, int is_static_object);

void printEncData(EncData * e);

#endif /** _PDFCOMMON_H_ */
