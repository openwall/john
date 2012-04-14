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

#ifndef _PDFCRACK_H_
#define _PDFCRACK_H_

#include <stdio.h>
#include "pdfcrack_common.h"

struct custom_salt {
	struct EncData e;
	unsigned char *userpassword;
	/* load and restore following fields */
	unsigned int ekwlen;
	uint8_t encKeyWorkSpace[128];
	uint8_t password_user[33];
	uint8_t rev3TestKey[16];
	unsigned char *currPW;
	unsigned int currPWLen;
	bool knownPassword;
	bool workWithUser;
};

int runCrack(char *password, struct custom_salt *cs);
bool initPDFCrack(struct custom_salt *cs);
void loadPDFCrack(struct custom_salt *cs);

#endif /** _PDFCRACK_H_ */
