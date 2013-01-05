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

#ifndef _PDFPARSER_H_
#define _PDFPARSER_H_

#include <stdio.h>

#include "pdfcrack_common.h"

#include "stdint.h"
#include "stdbool.h"

#define EENCNF -1 /* Encryption Object Not Found */
#define ETRANF -2 /* Trailer Information Not Found */
#define ETRENF -3 /* Trailer: Encryption Object Not Found */
#define ETRINF -4 /* Trailer: FileID Object Not Found */

bool
openPDF(FILE *file, EncData *e);

int
getEncryptedInfo(FILE *file, EncData *e);


#endif /** _PDFPARSER_H_ */
