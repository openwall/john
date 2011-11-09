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

bool initPDFCrack(const EncData * e, const uint8_t * upw, const bool user);

void cleanPDFCrack(void);

bool runCrackRev2(void);

bool runCrackRev2_o(void);

bool runCrackRev2_of(void);

bool runCrackRev3(void);

bool runCrackRev3_o(void);

bool runCrackRev3_of(void);

int runCrack(char *password);

bool printProgress(void);

unsigned int getNrProcessed(void);


#endif /** _PDFCRACK_H_ */
