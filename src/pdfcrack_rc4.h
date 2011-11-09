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

#ifndef _RC4_H_
#define _RC4_H_

#include "stdint.h"
#include "stdbool.h"

void
rc4Decrypt(const uint8_t *key, const uint8_t *bs,
	   const unsigned int len, uint8_t *out);

bool
rc4Match40b(const uint8_t *key, const uint8_t *bs, const uint8_t *match);

bool
setrc4DecryptMethod(const unsigned int length);

#endif /** _RC4_H_ */
