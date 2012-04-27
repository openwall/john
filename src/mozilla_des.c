/*
 *  des.c
 *
 *  core source file for DES-150 library
 *  Make key schedule from DES key.
 *  Encrypt/Decrypt one 8-byte block.
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is the DES-150 library.
 *
 * The Initial Developer of the Original Code is Nelson B. Bolyard,
 * nelsonb@iname.com.  Portions created by Nelson B. Bolyard are
 * Copyright (C) 1990, 2000  Nelson B. Bolyard, All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable
 * instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the GPL.
 */

#ifdef HAVE_NSS
#include "mozilla_des.h"
#include <stddef.h>
#include <stdio.h>

//#define USE_INDEXING 1

/*
 * The tables below are the 8 sbox functions, with the 6-bit input permutation
 * and the 32-bit output permutation pre-computed.
 * They are shifted circularly to the left 3 bits, which removes 2 shifts
 * and an or from each round by reducing the number of sboxes whose
 * indices cross word broundaries from 2 to 1.
 */

static	const HALF SP[8][64] = {
/* Box S1 */ {
	0x04041000, 0x00000000, 0x00040000, 0x04041010,
	0x04040010, 0x00041010, 0x00000010, 0x00040000,
	0x00001000, 0x04041000, 0x04041010, 0x00001000,
	0x04001010, 0x04040010, 0x04000000, 0x00000010,
	0x00001010, 0x04001000, 0x04001000, 0x00041000,
	0x00041000, 0x04040000, 0x04040000, 0x04001010,
	0x00040010, 0x04000010, 0x04000010, 0x00040010,
	0x00000000, 0x00001010, 0x00041010, 0x04000000,
	0x00040000, 0x04041010, 0x00000010, 0x04040000,
	0x04041000, 0x04000000, 0x04000000, 0x00001000,
	0x04040010, 0x00040000, 0x00041000, 0x04000010,
	0x00001000, 0x00000010, 0x04001010, 0x00041010,
	0x04041010, 0x00040010, 0x04040000, 0x04001010,
	0x04000010, 0x00001010, 0x00041010, 0x04041000,
	0x00001010, 0x04001000, 0x04001000, 0x00000000,
	0x00040010, 0x00041000, 0x00000000, 0x04040010
    },
/* Box S2 */ {
	0x00420082, 0x00020002, 0x00020000, 0x00420080,
	0x00400000, 0x00000080, 0x00400082, 0x00020082,
	0x00000082, 0x00420082, 0x00420002, 0x00000002,
	0x00020002, 0x00400000, 0x00000080, 0x00400082,
	0x00420000, 0x00400080, 0x00020082, 0x00000000,
	0x00000002, 0x00020000, 0x00420080, 0x00400002,
	0x00400080, 0x00000082, 0x00000000, 0x00420000,
	0x00020080, 0x00420002, 0x00400002, 0x00020080,
	0x00000000, 0x00420080, 0x00400082, 0x00400000,
	0x00020082, 0x00400002, 0x00420002, 0x00020000,
	0x00400002, 0x00020002, 0x00000080, 0x00420082,
	0x00420080, 0x00000080, 0x00020000, 0x00000002,
	0x00020080, 0x00420002, 0x00400000, 0x00000082,
	0x00400080, 0x00020082, 0x00000082, 0x00400080,
	0x00420000, 0x00000000, 0x00020002, 0x00020080,
	0x00000002, 0x00400082, 0x00420082, 0x00420000
    },
/* Box S3 */ {
	0x00000820, 0x20080800, 0x00000000, 0x20080020,
	0x20000800, 0x00000000, 0x00080820, 0x20000800,
	0x00080020, 0x20000020, 0x20000020, 0x00080000,
	0x20080820, 0x00080020, 0x20080000, 0x00000820,
	0x20000000, 0x00000020, 0x20080800, 0x00000800,
	0x00080800, 0x20080000, 0x20080020, 0x00080820,
	0x20000820, 0x00080800, 0x00080000, 0x20000820,
	0x00000020, 0x20080820, 0x00000800, 0x20000000,
	0x20080800, 0x20000000, 0x00080020, 0x00000820,
	0x00080000, 0x20080800, 0x20000800, 0x00000000,
	0x00000800, 0x00080020, 0x20080820, 0x20000800,
	0x20000020, 0x00000800, 0x00000000, 0x20080020,
	0x20000820, 0x00080000, 0x20000000, 0x20080820,
	0x00000020, 0x00080820, 0x00080800, 0x20000020,
	0x20080000, 0x20000820, 0x00000820, 0x20080000,
	0x00080820, 0x00000020, 0x20080020, 0x00080800
    },
/* Box S4 */ {
	0x02008004, 0x00008204, 0x00008204, 0x00000200,
	0x02008200, 0x02000204, 0x02000004, 0x00008004,
	0x00000000, 0x02008000, 0x02008000, 0x02008204,
	0x00000204, 0x00000000, 0x02000200, 0x02000004,
	0x00000004, 0x00008000, 0x02000000, 0x02008004,
	0x00000200, 0x02000000, 0x00008004, 0x00008200,
	0x02000204, 0x00000004, 0x00008200, 0x02000200,
	0x00008000, 0x02008200, 0x02008204, 0x00000204,
	0x02000200, 0x02000004, 0x02008000, 0x02008204,
	0x00000204, 0x00000000, 0x00000000, 0x02008000,
	0x00008200, 0x02000200, 0x02000204, 0x00000004,
	0x02008004, 0x00008204, 0x00008204, 0x00000200,
	0x02008204, 0x00000204, 0x00000004, 0x00008000,
	0x02000004, 0x00008004, 0x02008200, 0x02000204,
	0x00008004, 0x00008200, 0x02000000, 0x02008004,
	0x00000200, 0x02000000, 0x00008000, 0x02008200
    },
/* Box S5 */ {
	0x00000400, 0x08200400, 0x08200000, 0x08000401,
	0x00200000, 0x00000400, 0x00000001, 0x08200000,
	0x00200401, 0x00200000, 0x08000400, 0x00200401,
	0x08000401, 0x08200001, 0x00200400, 0x00000001,
	0x08000000, 0x00200001, 0x00200001, 0x00000000,
	0x00000401, 0x08200401, 0x08200401, 0x08000400,
	0x08200001, 0x00000401, 0x00000000, 0x08000001,
	0x08200400, 0x08000000, 0x08000001, 0x00200400,
	0x00200000, 0x08000401, 0x00000400, 0x08000000,
	0x00000001, 0x08200000, 0x08000401, 0x00200401,
	0x08000400, 0x00000001, 0x08200001, 0x08200400,
	0x00200401, 0x00000400, 0x08000000, 0x08200001,
	0x08200401, 0x00200400, 0x08000001, 0x08200401,
	0x08200000, 0x00000000, 0x00200001, 0x08000001,
	0x00200400, 0x08000400, 0x00000401, 0x00200000,
	0x00000000, 0x00200001, 0x08200400, 0x00000401
    },
/* Box S6 */ {
	0x80000040, 0x81000000, 0x00010000, 0x81010040,
	0x81000000, 0x00000040, 0x81010040, 0x01000000,
	0x80010000, 0x01010040, 0x01000000, 0x80000040,
	0x01000040, 0x80010000, 0x80000000, 0x00010040,
	0x00000000, 0x01000040, 0x80010040, 0x00010000,
	0x01010000, 0x80010040, 0x00000040, 0x81000040,
	0x81000040, 0x00000000, 0x01010040, 0x81010000,
	0x00010040, 0x01010000, 0x81010000, 0x80000000,
	0x80010000, 0x00000040, 0x81000040, 0x01010000,
	0x81010040, 0x01000000, 0x00010040, 0x80000040,
	0x01000000, 0x80010000, 0x80000000, 0x00010040,
	0x80000040, 0x81010040, 0x01010000, 0x81000000,
	0x01010040, 0x81010000, 0x00000000, 0x81000040,
	0x00000040, 0x00010000, 0x81000000, 0x01010040,
	0x00010000, 0x01000040, 0x80010040, 0x00000000,
	0x81010000, 0x80000000, 0x01000040, 0x80010040
    },
/* Box S7 */ {
	0x00800000, 0x10800008, 0x10002008, 0x00000000,
	0x00002000, 0x10002008, 0x00802008, 0x10802000,
	0x10802008, 0x00800000, 0x00000000, 0x10000008,
	0x00000008, 0x10000000, 0x10800008, 0x00002008,
	0x10002000, 0x00802008, 0x00800008, 0x10002000,
	0x10000008, 0x10800000, 0x10802000, 0x00800008,
	0x10800000, 0x00002000, 0x00002008, 0x10802008,
	0x00802000, 0x00000008, 0x10000000, 0x00802000,
	0x10000000, 0x00802000, 0x00800000, 0x10002008,
	0x10002008, 0x10800008, 0x10800008, 0x00000008,
	0x00800008, 0x10000000, 0x10002000, 0x00800000,
	0x10802000, 0x00002008, 0x00802008, 0x10802000,
	0x00002008, 0x10000008, 0x10802008, 0x10800000,
	0x00802000, 0x00000000, 0x00000008, 0x10802008,
	0x00000000, 0x00802008, 0x10800000, 0x00002000,
	0x10000008, 0x10002000, 0x00002000, 0x00800008
    },
/* Box S8 */ {
	0x40004100, 0x00004000, 0x00100000, 0x40104100,
	0x40000000, 0x40004100, 0x00000100, 0x40000000,
	0x00100100, 0x40100000, 0x40104100, 0x00104000,
	0x40104000, 0x00104100, 0x00004000, 0x00000100,
	0x40100000, 0x40000100, 0x40004000, 0x00004100,
	0x00104000, 0x00100100, 0x40100100, 0x40104000,
	0x00004100, 0x00000000, 0x00000000, 0x40100100,
	0x40000100, 0x40004000, 0x00104100, 0x00100000,
	0x00104100, 0x00100000, 0x40104000, 0x00004000,
	0x00000100, 0x40100100, 0x00004000, 0x00104100,
	0x40004000, 0x00000100, 0x40000100, 0x40100000,
	0x40100100, 0x40000000, 0x00100000, 0x40004100,
	0x00000000, 0x40104100, 0x00100100, 0x40000100,
	0x40100000, 0x40004000, 0x40004100, 0x00000000,
	0x40104100, 0x00104000, 0x00104000, 0x00004100,
	0x00004100, 0x00100100, 0x40000000, 0x40104000
    }
};


static const HALF PC2[8][64] = {
/* table 0 */ {
    0x00000000, 0x00001000, 0x04000000, 0x04001000,
    0x00100000, 0x00101000, 0x04100000, 0x04101000,
    0x00008000, 0x00009000, 0x04008000, 0x04009000,
    0x00108000, 0x00109000, 0x04108000, 0x04109000,
    0x00000004, 0x00001004, 0x04000004, 0x04001004,
    0x00100004, 0x00101004, 0x04100004, 0x04101004,
    0x00008004, 0x00009004, 0x04008004, 0x04009004,
    0x00108004, 0x00109004, 0x04108004, 0x04109004,
    0x08000000, 0x08001000, 0x0c000000, 0x0c001000,
    0x08100000, 0x08101000, 0x0c100000, 0x0c101000,
    0x08008000, 0x08009000, 0x0c008000, 0x0c009000,
    0x08108000, 0x08109000, 0x0c108000, 0x0c109000,
    0x08000004, 0x08001004, 0x0c000004, 0x0c001004,
    0x08100004, 0x08101004, 0x0c100004, 0x0c101004,
    0x08008004, 0x08009004, 0x0c008004, 0x0c009004,
    0x08108004, 0x08109004, 0x0c108004, 0x0c109004
  },
/* table 1 */ {
    0x00000000, 0x00002000, 0x80000000, 0x80002000,
    0x00000008, 0x00002008, 0x80000008, 0x80002008,
    0x00200000, 0x00202000, 0x80200000, 0x80202000,
    0x00200008, 0x00202008, 0x80200008, 0x80202008,
    0x20000000, 0x20002000, 0xa0000000, 0xa0002000,
    0x20000008, 0x20002008, 0xa0000008, 0xa0002008,
    0x20200000, 0x20202000, 0xa0200000, 0xa0202000,
    0x20200008, 0x20202008, 0xa0200008, 0xa0202008,
    0x00000400, 0x00002400, 0x80000400, 0x80002400,
    0x00000408, 0x00002408, 0x80000408, 0x80002408,
    0x00200400, 0x00202400, 0x80200400, 0x80202400,
    0x00200408, 0x00202408, 0x80200408, 0x80202408,
    0x20000400, 0x20002400, 0xa0000400, 0xa0002400,
    0x20000408, 0x20002408, 0xa0000408, 0xa0002408,
    0x20200400, 0x20202400, 0xa0200400, 0xa0202400,
    0x20200408, 0x20202408, 0xa0200408, 0xa0202408
  },
/* table 2 */ {
    0x00000000, 0x00004000, 0x00000020, 0x00004020,
    0x00080000, 0x00084000, 0x00080020, 0x00084020,
    0x00000800, 0x00004800, 0x00000820, 0x00004820,
    0x00080800, 0x00084800, 0x00080820, 0x00084820,
    0x00000010, 0x00004010, 0x00000030, 0x00004030,
    0x00080010, 0x00084010, 0x00080030, 0x00084030,
    0x00000810, 0x00004810, 0x00000830, 0x00004830,
    0x00080810, 0x00084810, 0x00080830, 0x00084830,
    0x00400000, 0x00404000, 0x00400020, 0x00404020,
    0x00480000, 0x00484000, 0x00480020, 0x00484020,
    0x00400800, 0x00404800, 0x00400820, 0x00404820,
    0x00480800, 0x00484800, 0x00480820, 0x00484820,
    0x00400010, 0x00404010, 0x00400030, 0x00404030,
    0x00480010, 0x00484010, 0x00480030, 0x00484030,
    0x00400810, 0x00404810, 0x00400830, 0x00404830,
    0x00480810, 0x00484810, 0x00480830, 0x00484830
  },
/* table 3 */ {
    0x00000000, 0x40000000, 0x00000080, 0x40000080,
    0x00040000, 0x40040000, 0x00040080, 0x40040080,
    0x00000040, 0x40000040, 0x000000c0, 0x400000c0,
    0x00040040, 0x40040040, 0x000400c0, 0x400400c0,
    0x10000000, 0x50000000, 0x10000080, 0x50000080,
    0x10040000, 0x50040000, 0x10040080, 0x50040080,
    0x10000040, 0x50000040, 0x100000c0, 0x500000c0,
    0x10040040, 0x50040040, 0x100400c0, 0x500400c0,
    0x00800000, 0x40800000, 0x00800080, 0x40800080,
    0x00840000, 0x40840000, 0x00840080, 0x40840080,
    0x00800040, 0x40800040, 0x008000c0, 0x408000c0,
    0x00840040, 0x40840040, 0x008400c0, 0x408400c0,
    0x10800000, 0x50800000, 0x10800080, 0x50800080,
    0x10840000, 0x50840000, 0x10840080, 0x50840080,
    0x10800040, 0x50800040, 0x108000c0, 0x508000c0,
    0x10840040, 0x50840040, 0x108400c0, 0x508400c0
  },
/* table 4 */ {
    0x00000000, 0x00000008, 0x08000000, 0x08000008,
    0x00040000, 0x00040008, 0x08040000, 0x08040008,
    0x00002000, 0x00002008, 0x08002000, 0x08002008,
    0x00042000, 0x00042008, 0x08042000, 0x08042008,
    0x80000000, 0x80000008, 0x88000000, 0x88000008,
    0x80040000, 0x80040008, 0x88040000, 0x88040008,
    0x80002000, 0x80002008, 0x88002000, 0x88002008,
    0x80042000, 0x80042008, 0x88042000, 0x88042008,
    0x00080000, 0x00080008, 0x08080000, 0x08080008,
    0x000c0000, 0x000c0008, 0x080c0000, 0x080c0008,
    0x00082000, 0x00082008, 0x08082000, 0x08082008,
    0x000c2000, 0x000c2008, 0x080c2000, 0x080c2008,
    0x80080000, 0x80080008, 0x88080000, 0x88080008,
    0x800c0000, 0x800c0008, 0x880c0000, 0x880c0008,
    0x80082000, 0x80082008, 0x88082000, 0x88082008,
    0x800c2000, 0x800c2008, 0x880c2000, 0x880c2008
  },
/* table 5 */ {
    0x00000000, 0x00400000, 0x00008000, 0x00408000,
    0x40000000, 0x40400000, 0x40008000, 0x40408000,
    0x00000020, 0x00400020, 0x00008020, 0x00408020,
    0x40000020, 0x40400020, 0x40008020, 0x40408020,
    0x00001000, 0x00401000, 0x00009000, 0x00409000,
    0x40001000, 0x40401000, 0x40009000, 0x40409000,
    0x00001020, 0x00401020, 0x00009020, 0x00409020,
    0x40001020, 0x40401020, 0x40009020, 0x40409020,
    0x00100000, 0x00500000, 0x00108000, 0x00508000,
    0x40100000, 0x40500000, 0x40108000, 0x40508000,
    0x00100020, 0x00500020, 0x00108020, 0x00508020,
    0x40100020, 0x40500020, 0x40108020, 0x40508020,
    0x00101000, 0x00501000, 0x00109000, 0x00509000,
    0x40101000, 0x40501000, 0x40109000, 0x40509000,
    0x00101020, 0x00501020, 0x00109020, 0x00509020,
    0x40101020, 0x40501020, 0x40109020, 0x40509020
  },
/* table 6 */ {
    0x00000000, 0x00000040, 0x04000000, 0x04000040,
    0x00000800, 0x00000840, 0x04000800, 0x04000840,
    0x00800000, 0x00800040, 0x04800000, 0x04800040,
    0x00800800, 0x00800840, 0x04800800, 0x04800840,
    0x10000000, 0x10000040, 0x14000000, 0x14000040,
    0x10000800, 0x10000840, 0x14000800, 0x14000840,
    0x10800000, 0x10800040, 0x14800000, 0x14800040,
    0x10800800, 0x10800840, 0x14800800, 0x14800840,
    0x00000080, 0x000000c0, 0x04000080, 0x040000c0,
    0x00000880, 0x000008c0, 0x04000880, 0x040008c0,
    0x00800080, 0x008000c0, 0x04800080, 0x048000c0,
    0x00800880, 0x008008c0, 0x04800880, 0x048008c0,
    0x10000080, 0x100000c0, 0x14000080, 0x140000c0,
    0x10000880, 0x100008c0, 0x14000880, 0x140008c0,
    0x10800080, 0x108000c0, 0x14800080, 0x148000c0,
    0x10800880, 0x108008c0, 0x14800880, 0x148008c0
  },
/* table 7 */ {
    0x00000000, 0x00000010, 0x00000400, 0x00000410,
    0x00000004, 0x00000014, 0x00000404, 0x00000414,
    0x00004000, 0x00004010, 0x00004400, 0x00004410,
    0x00004004, 0x00004014, 0x00004404, 0x00004414,
    0x20000000, 0x20000010, 0x20000400, 0x20000410,
    0x20000004, 0x20000014, 0x20000404, 0x20000414,
    0x20004000, 0x20004010, 0x20004400, 0x20004410,
    0x20004004, 0x20004014, 0x20004404, 0x20004414,
    0x00200000, 0x00200010, 0x00200400, 0x00200410,
    0x00200004, 0x00200014, 0x00200404, 0x00200414,
    0x00204000, 0x00204010, 0x00204400, 0x00204410,
    0x00204004, 0x00204014, 0x00204404, 0x00204414,
    0x20200000, 0x20200010, 0x20200400, 0x20200410,
    0x20200004, 0x20200014, 0x20200404, 0x20200414,
    0x20204000, 0x20204010, 0x20204400, 0x20204410,
    0x20204004, 0x20204014, 0x20204404, 0x20204414
  }
};

/*
 * The PC-1 Permutation
 * If we number the bits of the 8 bytes of key input like this (in octal):
 *     00 01 02 03 04 05 06 07
 *     10 11 12 13 14 15 16 17
 *     20 21 22 23 24 25 26 27
 *     30 31 32 33 34 35 36 37
 *     40 41 42 43 44 45 46 47
 *     50 51 52 53 54 55 56 57
 *     60 61 62 63 64 65 66 67
 *     70 71 72 73 74 75 76 77
 * then after the PC-1 permutation,
 * C0 is
 *     70 60 50 40 30 20 10 00
 *     71 61 51 41 31 21 11 01
 *     72 62 52 42 32 22 12 02
 *     73 63 53 43
 * D0 is
 *     76 66 56 46 36 26 16 06
 *     75 65 55 45 35 25 15 05
 *     74 64 54 44 34 24 14 04
 *                 33 23 13 03
 * and these parity bits have been discarded:
 *     77 67 57 47 37 27 17 07
 *
 * We achieve this by flipping the input matrix about the diagonal from 70-07,
 * getting left =
 *     77 67 57 47 37 27 17 07 	(these are the parity bits)
 *     76 66 56 46 36 26 16 06
 *     75 65 55 45 35 25 15 05
 *     74 64 54 44 34 24 14 04
 * right =
 *     73 63 53 43 33 23 13 03
 *     72 62 52 42 32 22 12 02
 *     71 61 51 41 31 21 11 01
 *     70 60 50 40 30 20 10 00
 * then byte swap right, ala htonl() on a little endian machine.
 * right =
 *     70 60 50 40 30 20 10 00
 *     71 67 57 47 37 27 11 07
 *     72 62 52 42 32 22 12 02
 *     73 63 53 43 33 23 13 03
 * then
 *     c0 = right >> 4;
 *     d0 = ((left & 0x00ffffff) << 4) | (right & 0xf);
*/

#define FLIP_RIGHT_DIAGONAL(word, temp) \
    temp  = (word ^ (word >> 18)) & 0x00003333; \
    word ^=  temp | (temp << 18); \
    temp  = (word ^ (word >> 9)) & 0x00550055; \
    word ^=  temp | (temp << 9);

#define BYTESWAP(word, temp) \
    word = (word >> 16) | (word << 16); \
    temp = 0x00ff00ff; \
    word = ((word & temp) << 8) | ((word >> 8) & temp);

#define PC1(left, right, c0, d0, temp) \
    right ^= temp = ((left >> 4) ^ right) & 0x0f0f0f0f; \
    left  ^= temp << 4; \
    FLIP_RIGHT_DIAGONAL(left, temp); \
    FLIP_RIGHT_DIAGONAL(right, temp); \
    BYTESWAP(right, temp); \
    c0 = right >> 4; \
    d0 = ((left & 0x00ffffff) << 4) | (right & 0xf);

#define LEFT_SHIFT_1( reg ) (((reg << 1) | (reg >> 27)) & 0x0FFFFFFF)
#define LEFT_SHIFT_2( reg ) (((reg << 2) | (reg >> 26)) & 0x0FFFFFFF)

/*
 *   setup key schedules from key
 */

void DES_MakeSchedule( HALF * ks, const BYTE * key,   DESDirection direction )
{
    register HALF left, right;
    register HALF c0, d0;
    register HALF temp;
    int           delta;
    unsigned int  ls;



#if defined(_X86_)
    left  = HALFPTR(key)[0];
    right = HALFPTR(key)[1];
    BYTESWAP(left, temp);
    BYTESWAP(right, temp);
#else
    if (((ptrdiff_t)key & 0x03) == 0) {
	left  = HALFPTR(key)[0];
	right = HALFPTR(key)[1];
#if defined(IS_LITTLE_ENDIAN)
	BYTESWAP(left, temp);
	BYTESWAP(right, temp);
#endif
    } else {
	left    = ((HALF)key[0] << 24) | ((HALF)key[1] << 16) |
		  ((HALF)key[2] << 8)  | key[3];
	right   = ((HALF)key[4] << 24) | ((HALF)key[5] << 16) |
		  ((HALF)key[6] << 8)  | key[7];
    }
#endif

    PC1(left, right, c0, d0, temp);

	// This is required...it goes in both direction...
    if (direction == DES_ENCRYPT)
	{
		delta = 2 * (int)sizeof(HALF);
    }
	else
	{
	ks += 30;
	delta = (-2) * (int)sizeof(HALF);
    }

    for (ls = 0x8103; ls; ls >>= 1) {
	if ( ls & 1 ) {
	    c0 = LEFT_SHIFT_1( c0 );
	    d0 = LEFT_SHIFT_1( d0 );
	} else {
	    c0 = LEFT_SHIFT_2( c0 );
	    d0 = LEFT_SHIFT_2( d0 );
	}

#ifdef USE_INDEXING
#define PC2LOOKUP(b,c) PC2[b][c]

	left   = PC2LOOKUP(0, ((c0 >> 22) & 0x3F) );
	left  = left | PC2LOOKUP(1, ((c0 >> 13) & 0x3F) );
	left  = left | PC2LOOKUP(2, ((c0 >>  4) & 0x38) | (c0 & 0x7) );
	left  = left | PC2LOOKUP(3, ((c0>>18)&0xC) | ((c0>>11)&0x3) | (c0&0x30));

	right  = PC2LOOKUP(4, ((d0 >> 22) & 0x3F) );
	right  = right | PC2LOOKUP(5, ((d0 >> 15) & 0x30) | ((d0 >> 14) & 0xf) );
	right  = right | PC2LOOKUP(6, ((d0 >>  7) & 0x3F) );
	right  = right | PC2LOOKUP(7, ((d0 >>  1) & 0x3C) | (d0 & 0x3));

#else
#define PC2LOOKUP(b,c) *(HALF *)((BYTE *)&PC2[b][0]+(c))

	left   = PC2LOOKUP(0, ((c0 >> 20) & 0xFC) );
	left  |= PC2LOOKUP(1, ((c0 >> 11) & 0xFC) );
	left  |= PC2LOOKUP(2, ((c0 >>  2) & 0xE0) | ((c0 <<  2) & 0x1C) );
	left  |= PC2LOOKUP(3, ((c0>>16)&0x30)|((c0>>9)&0xC)|((c0<<2)&0xC0));

	right  = PC2LOOKUP(4, ((d0 >> 20) & 0xFC) );
	right |= PC2LOOKUP(5, ((d0 >> 13) & 0xC0) | ((d0 >> 12) & 0x3C) );
	right |= PC2LOOKUP(6, ((d0 >>  5) & 0xFC) );
	right |= PC2LOOKUP(7, ((d0 <<  1) & 0xF0) | ((d0 << 2) & 0x0C));
#endif
	/* left  contains key bits for S1 S3 S2 S4 */
	/* right contains key bits for S6 S8 S5 S7 */
	temp = (left  << 16)        /* S2 S4 XX XX */
	     | (right >> 16);       /* XX XX S6 S8 */
	ks[0] = temp;

	temp = (left  & 0xffff0000) /* S1 S3 XX XX */
	     | (right & 0x0000ffff);/* XX XX S5 S7 */
	ks[1] = temp;

	ks = (HALF*)((BYTE *)ks + delta);
    }
}

/*
 * The DES Initial Permutation
 * if we number the bits of the 8 bytes of input like this (in octal):
 *     00 01 02 03 04 05 06 07
 *     10 11 12 13 14 15 16 17
 *     20 21 22 23 24 25 26 27
 *     30 31 32 33 34 35 36 37
 *     40 41 42 43 44 45 46 47
 *     50 51 52 53 54 55 56 57
 *     60 61 62 63 64 65 66 67
 *     70 71 72 73 74 75 76 77
 * then after the initial permutation, they will be in this order.
 *     71 61 51 41 31 21 11 01
 *     73 63 53 43 33 23 13 03
 *     75 65 55 45 35 25 15 05
 *     77 67 57 47 37 27 17 07
 *     70 60 50 40 30 20 10 00
 *     72 62 52 42 32 22 12 02
 *     74 64 54 44 34 24 14 04
 *     76 66 56 46 36 26 16 06
 *
 * One way to do this is in two steps:
 * 1. Flip this matrix about the diagonal from 70-07 as done for PC1.
 * 2. Rearrange the bytes (rows in the matrix above) with the following code.
 *
 * #define swapHiLo(word, temp) \
 *   temp  = (word ^ (word >> 24)) & 0x000000ff; \
 *   word ^=  temp | (temp << 24);
 *
 *   right ^= temp = ((left << 8) ^ right) & 0xff00ff00;
 *   left  ^= temp >> 8;
 *   swapHiLo(left, temp);
 *   swapHiLo(right,temp);
 *
 * However, the two steps can be combined, so that the rows are rearranged
 * while the matrix is being flipped, reducing the number of bit exchange
 * operations from 8 ot 5.
 *
 * Initial Permutation */
#define IP(left, right, temp) \
    right ^= temp = ((left >> 4) ^  right) & 0x0f0f0f0f; \
    left  ^= temp << 4; \
    right ^= temp = ((left >> 16) ^ right) & 0x0000ffff; \
    left  ^= temp << 16; \
    right ^= temp = ((left << 2) ^ right) & 0xcccccccc; \
    left  ^= temp >> 2; \
    right ^= temp = ((left << 8) ^ right) & 0xff00ff00; \
    left  ^= temp >> 8; \
    right ^= temp = ((left >> 1) ^ right) & 0x55555555; \
    left  ^= temp << 1;

/* The Final (Inverse Initial) permutation is done by reversing the
** steps of the Initital Permutation
*/

#define FP(left, right, temp) \
    right ^= temp = ((left >> 1) ^ right) & 0x55555555; \
    left  ^= temp << 1; \
    right ^= temp = ((left << 8) ^ right) & 0xff00ff00; \
    left  ^= temp >> 8; \
    right ^= temp = ((left << 2) ^ right) & 0xcccccccc; \
    left  ^= temp >> 2; \
    right ^= temp = ((left >> 16) ^ right) & 0x0000ffff; \
    left  ^= temp << 16; \
    right ^= temp = ((left >> 4) ^  right) & 0x0f0f0f0f; \
    left  ^= temp << 4;


void DES_Do1Block(HALF * ks, const BYTE * inbuf, BYTE * outbuf)
{
	register HALF left, right;
	register HALF temp;

	if (((ptrdiff_t)inbuf & 0x03) == 0) {
		left  = HALFPTR(inbuf)[0];
		right = HALFPTR(inbuf)[1];
		BYTESWAP(left, temp);
		BYTESWAP(right, temp);
	}
	else {
		left    = ((HALF)inbuf[0] << 24) | ((HALF)inbuf[1] << 16) |
			((HALF)inbuf[2] << 8)  | inbuf[3];
		right   = ((HALF)inbuf[4] << 24) | ((HALF)inbuf[5] << 16) |
			((HALF)inbuf[6] << 8)  | inbuf[7];
	}

	IP(left, right, temp);

	/* shift the values left circularly 3 bits. */
	left  = (left  << 3) | (left  >> 29);
	right = (right << 3) | (right >> 29);

#ifdef USE_INDEXING
#define KSLOOKUP(s,b) SP[s][((temp >> (b+2)) & 0x3f)]
#else
#define KSLOOKUP(s,b) *(HALF*)((BYTE*)&SP[s][0]+((temp >> b) & 0xFC))
#endif

#define ROUND(out, in, r) \
    temp  = in ^ ks[2*r]; \
    out ^= KSLOOKUP( 1,  24 ); \
    out ^= KSLOOKUP( 3,  16 ); \
    out ^= KSLOOKUP( 5,   8 ); \
    out ^= KSLOOKUP( 7,   0 ); \
    temp  = ((in >> 4) | (in << 28)) ^ ks[2*r+1]; \
    out ^= KSLOOKUP( 0,  24 ); \
    out ^= KSLOOKUP( 2,  16 ); \
    out ^= KSLOOKUP( 4,   8 ); \
    out ^= KSLOOKUP( 6,   0 );

    /* Do the 16 Feistel rounds */
    ROUND(left, right, 0)
    ROUND(right, left, 1)
    ROUND(left, right, 2)
    ROUND(right, left, 3)
    ROUND(left, right, 4)
    ROUND(right, left, 5)
    ROUND(left, right, 6)
    ROUND(right, left, 7)
    ROUND(left, right, 8)
    ROUND(right, left, 9)
    ROUND(left, right, 10)
    ROUND(right, left, 11)
    ROUND(left, right, 12)
    ROUND(right, left, 13)
    ROUND(left, right, 14)
    ROUND(right, left, 15)

    /* now shift circularly right 3 bits to undo the shifting done
    ** above.  switch left and right here.
    */
    temp  = (left >> 3) | (left << 29);
    left  = (right >> 3) | (right << 29);
    right = temp;

    FP(left, right, temp);

#if defined(_X86_)
    BYTESWAP(left, temp);
    BYTESWAP(right, temp);
    HALFPTR(outbuf)[0]  = left;
    HALFPTR(outbuf)[1]  = right;
#else
    if (((ptrdiff_t)inbuf & 0x03) == 0) {
#if defined(IS_LITTLE_ENDIAN)
	BYTESWAP(left, temp);
	BYTESWAP(right, temp);
#endif
	HALFPTR(outbuf)[0]  = left;
	HALFPTR(outbuf)[1]  = right;
    } else {
	outbuf[0] = (BYTE)(left >> 24);
	outbuf[1] = (BYTE)(left >> 16);
	outbuf[2] = (BYTE)(left >>  8);
	outbuf[3] = (BYTE)(left      );

	outbuf[4] = (BYTE)(right >> 24);
	outbuf[5] = (BYTE)(right >> 16);
	outbuf[6] = (BYTE)(right >>  8);
	outbuf[7] = (BYTE)(right      );
    }
#endif

}

/* Ackowledgements:
** Two ideas used in this implementation were shown to me by Dennis Ferguson
** in 1990.  He credits them to Richard Outerbridge and Dan Hoey.  They were:
** 1. The method of computing the Initial and Final permutations.
** 2. Circularly rotating the SP tables and the initial values of left and
**	right to reduce the number of shifts required during the 16 rounds.
*/

#define USE_MEMCPY

#if defined(_X86_)
/* Intel X86 CPUs do unaligned loads and stores without complaint. */
#define COPY8B(to, from, ptr) \
    	HALFPTR(to)[0] = HALFPTR(from)[0]; \
    	HALFPTR(to)[1] = HALFPTR(from)[1];
#elif defined(USE_MEMCPY)
#define COPY8B(to, from, ptr) memcpy(to, from, 8)
#else
#define COPY8B(to, from, ptr) \
    if (((ptrdiff_t)(ptr) & 0x3) == 0) { \
    	HALFPTR(to)[0] = HALFPTR(from)[0]; \
    	HALFPTR(to)[1] = HALFPTR(from)[1]; \
    } else if (((ptrdiff_t)(ptr) & 0x1) == 0) { \
    	SHORTPTR(to)[0] = SHORTPTR(from)[0]; \
    	SHORTPTR(to)[1] = SHORTPTR(from)[1]; \
    	SHORTPTR(to)[2] = SHORTPTR(from)[2]; \
    	SHORTPTR(to)[3] = SHORTPTR(from)[3]; \
    } else { \
    	BYTEPTR(to)[0] = BYTEPTR(from)[0]; \
    	BYTEPTR(to)[1] = BYTEPTR(from)[1]; \
    	BYTEPTR(to)[2] = BYTEPTR(from)[2]; \
    	BYTEPTR(to)[3] = BYTEPTR(from)[3]; \
    	BYTEPTR(to)[4] = BYTEPTR(from)[4]; \
    	BYTEPTR(to)[5] = BYTEPTR(from)[5]; \
    	BYTEPTR(to)[6] = BYTEPTR(from)[6]; \
    	BYTEPTR(to)[7] = BYTEPTR(from)[7]; \
    }
#endif
#define COPY8BTOHALF(to, from) COPY8B(to, from, from)
#define COPY8BFROMHALF(to, from) COPY8B(to, from, to)


void DES_ECB(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len)
{
    while (len) {
	DES_Do1Block(cx->ks0, in, out);
	len -= 8;
	in  += 8;
	out += 8;
    }
}

void DES_EDE3_ECB(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len)
{
    while (len) {
	DES_Do1Block(cx->ks0,  in, out);
	len -= 8;
	in  += 8;
	DES_Do1Block(cx->ks1, out, out);
	DES_Do1Block(cx->ks2, out, out);
	out += 8;
    }
}

void DES_CBCEn(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len)
{
    const BYTE * bufend = in + len;
    HALF  vec[2];

    while (in != bufend) {
	COPY8BTOHALF(vec, in);
	in += 8;
	vec[0] ^= cx->iv[0];
	vec[1] ^= cx->iv[1];
	DES_Do1Block( cx->ks0, (BYTE *)vec, (BYTE *)cx->iv);
	COPY8BFROMHALF(out, cx->iv);
	out += 8;
    }
}

void DES_CBCDe(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len)
{
    const BYTE * bufend;
    HALF oldciphertext[2];
    HALF plaintext    [2];

    for (bufend = in + len; in != bufend; ) {
	oldciphertext[0] = cx->iv[0];
	oldciphertext[1] = cx->iv[1];
	COPY8BTOHALF(cx->iv, in);
	in += 8;
	DES_Do1Block(cx->ks0, (BYTE *)cx->iv, (BYTE *)plaintext);
	plaintext[0] ^= oldciphertext[0];
	plaintext[1] ^= oldciphertext[1];
	COPY8BFROMHALF(out, plaintext);
	out += 8;
    }
}

void DES_EDE3CBCEn(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len)
{
    const BYTE * bufend = in + len;
    HALF  vec[2];

    while (in != bufend) {
	COPY8BTOHALF(vec, in);
	in += 8;
	vec[0] ^= cx->iv[0];
	vec[1] ^= cx->iv[1];
	DES_Do1Block( cx->ks0, (BYTE *)vec,    (BYTE *)cx->iv);
	DES_Do1Block( cx->ks1, (BYTE *)cx->iv, (BYTE *)cx->iv);
	DES_Do1Block( cx->ks2, (BYTE *)cx->iv, (BYTE *)cx->iv);
	COPY8BFROMHALF(out, cx->iv);
	out += 8;
    }
}

// This is the algorithm used for decryption....
int DES_EDE3CBCDe(struct DESContext *cx, const BYTE *in)
{
	HALF plaintext    [2];
	DES_Do1Block(cx->ks0, in /*(BYTE *)&oldcihpertext*/,    (BYTE *)plaintext);

	DES_Do1Block(cx->ks1, (BYTE *)plaintext, (BYTE *)plaintext);
	DES_Do1Block(cx->ks2, (BYTE *)plaintext, (BYTE *)plaintext);
	plaintext[0] =plaintext[0] ^  cx->iv[0];
	plaintext[1] =plaintext[1] ^  cx->iv[1];
	if( * (char*)(&plaintext) != KEYDB_PW_CHECK_STR[0] )
		return 0;
	if( memcmp(&plaintext, KEYDB_PW_CHECK_STR, 8) != 0)
		return 0;
	return 1;
}

struct DESContext *DES_CreateContext(struct DESContext *cx, const BYTE * key, const BYTE *iv)
{
	cx->direction =  DES_DECRYPT;
	COPY8BTOHALF(cx->iv, iv);
	DES_MakeSchedule(cx->ks2, key,      DES_DECRYPT);
	DES_MakeSchedule(cx->ks1, key +  8, DES_ENCRYPT);
	DES_MakeSchedule(cx->ks0, key + 16, DES_DECRYPT);
	return cx;
}

void DES_DestroyContext(struct DESContext *cx, PRBool freeit)
{
	if (cx)
		memset(cx, 0, sizeof *cx);

 }

SECStatus DES_Encrypt(struct DESContext *cx, BYTE *out, unsigned int *outLen, unsigned int maxOutLen, const BYTE *in, unsigned int inLen)
{
	if (inLen < 0 || (inLen % 8) != 0 || maxOutLen < inLen || !cx || cx->direction != DES_ENCRYPT)
		return SECFailure;

	if (outLen)
		*outLen = inLen;
	return SECSuccess;
}


int DES_Decrypt(struct DESContext *cx, BYTE *out, unsigned int *outLen,unsigned int maxOutLen, const BYTE *in, unsigned int inLen)
{
	return DES_EDE3CBCDe(cx, in);
}

#endif
