/*
 * BitLocker-OpenCL format developed by Elenago
 * <elena dot ago at gmail dot com> in 2015
 *
 * Copyright (c) 2015-2017 Elenago <elena dot ago at gmail dot com>
 * and Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor
 * implied. See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * More info here: http://openwall.info/wiki/john/OpenCL-BitLocker
 *
 * A standalone CUDA implementation is available here: https://github.com/e-ago/bitcracker.
 */


#ifndef _BITCRACKER_H
#define _BITCRACKER_H

#define ROR(x, i)	(rotate((x), 32U - (i)))

#define SCHEDULE0()  \
        schedule0 = schedule16 + schedule25 \
            + OPT3_XOR(ROR(schedule17, 7) , ROR(schedule17, 18) , (schedule17 >> 3)) \
            + OPT3_XOR(ROR(schedule30, 17) , ROR(schedule30, 19) , (schedule30 >> 10));


#define SCHEDULE1()  \
        schedule1 = schedule17 + schedule26 \
            + OPT3_XOR(ROR(schedule18, 7) , ROR(schedule18, 18) , (schedule18 >> 3)) \
            + OPT3_XOR(ROR(schedule31, 17) , ROR(schedule31, 19) , (schedule31 >> 10));


#define SCHEDULE2()  \
        schedule2 = schedule18 + schedule27 \
            + OPT3_XOR(ROR(schedule19, 7) , ROR(schedule19, 18) , (schedule19 >> 3)) \
            + OPT3_XOR(ROR(schedule0, 17) , ROR(schedule0, 19) , (schedule0 >> 10));


#define SCHEDULE3()  \
        schedule3 = schedule19 + schedule28 \
            + OPT3_XOR(ROR(schedule20, 7) , ROR(schedule20, 18) , (schedule20 >> 3)) \
            + OPT3_XOR(ROR(schedule1, 17) , ROR(schedule1, 19) , (schedule1 >> 10));


#define SCHEDULE4()  \
        schedule4 = schedule20 + schedule29 \
            + OPT3_XOR(ROR(schedule21, 7) , ROR(schedule21, 18) , (schedule21 >> 3)) \
            + OPT3_XOR(ROR(schedule2, 17) , ROR(schedule2, 19) , (schedule2 >> 10));


#define SCHEDULE5()  \
        schedule5 = schedule21 + schedule30 \
            + OPT3_XOR(ROR(schedule22, 7) , ROR(schedule22, 18) , (schedule22 >> 3)) \
            + OPT3_XOR(ROR(schedule3, 17) , ROR(schedule3, 19) , (schedule3 >> 10));


#define SCHEDULE6()  \
        schedule6 = schedule22 + schedule31 \
            + OPT3_XOR(ROR(schedule23, 7) , ROR(schedule23, 18) , (schedule23 >> 3)) \
            + OPT3_XOR(ROR(schedule4, 17) , ROR(schedule4, 19) , (schedule4 >> 10));


#define SCHEDULE7()  \
        schedule7 = schedule23 + schedule0 \
            + OPT3_XOR(ROR(schedule24, 7) , ROR(schedule24, 18) , (schedule24 >> 3)) \
            + OPT3_XOR(ROR(schedule5, 17) , ROR(schedule5, 19) , (schedule5 >> 10));


#define SCHEDULE8()  \
        schedule8 = schedule24 + schedule1 \
            + OPT3_XOR(ROR(schedule25, 7) , ROR(schedule25, 18) , (schedule25 >> 3)) \
            + OPT3_XOR(ROR(schedule6, 17) , ROR(schedule6, 19) , (schedule6 >> 10));


#define SCHEDULE9()  \
        schedule9 = schedule25 + schedule2 \
            + OPT3_XOR(ROR(schedule26, 7) , ROR(schedule26, 18) , (schedule26 >> 3)) \
            + OPT3_XOR(ROR(schedule7, 17) , ROR(schedule7, 19) , (schedule7 >> 10));


#define SCHEDULE10()  \
        schedule10 = schedule26 + schedule3 \
            + OPT3_XOR(ROR(schedule27, 7) , ROR(schedule27, 18) , (schedule27 >> 3)) \
            + OPT3_XOR(ROR(schedule8, 17) , ROR(schedule8, 19) , (schedule8 >> 10));


#define SCHEDULE11()  \
        schedule11 = schedule27 + schedule4 \
            + OPT3_XOR(ROR(schedule28, 7) , ROR(schedule28, 18) , (schedule28 >> 3)) \
            + OPT3_XOR(ROR(schedule9, 17) , ROR(schedule9, 19) , (schedule9 >> 10));


#define SCHEDULE12()  \
        schedule12 = schedule28 + schedule5 \
            + OPT3_XOR(ROR(schedule29, 7) , ROR(schedule29, 18) , (schedule29 >> 3)) \
            + OPT3_XOR(ROR(schedule10, 17) , ROR(schedule10, 19) , (schedule10 >> 10));


#define SCHEDULE13()  \
        schedule13 = schedule29 + schedule6 \
            + OPT3_XOR(ROR(schedule30, 7) , ROR(schedule30, 18) , (schedule30 >> 3)) \
            + OPT3_XOR(ROR(schedule11, 17) , ROR(schedule11, 19) , (schedule11 >> 10));


#define SCHEDULE14()  \
        schedule14 = schedule30 + schedule7 \
            + OPT3_XOR(ROR(schedule31, 7) , ROR(schedule31, 18) , (schedule31 >> 3)) \
            + OPT3_XOR(ROR(schedule12, 17) , ROR(schedule12, 19) , (schedule12 >> 10));


#define SCHEDULE15()  \
        schedule15 = schedule31 + schedule8 \
            + OPT3_XOR(ROR(schedule0, 7) , ROR(schedule0, 18) , (schedule0 >> 3)) \
            + OPT3_XOR(ROR(schedule13, 17) , ROR(schedule13, 19) , (schedule13 >> 10));

#define SCHEDULE16()  \
        schedule16 = schedule0 + schedule9  \
            + OPT3_XOR( ROR(schedule1, 7), ROR(schedule1, 18), (schedule1 >> 3))  \
            + OPT3_XOR( ROR(schedule14, 17), ROR(schedule14, 19), (schedule14 >> 10));

#define SCHEDULE17()  \
        schedule17 = schedule1 + schedule10  \
            + OPT3_XOR(ROR(schedule2, 7) , ROR(schedule2, 18) , (schedule2 >> 3))  \
            + OPT3_XOR(ROR(schedule15, 17) , ROR(schedule15, 19) , (schedule15 >> 10));

#define SCHEDULE18()  \
        schedule18 = schedule2 + schedule11  \
            + OPT3_XOR(ROR(schedule3, 7) ,ROR(schedule3, 18) ,(schedule3 >> 3))  \
            + OPT3_XOR(ROR(schedule16, 17), ROR(schedule16, 19), (schedule16 >> 10));
#define SCHEDULE19()  \
        schedule19 = schedule3 + schedule12  \
            + OPT3_XOR(ROR(schedule4, 7) , ROR(schedule4, 18) , (schedule4 >> 3))  \
            + OPT3_XOR(ROR(schedule17, 17) , ROR(schedule17, 19) , (schedule17 >> 10));

#define SCHEDULE20()  \
        schedule20 = schedule4 + schedule13  \
            + OPT3_XOR(ROR(schedule5, 7) , ROR(schedule5, 18) , (schedule5 >> 3))  \
            + OPT3_XOR(ROR(schedule18, 17) , ROR(schedule18, 19) , (schedule18 >> 10));

#define SCHEDULE21()  \
        schedule21 = schedule5 + schedule14  \
            + OPT3_XOR(ROR(schedule6, 7) , ROR(schedule6, 18) , (schedule6 >> 3))  \
            + OPT3_XOR(ROR(schedule19, 17) , ROR(schedule19, 19) , (schedule19 >> 10));

#define SCHEDULE22()  \
        schedule22 = schedule6 + schedule15  \
            + OPT3_XOR(ROR(schedule7, 7) , ROR(schedule7, 18) , (schedule7 >> 3))  \
            + OPT3_XOR(ROR(schedule20, 17) , ROR(schedule20, 19) , (schedule20 >> 10));

#define SCHEDULE23()  \
        schedule23 = schedule7 + schedule16  \
            + OPT3_XOR(ROR(schedule8, 7) , ROR(schedule8, 18) , (schedule8 >> 3))  \
            + OPT3_XOR(ROR(schedule21, 17) , ROR(schedule21, 19) , (schedule21 >> 10));

#define SCHEDULE24()  \
        schedule24 = schedule8 + schedule17  \
            + OPT3_XOR(ROR(schedule9, 7) , ROR(schedule9, 18) , (schedule9 >> 3))  \
            + OPT3_XOR(ROR(schedule22, 17) , ROR(schedule22, 19) , (schedule22 >> 10));

#define SCHEDULE25()  \
        schedule25 = schedule9 + schedule18  \
            + OPT3_XOR(ROR(schedule10, 7) , ROR(schedule10, 18) , (schedule10 >> 3))  \
            + OPT3_XOR(ROR(schedule23, 17) , ROR(schedule23, 19) , (schedule23 >> 10));

#define SCHEDULE26()  \
        schedule26 = schedule10 + schedule19  \
            + OPT3_XOR(ROR(schedule11, 7) , ROR(schedule11, 18) , (schedule11 >> 3))  \
            + OPT3_XOR(ROR(schedule24, 17) , ROR(schedule24, 19) , (schedule24 >> 10));

#define SCHEDULE27()  \
        schedule27 = schedule11 + schedule20  \
            + OPT3_XOR(ROR(schedule12, 7) , ROR(schedule12, 18) , (schedule12 >> 3))  \
            + OPT3_XOR(ROR(schedule25, 17) , ROR(schedule25, 19) , (schedule25 >> 10));

#define SCHEDULE28()  \
        schedule28 = schedule12 + schedule21  \
            + OPT3_XOR(ROR(schedule13, 7) , ROR(schedule13, 18) , (schedule13 >> 3))  \
            + OPT3_XOR(ROR(schedule26, 17) , ROR(schedule26, 19) , (schedule26 >> 10));

#define SCHEDULE29()  \
        schedule29 = schedule13 + schedule22  \
            + OPT3_XOR(ROR(schedule14, 7) , ROR(schedule14, 18) , (schedule14 >> 3))  \
            + OPT3_XOR(ROR(schedule27, 17) , ROR(schedule27, 19) , (schedule27 >> 10));

#define SCHEDULE30()  \
        schedule30 = schedule14 + schedule23  \
            + OPT3_XOR(ROR(schedule15, 7) , ROR(schedule15, 18) , (schedule15 >> 3))  \
            + OPT3_XOR(ROR(schedule28, 17) , ROR(schedule28, 19) , (schedule28 >> 10));

#define SCHEDULE31()  \
        schedule31 = schedule15 + schedule24  \
            + OPT3_XOR(ROR(schedule16, 7) , ROR(schedule16, 18) , (schedule16 >> 3))  \
            + OPT3_XOR(ROR(schedule29, 17) , ROR(schedule29, 19) , (schedule29 >> 10));

#define ALL_SCHEDULE32() \
        SCHEDULE0() \
        SCHEDULE1() \
        SCHEDULE2() \
        SCHEDULE3() \
        SCHEDULE4() \
        SCHEDULE5() \
        SCHEDULE6() \
        SCHEDULE7() \
        SCHEDULE8() \
        SCHEDULE9() \
        SCHEDULE10() \
        SCHEDULE11() \
        SCHEDULE12() \
        SCHEDULE13() \
        SCHEDULE14() \
        SCHEDULE15() \
        SCHEDULE16() \
        SCHEDULE17() \
        SCHEDULE18() \
        SCHEDULE19() \
        SCHEDULE20() \
        SCHEDULE21() \
        SCHEDULE22() \
        SCHEDULE23() \
        SCHEDULE24() \
        SCHEDULE25() \
        SCHEDULE26() \
        SCHEDULE27() \
        SCHEDULE28() \
        SCHEDULE29() \
        SCHEDULE30() \
        SCHEDULE31()

#define ALL_SCHEDULE_LAST16() \
        SCHEDULE16() \
        SCHEDULE17() \
        SCHEDULE18() \
        SCHEDULE19() \
        SCHEDULE20() \
        SCHEDULE21() \
        SCHEDULE22() \
        SCHEDULE23() \
        SCHEDULE24() \
        SCHEDULE25() \
        SCHEDULE26() \
        SCHEDULE27() \
        SCHEDULE28() \
        SCHEDULE29() \
        SCHEDULE30() \
        SCHEDULE31()

#define ROUND(a, b, c, d, e, f, g, h, W, k) \
        h += OPT3_XOR(ROR(e, 6), ROR(e, 11), ROR(e, 25)) + OPT3_XORAND(g,e,f) + k + W; \
        d += h;  \
        h += OPT3_XOR(ROR(a, 2), ROR(a, 13), ROR(a, 22)) + OPT3_ANDOR(a,b,c);   /*((a & (b | c)) | (b & c)); */

#define ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, i, k, indexW) \
        h += OPT3_XOR(ROR(e, 6), ROR(e, 11), ROR(e, 25)) + OPT3_XORAND(g,e,f) + k +  d_wblocks[indexW+i]; \
        d += h;  \
        h += OPT3_XOR(ROR(a, 2), ROR(a, 13), ROR(a, 22)) + OPT3_ANDOR(a,b,c);

//W-block evaluate
#define LOADSCHEDULE_WPRE(i, j)  \
        d_wblocks[j] =                           \
              (unsigned int)block[i * 4 + 0] << 24  \
            | (unsigned int)block[i * 4 + 1] << 16  \
            | (unsigned int)block[i * 4 + 2] <<  8  \
            | (unsigned int)block[i * 4 + 3];

#define SCHEDULE_WPRE(i)  \
        d_wblocks[i] = d_wblocks[i - 16] + d_wblocks[i - 7]  \
            + (ROR(d_wblocks[i - 15], 7) ^ ROR(d_wblocks[i - 15], 18) ^ (d_wblocks[i - 15] >> 3))  \
            + (ROR(d_wblocks[i - 2], 17) ^ ROR(d_wblocks[i - 2], 19) ^ (d_wblocks[i - 2] >> 10));

#endif
/* _BITCRACKER_H */
