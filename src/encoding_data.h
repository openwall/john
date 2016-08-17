/*
 * This source file is UTF-8 encoded, for auto-generated warnings
 *
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2011. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2011 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * character encoding additional information.  Casing and other info.
 *
 * This data was generated using ./run/cmpt_cp.pl (compute code page)
 * cmpt_cp.pl 1.2 has to be run in ./src, to load the proper file
 * ./src/unused/UnicodeData.txt used to determine char classes.
 * cmpt_cp.pl builds the proper array and #defines, and then all that
 * is needed is to put the output of that script into this file, and
 * then hook that code into rules.c and unicode.c (and options.c/.h to
 * add the new code page to command line).  See the wiki tutorial page
 * at http://openwall.info/wiki/john/tutorials/add-codepage for help.
 */

#ifndef __ENCODING_DATA_H__
#define __ENCODING_DATA_H__

// for UTF16/UTF8 definition
#include "unicode.h"

// unicode.c will declare the arrays as static and initialize them. All
// others that source this file should declare them as external.
#if JTR_UNICODE_C
#define EXTATIC static
#else
#define EXTATIC extern
#endif

// These are always invalid, but there are also a lot of multi-octet
// combinations that are invalid but can't be matched this easily.
#define CHARS_INVALID_UTF8 "\xc0\xc1\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

// for i in iso-8859-1 iso-8859-2 iso-8859-7 iso-8859-15 koi8-r cp437 cp737 cp850 cp852 cp858 cp866 cp1250 cp1251 cp1252 cp1253 ; do Unicode/cmpt_cp.pl -v $i; done >> encoding_data.h

// ----8<------8<---- AUTO-GENERATED DATA BELOW THIS POINT ----8<------8<----

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
//  ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ

// here is the ISO_8859_1 to Unicode conversion for ISO_8859_1 characters from 0x80 to 0xFF
EXTATIC const UTF16 ISO_8859_1_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,0x0088,0x0089,0x008A,0x008B,0x008C,0x008D,0x008E,0x008F,
0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,0x0098,0x0099,0x009A,0x009B,0x009C,0x009D,0x009E,0x009F,
0x00A0,0x00A1,0x00A2,0x00A3,0x00A4,0x00A5,0x00A6,0x00A7,0x00A8,0x00A9,0x00AA,0x00AB,0x00AC,0x00AD,0x00AE,0x00AF,
0x00B0,0x00B1,0x00B2,0x00B3,0x00B4,0x00B5,0x00B6,0x00B7,0x00B8,0x00B9,0x00BA,0x00BB,0x00BC,0x00BD,0x00BE,0x00BF,
0x00C0,0x00C1,0x00C2,0x00C3,0x00C4,0x00C5,0x00C6,0x00C7,0x00C8,0x00C9,0x00CA,0x00CB,0x00CC,0x00CD,0x00CE,0x00CF,
0x00D0,0x00D1,0x00D2,0x00D3,0x00D4,0x00D5,0x00D6,0x00D7,0x00D8,0x00D9,0x00DA,0x00DB,0x00DC,0x00DD,0x00DE,0x00DF,
0x00E0,0x00E1,0x00E2,0x00E3,0x00E4,0x00E5,0x00E6,0x00E7,0x00E8,0x00E9,0x00EA,0x00EB,0x00EC,0x00ED,0x00EE,0x00EF,
0x00F0,0x00F1,0x00F2,0x00F3,0x00F4,0x00F5,0x00F6,0x00F7,0x00F8,0x00F9,0x00FA,0x00FB,0x00FC,0x00FD,0x00FE,0x00FF }
#endif
;
// *** WARNING, char at 0xDF U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþ
#define CHARS_LOWER_ISO_8859_1 \
	"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

// ªµºßÿ
#define CHARS_LOW_ONLY_ISO_8859_1 "\xAA\xB5\xBA\xDF\xFF"

// ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞ
#define CHARS_UPPER_ISO_8859_1 \
	"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE"

//
#define CHARS_UP_ONLY_ISO_8859_1

//
#define CHARS_NOCASE_ISO_8859_1

// ²³¹¼½¾
#define CHARS_DIGITS_ISO_8859_1 "\xB2\xB3\xB9\xBC\xBD\xBE"

// ¡«·»¿
#define CHARS_PUNCTUATION_ISO_8859_1 "\xA1\xAB\xB7\xBB\xBF"

// ¢£¤¥¦§¨©¬­®¯°±´¶¸×÷
#define CHARS_SPECIALS_ISO_8859_1 "\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAC\xAD\xAE\xAF\xB0\xB1\xB4\xB6\xB8\xD7\xF7"

// ªµºÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ
#define CHARS_ALPHA_ISO_8859_1 \
	"\xAA\xB5\xBA\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

#define CHARS_WHITESPACE_ISO_8859_1 "\xA0"

#define CHARS_CONTROL_ISO_8859_1 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"

#define CHARS_INVALID_ISO_8859_1 ""

// YyÀÁÂÃÄÅÆÈÉÊËÌÍÎÏÒÓÔÕÖØÙÚÛÜÝàáâãäåæèéêëìíîïòóôõöøùúûüýÿ
#define CHARS_VOWELS_ISO_8859_1 \
	"\x59\x79\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFF"

// ªµºÇÐÑÝÞßçðñýþÿ
#define CHARS_CONSONANTS_ISO_8859_1 "\xAA\xB5\xBA\xC7\xD0\xD1\xDD\xDE\xDF\xE7\xF0\xF1\xFD\xFE\xFF"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
//  Ą˘Ł¤ĽŚ§¨ŠŞŤŹ­ŽŻ°ą˛ł´ľśˇ¸šşťź˝žżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙

// here is the ISO_8859_2 to Unicode conversion for ISO_8859_2 characters from 0x80 to 0xFF
EXTATIC const UTF16 ISO_8859_2_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,0x0088,0x0089,0x008A,0x008B,0x008C,0x008D,0x008E,0x008F,
0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,0x0098,0x0099,0x009A,0x009B,0x009C,0x009D,0x009E,0x009F,
0x00A0,0x0104,0x02D8,0x0141,0x00A4,0x013D,0x015A,0x00A7,0x00A8,0x0160,0x015E,0x0164,0x0179,0x00AD,0x017D,0x017B,
0x00B0,0x0105,0x02DB,0x0142,0x00B4,0x013E,0x015B,0x02C7,0x00B8,0x0161,0x015F,0x0165,0x017A,0x02DD,0x017E,0x017C,
0x0154,0x00C1,0x00C2,0x0102,0x00C4,0x0139,0x0106,0x00C7,0x010C,0x00C9,0x0118,0x00CB,0x011A,0x00CD,0x00CE,0x010E,
0x0110,0x0143,0x0147,0x00D3,0x00D4,0x0150,0x00D6,0x00D7,0x0158,0x016E,0x00DA,0x0170,0x00DC,0x00DD,0x0162,0x00DF,
0x0155,0x00E1,0x00E2,0x0103,0x00E4,0x013A,0x0107,0x00E7,0x010D,0x00E9,0x0119,0x00EB,0x011B,0x00ED,0x00EE,0x010F,
0x0111,0x0144,0x0148,0x00F3,0x00F4,0x0151,0x00F6,0x00F7,0x0159,0x016F,0x00FA,0x0171,0x00FC,0x00FD,0x0163,0x02D9 }
#endif
;
// *** WARNING, char at 0xDF U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// ąłľśšşťźžżŕáâăäĺćçčéęëěíîďđńňóôőöřůúűüýţ
#define CHARS_LOWER_ISO_8859_2 \
	"\xB1\xB3\xB5\xB6\xB9\xBA\xBB\xBC\xBE\xBF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

// ß
#define CHARS_LOW_ONLY_ISO_8859_2 "\xDF"

// ĄŁĽŚŠŞŤŹŽŻŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖŘŮÚŰÜÝŢ
#define CHARS_UPPER_ISO_8859_2 \
	"\xA1\xA3\xA5\xA6\xA9\xAA\xAB\xAC\xAE\xAF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE"

//
#define CHARS_UP_ONLY_ISO_8859_2

//
#define CHARS_NOCASE_ISO_8859_2

//
#define CHARS_DIGITS_ISO_8859_2 ""

//
#define CHARS_PUNCTUATION_ISO_8859_2

// ˘¤§¨­°˛´ˇ¸˝×÷˙
#define CHARS_SPECIALS_ISO_8859_2 "\xA2\xA4\xA7\xA8\xAD\xB0\xB2\xB4\xB7\xB8\xBD\xD7\xF7\xFF"

// ĄŁĽŚŠŞŤŹŽŻąłľśšşťźžżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőöřůúűüýţ
#define CHARS_ALPHA_ISO_8859_2 \
	"\xA1\xA3\xA5\xA6\xA9\xAA\xAB\xAC\xAE\xAF\xB1\xB3\xB5\xB6\xB9\xBA\xBB\xBC\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

#define CHARS_WHITESPACE_ISO_8859_2 "\xA0"

#define CHARS_CONTROL_ISO_8859_2 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"

#define CHARS_INVALID_ISO_8859_2 ""

// YyĄąÁÂĂÄÉĘËĚÍÎÓÔŐÖŮÚŰÜÝáâăäéęëěíîóôőöůúűüý
#define CHARS_VOWELS_ISO_8859_2 \
	"\x59\x79\xA1\xB1\xC1\xC2\xC3\xC4\xC9\xCA\xCB\xCC\xCD\xCE\xD3\xD4\xD5\xD6\xD9\xDA\xDB\xDC\xDD\xE1\xE2\xE3\xE4\xE9\xEA\xEB\xEC\xED\xEE\xF3\xF4\xF5\xF6\xF9\xFA\xFB\xFC\xFD"

// ŁĽŚŠŞŤŹŽŻłľśšşťźžżŔĹĆÇČĎĐŃŇŘÝŢßŕĺćçčďđńňřýţ
#define CHARS_CONSONANTS_ISO_8859_2 \
	"\xA3\xA5\xA6\xA9\xAA\xAB\xAC\xAE\xAF\xB3\xB5\xB6\xB9\xBA\xBB\xBC\xBE\xBF\xC0\xC5\xC6\xC7\xC8\xCF\xD0\xD1\xD2\xD8\xDD\xDE\xDF\xE0\xE5\xE6\xE7\xE8\xEF\xF0\xF1\xF2\xF8\xFD\xFE"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
//  ‘’£€₯¦§¨©ͺ«¬­�―°±²³΄΅Ά·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�

// here is the ISO_8859_7 to Unicode conversion for ISO_8859_7 characters from 0x80 to 0xFF
EXTATIC const UTF16 ISO_8859_7_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,0x0088,0x0089,0x008A,0x008B,0x008C,0x008D,0x008E,0x008F,
0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,0x0098,0x0099,0x009A,0x009B,0x009C,0x009D,0x009E,0x009F,
0x00A0,0x2018,0x2019,0x00A3,0x20AC,0x20AF,0x00A6,0x00A7,0x00A8,0x00A9,0x037A,0x00AB,0x00AC,0x00AD,0x00AE,0x2015,
0x00B0,0x00B1,0x00B2,0x00B3,0x0384,0x0385,0x0386,0x00B7,0x0388,0x0389,0x038A,0x00BB,0x038C,0x00BD,0x038E,0x038F,
0x0390,0x0391,0x0392,0x0393,0x0394,0x0395,0x0396,0x0397,0x0398,0x0399,0x039A,0x039B,0x039C,0x039D,0x039E,0x039F,
0x03A0,0x03A1,0x00D2,0x03A3,0x03A4,0x03A5,0x03A6,0x03A7,0x03A8,0x03A9,0x03AA,0x03AB,0x03AC,0x03AD,0x03AE,0x03AF,
0x03B0,0x03B1,0x03B2,0x03B3,0x03B4,0x03B5,0x03B6,0x03B7,0x03B8,0x03B9,0x03BA,0x03BB,0x03BC,0x03BD,0x03BE,0x03BF,
0x03C0,0x03C1,0x03C2,0x03C3,0x03C4,0x03C5,0x03C6,0x03C7,0x03C8,0x03C9,0x03CA,0x03CB,0x03CC,0x03CD,0x03CE,0x00FF }
#endif
;
// *** WARNING, char at 0xC0 U+0390 (ΐ -> Ϊ́) needs to be looked into.  Single to multi-byte conversion
// *** WARNING, char at 0xE0 U+03B0 (ΰ -> Ϋ́) needs to be looked into.  Single to multi-byte conversion

// άέήίαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ
#define CHARS_LOWER_ISO_8859_7 \
	"\xDC\xDD\xDE\xDF\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

// ΐΰ
#define CHARS_LOW_ONLY_ISO_8859_7 "\xC0\xE0"

// ΆΈΉΊΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΣΤΥΦΧΨΩΪΫΌΎΏ
#define CHARS_UPPER_ISO_8859_7 \
	"\xB6\xB8\xB9\xBA\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD3\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xBC\xBE\xBF"

//
#define CHARS_UP_ONLY_ISO_8859_7

//
#define CHARS_NOCASE_ISO_8859_7

// ²³½
#define CHARS_DIGITS_ISO_8859_7 "\xB2\xB3\xBD"

// ‘’«―·»
#define CHARS_PUNCTUATION_ISO_8859_7 "\xA1\xA2\xAB\xAF\xB7\xBB"

// £€₯¦§¨©ͺ¬­°±΄΅
#define CHARS_SPECIALS_ISO_8859_7 "\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAC\xAD\xB0\xB1\xB4\xB5"

// ΆΈΉΊΌΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ
#define CHARS_ALPHA_ISO_8859_7 \
	"\xB6\xB8\xB9\xBA\xBC\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

#define CHARS_WHITESPACE_ISO_8859_7 "\xA0"

#define CHARS_CONTROL_ISO_8859_7 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"

#define CHARS_INVALID_ISO_8859_7 "\xAE\xD2\xFF"

// YyΆΈΉΊΌΎΏΐΑΕΗΙΟΥΩΪΫάέήίΰαεηιουωϊϋόύώ
#define CHARS_VOWELS_ISO_8859_7 \
	"\x59\x79\xB6\xB8\xB9\xBA\xBC\xBE\xBF\xC0\xC1\xC5\xC7\xC9\xCF\xD5\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE5\xE7\xE9\xEF\xF5\xF9\xFA\xFB\xFC\xFD\xFE"

// ΒΓΔΖΘΚΛΜΝΞΠΡΣΤΦΧΨβγδζθκλμνξπρςστφχψ
#define CHARS_CONSONANTS_ISO_8859_7 \
	"\xC2\xC3\xC4\xC6\xC8\xCA\xCB\xCC\xCD\xCE\xD0\xD1\xD3\xD4\xD6\xD7\xD8\xE2\xE3\xE4\xE6\xE8\xEA\xEB\xEC\xED\xEE\xF0\xF1\xF2\xF3\xF4\xF6\xF7\xF8"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
//  ¡¢£€¥Š§š©ª«¬­®¯°±²³Žµ¶·ž¹º»ŒœŸ¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ

// here is the ISO_8859_15 to Unicode conversion for ISO_8859_15 characters from 0x80 to 0xFF
EXTATIC const UTF16 ISO_8859_15_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,0x0088,0x0089,0x008A,0x008B,0x008C,0x008D,0x008E,0x008F,
0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,0x0098,0x0099,0x009A,0x009B,0x009C,0x009D,0x009E,0x009F,
0x00A0,0x00A1,0x00A2,0x00A3,0x20AC,0x00A5,0x0160,0x00A7,0x0161,0x00A9,0x00AA,0x00AB,0x00AC,0x00AD,0x00AE,0x00AF,
0x00B0,0x00B1,0x00B2,0x00B3,0x017D,0x00B5,0x00B6,0x00B7,0x017E,0x00B9,0x00BA,0x00BB,0x0152,0x0153,0x0178,0x00BF,
0x00C0,0x00C1,0x00C2,0x00C3,0x00C4,0x00C5,0x00C6,0x00C7,0x00C8,0x00C9,0x00CA,0x00CB,0x00CC,0x00CD,0x00CE,0x00CF,
0x00D0,0x00D1,0x00D2,0x00D3,0x00D4,0x00D5,0x00D6,0x00D7,0x00D8,0x00D9,0x00DA,0x00DB,0x00DC,0x00DD,0x00DE,0x00DF,
0x00E0,0x00E1,0x00E2,0x00E3,0x00E4,0x00E5,0x00E6,0x00E7,0x00E8,0x00E9,0x00EA,0x00EB,0x00EC,0x00ED,0x00EE,0x00EF,
0x00F0,0x00F1,0x00F2,0x00F3,0x00F4,0x00F5,0x00F6,0x00F7,0x00F8,0x00F9,0x00FA,0x00FB,0x00FC,0x00FD,0x00FE,0x00FF }
#endif
;
// *** WARNING, char at 0xDF U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// šžœàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ
#define CHARS_LOWER_ISO_8859_15 \
	"\xA8\xB8\xBD\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

// ªµºß
#define CHARS_LOW_ONLY_ISO_8859_15 "\xAA\xB5\xBA\xDF"

// ŠŽŒÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞŸ
#define CHARS_UPPER_ISO_8859_15 \
	"\xA6\xB4\xBC\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xBE"

//
#define CHARS_UP_ONLY_ISO_8859_15

//
#define CHARS_NOCASE_ISO_8859_15

// ²³¹
#define CHARS_DIGITS_ISO_8859_15 "\xB2\xB3\xB9"

// ¡«·»¿
#define CHARS_PUNCTUATION_ISO_8859_15 "\xA1\xAB\xB7\xBB\xBF"

// ¢£€¥§©¬­®¯°±¶×÷
#define CHARS_SPECIALS_ISO_8859_15 "\xA2\xA3\xA4\xA5\xA7\xA9\xAC\xAD\xAE\xAF\xB0\xB1\xB6\xD7\xF7"

// ŠšªŽµžºŒœŸÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ
#define CHARS_ALPHA_ISO_8859_15 \
	"\xA6\xA8\xAA\xB4\xB5\xB8\xBA\xBC\xBD\xBE\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

#define CHARS_WHITESPACE_ISO_8859_15 "\xA0"

#define CHARS_CONTROL_ISO_8859_15 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"

#define CHARS_INVALID_ISO_8859_15 ""

// YyŒœŸÀÁÂÃÄÅÆÈÉÊËÌÍÎÏÒÓÔÕÖØÙÚÛÜÝàáâãäåæèéêëìíîïòóôõöøùúûüýÿ
#define CHARS_VOWELS_ISO_8859_15 \
	"\x59\x79\xBC\xBD\xBE\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFF"

// ŠšªŽµžºŸÇÐÑÝÞßçðñýþÿ
#define CHARS_CONSONANTS_ISO_8859_15 "\xA6\xA8\xAA\xB4\xB5\xB8\xBA\xBE\xC7\xD0\xD1\xDD\xDE\xDF\xE7\xF0\xF1\xFD\xFE\xFF"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒ё╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡Ё╢╣╤╥╦╧╨╩╪╫╬©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ

// here is the KOI8_R to Unicode conversion for KOI8_R characters from 0x80 to 0xFF
EXTATIC const UTF16 KOI8_R_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x2500,0x2502,0x250C,0x2510,0x2514,0x2518,0x251C,0x2524,0x252C,0x2534,0x253C,0x2580,0x2584,0x2588,0x258C,0x2590,
0x2591,0x2592,0x2593,0x2320,0x25A0,0x2219,0x221A,0x2248,0x2264,0x2265,0x00A0,0x2321,0x00B0,0x00B2,0x00B7,0x00F7,
0x2550,0x2551,0x2552,0x0451,0x2553,0x2554,0x2555,0x2556,0x2557,0x2558,0x2559,0x255A,0x255B,0x255C,0x255D,0x255E,
0x255F,0x2560,0x2561,0x0401,0x2562,0x2563,0x2564,0x2565,0x2566,0x2567,0x2568,0x2569,0x256A,0x256B,0x256C,0x00A9,
0x044E,0x0430,0x0431,0x0446,0x0434,0x0435,0x0444,0x0433,0x0445,0x0438,0x0439,0x043A,0x043B,0x043C,0x043D,0x043E,
0x043F,0x044F,0x0440,0x0441,0x0442,0x0443,0x0436,0x0432,0x044C,0x044B,0x0437,0x0448,0x044D,0x0449,0x0447,0x044A,
0x042E,0x0410,0x0411,0x0426,0x0414,0x0415,0x0424,0x0413,0x0425,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,
0x041F,0x042F,0x0420,0x0421,0x0422,0x0423,0x0416,0x0412,0x042C,0x042B,0x0417,0x0428,0x042D,0x0429,0x0427,0x042A }
#endif
;

// ёюабцдефгхийклмнопярстужвьызшэщчъ
#define CHARS_LOWER_KOI8_R \
	"\xA3\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"

//
#define CHARS_LOW_ONLY_KOI8_R

// ЁЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ
#define CHARS_UPPER_KOI8_R \
	"\xB3\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

//
#define CHARS_UP_ONLY_KOI8_R

//
#define CHARS_NOCASE_KOI8_R

// ²
#define CHARS_DIGITS_KOI8_R "\x9D"

// ·
#define CHARS_PUNCTUATION_KOI8_R "\x9E"

// ─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥⌡°÷═║╒╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬©
#define CHARS_SPECIALS_KOI8_R \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9B\x9C\x9F\xA0\xA1\xA2\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"

// ёЁюабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ
#define CHARS_ALPHA_KOI8_R \
	"\xA3\xB3\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

#define CHARS_WHITESPACE_KOI8_R "\x9A"

#define CHARS_CONTROL_KOI8_R

#define CHARS_INVALID_KOI8_R ""

// YyёЁюаеийояуыэЮАЕИЙОЯУЫЭ
#define CHARS_VOWELS_KOI8_R \
	"\x59\x79\xA3\xB3\xC0\xC1\xC5\xC9\xCA\xCF\xD1\xD5\xD9\xDC\xE0\xE1\xE5\xE9\xEA\xEF\xF1\xF5\xF9\xFC"

// бцдфгхклмнпрстжвьзшщчъБЦДФГХКЛМНПРСТЖВЬЗШЩЧЪ
#define CHARS_CONSONANTS_KOI8_R \
	"\xC2\xC3\xC4\xC6\xC7\xC8\xCB\xCC\xCD\xCE\xD0\xD2\xD3\xD4\xD6\xD7\xD8\xDA\xDB\xDD\xDE\xDF\xE2\xE3\xE4\xE6\xE7\xE8\xEB\xEC\xED\xEE\xF0\xF2\xF3\xF4\xF6\xF7\xF8\xFA\xFB\xFD\xFE\xFF"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ 

// here is the CP437 to Unicode conversion for CP437 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP437_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,
0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,0x00FF,0x00D6,0x00DC,0x00A2,0x00A3,0x00A5,0x20A7,0x0192,
0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,0x00BF,0x2310,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,
0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
0x03B1,0x00DF,0x0393,0x03C0,0x03A3,0x03C3,0x00B5,0x03C4,0x03A6,0x0398,0x03A9,0x03B4,0x221E,0x03C6,0x03B5,0x2229,
0x2261,0x00B1,0x2265,0x2264,0x2320,0x2321,0x00F7,0x2248,0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x00A0 }
#endif
;
// *** WARNING, char at 0xE1 U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// üéäåçæöñσφ
#define CHARS_LOWER_CP437 "\x81\x82\x84\x86\x87\x91\x94\xA4\xE5\xED"

// âàêëèïîìôòûùÿƒáíóúªºαßπµτδε
#define CHARS_LOW_ONLY_CP437 \
	"\x83\x85\x88\x89\x8A\x8B\x8C\x8D\x93\x95\x96\x97\x98\x9F\xA0\xA1\xA2\xA3\xA6\xA7\xE0\xE1\xE3\xE6\xE7\xEB\xEE"

// ÜÉÄÅÇÆÖÑΣΦ
#define CHARS_UPPER_CP437 "\x9A\x90\x8E\x8F\x80\x92\x99\xA5\xE4\xE8"

//
#define CHARS_UP_ONLY_CP437

//
#define CHARS_NOCASE_CP437

// ½¼²
#define CHARS_DIGITS_CP437 "\xAB\xAC\xFD"

// ¿¡«»·
#define CHARS_PUNCTUATION_CP437 "\xA8\xAD\xAE\xAF\xFA"

// ¢£¥₧⌐¬░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀∞∩≡±≥≤⌠⌡÷≈°∙√ⁿ■
#define CHARS_SPECIALS_CP437 \
	"\x9B\x9C\x9D\x9E\xA9\xAA\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xEC\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFB\xFC\xFE"

// ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜƒáíóúñÑªºαßΓπΣσµτΦΘΩδφε
#define CHARS_ALPHA_CP437 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xED\xEE"

#define CHARS_WHITESPACE_CP437 "\xFF"

#define CHARS_CONTROL_CP437

#define CHARS_INVALID_CP437 ""

// YyüéâäàåêëèïîìÄÅÉæÆôöòûùÿÖÜáíóúαΩε
#define CHARS_VOWELS_CP437 \
	"\x59\x79\x81\x82\x83\x84\x85\x86\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\xA0\xA1\xA2\xA3\xE0\xEA\xEE"

// ÇçÿƒñÑªºßΓπΣσµτΦΘδφ
#define CHARS_CONSONANTS_CP437 "\x80\x87\x98\x9F\xA4\xA5\xA6\xA7\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEB\xED"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
//

// here is the CP720 to Unicode conversion for CP720 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP720_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0080,0x0081,0x00E9,0x00E2,0x0084,0x00E0,0x0086,0x00E7,0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x008D,0x008E,0x008F,
0x0090,0x0651,0x0652,0x00F4,0x00A4,0x0640,0x00FB,0x00F9,0x0621,0x0622,0x0623,0x0624,0x00A3,0x0625,0x0626,0x0627,
0x0628,0x0629,0x062A,0x062B,0x062C,0x062D,0x062E,0x062F,0x0630,0x0631,0x0632,0x0633,0x0634,0x0635,0x00AB,0x00BB,
0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
0x0636,0x0637,0x0638,0x0639,0x063A,0x0641,0x00B5,0x0642,0x0643,0x0644,0x0645,0x0646,0x0647,0x0648,0x0649,0x064A,
0x2261,0x064B,0x064C,0x064D,0x064E,0x064F,0x0650,0x2248,0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x00A0 }
#endif
;

//
#define CHARS_LOWER_CP720 ""

// éâàçêëèïîôûùµ
#define CHARS_LOW_ONLY_CP720 "\x82\x83\x85\x87\x88\x89\x8A\x8B\x8C\x93\x96\x97\xE6"

//
#define CHARS_UPPER_CP720 ""

//
#define CHARS_UP_ONLY_CP720

//
#define CHARS_NOCASE_CP720 \
	"\x91\x92\x95\x98\x99\x9A\x9B\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xE0\xE1\xE2\xE3\xE4\xE5\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6"

// ²
#define CHARS_DIGITS_CP720 "\xFD"

// «»
#define CHARS_PUNCTUATION_CP720 "\xAE\xAF"

// ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀≈°∙√ⁿ■
#define CHARS_SPECIALS_CP720 \
	"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

//
#define CHARS_ALPHA_CP720 \
	"\x91\x92\x95\x98\x99\x9A\x9B\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xE0\xE1\xE2\xE3\xE4\xE5\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6"

#define CHARS_WHITESPACE_CP720 "\xFF"

#define CHARS_CONTROL_CP720 "\x80\x81\x84\x86\x8D\x8E\x8F\x90"

#define CHARS_INVALID_CP720 ""

//
#define CHARS_VOWELS_CP720

//
#define CHARS_CONSONANTS_CP720 \
	"\x91\x92\x95\x98\x99\x9A\x9B\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xE0\xE1\xE2\xE3\xE4\xE5\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀ωάέήϊίόύϋώΆΈΉΊΌΎΏ±≥≤ΪΫ÷≈°∙·√ⁿ²■ 

// here is the CP737 to Unicode conversion for CP737 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP737_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0391,0x0392,0x0393,0x0394,0x0395,0x0396,0x0397,0x0398,0x0399,0x039A,0x039B,0x039C,0x039D,0x039E,0x039F,0x03A0,
0x03A1,0x03A3,0x03A4,0x03A5,0x03A6,0x03A7,0x03A8,0x03A9,0x03B1,0x03B2,0x03B3,0x03B4,0x03B5,0x03B6,0x03B7,0x03B8,
0x03B9,0x03BA,0x03BB,0x03BC,0x03BD,0x03BE,0x03BF,0x03C0,0x03C1,0x03C3,0x03C2,0x03C4,0x03C5,0x03C6,0x03C7,0x03C8,
0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
0x03C9,0x03AC,0x03AD,0x03AE,0x03CA,0x03AF,0x03CC,0x03CD,0x03CB,0x03CE,0x0386,0x0388,0x0389,0x038A,0x038C,0x038E,
0x038F,0x00B1,0x2265,0x2264,0x03AA,0x03AB,0x00F7,0x2248,0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x00A0 }
#endif
;

// αβγδεζηθικλμνξοπρσςτυφχψωάέήϊίόύϋώ
#define CHARS_LOWER_CP737 \
	"\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9"

//
#define CHARS_LOW_ONLY_CP737

// ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΣΤΥΦΧΨΩΆΈΉΪΊΌΎΫΏ
#define CHARS_UPPER_CP737 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x91\x92\x93\x94\x95\x96\x97\xEA\xEB\xEC\xF4\xED\xEE\xEF\xF5\xF0"

//
#define CHARS_UP_ONLY_CP737

//
#define CHARS_NOCASE_CP737

// ²
#define CHARS_DIGITS_CP737 "\xFD"

// ·
#define CHARS_PUNCTUATION_CP737 "\xFA"

// ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀±≥≤÷≈°∙√ⁿ■
#define CHARS_SPECIALS_CP737 \
	"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xF1\xF2\xF3\xF6\xF7\xF8\xF9\xFB\xFC\xFE"

// ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψωάέήϊίόύϋώΆΈΉΊΌΎΏΪΫ
#define CHARS_ALPHA_CP737 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF4\xF5"

#define CHARS_WHITESPACE_CP737 "\xFF"

#define CHARS_CONTROL_CP737

#define CHARS_INVALID_CP737 ""

// YyΑΕΗΙΟΥΩαεηιουωάέήϊίόύϋώΆΈΉΊΌΎΏΪΫ
#define CHARS_VOWELS_CP737 \
	"\x59\x79\x80\x84\x86\x88\x8E\x93\x97\x98\x9C\x9E\xA0\xA6\xAC\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF4\xF5"

// ΒΓΔΖΘΚΛΜΝΞΠΡΣΤΦΧΨβγδζθκλμνξπρσςτφχψ
#define CHARS_CONSONANTS_CP737 \
	"\x81\x82\x83\x85\x87\x89\x8A\x8B\x8C\x8D\x8F\x90\x91\x92\x94\x95\x96\x99\x9A\x9B\x9D\x9F\xA1\xA2\xA3\xA4\xA5\xA7\xA8\xA9\xAA\xAB\xAD\xAE\xAF"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈıÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ 

// here is the CP850 to Unicode conversion for CP850 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP850_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,
0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,0x00FF,0x00D6,0x00DC,0x00F8,0x00A3,0x00D8,0x00D7,0x0192,
0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,0x00BF,0x00AE,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,
0x2591,0x2592,0x2593,0x2502,0x2524,0x00C1,0x00C2,0x00C0,0x00A9,0x2563,0x2551,0x2557,0x255D,0x00A2,0x00A5,0x2510,
0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x00E3,0x00C3,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x00A4,
0x00F0,0x00D0,0x00CA,0x00CB,0x00C8,0x0131,0x00CD,0x00CE,0x00CF,0x2518,0x250C,0x2588,0x2584,0x00A6,0x00CC,0x2580,
0x00D3,0x00DF,0x00D4,0x00D2,0x00F5,0x00D5,0x00B5,0x00FE,0x00DE,0x00DA,0x00DB,0x00D9,0x00FD,0x00DD,0x00AF,0x00B4,
0x00AD,0x00B1,0x2017,0x00BE,0x00B6,0x00A7,0x00F7,0x00B8,0x00B0,0x00A8,0x00B7,0x00B9,0x00B3,0x00B2,0x25A0,0x00A0 }
#endif
;
// *** WARNING, char at 0xD5 -> U+0131 -> U+0049 -> 0x49 (ı -> I) needs to be looked into.  Likely one way casing conversion
// *** WARNING, char at 0xE1 U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// üéâäàåçêëèïîìæôöòûùøáíóúñãðõþý
#define CHARS_LOWER_CP850 \
	"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x91\x93\x94\x95\x96\x97\x9B\xA0\xA1\xA2\xA3\xA4\xC6\xD0\xE4\xE7\xEC"

// ÿƒªºıßµ
#define CHARS_LOW_ONLY_CP850 "\x98\x9F\xA6\xA7\xD5\xE1\xE6"

// ÜÉÂÄÀÅÇÊËÈÏÎÌÆÔÖÒÛÙØÁÍÓÚÑÃÐÕÞÝ
#define CHARS_UPPER_CP850 \
	"\x9A\x90\xB6\x8E\xB7\x8F\x80\xD2\xD3\xD4\xD8\xD7\xDE\x92\xE2\x99\xE3\xEA\xEB\x9D\xB5\xD6\xE0\xE9\xA5\xC7\xD1\xE5\xE8\xED"

//
#define CHARS_UP_ONLY_CP850

//
#define CHARS_NOCASE_CP850

// ½¼¾¹³²
#define CHARS_DIGITS_CP850 "\xAB\xAC\xF3\xFB\xFC\xFD"

// ¿¡«»‗·
#define CHARS_PUNCTUATION_CP850 "\xA8\xAD\xAE\xAF\xF2\xFA"

// £×®¬░▒▓│┤©╣║╗╝¢¥┐└┴┬├─┼╚╔╩╦╠═╬¤┘┌█▄¦▀¯´­±¶§÷¸°¨■
#define CHARS_SPECIALS_CP850 \
	"\x9C\x9E\xA9\xAA\xB0\xB1\xB2\xB3\xB4\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD9\xDA\xDB\xDC\xDD\xDF\xEE\xEF\xF0\xF1\xF4\xF5\xF6\xF7\xF8\xF9\xFE"

// ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜøØƒáíóúñÑªºÁÂÀãÃðÐÊËÈıÍÎÏÌÓßÔÒõÕµþÞÚÛÙýÝ
#define CHARS_ALPHA_CP850 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9D\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xB5\xB6\xB7\xC6\xC7\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xDE\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED"

#define CHARS_WHITESPACE_CP850 "\xFF"

#define CHARS_CONTROL_CP850

#define CHARS_INVALID_CP850 ""

// YyüéâäàåêëèïîìÄÅÉæÆôöòûùÿÖÜøØáíóúÁÂÀãÃÊËÈıÍÎÏÌÓÔÒõÕÚÛÙýÝ
#define CHARS_VOWELS_CP850 \
	"\x59\x79\x81\x82\x83\x84\x85\x86\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9D\xA0\xA1\xA2\xA3\xB5\xB6\xB7\xC6\xC7\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xDE\xE0\xE2\xE3\xE4\xE5\xE9\xEA\xEB\xEC\xED"

// ÇçÿƒñÑªºðÐßµþÞýÝ
#define CHARS_CONSONANTS_CP850 "\x80\x87\x98\x9F\xA4\xA5\xA6\xA7\xD0\xD1\xE1\xE6\xE7\xE8\xEC\xED"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ÇüéâäůćçłëŐőîŹÄĆÉĹĺôöĽľŚśÖÜŤťŁ×čáíóúĄąŽžĘę¬źČş«»░▒▓│┤ÁÂĚŞ╣║╗╝Żż┐└┴┬├─┼Ăă╚╔╩╦╠═╬¤đĐĎËďŇÍÎě┘┌█▄ŢŮ▀ÓßÔŃńňŠšŔÚŕŰýÝţ´­˝˛ˇ˘§÷¸°¨˙űŘř■ 

// here is the CP852 to Unicode conversion for CP852 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP852_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x016F,0x0107,0x00E7,0x0142,0x00EB,0x0150,0x0151,0x00EE,0x0179,0x00C4,0x0106,
0x00C9,0x0139,0x013A,0x00F4,0x00F6,0x013D,0x013E,0x015A,0x015B,0x00D6,0x00DC,0x0164,0x0165,0x0141,0x00D7,0x010D,
0x00E1,0x00ED,0x00F3,0x00FA,0x0104,0x0105,0x017D,0x017E,0x0118,0x0119,0x00AC,0x017A,0x010C,0x015F,0x00AB,0x00BB,
0x2591,0x2592,0x2593,0x2502,0x2524,0x00C1,0x00C2,0x011A,0x015E,0x2563,0x2551,0x2557,0x255D,0x017B,0x017C,0x2510,
0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x0102,0x0103,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x00A4,
0x0111,0x0110,0x010E,0x00CB,0x010F,0x0147,0x00CD,0x00CE,0x011B,0x2518,0x250C,0x2588,0x2584,0x0162,0x016E,0x2580,
0x00D3,0x00DF,0x00D4,0x0143,0x0144,0x0148,0x0160,0x0161,0x0154,0x00DA,0x0155,0x0170,0x00FD,0x00DD,0x0163,0x00B4,
0x00AD,0x02DD,0x02DB,0x02C7,0x02D8,0x00A7,0x00F7,0x00B8,0x00B0,0x00A8,0x02D9,0x0171,0x0158,0x0159,0x25A0,0x00A0 }
#endif
;
// *** WARNING, char at 0xE1 U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// üéâäůćçłëőîĺôöľśťčáíóúąžęźşżăđďěńňšŕýţűř
#define CHARS_LOWER_CP852 \
	"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8B\x8C\x92\x93\x94\x96\x98\x9C\x9F\xA0\xA1\xA2\xA3\xA5\xA7\xA9\xAB\xAD\xBE\xC7\xD0\xD4\xD8\xE4\xE5\xE7\xEA\xEC\xEE\xFB\xFD"

// ß
#define CHARS_LOW_ONLY_CP852 "\xE1"

// ÜÉÂÄŮĆÇŁËŐÎĹÔÖĽŚŤČÁÍÓÚĄŽĘŹŞŻĂĐĎĚŃŇŠŔÝŢŰŘ
#define CHARS_UPPER_CP852 \
	"\x9A\x90\xB6\x8E\xDE\x8F\x80\x9D\xD3\x8A\xD7\x91\xE2\x99\x95\x97\x9B\xAC\xB5\xD6\xE0\xE9\xA4\xA6\xA8\x8D\xB8\xBD\xC6\xD1\xD2\xB7\xE3\xD5\xE6\xE8\xED\xDD\xEB\xFC"

//
#define CHARS_UP_ONLY_CP852

//
#define CHARS_NOCASE_CP852

//
#define CHARS_DIGITS_CP852 ""

// «»
#define CHARS_PUNCTUATION_CP852 "\xAE\xAF"

// ×¬░▒▓│┤╣║╗╝┐└┴┬├─┼╚╔╩╦╠═╬¤┘┌█▄▀´­˝˛ˇ˘§÷¸°¨˙■
#define CHARS_SPECIALS_CP852 \
	"\x9E\xAA\xB0\xB1\xB2\xB3\xB4\xB9\xBA\xBB\xBC\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD9\xDA\xDB\xDC\xDF\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFE"

// ÇüéâäůćçłëŐőîŹÄĆÉĹĺôöĽľŚśÖÜŤťŁčáíóúĄąŽžĘęźČşÁÂĚŞŻżĂăđĐĎËďŇÍÎěŢŮÓßÔŃńňŠšŔÚŕŰýÝţűŘř
#define CHARS_ALPHA_CP852 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAB\xAC\xAD\xB5\xB6\xB7\xB8\xBD\xBE\xC6\xC7\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xDD\xDE\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xFB\xFC\xFD"

#define CHARS_WHITESPACE_CP852 "\xFF"

#define CHARS_CONTROL_CP852

#define CHARS_INVALID_CP852 ""

// YyüéâäůëŐőîÄÉôöÖÜáíóúĄąĘęÁÂĚĂăËÍÎěŮÓÔÚŰýÝű
#define CHARS_VOWELS_CP852 \
	"\x59\x79\x81\x82\x83\x84\x85\x89\x8A\x8B\x8C\x8E\x90\x93\x94\x99\x9A\xA0\xA1\xA2\xA3\xA4\xA5\xA8\xA9\xB5\xB6\xB7\xC6\xC7\xD3\xD6\xD7\xD8\xDE\xE0\xE2\xE9\xEB\xEC\xED\xFB"

// ÇćçłŹĆĹĺĽľŚśŤťŁčŽžźČşŞŻżđĐĎďŇŢßŃńňŠšŔŕýÝţŘř
#define CHARS_CONSONANTS_CP852 \
	"\x80\x86\x87\x88\x8D\x8F\x91\x92\x95\x96\x97\x98\x9B\x9C\x9D\x9F\xA6\xA7\xAB\xAC\xAD\xB8\xBD\xBE\xD0\xD1\xD2\xD4\xD5\xDD\xE1\xE3\xE4\xE5\xE6\xE7\xE8\xEA\xEC\xED\xEE\xFC\xFD"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈ€ÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ 

// here is the CP858 to Unicode conversion for CP858 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP858_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,
0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,0x00FF,0x00D6,0x00DC,0x00F8,0x00A3,0x00D8,0x00D7,0x0192,
0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,0x00BF,0x00AE,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,
0x2591,0x2592,0x2593,0x2502,0x2524,0x00C1,0x00C2,0x00C0,0x00A9,0x2563,0x2551,0x2557,0x255D,0x00A2,0x00A5,0x2510,
0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x00E3,0x00C3,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x00A4,
0x00F0,0x00D0,0x00CA,0x00CB,0x00C8,0x20AC,0x00CD,0x00CE,0x00CF,0x2518,0x250C,0x2588,0x2584,0x00A6,0x00CC,0x2580,
0x00D3,0x00DF,0x00D4,0x00D2,0x00F5,0x00D5,0x00B5,0x00FE,0x00DE,0x00DA,0x00DB,0x00D9,0x00FD,0x00DD,0x00AF,0x00B4,
0x00AD,0x00B1,0x2017,0x00BE,0x00B6,0x00A7,0x00F7,0x00B8,0x00B0,0x00A8,0x00B7,0x00B9,0x00B3,0x00B2,0x25A0,0x00A0 }
#endif
;
// *** WARNING, char at 0xE1 U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// üéâäàåçêëèïîìæôöòûùøáíóúñãðõþý
#define CHARS_LOWER_CP858 \
	"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x91\x93\x94\x95\x96\x97\x9B\xA0\xA1\xA2\xA3\xA4\xC6\xD0\xE4\xE7\xEC"

// ÿƒªºßµ
#define CHARS_LOW_ONLY_CP858 "\x98\x9F\xA6\xA7\xE1\xE6"

// ÜÉÂÄÀÅÇÊËÈÏÎÌÆÔÖÒÛÙØÁÍÓÚÑÃÐÕÞÝ
#define CHARS_UPPER_CP858 \
	"\x9A\x90\xB6\x8E\xB7\x8F\x80\xD2\xD3\xD4\xD8\xD7\xDE\x92\xE2\x99\xE3\xEA\xEB\x9D\xB5\xD6\xE0\xE9\xA5\xC7\xD1\xE5\xE8\xED"

//
#define CHARS_UP_ONLY_CP858

//
#define CHARS_NOCASE_CP858

// ½¼¾¹³²
#define CHARS_DIGITS_CP858 "\xAB\xAC\xF3\xFB\xFC\xFD"

// ¿¡«»‗·
#define CHARS_PUNCTUATION_CP858 "\xA8\xAD\xAE\xAF\xF2\xFA"

// £×®¬░▒▓│┤©╣║╗╝¢¥┐└┴┬├─┼╚╔╩╦╠═╬¤€┘┌█▄¦▀¯´­±¶§÷¸°¨■
#define CHARS_SPECIALS_CP858 \
	"\x9C\x9E\xA9\xAA\xB0\xB1\xB2\xB3\xB4\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD5\xD9\xDA\xDB\xDC\xDD\xDF\xEE\xEF\xF0\xF1\xF4\xF5\xF6\xF7\xF8\xF9\xFE"

// ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜøØƒáíóúñÑªºÁÂÀãÃðÐÊËÈÍÎÏÌÓßÔÒõÕµþÞÚÛÙýÝ
#define CHARS_ALPHA_CP858 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9D\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xB5\xB6\xB7\xC6\xC7\xD0\xD1\xD2\xD3\xD4\xD6\xD7\xD8\xDE\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED"

#define CHARS_WHITESPACE_CP858 "\xFF"

#define CHARS_CONTROL_CP858

#define CHARS_INVALID_CP858 ""

// YyüéâäàåêëèïîìÄÅÉæÆôöòûùÿÖÜøØáíóúÁÂÀãÃÊËÈÍÎÏÌÓÔÒõÕÚÛÙýÝ
#define CHARS_VOWELS_CP858 \
	"\x59\x79\x81\x82\x83\x84\x85\x86\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9D\xA0\xA1\xA2\xA3\xB5\xB6\xB7\xC6\xC7\xD2\xD3\xD4\xD6\xD7\xD8\xDE\xE0\xE2\xE3\xE4\xE5\xE9\xEA\xEB\xEC\xED"

// ÇçÿƒñÑªºðÐßµþÞýÝ
#define CHARS_CONSONANTS_CP858 "\x80\x87\x98\x9F\xA4\xA5\xA6\xA7\xD0\xD1\xE1\xE6\xE7\xE8\xEC\xED"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№¤■ 

// here is the CP866 to Unicode conversion for CP866 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP866_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,0x041F,
0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042A,0x042B,0x042C,0x042D,0x042E,0x042F,
0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,0x043A,0x043B,0x043C,0x043D,0x043E,0x043F,
0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,0x044A,0x044B,0x044C,0x044D,0x044E,0x044F,
0x0401,0x0451,0x0404,0x0454,0x0407,0x0457,0x040E,0x045E,0x00B0,0x2219,0x00B7,0x221A,0x2116,0x00A4,0x25A0,0x00A0 }
#endif
;

// абвгдежзийклмнопрстуфхцчшщъыьэюяёєїў
#define CHARS_LOWER_CP866 \
	"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF1\xF3\xF5\xF7"

//
#define CHARS_LOW_ONLY_CP866

// АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯЁЄЇЎ
#define CHARS_UPPER_CP866 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xF0\xF2\xF4\xF6"

//
#define CHARS_UP_ONLY_CP866

//
#define CHARS_NOCASE_CP866

//
#define CHARS_DIGITS_CP866 ""

// ·
#define CHARS_PUNCTUATION_CP866 "\xFA"

// ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀°∙√№¤■
#define CHARS_SPECIALS_CP866 \
	"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xF8\xF9\xFB\xFC\xFD\xFE"

// АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяЁёЄєЇїЎў
#define CHARS_ALPHA_CP866 \
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7"

#define CHARS_WHITESPACE_CP866 "\xFF"

#define CHARS_CONTROL_CP866

#define CHARS_INVALID_CP866 ""

// YyАЕИЙОУЫЭЮЯаеийоуыэюяЁёЄєЇїЎў
#define CHARS_VOWELS_CP866 \
	"\x59\x79\x80\x85\x88\x89\x8E\x93\x9B\x9D\x9E\x9F\xA0\xA5\xA8\xA9\xAE\xE3\xEB\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7"

// БВГДЖЗКЛМНПРСТФХЦЧШЩЪЬбвгджзклмнпрстфхцчшщъь
#define CHARS_CONSONANTS_CP866 \
	"\x81\x82\x83\x84\x86\x87\x8A\x8B\x8C\x8D\x8F\x90\x91\x92\x94\x95\x96\x97\x98\x99\x9A\x9C\xA1\xA2\xA3\xA4\xA6\xA7\xAA\xAB\xAC\xAD\xAF\xE0\xE1\xE2\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEC"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ٠١٢٣٤٥٦٧٨٩،؛؟آاﺎبﺑپةتﺗثﺛجﺟحﺣخﺧدذرزسﺳش«»ﺷص░▒▓│┤ﺻضﺿط╣║╗╝ظع┐└┴┬├─┼ﻊﻋ╚╔╩╦╠═╬ﻌغﻎﻏﻐفﻓقﻗﻚ┘┌█▀ﻛ▄لﻞﻠمﻣنﻧوء­ّﹽ■ 

// here is the CP868 to Unicode conversion for CP868 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP868_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0660,0x0661,0x0662,0x0663,0x0664,0x0665,0x0666,0x0667,0x0668,0x0669,0x060C,0x061B,0x061F,0x0622,0x0627,0xFE8E,
0xE016,0x0628,0xFE91,0x067E,0x0094,0x0629,0x062A,0xFE97,0x0098,0x0099,0x062B,0xFE9B,0x062C,0xFE9F,0x009E,0x009F,
0x062D,0xFEA3,0x062E,0xFEA7,0x062F,0x00A5,0x0630,0x0631,0x00A8,0x0632,0x00AA,0x0633,0xFEB3,0x0634,0x00AB,0x00BB,
0xFEB7,0x0635,0x2591,0x2592,0x2593,0x2502,0x2524,0xFEBB,0x0636,0xFEBF,0x0637,0x2563,0x2551,0x2557,0x255D,0x0638,
0x0639,0x2510,0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0xFECA,0xFECB,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,
0x256C,0xFECC,0x063A,0xFECE,0xFECF,0xFED0,0x0641,0xFED3,0x0642,0xFED7,0xFEDA,0x2518,0x250C,0x2588,0x2580,0xFEDB,
0x00E0,0x2584,0x00E2,0x0644,0xFEDE,0xFEE0,0x0645,0xFEE3,0x00E8,0x0646,0xFEE7,0x00EB,0x0648,0x00ED,0x00EE,0x00EF,
0x00F0,0x0621,0x00AD,0x00F3,0x00F4,0x00F5,0x00F6,0x00F7,0x00F8,0x00F9,0x00FA,0x0651,0xFE7D,0x00FD,0x25A0,0x00A0 }
#endif
;

#define CHARS_LOWER_CP868 ""

#define CHARS_LOW_ONLY_CP868

#define CHARS_UPPER_CP868 ""

#define CHARS_UP_ONLY_CP868

// آاﺎبﺑپةتﺗثﺛجﺟحﺣخﺧدذرزسﺳشﺷصﺻضﺿطظعﻊﻋﻌغﻎﻏﻐفﻓقﻗﻚﻛلﻞﻠمﻣنﻧوءّﹽ
#define CHARS_NOCASE_CP868 \
	"\x8D\x8E\x8F\x90\x91\x92\x93\x95\x96\x97\x9A\x9B\x9C\x9D\xA0\xA1\xA2\xA3\xA4\xA6\xA7\xA9\xAB\xAC\xAD\xB0\xB1\xB7\xB8\xB9\xBA\xBF\xC0\xC8\xC9\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDF\xE3\xE4\xE5\xE6\xE7\xE9\xEA\xEC\xF1\xFB\xFC"

//٠١٢٣٤٥٦٧٨٩
#define CHARS_DIGITS_CP868 "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"

// ،؛؟«»
#define CHARS_PUNCTUATION_CP868 "\x8A\x8B\x8C\xAE\xAF"

//
#define CHARS_SPECIALS_CP868 ""

// آاﺎبﺑپةتﺗثﺛجﺟحﺣخﺧدذرزسﺳشﺷصﺻضﺿطظعﻊﻋﻌغﻎﻏﻐفﻓقﻗﻚﻛلﻞﻠمﻣنﻧوءّﹽ
#define CHARS_ALPHA_CP868 \
	"\x8D\x8E\x8F\x90\x91\x92\x93\x95\x96\x97\x9A\x9B\x9C\x9D\xA0\xA1\xA2\xA3\xA4\xA6\xA7\xA9\xAB\xAC\xAD\xB0\xB1\xB7\xB8\xB9\xBA\xBF\xC0\xC8\xC9\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDF\xE3\xE4\xE5\xE6\xE7\xE9\xEA\xEC\xF1\xFB\xFC"

#define CHARS_WHITESPACE_CP868 "\xF2\xFF"

#define CHARS_CONTROL_CP868

#define CHARS_INVALID_CP868 "\x94\x9E\x9F\xA5\xA8\xAA\xE2\xE8\xEB\xED\xEE\xEF\xF0\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFD"

#define CHARS_VOWELS_CP868

// آاﺎبﺑپةتﺗثﺛجﺟحﺣخﺧدذرزسﺳشﺷصﺻضﺿطظعﻊﻋﻌغﻎﻏﻐفﻓقﻗﻚﻛلﻞﻠمﻣنﻧوءّﹽ
#define CHARS_CONSONANTS_CP868 \
	"\x8D\x8E\x8F\x90\x91\x92\x93\x95\x96\x97\x9A\x9B\x9C\x9D\xA0\xA1\xA2\xA3\xA4\xA6\xA7\xA9\xAB\xAC\xAD\xB0\xB1\xB7\xB8\xB9\xBA\xBF\xC0\xC8\xC9\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDF\xE3\xE4\xE5\xE6\xE7\xE9\xEA\xEC\xF1\xFB\xFC"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// €�‚�„…†‡�‰Š‹ŚŤŽŹ�‘’“”•–—�™š›śťžź ˇ˘Ł¤Ą¦§¨©Ş«¬­®Ż°±˛ł´µ¶·¸ąş»Ľ˝ľżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙

// here is the CP1250 to Unicode conversion for CP1250 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP1250_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x20AC,0x0081,0x201A,0x0083,0x201E,0x2026,0x2020,0x2021,0x0088,0x2030,0x0160,0x2039,0x015A,0x0164,0x017D,0x0179,
0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x0098,0x2122,0x0161,0x203A,0x015B,0x0165,0x017E,0x017A,
0x00A0,0x02C7,0x02D8,0x0141,0x00A4,0x0104,0x00A6,0x00A7,0x00A8,0x00A9,0x015E,0x00AB,0x00AC,0x00AD,0x00AE,0x017B,
0x00B0,0x00B1,0x02DB,0x0142,0x00B4,0x00B5,0x00B6,0x00B7,0x00B8,0x0105,0x015F,0x00BB,0x013D,0x02DD,0x013E,0x017C,
0x0154,0x00C1,0x00C2,0x0102,0x00C4,0x0139,0x0106,0x00C7,0x010C,0x00C9,0x0118,0x00CB,0x011A,0x00CD,0x00CE,0x010E,
0x0110,0x0143,0x0147,0x00D3,0x00D4,0x0150,0x00D6,0x00D7,0x0158,0x016E,0x00DA,0x0170,0x00DC,0x00DD,0x0162,0x00DF,
0x0155,0x00E1,0x00E2,0x0103,0x00E4,0x013A,0x0107,0x00E7,0x010D,0x00E9,0x0119,0x00EB,0x011B,0x00ED,0x00EE,0x010F,
0x0111,0x0144,0x0148,0x00F3,0x00F4,0x0151,0x00F6,0x00F7,0x0159,0x016F,0x00FA,0x0171,0x00FC,0x00FD,0x0163,0x02D9 }
#endif
;
// *** WARNING, char at 0xDF U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// šśťžźłąşľżŕáâăäĺćçčéęëěíîďđńňóôőöřůúűüýţ
#define CHARS_LOWER_CP1250 \
	"\x9A\x9C\x9D\x9E\x9F\xB3\xB9\xBA\xBE\xBF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

// µß
#define CHARS_LOW_ONLY_CP1250 "\xB5\xDF"

// ŠŚŤŽŹŁĄŞĽŻŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖŘŮÚŰÜÝŢ
#define CHARS_UPPER_CP1250 \
	"\x8A\x8C\x8D\x8E\x8F\xA3\xA5\xAA\xBC\xAF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE"

//
#define CHARS_UP_ONLY_CP1250

//
#define CHARS_NOCASE_CP1250

//
#define CHARS_DIGITS_CP1250 ""

// ‚„…†‡‰‹‘’“”•–—›«·»
#define CHARS_PUNCTUATION_CP1250 "\x82\x84\x85\x86\x87\x89\x8B\x91\x92\x93\x94\x95\x96\x97\x9B\xAB\xB7\xBB"

// €™ˇ˘¤¦§¨©¬­®°±˛´¶¸˝×÷˙
#define CHARS_SPECIALS_CP1250 \
	"\x80\x99\xA1\xA2\xA4\xA6\xA7\xA8\xA9\xAC\xAD\xAE\xB0\xB1\xB2\xB4\xB6\xB8\xBD\xD7\xF7\xFF"

// ŠŚŤŽŹšśťžźŁĄŞŻłµąşĽľżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőöřůúűüýţ
#define CHARS_ALPHA_CP1250 \
	"\x8A\x8C\x8D\x8E\x8F\x9A\x9C\x9D\x9E\x9F\xA3\xA5\xAA\xAF\xB3\xB5\xB9\xBA\xBC\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

#define CHARS_WHITESPACE_CP1250 "\xA0"

#define CHARS_CONTROL_CP1250

#define CHARS_INVALID_CP1250 "\x81\x83\x88\x90\x98"

// YyĄąÁÂĂÄÉĘËĚÍÎÓÔŐÖŮÚŰÜÝáâăäéęëěíîóôőöůúűüý
#define CHARS_VOWELS_CP1250 \
	"\x59\x79\xA5\xB9\xC1\xC2\xC3\xC4\xC9\xCA\xCB\xCC\xCD\xCE\xD3\xD4\xD5\xD6\xD9\xDA\xDB\xDC\xDD\xE1\xE2\xE3\xE4\xE9\xEA\xEB\xEC\xED\xEE\xF3\xF4\xF5\xF6\xF9\xFA\xFB\xFC\xFD"

// ŠŚŤŽŹšśťžźŁŞŻłµşĽľżŔĹĆÇČĎĐŃŇŘÝŢßŕĺćçčďđńňřýţ
#define CHARS_CONSONANTS_CP1250 \
	"\x8A\x8C\x8D\x8E\x8F\x9A\x9C\x9D\x9E\x9F\xA3\xAA\xAF\xB3\xB5\xBA\xBC\xBE\xBF\xC0\xC5\xC6\xC7\xC8\xCF\xD0\xD1\xD2\xD8\xDD\xDE\xDF\xE0\xE5\xE6\xE7\xE8\xEF\xF0\xF1\xF2\xF8\xFD\xFE"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—�™љ›њќћџ ЎўЈ¤Ґ¦§Ё©Є«¬­®Ї°±Ііґµ¶·ё№є»јЅѕїАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя

// here is the CP1251 to Unicode conversion for CP1251 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP1251_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x0402,0x0403,0x201A,0x0453,0x201E,0x2026,0x2020,0x2021,0x20AC,0x2030,0x0409,0x2039,0x040A,0x040C,0x040B,0x040F,
0x0452,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x0098,0x2122,0x0459,0x203A,0x045A,0x045C,0x045B,0x045F,
0x00A0,0x040E,0x045E,0x0408,0x00A4,0x0490,0x00A6,0x00A7,0x0401,0x00A9,0x0404,0x00AB,0x00AC,0x00AD,0x00AE,0x0407,
0x00B0,0x00B1,0x0406,0x0456,0x0491,0x00B5,0x00B6,0x00B7,0x0451,0x2116,0x0454,0x00BB,0x0458,0x0405,0x0455,0x0457,
0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,0x041F,
0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042A,0x042B,0x042C,0x042D,0x042E,0x042F,
0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,0x043A,0x043B,0x043C,0x043D,0x043E,0x043F,
0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,0x044A,0x044B,0x044C,0x044D,0x044E,0x044F }
#endif
;

// ѓђљњќћџўіґёєјѕїабвгдежзийклмнопрстуфхцчшщъыьэюя
#define CHARS_LOWER_CP1251 \
	"\x83\x90\x9A\x9C\x9D\x9E\x9F\xA2\xB3\xB4\xB8\xBA\xBC\xBE\xBF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

// µ
#define CHARS_LOW_ONLY_CP1251 "\xB5"

// ЃЂЉЊЌЋЏЎІҐЁЄЈЅЇАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ
#define CHARS_UPPER_CP1251 \
	"\x81\x80\x8A\x8C\x8D\x8E\x8F\xA1\xB2\xA5\xA8\xAA\xA3\xBD\xAF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"

//
#define CHARS_UP_ONLY_CP1251

//
#define CHARS_NOCASE_CP1251

//
#define CHARS_DIGITS_CP1251 ""

// ‚„…†‡‰‹‘’“”•–—›«·»
#define CHARS_PUNCTUATION_CP1251 "\x82\x84\x85\x86\x87\x89\x8B\x91\x92\x93\x94\x95\x96\x97\x9B\xAB\xB7\xBB"

// €™¤¦§©¬­®°±¶№
#define CHARS_SPECIALS_CP1251 "\x88\x99\xA4\xA6\xA7\xA9\xAC\xAD\xAE\xB0\xB1\xB6\xB9"

// ЂЃѓЉЊЌЋЏђљњќћџЎўЈҐЁЄЇІіґµёєјЅѕїАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя
#define CHARS_ALPHA_CP1251 \
	"\x80\x81\x83\x8A\x8C\x8D\x8E\x8F\x90\x9A\x9C\x9D\x9E\x9F\xA1\xA2\xA3\xA5\xA8\xAA\xAF\xB2\xB3\xB4\xB5\xB8\xBA\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

#define CHARS_WHITESPACE_CP1251 "\xA0"

#define CHARS_CONTROL_CP1251

#define CHARS_INVALID_CP1251 "\x98"

// YyЎўЁЄЇІіёєїАЕИЙОУЫЭЮЯаеийоуыэюя
#define CHARS_VOWELS_CP1251 \
	"\x59\x79\xA1\xA2\xA8\xAA\xAF\xB2\xB3\xB8\xBA\xBF\xC0\xC5\xC8\xC9\xCE\xD3\xDB\xDD\xDE\xDF\xE0\xE5\xE8\xE9\xEE\xF3\xFB\xFD\xFE\xFF"

// ЂЃѓЉЊЌЋЏђљњќћџЈҐґµјЅѕБВГДЖЗКЛМНПРСТФХЦЧШЩЪЬбвгджзклмнпрстфхцчшщъь
#define CHARS_CONSONANTS_CP1251 \
	"\x80\x81\x83\x8A\x8C\x8D\x8E\x8F\x90\x9A\x9C\x9D\x9E\x9F\xA3\xA5\xB4\xB5\xBC\xBD\xBE\xC1\xC2\xC3\xC4\xC6\xC7\xCA\xCB\xCC\xCD\xCF\xD0\xD1\xD2\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDC\xE1\xE2\xE3\xE4\xE6\xE7\xEA\xEB\xEC\xED\xEF\xF0\xF1\xF2\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFC"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// €�‚ƒ„…†‡ˆ‰Š‹Œ�Ž��‘’“”•–—˜™š›œ�žŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ

// here is the CP1252 to Unicode conversion for CP1252 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP1252_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x20AC,0x0081,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,0x02C6,0x2030,0x0160,0x2039,0x0152,0x008D,0x017D,0x008F,
0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x02DC,0x2122,0x0161,0x203A,0x0153,0x009D,0x017E,0x0178,
0x00A0,0x00A1,0x00A2,0x00A3,0x00A4,0x00A5,0x00A6,0x00A7,0x00A8,0x00A9,0x00AA,0x00AB,0x00AC,0x00AD,0x00AE,0x00AF,
0x00B0,0x00B1,0x00B2,0x00B3,0x00B4,0x00B5,0x00B6,0x00B7,0x00B8,0x00B9,0x00BA,0x00BB,0x00BC,0x00BD,0x00BE,0x00BF,
0x00C0,0x00C1,0x00C2,0x00C3,0x00C4,0x00C5,0x00C6,0x00C7,0x00C8,0x00C9,0x00CA,0x00CB,0x00CC,0x00CD,0x00CE,0x00CF,
0x00D0,0x00D1,0x00D2,0x00D3,0x00D4,0x00D5,0x00D6,0x00D7,0x00D8,0x00D9,0x00DA,0x00DB,0x00DC,0x00DD,0x00DE,0x00DF,
0x00E0,0x00E1,0x00E2,0x00E3,0x00E4,0x00E5,0x00E6,0x00E7,0x00E8,0x00E9,0x00EA,0x00EB,0x00EC,0x00ED,0x00EE,0x00EF,
0x00F0,0x00F1,0x00F2,0x00F3,0x00F4,0x00F5,0x00F6,0x00F7,0x00F8,0x00F9,0x00FA,0x00FB,0x00FC,0x00FD,0x00FE,0x00FF }
#endif
;
// *** WARNING, char at 0xDF U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion

// šœžàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ
#define CHARS_LOWER_CP1252 \
	"\x9A\x9C\x9E\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

// ƒªµºß
#define CHARS_LOW_ONLY_CP1252 "\x83\xAA\xB5\xBA\xDF"

// ŠŒŽÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞŸ
#define CHARS_UPPER_CP1252 \
	"\x8A\x8C\x8E\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\x9F"

//
#define CHARS_UP_ONLY_CP1252

//
#define CHARS_NOCASE_CP1252

// ²³¹¼½¾
#define CHARS_DIGITS_CP1252 "\xB2\xB3\xB9\xBC\xBD\xBE"

// ‚„…†‡‰‹‘’“”•–—›¡«·»¿
#define CHARS_PUNCTUATION_CP1252 "\x82\x84\x85\x86\x87\x89\x8B\x91\x92\x93\x94\x95\x96\x97\x9B\xA1\xAB\xB7\xBB\xBF"

// €ˆ˜™¢£¤¥¦§¨©¬­®¯°±´¶¸×÷
#define CHARS_SPECIALS_CP1252 \
	"\x80\x88\x98\x99\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAC\xAD\xAE\xAF\xB0\xB1\xB4\xB6\xB8\xD7\xF7"

// ƒŠŒŽšœžŸªµºÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ
#define CHARS_ALPHA_CP1252 \
	"\x83\x8A\x8C\x8E\x9A\x9C\x9E\x9F\xAA\xB5\xBA\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

#define CHARS_WHITESPACE_CP1252 "\xA0"

#define CHARS_CONTROL_CP1252

#define CHARS_INVALID_CP1252 "\x81\x8D\x8F\x90\x9D"

// YyŒœŸÀÁÂÃÄÅÆÈÉÊËÌÍÎÏÒÓÔÕÖØÙÚÛÜÝàáâãäåæèéêëìíîïòóôõöøùúûüýÿ
#define CHARS_VOWELS_CP1252 \
	"\x59\x79\x8C\x9C\x9F\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFF"

// ƒŠŽšžŸªµºÇÐÑÝÞßçðñýþÿ
#define CHARS_CONSONANTS_CP1252 \
	"\x83\x8A\x8E\x9A\x9E\x9F\xAA\xB5\xBA\xC7\xD0\xD1\xDD\xDE\xDF\xE7\xF0\xF1\xFD\xFE\xFF"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// €�‚ƒ„…†‡�‰�‹�����‘’“”•–—�™�›���� ΅Ά£¤¥¦§¨©�«¬­®―°±²³΄µ¶·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�

// here is the CP1253 to Unicode conversion for CP1253 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP1253_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x20AC,0x0081,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,0x0088,0x2030,0x008A,0x2039,0x008C,0x008D,0x008E,0x008F,
0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x0098,0x2122,0x009A,0x203A,0x009C,0x009D,0x009E,0x009F,
0x00A0,0x0385,0x0386,0x00A3,0x00A4,0x00A5,0x00A6,0x00A7,0x00A8,0x00A9,0x00AA,0x00AB,0x00AC,0x00AD,0x00AE,0x2015,
0x00B0,0x00B1,0x00B2,0x00B3,0x0384,0x00B5,0x00B6,0x00B7,0x0388,0x0389,0x038A,0x00BB,0x038C,0x00BD,0x038E,0x038F,
0x0390,0x0391,0x0392,0x0393,0x0394,0x0395,0x0396,0x0397,0x0398,0x0399,0x039A,0x039B,0x039C,0x039D,0x039E,0x039F,
0x03A0,0x03A1,0x00D2,0x03A3,0x03A4,0x03A5,0x03A6,0x03A7,0x03A8,0x03A9,0x03AA,0x03AB,0x03AC,0x03AD,0x03AE,0x03AF,
0x03B0,0x03B1,0x03B2,0x03B3,0x03B4,0x03B5,0x03B6,0x03B7,0x03B8,0x03B9,0x03BA,0x03BB,0x03BC,0x03BD,0x03BE,0x03BF,
0x03C0,0x03C1,0x03C2,0x03C3,0x03C4,0x03C5,0x03C6,0x03C7,0x03C8,0x03C9,0x03CA,0x03CB,0x03CC,0x03CD,0x03CE,0x00FF }
#endif
;
// *** WARNING, char at 0xC0 U+0390 (ΐ -> Ϊ́) needs to be looked into.  Single to multi-byte conversion
// *** WARNING, char at 0xE0 U+03B0 (ΰ -> Ϋ́) needs to be looked into.  Single to multi-byte conversion

// µάέήίαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ
#define CHARS_LOWER_CP1253 \
	"\xB5\xDC\xDD\xDE\xDF\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

// ƒΐΰ
#define CHARS_LOW_ONLY_CP1253 "\x83\xC0\xE0"

// ΜΆΈΉΊΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΣΤΥΦΧΨΩΪΫΌΎΏ
#define CHARS_UPPER_CP1253 \
	"\xCC\xA2\xB8\xB9\xBA\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD3\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xBC\xBE\xBF"

//
#define CHARS_UP_ONLY_CP1253

//
#define CHARS_NOCASE_CP1253

// ²³½
#define CHARS_DIGITS_CP1253 "\xB2\xB3\xBD"

// ‚„…†‡‰‹‘’“”•–—›«―·»
#define CHARS_PUNCTUATION_CP1253 "\x82\x84\x85\x86\x87\x89\x8B\x91\x92\x93\x94\x95\x96\x97\x9B\xAB\xAF\xB7\xBB"

// €™΅£¤¥¦§¨©¬­®°±΄¶
#define CHARS_SPECIALS_CP1253 "\x80\x99\xA1\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAC\xAD\xAE\xB0\xB1\xB4\xB6"

// ƒΆµΈΉΊΌΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ
#define CHARS_ALPHA_CP1253 \
	"\x83\xA2\xB5\xB8\xB9\xBA\xBC\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE"

#define CHARS_WHITESPACE_CP1253 "\xA0"

#define CHARS_CONTROL_CP1253

#define CHARS_INVALID_CP1253 "\x81\x88\x8A\x8C\x8D\x8E\x8F\x90\x98\x9A\x9C\x9D\x9E\x9F\xAA\xD2\xFF"

// YyΆΈΉΊΌΎΏΐΑΕΗΙΟΥΩΪΫάέήίΰαεηιουωϊϋόύώ
#define CHARS_VOWELS_CP1253 \
	"\x59\x79\xA2\xB8\xB9\xBA\xBC\xBE\xBF\xC0\xC1\xC5\xC7\xC9\xCF\xD5\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE5\xE7\xE9\xEF\xF5\xF9\xFA\xFB\xFC\xFD\xFE"

// ƒµΒΓΔΖΘΚΛΜΝΞΠΡΣΤΦΧΨβγδζθκλμνξπρςστφχψ
#define CHARS_CONSONANTS_CP1253 \
	"\x83\xB5\xC2\xC3\xC4\xC6\xC8\xCA\xCB\xCC\xCD\xCE\xD0\xD1\xD3\xD4\xD6\xD7\xD8\xE2\xE3\xE4\xE6\xE8\xEA\xEB\xEC\xED\xEE\xF0\xF1\xF2\xF3\xF4\xF6\xF7\xF8"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// €�‚ƒ„…†‡ˆ‰Š‹Œ����‘’“”•–—˜™š›œ��Ÿ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞßàáâãäåæçèéêëìíîïğñòóôõö÷øùúûüışÿ

// here is the CP1254 to Unicode conversion for CP1254 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP1254_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x20AC,0x0081,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,0x02C6,0x2030,0x0160,0x2039,0x0152,0x008D,0x008E,0x008F,
0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x02DC,0x2122,0x0161,0x203A,0x0153,0x009D,0x009E,0x0178,
0x00A0,0x00A1,0x00A2,0x00A3,0x00A4,0x00A5,0x00A6,0x00A7,0x00A8,0x00A9,0x00AA,0x00AB,0x00AC,0x00AD,0x00AE,0x00AF,
0x00B0,0x00B1,0x00B2,0x00B3,0x00B4,0x00B5,0x00B6,0x00B7,0x00B8,0x00B9,0x00BA,0x00BB,0x00BC,0x00BD,0x00BE,0x00BF,
0x00C0,0x00C1,0x00C2,0x00C3,0x00C4,0x00C5,0x00C6,0x00C7,0x00C8,0x00C9,0x00CA,0x00CB,0x00CC,0x00CD,0x00CE,0x00CF,
0x011E,0x00D1,0x00D2,0x00D3,0x00D4,0x00D5,0x00D6,0x00D7,0x00D8,0x00D9,0x00DA,0x00DB,0x00DC,0x0130,0x015E,0x00DF,
0x00E0,0x00E1,0x00E2,0x00E3,0x00E4,0x00E5,0x00E6,0x00E7,0x00E8,0x00E9,0x00EA,0x00EB,0x00EC,0x00ED,0x00EE,0x00EF,
0x011F,0x00F1,0x00F2,0x00F3,0x00F4,0x00F5,0x00F6,0x00F7,0x00F8,0x00F9,0x00FA,0x00FB,0x00FC,0x0131,0x015F,0x00FF }
#endif
;
// *** WARNING, char at 0xDF U+00DF (ß -> SS) needs to be looked into.  Single to multi-byte conversion
// *** WARNING, char at 0xFD -> U+0131 -> U+0049 -> 0x49 (ı -> I) needs to be looked into.  Likely one way casing conversion

// šœàáâãäåæçèéêëìíîïğñòóôõöøùúûüşÿ
#define CHARS_LOWER_CP1254 \
	"\x9A\x9C\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFE\xFF"

// ƒªµºßı
#define CHARS_LOW_ONLY_CP1254 "\x83\xAA\xB5\xBA\xDF\xFD"

// ŠŒÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖØÙÚÛÜŞŸ
#define CHARS_UPPER_CP1254 \
	"\x8A\x8C\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDE\x9F"

//
#define CHARS_UP_ONLY_CP1254

//
#define CHARS_NOCASE_CP1254

// ²³¹¼½¾
#define CHARS_DIGITS_CP1254 "\xB2\xB3\xB9\xBC\xBD\xBE"

// ‚„…†‡‰‹‘’“”•–—›¡«·»¿
#define CHARS_PUNCTUATION_CP1254 "\x82\x84\x85\x86\x87\x89\x8B\x91\x92\x93\x94\x95\x96\x97\x9B\xA1\xAB\xB7\xBB\xBF"

// €ˆ˜™¢£¤¥¦§¨©¬­®¯°±´¶¸×÷
#define CHARS_SPECIALS_CP1254 \
	"\x80\x88\x98\x99\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAC\xAD\xAE\xAF\xB0\xB1\xB4\xB6\xB8\xD7\xF7"

// ƒŠŒšœŸªµºÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖØÙÚÛÜİŞßàáâãäåæçèéêëìíîïğñòóôõöøùúûüışÿ
#define CHARS_ALPHA_CP1254 \
	"\x83\x8A\x8C\x9A\x9C\x9F\xAA\xB5\xBA\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

#define CHARS_WHITESPACE_CP1254 "\xA0"

#define CHARS_CONTROL_CP1254

#define CHARS_INVALID_CP1254 "\x81\x8D\x8E\x8F\x90\x9D\x9E"

// YyŒœŸÀÁÂÃÄÅÆÈÉÊËÌÍÎÏÒÓÔÕÖØÙÚÛÜİàáâãäåæèéêëìíîïòóôõöøùúûüıÿ
#define CHARS_VOWELS_CP1254 \
	"\x59\x79\x8C\x9C\x9F\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDC\xDD\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF2\xF3\xF4\xF5\xF6\xF8\xF9\xFA\xFB\xFC\xFD\xFF"

// ƒŠšŸªµºÇĞÑŞßçğñşÿ
#define CHARS_CONSONANTS_CP1254 "\x83\x8A\x9A\x9F\xAA\xB5\xBA\xC7\xD0\xD1\xDE\xDF\xE7\xF0\xF1\xFE\xFF"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// €�‚ƒ„…†‡ˆ‰�‹�����‘’“”•–—˜™�›���� ¡¢£₪¥¦§¨©×«¬­®¯°±²³´µ¶·¸¹÷»¼½¾¿ְֱֲֳִֵֶַָֹ�ֻּֽ־ֿ׀ׁׂ׃װױײ׳״�������אבגדהוזחטיךכלםמןנסעףפץצקרשת��‎‏�

// here is the CP1255 to Unicode conversion for CP1255 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP1255_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x20AC,0x0081,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,0x02C6,0x2030,0x008A,0x2039,0x008C,0x008D,0x008E,0x008F,
0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x02DC,0x2122,0x009A,0x203A,0x009C,0x009D,0x009E,0x009F,
0x00A0,0x00A1,0x00A2,0x00A3,0x20AA,0x00A5,0x00A6,0x00A7,0x00A8,0x00A9,0x00D7,0x00AB,0x00AC,0x00AD,0x00AE,0x00AF,
0x00B0,0x00B1,0x00B2,0x00B3,0x00B4,0x00B5,0x00B6,0x00B7,0x00B8,0x00B9,0x00F7,0x00BB,0x00BC,0x00BD,0x00BE,0x00BF,
0x05B0,0x05B1,0x05B2,0x05B3,0x05B4,0x05B5,0x05B6,0x05B7,0x05B8,0x05B9,0x00CA,0x05BB,0x05BC,0x05BD,0x05BE,0x05BF,
0x05C0,0x05C1,0x05C2,0x05C3,0x05F0,0x05F1,0x05F2,0x05F3,0x05F4,0x00D9,0x00DA,0x00DB,0x00DC,0x00DD,0x00DE,0x00DF,
0x05D0,0x05D1,0x05D2,0x05D3,0x05D4,0x05D5,0x05D6,0x05D7,0x05D8,0x05D9,0x05DA,0x05DB,0x05DC,0x05DD,0x05DE,0x05DF,
0x05E0,0x05E1,0x05E2,0x05E3,0x05E4,0x05E5,0x05E6,0x05E7,0x05E8,0x05E9,0x05EA,0x00FB,0x00FC,0x200E,0x200F,0x00FF }
#endif
;

//
#define CHARS_LOWER_CP1255 ""

// ƒµ
#define CHARS_LOW_ONLY_CP1255 "\x83\xB5"

//
#define CHARS_UPPER_CP1255 ""

//
#define CHARS_UP_ONLY_CP1255

// װױײאבגדהוזחטיךכלםמןנסעףפץצקרשת
#define CHARS_NOCASE_CP1255 \
	"\xD4\xD5\xD6\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA"

// ²³¹¼½¾
#define CHARS_DIGITS_CP1255 "\xB2\xB3\xB9\xBC\xBD\xBE"

// ‚„…†‡‰‹‘’“”•–—›¡«·»¿־׀׃׳״
#define CHARS_PUNCTUATION_CP1255 \
	"\x82\x84\x85\x86\x87\x89\x8B\x91\x92\x93\x94\x95\x96\x97\x9B\xA1\xAB\xB7\xBB\xBF\xCE\xD0\xD3\xD7\xD8"

// €ˆ˜™¢£₪¥¦§¨©×¬­®¯°±´¶¸÷ְֱֲֳִֵֶַָֹֻּֽֿׁׂ‎‏
#define CHARS_SPECIALS_CP1255 \
	"\x80\x88\x98\x99\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAC\xAD\xAE\xAF\xB0\xB1\xB4\xB6\xB8\xBA\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCB\xCC\xCD\xCF\xD1\xD2\xFD\xFE"

// ƒµװױײאבגדהוזחטיךכלםמןנסעףפץצקרשת
#define CHARS_ALPHA_CP1255 \
	"\x83\xB5\xD4\xD5\xD6\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA"

#define CHARS_WHITESPACE_CP1255 "\xA0"

#define CHARS_CONTROL_CP1255

#define CHARS_INVALID_CP1255 \
	"\x81\x8A\x8C\x8D\x8E\x8F\x90\x9A\x9C\x9D\x9E\x9F\xCA\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xFB\xFC\xFF"

// Yy
#define CHARS_VOWELS_CP1255 "\x59\x79"

// ƒµװױײאבגדהוזחטיךכלםמןנסעףפץצקרשת
#define CHARS_CONSONANTS_CP1255 \
	"\x83\xB5\xD4\xD5\xD6\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA"

// 8               9               A               B               C               D               E               F
// 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// €پ‚ƒ„…†‡ˆ‰ٹ‹Œچژڈگ‘’“”•–—ک™ڑ›œ‌‍ں ،¢£¤¥¦§¨©ھ«¬­®¯°±²³´µ¶·¸¹؛»¼½¾؟ہءآأؤإئابةتثجحخدذرزسشصض×طظعغـفقكàلâمنهوçèéêëىيîïًٌٍَôُِ÷ّùْûü‎‏ے

// here is the CP1256 to Unicode conversion for CP1256 characters from 0x80 to 0xFF
EXTATIC const UTF16 CP1256_to_unicode_high128[]
#if JTR_UNICODE_C
= {
0x20AC,0x067E,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,0x02C6,0x2030,0x0679,0x2039,0x0152,0x0686,0x0698,0x0688,
0x06AF,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x06A9,0x2122,0x0691,0x203A,0x0153,0x200C,0x200D,0x06BA,
0x00A0,0x060C,0x00A2,0x00A3,0x00A4,0x00A5,0x00A6,0x00A7,0x00A8,0x00A9,0x06BE,0x00AB,0x00AC,0x00AD,0x00AE,0x00AF,
0x00B0,0x00B1,0x00B2,0x00B3,0x00B4,0x00B5,0x00B6,0x00B7,0x00B8,0x00B9,0x061B,0x00BB,0x00BC,0x00BD,0x00BE,0x061F,
0x06C1,0x0621,0x0622,0x0623,0x0624,0x0625,0x0626,0x0627,0x0628,0x0629,0x062A,0x062B,0x062C,0x062D,0x062E,0x062F,
0x0630,0x0631,0x0632,0x0633,0x0634,0x0635,0x0636,0x00D7,0x0637,0x0638,0x0639,0x063A,0x0640,0x0641,0x0642,0x0643,
0x00E0,0x0644,0x00E2,0x0645,0x0646,0x0647,0x0648,0x00E7,0x00E8,0x00E9,0x00EA,0x00EB,0x0649,0x064A,0x00EE,0x00EF,
0x064B,0x064C,0x064D,0x064E,0x00F4,0x064F,0x0650,0x00F7,0x0651,0x00F9,0x0652,0x00FB,0x00FC,0x200E,0x200F,0x06D2 }
#endif
;

// œ
#define CHARS_LOWER_CP1256 "\x9C"

// ƒµàâçèéêëîïôùûü
#define CHARS_LOW_ONLY_CP1256 "\x83\xB5\xE0\xE2\xE7\xE8\xE9\xEA\xEB\xEE\xEF\xF4\xF9\xFB\xFC"

// Œ
#define CHARS_UPPER_CP1256 "\x8C"

//
#define CHARS_UP_ONLY_CP1256

// پٹچژڈگکڑںھہءآأؤإئابةتثجحخدذرزسشصضطظعغفقكلمنهوىيے
#define CHARS_NOCASE_CP1256 \
	"\x81\x8A\x8D\x8E\x8F\x90\x98\x9A\x9F\xAA\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDD\xDE\xDF\xE1\xE3\xE4\xE5\xE6\xEC\xED\xFF"

// ²³¹¼½¾
#define CHARS_DIGITS_CP1256 "\xB2\xB3\xB9\xBC\xBD\xBE"

// ‚„…†‡‰‹‘’“”•–—›،«·؛»؟
#define CHARS_PUNCTUATION_CP1256 \
	"\x82\x84\x85\x86\x87\x89\x8B\x91\x92\x93\x94\x95\x96\x97\x9B\xA1\xAB\xB7\xBA\xBB\xBF"

// €ˆ™‌‍¢£¤¥¦§¨©¬­®¯°±´¶¸×ـًٌٍَُِ÷ّْ‎‏
#define CHARS_SPECIALS_CP1256 \
	"\x80\x88\x99\x9D\x9E\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAC\xAD\xAE\xAF\xB0\xB1\xB4\xB6\xB8\xD7\xDC\xF0\xF1\xF2\xF3\xF5\xF6\xF7\xF8\xFA\xFD\xFE"

// پƒٹŒچژڈگکڑœںھµہءآأؤإئابةتثجحخدذرزسشصضطظعغفقكàلâمنهوçèéêëىيîïôùûüے
#define CHARS_ALPHA_CP1256 \
	"\x81\x83\x8A\x8C\x8D\x8E\x8F\x90\x98\x9A\x9C\x9F\xAA\xB5\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF4\xF9\xFB\xFC\xFF"

#define CHARS_WHITESPACE_CP1256 "\xA0"

#define CHARS_CONTROL_CP1256

#define CHARS_INVALID_CP1256 ""

// YyŒœàâèéêëîïôùûü
#define CHARS_VOWELS_CP1256 "\x59\x79\x8C\x9C\xE0\xE2\xE8\xE9\xEA\xEB\xEE\xEF\xF4\xF9\xFB\xFC"

// پƒٹچژڈگکڑںھµہءآأؤإئابةتثجحخدذرزسشصضطظعغفقكلمنهوçىيے
#define CHARS_CONSONANTS_CP1256 \
	"\x81\x83\x8A\x8D\x8E\x8F\x90\x98\x9A\x9F\xAA\xB5\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD8\xD9\xDA\xDB\xDD\xDE\xDF\xE1\xE3\xE4\xE5\xE6\xE7\xEC\xED\xFF"

// ----8<------8<---- END OF AUTO-GENERATED DATA ----8<------8<----

#endif // __ENCODING_DATA_H__
