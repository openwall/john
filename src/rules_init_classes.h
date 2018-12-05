	case ISO_8859_2:
		rules_init_class('v', CHARS_VOWELS
		                 CHARS_VOWELS_ISO_8859_2);
		rules_init_class('c', CHARS_CONSONANTS
		                 CHARS_CONSONANTS_ISO_8859_2);
		rules_init_class('w', CHARS_WHITESPACE
		                 CHARS_WHITESPACE_ISO_8859_2);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_ISO_8859_2);
		rules_init_class('s', CHARS_SPECIALS
		                 CHARS_SPECIALS_ISO_8859_2);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_2
		                 CHARS_LOW_ONLY_ISO_8859_2);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_2
		                 CHARS_UP_ONLY_ISO_8859_2);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_2);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_2);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_2 CHARS_DIGITS
		                 CHARS_DIGITS_ISO_8859_2);
		rules_init_class('o', CHARS_CONTROL_ASCII
		                 CHARS_CONTROL_ISO_8859_2);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_2);
		break;
	case ISO_8859_7:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_ISO_8859_7);
		rules_init_class('c', CHARS_CONSONANTS
		                 CHARS_CONSONANTS_ISO_8859_7);
		rules_init_class('w', CHARS_WHITESPACE
		                 CHARS_WHITESPACE_ISO_8859_7);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_ISO_8859_7);
		rules_init_class('s', CHARS_SPECIALS
		                 CHARS_SPECIALS_ISO_8859_7);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_7
		                 CHARS_LOW_ONLY_ISO_8859_7);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_7
		                 CHARS_UP_ONLY_ISO_8859_7);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_7);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_7);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_7 CHARS_DIGITS
		                 CHARS_DIGITS_ISO_8859_7);
		rules_init_class('o', CHARS_CONTROL_ASCII
		                 CHARS_CONTROL_ISO_8859_7);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_7);
		break;
	case ISO_8859_15:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_ISO_8859_15);
		rules_init_class('c', CHARS_CONSONANTS
		                 CHARS_CONSONANTS_ISO_8859_15);
		rules_init_class('w', CHARS_WHITESPACE
		                 CHARS_WHITESPACE_ISO_8859_15);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_ISO_8859_15);
		rules_init_class('s', CHARS_SPECIALS
		                 CHARS_SPECIALS_ISO_8859_15);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_15
		                 CHARS_LOW_ONLY_ISO_8859_15);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_15
		                 CHARS_UP_ONLY_ISO_8859_15);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_15);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_15);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_15 CHARS_DIGITS
		                 CHARS_DIGITS_ISO_8859_15);
		rules_init_class('o', CHARS_CONTROL_ASCII
		                 CHARS_CONTROL_ISO_8859_15);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_15);
		break;
	case KOI8_R:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_KOI8_R);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_KOI8_R);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_KOI8_R);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_KOI8_R);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_KOI8_R);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_KOI8_R
		                 CHARS_LOW_ONLY_KOI8_R);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_KOI8_R
		                 CHARS_UP_ONLY_KOI8_R);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_KOI8_R);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_KOI8_R);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_KOI8_R
		                 CHARS_DIGITS CHARS_DIGITS_KOI8_R);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_KOI8_R);
		rules_init_class('Y', CHARS_INVALID_KOI8_R);
		break;
	case CP437:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP437);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP437);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP437);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP437);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP437);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP437
		                 CHARS_LOW_ONLY_CP437);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP437
		                 CHARS_UP_ONLY_CP437);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP437);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP437);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP437
		                 CHARS_DIGITS CHARS_DIGITS_CP437);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP437);
		rules_init_class('Y', CHARS_INVALID_CP437);
		break;
	case CP720:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP720);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP720);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP720);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP720);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP720);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP720
		                 CHARS_LOW_ONLY_CP720);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP720
		                 CHARS_UP_ONLY_CP720);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP720);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP720);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP720
		                 CHARS_DIGITS CHARS_DIGITS_CP720);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP720);
		rules_init_class('Y', CHARS_INVALID_CP720);
		break;
	case CP737:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP737);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP737);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP737);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP737);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP737);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP737
		                 CHARS_LOW_ONLY_CP737);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP737
		                 CHARS_UP_ONLY_CP737);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP737);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP737);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP737
		                 CHARS_DIGITS CHARS_DIGITS_CP737);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP737);
		rules_init_class('Y', CHARS_INVALID_CP737);
		break;
	case CP850:
		// NOTE, we need to deal with U+0131 (dottless I)
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP850);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP850);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP850);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP850);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP850);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP850
		                 CHARS_LOW_ONLY_CP850);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP850
		                 CHARS_UP_ONLY_CP850);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP850);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP850);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP850 CHARS_DIGITS
		                 CHARS_DIGITS_CP850);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP850);
		rules_init_class('Y', CHARS_INVALID_CP850);
		break;
	case CP852:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP852);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP852);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP852);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP852);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP852);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP852
		                 CHARS_LOW_ONLY_CP852);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP852
		                 CHARS_UP_ONLY_CP852);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP852);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP852);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP852
		                 CHARS_DIGITS CHARS_DIGITS_CP852);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP852);
		rules_init_class('Y', CHARS_INVALID_CP852);
		break;
	case CP858:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP858);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP858);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP858);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP858);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP858);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP858
		                 CHARS_LOW_ONLY_CP858);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP858
		                 CHARS_UP_ONLY_CP858);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP858);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP858);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP858
		                 CHARS_DIGITS CHARS_DIGITS_CP858);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP858);
		rules_init_class('Y', CHARS_INVALID_CP858);
		break;
	case CP866:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP866);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP866);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP866);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP866);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP866);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP866
		                 CHARS_LOW_ONLY_CP866);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP866
		                 CHARS_UP_ONLY_CP866);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP866);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP866);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP866
		                 CHARS_DIGITS CHARS_DIGITS_CP866);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP866);
		rules_init_class('Y', CHARS_INVALID_CP866);
		break;
	case CP868:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP868);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP868);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP868);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP868);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP868);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP868
		                 CHARS_LOW_ONLY_CP868);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP868
		                 CHARS_UP_ONLY_CP868);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP868);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP868);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP868
		                 CHARS_DIGITS CHARS_DIGITS_CP868);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP868);
		rules_init_class('Y', CHARS_INVALID_CP868);
		break;
	case CP1250:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1250);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1250);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1250);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP1250);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1250);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1250
		                 CHARS_LOW_ONLY_CP1250);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1250
		                 CHARS_UP_ONLY_CP1250);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1250);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP1250);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1250
		                 CHARS_DIGITS CHARS_DIGITS_CP1250);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1250);
		rules_init_class('Y', CHARS_INVALID_CP1250);
		break;
	case CP1251:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1251);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1251);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1251);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP1251);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1251);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1251
		                 CHARS_LOW_ONLY_CP1251);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1251
		                 CHARS_UP_ONLY_CP1251);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1251);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP1251);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP1251 CHARS_DIGITS
		                 CHARS_DIGITS_CP1251);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1251);
		rules_init_class('Y', CHARS_INVALID_CP1251);
		break;
	case CP1252:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1252);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1252);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1252);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP1252);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1252);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1252
		                 CHARS_LOW_ONLY_CP1252);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1252
		                 CHARS_UP_ONLY_CP1252);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1252);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP1252);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1252
		                 CHARS_DIGITS CHARS_DIGITS_CP1252);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1252);
		rules_init_class('Y', CHARS_INVALID_CP1252);
		break;
	case CP1253:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1253);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1253);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1253);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_CP1253);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1253);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1253
		                 CHARS_LOW_ONLY_CP1253);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1253
		                 CHARS_UP_ONLY_CP1253);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1253);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_CP1253);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1253
		                 CHARS_DIGITS CHARS_DIGITS_CP1253);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1253);
		rules_init_class('Y', CHARS_INVALID_CP1253);
		break;
	case CP1254:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1254);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1254);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1254);
		rules_init_class('p', CHARS_PUNCTUATION
				 CHARS_PUNCTUATION_CP1254);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1254);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1254
				 CHARS_LOW_ONLY_CP1254);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1254
				 CHARS_UP_ONLY_CP1254);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1254);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
				 CHARS_ALPHA_CP1254);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1254
				 CHARS_DIGITS  CHARS_DIGITS_CP1254);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1254);
		rules_init_class('Y', CHARS_INVALID_CP1254);
		break;
	case CP1255:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1255);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1255);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1255);
		rules_init_class('p', CHARS_PUNCTUATION
				 CHARS_PUNCTUATION_CP1255);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1255);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1255
				 CHARS_LOW_ONLY_CP1255);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1255
				 CHARS_UP_ONLY_CP1255);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1255);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
				 CHARS_ALPHA_CP1255);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1255
				 CHARS_DIGITS  CHARS_DIGITS_CP1255);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1255);
		rules_init_class('Y', CHARS_INVALID_CP1255);
		break;
	case CP1256:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1256);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1256);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1256);
		rules_init_class('p', CHARS_PUNCTUATION
				 CHARS_PUNCTUATION_CP1256);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1256);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1256
				 CHARS_LOW_ONLY_CP1256);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1256
				 CHARS_UP_ONLY_CP1256);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1256);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
				 CHARS_ALPHA_CP1256);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1256
				 CHARS_DIGITS  CHARS_DIGITS_CP1256);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1256);
		rules_init_class('Y', CHARS_INVALID_CP1256);
		break;
