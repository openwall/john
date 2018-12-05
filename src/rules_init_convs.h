	case ISO_8859_2:
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_2
			CHARS_UPPER_ISO_8859_2;
		conv_tolower = rules_init_conv(CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_2,
		                               CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_2);
		conv_toupper = rules_init_conv(CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_2,
		                               CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_2);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_ISO_8859_2
		                             CHARS_LOWER_ISO_8859_2);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_ISO_8859_2
		                              CHARS_LOWER_ISO_8859_2);
		break;
	case ISO_8859_7:
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_7
			CHARS_UPPER_ISO_8859_7;
		conv_tolower = rules_init_conv(CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_7,
		                               CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_7);
		conv_toupper = rules_init_conv(CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_7,
		                               CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_7);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_ISO_8859_7
		                             CHARS_LOWER_ISO_8859_7);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_ISO_8859_7
		                              CHARS_LOWER_ISO_8859_7);
		break;
	case ISO_8859_15:
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_15
			CHARS_UPPER_ISO_8859_15;
		conv_tolower = rules_init_conv(CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_15,
		                               CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_15);
		conv_toupper = rules_init_conv(CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_15,
		                               CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_15);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_ISO_8859_15
		                             CHARS_LOWER_ISO_8859_15);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_ISO_8859_15
		                              CHARS_LOWER_ISO_8859_15);
		break;
	case KOI8_R:
		conv_source = CONV_SOURCE CHARS_LOWER_KOI8_R CHARS_UPPER_KOI8_R;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_KOI8_R,
		                               CHARS_LOWER CHARS_LOWER_KOI8_R);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_KOI8_R,
		                               CHARS_UPPER CHARS_UPPER_KOI8_R);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_KOI8_R
		                             CHARS_LOWER_KOI8_R);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_KOI8_R
		                              CHARS_LOWER_KOI8_R);
		break;
	case CP437:
		conv_source = CONV_SOURCE CHARS_LOWER_CP437 CHARS_UPPER_CP437;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP437,
		                               CHARS_LOWER CHARS_LOWER_CP437);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP437,
		                               CHARS_UPPER CHARS_UPPER_CP437);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP437
		                             CHARS_LOWER_CP437);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP437
		                              CHARS_LOWER_CP437);
		break;
	case CP720:
		conv_source = CONV_SOURCE CHARS_LOWER_CP720 CHARS_UPPER_CP720;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP720,
		                               CHARS_LOWER CHARS_LOWER_CP720);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP720,
		                               CHARS_UPPER CHARS_UPPER_CP720);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP720
		                             CHARS_LOWER_CP720);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP720
		                              CHARS_LOWER_CP720);
		break;
	case CP737:
		conv_source = CONV_SOURCE CHARS_LOWER_CP737 CHARS_UPPER_CP737;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP737,
		                               CHARS_LOWER CHARS_LOWER_CP737);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP737,
		                               CHARS_UPPER CHARS_UPPER_CP737);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP737
		                             CHARS_LOWER_CP737);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP737
		                              CHARS_LOWER_CP737);
		break;
	case CP850:
		conv_source = CONV_SOURCE CHARS_LOWER_CP850 CHARS_UPPER_CP850;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP850,
		                               CHARS_LOWER CHARS_LOWER_CP850);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP850,
		                               CHARS_UPPER CHARS_UPPER_CP850);
// Ok, we need to handle upcasing of 0xD5. This is U+0131 and upcases to U+0049
// (undotted low i upcases to normal I).
// but there is NO low case into U+131, so we have to handle this, after setup
// of all the 'normal' shit.
		conv_toupper[0xD5] = 0x49;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP850
		                             CHARS_LOWER_CP850);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP850
		                              CHARS_LOWER_CP850);
		break;
	case CP852:
		conv_source = CONV_SOURCE CHARS_LOWER_CP852 CHARS_UPPER_CP852;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP852,
		                               CHARS_LOWER CHARS_LOWER_CP852);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP852,
		                               CHARS_UPPER CHARS_UPPER_CP852);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP852
		                             CHARS_LOWER_CP852);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP852
		                              CHARS_LOWER_CP852);
		break;
	case CP858:
		conv_source = CONV_SOURCE CHARS_LOWER_CP858 CHARS_UPPER_CP858;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP858,
		                               CHARS_LOWER CHARS_LOWER_CP858);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP858,
		                               CHARS_UPPER CHARS_UPPER_CP858);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP858
		                             CHARS_LOWER_CP858);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP858
		                              CHARS_LOWER_CP858);
		break;
	case CP866:
		conv_source = CONV_SOURCE CHARS_LOWER_CP866 CHARS_UPPER_CP866;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP866,
		                               CHARS_LOWER CHARS_LOWER_CP866);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP866,
		                               CHARS_UPPER CHARS_UPPER_CP866);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP866
		                             CHARS_LOWER_CP866);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP866
		                              CHARS_LOWER_CP866);
		break;
	case CP868:
		conv_source = CONV_SOURCE CHARS_LOWER_CP868 CHARS_UPPER_CP868;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP868,
		                               CHARS_LOWER CHARS_LOWER_CP868);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP868,
		                               CHARS_UPPER CHARS_UPPER_CP868);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP868
		                             CHARS_LOWER_CP868);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP868
		                              CHARS_LOWER_CP868);
		break;
	case CP1250:
		conv_source = CONV_SOURCE CHARS_LOWER_CP1250 CHARS_UPPER_CP1250;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1250,
		                               CHARS_LOWER CHARS_LOWER_CP1250);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1250,
		                               CHARS_UPPER CHARS_UPPER_CP1250);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP1250
		                             CHARS_LOWER_CP1250);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP1250
		                              CHARS_LOWER_CP1250);
		break;
	case CP1251:
		conv_source = CONV_SOURCE CHARS_LOWER_CP1251 CHARS_UPPER_CP1251;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1251,
		                               CHARS_LOWER CHARS_LOWER_CP1251);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1251,
		                               CHARS_UPPER CHARS_UPPER_CP1251);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP1251
		                             CHARS_LOWER_CP1251);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP1251
		                              CHARS_LOWER_CP1251);
		break;
	case CP1252:
		conv_source = CONV_SOURCE CHARS_LOWER_CP1252 CHARS_UPPER_CP1252;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1252,
		                               CHARS_LOWER CHARS_LOWER_CP1252);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1252,
		                               CHARS_UPPER CHARS_UPPER_CP1252);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP1252
		                             CHARS_LOWER_CP1252);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP1252
		                              CHARS_LOWER_CP1252);
		break;
	case CP1253:
		conv_source = CONV_SOURCE CHARS_LOWER_CP1253 CHARS_UPPER_CP1253;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1253,
		                               CHARS_LOWER CHARS_LOWER_CP1253);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1253,
		                               CHARS_UPPER CHARS_UPPER_CP1253);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_CP1253
		                             CHARS_LOWER_CP1253);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_CP1253
		                              CHARS_LOWER_CP1253);
		break;
	case CP1254:
		conv_source = CONV_SOURCE CHARS_LOWER_CP1254 CHARS_UPPER_CP1254;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1254,
					       CHARS_LOWER CHARS_LOWER_CP1254);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1254,
					       CHARS_UPPER CHARS_UPPER_CP1254);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
					     CHARS_UPPER_CP1254
					     CHARS_LOWER_CP1254);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
					      CHARS_UPPER_CP1254
					      CHARS_LOWER_CP1254);
		break;
	case CP1255:
		conv_source = CONV_SOURCE CHARS_LOWER_CP1255 CHARS_UPPER_CP1255;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1255,
					       CHARS_LOWER CHARS_LOWER_CP1255);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1255,
					       CHARS_UPPER CHARS_UPPER_CP1255);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
					     CHARS_UPPER_CP1255
					     CHARS_LOWER_CP1255);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
					      CHARS_UPPER_CP1255
					      CHARS_LOWER_CP1255);
		break;
	case CP1256:
		conv_source = CONV_SOURCE CHARS_LOWER_CP1256 CHARS_UPPER_CP1256;
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1256,
					       CHARS_LOWER CHARS_LOWER_CP1256);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1256,
					       CHARS_UPPER CHARS_UPPER_CP1256);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
					     CHARS_UPPER_CP1256
					     CHARS_LOWER_CP1256);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
					      CHARS_UPPER_CP1256
					      CHARS_LOWER_CP1256);
		break;
