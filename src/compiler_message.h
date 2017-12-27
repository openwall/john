/*
 * This file is part of John the Ripper password cracker.
 *
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2017
 *
 * Copyright (c) 2017 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _JTR_CC_MESSAGE_H
#define _JTR_CC_MESSAGE_H

#if __GNUC__ && GCC_VERSION >= 40201	// 4.2.1
#pragma message JTR_CC_MESSAGE
#elif _MSC_VER
#pragma message(JTR_CC_MESSAGE)
#else
#warning JTR_CC_MESSAGE
#endif

#endif /* _JTR_CC_MESSAGE_H */
