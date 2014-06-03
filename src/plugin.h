/*
 * Plugin module support.
 */
#ifndef _JOHN_PLUGIN_H
#define _JOHN_PLUGIN_H

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBDL || __MINGW32__ || __MINGW64__ || _MSC_VER

#include "list.h"
#include "formats.h"

typedef void    (*format_register) (struct fmt_main * format);
void
register_dlls(
	struct list_main * dll_list,
	char *config_param,
	format_register register_one);

#endif

#endif
