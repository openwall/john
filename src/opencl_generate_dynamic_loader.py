#!/usr/bin/env python3

#-------------------------------------------------------------------------------------
# Dynamic OpenCL library loader.
#
# This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
# is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#-------------------------------------------------------------------------------------

# Import modules
import re

# OpenCL version supported
CL_TARGET_OPENCL_VERSION = 120

opencl_header = open("CL/cl.h")
header_text: str = opencl_header.read()
opencl_header.close()

# Write C file
dynamic_loader = open("opencl_dynamic_loader.c", "w")
dynamic_loader.write(
'''/*
 * Dynamic OpenCL library loader. Automatically generated.
 *
 * This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#ifndef CL_TARGET_OPENCL_VERSION
''')
dynamic_loader.write(f'#define CL_TARGET_OPENCL_VERSION {CL_TARGET_OPENCL_VERSION}')
dynamic_loader.write(
'''
#endif

#include "CL/cl.h"
#include "CL/cl_ext.h"

#include <dlfcn.h>
#include <stdio.h>

/* DLL handle */
static void *opencl_dll;
static void load_opencl_dll(void);

''')

REGEX_C_ID = '[_a-zA-Z][_a-zA-Z0-9]*'
REGEX_ANY_SPACES = '[ \t\n\r]*'
REGEX_SPACES_ONE_OR_MORE = '[ \t\n\r]+'

# Search for all function definitions
funtions = re.findall(
    f"extern CL_API_ENTRY (CL_API_PREFIX__VERSION_[1-9]_[0-9]_DEPRECATED )?({REGEX_C_ID}[ \*]*) CL_API_CALL{REGEX_SPACES_ONE_OR_MORE}({REGEX_C_ID})\(([_a-zA-Z0-9, \t\r\n\*\(\)]*)\) CL_API_SUFFIX__VERSION_([0-9_]+)(_DEPRECATED)?;",
    header_text)

# Handle this special case
special_function_name = "clGetPlatformIDs"
special_function_code = '''load_opencl_dll();

	if (!opencl_dll) {
		/* Our implementation */
		if ((!num_entries && platforms) || (!num_platforms && !platforms))
			return CL_INVALID_VALUE;

		if (num_platforms)
			*num_platforms = 0;

		return CL_SUCCESS;
	}

\t'''

# Declare funtions and pointer to functions
# return_type, function_name, list_params, api_version
for x in funtions:
    if len(x) == 6:
        function_return = x[1]
        function_name = x[2]
        if "Image" in function_name:
            continue
        function_params = " ".join(x[3].split()) # Better param definition
        api_version = int(x[4].replace('_', '')) * 10
        if api_version > CL_TARGET_OPENCL_VERSION:
            print(f"Function '{function_name}' skipped, API {x[4]}")
            continue

        # Begin function
        dynamic_loader.write(f'/* {function_name} */\nstatic {function_return} (*ptr_{function_name})({function_params});\n') # Function pointer definition
        dynamic_loader.write(f'CL_API_ENTRY {function_return} CL_API_CALL {function_name}({function_params})\n') # Function definition
        dynamic_loader.write('{\n\t')

        # If we are in the special case
        if function_name == special_function_name:
            dynamic_loader.write(special_function_code)
        dynamic_loader.write(f'return ptr_{function_name}(') # Function call through pointer

        # Manage params
        function_params = "".join(re.split('\(CL_CALLBACK *', function_params))
        function_params = "".join(re.split('\)\([_a-zA-Z0-9 \*,]+\)', function_params))
        param_names = re.findall(f'(const )?(unsigned )?{REGEX_C_ID}[ \*]+({REGEX_C_ID})', function_params)
        for i in range(len(param_names)):
            dynamic_loader.write(f'{", " if i > 0 else ""}{param_names[i][2]}')

        # End function
        dynamic_loader.write(');\n}\n\n')
    else:
        print("Error parsing CL.h header file")
        exit(1)

# Load dynamic library
dynamic_loader.write(
'''
static cl_int unimplemented_function(void)
{
	return CL_INVALID_OPERATION;
}

static void load_opencl_dll(void)
{
	int i;

	if (opencl_dll)
		return;

	/* Names to try to load */
	const char * const opencl_names[] = {
		"libOpenCL.so",		/* Linux/others, hack via "development" sub-package's symlink */
		"OpenCL",		/* _WIN */
		"/System/Library/Frameworks/OpenCL.framework/OpenCL", /* __APPLE__ */
		"opencl.dll",		/* __CYGWIN__ */
		"cygOpenCL-1.dll",	/* __CYGWIN__ */
		"libOpenCL.so.1"	/* Linux/others, no "development" sub-package installed */
	};

	for (i = 0; i < sizeof(opencl_names)/sizeof(opencl_names[0]); i++) {
		opencl_dll = dlopen(opencl_names[i], RTLD_NOW);
		if (opencl_dll)
			break;
	}

	if (!opencl_dll) {
		puts("Cannot load OpenCL library");
		return;
	}

	/* Load function pointers */
''')

# Load function pointers
for x in funtions:
    function_name = x[2]
    if "Image" in function_name:
        continue
    api_version = int(x[4].replace('_', '')) * 10
    if api_version <= CL_TARGET_OPENCL_VERSION:
        dynamic_loader.write(f'\tptr_{function_name} = dlsym(opencl_dll, "{function_name}");\n')
        dynamic_loader.write(f'\tif (!ptr_{function_name}) {{\n')
        dynamic_loader.write(f'\t\tptr_{function_name} = (void *)unimplemented_function;\n')
        dynamic_loader.write(f'\t\tfprintf(stderr, "Warning: Cannot find the {function_name} function\\n");\n')
        dynamic_loader.write('\t}\n')

dynamic_loader.write('''}

#endif
''')
# End of file
dynamic_loader.close()
