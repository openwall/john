/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "common-opencl.h"
#include "opencl_sha2_common.h"

//Allow me to have a configurable step size.
int get_next_gws_size(size_t num, int step, int startup, int default_value) {

    if (startup) {

        if (step == 0)
            return GET_MULTIPLE(default_value, local_work_size);
        else
            return GET_MULTIPLE(step, local_work_size);
    }

    if (step < 1)
        return num * 2;

    return num + step;
}