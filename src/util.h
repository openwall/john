/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2020
 *
 * Copyright (c) 2020 Claudio André <claudioandre.br at gmail.com>
 *
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#define FALSE         0
#define TRUE          1

#define OUT_CONSOLE   (1 << 0)
#define OUT_LOG       (1 << 1)
#define OUT_STDOUT    (1 << 2)
#define OUT_STDERR    (1 << 3)

int get_windows_size(int *lines, int *cols);
void log_print(int destination, int verbosity, int main_only, int identation,
        char *format, ...);
