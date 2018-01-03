/*
 * This software is Copyright (c) 2018 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifndef _HAVE_OMP_AUTOTUNE_H
#define _HAVE_OMP_AUTOTUNE_H

extern void omp_autotune_init(void);
extern int omp_autotune(struct fmt_main *format, int preset);
extern void omp_autotune_run(struct db_main *db);

#endif /* _HAVE_OMP_AUTOTUNE_H */
