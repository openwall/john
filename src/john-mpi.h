#ifndef JOHN_MPI_INCLUDE
#define JOHN_MPI_INCLUDE

#include <mpi.h>

extern int mpi_p, mpi_id;
extern char mpi_name[MPI_MAX_PROCESSOR_NAME + 1];

/* returns the ascii representation of mpi_id */
extern char *id2string();

/* MPI initialization stuff, registers atexit() as well */
extern void mpi_setup(int argc, char **argv);
extern void mpi_teardown(void);
#endif
