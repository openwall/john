#ifndef JOHN_MPI_INCLUDE
#define JOHN_MPI_INCLUDE

#if HAVE_MPI

#include <mpi.h>

#define JOHN_MPI_RELOAD	1

extern int mpi_p_local, mpi_p, mpi_id;
extern char mpi_name[MPI_MAX_PROCESSOR_NAME + 1];
extern MPI_Request **mpi_req;

/* MPI tear down */
extern void mpi_teardown(void);

/* MPI initialization stuff, registers atexit() as well */
extern void mpi_setup(int argc, char **argv);

#endif /* HAVE_MPI */
#endif /* JOHN_MPI_INCLUDE */
