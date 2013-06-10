#ifdef HAVE_MPI

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "john-mpi.h"
#include "john.h"

int mpi_p, mpi_id;
char mpi_name[MPI_MAX_PROCESSOR_NAME + 1];

void mpi_teardown(void)
{
	static int finalized = 0;

	if (finalized++)
		return;

	if (nice(20) < 0)
		fprintf(stderr, "nice() failed\n");

	if (mpi_p > 1)
		MPI_Barrier(MPI_COMM_WORLD);

	MPI_Finalize();
}

void mpi_setup(int argc, char **argv)
{
	int namesize;

	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_id);
	MPI_Comm_size(MPI_COMM_WORLD, &mpi_p);
	john_main_process = !mpi_id;
	MPI_Get_processor_name(mpi_name, &namesize);
	atexit(mpi_teardown);
}

#endif /* HAVE_MPI */
