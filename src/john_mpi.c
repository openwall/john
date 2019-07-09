#ifdef HAVE_MPI

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif

#include "john_mpi.h"
#include "john.h"
#include "memory.h"

int mpi_p_local, mpi_p, mpi_id;
char mpi_name[MPI_MAX_PROCESSOR_NAME + 1];
MPI_Request **mpi_req;

void mpi_teardown(void)
{
	static int finalized = 0;

	if (finalized++)
		return;

	if (mpi_p > 1) {
		/* Some MPI platforms hang on 100% CPU while waiting */
		if (nice(19) == -1)
			perror("nice");
#if MPI_DEBUG
		fprintf(stderr, "Node %u reached %s barrier\n", mpi_id + 1, __FUNCTION__);
#endif
		MPI_Barrier(MPI_COMM_WORLD);
	}

	MPI_Finalize();
}

void mpi_setup(int argc, char **argv)
{
	int namesize;
	char *e;

	MPI_Init(&argc, &argv);

	if ((e = getenv("OMPI_COMM_WORLD_LOCAL_SIZE")))
		mpi_p_local = atoi(e);

	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_id);
	MPI_Comm_size(MPI_COMM_WORLD, &mpi_p);
	john_main_process = !mpi_id;
	MPI_Get_processor_name(mpi_name, &namesize);

	mpi_req = mem_calloc_tiny(sizeof(MPI_Request*) * mpi_p, MEM_ALIGN_WORD);

	atexit(mpi_teardown);
}

#endif /* HAVE_MPI */
