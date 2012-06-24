#include "john-mpi.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef _OPENMP
#include <omp.h>
#endif

int mpi_p, mpi_id, namesize;
char mpi_name[MPI_MAX_PROCESSOR_NAME + 1];

/* Fixed version of id2string to correct a memory leak
 * Submitted by Carsten G
 */
char *id2string() {
	static char id_string[12] = "";
	if (strlen(id_string)) return id_string;
	snprintf(id_string, 11, "%d", mpi_id);
	id_string[11] = 0x00;
	return id_string;
}

void mpi_teardown(void){
	if (nice(20) < 0) fprintf(stderr, "nice() failed\n");
	MPI_Finalize();
}

void mpi_setup(int argc, char **argv) {
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_id);
	MPI_Comm_size(MPI_COMM_WORLD, &mpi_p);
	MPI_Get_processor_name(mpi_name, &namesize);
	if (mpi_id != 0)
		close(1);
	atexit(mpi_teardown);
}
