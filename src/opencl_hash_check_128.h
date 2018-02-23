#include "bt_interface.h"
#include "opencl_common.h"

extern cl_uint num_loaded_hashes;
extern cl_uint *hash_ids;
extern unsigned int hash_table_size_128, offset_table_size;

extern void ocl_hc_128_init(struct fmt_main *_self);
extern void ocl_hc_128_prepare_table(struct db_salt *salt);
extern void ocl_hc_128_prepare_table_test(void);
extern char* ocl_hc_128_select_bitmap(unsigned int num_ld_hashes);
extern int ocl_hc_128_extract_info(struct db_salt *, void (*)(void), void (*)(void), void (*)(unsigned int, char *), size_t, size_t *, int *);
extern void ocl_hc_128_crobj(cl_kernel kernel);
extern void ocl_hc_128_rlobj(void);
extern int ocl_hc_128_cmp_all(void *binary, int count);
extern int ocl_hc_128_cmp_one(void *binary, int index);
extern int ocl_hc_128_cmp_exact(char *source, int index);
