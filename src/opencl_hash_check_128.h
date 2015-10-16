#include "bt_interface.h"
#include "common-opencl.h"

extern cl_uint num_loaded_hashes;
extern cl_uint *loaded_hashes;
extern cl_uint *hash_ids;
extern OFFSET_TABLE_WORD *offset_table;
extern unsigned int hash_table_size_128, offset_table_size;
extern cl_ulong bitmap_size_bits;
extern cl_uint *bitmaps;
extern cl_uint *zero_buffer;
extern cl_mem buffer_offset_table, buffer_hash_table, buffer_return_hashes, buffer_hash_ids, buffer_bitmap_dupe, buffer_bitmaps;

extern void ocl_hc_128_init(struct fmt_main *_self);
extern void ocl_hc_128_prepare_table(struct db_salt *salt);
extern void ocl_hc_128_prepare_table_test(void);
extern char* ocl_hc_128_select_bitmap(unsigned int num_ld_hashes);
extern int ocl_hc_128_extract_info(struct db_salt *, void (*)(void), void (*)(void), void (*)(unsigned int, char *), size_t, size_t *, int *);
extern void ocl_hc_128_crobj(void);
extern void ocl_hc_128_rlobj(void);
extern int ocl_hc_128_cmp_all(void *binary, int count);
extern int ocl_hc_128_cmp_one(void *binary, int index);
extern int ocl_hc_128_cmp_exact(char *source, int index);
