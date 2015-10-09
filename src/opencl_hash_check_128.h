#include "bt_interface.h"

extern cl_uint num_loaded_hashes;
extern cl_uint *loaded_hashes;
extern cl_uint *hash_ids;
extern OFFSET_TABLE_WORD *offset_table;
extern unsigned int hash_table_size, offset_table_size;
extern cl_ulong bitmap_size_bits;
extern cl_uint *bitmaps;

extern void opencl_hash_check_128_init(struct fmt_main *_self);
extern void prepare_table(struct db_salt *salt);
extern char* select_bitmap(unsigned int num_ld_hashes);
extern int cmp_all(void *binary, int count);
extern int cmp_one(void *binary, int index);
extern int cmp_exact(char *source, int index);
