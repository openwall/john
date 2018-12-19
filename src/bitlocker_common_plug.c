/*
 * Common code for the BitLocker format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "bitlocker_common.h"
#include "hmac_sha.h"
#include "johnswap.h"

unsigned int bitlocker_common_iteration_count(void *salt)
{
	bitlocker_custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
