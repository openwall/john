//-------------------------------------------------------------------------------------
// JtR OpenCL format to crack hashes from argon2.
//
// This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
// is hereby released to the general public under the following terms:
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.
//-------------------------------------------------------------------------------------

#define ARGON2_D  0
#define ARGON2_I  1
#define ARGON2_ID 2


#define ARGON2_TYPE ARGON2_D
#include "argon2_kernel.cl"


#define ONLY_KERNEL_DEFINITION
#undef ARGON2_TYPE
#define ARGON2_TYPE ARGON2_I
#include "argon2_kernel.cl"


// #undef ARGON2_TYPE
// #define ARGON2_TYPE ARGON2_ID
// #include "argon2_kernel.cl"