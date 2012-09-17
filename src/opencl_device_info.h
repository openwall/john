/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef OPENCL_DEVICE_INFO_H
#define	OPENCL_DEVICE_INFO_H

//Copied from common-opencl.h
#define UNKNOWN                 0
#define CPU                     1
#define GPU                     2
#define ACCELERATOR             4
#define AMD                     64
#define NVIDIA                  128
#define INTEL                   256
#define APPLE                   512
#define AMD_GCN                 1024
#define AMD_VLIW4               2048
#define AMD_VLIW5               4096
#define NO_BYTE_ADDRESSABLE     8192

#define cpu(n)                  ((n & CPU) == (CPU))
#define gpu(n)                  ((n & GPU) == (GPU))
#define gpu_amd(n)              ((n & AMD) && gpu(n))
#define gpu_nvidia(n)           ((n & NVIDIA) && gpu(n))
#define gpu_intel(n)            ((n & INTEL) && gpu(n))
#define cpu_amd(n)              ((n & AMD) && cpu(n))
#define amd_gcn(n)              ((n & AMD_GCN) && gpu_amd(n))
#define amd_vliw4(n)            ((n & AMD_VLIW4) && gpu_amd(n))
#define amd_vliw5(n)            ((n & AMD_VLIW5) && gpu_amd(n))
#define no_byte_addressable(n)  (n & NO_BYTE_ADDRESSABLE)

#endif	/* OPENCL_DEVICE_INFO_H */

