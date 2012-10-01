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
#define DEV_UNKNOWN                 0
#define DEV_CPU                     1
#define DEV_GPU                     2
#define DEV_ACCELERATOR             4
#define DEV_AMD                     64
#define DEV_NVIDIA                  128
#define DEV_INTEL                   256
#define DEV_APPLE                   512
#define DEV_AMD_GCN                 1024
#define DEV_AMD_VLIW4               2048
#define DEV_AMD_VLIW5               4096
#define DEV_NO_BYTE_ADDRESSABLE     8192
#define DEV_USE_LOCAL               32768

#define cpu(n)                      ((n & DEV_CPU) == (DEV_CPU))
#define gpu(n)                      ((n & DEV_GPU) == (DEV_GPU))
#define gpu_amd(n)                  ((n & DEV_AMD) && gpu(n))
#define gpu_nvidia(n)               ((n & DEV_NVIDIA) && gpu(n))
#define gpu_intel(n)                ((n & DEV_INTEL) && gpu(n))
#define cpu_amd(n)                  ((n & DEV_AMD) && cpu(n))
#define amd_gcn(n)                  ((n & DEV_AMD_GCN) && gpu_amd(n))
#define amd_vliw4(n)                ((n & DEV_AMD_VLIW4) && gpu_amd(n))
#define amd_vliw5(n)                ((n & DEV_AMD_VLIW5) && gpu_amd(n))
#define no_byte_addressable(n)      ((n & DEV_NO_BYTE_ADDRESSABLE))
#define use_local(n)                ((n & DEV_USE_LOCAL))

#endif	/* OPENCL_DEVICE_INFO_H */

