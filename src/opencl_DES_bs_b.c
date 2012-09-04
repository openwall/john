/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2010,2011 by Solar Designer
 */


#include "opencl_DES_bs.h"

typedef struct{
	
	DES_bs_vector K[56];	/* Keys */
	DES_bs_vector B[64];	/* Data blocks */

	DES_bs_vector zero;	/* All 0 bits */
	DES_bs_vector ones;	/* All 1 bits */
	DES_bs_vector masks[8];	/* Each byte set to 0x01 ... 0x80 */
	
	DES_bs_vector v[8][8];
	
	int keys_changed;
} opencl_DES_bs_transfer ;

opencl_DES_bs_transfer opencl_DES_bs_data[MULTIPLIER];
//#define DES_BS_VECTOR_LOOPS 0

typedef unsigned WORD vtype;

#define vxorf(a, b) \
	((a) ^ (b))

#define vnot(dst, a) \
	(dst) = ~(a)
#define vand(dst, a, b) \
	(dst) = (a) & (b)
#define vor(dst, a, b) \
	(dst) = (a) | (b)
#define vandn(dst, a, b) \
	(dst) = (a) & ~(b)
#define vsel(dst, a, b, c) \
	(dst) = (((a) & ~(c)) ^ ((b) & (c)))

#define vshl(dst, src, shift) \
	(dst) = (src) << (shift)
#define vshr(dst, src, shift) \
	(dst) = (src) >> (shift)

#define vzero 0

#define vones (~(vtype)0)

#define vst(dst, ofs, src) \
	*((vtype *)((DES_bs_vector *)&(dst) + (ofs))) = (src)

#define vxor(dst, a, b) \
	(dst) = vxorf((a), (b))

#define vshl1(dst, src) \
	vshl((dst), (src), 1)

#define kvtype vtype
#define kvand vand
#define kvor vor
#define kvshl1 vshl1
#define kvshl vshl
#define kvshr vshr


#define mask01 (*(kvtype *)&opencl_DES_bs_all[section].masks[0])
#define mask02 (*(kvtype *)&opencl_DES_bs_all[section].masks[1])
#define mask04 (*(kvtype *)&opencl_DES_bs_all[section].masks[2])
#define mask08 (*(kvtype *)&opencl_DES_bs_all[section].masks[3])
#define mask10 (*(kvtype *)&opencl_DES_bs_all[section].masks[4])
#define mask20 (*(kvtype *)&opencl_DES_bs_all[section].masks[5])
#define mask40 (*(kvtype *)&opencl_DES_bs_all[section].masks[6])
#define mask80 (*(kvtype *)&opencl_DES_bs_all[section].masks[7])

#define LOAD_V \
	kvtype v0 = *(kvtype *)&vp[0]; \
	kvtype v1 = *(kvtype *)&vp[1]; \
	kvtype v2 = *(kvtype *)&vp[2]; \
	kvtype v3 = *(kvtype *)&vp[3]; \
	kvtype v4 = *(kvtype *)&vp[4]; \
	kvtype v5 = *(kvtype *)&vp[5]; \
	kvtype v6 = *(kvtype *)&vp[6]; \
	kvtype v7 = *(kvtype *)&vp[7];

#define kvand_shl1_or(dst, src, mask) \
	kvand(tmp, src, mask); \
	kvshl1(tmp, tmp); \
	kvor(dst, dst, tmp)

#define kvand_shl_or(dst, src, mask, shift) \
	kvand(tmp, src, mask); \
	kvshl(tmp, tmp, shift); \
	kvor(dst, dst, tmp)

#define kvand_shl1(dst, src, mask) \
	kvand(tmp, src, mask); \
	kvshl1(dst, tmp)

#define kvand_or(dst, src, mask) \
	kvand(tmp, src, mask); \
	kvor(dst, dst, tmp)

#define kvand_shr_or(dst, src, mask, shift) \
	kvand(tmp, src, mask); \
	kvshr(tmp, tmp, shift); \
	kvor(dst, dst, tmp)

#define kvand_shr(dst, src, mask, shift) \
	kvand(tmp, src, mask); \
	kvshr(dst, tmp, shift)

#define FINALIZE_NEXT_KEY_BIT_0 { \
	kvtype m = mask01, va, vb, tmp; \
	kvand(va, v0, m); \
	kvand_shl1(vb, v1, m); \
	kvand_shl_or(va, v2, m, 2); \
	kvand_shl_or(vb, v3, m, 3); \
	kvand_shl_or(va, v4, m, 4); \
	kvand_shl_or(vb, v5, m, 5); \
	kvand_shl_or(va, v6, m, 6); \
	kvand_shl_or(vb, v7, m, 7); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_1 { \
	kvtype m = mask02, va, vb, tmp; \
	kvand_shr(va, v0, m, 1); \
	kvand(vb, v1, m); \
	kvand_shl1_or(va, v2, m); \
	kvand_shl_or(vb, v3, m, 2); \
	kvand_shl_or(va, v4, m, 3); \
	kvand_shl_or(vb, v5, m, 4); \
	kvand_shl_or(va, v6, m, 5); \
	kvand_shl_or(vb, v7, m, 6); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_2 { \
	kvtype m = mask04, va, vb, tmp; \
	kvand_shr(va, v0, m, 2); \
	kvand_shr(vb, v1, m, 1); \
	kvand_or(va, v2, m); \
	kvand_shl1_or(vb, v3, m); \
	kvand_shl_or(va, v4, m, 2); \
	kvand_shl_or(vb, v5, m, 3); \
	kvand_shl_or(va, v6, m, 4); \
	kvand_shl_or(vb, v7, m, 5); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_3 { \
	kvtype m = mask08, va, vb, tmp; \
	kvand_shr(va, v0, m, 3); \
	kvand_shr(vb, v1, m, 2); \
	kvand_shr_or(va, v2, m, 1); \
	kvand_or(vb, v3, m); \
	kvand_shl1_or(va, v4, m); \
	kvand_shl_or(vb, v5, m, 2); \
	kvand_shl_or(va, v6, m, 3); \
	kvand_shl_or(vb, v7, m, 4); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_4 { \
	kvtype m = mask10, va, vb, tmp; \
	kvand_shr(va, v0, m, 4); \
	kvand_shr(vb, v1, m, 3); \
	kvand_shr_or(va, v2, m, 2); \
	kvand_shr_or(vb, v3, m, 1); \
	kvand_or(va, v4, m); \
	kvand_shl1_or(vb, v5, m); \
	kvand_shl_or(va, v6, m, 2); \
	kvand_shl_or(vb, v7, m, 3); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_5 { \
	kvtype m = mask20, va, vb, tmp; \
	kvand_shr(va, v0, m, 5); \
	kvand_shr(vb, v1, m, 4); \
	kvand_shr_or(va, v2, m, 3); \
	kvand_shr_or(vb, v3, m, 2); \
	kvand_shr_or(va, v4, m, 1); \
	kvand_or(vb, v5, m); \
	kvand_shl1_or(va, v6, m); \
	kvand_shl_or(vb, v7, m, 2); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_6 { \
	kvtype m = mask40, va, vb, tmp; \
	kvand_shr(va, v0, m, 6); \
	kvand_shr(vb, v1, m, 5); \
	kvand_shr_or(va, v2, m, 4); \
	kvand_shr_or(vb, v3, m, 3); \
	kvand_shr_or(va, v4, m, 2); \
	kvand_shr_or(vb, v5, m, 1); \
	kvand_or(va, v6, m); \
	kvand_shl1_or(vb, v7, m); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_7 { \
	kvtype m = mask80, va, vb, tmp; \
	kvand_shr(va, v0, m, 7); \
	kvand_shr(vb, v1, m, 6); \
	kvand_shr_or(va, v2, m, 5); \
	kvand_shr_or(vb, v3, m, 4); \
	kvand_shr_or(va, v4, m, 3); \
	kvand_shr_or(vb, v5, m, 2); \
	kvand_shr_or(va, v6, m, 1); \
	kvand_or(vb, v7, m); \
	kvor(*(kvtype *)kp, va, vb); \
	kp++; \
}

        static cl_platform_id pltfrmid[MAX_PLATFORMS];

	static cl_device_id devid[MAX_PLATFORMS][MAX_DEVICES_PER_PLATFORM];

	static cl_context cntxt[MAX_PLATFORMS][MAX_DEVICES_PER_PLATFORM];

	static cl_command_queue cmdq[MAX_PLATFORMS][MAX_DEVICES_PER_PLATFORM];

	static cl_kernel krnl[MAX_PLATFORMS][MAX_DEVICES_PER_PLATFORM];

	static cl_program prg[MAX_PLATFORMS][MAX_DEVICES_PER_PLATFORM];

	static cl_int err;

	static int devno,pltfrmno;
	
	static cl_mem opencl_DES_bs_all_gpu, index768_gpu,index96_gpu,opencl_DES_bs_data_gpu;
	
void DES_bs_select_device(int platform_no,int dev_no)
{
	devno = dev_no;
	pltfrmno = platform_no;
	opencl_init("$JOHN/DES_bs_kernel.cl", dev_no, platform_no);
	pltfrmid[platform_no] = platform[platform_no];
	devid[platform_no][dev_no] = devices[dev_no];
	cntxt[platform_no][dev_no] = context[dev_no];
	prg[platform_no][dev_no] = program[dev_no];
	krnl[platform_no][dev_no] = clCreateKernel(prg[platform_no][dev_no],"DES_bs_25",&err) ;
	if(err) {printf("Create Kernel DES_bs_25 FAILED\n"); return ;}
	cmdq[platform_no][dev_no] = queue[dev_no];
	
	opencl_DES_bs_all_gpu = clCreateBuffer(cntxt[platform_no][dev_no], CL_MEM_READ_WRITE, MULTIPLIER*sizeof(opencl_DES_bs_combined), NULL, &err);
	if(opencl_DES_bs_all_gpu==(cl_mem)0) { HANDLE_CLERROR(err, "Create Buffer FAILED\n"); }
	
	opencl_DES_bs_data_gpu = clCreateBuffer(cntxt[platform_no][dev_no], CL_MEM_READ_WRITE, MULTIPLIER*sizeof(opencl_DES_bs_transfer), NULL, &err);
	if(opencl_DES_bs_data_gpu==(cl_mem)0) { HANDLE_CLERROR(err, "Create Buffer FAILED\n"); }
	
	index768_gpu = clCreateBuffer(cntxt[platform_no][dev_no], CL_MEM_READ_WRITE, 768*sizeof(unsigned int), NULL, &err);
	if(index768_gpu==(cl_mem)0) { HANDLE_CLERROR(err, "Create Buffer FAILED\n"); }
	
	index96_gpu = clCreateBuffer(cntxt[platform_no][dev_no], CL_MEM_READ_WRITE, 96*sizeof(unsigned int), NULL, &err);
	if(index96_gpu==(cl_mem)0) { HANDLE_CLERROR(err, "Create Buffer FAILED\n"); }
	
	
	HANDLE_CLERROR(clSetKernelArg(krnl[platform_no][dev_no],0,sizeof(cl_mem),&opencl_DES_bs_all_gpu),"Set Kernel Arg FAILED arg0\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[platform_no][dev_no],1,sizeof(cl_mem),&index768_gpu),"Set Kernel Arg FAILED arg1\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[platform_no][dev_no],2,sizeof(cl_mem),&index96_gpu),"Set Kernel Arg FAILED arg1\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[platform_no][dev_no],3,sizeof(cl_mem),&opencl_DES_bs_data_gpu),"Set Kernel Arg FAILED arg1\n");
}	


void opencl_DES_bs_set_salt(WORD salt)

{	//printf("DES_bs_set_salt");
	unsigned int new = salt,section=0;
	unsigned int old; 
	int dst;
	
	for(section = 0; section < MAX_KEYS_PER_CRYPT/DES_BS_DEPTH; section++) {
	new=salt;
	old = opencl_DES_bs_all[section].salt;
	opencl_DES_bs_all[section].salt = new;
	}
	section=0;
	for (dst = 0; dst < 24; dst++) {
		if ((new ^ old) & 1) {
			DES_bs_vector *sp1, *sp2;
			int src1 = dst;
			int src2 = dst + 24;
			if (new & 1) {
				src1 = src2;
				src2 = dst;
			}
			sp1 = opencl_DES_bs_all[section].Ens[src1];
			sp2 = opencl_DES_bs_all[section].Ens[src2];
			/*opencl_DES_bs_all[section].E.E[dst] = (WORD *)sp1;
			opencl_DES_bs_all[section].E.E[dst + 24] = (WORD *)sp2;
			opencl_DES_bs_all[section].E.E[dst + 48] = (WORD *)(sp1 + 32);
			opencl_DES_bs_all[section].E.E[dst + 72] = (WORD *)(sp2 + 32);*/
			index96[dst] = (WORD *)sp1 - (WORD *)opencl_DES_bs_all[section].B;
			index96[dst + 24] = (WORD *)sp2 - (WORD *)opencl_DES_bs_all[section].B;
			index96[dst + 48] = (WORD *)(sp1 + 32) - (WORD *)opencl_DES_bs_all[section].B;
			index96[dst + 72] = (WORD *)(sp2 + 32) - (WORD *)opencl_DES_bs_all[section].B;
			
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}
}

/* Include the S-boxes here so that the compiler can inline them */
//#if DES_BS == 3
//#include "sboxes-s.c"

//#elif DES_BS == 2
//#include "sboxes.c"
/*
#else
#undef andn
#include "nonstd.c"
#endif
*/
#define b				opencl_DES_bs_all[section].B
#define e				opencl_DES_bs_all[section].E.E

#if DES_BS_EXPAND
#define kd
#else
#define kd				[0]
#endif
#define bd
#define ed				[0]




#define DES_bs_clear_block_8(i) \
		vst(b[i] bd, 0, zero); \
		vst(b[i] bd, 1, zero); \
		vst(b[i] bd, 2, zero); \
		vst(b[i] bd, 3, zero); \
		vst(b[i] bd, 4, zero); \
		vst(b[i] bd, 5, zero); \
		vst(b[i] bd, 6, zero); \
		vst(b[i] bd, 7, zero); 
	

#define DES_bs_clear_block \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56);

#define DES_bs_set_block_8(i, v0, v1, v2, v3, v4, v5, v6, v7) \
		vst(b[i] bd, 0, v0); \
		vst(b[i] bd, 1, v1); \
		vst(b[i] bd, 2, v2); \
		vst(b[i] bd, 3, v3); \
		vst(b[i] bd, 4, v4); \
		vst(b[i] bd, 5, v5); \
		vst(b[i] bd, 6, v6); \
		vst(b[i] bd, 7, v7); 
	

#define x(p) vxorf(*(vtype *)&e[p] ed, *(vtype *)&k[p] kd)
#define y(p, q) vxorf(*(vtype *)&b[p] bd, *(vtype *)&k[q] kd)
#define z(r) ((vtype *)&b[r] bd)

void opencl_DES_bs_crypt_25(int keys_count)
{
	
	unsigned int section=0,keys_count_multiple,i ,j;
	
	cl_event evnt;
	
	size_t N;
	
	for(section=0;section<MULTIPLIER;section++)
	{
	
	for(i=0;i<56;i++)
		 opencl_DES_bs_data[section].K[i] = opencl_DES_bs_all[section].K[i] ;
			
	for(i=0;i<64;i++)
		 opencl_DES_bs_data[section].B[i] = opencl_DES_bs_all[section].B[i];
		
	opencl_DES_bs_data[section].zero = opencl_DES_bs_all[section].zero;
	opencl_DES_bs_data[section].ones = opencl_DES_bs_all[section].ones;
		
	for(i=0;i<8;i++)
		 opencl_DES_bs_data[section].masks[i] = opencl_DES_bs_all[section].masks[i];
			
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			opencl_DES_bs_data[section].v[i][j] = opencl_DES_bs_all[section].xkeys.v[i][j];
				
	opencl_DES_bs_data[section].keys_changed = opencl_DES_bs_all[section].keys_changed ;	
	
	}
	if(keys_count%DES_BS_DEPTH==0) keys_count_multiple=keys_count;
	
	else keys_count_multiple = ((keys_count/DES_BS_DEPTH)+1)*DES_BS_DEPTH;
	
	section=keys_count_multiple/DES_BS_DEPTH;
	
	
	
	//if(section>1) exit(0);

	N=section;

	//HANDLE_CLERROR(clEnqueueWriteBuffer(cmdq[pltfrmno][devno],opencl_DES_bs_all_gpu,CL_TRUE,0,MULTIPLIER*sizeof(opencl_DES_bs_combined),opencl_DES_bs_all,0,NULL,NULL ), "Failed Copy data to gpu");
	
	HANDLE_CLERROR(clEnqueueWriteBuffer(cmdq[pltfrmno][devno],index768_gpu,CL_TRUE,0,768*sizeof(unsigned int),index768,0,NULL,NULL ), "Failed Copy data to gpu");
	
	HANDLE_CLERROR(clEnqueueWriteBuffer(cmdq[pltfrmno][devno],index96_gpu,CL_TRUE,0,96*sizeof(unsigned int),index96,0,NULL,NULL ), "Failed Copy data to gpu");
	
	HANDLE_CLERROR(clEnqueueWriteBuffer(cmdq[pltfrmno][devno],opencl_DES_bs_data_gpu,CL_TRUE,0,MULTIPLIER*sizeof(opencl_DES_bs_transfer),opencl_DES_bs_data,0,NULL,NULL ), "Failed Copy data to gpu");
	
	err=clEnqueueNDRangeKernel(cmdq[pltfrmno][devno],krnl[pltfrmno][devno],1,NULL,&N,NULL,0,NULL,&evnt);

	clWaitForEvents(1,&evnt);
	
	//HANDLE_CLERROR(clEnqueueReadBuffer(cmdq[pltfrmno][devno],opencl_DES_bs_all_gpu,CL_TRUE,0,MULTIPLIER*sizeof(opencl_DES_bs_combined),opencl_DES_bs_all, 0, NULL, NULL),"Write FAILED\n");
	
	HANDLE_CLERROR(clEnqueueReadBuffer(cmdq[pltfrmno][devno],opencl_DES_bs_data_gpu,CL_TRUE,0,MULTIPLIER*sizeof(opencl_DES_bs_transfer),opencl_DES_bs_data, 0, NULL, NULL),"Write FAILED\n");

	clFinish(cmdq[pltfrmno][devno]);
	
	for(section=0;section<MULTIPLIER;section++)
	{
	
	for(i=0;i<56;i++)
		opencl_DES_bs_all[section].K[i] = opencl_DES_bs_data[section].K[i];
			
	for(i=0;i<64;i++)
		opencl_DES_bs_all[section].B[i] = opencl_DES_bs_data[section].B[i];
	
	opencl_DES_bs_all[section].zero = opencl_DES_bs_data[section].zero;
	opencl_DES_bs_all[section].ones = opencl_DES_bs_data[section].ones;
		
	for(i=0;i<8;i++)
		opencl_DES_bs_all[section].masks[i] = opencl_DES_bs_data[section].masks[i];
			
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			opencl_DES_bs_all[section].xkeys.v[i][j] = opencl_DES_bs_data[section].v[i][j];
				
	opencl_DES_bs_all[section].keys_changed = opencl_DES_bs_data[section].keys_changed;
	}
	
	
}
/*
void opencl_DES_bs_crypt(int count, int keys_count)
{



	for_each_t(n) {
#if DES_BS_EXPAND
		DES_bs_vector *k;
#else
		WORD **k;
#endif
		int iterations, rounds_and_swapped;

		if (opencl_DES_bs_all.keys_changed)
			goto finalize_keys;

body:

		{
			vtype zero = vzero;
			DES_bs_clear_block
		}

#if DES_BS_EXPAND
		k = opencl_DES_bs_all.KS.v;
#else
		k = opencl_DES_bs_all.KS.p;
#endif
		rounds_and_swapped = 8;
		iterations = count;

start:
		
		s1(x(0), x(1), x(2), x(3), x(4), x(5),
			z(40), z(48), z(54), z(62));
		
		s2(x(6), x(7), x(8), x(9), x(10), x(11),
			z(44), z(59), z(33), z(49));
		
		s3(x(12), x(13), x(14), x(15), x(16), x(17),
			z(55), z(47), z(61), z(37));
		
		s4(x(18), x(19), x(20), x(21), x(22), x(23),
			z(57), z(51), z(41), z(32));
		
		s5(x(24), x(25), x(26), x(27), x(28), x(29),
			z(39), z(45), z(56), z(34));
		
		s6(x(30), x(31), x(32), x(33), x(34), x(35),
			z(35), z(60), z(42), z(50));
		
		s7(x(36), x(37), x(38), x(39), x(40), x(41),
			z(63), z(43), z(53), z(38));
		
		s8(x(42), x(43), x(44), x(45), x(46), x(47),
			z(36), z(58), z(46), z(52));

		if (rounds_and_swapped == 0x100) goto next;

swap:
		
		s1(x(48), x(49), x(50), x(51), x(52), x(53),
			z(8), z(16), z(22), z(30));
		
		s2(x(54), x(55), x(56), x(57), x(58), x(59),
			z(12), z(27), z(1), z(17));
		
		s3(x(60), x(61), x(62), x(63), x(64), x(65),
			z(23), z(15), z(29), z(5));
		
		s4(x(66), x(67), x(68), x(69), x(70), x(71),
			z(25), z(19), z(9), z(0));
		
		s5(x(72), x(73), x(74), x(75), x(76), x(77),
			z(7), z(13), z(24), z(2));
		
		s6(x(78), x(79), x(80), x(81), x(82), x(83),
			z(3), z(28), z(10), z(18));
		
		s7(x(84), x(85), x(86), x(87), x(88), x(89),
			z(31), z(11), z(21), z(6));
		
		s8(x(90), x(91), x(92), x(93), x(94), x(95),
			z(4), z(26), z(14), z(20));

		k += 96;

		if (--rounds_and_swapped) goto start;
		k -= (0x300 + 48);
		rounds_and_swapped = 0x108;
		if (--iterations) goto swap;

		return;

next:
		k -= (0x300 - 48);
		rounds_and_swapped = 8;
		if (--iterations) goto start;

		return;


finalize_keys:
		opencl_DES_bs_all.keys_changed = 0;

		DES_bs_finalize_keys();

		goto body;
	}
}

#undef x


static inline void DES_bs_finalize_keys_LM(void)

{

	
		DES_bs_vector *kp = (DES_bs_vector *)&opencl_DES_bs_all.K[0] ;
		int ic;
		for (ic = 0; ic < 7; ic++) {
			DES_bs_vector *vp =
			    (DES_bs_vector *)&opencl_DES_bs_all.xkeys.v[ic][0] ;
			LOAD_V
			FINALIZE_NEXT_KEY_BIT_0
			FINALIZE_NEXT_KEY_BIT_1
			FINALIZE_NEXT_KEY_BIT_2
			FINALIZE_NEXT_KEY_BIT_3
			FINALIZE_NEXT_KEY_BIT_4
			FINALIZE_NEXT_KEY_BIT_5
			FINALIZE_NEXT_KEY_BIT_6
			FINALIZE_NEXT_KEY_BIT_7
		}
	
}

#undef v1
#undef v2
#undef v3
#undef v5
#undef v6
#undef v7

#undef kd

#define kd				[0]


void opencl_DES_bs_crypt_LM(int keys_count)
{



	for_each_t(n) {
		WORD **k;
		int rounds;


		{
			vtype z = vzero, o = vones;
			DES_bs_set_block_8(0, z, z, z, z, z, z, z, z);
			DES_bs_set_block_8(8, o, o, o, z, o, z, z, z);
			DES_bs_set_block_8(16, z, z, z, z, z, z, z, o);
			DES_bs_set_block_8(24, z, z, o, z, z, o, o, o);
			DES_bs_set_block_8(32, z, z, z, o, z, o, o, o);
			DES_bs_set_block_8(40, z, z, z, z, z, o, z, z);
			DES_bs_set_block_8(48, o, o, z, z, z, z, o, z);
			DES_bs_set_block_8(56, o, z, o, z, o, o, o, o);
		}


		DES_bs_finalize_keys_LM();


		k = opencl_DES_bs_all.KS.p;
		rounds = 8;

		do {
			
			s1(y(31, 0), y(0, 1), y(1, 2),
				y(2, 3), y(3, 4), y(4, 5),
				z(40), z(48), z(54), z(62));
			
			s2(y(3, 6), y(4, 7), y(5, 8),
				y(6, 9), y(7, 10), y(8, 11),
				z(44), z(59), z(33), z(49));
			
			s3(y(7, 12), y(8, 13), y(9, 14),
				y(10, 15), y(11, 16), y(12, 17),
				z(55), z(47), z(61), z(37));
			
			s4(y(11, 18), y(12, 19), y(13, 20),
				y(14, 21), y(15, 22), y(16, 23),
				z(57), z(51), z(41), z(32));
			
			s5(y(15, 24), y(16, 25), y(17, 26),
				y(18, 27), y(19, 28), y(20, 29),
				z(39), z(45), z(56), z(34));
			
			s6(y(19, 30), y(20, 31), y(21, 32),
				y(22, 33), y(23, 34), y(24, 35),
				z(35), z(60), z(42), z(50));
			
			s7(y(23, 36), y(24, 37), y(25, 38),
				y(26, 39), y(27, 40), y(28, 41),
				z(63), z(43), z(53), z(38));
			
			s8(y(27, 42), y(28, 43), y(29, 44),
				y(30, 45), y(31, 46), y(0, 47),
				z(36), z(58), z(46), z(52));

			
			s1(y(63, 48), y(32, 49), y(33, 50),
				y(34, 51), y(35, 52), y(36, 53),
				z(8), z(16), z(22), z(30));
			
			s2(y(35, 54), y(36, 55), y(37, 56),
				y(38, 57), y(39, 58), y(40, 59),
				z(12), z(27), z(1), z(17));
			
			s3(y(39, 60), y(40, 61), y(41, 62),
				y(42, 63), y(43, 64), y(44, 65),
				z(23), z(15), z(29), z(5));
			
			s4(y(43, 66), y(44, 67), y(45, 68),
				y(46, 69), y(47, 70), y(48, 71),
				z(25), z(19), z(9), z(0));
			
			s5(y(47, 72), y(48, 73), y(49, 74),
				y(50, 75), y(51, 76), y(52, 77),
				z(7), z(13), z(24), z(2));
			
			s6(y(51, 78), y(52, 79), y(53, 80),
				y(54, 81), y(55, 82), y(56, 83),
				z(3), z(28), z(10), z(18));
			
			s7(y(55, 84), y(56, 85), y(57, 86),
				y(58, 87), y(59, 88), y(60, 89),
				z(31), z(11), z(21), z(6));
			
			s8(y(59, 90), y(60, 91), y(61, 92),
				y(62, 93), y(63, 94), y(32, 95),
				z(4), z(26), z(14), z(20));

			k += 96;
		} while (--rounds);
	}
}
*/
