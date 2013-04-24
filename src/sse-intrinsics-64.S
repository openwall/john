	.file "sse-intrinsics.c"
	.text
..TXTST0:
# -- Begin  sse_debug
       .align    16,0x90
	.globl sse_debug
sse_debug:
..B1.1:
..___tag_value_sse_debug.1:
        movl      $1, debug(%rip)
        ret       
        .align    16,0x90
..___tag_value_sse_debug.3:
	.type	sse_debug,@function
	.size	sse_debug,.-sse_debug
	.data
# -- End  sse_debug
	.text
# -- Begin  mmxput
       .align    16,0x90
	.globl mmxput
mmxput:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %edx
# parameter 4: %ecx
# parameter 5: %r8
# parameter 6: %r9d
..B2.1:
..___tag_value_mmxput.4:
        movl      %esi, %eax
        shrl      $2, %eax
        lea       (%rdx,%rdx,2), %r10d
        shll      $8, %eax
        shll      $8, %r10d
        addq      %rax, %rdi
        addq      %r10, %rdi
        testl     %r9d, %r9d
        jbe       ..B2.8
..B2.2:
        movl      %r9d, %edx
        movl      $1, %eax
        shrl      $1, %edx
        xorl      %r10d, %r10d
        testl     %edx, %edx
        jbe       ..B2.6
..B2.3:
        movl      %esi, %eax
        movq      %r15, -24(%rsp)
        andl      $3, %eax
        movq      %rbx, -16(%rsp)
        movq      %rbp, -8(%rsp)
..___tag_value_mmxput.6:
..B2.4:
        lea       (%rcx,%r10,2), %r11d
        movl      %r11d, %r15d
        movl      %r11d, %ebx
        andl      $-4, %r15d
        lea       (%r10,%r10), %ebp
        shll      $2, %r15d
        andl      $3, %ebx
        incl      %r11d
        lea       (%r15,%rax,4), %r15d
        addl      %ebx, %r15d
        lea       1(%r10,%r10), %ebx
        incl      %r10d
        movb      (%rbp,%r8), %bpl
        movb      %bpl, (%r15,%rdi)
        movl      %r11d, %ebp
        andl      $-4, %ebp
        andl      $3, %r11d
        shll      $2, %ebp
        lea       (%rbp,%rax,4), %r15d
        addl      %r11d, %r15d
        cmpl      %edx, %r10d
        movb      (%rbx,%r8), %r11b
        movb      %r11b, (%r15,%rdi)
        jb        ..B2.4
..B2.5:
        movq      -24(%rsp), %r15
..___tag_value_mmxput.9:
        lea       1(%r10,%r10), %eax
        movq      -16(%rsp), %rbx
..___tag_value_mmxput.10:
        movq      -8(%rsp), %rbp
..___tag_value_mmxput.11:
..B2.6:
        lea       -1(%rax), %edx
        cmpl      %r9d, %edx
        jae       ..B2.8
..B2.7:
        andl      $3, %esi
        lea       -1(%rcx,%rax), %ecx
        movl      %ecx, %eax
        andl      $3, %ecx
        andl      $-4, %eax
        addl      %eax, %esi
        lea       (%rcx,%rsi,4), %esi
        movb      (%rdx,%r8), %r8b
        movb      %r8b, (%rsi,%rdi)
..B2.8:
        ret       
        .align    16,0x90
..___tag_value_mmxput.12:
	.type	mmxput,@function
	.size	mmxput,.-mmxput
	.data
# -- End  mmxput
	.text
# -- Begin  mmxput2
       .align    16,0x90
	.globl mmxput2
mmxput2:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %rdx
..B3.1:
..___tag_value_mmxput2.13:
        pushq     %r12
..___tag_value_mmxput2.15:
        pushq     %r13
..___tag_value_mmxput2.17:
        pushq     %r14
..___tag_value_mmxput2.19:
        pushq     %r15
..___tag_value_mmxput2.21:
        pushq     %rbx
..___tag_value_mmxput2.23:
        lea       (%rsi,%rsi,2), %eax
        shll      $8, %eax
        xorl      %ecx, %ecx
        movb      $0, %sil
        addq      %rax, %rdi
        movl      %ecx, %ebx
        movq      %rdx, %r13
        movl      %ecx, %r14d
        movb      %sil, %r12b
        movq      %rdi, %r15
..B3.2:
        movl      %ebx, %edi
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %r15, %rdi
        addq      %r13, %rsi
..___tag_value_mmxput2.25:
        call      memcpy
..___tag_value_mmxput2.26:
..B3.3:
        incb      %r12b
        addl      $64, %r14d
        addl      $256, %ebx
        cmpb      $3, %r12b
        jb        ..B3.2
..B3.4:
..___tag_value_mmxput2.27:
        popq      %rbx
..___tag_value_mmxput2.28:
        popq      %r15
..___tag_value_mmxput2.30:
        popq      %r14
..___tag_value_mmxput2.32:
        popq      %r13
..___tag_value_mmxput2.34:
        popq      %r12
..___tag_value_mmxput2.36:
        ret       
        .align    16,0x90
..___tag_value_mmxput2.37:
	.type	mmxput2,@function
	.size	mmxput2,.-mmxput2
	.data
# -- End  mmxput2
	.text
# -- Begin  dispatch
       .align    16,0x90
	.globl dispatch
dispatch:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B4.1:
..___tag_value_dispatch.38:
        pushq     %r12
..___tag_value_dispatch.40:
        pushq     %r13
..___tag_value_dispatch.42:
        pushq     %r14
..___tag_value_dispatch.44:
        pushq     %r15
..___tag_value_dispatch.46:
        pushq     %rbx
..___tag_value_dispatch.48:
        pushq     %rbp
..___tag_value_dispatch.50:
        subq      $40, %rsp
..___tag_value_dispatch.52:
        movq      %rdx, %r8
        movl      $23, %edx
        xorl      %eax, %eax
        movl      %ecx, 24(%rsp)
        movl      %eax, %r14d
        movl      %edx, %r13d
        movq      %rsi, %rbp
        movq      %rdi, %r12
        movq      %r8, %r15
..B4.2:
        cmpl      $40, %r14d
        ja        ..B4.54
..B4.3:
        jmp       *..1..TPKT.6_0.0.6(,%r14,8)
..1.6_0.TAG.015.0.6:
..B4.19:
        movl      $1, %esi
        movq      %r12, %rdi
        movq      %r15, %rdx
        movl      %esi, %ecx
        xorl      %r8d, %r8d
        movq      %rbp, %r9
        movl      $1, %ebx
..___tag_value_dispatch.53:
        call      mmxput3
..___tag_value_dispatch.54:
        jmp       ..B4.55
..1.6_0.TAG.01c.0.6:
..1.6_0.TAG.0e.0.6:
..B4.25:
        xorl      %edx, %edx
        movb      $0, %cl
        movl      $5, %ebx
        movl      %r14d, (%rsp)
        movl      %edx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %edx, %r13d
        movq      %r15, 16(%rsp)
        movb      %cl, %r15b
..B4.26:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %rbp, %rsi
        lea       3840(%r12,%r13), %rdi
..___tag_value_dispatch.55:
        call      memcpy
..___tag_value_dispatch.56:
..B4.27:
        incb      %r15b
        addl      $64, %r14d
        addl      $256, %r13d
        cmpb      $3, %r15b
        jb        ..B4.26
..B4.28:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.023.0.6:
..1.6_0.TAG.07.0.6:
..B4.34:
        movq      %r12, %rdi
        movl      $4, %esi
        movq      %r15, %rdx
        movl      $1, %ecx
        movq      %rbp, %r9
        movl      $4, %ebx
        movl      24(%rsp), %r8d
..___tag_value_dispatch.57:
        call      mmxput3
..___tag_value_dispatch.58:
        jmp       ..B4.55
..1.6_0.TAG.024.0.6:
..1.6_0.TAG.01e.0.6:
..1.6_0.TAG.018.0.6:
..1.6_0.TAG.012.0.6:
..1.6_0.TAG.0c.0.6:
..1.6_0.TAG.06.0.6:
..B4.36:
        xorl      %edx, %edx
        movb      $0, %cl
        movl      $3, %ebx
        movl      %r14d, (%rsp)
        movl      %edx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %edx, %r13d
        movq      %r15, 16(%rsp)
        movb      %cl, %r15b
..B4.37:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %rbp, %rsi
        lea       2304(%r12,%r13), %rdi
..___tag_value_dispatch.59:
        call      memcpy
..___tag_value_dispatch.60:
..B4.38:
        incb      %r15b
        addl      $64, %r14d
        addl      $256, %r13d
        cmpb      $3, %r15b
        jb        ..B4.37
..B4.39:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.027.0.6:
..1.6_0.TAG.021.0.6:
..1.6_0.TAG.01b.0.6:
..1.6_0.TAG.0f.0.6:
..1.6_0.TAG.09.0.6:
..1.6_0.TAG.03.0.6:
..B4.42:
        movl      $2, %esi
        movq      %r12, %rdi
        movq      %r15, %rdx
        movl      %esi, %ecx
        xorl      %r8d, %r8d
        movq      %rbp, %r9
        movl      $2, %ebx
..___tag_value_dispatch.61:
        call      mmxput3
..___tag_value_dispatch.62:
        jmp       ..B4.55
..1.6_0.TAG.028.0.6:
..1.6_0.TAG.026.0.6:
..1.6_0.TAG.022.0.6:
..1.6_0.TAG.020.0.6:
..1.6_0.TAG.01a.0.6:
..1.6_0.TAG.016.0.6:
..1.6_0.TAG.014.0.6:
..1.6_0.TAG.010.0.6:
..1.6_0.TAG.0a.0.6:
..1.6_0.TAG.08.0.6:
..1.6_0.TAG.04.0.6:
..1.6_0.TAG.02.0.6:
..B4.44:
        xorl      %edx, %edx
        movb      $0, %cl
        movl      $6, %ebx
        movl      %r14d, (%rsp)
        movl      %edx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %edx, %r13d
        movq      %r15, 16(%rsp)
        movb      %cl, %r15b
..B4.45:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %rbp, %rsi
        lea       4608(%r12,%r13), %rdi
..___tag_value_dispatch.63:
        call      memcpy
..___tag_value_dispatch.64:
..B4.46:
        incb      %r15b
        addl      $64, %r14d
        addl      $256, %r13d
        cmpb      $3, %r15b
        jb        ..B4.45
..B4.47:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.00.0.6:
..B4.50:
        xorl      %edx, %edx
        movb      $0, %cl
        xorl      %ebx, %ebx
        movl      %r14d, (%rsp)
        movl      %edx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %edx, %r13d
        movq      %r15, 16(%rsp)
        movb      %cl, %r15b
..B4.51:
        movl      %r13d, %edi
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %r12, %rdi
        addq      %rbp, %rsi
..___tag_value_dispatch.65:
        call      memcpy
..___tag_value_dispatch.66:
..B4.52:
        incb      %r15b
        addl      $64, %r14d
        addl      $256, %r13d
        cmpb      $3, %r15b
        jb        ..B4.51
..B4.53:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.DEFAULT.0.6:
..B4.54:
        movq      %r12, %rdi
        movl      $7, %esi
        movq      %r15, %rdx
        movl      $2, %ecx
        movq      %rbp, %r9
        movl      $7, %ebx
        movl      24(%rsp), %r8d
..___tag_value_dispatch.67:
        call      mmxput3
..___tag_value_dispatch.68:
..B4.55:
        movq      %rbp, %rsi
        lea       (%rbx,%rbx,2), %rdi
        shlq      $8, %rdi
        movl      $1, %edx
        addq      %r12, %rdi
..___tag_value_dispatch.69:
        call      SSEmd5body
..___tag_value_dispatch.70:
..B4.56:
        incl      %r14d
        lea       -1(%r14), %ecx
        cmpl      $33, %ecx
        jb        ..B4.2
..B4.57:
        cmpl      $34, %r14d
        jne       ..B4.60
..B4.58:
        testl     %r13d, %r13d
        je        ..B4.61
..B4.59:
        decl      %r13d
        jmp       ..B4.2
..B4.60:
        xorl      %ecx, %ecx
        cmpl      $42, %r14d
        cmovae    %ecx, %r14d
        jmp       ..B4.2
..B4.61:
        addq      $40, %rsp
..___tag_value_dispatch.71:
        popq      %rbp
..___tag_value_dispatch.73:
        popq      %rbx
..___tag_value_dispatch.75:
        popq      %r15
..___tag_value_dispatch.77:
        popq      %r14
..___tag_value_dispatch.79:
        popq      %r13
..___tag_value_dispatch.81:
        popq      %r12
..___tag_value_dispatch.83:
        ret       
        .align    16,0x90
..___tag_value_dispatch.84:
	.type	dispatch,@function
	.size	dispatch,.-dispatch
	.section .rodata, "a"
	.align 32
	.align 32
..1..TPKT.6_0.0.6:
	.quad	..1.6_0.TAG.00.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.02.0.6
	.quad	..1.6_0.TAG.03.0.6
	.quad	..1.6_0.TAG.04.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.06.0.6
	.quad	..1.6_0.TAG.07.0.6
	.quad	..1.6_0.TAG.08.0.6
	.quad	..1.6_0.TAG.09.0.6
	.quad	..1.6_0.TAG.0a.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.0c.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.0e.0.6
	.quad	..1.6_0.TAG.0f.0.6
	.quad	..1.6_0.TAG.010.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.012.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.014.0.6
	.quad	..1.6_0.TAG.015.0.6
	.quad	..1.6_0.TAG.016.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.018.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.01a.0.6
	.quad	..1.6_0.TAG.01b.0.6
	.quad	..1.6_0.TAG.01c.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.01e.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.020.0.6
	.quad	..1.6_0.TAG.021.0.6
	.quad	..1.6_0.TAG.022.0.6
	.quad	..1.6_0.TAG.023.0.6
	.quad	..1.6_0.TAG.024.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.026.0.6
	.quad	..1.6_0.TAG.027.0.6
	.quad	..1.6_0.TAG.028.0.6
	.data
# -- End  dispatch
	.text
# -- Begin  mmxput3
       .align    16,0x90
	.globl mmxput3
mmxput3:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %rdx
# parameter 4: %ecx
# parameter 5: %r8d
# parameter 6: %r9
..B5.1:
..___tag_value_mmxput3.85:
        pushq     %r12
..___tag_value_mmxput3.87:
        pushq     %r13
..___tag_value_mmxput3.89:
        pushq     %r14
..___tag_value_mmxput3.91:
        pushq     %r15
..___tag_value_mmxput3.93:
        pushq     %rbx
..___tag_value_mmxput3.95:
        pushq     %rbp
..___tag_value_mmxput3.97:
        lea       (%rsi,%rsi,2), %eax
        shll      $8, %eax
        xorl      %r10d, %r10d
        xorl      %esi, %esi
        movl      %ecx, -24(%rsp)
        addq      %rax, %rdi
        movl      %r8d, -16(%rsp)
        xorl      %eax, %eax
..B5.2:
        lea       (,%r10,4), %ecx
        movl      (%rdx,%rcx,4), %r14d
        imull     -24(%rsp), %r14d
        addl      -16(%rsp), %r14d
        movl      %r14d, %r11d
        andl      $3, %r11d
        shll      $3, %r11d
        testl     %r11d, %r11d
        je        ..B5.4
..B5.3:
        movl      %r10d, %r12d
        andl      $-4, %r14d
        shll      $8, %r12d
        movl      %r11d, %r13d
        shll      $2, %r14d
        negl      %r13d
        movl      %r13d, %ecx
        addq      %rdi, %r12
        movl      $-1, %ebx
        shrl      %cl, %ebx
        movl      %r11d, %ecx
        andl      %ebx, (%r14,%r12)
        movl      %esi, %ebx
        addq      %rdi, %rbx
        movl      (%r9,%rax,4), %ebp
        shll      %cl, %ebp
        movl      %r11d, %ecx
        orl       %ebp, (%r14,%rbx)
        lea       4(%rax), %ebp
        movl      (%r9,%rax,4), %r15d
        movl      (%r9,%rbp,4), %r8d
        shll      %cl, %r8d
        movl      %r13d, %ecx
        shrl      %cl, %r15d
        movl      %r11d, %ecx
        orl       %r15d, %r8d
        movl      %r8d, 16(%r14,%rbx)
        lea       8(%rax), %r8d
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%r8,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %ebp
        movl      %r11d, %ecx
        orl       %ebp, %r15d
        lea       12(%rax), %ebp
        movl      %r15d, 32(%r14,%rbx)
        movl      (%r9,%r8,4), %r8d
        movl      (%r9,%rbp,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %r8d
        movl      %r11d, %ecx
        movl      $-1, %r11d
        orl       %r8d, %r15d
        movl      %r15d, 48(%r14,%rbx)
        shll      %cl, %r11d
        movl      %r13d, %ecx
        andl      %r11d, 64(%r14,%r12)
        movl      (%r9,%rbp,4), %ebp
        shrl      %cl, %ebp
        orl       %ebp, 64(%r14,%rbx)
        jmp       ..B5.5
..B5.4:
        shll      $2, %r14d
        movl      %esi, %ebx
        lea       4(%rax), %r8d
        lea       8(%rax), %r12d
        lea       (%r14,%rbx), %rbp
        addq      %rdi, %r14
        lea       12(%rax), %r15d
        movl      (%r9,%rax,4), %ecx
        movl      %ecx, (%rbp,%rdi)
        movl      (%r9,%r8,4), %r11d
        movl      %r11d, 16(%r14,%rbx)
        movl      (%r9,%r12,4), %r13d
        movl      %r13d, 32(%r14,%rbx)
        movl      (%r9,%r15,4), %ecx
        movl      %ecx, 48(%r14,%rbx)
        addq      %rdi, %rbx
..B5.5:
        lea       1(,%r10,4), %ecx
        movl      (%rdx,%rcx,4), %r14d
        imull     -24(%rsp), %r14d
        addl      -16(%rsp), %r14d
        movl      %r14d, %r11d
        andl      $3, %r11d
        shll      $3, %r11d
        testl     %r11d, %r11d
        je        ..B5.7
..B5.6:
        movl      %r10d, %r12d
        andl      $-4, %r14d
        shll      $8, %r12d
        movl      %r11d, %r13d
        shll      $2, %r14d
        negl      %r13d
        lea       1(%rax), %r15d
        addq      %rdi, %r12
        movl      %r13d, %ecx
        movl      $-1, %ebp
        shrl      %cl, %ebp
        movl      %r11d, %ecx
        andl      %ebp, 4(%r14,%r12)
        lea       5(%rax), %ebp
        movl      (%r9,%r15,4), %r8d
        shll      %cl, %r8d
        movl      %r11d, %ecx
        orl       %r8d, 4(%r14,%rbx)
        movl      (%r9,%rbp,4), %r8d
        shll      %cl, %r8d
        movl      %r13d, %ecx
        movl      (%r9,%r15,4), %r15d
        shrl      %cl, %r15d
        movl      %r11d, %ecx
        orl       %r15d, %r8d
        movl      %r8d, 20(%r14,%rbx)
        lea       9(%rax), %r8d
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%r8,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %ebp
        movl      %r11d, %ecx
        orl       %ebp, %r15d
        lea       13(%rax), %ebp
        movl      %r15d, 36(%r14,%rbx)
        movl      (%r9,%r8,4), %r8d
        movl      (%r9,%rbp,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %r8d
        movl      %r11d, %ecx
        movl      $-1, %r11d
        orl       %r8d, %r15d
        movl      %r15d, 52(%r14,%rbx)
        shll      %cl, %r11d
        movl      %r13d, %ecx
        andl      %r11d, 68(%r14,%r12)
        movl      (%r9,%rbp,4), %ebp
        shrl      %cl, %ebp
        orl       %ebp, 68(%r14,%rbx)
        jmp       ..B5.8
..B5.7:
        shll      $2, %r14d
        lea       1(%rax), %ecx
        lea       5(%rax), %r8d
        lea       9(%rax), %r12d
        lea       13(%rax), %r15d
        movl      (%r9,%rcx,4), %ebp
        movl      %ebp, 4(%rbx,%r14)
        movl      (%r9,%r8,4), %r11d
        movl      %r11d, 20(%rbx,%r14)
        movl      (%r9,%r12,4), %r13d
        movl      %r13d, 36(%rbx,%r14)
        movl      (%r9,%r15,4), %ecx
        movl      %ecx, 52(%rbx,%r14)
..B5.8:
        lea       2(,%r10,4), %ecx
        movl      (%rdx,%rcx,4), %r14d
        imull     -24(%rsp), %r14d
        addl      -16(%rsp), %r14d
        movl      %r14d, %r11d
        andl      $3, %r11d
        shll      $3, %r11d
        testl     %r11d, %r11d
        je        ..B5.10
..B5.9:
        movl      %r10d, %r12d
        andl      $-4, %r14d
        shll      $8, %r12d
        movl      %r11d, %r13d
        shll      $2, %r14d
        negl      %r13d
        lea       2(%rax), %r15d
        addq      %rdi, %r12
        movl      %r13d, %ecx
        movl      $-1, %ebp
        shrl      %cl, %ebp
        movl      %r11d, %ecx
        andl      %ebp, 8(%r14,%r12)
        lea       6(%rax), %ebp
        movl      (%r9,%r15,4), %r8d
        shll      %cl, %r8d
        movl      %r11d, %ecx
        orl       %r8d, 8(%r14,%rbx)
        movl      (%r9,%rbp,4), %r8d
        shll      %cl, %r8d
        movl      %r13d, %ecx
        movl      (%r9,%r15,4), %r15d
        shrl      %cl, %r15d
        movl      %r11d, %ecx
        orl       %r15d, %r8d
        movl      %r8d, 24(%r14,%rbx)
        lea       10(%rax), %r8d
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%r8,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %ebp
        movl      %r11d, %ecx
        orl       %ebp, %r15d
        lea       14(%rax), %ebp
        movl      %r15d, 40(%r14,%rbx)
        movl      (%r9,%r8,4), %r8d
        movl      (%r9,%rbp,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %r8d
        movl      %r11d, %ecx
        movl      $-1, %r11d
        orl       %r8d, %r15d
        movl      %r15d, 56(%r14,%rbx)
        shll      %cl, %r11d
        movl      %r13d, %ecx
        andl      %r11d, 72(%r14,%r12)
        movl      (%r9,%rbp,4), %ebp
        shrl      %cl, %ebp
        orl       %ebp, 72(%r14,%rbx)
        jmp       ..B5.11
..B5.10:
        shll      $2, %r14d
        lea       2(%rax), %ecx
        lea       6(%rax), %r8d
        lea       10(%rax), %r12d
        lea       14(%rax), %r15d
        movl      (%r9,%rcx,4), %ebp
        movl      %ebp, 8(%rbx,%r14)
        movl      (%r9,%r8,4), %r11d
        movl      %r11d, 24(%rbx,%r14)
        movl      (%r9,%r12,4), %r13d
        movl      %r13d, 40(%rbx,%r14)
        movl      (%r9,%r15,4), %ecx
        movl      %ecx, 56(%rbx,%r14)
..B5.11:
        lea       3(,%r10,4), %ecx
        movl      (%rdx,%rcx,4), %r14d
        imull     -24(%rsp), %r14d
        addl      -16(%rsp), %r14d
        movl      %r14d, %r11d
        andl      $3, %r11d
        shll      $3, %r11d
        testl     %r11d, %r11d
        je        ..B5.13
..B5.12:
        movl      %r10d, %r12d
        andl      $-4, %r14d
        shll      $8, %r12d
        movl      %r11d, %r13d
        shll      $2, %r14d
        negl      %r13d
        lea       3(%rax), %r15d
        addq      %rdi, %r12
        movl      %r13d, %ecx
        movl      $-1, %ebp
        shrl      %cl, %ebp
        movl      %r11d, %ecx
        andl      %ebp, 12(%r14,%r12)
        lea       7(%rax), %ebp
        movl      (%r9,%r15,4), %r8d
        shll      %cl, %r8d
        movl      %r11d, %ecx
        orl       %r8d, 12(%r14,%rbx)
        movl      (%r9,%rbp,4), %r8d
        shll      %cl, %r8d
        movl      %r13d, %ecx
        movl      (%r9,%r15,4), %r15d
        shrl      %cl, %r15d
        movl      %r11d, %ecx
        orl       %r15d, %r8d
        movl      %r8d, 28(%r14,%rbx)
        lea       11(%rax), %r8d
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%r8,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %ebp
        movl      %r11d, %ecx
        orl       %ebp, %r15d
        lea       15(%rax), %ebp
        movl      %r15d, 44(%r14,%rbx)
        movl      (%r9,%r8,4), %r8d
        movl      (%r9,%rbp,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %r8d
        movl      %r11d, %ecx
        movl      $-1, %r11d
        orl       %r8d, %r15d
        movl      %r15d, 60(%r14,%rbx)
        shll      %cl, %r11d
        movl      %r13d, %ecx
        andl      %r11d, 76(%r14,%r12)
        movl      (%r9,%rbp,4), %ebp
        shrl      %cl, %ebp
        orl       %ebp, 76(%r14,%rbx)
        jmp       ..B5.14
..B5.13:
        shll      $2, %r14d
        lea       3(%rax), %ecx
        lea       7(%rax), %r8d
        lea       11(%rax), %r12d
        lea       15(%rax), %r15d
        movl      (%r9,%rcx,4), %ebp
        movl      %ebp, 12(%rbx,%r14)
        movl      (%r9,%r8,4), %r11d
        movl      %r11d, 28(%rbx,%r14)
        movl      (%r9,%r12,4), %r13d
        movl      %r13d, 44(%rbx,%r14)
        movl      (%r9,%r15,4), %ecx
        movl      %ecx, 60(%rbx,%r14)
..B5.14:
        incl      %r10d
        addl      $256, %esi
        addl      $16, %eax
        cmpl      $3, %r10d
        jb        ..B5.2
..B5.15:
..___tag_value_mmxput3.99:
        popq      %rbp
..___tag_value_mmxput3.100:
        popq      %rbx
..___tag_value_mmxput3.102:
        popq      %r15
..___tag_value_mmxput3.104:
        popq      %r14
..___tag_value_mmxput3.106:
        popq      %r13
..___tag_value_mmxput3.108:
        popq      %r12
..___tag_value_mmxput3.110:
        ret       
        .align    16,0x90
..___tag_value_mmxput3.111:
	.type	mmxput3,@function
	.size	mmxput3,.-mmxput3
	.data
# -- End  mmxput3
	.text
# -- Begin  SSEmd5body
       .align    16,0x90
	.globl SSEmd5body
SSEmd5body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %edx
..B6.1:
..___tag_value_SSEmd5body.112:
        subq      $840, %rsp
..___tag_value_SSEmd5body.114:
        movdqa    (%rsi), %xmm0
        testl     %edx, %edx
        movdqa    16(%rsi), %xmm1
        movdqa    32(%rsi), %xmm2
        movdqa    48(%rsi), %xmm3
        movdqa    %xmm0, (%rsp)
        movdqa    %xmm1, 16(%rsp)
        movdqa    %xmm2, 32(%rsp)
        movdqa    %xmm3, 48(%rsp)
        je        ..B6.3
..B6.2:
        movdqa    .L_2il0floatpacket.61(%rip), %xmm4
        movdqa    .L_2il0floatpacket.62(%rip), %xmm9
        movdqa    %xmm4, %xmm6
        movdqa    .L_2il0floatpacket.63(%rip), %xmm10
        movdqa    %xmm9, %xmm12
        movdqa    .L_2il0floatpacket.64(%rip), %xmm7
        movdqa    %xmm10, %xmm13
        movdqa    %xmm7, %xmm14
        movdqa    %xmm4, %xmm3
        movdqa    %xmm9, %xmm0
        movdqa    %xmm10, %xmm8
        movdqa    %xmm7, %xmm1
        jmp       ..B6.4
..B6.3:
        movdqa    (%rsp), %xmm4
        movdqa    16(%rsp), %xmm9
        movdqa    32(%rsp), %xmm10
        movdqa    48(%rsp), %xmm7
        movdqa    64(%rsi), %xmm6
        movdqa    80(%rsi), %xmm12
        movdqa    96(%rsi), %xmm13
        movdqa    112(%rsi), %xmm14
        movdqa    128(%rsi), %xmm3
        movdqa    144(%rsi), %xmm0
        movdqa    160(%rsi), %xmm8
        movdqa    176(%rsi), %xmm1
..B6.4:
        movdqa    %xmm10, %xmm5
        movdqa    %xmm13, %xmm15
        movdqa    .L_2il0floatpacket.65(%rip), %xmm2
        pxor      %xmm7, %xmm5
        paddd     %xmm2, %xmm4
        pand      %xmm9, %xmm5
        paddd     %xmm2, %xmm6
        paddd     %xmm2, %xmm3
        movdqa    %xmm8, %xmm2
        pxor      %xmm7, %xmm5
        pxor      %xmm14, %xmm15
        pxor      %xmm1, %xmm2
        movdqa    (%rdi), %xmm11
        paddd     %xmm5, %xmm4
        pand      %xmm12, %xmm15
        pand      %xmm0, %xmm2
        paddd     %xmm11, %xmm4
        pxor      %xmm14, %xmm15
        pxor      %xmm1, %xmm2
        paddd     %xmm15, %xmm6
        movdqa    512(%rdi), %xmm15
        paddd     %xmm2, %xmm3
        movdqa    %xmm4, %xmm2
        paddd     %xmm15, %xmm3
        pslld     $7, %xmm2
        psrld     $25, %xmm4
        movdqa    256(%rdi), %xmm5
        por       %xmm4, %xmm2
        movdqa    %xmm3, %xmm4
        paddd     %xmm5, %xmm6
        pslld     $7, %xmm4
        psrld     $25, %xmm3
        movdqa    %xmm5, 768(%rsp)
        movdqa    %xmm6, %xmm5
        por       %xmm3, %xmm4
        movdqa    %xmm9, %xmm3
        paddd     %xmm9, %xmm2
        pslld     $7, %xmm5
        psrld     $25, %xmm6
        pxor      %xmm10, %xmm3
        por       %xmm6, %xmm5
        pand      %xmm2, %xmm3
        movdqa    .L_2il0floatpacket.66(%rip), %xmm6
        pxor      %xmm10, %xmm3
        paddd     %xmm6, %xmm7
        paddd     %xmm6, %xmm14
        paddd     %xmm3, %xmm7
        movdqa    %xmm12, %xmm3
        paddd     %xmm6, %xmm1
        movdqa    %xmm0, %xmm6
        paddd     %xmm12, %xmm5
        paddd     %xmm0, %xmm4
        pxor      %xmm13, %xmm3
        pxor      %xmm8, %xmm6
        movdqa    %xmm15, 448(%rsp)
        pand      %xmm5, %xmm3
        movdqa    16(%rdi), %xmm15
        pand      %xmm4, %xmm6
        paddd     %xmm15, %xmm7
        pxor      %xmm13, %xmm3
        pxor      %xmm8, %xmm6
        paddd     %xmm3, %xmm14
        movdqa    528(%rdi), %xmm3
        paddd     %xmm6, %xmm1
        movdqa    %xmm7, %xmm6
        paddd     %xmm3, %xmm1
        pslld     $12, %xmm6
        psrld     $20, %xmm7
        por       %xmm7, %xmm6
        movdqa    %xmm1, %xmm7
        pslld     $12, %xmm7
        psrld     $20, %xmm1
        movdqa    %xmm15, 208(%rsp)
        por       %xmm1, %xmm7
        movdqa    272(%rdi), %xmm15
        movdqa    %xmm9, %xmm1
        paddd     %xmm15, %xmm14
        paddd     %xmm2, %xmm6
        pxor      %xmm2, %xmm1
        paddd     %xmm4, %xmm7
        movdqa    %xmm15, 176(%rsp)
        pand      %xmm6, %xmm1
        movdqa    %xmm3, 160(%rsp)
        movdqa    %xmm14, %xmm3
        movdqa    .L_2il0floatpacket.67(%rip), %xmm15
        pslld     $12, %xmm3
        psrld     $20, %xmm14
        paddd     %xmm15, %xmm10
        pxor      %xmm9, %xmm1
        por       %xmm14, %xmm3
        paddd     %xmm1, %xmm10
        paddd     %xmm15, %xmm13
        movdqa    %xmm12, %xmm1
        paddd     %xmm15, %xmm8
        movdqa    %xmm0, %xmm15
        paddd     %xmm5, %xmm3
        pxor      %xmm5, %xmm1
        pxor      %xmm4, %xmm15
        movdqa    32(%rdi), %xmm14
        pand      %xmm3, %xmm1
        pand      %xmm7, %xmm15
        paddd     %xmm14, %xmm10
        pxor      %xmm12, %xmm1
        pxor      %xmm0, %xmm15
        paddd     %xmm1, %xmm13
        paddd     %xmm15, %xmm8
        movdqa    544(%rdi), %xmm1
        movdqa    %xmm10, %xmm15
        movdqa    %xmm14, 64(%rsp)
        paddd     %xmm1, %xmm8
        movdqa    288(%rdi), %xmm14
        pslld     $17, %xmm15
        psrld     $15, %xmm10
        paddd     %xmm14, %xmm13
        movdqa    %xmm14, 96(%rsp)
        por       %xmm10, %xmm15
        movdqa    %xmm8, %xmm14
        movdqa    %xmm6, %xmm10
        paddd     %xmm6, %xmm15
        pslld     $17, %xmm14
        psrld     $15, %xmm8
        pxor      %xmm2, %xmm10
        movdqa    %xmm1, 80(%rsp)
        movdqa    %xmm13, %xmm1
        por       %xmm8, %xmm14
        pand      %xmm15, %xmm10
        movdqa    .L_2il0floatpacket.68(%rip), %xmm8
        pslld     $17, %xmm1
        psrld     $15, %xmm13
        paddd     %xmm8, %xmm9
        pxor      %xmm2, %xmm10
        por       %xmm13, %xmm1
        paddd     %xmm10, %xmm9
        movdqa    %xmm3, %xmm10
        paddd     %xmm3, %xmm1
        paddd     %xmm8, %xmm12
        pxor      %xmm5, %xmm10
        paddd     %xmm8, %xmm0
        movdqa    %xmm7, %xmm8
        paddd     %xmm7, %xmm14
        pand      %xmm1, %xmm10
        pxor      %xmm4, %xmm8
        movdqa    48(%rdi), %xmm13
        pxor      %xmm5, %xmm10
        pand      %xmm14, %xmm8
        paddd     %xmm13, %xmm9
        movdqa    %xmm13, 336(%rsp)
        paddd     %xmm10, %xmm12
        movdqa    304(%rdi), %xmm13
        pxor      %xmm4, %xmm8
        movdqa    560(%rdi), %xmm10
        paddd     %xmm13, %xmm12
        paddd     %xmm8, %xmm0
        movdqa    %xmm9, %xmm8
        movdqa    %xmm10, 352(%rsp)
        paddd     %xmm10, %xmm0
        movdqa    %xmm12, %xmm10
        pslld     $22, %xmm8
        psrld     $10, %xmm9
        pslld     $22, %xmm10
        psrld     $10, %xmm12
        por       %xmm9, %xmm8
        por       %xmm12, %xmm10
        movdqa    %xmm15, %xmm12
        paddd     %xmm15, %xmm8
        pxor      %xmm6, %xmm12
        movdqa    %xmm13, 320(%rsp)
        movdqa    %xmm0, %xmm9
        movdqa    .L_2il0floatpacket.69(%rip), %xmm13
        pand      %xmm8, %xmm12
        pslld     $22, %xmm9
        psrld     $10, %xmm0
        paddd     %xmm13, %xmm2
        pxor      %xmm6, %xmm12
        por       %xmm0, %xmm9
        paddd     %xmm12, %xmm2
        paddd     %xmm13, %xmm5
        movdqa    %xmm1, %xmm12
        paddd     %xmm13, %xmm4
        movdqa    %xmm14, %xmm13
        paddd     %xmm1, %xmm10
        paddd     %xmm14, %xmm9
        pxor      %xmm3, %xmm12
        pxor      %xmm7, %xmm13
        movdqa    64(%rdi), %xmm0
        pand      %xmm10, %xmm12
        pand      %xmm9, %xmm13
        paddd     %xmm0, %xmm2
        pxor      %xmm3, %xmm12
        pxor      %xmm7, %xmm13
        movdqa    %xmm0, 112(%rsp)
        paddd     %xmm12, %xmm5
        movdqa    320(%rdi), %xmm0
        paddd     %xmm13, %xmm4
        movdqa    %xmm2, %xmm13
        paddd     %xmm0, %xmm5
        pslld     $7, %xmm13
        psrld     $25, %xmm2
        movdqa    576(%rdi), %xmm12
        por       %xmm2, %xmm13
        movdqa    %xmm5, %xmm2
        paddd     %xmm12, %xmm4
        pslld     $7, %xmm2
        psrld     $25, %xmm5
        movdqa    %xmm12, 128(%rsp)
        por       %xmm5, %xmm2
        movdqa    %xmm4, %xmm12
        movdqa    %xmm8, %xmm5
        paddd     %xmm8, %xmm13
        pslld     $7, %xmm12
        psrld     $25, %xmm4
        pxor      %xmm15, %xmm5
        por       %xmm4, %xmm12
        pand      %xmm13, %xmm5
        movdqa    .L_2il0floatpacket.70(%rip), %xmm4
        pxor      %xmm15, %xmm5
        paddd     %xmm4, %xmm6
        paddd     %xmm4, %xmm3
        paddd     %xmm5, %xmm6
        movdqa    %xmm10, %xmm5
        paddd     %xmm4, %xmm7
        movdqa    %xmm9, %xmm4
        paddd     %xmm10, %xmm2
        paddd     %xmm9, %xmm12
        pxor      %xmm1, %xmm5
        pxor      %xmm14, %xmm4
        movdqa    %xmm0, 144(%rsp)
        pand      %xmm2, %xmm5
        movdqa    80(%rdi), %xmm0
        pand      %xmm12, %xmm4
        paddd     %xmm0, %xmm6
        pxor      %xmm1, %xmm5
        pxor      %xmm14, %xmm4
        paddd     %xmm5, %xmm3
        movdqa    %xmm0, 464(%rsp)
        paddd     %xmm4, %xmm7
        movdqa    336(%rdi), %xmm0
        movdqa    %xmm6, %xmm4
        paddd     %xmm0, %xmm3
        pslld     $12, %xmm4
        psrld     $20, %xmm6
        movdqa    592(%rdi), %xmm5
        por       %xmm6, %xmm4
        movdqa    %xmm3, %xmm6
        paddd     %xmm5, %xmm7
        pslld     $12, %xmm6
        psrld     $20, %xmm3
        movdqa    %xmm0, 512(%rsp)
        por       %xmm3, %xmm6
        movdqa    %xmm7, %xmm0
        movdqa    %xmm13, %xmm3
        paddd     %xmm13, %xmm4
        pslld     $12, %xmm0
        psrld     $20, %xmm7
        pxor      %xmm8, %xmm3
        por       %xmm7, %xmm0
        pand      %xmm4, %xmm3
        movdqa    .L_2il0floatpacket.71(%rip), %xmm7
        pxor      %xmm8, %xmm3
        paddd     %xmm7, %xmm15
        paddd     %xmm2, %xmm6
        paddd     %xmm3, %xmm15
        movdqa    %xmm2, %xmm3
        paddd     %xmm7, %xmm1
        pxor      %xmm10, %xmm3
        paddd     %xmm7, %xmm14
        movdqa    %xmm12, %xmm7
        paddd     %xmm12, %xmm0
        pand      %xmm6, %xmm3
        pxor      %xmm9, %xmm7
        pxor      %xmm10, %xmm3
        movdqa    %xmm5, 496(%rsp)
        pand      %xmm0, %xmm7
        movdqa    96(%rdi), %xmm5
        paddd     %xmm3, %xmm1
        movdqa    %xmm5, 256(%rsp)
        paddd     %xmm5, %xmm15
        movdqa    352(%rdi), %xmm5
        pxor      %xmm9, %xmm7
        movdqa    608(%rdi), %xmm3
        paddd     %xmm5, %xmm1
        paddd     %xmm7, %xmm14
        movdqa    %xmm5, 240(%rsp)
        paddd     %xmm3, %xmm14
        movdqa    %xmm3, 224(%rsp)
        movdqa    %xmm15, %xmm5
        movdqa    %xmm1, %xmm3
        pslld     $17, %xmm5
        psrld     $15, %xmm15
        pslld     $17, %xmm3
        psrld     $15, %xmm1
        por       %xmm15, %xmm5
        por       %xmm1, %xmm3
        movdqa    %xmm14, %xmm1
        movdqa    %xmm4, %xmm15
        paddd     %xmm4, %xmm5
        pslld     $17, %xmm1
        psrld     $15, %xmm14
        pxor      %xmm13, %xmm15
        por       %xmm14, %xmm1
        movdqa    .L_2il0floatpacket.72(%rip), %xmm14
        pand      %xmm5, %xmm15
        paddd     %xmm14, %xmm8
        pxor      %xmm13, %xmm15
        paddd     %xmm15, %xmm8
        paddd     %xmm14, %xmm10
        movdqa    %xmm6, %xmm15
        paddd     %xmm14, %xmm9
        movdqa    %xmm0, %xmm14
        paddd     %xmm6, %xmm3
        paddd     %xmm0, %xmm1
        pxor      %xmm2, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm3, %xmm15
        movdqa    112(%rdi), %xmm7
        pand      %xmm1, %xmm14
        paddd     %xmm7, %xmm8
        pxor      %xmm2, %xmm15
        pxor      %xmm12, %xmm14
        paddd     %xmm15, %xmm10
        movdqa    %xmm7, 608(%rsp)
        paddd     %xmm14, %xmm9
        movdqa    368(%rdi), %xmm7
        movdqa    %xmm8, %xmm14
        paddd     %xmm7, %xmm10
        pslld     $22, %xmm14
        psrld     $10, %xmm8
        movdqa    %xmm5, %xmm15
        movdqa    %xmm7, 656(%rsp)
        por       %xmm8, %xmm14
        movdqa    624(%rdi), %xmm7
        movdqa    %xmm10, %xmm8
        paddd     %xmm7, %xmm9
        pslld     $22, %xmm8
        psrld     $10, %xmm10
        paddd     %xmm5, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm9, %xmm10
        pslld     $22, %xmm10
        psrld     $10, %xmm9
        pxor      %xmm4, %xmm15
        por       %xmm9, %xmm10
        movdqa    .L_2il0floatpacket.73(%rip), %xmm9
        pand      %xmm14, %xmm15
        paddd     %xmm9, %xmm13
        pxor      %xmm4, %xmm15
        paddd     %xmm15, %xmm13
        paddd     %xmm9, %xmm2
        movdqa    %xmm3, %xmm15
        paddd     %xmm9, %xmm12
        movdqa    %xmm1, %xmm9
        paddd     %xmm3, %xmm8
        paddd     %xmm1, %xmm10
        pxor      %xmm6, %xmm15
        pxor      %xmm0, %xmm9
        pand      %xmm8, %xmm15
        movdqa    %xmm7, 624(%rsp)
        pand      %xmm10, %xmm9
        movdqa    128(%rdi), %xmm7
        pxor      %xmm6, %xmm15
        paddd     %xmm7, %xmm13
        pxor      %xmm0, %xmm9
        movdqa    %xmm7, 432(%rsp)
        paddd     %xmm15, %xmm2
        movdqa    384(%rdi), %xmm7
        paddd     %xmm9, %xmm12
        movdqa    %xmm13, %xmm9
        paddd     %xmm7, %xmm2
        pslld     $7, %xmm9
        psrld     $25, %xmm13
        movdqa    640(%rdi), %xmm15
        por       %xmm13, %xmm9
        movdqa    %xmm2, %xmm13
        paddd     %xmm15, %xmm12
        pslld     $7, %xmm13
        psrld     $25, %xmm2
        movdqa    %xmm7, 416(%rsp)
        por       %xmm2, %xmm13
        movdqa    %xmm12, %xmm2
        movdqa    %xmm14, %xmm7
        paddd     %xmm14, %xmm9
        pslld     $7, %xmm2
        psrld     $25, %xmm12
        pxor      %xmm5, %xmm7
        por       %xmm12, %xmm2
        pand      %xmm9, %xmm7
        movdqa    .L_2il0floatpacket.74(%rip), %xmm12
        pxor      %xmm5, %xmm7
        paddd     %xmm12, %xmm4
        paddd     %xmm12, %xmm6
        paddd     %xmm7, %xmm4
        movdqa    %xmm8, %xmm7
        paddd     %xmm12, %xmm0
        movdqa    %xmm10, %xmm12
        paddd     %xmm8, %xmm13
        paddd     %xmm10, %xmm2
        pxor      %xmm3, %xmm7
        pxor      %xmm1, %xmm12
        movdqa    %xmm15, 400(%rsp)
        pand      %xmm13, %xmm7
        movdqa    144(%rdi), %xmm15
        pand      %xmm2, %xmm12
        paddd     %xmm15, %xmm4
        pxor      %xmm3, %xmm7
        pxor      %xmm1, %xmm12
        paddd     %xmm7, %xmm6
        movdqa    %xmm15, 192(%rsp)
        paddd     %xmm12, %xmm0
        movdqa    400(%rdi), %xmm15
        movdqa    %xmm4, %xmm12
        paddd     %xmm15, %xmm6
        pslld     $12, %xmm12
        psrld     $20, %xmm4
        movdqa    656(%rdi), %xmm7
        por       %xmm4, %xmm12
        movdqa    %xmm6, %xmm4
        paddd     %xmm7, %xmm0
        pslld     $12, %xmm4
        psrld     $20, %xmm6
        movdqa    %xmm15, 272(%rsp)
        por       %xmm6, %xmm4
        movdqa    %xmm0, %xmm6
        movdqa    %xmm9, %xmm15
        paddd     %xmm9, %xmm12
        pslld     $12, %xmm6
        psrld     $20, %xmm0
        pxor      %xmm14, %xmm15
        por       %xmm0, %xmm6
        pand      %xmm12, %xmm15
        movdqa    .L_2il0floatpacket.75(%rip), %xmm0
        pxor      %xmm14, %xmm15
        paddd     %xmm0, %xmm5
        paddd     %xmm0, %xmm3
        paddd     %xmm15, %xmm5
        movdqa    %xmm13, %xmm15
        paddd     %xmm0, %xmm1
        movdqa    %xmm2, %xmm0
        paddd     %xmm13, %xmm4
        paddd     %xmm2, %xmm6
        pxor      %xmm8, %xmm15
        pxor      %xmm10, %xmm0
        movdqa    %xmm7, 288(%rsp)
        pand      %xmm4, %xmm15
        movdqa    160(%rdi), %xmm7
        pand      %xmm6, %xmm0
        paddd     %xmm7, %xmm5
        pxor      %xmm8, %xmm15
        pxor      %xmm10, %xmm0
        paddd     %xmm15, %xmm3
        movdqa    %xmm7, 576(%rsp)
        paddd     %xmm0, %xmm1
        movdqa    416(%rdi), %xmm7
        movdqa    %xmm5, %xmm0
        paddd     %xmm7, %xmm3
        pslld     $17, %xmm0
        psrld     $15, %xmm5
        movdqa    672(%rdi), %xmm15
        por       %xmm5, %xmm0
        movdqa    %xmm3, %xmm5
        paddd     %xmm15, %xmm1
        pslld     $17, %xmm5
        psrld     $15, %xmm3
        movdqa    %xmm7, 592(%rsp)
        por       %xmm3, %xmm5
        movdqa    %xmm1, %xmm3
        movdqa    %xmm12, %xmm7
        paddd     %xmm12, %xmm0
        pslld     $17, %xmm3
        psrld     $15, %xmm1
        pxor      %xmm9, %xmm7
        por       %xmm1, %xmm3
        pand      %xmm0, %xmm7
        movdqa    .L_2il0floatpacket.76(%rip), %xmm1
        pxor      %xmm9, %xmm7
        paddd     %xmm1, %xmm14
        paddd     %xmm4, %xmm5
        paddd     %xmm7, %xmm14
        paddd     %xmm6, %xmm3
        movdqa    432(%rdi), %xmm7
        paddd     %xmm1, %xmm8
        movdqa    %xmm7, 368(%rsp)
        movdqa    %xmm4, %xmm7
        pxor      %xmm13, %xmm7
        movdqa    %xmm15, 560(%rsp)
        pand      %xmm5, %xmm7
        movdqa    176(%rdi), %xmm15
        pxor      %xmm13, %xmm7
        movdqa    %xmm15, 304(%rsp)
        paddd     %xmm15, %xmm14
..B6.13:
        movdqa    %xmm6, %xmm15
        paddd     %xmm7, %xmm8
        pxor      %xmm2, %xmm15
        paddd     %xmm1, %xmm10
        movdqa    368(%rsp), %xmm7
        pand      %xmm3, %xmm15
        paddd     %xmm7, %xmm8
        pxor      %xmm2, %xmm15
        movdqa    %xmm11, 784(%rsp)
        paddd     %xmm15, %xmm10
        movdqa    688(%rdi), %xmm11
        movdqa    %xmm14, %xmm15
        movdqa    %xmm8, %xmm1
        paddd     %xmm11, %xmm10
        pslld     $22, %xmm15
        psrld     $10, %xmm14
        pslld     $22, %xmm1
        psrld     $10, %xmm8
        por       %xmm14, %xmm15
        por       %xmm8, %xmm1
        movdqa    %xmm10, %xmm8
        movdqa    %xmm0, %xmm14
        paddd     %xmm0, %xmm15
        pslld     $22, %xmm8
        psrld     $10, %xmm10
        pxor      %xmm12, %xmm14
        por       %xmm10, %xmm8
        pand      %xmm15, %xmm14
        movdqa    .L_2il0floatpacket.77(%rip), %xmm10
        pxor      %xmm12, %xmm14
        paddd     %xmm10, %xmm9
        paddd     %xmm10, %xmm13
        paddd     %xmm14, %xmm9
        movdqa    %xmm5, %xmm14
        paddd     %xmm10, %xmm2
        movdqa    %xmm3, %xmm10
        paddd     %xmm5, %xmm1
        paddd     %xmm3, %xmm8
        pxor      %xmm4, %xmm14
        pxor      %xmm6, %xmm10
        pand      %xmm1, %xmm14
        pand      %xmm8, %xmm10
        pxor      %xmm4, %xmm14
        pxor      %xmm6, %xmm10
        movdqa    %xmm11, 384(%rsp)
        paddd     %xmm14, %xmm13
        movdqa    192(%rdi), %xmm11
        paddd     %xmm10, %xmm2
        movdqa    704(%rdi), %xmm14
        paddd     %xmm11, %xmm9
        paddd     %xmm14, %xmm2
        movdqa    %xmm9, %xmm10
        movdqa    %xmm11, 688(%rsp)
        pslld     $7, %xmm10
        movdqa    448(%rdi), %xmm11
        psrld     $25, %xmm9
        movdqa    %xmm14, 704(%rsp)
        movdqa    %xmm2, %xmm14
        paddd     %xmm11, %xmm13
        pslld     $7, %xmm14
        psrld     $25, %xmm2
        por       %xmm9, %xmm10
        movdqa    %xmm13, %xmm9
        por       %xmm2, %xmm14
        movdqa    %xmm0, %xmm2
        paddd     %xmm15, %xmm10
        pslld     $7, %xmm9
        psrld     $25, %xmm13
        pxor      %xmm15, %xmm2
        por       %xmm13, %xmm9
        movdqa    .L_2il0floatpacket.78(%rip), %xmm13
        pand      %xmm10, %xmm2
        paddd     %xmm13, %xmm12
        pxor      %xmm0, %xmm2
        paddd     %xmm2, %xmm12
        movdqa    %xmm5, %xmm2
        paddd     %xmm1, %xmm9
        paddd     %xmm13, %xmm4
        pxor      %xmm1, %xmm2
        paddd     %xmm13, %xmm6
        movdqa    %xmm3, %xmm13
        paddd     %xmm8, %xmm14
        pand      %xmm9, %xmm2
        pxor      %xmm8, %xmm13
        movdqa    %xmm11, 672(%rsp)
        pxor      %xmm5, %xmm2
        movdqa    208(%rdi), %xmm11
        pand      %xmm14, %xmm13
        movdqa    %xmm11, 480(%rsp)
        paddd     %xmm11, %xmm12
        movdqa    464(%rdi), %xmm11
        paddd     %xmm2, %xmm4
        pxor      %xmm3, %xmm13
        paddd     %xmm11, %xmm4
        movdqa    720(%rdi), %xmm2
        paddd     %xmm13, %xmm6
        movdqa    %xmm2, 544(%rsp)
        paddd     %xmm2, %xmm6
        movdqa    %xmm4, %xmm2
        psrld     $20, %xmm4
        pslld     $12, %xmm2
        movdqa    %xmm12, %xmm13
        por       %xmm4, %xmm2
        movdqa    %xmm6, %xmm4
        pslld     $12, %xmm13
        psrld     $20, %xmm12
        pslld     $12, %xmm4
        psrld     $20, %xmm6
        por       %xmm12, %xmm13
        por       %xmm6, %xmm4
        movdqa    %xmm10, %xmm6
        paddd     %xmm10, %xmm13
        movdqa    %xmm11, 528(%rsp)
        pxor      %xmm15, %xmm6
        movdqa    .L_2il0floatpacket.79(%rip), %xmm11
        pand      %xmm13, %xmm6
        paddd     %xmm11, %xmm0
        paddd     %xmm11, %xmm5
        movdqa    %xmm9, %xmm12
        paddd     %xmm11, %xmm3
        movdqa    %xmm14, %xmm11
        paddd     %xmm9, %xmm2
        paddd     %xmm14, %xmm4
        pxor      %xmm15, %xmm6
        pxor      %xmm1, %xmm12
        pxor      %xmm8, %xmm11
        paddd     %xmm6, %xmm0
        pand      %xmm2, %xmm12
        pand      %xmm4, %xmm11
        pxor      %xmm1, %xmm12
        paddd     224(%rdi), %xmm0
        pxor      %xmm8, %xmm11
        movdqa    480(%rdi), %xmm6
        paddd     %xmm12, %xmm5
        paddd     %xmm11, %xmm3
        movdqa    %xmm0, %xmm11
        paddd     %xmm6, %xmm5
        pslld     $17, %xmm11
        psrld     $15, %xmm0
        movdqa    736(%rdi), %xmm12
        por       %xmm0, %xmm11
        movdqa    %xmm5, %xmm0
        paddd     %xmm12, %xmm3
        pslld     $17, %xmm0
        psrld     $15, %xmm5
        por       %xmm5, %xmm0
        movdqa    %xmm3, %xmm5
        pslld     $17, %xmm5
        psrld     $15, %xmm3
        por       %xmm3, %xmm5
        movdqa    %xmm13, %xmm3
        movdqa    %xmm12, 736(%rsp)
        paddd     %xmm13, %xmm11
        movdqa    .L_2il0floatpacket.80(%rip), %xmm12
        pxor      %xmm10, %xmm3
        paddd     %xmm12, %xmm15
        pand      %xmm11, %xmm3
        paddd     %xmm12, %xmm1
        paddd     %xmm12, %xmm8
        movdqa    %xmm4, %xmm12
        paddd     %xmm4, %xmm5
        pxor      %xmm10, %xmm3
        pxor      %xmm14, %xmm12
        paddd     %xmm3, %xmm15
        movdqa    %xmm2, %xmm3
        pand      %xmm5, %xmm12
        paddd     %xmm2, %xmm0
        movdqa    %xmm6, 720(%rsp)
        pxor      %xmm9, %xmm3
        movdqa    240(%rdi), %xmm6
        pxor      %xmm14, %xmm12
        paddd     %xmm6, %xmm15
        pand      %xmm0, %xmm3
        paddd     %xmm12, %xmm8
        pxor      %xmm9, %xmm3
        paddd     752(%rdi), %xmm8
        movdqa    %xmm15, %xmm12
        movdqa    %xmm6, 640(%rsp)
        paddd     %xmm3, %xmm1
        movdqa    496(%rdi), %xmm6
        pslld     $22, %xmm12
        psrld     $10, %xmm15
        movdqa    %xmm8, %xmm3
        paddd     %xmm6, %xmm1
        por       %xmm15, %xmm12
        pslld     $22, %xmm3
        psrld     $10, %xmm8
        paddd     %xmm11, %xmm12
        movdqa    %xmm1, %xmm15
        por       %xmm8, %xmm3
        movdqa    %xmm11, %xmm8
        pslld     $22, %xmm15
        psrld     $10, %xmm1
        pxor      %xmm12, %xmm8
        por       %xmm1, %xmm15
        movdqa    .L_2il0floatpacket.81(%rip), %xmm1
        pand      %xmm13, %xmm8
        paddd     %xmm1, %xmm10
        pxor      %xmm11, %xmm8
        paddd     %xmm0, %xmm15
        paddd     %xmm5, %xmm3
        paddd     %xmm8, %xmm10
        paddd     %xmm1, %xmm9
        movdqa    %xmm0, %xmm8
        paddd     %xmm1, %xmm14
        movdqa    %xmm5, %xmm1
        pxor      %xmm15, %xmm8
        pxor      %xmm3, %xmm1
        pand      %xmm2, %xmm8
        pand      %xmm4, %xmm1
        pxor      %xmm0, %xmm8
        paddd     208(%rsp), %xmm10
        pxor      %xmm5, %xmm1
        paddd     %xmm8, %xmm9
        paddd     %xmm1, %xmm14
        movdqa    %xmm10, %xmm1
        psrld     $27, %xmm10
        paddd     176(%rsp), %xmm9
        pslld     $5, %xmm1
        por       %xmm10, %xmm1
        movdqa    %xmm9, %xmm10
        paddd     160(%rsp), %xmm14
        pslld     $5, %xmm10
        psrld     $27, %xmm9
        paddd     %xmm12, %xmm1
        por       %xmm9, %xmm10
        movdqa    %xmm14, %xmm9
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        movdqa    %xmm12, %xmm8
        por       %xmm14, %xmm9
        movdqa    .L_2il0floatpacket.82(%rip), %xmm14
        pxor      %xmm1, %xmm8
        paddd     %xmm3, %xmm9
        paddd     %xmm14, %xmm13
        pand      %xmm11, %xmm8
        paddd     %xmm14, %xmm2
        paddd     %xmm14, %xmm4
        movdqa    %xmm3, %xmm14
        pxor      %xmm12, %xmm8
        pxor      %xmm9, %xmm14
        paddd     %xmm15, %xmm10
        paddd     %xmm8, %xmm13
        movdqa    %xmm15, %xmm8
        pand      %xmm5, %xmm14
        pxor      %xmm10, %xmm8
        pxor      %xmm3, %xmm14
        paddd     256(%rsp), %xmm13
        pand      %xmm0, %xmm8
        paddd     %xmm14, %xmm4
        pxor      %xmm15, %xmm8
        paddd     224(%rsp), %xmm4
        movdqa    %xmm13, %xmm14
        paddd     %xmm8, %xmm2
        pslld     $9, %xmm14
        psrld     $23, %xmm13
        movdqa    %xmm4, %xmm8
        paddd     240(%rsp), %xmm2
        por       %xmm13, %xmm14
        pslld     $9, %xmm8
        psrld     $23, %xmm4
        paddd     %xmm1, %xmm14
        movdqa    %xmm2, %xmm13
        por       %xmm4, %xmm8
        movdqa    %xmm1, %xmm4
        pslld     $9, %xmm13
        psrld     $23, %xmm2
        pxor      %xmm14, %xmm4
        por       %xmm2, %xmm13
        movdqa    .L_2il0floatpacket.83(%rip), %xmm2
        pand      %xmm12, %xmm4
        paddd     %xmm2, %xmm11
        pxor      %xmm1, %xmm4
        paddd     %xmm10, %xmm13
        paddd     %xmm4, %xmm11
        movdqa    %xmm10, %xmm4
        paddd     %xmm2, %xmm0
        pxor      %xmm13, %xmm4
        paddd     %xmm9, %xmm8
        pand      %xmm15, %xmm4
        paddd     %xmm2, %xmm5
        pxor      %xmm10, %xmm4
        paddd     %xmm4, %xmm0
        paddd     %xmm7, %xmm0
        movdqa    %xmm9, %xmm7
        pxor      %xmm8, %xmm7
        movdqa    %xmm0, %xmm2
        pand      %xmm3, %xmm7
        pslld     $14, %xmm2
        pxor      %xmm9, %xmm7
        psrld     $18, %xmm0
        paddd     304(%rsp), %xmm11
        paddd     %xmm7, %xmm5
        paddd     688(%rdi), %xmm5
        movdqa    %xmm11, %xmm7
        pslld     $14, %xmm7
        psrld     $18, %xmm11
        movdqa    %xmm5, %xmm4
        por       %xmm11, %xmm7
        pslld     $14, %xmm4
        psrld     $18, %xmm5
        paddd     %xmm14, %xmm7
        por       %xmm5, %xmm4
        movdqa    %xmm14, %xmm5
        por       %xmm0, %xmm2
        pxor      %xmm7, %xmm5
        paddd     %xmm13, %xmm2
        movdqa    .L_2il0floatpacket.84(%rip), %xmm0
        pand      %xmm1, %xmm5
        paddd     %xmm0, %xmm12
        pxor      %xmm14, %xmm5
        paddd     %xmm5, %xmm12
        movdqa    %xmm13, %xmm5
        pxor      %xmm2, %xmm5
        paddd     %xmm8, %xmm4
        paddd     %xmm0, %xmm15
        pand      %xmm10, %xmm5
        paddd     %xmm0, %xmm3
        movdqa    %xmm8, %xmm0
        movdqa    784(%rsp), %xmm11
        pxor      %xmm13, %xmm5
        pxor      %xmm4, %xmm0
        paddd     %xmm11, %xmm12
        paddd     %xmm5, %xmm15
        pand      %xmm9, %xmm0
        paddd     768(%rsp), %xmm15
        pxor      %xmm8, %xmm0
        movdqa    %xmm12, %xmm5
        paddd     %xmm0, %xmm3
        pslld     $20, %xmm5
        psrld     $12, %xmm12
        movdqa    %xmm15, %xmm0
        por       %xmm12, %xmm5
        paddd     448(%rsp), %xmm3
        pslld     $20, %xmm0
        psrld     $12, %xmm15
        paddd     %xmm7, %xmm5
        por       %xmm15, %xmm0
        movdqa    %xmm3, %xmm12
        movdqa    %xmm7, %xmm15
        pslld     $20, %xmm12
        psrld     $12, %xmm3
        pxor      %xmm5, %xmm15
        por       %xmm3, %xmm12
        pand      %xmm14, %xmm15
        movdqa    .L_2il0floatpacket.85(%rip), %xmm3
        pxor      %xmm7, %xmm15
        paddd     %xmm3, %xmm1
        paddd     %xmm2, %xmm0
        paddd     %xmm4, %xmm12
        paddd     %xmm15, %xmm1
        paddd     %xmm3, %xmm10
        movdqa    %xmm2, %xmm15
        paddd     %xmm3, %xmm9
        movdqa    %xmm4, %xmm3
        pxor      %xmm0, %xmm15
        pxor      %xmm12, %xmm3
        pand      %xmm13, %xmm15
        pand      %xmm8, %xmm3
        paddd     464(%rsp), %xmm1
        pxor      %xmm2, %xmm15
        pxor      %xmm4, %xmm3
        paddd     %xmm15, %xmm10
        paddd     %xmm3, %xmm9
        movdqa    %xmm1, %xmm3
        paddd     512(%rsp), %xmm10
        pslld     $5, %xmm3
        psrld     $27, %xmm1
        movdqa    %xmm5, %xmm15
        por       %xmm1, %xmm3
        movdqa    %xmm10, %xmm1
        paddd     496(%rsp), %xmm9
        pslld     $5, %xmm1
        psrld     $27, %xmm10
        paddd     %xmm5, %xmm3
        por       %xmm10, %xmm1
        movdqa    %xmm9, %xmm10
        pslld     $5, %xmm10
        psrld     $27, %xmm9
        pxor      %xmm3, %xmm15
        por       %xmm9, %xmm10
        movdqa    .L_2il0floatpacket.86(%rip), %xmm9
        pand      %xmm7, %xmm15
        paddd     %xmm9, %xmm14
        pxor      %xmm5, %xmm15
        paddd     %xmm0, %xmm1
        paddd     %xmm12, %xmm10
        paddd     %xmm15, %xmm14
        paddd     %xmm9, %xmm13
        movdqa    %xmm0, %xmm15
        paddd     %xmm9, %xmm8
        movdqa    %xmm12, %xmm9
        pxor      %xmm1, %xmm15
        pxor      %xmm10, %xmm9
        pand      %xmm2, %xmm15
        pand      %xmm4, %xmm9
        pxor      %xmm0, %xmm15
        paddd     576(%rsp), %xmm14
        pxor      %xmm12, %xmm9
        paddd     %xmm15, %xmm13
        paddd     %xmm9, %xmm8
        movdqa    %xmm14, %xmm9
        psrld     $23, %xmm14
        paddd     592(%rsp), %xmm13
        pslld     $9, %xmm9
        por       %xmm14, %xmm9
        movdqa    %xmm13, %xmm14
        paddd     560(%rsp), %xmm8
        pslld     $9, %xmm14
        psrld     $23, %xmm13
        paddd     %xmm3, %xmm9
        por       %xmm13, %xmm14
        movdqa    %xmm8, %xmm13
        movdqa    %xmm3, %xmm15
        pslld     $9, %xmm13
        psrld     $23, %xmm8
        pxor      %xmm9, %xmm15
        por       %xmm8, %xmm13
        pand      %xmm5, %xmm15
        movdqa    .L_2il0floatpacket.87(%rip), %xmm8
        pxor      %xmm3, %xmm15
        paddd     %xmm8, %xmm7
        paddd     %xmm1, %xmm14
        paddd     %xmm15, %xmm7
        movdqa    %xmm1, %xmm15
        pxor      %xmm14, %xmm15
        paddd     %xmm8, %xmm2
        pand      %xmm0, %xmm15
        paddd     %xmm10, %xmm13
        pxor      %xmm1, %xmm15
        paddd     %xmm8, %xmm4
        paddd     %xmm15, %xmm2
        movdqa    %xmm9, %xmm15
        movdqa    %xmm6, 752(%rsp)
        paddd     %xmm6, %xmm2
        movdqa    %xmm10, %xmm6
        paddd     240(%rdi), %xmm7
        pxor      %xmm13, %xmm6
        pand      %xmm12, %xmm6
        movdqa    %xmm7, %xmm8
        pxor      %xmm10, %xmm6
        pslld     $14, %xmm8
        psrld     $18, %xmm7
        paddd     %xmm6, %xmm4
        movdqa    752(%rdi), %xmm6
        por       %xmm7, %xmm8
        movdqa    %xmm2, %xmm7
        paddd     %xmm6, %xmm4
        pslld     $14, %xmm7
        psrld     $18, %xmm2
        paddd     %xmm9, %xmm8
        por       %xmm2, %xmm7
        movdqa    %xmm4, %xmm2
        psrld     $18, %xmm4
        pslld     $14, %xmm2
        pxor      %xmm8, %xmm15
        por       %xmm4, %xmm2
        pand      %xmm3, %xmm15
        movdqa    .L_2il0floatpacket.88(%rip), %xmm4
        pxor      %xmm9, %xmm15
        paddd     %xmm4, %xmm5
        paddd     %xmm14, %xmm7
        paddd     %xmm13, %xmm2
        paddd     %xmm15, %xmm5
        paddd     %xmm4, %xmm0
        movdqa    %xmm14, %xmm15
        paddd     %xmm4, %xmm12
        movdqa    %xmm13, %xmm4
        pxor      %xmm7, %xmm15
        pxor      %xmm2, %xmm4
        pand      %xmm1, %xmm15
        pand      %xmm10, %xmm4
        paddd     112(%rsp), %xmm5
        pxor      %xmm14, %xmm15
        pxor      %xmm13, %xmm4
        paddd     %xmm15, %xmm0
        paddd     %xmm4, %xmm12
        movdqa    %xmm5, %xmm4
        paddd     144(%rsp), %xmm0
        pslld     $20, %xmm4
        psrld     $12, %xmm5
        por       %xmm5, %xmm4
        movdqa    %xmm0, %xmm5
        pslld     $20, %xmm5
        psrld     $12, %xmm0
        paddd     128(%rsp), %xmm12
        paddd     %xmm8, %xmm4
        por       %xmm0, %xmm5
        movdqa    224(%rdi), %xmm0
..B6.12:
        movdqa    %xmm6, 816(%rsp)
        movdqa    %xmm12, %xmm6
        pslld     $20, %xmm6
        psrld     $12, %xmm12
        por       %xmm12, %xmm6
        movdqa    %xmm8, %xmm12
        pxor      %xmm4, %xmm12
        paddd     %xmm7, %xmm5
        movdqa    .L_2il0floatpacket.89(%rip), %xmm15
        pand      %xmm9, %xmm12
        paddd     %xmm15, %xmm3
        pxor      %xmm8, %xmm12
        movdqa    %xmm11, 784(%rsp)
        paddd     %xmm2, %xmm6
        paddd     %xmm12, %xmm3
        movdqa    %xmm7, %xmm11
        movdqa    %xmm2, %xmm12
        pxor      %xmm5, %xmm11
        pxor      %xmm6, %xmm12
        pand      %xmm14, %xmm11
        pand      %xmm13, %xmm12
        paddd     %xmm15, %xmm1
        paddd     192(%rsp), %xmm3
        pxor      %xmm7, %xmm11
        paddd     %xmm15, %xmm10
        pxor      %xmm2, %xmm12
        paddd     %xmm11, %xmm1
        paddd     %xmm12, %xmm10
        movdqa    %xmm3, %xmm12
        psrld     $27, %xmm3
        paddd     272(%rsp), %xmm1
        pslld     $5, %xmm12
        por       %xmm3, %xmm12
        movdqa    %xmm1, %xmm3
        paddd     288(%rsp), %xmm10
        pslld     $5, %xmm3
        psrld     $27, %xmm1
        paddd     %xmm4, %xmm12
        por       %xmm1, %xmm3
        movdqa    %xmm10, %xmm1
        pslld     $5, %xmm1
        psrld     $27, %xmm10
        por       %xmm10, %xmm1
        movdqa    %xmm4, %xmm10
        pxor      %xmm12, %xmm10
        paddd     %xmm6, %xmm1
        movdqa    .L_2il0floatpacket.90(%rip), %xmm11
        pand      %xmm8, %xmm10
        paddd     %xmm11, %xmm9
        pxor      %xmm4, %xmm10
        paddd     %xmm10, %xmm9
        movdqa    %xmm6, %xmm15
        movdqa    %xmm0, 800(%rsp)
        paddd     %xmm5, %xmm3
        paddd     %xmm0, %xmm9
        movdqa    %xmm5, %xmm0
        pxor      %xmm1, %xmm15
        pxor      %xmm3, %xmm0
        pand      %xmm2, %xmm15
        pand      %xmm7, %xmm0
        paddd     %xmm11, %xmm13
        pxor      %xmm6, %xmm15
        paddd     %xmm11, %xmm14
        pxor      %xmm5, %xmm0
        paddd     %xmm15, %xmm13
        paddd     %xmm0, %xmm14
        paddd     736(%rsp), %xmm13
        movdqa    %xmm9, %xmm10
        paddd     720(%rsp), %xmm14
        pslld     $9, %xmm10
        psrld     $23, %xmm9
        movdqa    %xmm13, %xmm15
        por       %xmm9, %xmm10
        movdqa    %xmm14, %xmm9
        pslld     $9, %xmm15
        psrld     $23, %xmm13
        paddd     %xmm12, %xmm10
        pslld     $9, %xmm9
        psrld     $23, %xmm14
        por       %xmm13, %xmm15
        movdqa    %xmm12, %xmm13
        por       %xmm14, %xmm9
        pxor      %xmm10, %xmm13
        paddd     %xmm3, %xmm9
        movdqa    .L_2il0floatpacket.91(%rip), %xmm14
        paddd     %xmm1, %xmm15
        pand      %xmm4, %xmm13
        movdqa    %xmm3, %xmm0
        movdqa    %xmm1, %xmm11
        paddd     %xmm14, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm9, %xmm0
        pxor      %xmm15, %xmm11
        paddd     %xmm13, %xmm8
        pand      %xmm5, %xmm0
        pand      %xmm6, %xmm11
        paddd     336(%rsp), %xmm8
        paddd     %xmm14, %xmm7
        pxor      %xmm3, %xmm0
        paddd     %xmm14, %xmm2
        pxor      %xmm1, %xmm11
        paddd     %xmm0, %xmm7
        paddd     %xmm11, %xmm2
        movdqa    %xmm8, %xmm14
        paddd     320(%rsp), %xmm7
        pslld     $14, %xmm14
        paddd     352(%rsp), %xmm2
        psrld     $18, %xmm8
        por       %xmm8, %xmm14
        movdqa    %xmm7, %xmm13
        movdqa    %xmm2, %xmm8
        pslld     $14, %xmm13
        psrld     $18, %xmm7
        pslld     $14, %xmm8
        psrld     $18, %xmm2
        paddd     %xmm10, %xmm14
        por       %xmm7, %xmm13
        por       %xmm2, %xmm8
        movdqa    .L_2il0floatpacket.92(%rip), %xmm7
        movdqa    %xmm10, %xmm2
        paddd     %xmm15, %xmm8
        paddd     %xmm7, %xmm4
        pxor      %xmm14, %xmm2
        paddd     %xmm7, %xmm5
        paddd     %xmm7, %xmm6
        movdqa    %xmm15, %xmm7
        pand      %xmm12, %xmm2
        pxor      %xmm8, %xmm7
        paddd     %xmm9, %xmm13
        pxor      %xmm10, %xmm2
        movdqa    %xmm9, %xmm0
        pand      %xmm1, %xmm7
        paddd     %xmm2, %xmm4
        pxor      %xmm13, %xmm0
        movdqa    432(%rsp), %xmm2
        pxor      %xmm15, %xmm7
        paddd     %xmm2, %xmm4
        pand      %xmm3, %xmm0
        paddd     %xmm7, %xmm6
        pxor      %xmm9, %xmm0
        paddd     400(%rsp), %xmm6
        movdqa    %xmm4, %xmm7
        paddd     %xmm0, %xmm5
        pslld     $20, %xmm7
        movdqa    416(%rsp), %xmm0
        psrld     $12, %xmm4
        movdqa    %xmm6, %xmm11
        paddd     %xmm0, %xmm5
        por       %xmm4, %xmm7
        pslld     $20, %xmm11
        psrld     $12, %xmm6
        paddd     %xmm14, %xmm7
        movdqa    %xmm5, %xmm4
        por       %xmm6, %xmm11
        movdqa    %xmm14, %xmm6
        pslld     $20, %xmm4
        psrld     $12, %xmm5
        pxor      %xmm7, %xmm6
        por       %xmm5, %xmm4
        pand      %xmm10, %xmm6
        movdqa    .L_2il0floatpacket.93(%rip), %xmm5
        pxor      %xmm14, %xmm6
        paddd     %xmm5, %xmm12
        paddd     %xmm13, %xmm4
        paddd     %xmm6, %xmm12
        movdqa    %xmm13, %xmm6
        pxor      %xmm4, %xmm6
        paddd     %xmm8, %xmm11
        paddd     %xmm5, %xmm3
        pand      %xmm9, %xmm6
        paddd     %xmm5, %xmm1
        movdqa    %xmm8, %xmm5
        pxor      %xmm13, %xmm6
        pxor      %xmm11, %xmm5
        paddd     %xmm6, %xmm3
        pand      %xmm15, %xmm5
        paddd     480(%rsp), %xmm12
        pxor      %xmm8, %xmm5
        paddd     528(%rsp), %xmm3
        paddd     %xmm5, %xmm1
        movdqa    %xmm12, %xmm5
        movdqa    %xmm3, %xmm6
        paddd     544(%rsp), %xmm1
        pslld     $5, %xmm5
        psrld     $27, %xmm12
        pslld     $5, %xmm6
        psrld     $27, %xmm3
        por       %xmm12, %xmm5
        por       %xmm3, %xmm6
        movdqa    %xmm1, %xmm3
        paddd     %xmm7, %xmm5
        pslld     $5, %xmm3
        psrld     $27, %xmm1
        movdqa    %xmm7, %xmm12
        por       %xmm1, %xmm3
        pxor      %xmm5, %xmm12
        movdqa    .L_2il0floatpacket.94(%rip), %xmm1
        paddd     %xmm11, %xmm3
        paddd     %xmm1, %xmm10
        pand      %xmm14, %xmm12
        paddd     %xmm1, %xmm9
        paddd     %xmm1, %xmm15
        movdqa    %xmm11, %xmm1
        pxor      %xmm7, %xmm12
        pxor      %xmm3, %xmm1
        paddd     %xmm4, %xmm6
        paddd     %xmm12, %xmm10
        movdqa    %xmm4, %xmm12
        pand      %xmm8, %xmm1
        pxor      %xmm6, %xmm12
        pxor      %xmm11, %xmm1
        pand      %xmm13, %xmm12
        paddd     64(%rsp), %xmm10
        paddd     %xmm1, %xmm15
        paddd     80(%rsp), %xmm15
        pxor      %xmm4, %xmm12
        movdqa    %xmm10, %xmm1
        paddd     %xmm12, %xmm9
        pslld     $9, %xmm1
        psrld     $23, %xmm10
        movdqa    %xmm15, %xmm12
        por       %xmm10, %xmm1
        paddd     96(%rsp), %xmm9
        pslld     $9, %xmm12
        psrld     $23, %xmm15
        paddd     %xmm5, %xmm1
        movdqa    %xmm9, %xmm10
        por       %xmm15, %xmm12
        movdqa    %xmm5, %xmm15
        pslld     $9, %xmm10
        psrld     $23, %xmm9
        pxor      %xmm1, %xmm15
        por       %xmm9, %xmm10
        pand      %xmm7, %xmm15
        movdqa    .L_2il0floatpacket.95(%rip), %xmm9
        pxor      %xmm5, %xmm15
        paddd     %xmm9, %xmm14
        paddd     %xmm6, %xmm10
        paddd     %xmm15, %xmm14
        movdqa    %xmm6, %xmm15
        paddd     %xmm3, %xmm12
        paddd     %xmm9, %xmm13
        pxor      %xmm10, %xmm15
        paddd     %xmm9, %xmm8
        movdqa    %xmm3, %xmm9
        pand      %xmm4, %xmm15
        pxor      %xmm12, %xmm9
        pxor      %xmm6, %xmm15
        pand      %xmm11, %xmm9
        paddd     %xmm15, %xmm13
        paddd     608(%rsp), %xmm14
        pxor      %xmm3, %xmm9
        paddd     656(%rsp), %xmm13
        paddd     %xmm9, %xmm8
        movdqa    %xmm14, %xmm9
        psrld     $18, %xmm14
        pslld     $14, %xmm9
        movdqa    %xmm13, %xmm15
        paddd     624(%rsp), %xmm8
        por       %xmm14, %xmm9
        pslld     $14, %xmm15
        psrld     $18, %xmm13
        paddd     %xmm1, %xmm9
        por       %xmm13, %xmm15
        movdqa    %xmm8, %xmm13
        movdqa    %xmm1, %xmm14
        pslld     $14, %xmm13
        psrld     $18, %xmm8
        pxor      %xmm9, %xmm14
        por       %xmm8, %xmm13
        movdqa    .L_2il0floatpacket.96(%rip), %xmm8
        pand      %xmm5, %xmm14
        paddd     %xmm8, %xmm7
        pxor      %xmm1, %xmm14
        paddd     %xmm10, %xmm15
        paddd     %xmm12, %xmm13
        paddd     %xmm14, %xmm7
        paddd     %xmm8, %xmm4
        movdqa    %xmm10, %xmm14
        paddd     %xmm8, %xmm11
        movdqa    %xmm12, %xmm8
        pxor      %xmm15, %xmm14
        pxor      %xmm13, %xmm8
        pand      %xmm6, %xmm14
        pand      %xmm3, %xmm8
        pxor      %xmm10, %xmm14
        paddd     688(%rsp), %xmm7
        pxor      %xmm12, %xmm8
        paddd     %xmm14, %xmm4
        paddd     %xmm8, %xmm11
        movdqa    %xmm7, %xmm8
        psrld     $12, %xmm7
        paddd     672(%rsp), %xmm4
        pslld     $20, %xmm8
        por       %xmm7, %xmm8
        movdqa    %xmm4, %xmm7
        paddd     704(%rsp), %xmm11
        pslld     $20, %xmm7
        psrld     $12, %xmm4
        paddd     %xmm9, %xmm8
        por       %xmm4, %xmm7
        movdqa    %xmm11, %xmm4
        pslld     $20, %xmm4
        psrld     $12, %xmm11
        por       %xmm11, %xmm4
        movdqa    %xmm9, %xmm11
        movdqa    .L_2il0floatpacket.97(%rip), %xmm14
        pxor      %xmm1, %xmm11
        paddd     %xmm14, %xmm5
        pxor      %xmm8, %xmm11
        paddd     %xmm11, %xmm5
        movdqa    %xmm15, %xmm11
        paddd     %xmm15, %xmm7
        pxor      %xmm10, %xmm11
        paddd     464(%rsp), %xmm5
        paddd     %xmm14, %xmm6
        pxor      %xmm7, %xmm11
        paddd     %xmm14, %xmm3
        movdqa    %xmm13, %xmm14
        paddd     %xmm13, %xmm4
        paddd     %xmm11, %xmm6
        pxor      %xmm12, %xmm14
        movdqa    %xmm5, %xmm11
        pxor      %xmm4, %xmm14
        paddd     512(%rsp), %xmm6
        pslld     $4, %xmm11
        psrld     $28, %xmm5
        paddd     %xmm14, %xmm3
        por       %xmm5, %xmm11
        movdqa    %xmm6, %xmm5
        paddd     496(%rsp), %xmm3
        pslld     $4, %xmm5
        psrld     $28, %xmm6
        paddd     %xmm8, %xmm11
        por       %xmm6, %xmm5
        movdqa    %xmm3, %xmm6
        pslld     $4, %xmm6
        psrld     $28, %xmm3
        por       %xmm3, %xmm6
        movdqa    %xmm8, %xmm3
        movdqa    .L_2il0floatpacket.98(%rip), %xmm14
        pxor      %xmm9, %xmm3
        paddd     %xmm14, %xmm1
        pxor      %xmm11, %xmm3
        paddd     %xmm3, %xmm1
        paddd     %xmm7, %xmm5
        paddd     %xmm2, %xmm1
        movdqa    %xmm7, %xmm2
        pxor      %xmm15, %xmm2
        paddd     %xmm14, %xmm10
        pxor      %xmm5, %xmm2
        paddd     %xmm4, %xmm6
        paddd     %xmm2, %xmm10
        movdqa    %xmm1, %xmm2
        paddd     %xmm0, %xmm10
        movdqa    %xmm4, %xmm0
        pslld     $11, %xmm2
        psrld     $21, %xmm1
        pxor      %xmm13, %xmm0
        por       %xmm1, %xmm2
        movdqa    %xmm10, %xmm1
        paddd     %xmm14, %xmm12
        pxor      %xmm6, %xmm0
        pslld     $11, %xmm1
        psrld     $21, %xmm10
        paddd     %xmm0, %xmm12
        por       %xmm10, %xmm1
        movdqa    %xmm5, %xmm14
        paddd     400(%rsp), %xmm12
        paddd     %xmm5, %xmm1
        movdqa    .L_2il0floatpacket.99(%rip), %xmm0
        pxor      %xmm7, %xmm14
        movdqa    %xmm12, %xmm10
        paddd     %xmm0, %xmm15
        pxor      %xmm1, %xmm14
        pslld     $11, %xmm10
        psrld     $21, %xmm12
        paddd     %xmm14, %xmm15
        paddd     368(%rsp), %xmm15
        por       %xmm12, %xmm10
        movdqa    %xmm11, %xmm12
        paddd     %xmm11, %xmm2
        pshufhw   $177, %xmm15, %xmm3
        pxor      %xmm8, %xmm12
        movdqa    %xmm6, %xmm15
        paddd     %xmm6, %xmm10
        paddd     %xmm0, %xmm9
        pxor      %xmm2, %xmm12
        pxor      %xmm4, %xmm15
        paddd     %xmm12, %xmm9
        paddd     %xmm0, %xmm13
        pxor      %xmm10, %xmm15
        paddd     304(%rsp), %xmm9
        paddd     %xmm15, %xmm13
        paddd     384(%rsp), %xmm13
        movdqa    %xmm2, %xmm0
        pshufhw   $177, %xmm9, %xmm9
        pxor      %xmm11, %xmm0
        pshuflw   $177, %xmm9, %xmm9
        movdqa    %xmm1, %xmm14
        pshufhw   $177, %xmm13, %xmm13
        paddd     %xmm2, %xmm9
        pshuflw   $177, %xmm13, %xmm12
        pxor      %xmm9, %xmm0
        movdqa    .L_2il0floatpacket.100(%rip), %xmm13
        pxor      %xmm5, %xmm14
        pshuflw   $177, %xmm3, %xmm3
        paddd     %xmm13, %xmm8
        paddd     %xmm1, %xmm3
        paddd     %xmm0, %xmm8
        movdqa    800(%rsp), %xmm0
        paddd     %xmm13, %xmm7
        paddd     %xmm0, %xmm8
        pxor      %xmm3, %xmm14
        movdqa    %xmm10, %xmm15
        paddd     %xmm10, %xmm12
        paddd     %xmm14, %xmm7
        paddd     %xmm13, %xmm4
        pxor      %xmm6, %xmm15
        movdqa    %xmm8, %xmm13
        paddd     720(%rsp), %xmm7
        pxor      %xmm12, %xmm15
        pslld     $23, %xmm13
        psrld     $9, %xmm8
        paddd     %xmm15, %xmm4
        por       %xmm8, %xmm13
        movdqa    %xmm7, %xmm8
        psrld     $9, %xmm7
        paddd     736(%rsp), %xmm4
        pslld     $23, %xmm8
        por       %xmm7, %xmm8
        movdqa    %xmm4, %xmm7
        pslld     $23, %xmm7
        psrld     $9, %xmm4
        por       %xmm4, %xmm7
        movdqa    %xmm9, %xmm4
        movdqa    .L_2il0floatpacket.101(%rip), %xmm15
        paddd     %xmm9, %xmm13
        pxor      %xmm2, %xmm4
        movdqa    %xmm3, %xmm14
        paddd     %xmm3, %xmm8
        paddd     %xmm15, %xmm11
        pxor      %xmm13, %xmm4
        pxor      %xmm1, %xmm14
        paddd     %xmm4, %xmm11
        paddd     %xmm15, %xmm5
        pxor      %xmm8, %xmm14
        movdqa    %xmm12, %xmm4
        paddd     %xmm12, %xmm7
        paddd     %xmm14, %xmm5
        pxor      %xmm10, %xmm4
        paddd     %xmm15, %xmm6
        paddd     176(%rsp), %xmm5
        pxor      %xmm7, %xmm4
        paddd     %xmm4, %xmm6
        movdqa    %xmm5, %xmm14
        paddd     208(%rsp), %xmm11
        pslld     $4, %xmm14
        paddd     160(%rsp), %xmm6
        psrld     $28, %xmm5
        movdqa    %xmm11, %xmm4
        por       %xmm5, %xmm14
        movdqa    %xmm6, %xmm5
        pslld     $4, %xmm4
        psrld     $28, %xmm11
        pslld     $4, %xmm5
        psrld     $28, %xmm6
        por       %xmm11, %xmm4
        por       %xmm6, %xmm5
        movdqa    %xmm13, %xmm6
        movdqa    .L_2il0floatpacket.102(%rip), %xmm11
        paddd     %xmm13, %xmm4
        pxor      %xmm9, %xmm6
        movdqa    %xmm8, %xmm15
        paddd     %xmm8, %xmm14
        paddd     %xmm11, %xmm2
        pxor      %xmm4, %xmm6
        pxor      %xmm3, %xmm15
        paddd     %xmm6, %xmm2
        paddd     %xmm11, %xmm1
        pxor      %xmm14, %xmm15
        paddd     %xmm7, %xmm5
        paddd     112(%rsp), %xmm2
        paddd     %xmm15, %xmm1
        movdqa    816(%rsp), %xmm6
        movdqa    784(%rsp), %xmm11
..B6.11:
        movdqa    %xmm0, 800(%rsp)
        movdqa    %xmm7, %xmm0
        pxor      %xmm12, %xmm0
        movdqa    %xmm4, %xmm15
        paddd     .L_2il0floatpacket.102(%rip), %xmm10
        pxor      %xmm5, %xmm0
        paddd     %xmm0, %xmm10
        movdqa    %xmm2, %xmm0
        paddd     144(%rsp), %xmm1
        pslld     $11, %xmm0
        psrld     $21, %xmm2
        pxor      %xmm13, %xmm15
        por       %xmm2, %xmm0
        movdqa    %xmm1, %xmm2
        paddd     128(%rsp), %xmm10
        pslld     $11, %xmm2
        psrld     $21, %xmm1
        paddd     %xmm4, %xmm0
        por       %xmm1, %xmm2
        movdqa    %xmm10, %xmm1
        pslld     $11, %xmm1
        psrld     $21, %xmm10
        por       %xmm10, %xmm1
        pxor      %xmm0, %xmm15
        movdqa    .L_2il0floatpacket.103(%rip), %xmm10
        paddd     %xmm14, %xmm2
        paddd     %xmm10, %xmm9
        paddd     %xmm10, %xmm3
        paddd     %xmm15, %xmm9
        movdqa    %xmm14, %xmm15
        paddd     %xmm10, %xmm12
        movdqa    %xmm5, %xmm10
        paddd     608(%rsp), %xmm9
        paddd     %xmm5, %xmm1
        pxor      %xmm8, %xmm15
        pxor      %xmm7, %xmm10
        pshufhw   $177, %xmm9, %xmm9
        pxor      %xmm2, %xmm15
        pxor      %xmm1, %xmm10
        paddd     %xmm15, %xmm3
        pshuflw   $177, %xmm9, %xmm9
        paddd     %xmm10, %xmm12
        movdqa    %xmm4, %xmm10
        paddd     %xmm0, %xmm9
        paddd     656(%rsp), %xmm3
        pxor      %xmm0, %xmm10
        paddd     624(%rsp), %xmm12
        pxor      %xmm9, %xmm10
        movdqa    .L_2il0floatpacket.104(%rip), %xmm15
        pshufhw   $177, %xmm3, %xmm3
        paddd     %xmm15, %xmm13
        pshufhw   $177, %xmm12, %xmm12
        paddd     %xmm10, %xmm13
        pshuflw   $177, %xmm3, %xmm3
        paddd     %xmm15, %xmm8
        pshuflw   $177, %xmm12, %xmm12
        movdqa    %xmm14, %xmm10
        paddd     %xmm15, %xmm7
        movdqa    %xmm5, %xmm15
        paddd     %xmm2, %xmm3
        paddd     %xmm1, %xmm12
        pxor      %xmm2, %xmm10
        pxor      %xmm1, %xmm15
        paddd     576(%rsp), %xmm13
        pxor      %xmm3, %xmm10
        pxor      %xmm12, %xmm15
        paddd     %xmm10, %xmm8
        paddd     %xmm15, %xmm7
        movdqa    %xmm13, %xmm15
        paddd     592(%rsp), %xmm8
        pslld     $23, %xmm15
        psrld     $9, %xmm13
        movdqa    %xmm9, %xmm10
        por       %xmm13, %xmm15
        movdqa    %xmm8, %xmm13
        paddd     560(%rsp), %xmm7
        pslld     $23, %xmm13
        psrld     $9, %xmm8
        paddd     %xmm9, %xmm15
        por       %xmm8, %xmm13
        movdqa    %xmm7, %xmm8
        pslld     $23, %xmm8
        psrld     $9, %xmm7
        por       %xmm7, %xmm8
        pxor      %xmm0, %xmm10
        movdqa    .L_2il0floatpacket.105(%rip), %xmm7
        pxor      %xmm15, %xmm10
        paddd     %xmm7, %xmm4
        paddd     %xmm7, %xmm14
        paddd     %xmm10, %xmm4
        movdqa    %xmm3, %xmm10
        paddd     %xmm7, %xmm5
        movdqa    %xmm12, %xmm7
        paddd     %xmm3, %xmm13
        paddd     %xmm12, %xmm8
        pxor      %xmm2, %xmm10
        pxor      %xmm1, %xmm7
        paddd     480(%rsp), %xmm4
        pxor      %xmm13, %xmm10
        pxor      %xmm8, %xmm7
        paddd     %xmm10, %xmm14
        paddd     %xmm7, %xmm5
        movdqa    %xmm4, %xmm7
        paddd     528(%rsp), %xmm14
        pslld     $4, %xmm7
        psrld     $28, %xmm4
        movdqa    %xmm15, %xmm10
        por       %xmm4, %xmm7
        movdqa    %xmm14, %xmm4
        paddd     544(%rsp), %xmm5
        pslld     $4, %xmm4
        psrld     $28, %xmm14
        paddd     %xmm15, %xmm7
        por       %xmm14, %xmm4
        movdqa    %xmm5, %xmm14
        pslld     $4, %xmm14
        psrld     $28, %xmm5
        por       %xmm5, %xmm14
        pxor      %xmm9, %xmm10
        movdqa    .L_2il0floatpacket.106(%rip), %xmm5
        pxor      %xmm7, %xmm10
        paddd     %xmm5, %xmm0
        paddd     %xmm13, %xmm4
        paddd     %xmm10, %xmm0
        movdqa    %xmm13, %xmm10
        pxor      %xmm3, %xmm10
        paddd     %xmm5, %xmm2
        pxor      %xmm4, %xmm10
        paddd     %xmm5, %xmm1
        movdqa    %xmm8, %xmm5
        paddd     %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        pxor      %xmm12, %xmm5
        paddd     768(%rsp), %xmm2
        pxor      %xmm14, %xmm5
        paddd     %xmm5, %xmm1
        movdqa    %xmm2, %xmm5
        paddd     448(%rsp), %xmm1
        paddd     %xmm11, %xmm0
        pslld     $11, %xmm5
        psrld     $21, %xmm2
        movdqa    %xmm0, %xmm10
        por       %xmm2, %xmm5
        movdqa    %xmm1, %xmm2
        pslld     $11, %xmm10
        psrld     $21, %xmm0
        pslld     $11, %xmm2
        psrld     $21, %xmm1
        por       %xmm0, %xmm10
        por       %xmm1, %xmm2
        movdqa    %xmm7, %xmm0
        movdqa    .L_2il0floatpacket.107(%rip), %xmm1
        paddd     %xmm7, %xmm10
        paddd     %xmm1, %xmm9
        pxor      %xmm15, %xmm0
        paddd     %xmm1, %xmm3
        paddd     %xmm1, %xmm12
        movdqa    %xmm14, %xmm1
        paddd     %xmm14, %xmm2
        pxor      %xmm10, %xmm0
        pxor      %xmm8, %xmm1
        paddd     %xmm0, %xmm9
        movdqa    %xmm4, %xmm0
        pxor      %xmm2, %xmm1
        paddd     %xmm4, %xmm5
        paddd     336(%rsp), %xmm9
        pxor      %xmm13, %xmm0
        paddd     %xmm1, %xmm12
        pxor      %xmm5, %xmm0
        paddd     352(%rsp), %xmm12
        paddd     %xmm0, %xmm3
        pshufhw   $177, %xmm9, %xmm9
        movdqa    %xmm10, %xmm1
        pshuflw   $177, %xmm9, %xmm9
        pxor      %xmm7, %xmm1
        pshufhw   $177, %xmm12, %xmm0
        paddd     %xmm10, %xmm9
        paddd     320(%rsp), %xmm3
        pxor      %xmm9, %xmm1
        pshuflw   $177, %xmm0, %xmm12
        movdqa    .L_2il0floatpacket.108(%rip), %xmm0
        paddd     %xmm2, %xmm12
        pshufhw   $177, %xmm3, %xmm3
        paddd     %xmm0, %xmm15
        pshuflw   $177, %xmm3, %xmm3
        paddd     %xmm1, %xmm15
        paddd     %xmm0, %xmm13
        movdqa    %xmm5, %xmm1
        paddd     %xmm0, %xmm8
        movdqa    %xmm2, %xmm0
        paddd     %xmm5, %xmm3
        pxor      %xmm4, %xmm1
        pxor      %xmm14, %xmm0
        pxor      %xmm3, %xmm1
        paddd     256(%rsp), %xmm15
        pxor      %xmm12, %xmm0
        paddd     %xmm1, %xmm13
        paddd     %xmm0, %xmm8
        movdqa    %xmm15, %xmm0
        psrld     $9, %xmm15
        paddd     240(%rsp), %xmm13
        pslld     $23, %xmm0
        por       %xmm15, %xmm0
        movdqa    %xmm13, %xmm15
        paddd     224(%rsp), %xmm8
        pslld     $23, %xmm15
        psrld     $9, %xmm13
        movdqa    %xmm9, %xmm1
        por       %xmm13, %xmm15
        movdqa    %xmm8, %xmm13
        pslld     $23, %xmm13
        psrld     $9, %xmm8
        paddd     %xmm9, %xmm0
        por       %xmm8, %xmm13
        movdqa    .L_2il0floatpacket.109(%rip), %xmm8
        pxor      %xmm10, %xmm1
        paddd     %xmm8, %xmm7
        pxor      %xmm0, %xmm1
        paddd     %xmm1, %xmm7
        paddd     %xmm8, %xmm4
        movdqa    %xmm3, %xmm1
        paddd     %xmm8, %xmm14
        movdqa    %xmm12, %xmm8
        paddd     %xmm3, %xmm15
        paddd     %xmm12, %xmm13
        pxor      %xmm5, %xmm1
        pxor      %xmm2, %xmm8
        pxor      %xmm15, %xmm1
        paddd     192(%rsp), %xmm7
        pxor      %xmm13, %xmm8
        paddd     %xmm1, %xmm4
        paddd     %xmm8, %xmm14
        movdqa    %xmm7, %xmm8
        psrld     $28, %xmm7
        paddd     272(%rsp), %xmm4
        pslld     $4, %xmm8
        por       %xmm7, %xmm8
        movdqa    %xmm4, %xmm7
        paddd     288(%rsp), %xmm14
        pslld     $4, %xmm7
        psrld     $28, %xmm4
        paddd     %xmm0, %xmm8
        por       %xmm4, %xmm7
        movdqa    %xmm14, %xmm4
        pslld     $4, %xmm4
        psrld     $28, %xmm14
        por       %xmm14, %xmm4
        movdqa    %xmm0, %xmm14
        movdqa    .L_2il0floatpacket.110(%rip), %xmm1
        pxor      %xmm9, %xmm14
        paddd     %xmm1, %xmm10
        pxor      %xmm8, %xmm14
        paddd     %xmm14, %xmm10
        movdqa    %xmm15, %xmm14
        paddd     %xmm15, %xmm7
        pxor      %xmm3, %xmm14
        paddd     688(%rsp), %xmm10
        paddd     %xmm1, %xmm5
        pxor      %xmm7, %xmm14
        paddd     %xmm1, %xmm2
        movdqa    %xmm13, %xmm1
        paddd     %xmm13, %xmm4
        paddd     %xmm14, %xmm5
        pxor      %xmm12, %xmm1
        movdqa    %xmm10, %xmm14
        pxor      %xmm4, %xmm1
        paddd     672(%rsp), %xmm5
        pslld     $11, %xmm14
        psrld     $21, %xmm10
        paddd     %xmm1, %xmm2
        por       %xmm10, %xmm14
        movdqa    %xmm5, %xmm10
        paddd     704(%rsp), %xmm2
        pslld     $11, %xmm10
        psrld     $21, %xmm5
        movdqa    %xmm8, %xmm1
        por       %xmm5, %xmm10
        movdqa    %xmm2, %xmm5
        pslld     $11, %xmm5
        psrld     $21, %xmm2
        paddd     %xmm8, %xmm14
        por       %xmm2, %xmm5
        movdqa    .L_2il0floatpacket.111(%rip), %xmm2
        pxor      %xmm0, %xmm1
        paddd     %xmm2, %xmm9
        pxor      %xmm14, %xmm1
        paddd     %xmm1, %xmm9
        paddd     %xmm2, %xmm3
        movdqa    %xmm7, %xmm1
        paddd     %xmm2, %xmm12
        movdqa    %xmm4, %xmm2
        paddd     %xmm7, %xmm10
        paddd     640(%rsp), %xmm9
        paddd     %xmm4, %xmm5
        pxor      %xmm15, %xmm1
        pxor      %xmm13, %xmm2
        pshufhw   $177, %xmm9, %xmm9
        pxor      %xmm10, %xmm1
        pxor      %xmm5, %xmm2
        paddd     %xmm1, %xmm3
        pshuflw   $177, %xmm9, %xmm9
        paddd     %xmm2, %xmm12
        movdqa    %xmm14, %xmm1
        paddd     %xmm14, %xmm9
        movdqa    .L_2il0floatpacket.112(%rip), %xmm2
        paddd     %xmm6, %xmm12
        pxor      %xmm8, %xmm1
        paddd     %xmm2, %xmm0
        paddd     752(%rsp), %xmm3
        pxor      %xmm9, %xmm1
        movdqa    %xmm6, 816(%rsp)
        paddd     %xmm1, %xmm0
        pshufhw   $177, %xmm12, %xmm6
        movdqa    %xmm5, %xmm1
        pshufhw   $177, %xmm3, %xmm3
        movdqa    %xmm10, %xmm12
        pshuflw   $177, %xmm6, %xmm6
        pxor      %xmm4, %xmm1
        pshuflw   $177, %xmm3, %xmm3
        paddd     %xmm5, %xmm6
        paddd     %xmm10, %xmm3
        pxor      %xmm7, %xmm12
        paddd     64(%rsp), %xmm0
        paddd     %xmm2, %xmm13
        pxor      %xmm6, %xmm1
        paddd     %xmm2, %xmm15
        pxor      %xmm3, %xmm12
        paddd     %xmm1, %xmm13
        movdqa    %xmm0, %xmm1
        paddd     %xmm12, %xmm15
        paddd     80(%rsp), %xmm13
        pslld     $23, %xmm1
        psrld     $9, %xmm0
        paddd     96(%rsp), %xmm15
        por       %xmm0, %xmm1
        movdqa    %xmm13, %xmm0
        movdqa    %xmm15, %xmm2
        pslld     $23, %xmm0
        psrld     $9, %xmm13
        pslld     $23, %xmm2
        psrld     $9, %xmm15
        por       %xmm13, %xmm0
        por       %xmm15, %xmm2
        movdqa    %xmm14, %xmm15
        pcmpeqd   %xmm13, %xmm13
        paddd     %xmm9, %xmm1
        pandn     %xmm13, %xmm15
        movdqa    .L_2il0floatpacket.113(%rip), %xmm12
        por       %xmm1, %xmm15
        paddd     %xmm12, %xmm8
        pxor      %xmm9, %xmm15
        paddd     %xmm15, %xmm8
        paddd     %xmm3, %xmm2
        paddd     %xmm11, %xmm8
        movdqa    %xmm10, %xmm11
        pandn     %xmm13, %xmm11
        paddd     %xmm12, %xmm7
        por       %xmm2, %xmm11
        paddd     %xmm12, %xmm4
        movdqa    %xmm5, %xmm12
        paddd     %xmm6, %xmm0
        pxor      %xmm3, %xmm11
        pandn     %xmm13, %xmm12
        paddd     %xmm11, %xmm7
        por       %xmm0, %xmm12
        movdqa    %xmm8, %xmm11
        pxor      %xmm6, %xmm12
        paddd     768(%rsp), %xmm7
        pslld     $6, %xmm11
        psrld     $26, %xmm8
        paddd     %xmm12, %xmm4
        por       %xmm8, %xmm11
        movdqa    %xmm7, %xmm8
        paddd     448(%rsp), %xmm4
        pslld     $6, %xmm8
        psrld     $26, %xmm7
        paddd     %xmm1, %xmm11
        por       %xmm7, %xmm8
        movdqa    %xmm4, %xmm7
        pslld     $6, %xmm7
        psrld     $26, %xmm4
        por       %xmm4, %xmm7
        movdqa    %xmm9, %xmm4
        pandn     %xmm13, %xmm4
        movdqa    %xmm3, %xmm12
        movdqa    .L_2il0floatpacket.114(%rip), %xmm15
        por       %xmm11, %xmm4
        paddd     %xmm2, %xmm8
        paddd     %xmm15, %xmm14
        pxor      %xmm1, %xmm4
        pandn     %xmm13, %xmm12
        paddd     %xmm4, %xmm14
        por       %xmm8, %xmm12
        movdqa    %xmm6, %xmm4
        paddd     %xmm0, %xmm7
        paddd     %xmm15, %xmm10
        pxor      %xmm2, %xmm12
        pandn     %xmm13, %xmm4
        paddd     %xmm12, %xmm10
        por       %xmm7, %xmm4
        paddd     %xmm15, %xmm5
        paddd     656(%rsp), %xmm10
        pxor      %xmm0, %xmm4
        paddd     %xmm4, %xmm5
        movdqa    %xmm10, %xmm4
        paddd     608(%rsp), %xmm14
        pslld     $10, %xmm4
        paddd     624(%rsp), %xmm5
        psrld     $22, %xmm10
        movdqa    %xmm14, %xmm12
        por       %xmm10, %xmm4
        movdqa    %xmm5, %xmm10
        pslld     $10, %xmm12
        psrld     $22, %xmm14
        pslld     $10, %xmm10
        psrld     $22, %xmm5
        por       %xmm14, %xmm12
        por       %xmm5, %xmm10
        movdqa    %xmm1, %xmm5
        paddd     %xmm11, %xmm12
        pandn     %xmm13, %xmm5
        movdqa    .L_2il0floatpacket.115(%rip), %xmm15
        por       %xmm12, %xmm5
        paddd     %xmm15, %xmm9
        pxor      %xmm11, %xmm5
        paddd     %xmm5, %xmm9
        movdqa    %xmm2, %xmm14
        movdqa    %xmm0, %xmm5
        paddd     %xmm8, %xmm4
        paddd     %xmm7, %xmm10
        pandn     %xmm13, %xmm14
        pandn     %xmm13, %xmm5
        por       %xmm4, %xmm14
        por       %xmm10, %xmm5
        paddd     %xmm15, %xmm3
        paddd     800(%rsp), %xmm9
        pxor      %xmm8, %xmm14
        paddd     %xmm15, %xmm6
        pxor      %xmm7, %xmm5
        paddd     %xmm14, %xmm3
        paddd     %xmm5, %xmm6
        movdqa    %xmm9, %xmm5
        psrld     $17, %xmm9
        paddd     720(%rsp), %xmm3
        pslld     $15, %xmm5
        por       %xmm9, %xmm5
        movdqa    %xmm3, %xmm9
        paddd     736(%rsp), %xmm6
        pslld     $15, %xmm9
        psrld     $17, %xmm3
        paddd     %xmm12, %xmm5
        por       %xmm3, %xmm9
        movdqa    %xmm6, %xmm3
        pslld     $15, %xmm3
        psrld     $17, %xmm6
        por       %xmm6, %xmm3
        movdqa    %xmm11, %xmm6
        pandn     %xmm13, %xmm6
        movdqa    %xmm8, %xmm14
        movdqa    .L_2il0floatpacket.116(%rip), %xmm15
        por       %xmm5, %xmm6
        paddd     %xmm15, %xmm1
        pxor      %xmm12, %xmm6
        paddd     %xmm4, %xmm9
        paddd     %xmm6, %xmm1
        pandn     %xmm13, %xmm14
        movdqa    %xmm7, %xmm6
        paddd     %xmm10, %xmm3
        por       %xmm9, %xmm14
        pandn     %xmm13, %xmm6
        paddd     %xmm15, %xmm2
        pxor      %xmm4, %xmm14
        por       %xmm3, %xmm6
        paddd     %xmm14, %xmm2
        paddd     %xmm15, %xmm0
        pxor      %xmm10, %xmm6
        paddd     464(%rsp), %xmm1
        paddd     %xmm6, %xmm0
        paddd     512(%rsp), %xmm2
        movdqa    816(%rsp), %xmm6
..B6.10:
        movdqa    %xmm1, %xmm13
        psrld     $11, %xmm1
        pslld     $21, %xmm13
        movdqa    %xmm12, %xmm15
        por       %xmm1, %xmm13
        movdqa    %xmm2, %xmm1
        pslld     $21, %xmm1
        psrld     $11, %xmm2
        paddd     496(%rsp), %xmm0
        por       %xmm2, %xmm1
        movdqa    %xmm0, %xmm14
        paddd     %xmm5, %xmm13
        pcmpeqd   %xmm2, %xmm2
        pslld     $21, %xmm14
        psrld     $11, %xmm0
        pandn     %xmm2, %xmm15
        por       %xmm0, %xmm14
        por       %xmm13, %xmm15
        movdqa    .L_2il0floatpacket.117(%rip), %xmm0
        pxor      %xmm5, %xmm15
        paddd     %xmm0, %xmm11
        paddd     %xmm0, %xmm8
        paddd     %xmm15, %xmm11
        movdqa    %xmm4, %xmm15
        paddd     %xmm0, %xmm7
        movdqa    %xmm10, %xmm0
        paddd     %xmm9, %xmm1
        paddd     %xmm3, %xmm14
        pandn     %xmm2, %xmm15
        pandn     %xmm2, %xmm0
        por       %xmm1, %xmm15
        por       %xmm14, %xmm0
        paddd     688(%rsp), %xmm11
        pxor      %xmm9, %xmm15
        pxor      %xmm3, %xmm0
        paddd     %xmm15, %xmm8
        paddd     %xmm0, %xmm7
        movdqa    %xmm11, %xmm0
        paddd     672(%rsp), %xmm8
        pslld     $6, %xmm0
        psrld     $26, %xmm11
        movdqa    %xmm5, %xmm15
        por       %xmm11, %xmm0
        movdqa    %xmm8, %xmm11
        paddd     704(%rsp), %xmm7
        pslld     $6, %xmm11
        psrld     $26, %xmm8
        paddd     %xmm13, %xmm0
        por       %xmm8, %xmm11
        movdqa    %xmm7, %xmm8
        pslld     $6, %xmm8
        psrld     $26, %xmm7
        pandn     %xmm2, %xmm15
        por       %xmm7, %xmm8
        movdqa    .L_2il0floatpacket.118(%rip), %xmm7
        por       %xmm0, %xmm15
        paddd     %xmm7, %xmm12
        pxor      %xmm13, %xmm15
        paddd     %xmm15, %xmm12
        paddd     %xmm7, %xmm4
        movdqa    %xmm9, %xmm15
        paddd     %xmm7, %xmm10
        movdqa    %xmm3, %xmm7
        paddd     %xmm1, %xmm11
        paddd     %xmm14, %xmm8
        pandn     %xmm2, %xmm15
        pandn     %xmm2, %xmm7
        por       %xmm11, %xmm15
        por       %xmm8, %xmm7
        pxor      %xmm1, %xmm15
        paddd     336(%rsp), %xmm12
        pxor      %xmm14, %xmm7
        paddd     %xmm15, %xmm4
        paddd     %xmm7, %xmm10
        movdqa    %xmm12, %xmm7
        psrld     $22, %xmm12
        paddd     320(%rsp), %xmm4
        pslld     $10, %xmm7
        por       %xmm12, %xmm7
        movdqa    %xmm4, %xmm12
        paddd     352(%rsp), %xmm10
        pslld     $10, %xmm12
        psrld     $22, %xmm4
        paddd     %xmm0, %xmm7
        por       %xmm4, %xmm12
        movdqa    %xmm10, %xmm4
        pslld     $10, %xmm4
        psrld     $22, %xmm10
        por       %xmm10, %xmm4
        movdqa    %xmm13, %xmm10
        pandn     %xmm2, %xmm10
        paddd     %xmm11, %xmm12
        movdqa    .L_2il0floatpacket.119(%rip), %xmm15
        por       %xmm7, %xmm10
        paddd     %xmm15, %xmm5
        pxor      %xmm0, %xmm10
        paddd     %xmm10, %xmm5
        movdqa    %xmm1, %xmm10
        pandn     %xmm2, %xmm10
        paddd     %xmm15, %xmm9
        por       %xmm12, %xmm10
        paddd     %xmm15, %xmm3
        movdqa    %xmm14, %xmm15
        paddd     %xmm8, %xmm4
        paddd     576(%rsp), %xmm5
        pxor      %xmm11, %xmm10
        pandn     %xmm2, %xmm15
        paddd     %xmm10, %xmm9
        por       %xmm4, %xmm15
        movdqa    %xmm5, %xmm10
        paddd     592(%rsp), %xmm9
        pxor      %xmm8, %xmm15
        pslld     $15, %xmm10
        psrld     $17, %xmm5
        paddd     %xmm15, %xmm3
        por       %xmm5, %xmm10
        movdqa    %xmm9, %xmm5
        psrld     $17, %xmm9
        paddd     560(%rsp), %xmm3
        pslld     $15, %xmm5
        por       %xmm9, %xmm5
        movdqa    %xmm3, %xmm9
        movdqa    %xmm0, %xmm15
        paddd     %xmm7, %xmm10
        pslld     $15, %xmm9
        psrld     $17, %xmm3
        pandn     %xmm2, %xmm15
        por       %xmm3, %xmm9
        movdqa    .L_2il0floatpacket.120(%rip), %xmm3
        por       %xmm10, %xmm15
        paddd     %xmm3, %xmm13
        pxor      %xmm7, %xmm15
        paddd     %xmm15, %xmm13
        movdqa    %xmm11, %xmm15
        paddd     %xmm12, %xmm5
        pandn     %xmm2, %xmm15
        paddd     %xmm3, %xmm1
        por       %xmm5, %xmm15
        paddd     %xmm3, %xmm14
        movdqa    %xmm8, %xmm3
        paddd     %xmm4, %xmm9
        pxor      %xmm12, %xmm15
        pandn     %xmm2, %xmm3
        paddd     %xmm15, %xmm1
        por       %xmm9, %xmm3
        paddd     176(%rsp), %xmm1
        pxor      %xmm4, %xmm3
        paddd     %xmm3, %xmm14
        movdqa    %xmm1, %xmm3
        paddd     208(%rsp), %xmm13
        pslld     $21, %xmm3
        paddd     160(%rsp), %xmm14
        psrld     $11, %xmm1
        movdqa    %xmm13, %xmm15
        por       %xmm1, %xmm3
        movdqa    %xmm14, %xmm1
        pslld     $21, %xmm15
        psrld     $11, %xmm13
        pslld     $21, %xmm1
        psrld     $11, %xmm14
        por       %xmm13, %xmm15
        por       %xmm14, %xmm1
        movdqa    %xmm7, %xmm14
        paddd     %xmm10, %xmm15
        pandn     %xmm2, %xmm14
        movdqa    .L_2il0floatpacket.121(%rip), %xmm13
        por       %xmm15, %xmm14
        paddd     %xmm13, %xmm0
        pxor      %xmm10, %xmm14
        paddd     %xmm14, %xmm0
        movdqa    %xmm12, %xmm14
        paddd     %xmm5, %xmm3
        pandn     %xmm2, %xmm14
        paddd     %xmm13, %xmm11
        por       %xmm3, %xmm14
        paddd     %xmm13, %xmm8
        movdqa    %xmm4, %xmm13
        paddd     432(%rsp), %xmm0
        paddd     %xmm9, %xmm1
        pxor      %xmm5, %xmm14
        pandn     %xmm2, %xmm13
        paddd     %xmm14, %xmm11
        por       %xmm1, %xmm13
        movdqa    %xmm0, %xmm14
        pxor      %xmm9, %xmm13
        paddd     416(%rsp), %xmm11
        pslld     $6, %xmm14
        psrld     $26, %xmm0
        paddd     %xmm13, %xmm8
        por       %xmm0, %xmm14
        movdqa    %xmm11, %xmm0
        paddd     400(%rsp), %xmm8
        pslld     $6, %xmm0
        psrld     $26, %xmm11
        paddd     %xmm15, %xmm14
        por       %xmm11, %xmm0
        movdqa    %xmm8, %xmm11
        pslld     $6, %xmm11
        psrld     $26, %xmm8
        por       %xmm8, %xmm11
        movdqa    %xmm10, %xmm8
        pandn     %xmm2, %xmm8
        paddd     %xmm3, %xmm0
        movdqa    .L_2il0floatpacket.122(%rip), %xmm13
        por       %xmm14, %xmm8
        paddd     %xmm13, %xmm7
        pxor      %xmm15, %xmm8
        paddd     %xmm8, %xmm7
        paddd     %xmm13, %xmm12
        movdqa    %xmm5, %xmm8
        paddd     %xmm13, %xmm4
        movdqa    %xmm9, %xmm13
        paddd     %xmm1, %xmm11
        pandn     %xmm2, %xmm8
        pandn     %xmm2, %xmm13
        por       %xmm0, %xmm8
        por       %xmm11, %xmm13
        paddd     640(%rsp), %xmm7
        pxor      %xmm3, %xmm8
        pxor      %xmm1, %xmm13
        paddd     %xmm8, %xmm12
        paddd     %xmm13, %xmm4
        movdqa    %xmm7, %xmm8
        paddd     752(%rsp), %xmm12
        paddd     %xmm6, %xmm4
        pslld     $10, %xmm8
        psrld     $22, %xmm7
        por       %xmm7, %xmm8
        movdqa    %xmm12, %xmm7
        movdqa    %xmm4, %xmm6
        pslld     $10, %xmm7
        psrld     $22, %xmm12
        pslld     $10, %xmm6
        psrld     $22, %xmm4
        por       %xmm12, %xmm7
        por       %xmm4, %xmm6
        movdqa    %xmm3, %xmm4
        paddd     %xmm0, %xmm7
        pandn     %xmm2, %xmm4
        movdqa    .L_2il0floatpacket.123(%rip), %xmm13
        movdqa    %xmm15, %xmm12
        por       %xmm7, %xmm4
        paddd     %xmm14, %xmm8
        pandn     %xmm2, %xmm12
        paddd     %xmm13, %xmm5
        pxor      %xmm0, %xmm4
        por       %xmm8, %xmm12
        paddd     %xmm4, %xmm5
        movdqa    %xmm1, %xmm4
        paddd     %xmm11, %xmm6
        paddd     %xmm13, %xmm10
        pxor      %xmm14, %xmm12
        pandn     %xmm2, %xmm4
        paddd     %xmm12, %xmm10
        por       %xmm6, %xmm4
        paddd     256(%rsp), %xmm10
        paddd     %xmm13, %xmm9
        pxor      %xmm11, %xmm4
        movdqa    %xmm0, %xmm12
        paddd     %xmm4, %xmm9
        movdqa    %xmm10, %xmm4
        paddd     240(%rsp), %xmm5
        pslld     $15, %xmm4
        psrld     $17, %xmm10
        pandn     %xmm2, %xmm12
        por       %xmm10, %xmm4
        movdqa    %xmm5, %xmm10
        paddd     224(%rsp), %xmm9
        pslld     $15, %xmm10
        psrld     $17, %xmm5
        paddd     %xmm8, %xmm4
        por       %xmm5, %xmm10
        movdqa    %xmm9, %xmm5
        pslld     $15, %xmm5
        psrld     $17, %xmm9
        por       %xmm9, %xmm5
        movdqa    %xmm14, %xmm9
        pandn     %xmm2, %xmm9
        paddd     %xmm7, %xmm10
        movdqa    .L_2il0floatpacket.124(%rip), %xmm13
        por       %xmm4, %xmm9
        paddd     %xmm13, %xmm15
        pxor      %xmm8, %xmm9
        paddd     %xmm9, %xmm15
        movdqa    %xmm11, %xmm9
        paddd     %xmm6, %xmm5
        pandn     %xmm2, %xmm9
        por       %xmm10, %xmm12
        por       %xmm5, %xmm9
        paddd     480(%rsp), %xmm15
        paddd     %xmm13, %xmm3
        pxor      %xmm7, %xmm12
        paddd     %xmm13, %xmm1
        pxor      %xmm6, %xmm9
        paddd     %xmm12, %xmm3
        paddd     %xmm9, %xmm1
        movdqa    %xmm15, %xmm9
        paddd     528(%rsp), %xmm3
        pslld     $21, %xmm9
        psrld     $11, %xmm15
        movdqa    %xmm7, %xmm12
        por       %xmm15, %xmm9
        movdqa    %xmm3, %xmm15
        paddd     544(%rsp), %xmm1
        pslld     $21, %xmm15
        psrld     $11, %xmm3
        paddd     %xmm4, %xmm9
        por       %xmm3, %xmm15
        movdqa    %xmm1, %xmm3
        pslld     $21, %xmm3
        psrld     $11, %xmm1
        por       %xmm1, %xmm3
        movdqa    %xmm8, %xmm1
        pandn     %xmm2, %xmm1
        paddd     %xmm10, %xmm15
        movdqa    .L_2il0floatpacket.125(%rip), %xmm13
        por       %xmm9, %xmm1
        paddd     %xmm13, %xmm14
        pxor      %xmm4, %xmm1
        pandn     %xmm2, %xmm12
        paddd     %xmm1, %xmm14
        por       %xmm15, %xmm12
        movdqa    %xmm6, %xmm1
        paddd     %xmm5, %xmm3
        paddd     %xmm13, %xmm0
        pxor      %xmm10, %xmm12
        pandn     %xmm2, %xmm1
        paddd     %xmm12, %xmm0
        por       %xmm3, %xmm1
        paddd     144(%rsp), %xmm0
        paddd     %xmm13, %xmm11
        pxor      %xmm5, %xmm1
        movdqa    %xmm10, %xmm13
        paddd     %xmm1, %xmm11
        movdqa    %xmm0, %xmm1
        paddd     112(%rsp), %xmm14
        pslld     $6, %xmm1
        paddd     128(%rsp), %xmm11
        psrld     $26, %xmm0
        movdqa    %xmm14, %xmm12
        por       %xmm0, %xmm1
        movdqa    %xmm11, %xmm0
        pslld     $6, %xmm12
        psrld     $26, %xmm14
        pslld     $6, %xmm0
        psrld     $26, %xmm11
        por       %xmm14, %xmm12
        por       %xmm11, %xmm0
        movdqa    %xmm4, %xmm11
        paddd     %xmm9, %xmm12
        pandn     %xmm2, %xmm11
        movdqa    .L_2il0floatpacket.126(%rip), %xmm14
        por       %xmm12, %xmm11
        paddd     %xmm14, %xmm8
        pxor      %xmm9, %xmm11
        paddd     %xmm11, %xmm8
        movdqa    %xmm5, %xmm11
        paddd     %xmm15, %xmm1
        paddd     %xmm3, %xmm0
        pandn     %xmm2, %xmm13
        pandn     %xmm2, %xmm11
        por       %xmm1, %xmm13
        por       %xmm0, %xmm11
        paddd     304(%rsp), %xmm8
        paddd     %xmm14, %xmm7
        pxor      %xmm15, %xmm13
        paddd     %xmm14, %xmm6
        pxor      %xmm3, %xmm11
        paddd     %xmm13, %xmm7
        paddd     %xmm11, %xmm6
        movdqa    %xmm8, %xmm11
        paddd     368(%rsp), %xmm7
        pslld     $10, %xmm11
        psrld     $22, %xmm8
        movdqa    %xmm15, %xmm13
        por       %xmm8, %xmm11
        movdqa    %xmm7, %xmm8
        paddd     384(%rsp), %xmm6
        pslld     $10, %xmm8
        psrld     $22, %xmm7
        paddd     %xmm12, %xmm11
        por       %xmm7, %xmm8
        movdqa    %xmm6, %xmm7
        pslld     $10, %xmm7
        psrld     $22, %xmm6
        por       %xmm6, %xmm7
        movdqa    %xmm9, %xmm6
        pandn     %xmm2, %xmm6
        paddd     %xmm1, %xmm8
        movdqa    .L_2il0floatpacket.127(%rip), %xmm14
        por       %xmm11, %xmm6
        paddd     %xmm14, %xmm4
        pxor      %xmm12, %xmm6
        paddd     %xmm6, %xmm4
        movdqa    %xmm3, %xmm6
        paddd     %xmm0, %xmm7
        pandn     %xmm2, %xmm13
        pandn     %xmm2, %xmm6
        por       %xmm8, %xmm13
        por       %xmm7, %xmm6
        paddd     %xmm14, %xmm10
        paddd     64(%rsp), %xmm4
        pxor      %xmm1, %xmm13
        paddd     %xmm14, %xmm5
        pxor      %xmm0, %xmm6
        paddd     %xmm13, %xmm10
        paddd     %xmm6, %xmm5
        movdqa    %xmm4, %xmm13
        psrld     $17, %xmm4
        paddd     80(%rsp), %xmm5
        pslld     $15, %xmm13
        por       %xmm4, %xmm13
        movdqa    %xmm5, %xmm4
        pslld     $15, %xmm4
        psrld     $17, %xmm5
        por       %xmm5, %xmm4
        movdqa    %xmm12, %xmm5
        paddd     96(%rsp), %xmm10
        paddd     %xmm11, %xmm13
        pandn     %xmm2, %xmm5
        movdqa    %xmm10, %xmm6
        movdqa    .L_2il0floatpacket.128(%rip), %xmm14
        por       %xmm13, %xmm5
        pslld     $15, %xmm6
        psrld     $17, %xmm10
        paddd     %xmm14, %xmm9
        pxor      %xmm11, %xmm5
        por       %xmm10, %xmm6
        paddd     %xmm5, %xmm9
        movdqa    %xmm1, %xmm10
        movdqa    %xmm0, %xmm5
        paddd     %xmm8, %xmm6
        paddd     %xmm7, %xmm4
        pandn     %xmm2, %xmm10
        pandn     %xmm2, %xmm5
        por       %xmm6, %xmm10
        por       %xmm4, %xmm5
        paddd     %xmm14, %xmm15
        pxor      %xmm8, %xmm10
        paddd     %xmm14, %xmm3
        pxor      %xmm7, %xmm5
        paddd     %xmm10, %xmm15
        paddd     %xmm5, %xmm3
        paddd     192(%rsp), %xmm9
        paddd     272(%rsp), %xmm15
        movdqa    %xmm9, %xmm10
        paddd     288(%rsp), %xmm3
        movdqa    %xmm15, %xmm5
        movdqa    %xmm3, %xmm2
        pslld     $21, %xmm10
        psrld     $11, %xmm9
        pslld     $21, %xmm5
        psrld     $11, %xmm15
        pslld     $21, %xmm2
        psrld     $11, %xmm3
        por       %xmm9, %xmm10
        por       %xmm15, %xmm5
        por       %xmm3, %xmm2
        paddd     %xmm13, %xmm10
        paddd     %xmm6, %xmm5
        paddd     %xmm4, %xmm2
        je        ..B6.6
..B6.5:
        movdqa    .L_2il0floatpacket.129(%rip), %xmm3
        movdqa    .L_2il0floatpacket.62(%rip), %xmm9
        paddd     %xmm3, %xmm12
        movdqa    .L_2il0floatpacket.63(%rip), %xmm14
        paddd     %xmm9, %xmm10
        movdqa    .L_2il0floatpacket.64(%rip), %xmm15
        paddd     %xmm14, %xmm13
        paddd     %xmm15, %xmm11
        paddd     %xmm3, %xmm1
        paddd     %xmm9, %xmm5
        paddd     %xmm14, %xmm6
        paddd     %xmm15, %xmm8
        paddd     %xmm3, %xmm0
        paddd     %xmm9, %xmm2
        paddd     %xmm14, %xmm4
        paddd     %xmm15, %xmm7
        movdqa    %xmm12, (%rsi)
        movdqa    %xmm10, 16(%rsi)
        movdqa    %xmm13, 32(%rsi)
        movdqa    %xmm11, 48(%rsi)
        movdqa    %xmm1, 64(%rsi)
        movdqa    %xmm5, 80(%rsi)
        movdqa    %xmm6, 96(%rsi)
        movdqa    %xmm8, 112(%rsi)
        movdqa    %xmm0, 128(%rsi)
        movdqa    %xmm2, 144(%rsi)
        movdqa    %xmm4, 160(%rsi)
        movdqa    %xmm7, 176(%rsi)
        addq      $840, %rsp
..___tag_value_SSEmd5body.115:
        ret       
..___tag_value_SSEmd5body.116:
..B6.6:
        paddd     (%rsp), %xmm12
        paddd     16(%rsp), %xmm10
        paddd     32(%rsp), %xmm13
        paddd     48(%rsp), %xmm11
        paddd     64(%rsi), %xmm1
        paddd     80(%rsi), %xmm5
        paddd     96(%rsi), %xmm6
        paddd     112(%rsi), %xmm8
        paddd     128(%rsi), %xmm0
        paddd     144(%rsi), %xmm2
        paddd     160(%rsi), %xmm4
        paddd     176(%rsi), %xmm7
        movdqa    %xmm12, (%rsi)
        movdqa    %xmm10, 16(%rsi)
        movdqa    %xmm13, 32(%rsi)
        movdqa    %xmm11, 48(%rsi)
        movdqa    %xmm1, 64(%rsi)
        movdqa    %xmm5, 80(%rsi)
        movdqa    %xmm6, 96(%rsi)
        movdqa    %xmm8, 112(%rsi)
        movdqa    %xmm0, 128(%rsi)
        movdqa    %xmm2, 144(%rsi)
        movdqa    %xmm4, 160(%rsi)
        movdqa    %xmm7, 176(%rsi)
..B6.7:
        addq      $840, %rsp
..___tag_value_SSEmd5body.117:
        ret       
        .align    16,0x90
..___tag_value_SSEmd5body.118:
	.type	SSEmd5body,@function
	.size	SSEmd5body,.-SSEmd5body
	.data
# -- End  SSEmd5body
	.text
# -- Begin  md5cryptsse
       .align    16,0x90
	.globl md5cryptsse
md5cryptsse:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B7.1:
..___tag_value_md5cryptsse.119:
        pushq     %r12
..___tag_value_md5cryptsse.121:
        pushq     %r13
..___tag_value_md5cryptsse.123:
        pushq     %r14
..___tag_value_md5cryptsse.125:
        pushq     %r15
..___tag_value_md5cryptsse.127:
        pushq     %rbx
..___tag_value_md5cryptsse.129:
        pushq     %rbp
..___tag_value_md5cryptsse.131:
        subq      $6888, %rsp
..___tag_value_md5cryptsse.133:
        movq      %rdx, %rbp
        movq      %rsi, %r13
        movq      %rdi, %r12
        xorl      %esi, %esi
        lea       6304(%rsp), %rdi
        movl      $192, %edx
        movl      %ecx, %r14d
..___tag_value_md5cryptsse.134:
        call      memset
..___tag_value_md5cryptsse.135:
..B7.2:
        xorl      %esi, %esi
        lea       (%rsp), %rdi
        movl      $6144, %edx
..___tag_value_md5cryptsse.136:
        call      memset
..___tag_value_md5cryptsse.137:
..B7.3:
        movq      %r13, %rdi
..___tag_value_md5cryptsse.138:
        call      strlen
..___tag_value_md5cryptsse.139:
..B7.4:
        movl      %eax, %r15d
        movl      $-4, %r9d
        movl      %eax, %edi
        movl      $16, %eax
        movdqa    .L_2il0floatpacket.454(%rip), %xmm1
        xorl      %ebx, %ebx
        movq      %rdi, 6840(%rsp)
        movd      %r9d, %xmm0
        lea       16(%r15), %r10d
        pshufd    $0, %xmm0, %xmm2
        lea       17(%r15), %r11d
        movd      %eax, %xmm3
        lea       18(%r15), %r9d
        movl      %r15d, %eax
        lea       20(%r15), %edx
        movd      %r10d, %xmm0
        lea       24(%r15), %ecx
        movd      %r11d, %xmm4
        lea       28(%r15), %esi
        movd      %r9d, %xmm6
        lea       22(%r15), %r9d
        punpcklqdq %xmm4, %xmm0
        lea       (,%r15,8), %r8d
        pshufd    $0, %xmm3, %xmm3
        andl      $-16, %eax
        movd      %esi, %xmm4
        lea       19(%r15), %r10d
        movd      %r9d, %xmm9
        lea       21(%r15), %r11d
        movdqa    %xmm2, 6720(%rsp)
        lea       26(%r15), %r9d
        movdqa    %xmm3, 6704(%rsp)
        lea       31(%r15), %esi
        movd      %r10d, %xmm5
        punpcklqdq %xmm5, %xmm6
        movd      %ecx, %xmm5
        shufps    $136, %xmm6, %xmm0
        movd      %edx, %xmm6
        movd      %r11d, %xmm7
        lea       23(%r15), %edx
        movd      %r9d, %xmm12
        lea       27(%r15), %ecx
        movd      %esi, %xmm14
        punpcklqdq %xmm7, %xmm6
        movd      %edx, %xmm8
        lea       25(%r15), %edx
        movd      %ecx, %xmm11
        lea       30(%r15), %ecx
        punpcklqdq %xmm8, %xmm9
        punpcklqdq %xmm11, %xmm12
        movd      %edx, %xmm10
        lea       29(%r15), %edx
        movd      %ecx, %xmm15
        punpcklqdq %xmm10, %xmm5
        punpcklqdq %xmm14, %xmm15
        movd      %edx, %xmm13
        punpcklqdq %xmm13, %xmm4
        shufps    $136, %xmm9, %xmm6
        shufps    $136, %xmm12, %xmm5
        shufps    $136, %xmm15, %xmm4
        movaps    %xmm4, 6784(%rsp)
        movaps    %xmm5, 6768(%rsp)
        movaps    %xmm6, 6752(%rsp)
        movaps    %xmm0, 6736(%rsp)
        movl      %eax, 6696(%rsp)
        movl      %r8d, 6848(%rsp)
        movq      %r12, 6856(%rsp)
        movq      %r13, 6864(%rsp)
        movq      %rbp, 6296(%rsp)
        movl      %r14d, 6872(%rsp)
..B7.5:
        movl      %ebx, %edi
        shlq      $4, %rdi
        addq      6856(%rsp), %rdi
        movq      %rdi, 6880(%rsp)
..___tag_value_md5cryptsse.140:
        call      strlen
..___tag_value_md5cryptsse.141:
..B7.259:
        movq      %rax, %rbp
..B7.6:
        movl      %ebx, %r13d
        movl      %ebx, %r14d
        shrl      $2, %r13d
        movl      %ebp, %r12d
        movl      %r13d, %eax
        andl      $3, %r14d
        shll      $8, %eax
        testl     %r12d, %r12d
        lea       (%rsp,%rax), %rcx
        jbe       ..B7.15
..B7.7:
        cmpl      $16, %r12d
        jb        ..B7.238
..B7.8:
        movl      %r12d, %edi
        xorl      %edx, %edx
        movd      %r14d, %xmm0
        andl      $-16, %edi
        movdqa    .L_2il0floatpacket.459(%rip), %xmm6
        movdqa    .L_2il0floatpacket.460(%rip), %xmm5
        movdqa    .L_2il0floatpacket.461(%rip), %xmm4
        movdqa    .L_2il0floatpacket.462(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %rsi
..B7.9:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r8d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rdx,%rsi), %xmm1
        movd      %xmm2, %r10d
        movd      %xmm1, %r9d
        paddd     %xmm11, %xmm14
        psrldq    $1, %xmm1
        movdqa    %xmm4, %xmm15
        psrldq    $4, %xmm2
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movd      %xmm1, %r11d
        pslld     $2, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm7, %xmm12
        paddd     %xmm12, %xmm15
        movdqa    %xmm3, %xmm10
        movb      %r9b, (%r8,%rcx)
        pand      %xmm8, %xmm10
        movd      %xmm2, %r8d
        paddd     %xmm0, %xmm10
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        movb      %r11b, (%r10,%rcx)
        paddd     %xmm13, %xmm10
        movd      %xmm2, %r11d
        addl      $16, %edx
        movd      %xmm1, %r9d
        paddd     %xmm9, %xmm6
        psrldq    $1, %xmm1
        paddd     %xmm9, %xmm5
        paddd     %xmm9, %xmm4
        paddd     %xmm9, %xmm3
        cmpl      %edi, %edx
        movb      %r9b, (%r8,%rcx)
        movd      %xmm1, %r8d
        movd      %xmm14, %r9d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r8b, (%r11,%rcx)
        movd      %xmm14, %r8d
        psrldq    $4, %xmm14
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        psrldq    $4, %xmm14
        movb      %r10b, (%r9,%rcx)
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movd      %xmm14, %r9d
        movb      %r10b, (%r8,%rcx)
        movd      %xmm1, %r8d
        psrldq    $1, %xmm1
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r8b, (%r11,%rcx)
        movd      %xmm15, %r8d
        psrldq    $4, %xmm15
        movd      %xmm15, %r11d
        psrldq    $4, %xmm15
        movb      %r10b, (%r9,%rcx)
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movd      %xmm15, %r9d
        psrldq    $4, %xmm15
        movb      %r10b, (%r8,%rcx)
        movd      %xmm1, %r8d
        psrldq    $1, %xmm1
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r8b, (%r11,%rcx)
        movd      %xmm15, %r8d
        movd      %xmm10, %r11d
        psrldq    $4, %xmm10
        movb      %r10b, (%r9,%rcx)
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movd      %xmm10, %r9d
        psrldq    $4, %xmm10
        movb      %r10b, (%r8,%rcx)
        movd      %xmm1, %r8d
        psrldq    $1, %xmm1
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r8b, (%r11,%rcx)
        movd      %xmm10, %r8d
        psrldq    $4, %xmm10
        movd      %xmm10, %r11d
        movb      %r10b, (%r9,%rcx)
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, (%r8,%rcx)
        movd      %xmm1, %r8d
        movb      %r8b, (%r11,%rcx)
        jb        ..B7.9
..B7.11:
        cmpl      %r12d, %edi
        jae       ..B7.15
..B7.12:
        movq      6880(%rsp), %rdx
..B7.13:
        lea       16(%rdi), %r8d
        movl      %r8d, %esi
        andl      $3, %r8d
        andl      $-4, %esi
        shll      $2, %esi
        movb      (%rdi,%rdx), %r10b
        incl      %edi
        lea       (%rsi,%r14,4), %r9d
        addl      %r8d, %r9d
        cmpl      %r12d, %edi
        movb      %r10b, (%r9,%rcx)
        jb        ..B7.13
..B7.15:
        lea       16(%r12), %esi
        movl      %esi, %edi
        movl      %esi, %edx
        andl      $-4, %edi
        andl      $3, %edx
        addl      %r14d, %edi
        testl     %r12d, %r12d
        lea       (%rdx,%rdi,4), %r9d
        movb      $128, (%r9,%rcx)
        jbe       ..B7.24
..B7.16:
        cmpl      $16, %r12d
        jb        ..B7.239
..B7.17:
        movl      %r12d, %r8d
        xorl      %edi, %edi
        movd      %r14d, %xmm0
        andl      $-16, %r8d
        movdqa    .L_2il0floatpacket.455(%rip), %xmm6
        movdqa    .L_2il0floatpacket.456(%rip), %xmm5
        movdqa    .L_2il0floatpacket.457(%rip), %xmm4
        movdqa    .L_2il0floatpacket.458(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %rdx
..B7.18:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r10d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rdi,%rdx), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r11d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r11b, 768(%r10,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r11d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r10d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %edi
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r10b, 768(%r11,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r10d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r11d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r8d, %edi
        movb      %r11b, 768(%r10,%rcx)
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 768(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 768(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r10b, 768(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 768(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 768(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 768(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r10b, 768(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 768(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 768(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 768(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r10b, 768(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 768(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        movb      %r10b, 768(%r11,%rcx)
        jb        ..B7.18
..B7.20:
        cmpl      %r12d, %r8d
        jae       ..B7.23
..B7.21:
        movq      6880(%rsp), %rdx
..B7.22:
        movl      %r8d, %edi
        movl      %r8d, %r10d
        andl      $-4, %edi
        andl      $3, %r10d
        shll      $2, %edi
        lea       (%rdi,%r14,4), %r11d
        movb      (%r8,%rdx), %dil
        addl      %r10d, %r11d
        incl      %r8d
        cmpl      %r12d, %r8d
        movb      %dil, 768(%r11,%rcx)
        jb        ..B7.22
..B7.23:
        testl     %r12d, %r12d
..B7.24:
        movb      $128, 768(%r9,%rcx)
        jbe       ..B7.37
..B7.25:
        cmpl      $16, %r12d
        jb        ..B7.240
..B7.26:
        movl      %r12d, %r8d
        xorl      %edx, %edx
        movd      %r14d, %xmm0
        andl      $-16, %r8d
        movdqa    .L_2il0floatpacket.455(%rip), %xmm6
        movdqa    .L_2il0floatpacket.456(%rip), %xmm5
        movdqa    .L_2il0floatpacket.457(%rip), %xmm4
        movdqa    .L_2il0floatpacket.458(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %rdi
..B7.27:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r9d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rdx,%rdi), %xmm1
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        paddd     %xmm11, %xmm14
        psrldq    $1, %xmm1
        movdqa    %xmm4, %xmm15
        psrldq    $4, %xmm2
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        pslld     $2, %xmm15
        pand      %xmm7, %xmm12
        paddd     %xmm12, %xmm15
        movdqa    %xmm3, %xmm10
        movb      %r10b, 1536(%r9,%rcx)
        pand      %xmm8, %xmm10
        movd      %xmm1, %r9d
        paddd     %xmm0, %xmm10
        movd      %xmm2, %r10d
        movdqa    %xmm3, %xmm13
        psrldq    $4, %xmm2
        pslld     $2, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm7, %xmm13
        movb      %r9b, 1536(%r11,%rcx)
        paddd     %xmm13, %xmm10
        movd      %xmm2, %r11d
        addl      $16, %edx
        movd      %xmm1, %r9d
        paddd     %xmm9, %xmm6
        psrldq    $1, %xmm1
        paddd     %xmm9, %xmm5
        paddd     %xmm9, %xmm4
        paddd     %xmm9, %xmm3
        cmpl      %r8d, %edx
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm14, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        psrldq    $4, %xmm14
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm14, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm15, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        psrldq    $4, %xmm15
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm15, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm10, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        psrldq    $4, %xmm10
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm10, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        .byte     144
        movb      %r9b, 1536(%r11,%rcx)
        jb        ..B7.27
..B7.29:
        cmpl      %r12d, %r8d
        jae       ..B7.33
..B7.30:
        movq      6880(%rsp), %rdx
..B7.31:
        movl      %r8d, %edi
        movl      %r8d, %r9d
        andl      $-4, %edi
        andl      $3, %r9d
        shll      $2, %edi
        movb      (%r8,%rdx), %r11b
        incl      %r8d
        lea       (%rdi,%r14,4), %r10d
        addl      %r9d, %r10d
        cmpl      %r12d, %r8d
        movb      %r11b, 1536(%r10,%rcx)
        jb        ..B7.31
..B7.33:
        cmpl      $16, %r12d
        jb        ..B7.38
..B7.34:
        movd      %r12d, %xmm6
        lea       1(%r12), %edx
        movl      %r12d, %r8d
        lea       2(%r12), %edi
        movd      %r14d, %xmm13
        lea       3(%r12), %r9d
        andl      $-16, %r8d
        lea       4(%r12), %r10d
        movd      %edx, %xmm5
        lea       5(%r12), %r11d
        punpcklqdq %xmm5, %xmm6
        movd      %edi, %xmm3
        movd      %r9d, %xmm4
        lea       6(%r12), %edx
        movd      %r10d, %xmm5
        lea       7(%r12), %edi
        movd      %r11d, %xmm0
        lea       8(%r12), %r9d
        punpcklqdq %xmm4, %xmm3
        lea       9(%r12), %r10d
        movd      %edx, %xmm2
        lea       10(%r12), %r11d
        movd      %edi, %xmm1
        lea       11(%r12), %edx
        movd      %r9d, %xmm4
        lea       12(%r12), %edi
        movd      %r10d, %xmm7
        lea       13(%r12), %r9d
        movd      %r11d, %xmm9
        lea       14(%r12), %r10d
        shufps    $136, %xmm3, %xmm6
        lea       15(%r12), %r11d
        movd      %edx, %xmm8
        movd      %edi, %xmm3
        movd      %r9d, %xmm10
        xorl      %edx, %edx
        movd      %r10d, %xmm12
        movd      %r11d, %xmm11
        punpcklqdq %xmm0, %xmm5
        punpcklqdq %xmm1, %xmm2
        punpcklqdq %xmm7, %xmm4
        punpcklqdq %xmm8, %xmm9
        punpcklqdq %xmm10, %xmm3
        punpcklqdq %xmm11, %xmm12
        shufps    $136, %xmm2, %xmm5
        shufps    $136, %xmm9, %xmm4
        shufps    $136, %xmm12, %xmm3
        pshufd    $0, %xmm13, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %rdi
..B7.35:
        movaps    %xmm6, %xmm2
        movaps    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movaps    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r9d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movaps    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rdx,%rdi), %xmm1
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        paddd     %xmm11, %xmm14
        psrldq    $1, %xmm1
        movaps    %xmm4, %xmm15
        psrldq    $4, %xmm2
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movaps    %xmm4, %xmm12
        pslld     $2, %xmm15
        pand      %xmm7, %xmm12
        paddd     %xmm12, %xmm15
        movaps    %xmm3, %xmm10
        movb      %r10b, 1536(%r9,%rcx)
        pand      %xmm8, %xmm10
        movd      %xmm1, %r9d
        paddd     %xmm0, %xmm10
        movd      %xmm2, %r10d
        movaps    %xmm3, %xmm13
        psrldq    $4, %xmm2
        pslld     $2, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm7, %xmm13
        movb      %r9b, 1536(%r11,%rcx)
        paddd     %xmm13, %xmm10
        movd      %xmm2, %r11d
        addl      $16, %edx
        movd      %xmm1, %r9d
        paddd     %xmm9, %xmm6
        psrldq    $1, %xmm1
        paddd     %xmm9, %xmm5
        paddd     %xmm9, %xmm4
        paddd     %xmm9, %xmm3
        cmpl      %r8d, %edx
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm14, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        psrldq    $4, %xmm14
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm14, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm15, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        psrldq    $4, %xmm15
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm15, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm10, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        psrldq    $4, %xmm10
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        movd      %xmm10, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r11,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r9d
        psrldq    $1, %xmm1
        movb      %r9b, 1536(%r10,%rcx)
        movd      %xmm1, %r9d
        .byte     144
        movb      %r9b, 1536(%r11,%rcx)
        jb        ..B7.35
        jmp       ..B7.39
..B7.37:
        jbe       ..B7.43
..B7.38:
        xorl      %r8d, %r8d
..B7.39:
        cmpl      %r12d, %r8d
        jae       ..B7.43
..B7.40:
        movq      6880(%rsp), %rdx
..B7.41:
        lea       (%r12,%r8), %r9d
        movl      %r9d, %edi
        andl      $3, %r9d
        andl      $-4, %edi
        shll      $2, %edi
        movb      (%r8,%rdx), %r11b
        incl      %r8d
        lea       (%rdi,%r14,4), %r10d
        addl      %r9d, %r10d
        cmpl      %r12d, %r8d
        movb      %r11b, 1536(%r10,%rcx)
        jb        ..B7.41
..B7.43:
        lea       16(%r12,%r12), %edx
        movl      %edx, %r8d
        andl      $3, %edx
        andl      $-4, %r8d
        lea       (%r12,%r12), %edi
        addl      %r14d, %r8d
        testl     %r12d, %r12d
        lea       (%rdx,%r8,4), %edx
        movb      $128, 1536(%rdx,%rcx)
        jbe       ..B7.56
..B7.44:
        cmpl      $16, %r12d
        jb        ..B7.241
..B7.45:
        movl      %r12d, %r10d
        xorl      %r9d, %r9d
        movd      %r14d, %xmm0
        andl      $-16, %r10d
        movdqa    .L_2il0floatpacket.459(%rip), %xmm6
        movdqa    .L_2il0floatpacket.460(%rip), %xmm5
        movdqa    .L_2il0floatpacket.461(%rip), %xmm4
        movdqa    .L_2il0floatpacket.462(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movl      %r15d, 6816(%rsp)
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %r8
..B7.46:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r11d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r9,%r8), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r15d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r15b, 2304(%r11,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r15d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r11d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r9d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r11b, 2304(%r15,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r11d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r15d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r10d, %r9d
        movb      %r15b, 2304(%r11,%rcx)
        movd      %xmm2, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 2304(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 2304(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 2304(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 2304(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 2304(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 2304(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        movb      %r11b, 2304(%r15,%rcx)
        jb        ..B7.46
..B7.47:
        movl      6816(%rsp), %r15d
..B7.48:
        cmpl      %r12d, %r10d
        jae       ..B7.52
..B7.49:
        movl      %r15d, 6816(%rsp)
        movq      6880(%rsp), %r8
..B7.50:
        lea       16(%r10), %r9d
        movl      %r9d, %r11d
        andl      $3, %r9d
        andl      $-4, %r11d
        shll      $2, %r11d
        lea       (%r11,%r14,4), %r15d
        addl      %r9d, %r15d
        movb      (%r10,%r8), %r9b
        incl      %r10d
        cmpl      %r12d, %r10d
        movb      %r9b, 2304(%r15,%rcx)
        jb        ..B7.50
..B7.51:
        movl      6816(%rsp), %r15d
..B7.52:
        cmpl      $16, %r12d
        jb        ..B7.57
..B7.53:
        movd      %esi, %xmm6
        lea       17(%r12), %r8d
        movl      %r12d, %r9d
        lea       18(%r12), %r10d
        movd      %r14d, %xmm13
        lea       19(%r12), %esi
        andl      $-16, %r9d
        lea       20(%r12), %r11d
        movd      %r8d, %xmm5
        lea       22(%r12), %r8d
        movd      %r10d, %xmm3
        lea       23(%r12), %r10d
        movd      %esi, %xmm4
        lea       21(%r12), %esi
        punpcklqdq %xmm5, %xmm6
        movd      %r11d, %xmm5
        movd      %r8d, %xmm2
        lea       24(%r12), %r11d
        movd      %r10d, %xmm1
        lea       26(%r12), %r8d
        movd      %esi, %xmm0
        lea       25(%r12), %esi
        punpcklqdq %xmm4, %xmm3
        lea       27(%r12), %r10d
        movd      %r11d, %xmm4
        lea       28(%r12), %r11d
        movd      %r8d, %xmm9
        lea       30(%r12), %r8d
        movd      %esi, %xmm7
        lea       29(%r12), %esi
        movd      %r10d, %xmm8
        lea       31(%r12), %r10d
        shufps    $136, %xmm3, %xmm6
        movd      %r11d, %xmm3
        movd      %r8d, %xmm12
        movd      %esi, %xmm10
        xorl      %esi, %esi
        movd      %r10d, %xmm11
        punpcklqdq %xmm0, %xmm5
        punpcklqdq %xmm1, %xmm2
        punpcklqdq %xmm7, %xmm4
        punpcklqdq %xmm8, %xmm9
        punpcklqdq %xmm10, %xmm3
        punpcklqdq %xmm11, %xmm12
        shufps    $136, %xmm2, %xmm5
        shufps    $136, %xmm9, %xmm4
        shufps    $136, %xmm12, %xmm3
        pshufd    $0, %xmm13, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %r8
..B7.54:
        movaps    %xmm6, %xmm2
        movaps    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movaps    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r10d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movaps    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rsi,%r8), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r11d
        movaps    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movaps    %xmm4, %xmm12
        movb      %r11b, 2304(%r10,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r11d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r10d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movaps    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movaps    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %esi
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r10b, 2304(%r11,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r10d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r11d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r9d, %esi
        movb      %r11b, 2304(%r10,%rcx)
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 2304(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r10b, 2304(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 2304(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r10b, 2304(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 2304(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r10b, 2304(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 2304(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        movb      %r10b, 2304(%r11,%rcx)
        jb        ..B7.54
        jmp       ..B7.58
..B7.56:
        jbe       ..B7.71
..B7.57:
        xorl      %r9d, %r9d
..B7.58:
        cmpl      %r12d, %r9d
        lea       (%r12,%r9), %r10d
        jae       ..B7.62
..B7.59:
        movl      %r15d, 6816(%rsp)
        movq      6880(%rsp), %rsi
..B7.60:
        lea       16(%r10), %r8d
        movl      %r8d, %r11d
        andl      $3, %r8d
        andl      $-4, %r11d
        incl      %r10d
        shll      $2, %r11d
        lea       (%r11,%r14,4), %r15d
        addl      %r8d, %r15d
        movb      (%r9,%rsi), %r8b
        incl      %r9d
        cmpl      %r12d, %r9d
        movb      %r8b, 2304(%r15,%rcx)
        jb        ..B7.60
..B7.61:
        movl      6816(%rsp), %r15d
..B7.62:
        movb      $128, 2304(%rdx,%rcx)
        lea       3072(%rsp,%rax), %rdx
        testl     %r12d, %r12d
        jbe       ..B7.72
..B7.63:
        cmpl      $16, %r12d
        jb        ..B7.242
..B7.64:
        movl      %r12d, %r9d
        xorl      %esi, %esi
        movd      %r14d, %xmm0
        andl      $-16, %r9d
        movdqa    .L_2il0floatpacket.455(%rip), %xmm6
        movdqa    .L_2il0floatpacket.456(%rip), %xmm5
        movdqa    .L_2il0floatpacket.457(%rip), %xmm4
        movdqa    .L_2il0floatpacket.458(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %r8
..B7.65:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r10d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rsi,%r8), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r11d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r11b, (%r10,%rdx)
        pslld     $2, %xmm15
        movd      %xmm2, %r11d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r10d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %esi
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r10b, (%r11,%rdx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r10d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r11d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r9d, %esi
        movb      %r11b, (%r10,%rdx)
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rdx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rdx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rdx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rdx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rdx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rdx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rdx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rdx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rdx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rdx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rdx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rdx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        movb      %r10b, (%r11,%rdx)
        jb        ..B7.65
..B7.67:
        cmpl      %r12d, %r9d
        jae       ..B7.72
..B7.68:
        movq      6880(%rsp), %rsi
..B7.69:
        movl      %r9d, %r8d
        movl      %r9d, %r10d
        andl      $-4, %r8d
        andl      $3, %r10d
        shll      $2, %r8d
        lea       (%r8,%r14,4), %r11d
        movb      (%r9,%rsi), %r8b
        addl      %r10d, %r11d
        incl      %r9d
        cmpl      %r12d, %r9d
        movb      %r8b, (%r11,%rdx)
        jb        ..B7.69
        jmp       ..B7.72
..B7.71:
        movb      $128, 2304(%rdx,%rcx)
        lea       3072(%rsp,%rax), %rdx
..B7.72:
        testl     %r15d, %r15d
        jbe       ..B7.81
..B7.73:
        cmpl      $16, %r15d
        jb        ..B7.243
..B7.74:
        movd      %r12d, %xmm6
        lea       1(%r12), %esi
        movd      %r14d, %xmm13
        lea       2(%r12), %r8d
        movl      6696(%rsp), %r10d
        lea       3(%r12), %r9d
        movl      %r15d, 6816(%rsp)
        lea       4(%r12), %r11d
        movd      %esi, %xmm5
        lea       5(%r12), %esi
        movd      %r8d, %xmm3
        lea       6(%r12), %r8d
        movd      %r9d, %xmm4
        lea       7(%r12), %r9d
        punpcklqdq %xmm5, %xmm6
        movd      %r11d, %xmm5
        movd      %esi, %xmm0
        lea       8(%r12), %r11d
        movd      %r8d, %xmm2
        lea       9(%r12), %esi
        movd      %r9d, %xmm1
        lea       10(%r12), %r8d
        punpcklqdq %xmm4, %xmm3
        lea       11(%r12), %r9d
        movd      %r11d, %xmm4
        lea       12(%r12), %r11d
        movd      %esi, %xmm7
        lea       13(%r12), %esi
        movd      %r8d, %xmm9
        lea       14(%r12), %r8d
        movd      %r9d, %xmm8
        lea       15(%r12), %r9d
        shufps    $136, %xmm3, %xmm6
        movd      %r11d, %xmm3
        movd      %esi, %xmm10
        movd      %r8d, %xmm12
        movl      %r10d, %r8d
        movd      %r9d, %xmm11
        xorl      %r9d, %r9d
        punpcklqdq %xmm0, %xmm5
        punpcklqdq %xmm1, %xmm2
        punpcklqdq %xmm7, %xmm4
        punpcklqdq %xmm8, %xmm9
        punpcklqdq %xmm10, %xmm3
        punpcklqdq %xmm11, %xmm12
        shufps    $136, %xmm2, %xmm5
        shufps    $136, %xmm9, %xmm4
        shufps    $136, %xmm12, %xmm3
        pshufd    $0, %xmm13, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6864(%rsp), %rsi
..B7.75:
        movaps    %xmm6, %xmm2
        movaps    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movaps    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r11d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movaps    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r9,%rsi), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r15d
        movaps    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movaps    %xmm4, %xmm12
        movb      %r15b, (%r11,%rdx)
        pslld     $2, %xmm15
        movd      %xmm2, %r15d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r11d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movaps    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movaps    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r9d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r11b, (%r15,%rdx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r11d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r15d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r8d, %r9d
        movb      %r15b, (%r11,%rdx)
        movd      %xmm2, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rdx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rdx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rdx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rdx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rdx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rdx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rdx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rdx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rdx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rdx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rdx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rdx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        movb      %r11b, (%r15,%rdx)
        jb        ..B7.75
..B7.76:
        movl      6816(%rsp), %r15d
..B7.77:
        cmpl      %r15d, %r10d
        jae       ..B7.81
..B7.78:
        movq      6864(%rsp), %rsi
..B7.79:
        lea       (%r12,%r10), %r8d
        movl      %r8d, %r9d
        andl      $3, %r8d
        andl      $-4, %r9d
        shll      $2, %r9d
        lea       (%r9,%r14,4), %r11d
        addl      %r8d, %r11d
        movb      (%r10,%rsi), %r8b
        incl      %r10d
        cmpl      %r15d, %r10d
        movb      %r8b, (%r11,%rdx)
        jb        ..B7.79
..B7.81:
        lea       16(%r12,%r15), %edx
        movl      %edx, %r9d
        movl      %edx, %r8d
        andl      $-4, %r9d
        andl      $3, %r8d
        addl      %r14d, %r9d
        lea       (%r12,%r15), %esi
        testl     %r15d, %r15d
        lea       (%r8,%r9,4), %r10d
        movb      $128, 3072(%r10,%rcx)
        jbe       ..B7.91
..B7.82:
        cmpl      $16, %r15d
        jb        ..B7.246
..B7.83:
        xorl      %r8d, %r8d
        movd      %r14d, %xmm0
        movl      6696(%rsp), %r9d
        movl      %ebx, 6832(%rsp)
        movdqa    .L_2il0floatpacket.459(%rip), %xmm6
        movdqa    .L_2il0floatpacket.460(%rip), %xmm5
        movdqa    .L_2il0floatpacket.461(%rip), %xmm4
        movdqa    .L_2il0floatpacket.462(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movq      %rbp, 6824(%rsp)
        movl      %r9d, %ebp
        movl      %r15d, 6816(%rsp)
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6864(%rsp), %rbx
..B7.84:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r11d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r8,%rbx), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r15d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r15b, 3840(%r11,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r15d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r11d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r8d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r11b, 3840(%r15,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r11d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r15d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %ebp, %r8d
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm2, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        movb      %r11b, 3840(%r15,%rcx)
        jb        ..B7.84
..B7.85:
        movq      6824(%rsp), %rbp
        movl      6832(%rsp), %ebx
        movl      6816(%rsp), %r15d
..B7.86:
        cmpl      %r15d, %r9d
        jae       ..B7.244
..B7.87:
        movl      %ebx, 6832(%rsp)
        movq      %rbp, 6824(%rsp)
        movq      6864(%rsp), %rbx
..B7.88:
        lea       16(%r9), %ebp
        movl      %ebp, %r8d
        andl      $3, %ebp
        andl      $-4, %r8d
        shll      $2, %r8d
        lea       (%r8,%r14,4), %r11d
        addl      %ebp, %r11d
        movb      (%r9,%rbx), %bpl
        incl      %r9d
        cmpl      %r15d, %r9d
        movb      %bpl, 3840(%r11,%rcx)
        jb        ..B7.88
..B7.89:
        movq      6824(%rsp), %rbp
        testl     %r12d, %r12d
        movl      6832(%rsp), %ebx
        ja        ..B7.92
..B7.90:
        movb      $128, 3840(%r10,%rcx)
        lea       4608(%rsp,%rax), %rax
        jmp       ..B7.101
..B7.91:
        testl     %r12d, %r12d
        jbe       ..B7.109
..B7.92:
        cmpl      $16, %r12d
        jb        ..B7.248
..B7.93:
        movl      %r12d, %r8d
        xorl      %r9d, %r9d
        movd      %r14d, %xmm0
        andl      $-16, %r8d
        movl      %ebx, 6832(%rsp)
        movaps    6736(%rsp), %xmm6
        movaps    6752(%rsp), %xmm5
        movaps    6768(%rsp), %xmm4
        movaps    6784(%rsp), %xmm3
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %rbx
        pshufd    $0, %xmm0, %xmm0
        movl      %r15d, 6816(%rsp)
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
..B7.94:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r11d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r9,%rbx), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r15d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r15b, 3840(%r11,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r15d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r11d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r9d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r11b, 3840(%r15,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r11d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r15d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r8d, %r9d
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm2, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 3840(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 3840(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        movb      %r11b, 3840(%r15,%rcx)
        jb        ..B7.94
..B7.95:
        movl      6832(%rsp), %ebx
        movl      6816(%rsp), %r15d
..B7.96:
        cmpl      %r12d, %r8d
        lea       (%r15,%r8), %r9d
        jae       ..B7.100
..B7.97:
        movl      %ebx, 6832(%rsp)
        movq      %rbp, 6824(%rsp)
        movl      %r15d, 6816(%rsp)
        movq      6880(%rsp), %rbx
..B7.98:
        lea       16(%r9), %ebp
        movl      %ebp, %r11d
        andl      $3, %ebp
        andl      $-4, %r11d
        incl      %r9d
        shll      $2, %r11d
        lea       (%r11,%r14,4), %r15d
        addl      %ebp, %r15d
        movb      (%r8,%rbx), %bpl
        incl      %r8d
        cmpl      %r12d, %r8d
        movb      %bpl, 3840(%r15,%rcx)
        jb        ..B7.98
..B7.99:
        movq      6824(%rsp), %rbp
        movl      6832(%rsp), %ebx
        movl      6816(%rsp), %r15d
..B7.100:
        movb      $128, 3840(%r10,%rcx)
        lea       4608(%rsp,%rax), %rax
        testl     %r15d, %r15d
        jbe       ..B7.260
..B7.101:
        cmpl      $16, %r15d
        jb        ..B7.247
..B7.102:
        xorl      %r9d, %r9d
        movd      %r14d, %xmm0
        movl      6696(%rsp), %r10d
        movl      %r10d, %r8d
        movl      %ebx, 6832(%rsp)
        movdqa    .L_2il0floatpacket.459(%rip), %xmm6
        movdqa    .L_2il0floatpacket.460(%rip), %xmm5
        movdqa    .L_2il0floatpacket.461(%rip), %xmm4
        movdqa    .L_2il0floatpacket.462(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movl      %r15d, 6816(%rsp)
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6864(%rsp), %rbx
..B7.103:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r11d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r9,%rbx), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r15d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r15b, (%r11,%rax)
        pslld     $2, %xmm15
        movd      %xmm2, %r15d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r11d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r9d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r11b, (%r15,%rax)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r11d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r15d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r8d, %r9d
        movb      %r15b, (%r11,%rax)
        movd      %xmm2, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        movb      %r11b, (%r15,%rax)
        jb        ..B7.103
..B7.104:
        movl      6832(%rsp), %ebx
        movl      6816(%rsp), %r15d
..B7.105:
        cmpl      %r15d, %r10d
        jae       ..B7.260
..B7.106:
        movl      %ebx, 6832(%rsp)
        movq      6864(%rsp), %rbx
..B7.107:
        lea       16(%r10), %r8d
        movl      %r8d, %r9d
        andl      $3, %r8d
        andl      $-4, %r9d
        shll      $2, %r9d
        lea       (%r9,%r14,4), %r11d
        addl      %r8d, %r11d
        movb      (%r10,%rbx), %r8b
        incl      %r10d
        cmpl      %r15d, %r10d
        movb      %r8b, (%r11,%rax)
        jb        ..B7.107
..B7.108:
        movl      6832(%rsp), %ebx
        testl     %r12d, %r12d
        ja        ..B7.111
        jmp       ..B7.123
..B7.109:
        movb      $128, 3840(%r10,%rcx)
        lea       4608(%rsp,%rax), %rax
..B7.110:
        jbe       ..B7.123
..B7.111:
        cmpl      $16, %r12d
        jb        ..B7.249
..B7.112:
        movl      %r12d, %r10d
        xorl      %r9d, %r9d
        movd      %r14d, %xmm0
        andl      $-16, %r10d
        movaps    6736(%rsp), %xmm6
        movaps    6752(%rsp), %xmm5
        movaps    6768(%rsp), %xmm4
        movaps    6784(%rsp), %xmm3
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %r8
        pshufd    $0, %xmm0, %xmm0
        movl      %r15d, 6816(%rsp)
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
..B7.113:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r11d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r9,%r8), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r15d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r15b, (%r11,%rax)
        pslld     $2, %xmm15
        movd      %xmm2, %r15d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r11d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r9d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r11b, (%r15,%rax)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r11d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r15d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r10d, %r9d
        movb      %r15b, (%r11,%rax)
        movd      %xmm2, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, (%r15,%rax)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, (%r11,%rax)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        movb      %r11b, (%r15,%rax)
        jb        ..B7.113
..B7.114:
        movl      6816(%rsp), %r15d
..B7.115:
        cmpl      %r12d, %r10d
        lea       (%r15,%r10), %r8d
        jae       ..B7.119
..B7.116:
        movl      %ebx, 6832(%rsp)
        movl      %r15d, 6816(%rsp)
        movq      6880(%rsp), %rbx
..B7.117:
        lea       16(%r8), %r9d
        movl      %r9d, %r11d
        andl      $3, %r9d
        andl      $-4, %r11d
        incl      %r8d
        shll      $2, %r11d
        lea       (%r11,%r14,4), %r15d
        addl      %r9d, %r15d
        movb      (%r10,%rbx), %r9b
        incl      %r10d
        cmpl      %r12d, %r10d
        movb      %r9b, (%r15,%rax)
        jb        ..B7.117
..B7.118:
        movl      6832(%rsp), %ebx
        movl      6816(%rsp), %r15d
..B7.119:
        cmpl      $16, %r12d
        jb        ..B7.124
..B7.120:
        movd      %edx, %xmm6
        lea       1(%rdx), %r8d
        movl      %r12d, %r9d
        lea       2(%rdx), %r10d
        addl      $3, %edx
        movd      %r14d, %xmm13
        andl      $-16, %r9d
        movd      %r8d, %xmm5
        lea       20(%r12,%r15), %r8d
        punpcklqdq %xmm5, %xmm6
        lea       2(%r8), %r11d
        movd      %edx, %xmm4
        lea       1(%r8), %edx
        movd      %r10d, %xmm3
        movd      %r8d, %xmm5
        addl      $3, %r8d
        punpcklqdq %xmm4, %xmm3
        movd      %r11d, %xmm2
        movd      %edx, %xmm0
        shufps    $136, %xmm3, %xmm6
        movd      %r8d, %xmm1
        lea       24(%r12,%r15), %r8d
        punpcklqdq %xmm0, %xmm5
        lea       1(%r8), %edx
        punpcklqdq %xmm1, %xmm2
        lea       2(%r8), %r10d
        shufps    $136, %xmm2, %xmm5
        movd      %r8d, %xmm4
        addl      $3, %r8d
        movd      %edx, %xmm7
        movd      %r10d, %xmm9
        punpcklqdq %xmm7, %xmm4
        movd      %r8d, %xmm8
        lea       28(%r12,%r15), %r8d
        punpcklqdq %xmm8, %xmm9
        lea       1(%r8), %r11d
        shufps    $136, %xmm9, %xmm4
        lea       2(%r8), %edx
        pshufd    $0, %xmm13, %xmm0
        movd      %r8d, %xmm3
        addl      $3, %r8d
        movd      %r11d, %xmm10
        movd      %edx, %xmm12
        xorl      %edx, %edx
        punpcklqdq %xmm10, %xmm3
        movd      %r8d, %xmm11
        punpcklqdq %xmm11, %xmm12
        shufps    $136, %xmm12, %xmm3
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %r8
..B7.121:
        movaps    %xmm6, %xmm2
        movaps    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movaps    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r10d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movaps    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rdx,%r8), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r11d
        movaps    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movaps    %xmm4, %xmm12
        movb      %r11b, (%r10,%rax)
        pslld     $2, %xmm15
        movd      %xmm2, %r11d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r10d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movaps    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movaps    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %edx
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r10b, (%r11,%rax)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r10d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r11d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r9d, %edx
        movb      %r11b, (%r10,%rax)
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rax)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rax)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rax)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rax)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rax)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rax)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rax)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rax)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rax)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rax)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r10b, (%r11,%rax)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, (%r10,%rax)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        movb      %r10b, (%r11,%rax)
        jb        ..B7.121
        jmp       ..B7.125
..B7.123:
        jbe       ..B7.129
..B7.124:
        xorl      %r9d, %r9d
..B7.125:
        cmpl      %r12d, %r9d
        lea       (%rsi,%r9), %r10d
        jae       ..B7.129
..B7.126:
        movl      %r15d, 6816(%rsp)
        movq      6880(%rsp), %rdx
..B7.127:
        lea       16(%r10), %r8d
        movl      %r8d, %r11d
        andl      $3, %r8d
        andl      $-4, %r11d
        incl      %r10d
        shll      $2, %r11d
        lea       (%r11,%r14,4), %r15d
        addl      %r8d, %r15d
        movb      (%r9,%rdx), %r8b
        incl      %r9d
        cmpl      %r12d, %r9d
        movb      %r8b, (%r15,%rax)
        jb        ..B7.127
..B7.128:
        movl      6816(%rsp), %r15d
..B7.129:
        lea       16(%r15,%r12,2), %eax
        movl      %eax, %edx
        andl      $3, %eax
        andl      $-4, %edx
        addl      %r14d, %edx
        testl     %r12d, %r12d
        lea       (%rax,%rdx,4), %eax
        movb      $128, 4608(%rax,%rcx)
        jbe       ..B7.138
..B7.130:
        cmpl      $16, %r12d
        jb        ..B7.251
..B7.131:
        movl      %r12d, %r9d
        xorl      %edx, %edx
        movd      %r14d, %xmm0
        andl      $-16, %r9d
        movdqa    .L_2il0floatpacket.455(%rip), %xmm6
        movdqa    .L_2il0floatpacket.456(%rip), %xmm5
        movdqa    .L_2il0floatpacket.457(%rip), %xmm4
        movdqa    .L_2il0floatpacket.458(%rip), %xmm3
        pshufd    $0, %xmm0, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %r8
..B7.132:
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r10d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movdqa    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%rdx,%r8), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r11d
        movdqa    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movdqa    %xmm4, %xmm12
        movb      %r11b, 5376(%r10,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r11d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r10d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movdqa    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %edx
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r10b, 5376(%r11,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r10d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r11d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r9d, %edx
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        .byte     144
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        movb      %r10b, 5376(%r11,%rcx)
        jb        ..B7.132
..B7.134:
        cmpl      %r12d, %r9d
        jae       ..B7.137
..B7.135:
        movq      6880(%rsp), %rdx
..B7.136:
        movl      %r9d, %r8d
        movl      %r9d, %r10d
        andl      $-4, %r8d
        andl      $3, %r10d
        shll      $2, %r8d
        lea       (%r8,%r14,4), %r11d
        movb      (%r9,%rdx), %r8b
        addl      %r10d, %r11d
        incl      %r9d
        cmpl      %r12d, %r9d
        movb      %r8b, 5376(%r11,%rcx)
        jb        ..B7.136
..B7.137:
        testl     %r15d, %r15d
        ja        ..B7.139
        jmp       ..B7.148
..B7.138:
        testl     %r15d, %r15d
        jbe       ..B7.156
..B7.139:
        cmpl      $16, %r15d
        jb        ..B7.253
..B7.140:
        movd      %r12d, %xmm6
        lea       1(%r12), %edx
        movd      %r14d, %xmm13
        lea       2(%r12), %r8d
        movl      6696(%rsp), %r10d
        lea       3(%r12), %r9d
        movl      %r15d, 6816(%rsp)
        lea       4(%r12), %r11d
        movd      %edx, %xmm5
        lea       5(%r12), %edx
        movd      %r8d, %xmm3
        lea       6(%r12), %r8d
        movd      %r9d, %xmm4
        lea       7(%r12), %r9d
        punpcklqdq %xmm5, %xmm6
        movd      %r11d, %xmm5
        movd      %edx, %xmm0
        lea       8(%r12), %r11d
        movd      %r8d, %xmm2
        lea       9(%r12), %edx
        movd      %r9d, %xmm1
        lea       10(%r12), %r8d
        punpcklqdq %xmm4, %xmm3
        lea       11(%r12), %r9d
        movd      %r11d, %xmm4
        lea       12(%r12), %r11d
        movd      %edx, %xmm7
        lea       13(%r12), %edx
        movd      %r8d, %xmm9
        lea       14(%r12), %r8d
        movd      %r9d, %xmm8
        lea       15(%r12), %r9d
        shufps    $136, %xmm3, %xmm6
        movd      %r11d, %xmm3
        movd      %edx, %xmm10
        movd      %r8d, %xmm12
        movl      %r10d, %r8d
        movd      %r9d, %xmm11
        xorl      %r9d, %r9d
        punpcklqdq %xmm0, %xmm5
        punpcklqdq %xmm1, %xmm2
        punpcklqdq %xmm7, %xmm4
        punpcklqdq %xmm8, %xmm9
        punpcklqdq %xmm10, %xmm3
        punpcklqdq %xmm11, %xmm12
        shufps    $136, %xmm2, %xmm5
        shufps    $136, %xmm9, %xmm4
        shufps    $136, %xmm12, %xmm3
        pshufd    $0, %xmm13, %xmm0
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6864(%rsp), %rdx
..B7.141:
        movaps    %xmm6, %xmm2
        movaps    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movaps    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r11d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movaps    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r9,%rdx), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r15d
        movaps    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movaps    %xmm4, %xmm12
        movb      %r15b, 5376(%r11,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r15d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r11d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movaps    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movaps    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r9d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r11b, 5376(%r15,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r11d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r15d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r8d, %r9d
        movb      %r15b, 5376(%r11,%rcx)
        movd      %xmm2, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 5376(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r15,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r15b, 5376(%r11,%rcx)
        movd      %xmm14, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 5376(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r15,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r15b, 5376(%r11,%rcx)
        movd      %xmm15, %r15d
        movd      %xmm1, %r11d
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 5376(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r15,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r15d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r15b, 5376(%r11,%rcx)
        movd      %xmm10, %r15d
        movd      %xmm1, %r11d
        movb      %r11b, 5376(%r15,%rcx)
        jb        ..B7.141
..B7.142:
        movl      6816(%rsp), %r15d
..B7.143:
        cmpl      %r15d, %r10d
        jae       ..B7.147
..B7.144:
        movq      6864(%rsp), %rdx
..B7.145:
        lea       (%r12,%r10), %r8d
        movl      %r8d, %r9d
        andl      $3, %r8d
        andl      $-4, %r9d
        shll      $2, %r9d
        lea       (%r9,%r14,4), %r11d
        addl      %r8d, %r11d
        movb      (%r10,%rdx), %r8b
        incl      %r10d
        cmpl      %r15d, %r10d
        movb      %r8b, 5376(%r11,%rcx)
        jb        ..B7.145
..B7.147:
        testl     %r12d, %r12d
        jbe       ..B7.156
..B7.148:
        cmpl      $16, %r12d
        jb        ..B7.252
..B7.149:
        movd      %esi, %xmm6
        lea       1(%r12,%r15), %r8d
        movl      %r12d, %r9d
        lea       1(%r8), %edx
        movd      %r14d, %xmm13
        andl      $-16, %r9d
        movd      %r8d, %xmm5
        addl      $2, %r8d
        movd      %edx, %xmm3
        lea       4(%r12,%r15), %edx
        punpcklqdq %xmm5, %xmm6
        lea       1(%rdx), %r10d
        lea       2(%rdx), %r11d
        movd      %r8d, %xmm4
        movd      %edx, %xmm5
        addl      $3, %edx
        punpcklqdq %xmm4, %xmm3
        movd      %r10d, %xmm0
        shufps    $136, %xmm3, %xmm6
        movd      %r11d, %xmm2
        punpcklqdq %xmm0, %xmm5
        movd      %edx, %xmm1
        lea       8(%r12,%r15), %edx
        punpcklqdq %xmm1, %xmm2
        lea       1(%rdx), %r8d
        shufps    $136, %xmm2, %xmm5
        lea       2(%rdx), %r10d
        pshufd    $0, %xmm13, %xmm0
        movd      %edx, %xmm4
        addl      $3, %edx
        movd      %r8d, %xmm7
        lea       12(%r12,%r15), %r8d
        movd      %r10d, %xmm9
        lea       1(%r8), %r11d
        punpcklqdq %xmm7, %xmm4
        movd      %edx, %xmm8
        lea       2(%r8), %edx
        movd      %r8d, %xmm3
        addl      $3, %r8d
        movd      %r11d, %xmm10
        punpcklqdq %xmm8, %xmm9
        movd      %edx, %xmm12
        movd      %r8d, %xmm11
        xorl      %r8d, %r8d
        punpcklqdq %xmm10, %xmm3
        punpcklqdq %xmm11, %xmm12
        shufps    $136, %xmm9, %xmm4
        shufps    $136, %xmm12, %xmm3
        movdqa    .L_2il0floatpacket.454(%rip), %xmm7
        movdqa    6720(%rsp), %xmm8
        movdqa    6704(%rsp), %xmm9
        movq      6880(%rsp), %rdx
..B7.150:
        movaps    %xmm6, %xmm2
        movaps    %xmm6, %xmm10
        pand      %xmm8, %xmm2
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm2
        movaps    %xmm5, %xmm14
        pslld     $2, %xmm2
        pand      %xmm8, %xmm14
        paddd     %xmm10, %xmm2
        movd      %xmm2, %r10d
        paddd     %xmm0, %xmm14
        psrldq    $4, %xmm2
        movaps    %xmm5, %xmm11
        pslld     $2, %xmm14
        pand      %xmm7, %xmm11
        movdqu    (%r8,%rdx), %xmm1
        paddd     %xmm11, %xmm14
        movd      %xmm1, %r11d
        movaps    %xmm4, %xmm15
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm15
        paddd     %xmm0, %xmm15
        movaps    %xmm4, %xmm12
        movb      %r11b, 5376(%r10,%rcx)
        pslld     $2, %xmm15
        movd      %xmm2, %r11d
        pand      %xmm7, %xmm12
        movd      %xmm1, %r10d
        paddd     %xmm12, %xmm15
        psrldq    $4, %xmm2
        movaps    %xmm3, %xmm10
        psrldq    $1, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm0, %xmm10
        movaps    %xmm3, %xmm13
        pslld     $2, %xmm10
        pand      %xmm7, %xmm13
        addl      $16, %r8d
        paddd     %xmm13, %xmm10
        paddd     %xmm9, %xmm6
        movb      %r10b, 5376(%r11,%rcx)
        paddd     %xmm9, %xmm5
        movd      %xmm2, %r10d
        paddd     %xmm9, %xmm4
        movd      %xmm1, %r11d
        paddd     %xmm9, %xmm3
        psrldq    $4, %xmm2
        psrldq    $1, %xmm1
        cmpl      %r9d, %r8d
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm2, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm14, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm14
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm14, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm15, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm15
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm15, %r11d
        movd      %xmm1, %r10d
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r10b, 5376(%r11,%rcx)
        movd      %xmm10, %r10d
        movd      %xmm1, %r11d
        psrldq    $4, %xmm10
        psrldq    $1, %xmm1
        movb      %r11b, 5376(%r10,%rcx)
        movd      %xmm10, %r11d
        movd      %xmm1, %r10d
        movb      %r10b, 5376(%r11,%rcx)
        jb        ..B7.150
..B7.152:
        cmpl      %r12d, %r9d
        jae       ..B7.156
..B7.153:
        movq      6880(%rsp), %rdx
..B7.154:
        lea       (%rsi,%r9), %r8d
        movl      %r8d, %r10d
        andl      $3, %r8d
        andl      $-4, %r10d
        shll      $2, %r10d
        lea       (%r10,%r14,4), %r11d
        addl      %r8d, %r11d
        movb      (%r9,%rdx), %r8b
        incl      %r9d
        cmpl      %r12d, %r9d
        movb      %r8b, 5376(%r11,%rcx)
        jb        ..B7.154
..B7.156:
        movb      $128, 5376(%rax,%rcx)
        movl      %r13d, %eax
        shll      $6, %eax
        lea       128(,%rdi,8), %esi
        movl      6848(%rsp), %r9d
        lea       128(,%r12,8), %ecx
        lea       56(%r14,%rax), %edx
        lea       128(%r9,%rdi,8), %r10d
        lea       6496(%rsp), %rdi
        lea       128(%r9,%r12,8), %r8d
        movl      %ecx, (%rsp,%rdx,4)
        movl      %ecx, 768(%rsp,%rdx,4)
        movl      %esi, 1536(%rsp,%rdx,4)
        movl      %esi, 2304(%rsp,%rdx,4)
        movl      %r8d, 3072(%rsp,%rdx,4)
        movl      %r8d, 3840(%rsp,%rdx,4)
        movl      %r10d, 4608(%rsp,%rdx,4)
        movl      %r10d, 5376(%rsp,%rdx,4)
..___tag_value_md5cryptsse.142:
        call      john_MD5_Init
..___tag_value_md5cryptsse.143:
..B7.157:
        movl      %ebp, %ebp
        lea       6496(%rsp), %rdi
        movq      %rbp, %rdx
        movq      6880(%rsp), %rsi
..___tag_value_md5cryptsse.144:
        call      john_MD5_Update
..___tag_value_md5cryptsse.145:
..B7.158:
        cmpl      $2, 6872(%rsp)
        jne       ..B7.160
..B7.159:
        movl      $.L_2__STRING.1, %esi
        lea       6496(%rsp), %rdi
        movl      $3, %edx
..___tag_value_md5cryptsse.146:
        call      john_MD5_Update
..___tag_value_md5cryptsse.147:
        jmp       ..B7.162
..B7.160:
        cmpl      $1, 6872(%rsp)
        jne       ..B7.162
..B7.161:
        movl      $.L_2__STRING.2, %esi
        lea       6496(%rsp), %rdi
        movl      $6, %edx
..___tag_value_md5cryptsse.148:
        call      john_MD5_Update
..___tag_value_md5cryptsse.149:
..B7.162:
        movq      6864(%rsp), %rsi
        lea       6496(%rsp), %rdi
        movq      6840(%rsp), %rdx
..___tag_value_md5cryptsse.150:
        call      john_MD5_Update
..___tag_value_md5cryptsse.151:
..B7.163:
        lea       6144(%rsp), %rdi
..___tag_value_md5cryptsse.152:
        call      john_MD5_Init
..___tag_value_md5cryptsse.153:
..B7.164:
        movq      %rbp, %rdx
        lea       6144(%rsp), %rdi
        movq      6880(%rsp), %rsi
..___tag_value_md5cryptsse.154:
        call      john_MD5_Update
..___tag_value_md5cryptsse.155:
..B7.165:
        movq      6864(%rsp), %rsi
        lea       6144(%rsp), %rdi
        movq      6840(%rsp), %rdx
..___tag_value_md5cryptsse.156:
        call      john_MD5_Update
..___tag_value_md5cryptsse.157:
..B7.166:
        movq      %rbp, %rdx
        lea       6144(%rsp), %rdi
        movq      6880(%rsp), %rsi
..___tag_value_md5cryptsse.158:
        call      john_MD5_Update
..___tag_value_md5cryptsse.159:
..B7.167:
        lea       6800(%rsp), %rdi
        lea       6144(%rsp), %rsi
..___tag_value_md5cryptsse.160:
        call      john_MD5_Final
..___tag_value_md5cryptsse.161:
..B7.168:
        movq      %rbp, %rdx
        lea       6496(%rsp), %rdi
        lea       6800(%rsp), %rsi
..___tag_value_md5cryptsse.162:
        call      john_MD5_Update
..___tag_value_md5cryptsse.163:
..B7.169:
        movl      %ebx, %ebx
        testl     %r12d, %r12d
        movl      %r12d, 6648(%rsp,%rbx,4)
        je        ..B7.176
..B7.170:
        movq      6880(%rsp), %rbp
..B7.171:
        testl     $1, %r12d
        je        ..B7.173
..B7.172:
        movl      $.L_2__STRING.3, %esi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.164:
        call      john_MD5_Update
..___tag_value_md5cryptsse.165:
        jmp       ..B7.174
..B7.173:
        movq      %rbp, %rsi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.166:
        call      john_MD5_Update
..___tag_value_md5cryptsse.167:
..B7.174:
        shrl      $1, %r12d
        testl     %r12d, %r12d
        jne       ..B7.171
..B7.176:
        lea       6800(%rsp), %rdi
        lea       6496(%rsp), %rsi
..___tag_value_md5cryptsse.168:
        call      john_MD5_Final
..___tag_value_md5cryptsse.169:
..B7.177:
        shll      $4, %r13d
        incl      %ebx
        movl      6800(%rsp), %edx
        cmpl      $12, %ebx
        movl      6804(%rsp), %ebp
        movl      6808(%rsp), %edi
        movl      6812(%rsp), %r9d
        lea       (%r14,%r13), %eax
        lea       4(%r13,%r14), %ecx
        lea       8(%r13,%r14), %esi
        lea       12(%r13,%r14), %r8d
        movl      %edx, 6304(%rsp,%rax,4)
        movl      %ebp, 6304(%rsp,%rcx,4)
        movl      %edi, 6304(%rsp,%rsi,4)
        movl      %r9d, 6304(%rsp,%r8,4)
        jb        ..B7.5
..B7.178:
        xorl      %ebx, %ebx
        movl      $23, %r12d
        lea       3840(%rsp), %rcx
        xorl      %r14d, %r14d
        lea       (%rsp), %rbp
..B7.179:
        cmpl      $40, %ebx
        ja        ..B7.231
..B7.180:
        jmp       *..1..TPKT.6_0.0.6.38(,%rbx,8)
..1.6_0.TAG.015.0.6.38:
..B7.196:
        movl      $1, %esi
        movq      %rbp, %rdi
        movl      %esi, %ecx
        lea       6648(%rsp), %rdx
        xorl      %r8d, %r8d
        lea       6304(%rsp), %r9
        movl      $1, %r13d
..___tag_value_md5cryptsse.170:
        call      mmxput3
..___tag_value_md5cryptsse.171:
        jmp       ..B7.232
..1.6_0.TAG.01c.0.6.38:
..1.6_0.TAG.0e.0.6.38:
..B7.202:
        movl      %r14d, %edx
        movb      $0, %cl
        movl      %edx, %eax
        movl      $5, %r13d
        movl      %ebx, 6696(%rsp)
        movl      %eax, %r14d
        movl      %r12d, 6704(%rsp)
        movl      %edx, %r12d
        movl      %r15d, 6816(%rsp)
        movb      %cl, %bpl
        lea       3840(%rsp), %rbx
        lea       6304(%rsp), %r15
..B7.203:
        movl      %r14d, %edi
        movl      $64, %edx
        movl      %r12d, %esi
        addq      %rbx, %rdi
        addq      %r15, %rsi
..___tag_value_md5cryptsse.172:
        call      memcpy
..___tag_value_md5cryptsse.173:
..B7.204:
        incb      %bpl
        addl      $64, %r12d
        addl      $256, %r14d
        cmpb      $3, %bpl
        jb        ..B7.203
..B7.205:
        movl      6696(%rsp), %ebx
        xorl      %r14d, %r14d
        movl      6704(%rsp), %r12d
        lea       (%rsp), %rbp
        movl      6816(%rsp), %r15d
        jmp       ..B7.232
..1.6_0.TAG.023.0.6.38:
..1.6_0.TAG.07.0.6.38:
..B7.211:
        movq      %rbp, %rdi
        movl      $4, %esi
        movl      $1, %ecx
        lea       6648(%rsp), %rdx
        movl      %r15d, %r8d
        lea       6304(%rsp), %r9
        movl      $4, %r13d
..___tag_value_md5cryptsse.174:
        call      mmxput3
..___tag_value_md5cryptsse.175:
        jmp       ..B7.232
..1.6_0.TAG.024.0.6.38:
..1.6_0.TAG.01e.0.6.38:
..1.6_0.TAG.018.0.6.38:
..1.6_0.TAG.012.0.6.38:
..1.6_0.TAG.0c.0.6.38:
..1.6_0.TAG.06.0.6.38:
..B7.213:
        movl      %r14d, %edx
        movb      $0, %cl
        movl      %edx, %eax
        movl      $3, %r13d
        movl      %ebx, 6696(%rsp)
        movl      %eax, %r14d
        movl      %r12d, 6704(%rsp)
        movl      %edx, %r12d
        movl      %r15d, 6816(%rsp)
        movb      %cl, %bpl
        lea       2304(%rsp), %rbx
        lea       6304(%rsp), %r15
..B7.214:
        movl      %r14d, %edi
        movl      $64, %edx
        movl      %r12d, %esi
        addq      %rbx, %rdi
        addq      %r15, %rsi
..___tag_value_md5cryptsse.176:
        call      memcpy
..___tag_value_md5cryptsse.177:
..B7.215:
        incb      %bpl
        addl      $64, %r12d
        addl      $256, %r14d
        cmpb      $3, %bpl
        jb        ..B7.214
..B7.216:
        movl      6696(%rsp), %ebx
        xorl      %r14d, %r14d
        movl      6704(%rsp), %r12d
        lea       (%rsp), %rbp
        movl      6816(%rsp), %r15d
        jmp       ..B7.232
..1.6_0.TAG.027.0.6.38:
..1.6_0.TAG.021.0.6.38:
..1.6_0.TAG.01b.0.6.38:
..1.6_0.TAG.0f.0.6.38:
..1.6_0.TAG.09.0.6.38:
..1.6_0.TAG.03.0.6.38:
..B7.219:
        movl      $2, %esi
        movq      %rbp, %rdi
        movl      %esi, %ecx
        lea       6648(%rsp), %rdx
        xorl      %r8d, %r8d
        lea       6304(%rsp), %r9
        movl      $2, %r13d
..___tag_value_md5cryptsse.178:
        call      mmxput3
..___tag_value_md5cryptsse.179:
        jmp       ..B7.232
..1.6_0.TAG.028.0.6.38:
..1.6_0.TAG.026.0.6.38:
..1.6_0.TAG.022.0.6.38:
..1.6_0.TAG.020.0.6.38:
..1.6_0.TAG.01a.0.6.38:
..1.6_0.TAG.016.0.6.38:
..1.6_0.TAG.014.0.6.38:
..1.6_0.TAG.010.0.6.38:
..1.6_0.TAG.0a.0.6.38:
..1.6_0.TAG.08.0.6.38:
..1.6_0.TAG.04.0.6.38:
..1.6_0.TAG.02.0.6.38:
..B7.221:
        movl      %r14d, %edx
        movb      $0, %cl
        movl      %edx, %eax
        movl      $6, %r13d
        movl      %ebx, 6696(%rsp)
        movl      %eax, %r14d
        movl      %r12d, 6704(%rsp)
        movl      %edx, %r12d
        movl      %r15d, 6816(%rsp)
        movb      %cl, %bpl
        lea       4608(%rsp), %rbx
        lea       6304(%rsp), %r15
..B7.222:
        movl      %r14d, %edi
        movl      $64, %edx
        movl      %r12d, %esi
        addq      %rbx, %rdi
        addq      %r15, %rsi
..___tag_value_md5cryptsse.180:
        call      memcpy
..___tag_value_md5cryptsse.181:
..B7.223:
        incb      %bpl
        addl      $64, %r12d
        addl      $256, %r14d
        cmpb      $3, %bpl
        jb        ..B7.222
..B7.224:
        movl      6696(%rsp), %ebx
        xorl      %r14d, %r14d
        movl      6704(%rsp), %r12d
        lea       (%rsp), %rbp
        movl      6816(%rsp), %r15d
        jmp       ..B7.232
..1.6_0.TAG.00.0.6.38:
..B7.227:
        movl      %r14d, %edx
        movb      $0, %cl
        movl      %edx, %eax
        xorl      %r13d, %r13d
        movl      %ebx, 6696(%rsp)
        movl      %eax, %r14d
        movl      %r12d, 6704(%rsp)
        movb      %cl, %r12b
        movl      %r15d, 6816(%rsp)
        movl      %edx, %r15d
        lea       6304(%rsp), %rbx
..B7.228:
        movl      %r14d, %edi
        movl      $64, %edx
        movl      %r15d, %esi
        addq      %rbp, %rdi
        addq      %rbx, %rsi
..___tag_value_md5cryptsse.182:
        call      memcpy
..___tag_value_md5cryptsse.183:
..B7.229:
        incb      %r12b
        addl      $64, %r15d
        addl      $256, %r14d
        cmpb      $3, %r12b
        jb        ..B7.228
..B7.230:
        movl      6696(%rsp), %ebx
        xorl      %r14d, %r14d
        movl      6704(%rsp), %r12d
        movl      6816(%rsp), %r15d
        jmp       ..B7.232
..1.6_0.TAG.DEFAULT.0.6.38:
..B7.231:
        movq      %rbp, %rdi
        movl      $7, %esi
        movl      $2, %ecx
        lea       6648(%rsp), %rdx
        movl      %r15d, %r8d
        lea       6304(%rsp), %r9
        movl      $7, %r13d
..___tag_value_md5cryptsse.184:
        call      mmxput3
..___tag_value_md5cryptsse.185:
..B7.232:
        movl      $1, %edx
        lea       (%r13,%r13,2), %rdi
        shlq      $8, %rdi
        lea       6304(%rsp), %rsi
        addq      %rbp, %rdi
..___tag_value_md5cryptsse.186:
        call      SSEmd5body
..___tag_value_md5cryptsse.187:
..B7.233:
        incl      %ebx
        lea       -1(%rbx), %eax
        cmpl      $33, %eax
        jb        ..B7.179
..B7.234:
        cmpl      $34, %ebx
        jne       ..B7.237
..B7.235:
        testl     %r12d, %r12d
        je        ..B7.254
..B7.236:
        decl      %r12d
        jmp       ..B7.179
..B7.237:
        cmpl      $42, %ebx
        cmovae    %r14d, %ebx
        jmp       ..B7.179
..B7.238:
        xorl      %edi, %edi
        jmp       ..B7.11
..B7.239:
        xorl      %r8d, %r8d
        jmp       ..B7.20
..B7.240:
        xorl      %r8d, %r8d
        jmp       ..B7.29
..B7.241:
        xorl      %r10d, %r10d
        jmp       ..B7.48
..B7.242:
        xorl      %r9d, %r9d
        jmp       ..B7.67
..B7.243:
        xorl      %r10d, %r10d
        jmp       ..B7.77
..B7.244:
        testl     %r12d, %r12d
        ja        ..B7.92
..B7.245:
        movb      $128, 3840(%r10,%rcx)
        lea       4608(%rsp,%rax), %rax
        jmp       ..B7.101
..B7.246:
        xorl      %r9d, %r9d
        jmp       ..B7.86
..B7.247:
        xorl      %r10d, %r10d
        jmp       ..B7.105
..B7.248:
        xorl      %r8d, %r8d
        jmp       ..B7.96
..B7.249:
        xorl      %r10d, %r10d
        jmp       ..B7.115
..B7.251:
        xorl      %r9d, %r9d
        jmp       ..B7.134
..B7.252:
        xorl      %r9d, %r9d
        jmp       ..B7.152
..B7.253:
        xorl      %r10d, %r10d
        jmp       ..B7.143
..B7.254:
        movq      6296(%rsp), %rbp
        movq      %rbp, %rdi
        movl      $192, %edx
        lea       6304(%rsp), %rsi
..___tag_value_md5cryptsse.188:
        call      memcpy
..___tag_value_md5cryptsse.189:
..B7.255:
        addq      $6888, %rsp
..___tag_value_md5cryptsse.190:
        popq      %rbp
..___tag_value_md5cryptsse.192:
        popq      %rbx
..___tag_value_md5cryptsse.194:
        popq      %r15
..___tag_value_md5cryptsse.196:
        popq      %r14
..___tag_value_md5cryptsse.198:
        popq      %r13
..___tag_value_md5cryptsse.200:
        popq      %r12
..___tag_value_md5cryptsse.202:
        ret       
..___tag_value_md5cryptsse.203:
..B7.260:
        testl     %r12d, %r12d
        ja        ..B7.111
        jmp       ..B7.123
        .align    16,0x90
..___tag_value_md5cryptsse.210:
	.type	md5cryptsse,@function
	.size	md5cryptsse,.-md5cryptsse
	.section .rodata, "a"
	.space 24, 0x00 	# pad
	.align 32
..1..TPKT.6_0.0.6.38:
	.quad	..1.6_0.TAG.00.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.02.0.6.38
	.quad	..1.6_0.TAG.03.0.6.38
	.quad	..1.6_0.TAG.04.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.06.0.6.38
	.quad	..1.6_0.TAG.07.0.6.38
	.quad	..1.6_0.TAG.08.0.6.38
	.quad	..1.6_0.TAG.09.0.6.38
	.quad	..1.6_0.TAG.0a.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.0c.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.0e.0.6.38
	.quad	..1.6_0.TAG.0f.0.6.38
	.quad	..1.6_0.TAG.010.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.012.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.014.0.6.38
	.quad	..1.6_0.TAG.015.0.6.38
	.quad	..1.6_0.TAG.016.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.018.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.01a.0.6.38
	.quad	..1.6_0.TAG.01b.0.6.38
	.quad	..1.6_0.TAG.01c.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.01e.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.020.0.6.38
	.quad	..1.6_0.TAG.021.0.6.38
	.quad	..1.6_0.TAG.022.0.6.38
	.quad	..1.6_0.TAG.023.0.6.38
	.quad	..1.6_0.TAG.024.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.026.0.6.38
	.quad	..1.6_0.TAG.027.0.6.38
	.quad	..1.6_0.TAG.028.0.6.38
	.data
# -- End  md5cryptsse
	.text
# -- Begin  SSEmd4body
       .align    16,0x90
	.globl SSEmd4body
SSEmd4body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %edx
..B8.1:
..___tag_value_SSEmd4body.211:
        subq      $840, %rsp
..___tag_value_SSEmd4body.213:
        movdqa    (%rsi), %xmm0
        testl     %edx, %edx
        movdqa    16(%rsi), %xmm1
        movdqa    32(%rsi), %xmm2
        movdqa    48(%rsi), %xmm3
        movdqa    %xmm0, (%rsp)
        movdqa    %xmm1, 48(%rsp)
        movdqa    %xmm2, 32(%rsp)
        movdqa    %xmm3, 16(%rsp)
        je        ..B8.3
..B8.2:
        movdqa    .L_2il0floatpacket.484(%rip), %xmm4
        movdqa    .L_2il0floatpacket.485(%rip), %xmm2
        movdqa    %xmm4, %xmm7
        movdqa    .L_2il0floatpacket.486(%rip), %xmm3
        movdqa    %xmm2, %xmm5
        movdqa    .L_2il0floatpacket.487(%rip), %xmm0
        movdqa    %xmm3, %xmm12
        movdqa    %xmm0, %xmm11
        movdqa    %xmm4, %xmm15
        movdqa    %xmm2, %xmm6
        movdqa    %xmm3, %xmm14
        movdqa    %xmm0, %xmm13
        jmp       ..B8.4
..B8.3:
        movdqa    (%rsp), %xmm4
        movdqa    48(%rsp), %xmm2
        movdqa    32(%rsp), %xmm3
        movdqa    16(%rsp), %xmm0
        movdqa    64(%rsi), %xmm7
        movdqa    80(%rsi), %xmm5
        movdqa    96(%rsi), %xmm12
        movdqa    112(%rsi), %xmm11
        movdqa    128(%rsi), %xmm15
        movdqa    144(%rsi), %xmm6
        movdqa    160(%rsi), %xmm14
        movdqa    176(%rsi), %xmm13
..B8.4:
        movdqa    %xmm3, %xmm8
        movdqa    %xmm12, %xmm9
        pxor      %xmm0, %xmm8
        pxor      %xmm1, %xmm1
        pand      %xmm2, %xmm8
        paddd     %xmm1, %xmm4
        pxor      %xmm0, %xmm8
        pxor      %xmm11, %xmm9
        movdqa    (%rdi), %xmm10
        paddd     %xmm8, %xmm4
        movdqa    %xmm10, 784(%rsp)
        paddd     %xmm10, %xmm4
        pand      %xmm5, %xmm9
        movdqa    %xmm14, %xmm10
        paddd     %xmm1, %xmm7
        pxor      %xmm11, %xmm9
        pxor      %xmm13, %xmm10
        paddd     %xmm9, %xmm7
        movdqa    256(%rdi), %xmm8
        pand      %xmm6, %xmm10
        paddd     %xmm8, %xmm7
        paddd     %xmm1, %xmm15
        pxor      %xmm13, %xmm10
        paddd     %xmm1, %xmm0
        movdqa    %xmm8, 816(%rsp)
        paddd     %xmm10, %xmm15
        movdqa    512(%rdi), %xmm8
        movdqa    %xmm7, %xmm10
        movdqa    %xmm8, 752(%rsp)
        paddd     %xmm8, %xmm15
        movdqa    %xmm4, %xmm8
        pslld     $3, %xmm10
        psrld     $29, %xmm7
        pslld     $3, %xmm8
        psrld     $29, %xmm4
        por       %xmm7, %xmm10
        movdqa    %xmm2, %xmm7
        por       %xmm4, %xmm8
        pxor      %xmm3, %xmm7
        movdqa    %xmm15, %xmm9
        pand      %xmm8, %xmm7
        pslld     $3, %xmm9
        psrld     $29, %xmm15
        pxor      %xmm3, %xmm7
        movdqa    %xmm5, %xmm4
        por       %xmm15, %xmm9
        movdqa    16(%rdi), %xmm15
        paddd     %xmm7, %xmm0
        pxor      %xmm12, %xmm4
        paddd     %xmm15, %xmm0
        movdqa    %xmm15, 112(%rsp)
        pand      %xmm10, %xmm4
        movdqa    %xmm6, %xmm15
        paddd     %xmm1, %xmm11
        pxor      %xmm12, %xmm4
        pxor      %xmm14, %xmm15
        movdqa    272(%rdi), %xmm7
        paddd     %xmm4, %xmm11
        pand      %xmm9, %xmm15
        paddd     %xmm7, %xmm11
        paddd     %xmm1, %xmm13
        pxor      %xmm14, %xmm15
        movdqa    %xmm7, 176(%rsp)
        paddd     %xmm15, %xmm13
        movdqa    528(%rdi), %xmm7
        movdqa    %xmm11, %xmm4
        movdqa    %xmm7, 192(%rsp)
        paddd     %xmm7, %xmm13
        movdqa    %xmm0, %xmm7
        pslld     $7, %xmm4
        psrld     $25, %xmm11
        pslld     $7, %xmm7
        psrld     $25, %xmm0
        por       %xmm11, %xmm4
        movdqa    %xmm2, %xmm11
        por       %xmm0, %xmm7
        pxor      %xmm8, %xmm11
        movdqa    %xmm13, %xmm0
        pand      %xmm7, %xmm11
        paddd     %xmm1, %xmm3
        pxor      %xmm2, %xmm11
        pslld     $7, %xmm0
        psrld     $25, %xmm13
        paddd     %xmm11, %xmm3
        movdqa    %xmm5, %xmm11
        movdqa    %xmm6, %xmm15
        por       %xmm13, %xmm0
        pxor      %xmm10, %xmm11
        pxor      %xmm9, %xmm15
        pand      %xmm4, %xmm11
        pand      %xmm0, %xmm15
        paddd     %xmm1, %xmm12
        movdqa    32(%rdi), %xmm13
        pxor      %xmm5, %xmm11
        paddd     %xmm1, %xmm14
        pxor      %xmm6, %xmm15
        paddd     %xmm13, %xmm3
        paddd     %xmm11, %xmm12
        movdqa    544(%rdi), %xmm11
        paddd     %xmm15, %xmm14
        movdqa    %xmm13, 272(%rsp)
        paddd     %xmm11, %xmm14
        movdqa    288(%rdi), %xmm13
        paddd     %xmm1, %xmm2
        movdqa    %xmm11, 304(%rsp)
        movdqa    %xmm3, %xmm11
        paddd     %xmm13, %xmm12
        pslld     $11, %xmm11
        psrld     $21, %xmm3
        movdqa    %xmm0, %xmm15
        por       %xmm3, %xmm11
        movdqa    %xmm12, %xmm3
        pslld     $11, %xmm3
        psrld     $21, %xmm12
        por       %xmm12, %xmm3
        movdqa    %xmm7, %xmm12
        pxor      %xmm8, %xmm12
        paddd     %xmm1, %xmm5
        pand      %xmm11, %xmm12
        pxor      %xmm9, %xmm15
        pxor      %xmm8, %xmm12
        paddd     %xmm1, %xmm6
        paddd     %xmm12, %xmm2
        movdqa    %xmm4, %xmm12
        movdqa    %xmm13, 288(%rsp)
        movdqa    %xmm14, %xmm13
        pxor      %xmm10, %xmm12
        pslld     $11, %xmm13
        psrld     $21, %xmm14
        pand      %xmm3, %xmm12
        por       %xmm14, %xmm13
        pxor      %xmm10, %xmm12
        movdqa    48(%rdi), %xmm14
        paddd     %xmm12, %xmm5
        movdqa    %xmm14, 64(%rsp)
        paddd     %xmm14, %xmm2
        movdqa    304(%rdi), %xmm14
        pand      %xmm13, %xmm15
        paddd     %xmm14, %xmm5
        pxor      %xmm9, %xmm15
        paddd     %xmm15, %xmm6
        movdqa    %xmm5, %xmm15
        movdqa    %xmm14, 80(%rsp)
        movdqa    %xmm2, %xmm14
        pslld     $19, %xmm15
        psrld     $13, %xmm5
        pslld     $19, %xmm14
        psrld     $13, %xmm2
        por       %xmm5, %xmm15
        movdqa    %xmm11, %xmm5
        movdqa    560(%rdi), %xmm12
        por       %xmm2, %xmm14
        pxor      %xmm7, %xmm5
        paddd     %xmm12, %xmm6
        pand      %xmm14, %xmm5
        movdqa    %xmm6, %xmm2
        paddd     %xmm1, %xmm8
        pxor      %xmm7, %xmm5
        movdqa    %xmm12, 96(%rsp)
        pslld     $19, %xmm2
        psrld     $13, %xmm6
        paddd     %xmm5, %xmm8
        movdqa    %xmm3, %xmm5
        movdqa    %xmm13, %xmm12
        por       %xmm6, %xmm2
        pxor      %xmm4, %xmm5
        pxor      %xmm0, %xmm12
        pand      %xmm15, %xmm5
        pand      %xmm2, %xmm12
        paddd     %xmm1, %xmm10
        movdqa    64(%rdi), %xmm6
        pxor      %xmm4, %xmm5
        paddd     %xmm1, %xmm9
        pxor      %xmm0, %xmm12
        paddd     %xmm6, %xmm8
        paddd     %xmm5, %xmm10
        movdqa    576(%rdi), %xmm5
        paddd     %xmm12, %xmm9
        movdqa    %xmm6, 480(%rsp)
        paddd     %xmm5, %xmm9
        movdqa    320(%rdi), %xmm6
        paddd     %xmm1, %xmm7
        movdqa    %xmm5, 512(%rsp)
        movdqa    %xmm8, %xmm5
        paddd     %xmm6, %xmm10
        pslld     $3, %xmm5
        psrld     $29, %xmm8
        movdqa    %xmm2, %xmm12
        por       %xmm8, %xmm5
        movdqa    %xmm10, %xmm8
        pslld     $3, %xmm8
        psrld     $29, %xmm10
        por       %xmm10, %xmm8
        movdqa    %xmm14, %xmm10
        pxor      %xmm11, %xmm10
        pxor      %xmm13, %xmm12
        pand      %xmm5, %xmm10
        paddd     %xmm1, %xmm4
        movdqa    %xmm6, 496(%rsp)
        movdqa    %xmm9, %xmm6
        pxor      %xmm11, %xmm10
        pslld     $3, %xmm6
        psrld     $29, %xmm9
        paddd     %xmm10, %xmm7
        movdqa    %xmm15, %xmm10
        por       %xmm9, %xmm6
        pxor      %xmm3, %xmm10
        pand      %xmm6, %xmm12
        pand      %xmm8, %xmm10
        paddd     %xmm1, %xmm0
        movdqa    80(%rdi), %xmm9
        pxor      %xmm3, %xmm10
        pxor      %xmm13, %xmm12
        paddd     %xmm9, %xmm7
        paddd     %xmm10, %xmm4
        paddd     %xmm12, %xmm0
        movdqa    592(%rdi), %xmm10
        paddd     %xmm1, %xmm11
        movdqa    %xmm9, 208(%rsp)
        paddd     %xmm10, %xmm0
        movdqa    336(%rdi), %xmm9
        movdqa    %xmm6, %xmm12
        movdqa    %xmm10, 240(%rsp)
        movdqa    %xmm7, %xmm10
        paddd     %xmm9, %xmm4
        pslld     $7, %xmm10
        psrld     $25, %xmm7
        pxor      %xmm2, %xmm12
        por       %xmm7, %xmm10
        movdqa    %xmm4, %xmm7
        pslld     $7, %xmm7
        psrld     $25, %xmm4
        por       %xmm4, %xmm7
        movdqa    %xmm5, %xmm4
        pxor      %xmm14, %xmm4
        paddd     %xmm1, %xmm3
        pand      %xmm10, %xmm4
        paddd     %xmm1, %xmm13
        movdqa    %xmm9, 224(%rsp)
        movdqa    %xmm0, %xmm9
        pxor      %xmm14, %xmm4
        pslld     $7, %xmm9
        psrld     $25, %xmm0
        paddd     %xmm4, %xmm11
        movdqa    %xmm8, %xmm4
        por       %xmm0, %xmm9
        pxor      %xmm15, %xmm4
        pand      %xmm9, %xmm12
        pand      %xmm7, %xmm4
        pxor      %xmm2, %xmm12
        movdqa    96(%rdi), %xmm0
        pxor      %xmm15, %xmm4
        paddd     %xmm0, %xmm11
        paddd     %xmm4, %xmm3
        movdqa    608(%rdi), %xmm4
        paddd     %xmm12, %xmm13
        movdqa    %xmm0, 400(%rsp)
        paddd     %xmm4, %xmm13
        movdqa    352(%rdi), %xmm0
        paddd     %xmm1, %xmm14
        movdqa    %xmm4, 432(%rsp)
        movdqa    %xmm11, %xmm4
        paddd     %xmm0, %xmm3
        pslld     $11, %xmm4
        psrld     $21, %xmm11
        movdqa    %xmm9, %xmm12
        por       %xmm11, %xmm4
        movdqa    %xmm3, %xmm11
        pslld     $11, %xmm11
        psrld     $21, %xmm3
        por       %xmm3, %xmm11
        movdqa    %xmm10, %xmm3
        pxor      %xmm5, %xmm3
        pxor      %xmm6, %xmm12
        pand      %xmm4, %xmm3
        paddd     %xmm1, %xmm15
        movdqa    %xmm0, 416(%rsp)
        movdqa    %xmm13, %xmm0
        pxor      %xmm5, %xmm3
        pslld     $11, %xmm0
        psrld     $21, %xmm13
        paddd     %xmm3, %xmm14
        movdqa    %xmm7, %xmm3
        por       %xmm13, %xmm0
        pxor      %xmm8, %xmm3
        pand      %xmm0, %xmm12
        pand      %xmm11, %xmm3
        paddd     %xmm1, %xmm2
        pxor      %xmm8, %xmm3
        pxor      %xmm6, %xmm12
        paddd     %xmm3, %xmm15
        paddd     %xmm12, %xmm2
        movdqa    624(%rdi), %xmm3
        paddd     %xmm1, %xmm5
        movdqa    112(%rdi), %xmm13
        paddd     %xmm3, %xmm2
        paddd     %xmm13, %xmm14
        movdqa    %xmm2, %xmm12
        movdqa    %xmm3, 128(%rsp)
        movdqa    %xmm14, %xmm3
        pslld     $19, %xmm12
        psrld     $13, %xmm2
        movdqa    %xmm13, 160(%rsp)
        pslld     $19, %xmm3
        movdqa    368(%rdi), %xmm13
        psrld     $13, %xmm14
        por       %xmm2, %xmm12
        movdqa    %xmm4, %xmm2
        paddd     %xmm13, %xmm15
        por       %xmm14, %xmm3
        pxor      %xmm10, %xmm2
        paddd     %xmm1, %xmm8
        movdqa    %xmm13, 144(%rsp)
        movdqa    %xmm15, %xmm13
        pand      %xmm3, %xmm2
        pslld     $19, %xmm13
        psrld     $13, %xmm15
        pxor      %xmm10, %xmm2
        movdqa    128(%rdi), %xmm14
        por       %xmm15, %xmm13
        paddd     %xmm2, %xmm5
        movdqa    %xmm11, %xmm15
        movdqa    %xmm14, 688(%rsp)
        paddd     %xmm14, %xmm5
        pxor      %xmm7, %xmm15
        movdqa    %xmm0, %xmm14
        pand      %xmm13, %xmm15
        pxor      %xmm9, %xmm14
        pxor      %xmm7, %xmm15
        pand      %xmm12, %xmm14
        movdqa    384(%rdi), %xmm2
        paddd     %xmm15, %xmm8
        paddd     %xmm1, %xmm6
        pxor      %xmm9, %xmm14
        movdqa    %xmm2, 624(%rsp)
        paddd     %xmm2, %xmm8
        movdqa    640(%rdi), %xmm2
        paddd     %xmm14, %xmm6
        movdqa    %xmm2, 656(%rsp)
        paddd     %xmm2, %xmm6
        movdqa    %xmm5, %xmm2
        psrld     $29, %xmm5
        pslld     $3, %xmm2
        paddd     %xmm1, %xmm10
        por       %xmm5, %xmm2
        movdqa    %xmm8, %xmm5
        pslld     $3, %xmm5
        psrld     $29, %xmm8
        por       %xmm8, %xmm5
        movdqa    %xmm6, %xmm8
        pslld     $3, %xmm8
        psrld     $29, %xmm6
        por       %xmm6, %xmm8
        movdqa    %xmm3, %xmm6
        pxor      %xmm4, %xmm6
        movdqa    %xmm13, %xmm14
        pand      %xmm2, %xmm6
        pxor      %xmm11, %xmm14
        pxor      %xmm4, %xmm6
        pand      %xmm5, %xmm14
        movdqa    144(%rdi), %xmm15
        paddd     %xmm6, %xmm10
        movdqa    %xmm15, 384(%rsp)
        paddd     %xmm15, %xmm10
        movdqa    %xmm12, %xmm15
        paddd     %xmm1, %xmm7
        pxor      %xmm0, %xmm15
        pxor      %xmm11, %xmm14
        pand      %xmm8, %xmm15
        paddd     %xmm14, %xmm7
        movdqa    400(%rdi), %xmm6
        paddd     %xmm1, %xmm9
        pxor      %xmm0, %xmm15
        paddd     %xmm6, %xmm7
        movdqa    %xmm6, 368(%rsp)
        paddd     %xmm15, %xmm9
        movdqa    656(%rdi), %xmm6
        paddd     %xmm1, %xmm4
        movdqa    %xmm6, 352(%rsp)
        paddd     %xmm6, %xmm9
        movdqa    %xmm10, %xmm6
        psrld     $25, %xmm10
        pslld     $7, %xmm6
        movdqa    %xmm5, %xmm15
        por       %xmm10, %xmm6
        movdqa    %xmm7, %xmm10
        pslld     $7, %xmm10
        psrld     $25, %xmm7
        por       %xmm7, %xmm10
        movdqa    %xmm9, %xmm7
        pslld     $7, %xmm7
        psrld     $25, %xmm9
        por       %xmm9, %xmm7
        movdqa    %xmm2, %xmm9
        pxor      %xmm3, %xmm9
        pxor      %xmm13, %xmm15
        pand      %xmm6, %xmm9
        pand      %xmm10, %xmm15
        pxor      %xmm3, %xmm9
        paddd     %xmm1, %xmm11
        movdqa    160(%rdi), %xmm14
        paddd     %xmm9, %xmm4
        movdqa    %xmm14, 592(%rsp)
        paddd     %xmm14, %xmm4
        movdqa    %xmm8, %xmm14
        pxor      %xmm13, %xmm15
        pxor      %xmm12, %xmm14
        paddd     %xmm15, %xmm11
        pand      %xmm7, %xmm14
        paddd     %xmm1, %xmm0
        movdqa    416(%rdi), %xmm9
        pxor      %xmm12, %xmm14
        movdqa    %xmm9, 560(%rsp)
        paddd     %xmm9, %xmm11
        movdqa    672(%rdi), %xmm9
        paddd     %xmm14, %xmm0
        movdqa    %xmm9, 576(%rsp)
        paddd     %xmm9, %xmm0
        movdqa    %xmm4, %xmm9
        psrld     $21, %xmm4
        pslld     $11, %xmm9
        paddd     %xmm1, %xmm3
        por       %xmm4, %xmm9
        movdqa    %xmm11, %xmm4
        pslld     $11, %xmm4
        psrld     $21, %xmm11
        por       %xmm11, %xmm4
        movdqa    %xmm0, %xmm11
        pslld     $11, %xmm11
        psrld     $21, %xmm0
        por       %xmm0, %xmm11
        movdqa    %xmm6, %xmm0
        pxor      %xmm2, %xmm0
        movdqa    %xmm10, %xmm15
        pand      %xmm9, %xmm0
        pxor      %xmm5, %xmm15
        pxor      %xmm2, %xmm0
        pand      %xmm4, %xmm15
        movdqa    176(%rdi), %xmm14
        paddd     %xmm0, %xmm3
        movdqa    %xmm14, 256(%rsp)
        paddd     %xmm14, %xmm3
        movdqa    %xmm7, %xmm14
        paddd     %xmm1, %xmm13
        pxor      %xmm8, %xmm14
        pxor      %xmm5, %xmm15
        pand      %xmm11, %xmm14
        paddd     %xmm15, %xmm13
        movdqa    432(%rdi), %xmm0
        paddd     %xmm1, %xmm12
        pxor      %xmm8, %xmm14
        paddd     %xmm0, %xmm13
        movdqa    %xmm0, 336(%rsp)
        paddd     %xmm14, %xmm12
        movdqa    688(%rdi), %xmm0
        paddd     %xmm1, %xmm2
        movdqa    %xmm0, 320(%rsp)
        paddd     %xmm0, %xmm12
        movdqa    %xmm3, %xmm0
        psrld     $13, %xmm3
        pslld     $19, %xmm0
        paddd     %xmm1, %xmm5
        por       %xmm3, %xmm0
        movdqa    %xmm13, %xmm3
        pslld     $19, %xmm3
        psrld     $13, %xmm13
        por       %xmm13, %xmm3
        movdqa    %xmm12, %xmm13
        pslld     $19, %xmm13
        psrld     $13, %xmm12
        por       %xmm12, %xmm13
        movdqa    %xmm9, %xmm12
        pxor      %xmm6, %xmm12
        movdqa    %xmm4, %xmm15
        pand      %xmm0, %xmm12
        paddd     %xmm1, %xmm8
        movdqa    %xmm11, %xmm1
        pxor      %xmm6, %xmm12
        pxor      %xmm10, %xmm15
        pxor      %xmm7, %xmm1
        movdqa    192(%rdi), %xmm14
        paddd     %xmm12, %xmm2
        pand      %xmm3, %xmm15
        pand      %xmm13, %xmm1
        paddd     %xmm14, %xmm2
        pxor      %xmm10, %xmm15
        pxor      %xmm7, %xmm1
        paddd     %xmm15, %xmm5
        movdqa    448(%rdi), %xmm12
        paddd     %xmm1, %xmm8
        movdqa    %xmm2, %xmm1
        paddd     %xmm12, %xmm5
        pslld     $3, %xmm1
        psrld     $29, %xmm2
        movdqa    %xmm12, 736(%rsp)
        por       %xmm2, %xmm1
        movdqa    704(%rdi), %xmm12
        movdqa    %xmm5, %xmm2
        movdqa    %xmm14, 704(%rsp)
        paddd     %xmm12, %xmm8
        movdqa    %xmm12, 720(%rsp)
        pslld     $3, %xmm2
        psrld     $29, %xmm5
..B8.12:
        movdqa    %xmm3, %xmm15
        por       %xmm5, %xmm2
        pxor      %xmm4, %xmm15
        movdqa    %xmm0, %xmm14
        pxor      %xmm12, %xmm12
        pand      %xmm2, %xmm15
        movdqa    %xmm8, %xmm5
        paddd     %xmm12, %xmm10
        pxor      %xmm4, %xmm15
        pxor      %xmm9, %xmm14
        pslld     $3, %xmm5
        psrld     $29, %xmm8
        paddd     %xmm15, %xmm10
        movdqa    %xmm13, %xmm15
        pand      %xmm1, %xmm14
        por       %xmm8, %xmm5
        pxor      %xmm11, %xmm15
        paddd     %xmm12, %xmm6
        pxor      %xmm9, %xmm14
        pand      %xmm5, %xmm15
        paddd     %xmm14, %xmm6
        paddd     %xmm12, %xmm7
        movdqa    464(%rdi), %xmm14
        pxor      %xmm11, %xmm15
        movdqa    %xmm14, 544(%rsp)
        paddd     %xmm14, %xmm10
        movdqa    720(%rdi), %xmm14
        paddd     %xmm15, %xmm7
        movdqa    208(%rdi), %xmm8
        paddd     %xmm14, %xmm7
        movdqa    %xmm14, 464(%rsp)
        paddd     %xmm8, %xmm6
        movdqa    %xmm7, %xmm14
        movdqa    %xmm6, %xmm15
        pslld     $7, %xmm14
        psrld     $25, %xmm7
        pslld     $7, %xmm15
        psrld     $25, %xmm6
        por       %xmm7, %xmm14
        movdqa    %xmm1, %xmm7
        por       %xmm6, %xmm15
        pxor      %xmm0, %xmm7
        pand      %xmm15, %xmm7
        movdqa    %xmm10, %xmm6
        paddd     %xmm12, %xmm9
        pxor      %xmm0, %xmm7
        pslld     $7, %xmm6
        psrld     $25, %xmm10
        paddd     %xmm7, %xmm9
        movdqa    %xmm3, %xmm7
        por       %xmm10, %xmm6
        pxor      %xmm2, %xmm7
        pand      %xmm6, %xmm7
        paddd     %xmm12, %xmm4
        pxor      %xmm3, %xmm7
        paddd     %xmm12, %xmm11
        paddd     %xmm7, %xmm4
        movdqa    %xmm13, %xmm7
        pxor      %xmm5, %xmm7
        paddd     %xmm12, %xmm0
        movdqa    224(%rdi), %xmm10
        pand      %xmm14, %xmm7
        movdqa    %xmm10, 672(%rsp)
        paddd     %xmm10, %xmm9
        movdqa    480(%rdi), %xmm10
        pxor      %xmm13, %xmm7
        movdqa    %xmm10, 608(%rsp)
        paddd     %xmm10, %xmm4
        movdqa    736(%rdi), %xmm10
        paddd     %xmm7, %xmm11
        paddd     %xmm10, %xmm11
        movdqa    %xmm9, %xmm7
        movdqa    %xmm10, 640(%rsp)
        movdqa    %xmm11, %xmm10
        pslld     $11, %xmm10
        psrld     $21, %xmm11
        pslld     $11, %xmm7
        psrld     $21, %xmm9
        por       %xmm11, %xmm10
        movdqa    %xmm1, %xmm11
        por       %xmm9, %xmm7
        pxor      %xmm15, %xmm11
        pand      %xmm7, %xmm11
        movdqa    %xmm4, %xmm9
        pxor      %xmm1, %xmm11
        pslld     $11, %xmm9
        psrld     $21, %xmm4
        paddd     %xmm11, %xmm0
        movdqa    %xmm6, %xmm11
        por       %xmm4, %xmm9
        pxor      %xmm2, %xmm11
        paddd     %xmm12, %xmm3
        pand      %xmm9, %xmm11
        paddd     %xmm12, %xmm13
        movdqa    %xmm14, %xmm12
        pxor      %xmm2, %xmm11
        movdqa    240(%rdi), %xmm4
        pxor      %xmm5, %xmm12
        movdqa    %xmm4, 448(%rsp)
        paddd     %xmm4, %xmm0
        movdqa    496(%rdi), %xmm4
        paddd     %xmm11, %xmm3
        pand      %xmm10, %xmm12
        paddd     %xmm4, %xmm3
        pxor      %xmm5, %xmm12
        movdqa    752(%rdi), %xmm11
        paddd     %xmm12, %xmm13
        movdqa    %xmm3, %xmm12
        paddd     %xmm11, %xmm13
        movdqa    %xmm11, 768(%rsp)
        movdqa    %xmm0, %xmm11
        pslld     $19, %xmm12
        psrld     $13, %xmm3
        movdqa    %xmm4, 800(%rsp)
        pslld     $19, %xmm11
        psrld     $13, %xmm0
        por       %xmm3, %xmm12
        movdqa    %xmm13, %xmm4
        movdqa    %xmm7, %xmm3
        por       %xmm0, %xmm11
        pslld     $19, %xmm4
        psrld     $13, %xmm13
        por       %xmm15, %xmm3
        movdqa    %xmm7, %xmm0
        por       %xmm13, %xmm4
        movdqa    .L_2il0floatpacket.488(%rip), %xmm13
        pand      %xmm11, %xmm3
        pand      %xmm15, %xmm0
        paddd     %xmm13, %xmm1
        por       %xmm0, %xmm3
        movdqa    %xmm9, %xmm0
        paddd     %xmm3, %xmm1
        movdqa    %xmm9, %xmm3
        por       %xmm6, %xmm3
        pand      %xmm6, %xmm0
        pand      %xmm12, %xmm3
        paddd     %xmm13, %xmm2
        por       %xmm0, %xmm3
        movdqa    %xmm10, %xmm0
        paddd     %xmm3, %xmm2
        movdqa    %xmm10, %xmm3
        por       %xmm14, %xmm3
        pand      %xmm14, %xmm0
        paddd     784(%rsp), %xmm1
        pand      %xmm4, %xmm3
        por       %xmm0, %xmm3
        movdqa    %xmm1, %xmm0
        paddd     816(%rsp), %xmm2
        paddd     %xmm13, %xmm5
        pslld     $3, %xmm0
        psrld     $29, %xmm1
        paddd     %xmm3, %xmm5
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        psrld     $29, %xmm2
        paddd     752(%rsp), %xmm5
        pslld     $3, %xmm1
        por       %xmm2, %xmm1
        movdqa    %xmm5, %xmm2
        pslld     $3, %xmm2
        psrld     $29, %xmm5
        movdqa    %xmm11, %xmm3
        por       %xmm5, %xmm2
        por       %xmm7, %xmm3
        movdqa    %xmm11, %xmm5
        pand      %xmm0, %xmm3
        pand      %xmm7, %xmm5
        paddd     %xmm13, %xmm15
        por       %xmm5, %xmm3
        paddd     %xmm3, %xmm15
        movdqa    %xmm12, %xmm3
        por       %xmm9, %xmm3
        movdqa    %xmm12, %xmm5
        pand      %xmm1, %xmm3
        pand      %xmm9, %xmm5
        paddd     %xmm13, %xmm6
        por       %xmm5, %xmm3
        paddd     %xmm3, %xmm6
        movdqa    %xmm4, %xmm3
        por       %xmm10, %xmm3
        movdqa    %xmm4, %xmm5
        pand      %xmm2, %xmm3
        pand      %xmm10, %xmm5
        paddd     480(%rsp), %xmm15
        paddd     %xmm13, %xmm14
        por       %xmm5, %xmm3
        paddd     %xmm13, %xmm7
        paddd     %xmm3, %xmm14
        movdqa    %xmm15, %xmm3
        paddd     512(%rsp), %xmm14
        pslld     $5, %xmm3
        psrld     $27, %xmm15
        paddd     %xmm13, %xmm9
        paddd     496(%rsp), %xmm6
        por       %xmm15, %xmm3
        movdqa    %xmm14, %xmm15
        movdqa    %xmm6, %xmm5
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        pslld     $5, %xmm5
        psrld     $27, %xmm6
        por       %xmm14, %xmm15
        movdqa    %xmm0, %xmm14
        por       %xmm6, %xmm5
        por       %xmm11, %xmm14
        movdqa    %xmm0, %xmm6
        pand      %xmm3, %xmm14
        pand      %xmm11, %xmm6
        paddd     %xmm13, %xmm10
        por       %xmm6, %xmm14
        movdqa    %xmm1, %xmm6
        paddd     %xmm14, %xmm7
        movdqa    %xmm1, %xmm14
        por       %xmm12, %xmm14
        pand      %xmm12, %xmm6
        pand      %xmm5, %xmm14
        paddd     %xmm13, %xmm11
        por       %xmm6, %xmm14
        movdqa    %xmm2, %xmm6
        paddd     %xmm14, %xmm9
        movdqa    %xmm2, %xmm14
        por       %xmm4, %xmm14
        pand      %xmm4, %xmm6
        paddd     688(%rsp), %xmm7
        pand      %xmm15, %xmm14
        por       %xmm6, %xmm14
        movdqa    %xmm7, %xmm6
        paddd     624(%rsp), %xmm9
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        paddd     %xmm14, %xmm10
        por       %xmm7, %xmm6
        movdqa    %xmm9, %xmm7
        paddd     656(%rsp), %xmm10
        pslld     $9, %xmm7
        psrld     $23, %xmm9
        movdqa    %xmm3, %xmm14
        por       %xmm9, %xmm7
        movdqa    %xmm10, %xmm9
        pslld     $9, %xmm9
        psrld     $23, %xmm10
        por       %xmm10, %xmm9
        por       %xmm0, %xmm14
        movdqa    %xmm3, %xmm10
        pand      %xmm6, %xmm14
        pand      %xmm0, %xmm10
        paddd     %xmm13, %xmm12
        por       %xmm10, %xmm14
        movdqa    %xmm5, %xmm10
        paddd     %xmm14, %xmm11
        movdqa    %xmm5, %xmm14
        por       %xmm1, %xmm14
        pand      %xmm1, %xmm10
        pand      %xmm7, %xmm14
        paddd     %xmm13, %xmm4
        por       %xmm10, %xmm14
        movdqa    %xmm15, %xmm10
        paddd     %xmm14, %xmm12
        movdqa    %xmm15, %xmm14
        por       %xmm2, %xmm14
        pand      %xmm2, %xmm10
        pand      %xmm9, %xmm14
        paddd     %xmm13, %xmm0
        paddd     704(%rsp), %xmm11
        por       %xmm10, %xmm14
        paddd     736(%rsp), %xmm12
        paddd     %xmm14, %xmm4
        movdqa    %xmm11, %xmm14
        psrld     $19, %xmm11
        paddd     720(%rsp), %xmm4
        pslld     $13, %xmm14
        movdqa    %xmm12, %xmm10
        por       %xmm11, %xmm14
        pslld     $13, %xmm10
        psrld     $19, %xmm12
        movdqa    %xmm4, %xmm11
        por       %xmm12, %xmm10
        pslld     $13, %xmm11
        psrld     $19, %xmm4
        movdqa    %xmm6, %xmm12
        por       %xmm4, %xmm11
        por       %xmm3, %xmm12
        movdqa    %xmm6, %xmm4
        pand      %xmm14, %xmm12
        pand      %xmm3, %xmm4
        por       %xmm4, %xmm12
        movdqa    %xmm7, %xmm4
        paddd     %xmm12, %xmm0
        movdqa    %xmm7, %xmm12
        por       %xmm5, %xmm12
        pand      %xmm5, %xmm4
        pand      %xmm10, %xmm12
        paddd     %xmm13, %xmm1
        por       %xmm4, %xmm12
        movdqa    %xmm9, %xmm4
        paddd     %xmm12, %xmm1
        movdqa    %xmm9, %xmm12
        por       %xmm15, %xmm12
        pand      %xmm15, %xmm4
        pand      %xmm11, %xmm12
        paddd     %xmm13, %xmm2
        paddd     112(%rsp), %xmm0
        por       %xmm4, %xmm12
        paddd     %xmm12, %xmm2
        movdqa    %xmm0, %xmm12
        paddd     176(%rsp), %xmm1
        pslld     $3, %xmm12
        psrld     $29, %xmm0
        movdqa    %xmm14, %xmm4
        por       %xmm0, %xmm12
        movdqa    %xmm1, %xmm0
        paddd     192(%rsp), %xmm2
        pslld     $3, %xmm0
        psrld     $29, %xmm1
        por       %xmm6, %xmm4
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        pslld     $3, %xmm1
        psrld     $29, %xmm2
        por       %xmm2, %xmm1
        movdqa    %xmm14, %xmm2
        pand      %xmm12, %xmm4
        pand      %xmm6, %xmm2
        paddd     %xmm13, %xmm3
        por       %xmm2, %xmm4
        paddd     %xmm4, %xmm3
        movdqa    %xmm10, %xmm4
        por       %xmm7, %xmm4
        movdqa    %xmm10, %xmm2
        pand      %xmm0, %xmm4
        pand      %xmm7, %xmm2
        paddd     %xmm13, %xmm5
        por       %xmm2, %xmm4
        paddd     %xmm4, %xmm5
        movdqa    %xmm11, %xmm4
        por       %xmm9, %xmm4
        movdqa    %xmm11, %xmm2
        paddd     208(%rsp), %xmm3
        pand      %xmm1, %xmm4
        pand      %xmm9, %xmm2
        paddd     %xmm13, %xmm15
        por       %xmm2, %xmm4
        movdqa    %xmm3, %xmm2
        paddd     224(%rsp), %xmm5
        paddd     %xmm4, %xmm15
        pslld     $5, %xmm2
        psrld     $27, %xmm3
        paddd     240(%rsp), %xmm15
        por       %xmm3, %xmm2
        movdqa    %xmm5, %xmm3
        psrld     $27, %xmm5
        pslld     $5, %xmm3
        movdqa    %xmm15, %xmm4
        por       %xmm5, %xmm3
        pslld     $5, %xmm4
        psrld     $27, %xmm15
        movdqa    %xmm12, %xmm5
        por       %xmm15, %xmm4
        por       %xmm14, %xmm5
        movdqa    %xmm12, %xmm15
        pand      %xmm2, %xmm5
        pand      %xmm14, %xmm15
        paddd     %xmm13, %xmm6
        por       %xmm15, %xmm5
        movdqa    %xmm0, %xmm15
        paddd     %xmm5, %xmm6
        movdqa    %xmm0, %xmm5
        por       %xmm10, %xmm5
        pand      %xmm10, %xmm15
        pand      %xmm3, %xmm5
        paddd     %xmm13, %xmm7
        por       %xmm15, %xmm5
        movdqa    %xmm1, %xmm15
        paddd     %xmm5, %xmm7
        movdqa    %xmm1, %xmm5
        por       %xmm11, %xmm5
        pand      %xmm11, %xmm15
        pand      %xmm4, %xmm5
        paddd     %xmm13, %xmm9
        paddd     384(%rsp), %xmm6
        por       %xmm15, %xmm5
        paddd     %xmm5, %xmm9
        movdqa    %xmm6, %xmm5
        paddd     368(%rsp), %xmm7
        pslld     $9, %xmm5
        psrld     $23, %xmm6
        movdqa    %xmm2, %xmm15
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        paddd     352(%rsp), %xmm9
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        por       %xmm12, %xmm15
        por       %xmm7, %xmm6
        movdqa    %xmm9, %xmm7
        pslld     $9, %xmm7
        psrld     $23, %xmm9
        por       %xmm9, %xmm7
        movdqa    %xmm2, %xmm9
        pand      %xmm5, %xmm15
        pand      %xmm12, %xmm9
        paddd     %xmm13, %xmm14
        por       %xmm9, %xmm15
        paddd     %xmm15, %xmm14
        movdqa    %xmm3, %xmm9
        movdqa    %xmm8, 528(%rsp)
        paddd     %xmm8, %xmm14
        por       %xmm0, %xmm9
        movdqa    %xmm3, %xmm8
        pand      %xmm6, %xmm9
        pand      %xmm0, %xmm8
        por       %xmm8, %xmm9
        movdqa    %xmm4, %xmm8
        paddd     %xmm13, %xmm10
        por       %xmm1, %xmm8
        movdqa    %xmm4, %xmm15
        paddd     %xmm9, %xmm10
        pand      %xmm7, %xmm8
        pand      %xmm1, %xmm15
        paddd     464(%rdi), %xmm10
        paddd     %xmm13, %xmm11
        por       %xmm15, %xmm8
        movdqa    %xmm10, %xmm9
        paddd     %xmm8, %xmm11
        movdqa    %xmm14, %xmm8
        paddd     720(%rdi), %xmm11
        pslld     $13, %xmm9
        psrld     $19, %xmm10
        pslld     $13, %xmm8
        psrld     $19, %xmm14
        por       %xmm10, %xmm9
        movdqa    %xmm11, %xmm10
        por       %xmm14, %xmm8
        pslld     $13, %xmm10
        psrld     $19, %xmm11
        movdqa    %xmm5, %xmm14
        por       %xmm11, %xmm10
        por       %xmm2, %xmm14
        movdqa    %xmm5, %xmm11
        pand      %xmm8, %xmm14
        pand      %xmm2, %xmm11
        movdqa    %xmm6, %xmm15
        paddd     %xmm13, %xmm12
        por       %xmm11, %xmm14
        por       %xmm3, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm14, %xmm12
        pand      %xmm9, %xmm15
        pand      %xmm3, %xmm11
        movdqa    %xmm7, %xmm14
        por       %xmm11, %xmm15
        por       %xmm4, %xmm14
        movdqa    %xmm7, %xmm11
        paddd     272(%rsp), %xmm12
        paddd     %xmm13, %xmm0
        pand      %xmm10, %xmm14
        pand      %xmm4, %xmm11
        paddd     %xmm15, %xmm0
        paddd     %xmm13, %xmm1
        por       %xmm11, %xmm14
        movdqa    %xmm12, %xmm11
        paddd     288(%rsp), %xmm0
        paddd     %xmm14, %xmm1
        pslld     $3, %xmm11
        psrld     $29, %xmm12
        paddd     304(%rsp), %xmm1
        por       %xmm12, %xmm11
        movdqa    %xmm0, %xmm12
        psrld     $29, %xmm0
        pslld     $3, %xmm12
        movdqa    %xmm1, %xmm14
        por       %xmm0, %xmm12
        pslld     $3, %xmm14
        psrld     $29, %xmm1
        movdqa    %xmm8, %xmm0
        por       %xmm1, %xmm14
        por       %xmm5, %xmm0
        movdqa    %xmm8, %xmm1
        pand      %xmm11, %xmm0
        pand      %xmm5, %xmm1
        paddd     %xmm13, %xmm2
        por       %xmm1, %xmm0
        movdqa    %xmm9, %xmm15
        paddd     %xmm0, %xmm2
        movdqa    %xmm9, %xmm0
        por       %xmm6, %xmm0
        pand      %xmm6, %xmm15
        pand      %xmm12, %xmm0
        paddd     %xmm13, %xmm3
        por       %xmm15, %xmm0
        movdqa    %xmm10, %xmm1
        paddd     %xmm0, %xmm3
        movdqa    %xmm10, %xmm0
        por       %xmm7, %xmm0
        pand      %xmm7, %xmm1
        paddd     400(%rsp), %xmm2
        pand      %xmm14, %xmm0
        paddd     416(%rsp), %xmm3
        paddd     %xmm13, %xmm4
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        paddd     %xmm0, %xmm4
        pslld     $5, %xmm1
        psrld     $27, %xmm2
        movdqa    %xmm3, %xmm0
        paddd     432(%rsp), %xmm4
        por       %xmm2, %xmm1
        pslld     $5, %xmm0
        psrld     $27, %xmm3
        movdqa    %xmm11, %xmm2
        por       %xmm3, %xmm0
        movdqa    %xmm4, %xmm15
        por       %xmm8, %xmm2
        movdqa    %xmm11, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        pand      %xmm1, %xmm2
        pand      %xmm8, %xmm3
        por       %xmm4, %xmm15
        paddd     %xmm13, %xmm5
        por       %xmm3, %xmm2
..B8.11:
        movdqa    %xmm12, %xmm4
        paddd     %xmm2, %xmm5
        por       %xmm9, %xmm4
        movdqa    %xmm12, %xmm2
        pand      %xmm0, %xmm4
        pand      %xmm9, %xmm2
        paddd     %xmm13, %xmm6
        por       %xmm2, %xmm4
        paddd     %xmm4, %xmm6
        movdqa    %xmm14, %xmm4
        movdqa    592(%rsp), %xmm3
        por       %xmm10, %xmm4
        movdqa    %xmm14, %xmm2
        paddd     %xmm3, %xmm5
        pand      %xmm15, %xmm4
        pand      %xmm10, %xmm2
        por       %xmm2, %xmm4
        movdqa    %xmm5, %xmm2
        paddd     560(%rsp), %xmm6
        paddd     %xmm13, %xmm7
        pslld     $9, %xmm2
        psrld     $23, %xmm5
        paddd     %xmm4, %xmm7
        por       %xmm5, %xmm2
        movdqa    %xmm6, %xmm5
        psrld     $23, %xmm6
        paddd     576(%rsp), %xmm7
        pslld     $9, %xmm5
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        movdqa    %xmm1, %xmm4
        por       %xmm7, %xmm6
        por       %xmm11, %xmm4
        movdqa    %xmm1, %xmm7
        pand      %xmm2, %xmm4
        pand      %xmm11, %xmm7
        paddd     %xmm13, %xmm8
        por       %xmm7, %xmm4
        paddd     %xmm4, %xmm8
        movdqa    %xmm0, %xmm4
        por       %xmm12, %xmm4
        movdqa    %xmm0, %xmm7
        pand      %xmm5, %xmm4
        pand      %xmm12, %xmm7
        paddd     %xmm13, %xmm9
        por       %xmm7, %xmm4
        paddd     %xmm4, %xmm9
        movdqa    %xmm15, %xmm4
        por       %xmm14, %xmm4
        movdqa    %xmm15, %xmm7
        paddd     672(%rsp), %xmm8
        pand      %xmm6, %xmm4
        pand      %xmm14, %xmm7
        paddd     %xmm13, %xmm10
        por       %xmm7, %xmm4
        movdqa    %xmm8, %xmm7
        paddd     608(%rsp), %xmm9
        pslld     $13, %xmm7
        psrld     $19, %xmm8
        paddd     %xmm4, %xmm10
        por       %xmm8, %xmm7
        movdqa    %xmm9, %xmm8
        paddd     640(%rsp), %xmm10
        pslld     $13, %xmm8
        psrld     $19, %xmm9
        movdqa    %xmm1, %xmm4
        por       %xmm9, %xmm8
        movdqa    %xmm10, %xmm9
        pslld     $13, %xmm9
        psrld     $19, %xmm10
        por       %xmm10, %xmm9
        por       %xmm2, %xmm4
        movdqa    %xmm1, %xmm10
        pand      %xmm7, %xmm4
        pand      %xmm2, %xmm10
        paddd     %xmm13, %xmm11
        por       %xmm10, %xmm4
        movdqa    %xmm0, %xmm10
        paddd     %xmm4, %xmm11
        movdqa    %xmm0, %xmm4
        por       %xmm5, %xmm4
        pand      %xmm5, %xmm10
        pand      %xmm8, %xmm4
        paddd     %xmm13, %xmm12
        por       %xmm10, %xmm4
        movdqa    %xmm15, %xmm10
        paddd     %xmm4, %xmm12
        movdqa    %xmm15, %xmm4
        por       %xmm6, %xmm4
        pand      %xmm6, %xmm10
        paddd     64(%rsp), %xmm11
        pand      %xmm9, %xmm4
        por       %xmm10, %xmm4
        movdqa    %xmm11, %xmm10
        paddd     80(%rsp), %xmm12
        paddd     %xmm13, %xmm14
        pslld     $3, %xmm10
        psrld     $29, %xmm11
        paddd     %xmm4, %xmm14
        por       %xmm11, %xmm10
        movdqa    %xmm12, %xmm11
        psrld     $29, %xmm12
        paddd     96(%rsp), %xmm14
        pslld     $3, %xmm11
        por       %xmm12, %xmm11
        movdqa    %xmm14, %xmm12
        pslld     $3, %xmm12
        psrld     $29, %xmm14
        movdqa    %xmm7, %xmm4
        por       %xmm14, %xmm12
        por       %xmm2, %xmm4
        movdqa    %xmm7, %xmm14
        pand      %xmm10, %xmm4
        pand      %xmm2, %xmm14
        paddd     %xmm13, %xmm1
        por       %xmm14, %xmm4
        paddd     %xmm4, %xmm1
        movdqa    %xmm8, %xmm4
        por       %xmm5, %xmm4
        movdqa    %xmm8, %xmm14
        pand      %xmm11, %xmm4
        pand      %xmm5, %xmm14
        paddd     %xmm13, %xmm0
        por       %xmm14, %xmm4
        paddd     %xmm4, %xmm0
        movdqa    %xmm9, %xmm4
        por       %xmm6, %xmm4
        movdqa    %xmm9, %xmm14
        paddd     160(%rsp), %xmm1
        pand      %xmm12, %xmm4
        pand      %xmm6, %xmm14
        paddd     %xmm13, %xmm15
        por       %xmm14, %xmm4
        movdqa    %xmm1, %xmm14
        paddd     144(%rsp), %xmm0
        pslld     $5, %xmm14
        psrld     $27, %xmm1
        paddd     %xmm4, %xmm15
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        paddd     128(%rsp), %xmm15
        pslld     $5, %xmm1
        psrld     $27, %xmm0
        movdqa    %xmm10, %xmm4
        por       %xmm0, %xmm1
        movdqa    %xmm15, %xmm0
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        por       %xmm15, %xmm0
        por       %xmm7, %xmm4
        movdqa    %xmm10, %xmm15
        pand      %xmm14, %xmm4
        pand      %xmm7, %xmm15
        paddd     %xmm13, %xmm2
        por       %xmm15, %xmm4
        movdqa    %xmm11, %xmm15
        paddd     %xmm4, %xmm2
        movdqa    %xmm11, %xmm4
        por       %xmm8, %xmm4
        pand      %xmm8, %xmm15
        pand      %xmm1, %xmm4
        paddd     %xmm13, %xmm5
        por       %xmm15, %xmm4
        movdqa    %xmm12, %xmm15
        paddd     %xmm4, %xmm5
        movdqa    %xmm12, %xmm4
        por       %xmm9, %xmm4
        pand      %xmm9, %xmm15
        paddd     256(%rsp), %xmm2
        pand      %xmm0, %xmm4
        paddd     %xmm13, %xmm6
        por       %xmm15, %xmm4
        movdqa    %xmm2, %xmm15
        paddd     %xmm4, %xmm6
        paddd     336(%rsp), %xmm5
        pslld     $9, %xmm15
        psrld     $23, %xmm2
        paddd     %xmm13, %xmm7
        paddd     320(%rsp), %xmm6
        por       %xmm2, %xmm15
        movdqa    %xmm5, %xmm2
        psrld     $23, %xmm5
        pslld     $9, %xmm2
        movdqa    %xmm6, %xmm4
        por       %xmm5, %xmm2
        pslld     $9, %xmm4
        psrld     $23, %xmm6
        movdqa    %xmm14, %xmm5
        por       %xmm6, %xmm4
        por       %xmm10, %xmm5
        movdqa    %xmm14, %xmm6
        pand      %xmm15, %xmm5
        pand      %xmm10, %xmm6
        paddd     %xmm13, %xmm8
        por       %xmm6, %xmm5
        movdqa    %xmm1, %xmm6
        paddd     %xmm5, %xmm7
        movdqa    %xmm1, %xmm5
        por       %xmm11, %xmm5
        pand      %xmm11, %xmm6
        pand      %xmm2, %xmm5
        paddd     %xmm13, %xmm9
        por       %xmm6, %xmm5
        movdqa    %xmm0, %xmm6
        por       %xmm12, %xmm6
        movdqa    %xmm0, %xmm13
        paddd     %xmm5, %xmm8
        pand      %xmm4, %xmm6
        pand      %xmm12, %xmm13
        paddd     800(%rsp), %xmm8
        por       %xmm13, %xmm6
        paddd     %xmm6, %xmm9
        movdqa    %xmm8, %xmm13
        paddd     768(%rsp), %xmm9
        pslld     $13, %xmm13
        psrld     $19, %xmm8
        paddd     448(%rsp), %xmm7
        por       %xmm8, %xmm13
        movdqa    %xmm9, %xmm8
        movdqa    %xmm7, %xmm5
        pslld     $13, %xmm8
        psrld     $19, %xmm9
        pslld     $13, %xmm5
        psrld     $19, %xmm7
        por       %xmm9, %xmm8
        movdqa    %xmm15, %xmm9
        movdqa    .L_2il0floatpacket.489(%rip), %xmm6
        por       %xmm7, %xmm5
        pxor      %xmm14, %xmm9
        paddd     %xmm6, %xmm10
        pxor      %xmm5, %xmm9
        movdqa    %xmm2, %xmm7
        paddd     %xmm9, %xmm10
        movdqa    %xmm4, %xmm9
        pxor      %xmm1, %xmm7
        pxor      %xmm0, %xmm9
        paddd     784(%rsp), %xmm10
        paddd     %xmm6, %xmm11
        pxor      %xmm13, %xmm7
        paddd     %xmm6, %xmm12
        pxor      %xmm8, %xmm9
        paddd     %xmm7, %xmm11
        paddd     %xmm9, %xmm12
        movdqa    %xmm10, %xmm9
        paddd     816(%rsp), %xmm11
        pslld     $3, %xmm9
        psrld     $29, %xmm10
        paddd     %xmm6, %xmm14
        por       %xmm10, %xmm9
        movdqa    %xmm11, %xmm10
        paddd     752(%rsp), %xmm12
        pslld     $3, %xmm10
        psrld     $29, %xmm11
        movdqa    %xmm13, %xmm7
        por       %xmm11, %xmm10
        movdqa    %xmm12, %xmm11
        pslld     $3, %xmm11
        psrld     $29, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm5, %xmm12
        pxor      %xmm15, %xmm12
        pxor      %xmm2, %xmm7
        pxor      %xmm9, %xmm12
        paddd     %xmm6, %xmm1
        paddd     %xmm12, %xmm14
        movdqa    %xmm8, %xmm12
        pxor      %xmm4, %xmm12
        pxor      %xmm10, %xmm7
        paddd     688(%rsp), %xmm14
        paddd     %xmm6, %xmm0
        pxor      %xmm11, %xmm12
        paddd     %xmm7, %xmm1
        paddd     %xmm12, %xmm0
        movdqa    %xmm14, %xmm12
        paddd     624(%rsp), %xmm1
        pslld     $9, %xmm12
        psrld     $23, %xmm14
        paddd     %xmm6, %xmm15
        por       %xmm14, %xmm12
        movdqa    %xmm1, %xmm14
        paddd     656(%rsp), %xmm0
        pslld     $9, %xmm14
        psrld     $23, %xmm1
        movdqa    %xmm10, %xmm7
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        pslld     $9, %xmm1
        psrld     $23, %xmm0
        por       %xmm0, %xmm1
        movdqa    %xmm9, %xmm0
        pxor      %xmm5, %xmm0
        pxor      %xmm13, %xmm7
        pxor      %xmm12, %xmm0
        paddd     %xmm6, %xmm2
        paddd     %xmm0, %xmm15
        movdqa    %xmm11, %xmm0
        pxor      %xmm8, %xmm0
        pxor      %xmm14, %xmm7
        paddd     480(%rsp), %xmm15
        paddd     %xmm6, %xmm4
        pxor      %xmm1, %xmm0
        paddd     %xmm7, %xmm2
        paddd     %xmm0, %xmm4
        movdqa    %xmm15, %xmm0
        paddd     496(%rsp), %xmm2
        pslld     $11, %xmm0
        psrld     $21, %xmm15
        movdqa    %xmm14, %xmm7
        por       %xmm15, %xmm0
        movdqa    %xmm2, %xmm15
        paddd     512(%rsp), %xmm4
        pslld     $11, %xmm15
        psrld     $21, %xmm2
        paddd     %xmm6, %xmm5
        por       %xmm2, %xmm15
        movdqa    %xmm4, %xmm2
        pslld     $11, %xmm2
        psrld     $21, %xmm4
        por       %xmm4, %xmm2
        movdqa    %xmm12, %xmm4
        pxor      %xmm9, %xmm4
        pxor      %xmm10, %xmm7
        pxor      %xmm0, %xmm4
        paddd     %xmm6, %xmm13
        paddd     %xmm4, %xmm5
        pxor      %xmm15, %xmm7
        movdqa    %xmm1, %xmm4
        paddd     %xmm7, %xmm13
        pxor      %xmm11, %xmm4
        paddd     %xmm6, %xmm8
        paddd     736(%rsp), %xmm13
        pxor      %xmm2, %xmm4
        paddd     %xmm4, %xmm8
        movdqa    %xmm13, %xmm4
        paddd     720(%rsp), %xmm8
        pslld     $15, %xmm4
        psrld     $17, %xmm13
        paddd     %xmm6, %xmm9
        paddd     704(%rsp), %xmm5
        por       %xmm13, %xmm4
        movdqa    %xmm8, %xmm13
        movdqa    %xmm5, %xmm7
        pslld     $15, %xmm13
        psrld     $17, %xmm8
        pslld     $15, %xmm7
        psrld     $17, %xmm5
        por       %xmm8, %xmm13
        movdqa    %xmm0, %xmm8
        por       %xmm5, %xmm7
        pxor      %xmm12, %xmm8
        pxor      %xmm7, %xmm8
        movdqa    %xmm15, %xmm5
        paddd     %xmm8, %xmm9
        movdqa    %xmm2, %xmm8
        pxor      %xmm14, %xmm5
        pxor      %xmm1, %xmm8
        paddd     272(%rsp), %xmm9
        paddd     %xmm6, %xmm10
        pxor      %xmm4, %xmm5
        paddd     %xmm6, %xmm11
        pxor      %xmm13, %xmm8
        paddd     %xmm5, %xmm10
        paddd     %xmm8, %xmm11
        movdqa    %xmm9, %xmm8
        paddd     288(%rsp), %xmm10
        pslld     $3, %xmm8
        psrld     $29, %xmm9
        paddd     %xmm6, %xmm12
        por       %xmm9, %xmm8
        movdqa    %xmm10, %xmm9
        paddd     304(%rsp), %xmm11
        pslld     $3, %xmm9
        psrld     $29, %xmm10
        movdqa    %xmm13, %xmm5
        por       %xmm10, %xmm9
        movdqa    %xmm11, %xmm10
        pslld     $3, %xmm10
        psrld     $29, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm7, %xmm11
        pxor      %xmm0, %xmm11
        pxor      %xmm2, %xmm5
        pxor      %xmm8, %xmm11
        paddd     %xmm6, %xmm1
        paddd     %xmm11, %xmm12
        pxor      %xmm10, %xmm5
        paddd     %xmm3, %xmm12
        movdqa    %xmm4, %xmm3
        pxor      %xmm15, %xmm3
        paddd     %xmm5, %xmm1
        paddd     576(%rsp), %xmm1
        paddd     %xmm6, %xmm14
        pxor      %xmm9, %xmm3
        movdqa    %xmm12, %xmm11
        paddd     %xmm3, %xmm14
        movdqa    %xmm1, %xmm3
        paddd     560(%rsp), %xmm14
        pslld     $9, %xmm3
        psrld     $23, %xmm1
        pslld     $9, %xmm11
        psrld     $23, %xmm12
        movdqa    %xmm14, %xmm5
        por       %xmm1, %xmm3
        movdqa    %xmm8, %xmm1
        por       %xmm12, %xmm11
        pslld     $9, %xmm5
        psrld     $23, %xmm14
        pxor      %xmm7, %xmm1
        por       %xmm14, %xmm5
        paddd     %xmm6, %xmm0
        pxor      %xmm11, %xmm1
        movdqa    %xmm9, %xmm12
        movdqa    %xmm10, %xmm14
        paddd     %xmm1, %xmm0
        pxor      %xmm4, %xmm12
        pxor      %xmm13, %xmm14
        paddd     400(%rsp), %xmm0
        paddd     %xmm6, %xmm15
        pxor      %xmm5, %xmm12
        paddd     %xmm6, %xmm2
        pxor      %xmm3, %xmm14
        paddd     %xmm12, %xmm15
        paddd     %xmm14, %xmm2
        movdqa    %xmm0, %xmm12
        paddd     432(%rsp), %xmm2
        pslld     $11, %xmm12
        psrld     $21, %xmm0
        paddd     %xmm6, %xmm7
        por       %xmm0, %xmm12
        movdqa    %xmm2, %xmm0
        pslld     $11, %xmm0
        psrld     $21, %xmm2
        paddd     416(%rsp), %xmm15
        por       %xmm2, %xmm0
        movdqa    %xmm11, %xmm2
        movdqa    %xmm15, %xmm1
        pxor      %xmm8, %xmm2
        pslld     $11, %xmm1
        psrld     $21, %xmm15
        pxor      %xmm12, %xmm2
        movdqa    %xmm5, %xmm14
        por       %xmm15, %xmm1
        paddd     %xmm2, %xmm7
        pxor      %xmm9, %xmm14
        paddd     672(%rsp), %xmm7
        paddd     %xmm6, %xmm4
        pxor      %xmm1, %xmm14
        movdqa    %xmm3, %xmm15
        paddd     %xmm14, %xmm4
        movdqa    %xmm7, %xmm14
        paddd     608(%rsp), %xmm4
        pslld     $15, %xmm14
        psrld     $17, %xmm7
        pxor      %xmm10, %xmm15
        por       %xmm7, %xmm14
        movdqa    %xmm4, %xmm7
        paddd     %xmm6, %xmm13
        pxor      %xmm0, %xmm15
        pslld     $15, %xmm7
        psrld     $17, %xmm4
        paddd     %xmm15, %xmm13
        por       %xmm4, %xmm7
        movdqa    %xmm12, %xmm4
        paddd     %xmm6, %xmm8
        paddd     640(%rsp), %xmm13
        pxor      %xmm11, %xmm4
        movdqa    %xmm13, %xmm2
        pxor      %xmm14, %xmm4
        pslld     $15, %xmm2
        psrld     $17, %xmm13
        paddd     %xmm4, %xmm8
        movdqa    %xmm0, %xmm4
        por       %xmm13, %xmm2
        pxor      %xmm3, %xmm4
        movdqa    %xmm1, %xmm13
        paddd     %xmm6, %xmm10
        pxor      %xmm2, %xmm4
        pxor      %xmm5, %xmm13
        paddd     %xmm4, %xmm10
        paddd     %xmm6, %xmm9
        paddd     112(%rsp), %xmm8
        pxor      %xmm7, %xmm13
        paddd     192(%rsp), %xmm10
        paddd     %xmm13, %xmm9
        movdqa    %xmm8, %xmm13
        movdqa    %xmm10, %xmm4
        paddd     176(%rsp), %xmm9
        pslld     $3, %xmm13
        psrld     $29, %xmm8
        pslld     $3, %xmm4
        psrld     $29, %xmm10
        por       %xmm8, %xmm13
        movdqa    %xmm9, %xmm8
        por       %xmm10, %xmm4
        movdqa    %xmm14, %xmm10
        pslld     $3, %xmm8
        psrld     $29, %xmm9
        pxor      %xmm12, %xmm10
        por       %xmm9, %xmm8
        paddd     %xmm6, %xmm11
        pxor      %xmm13, %xmm10
        movdqa    %xmm7, %xmm9
        paddd     %xmm10, %xmm11
        pxor      %xmm1, %xmm9
        paddd     384(%rsp), %xmm11
        paddd     %xmm6, %xmm5
        pxor      %xmm8, %xmm9
..B8.10:
        movdqa    %xmm2, %xmm10
        paddd     %xmm9, %xmm5
        pxor      %xmm0, %xmm10
        movdqa    %xmm11, %xmm9
        paddd     368(%rsp), %xmm5
        paddd     %xmm6, %xmm3
        pxor      %xmm4, %xmm10
        pslld     $9, %xmm9
        psrld     $23, %xmm11
        paddd     %xmm10, %xmm3
        por       %xmm11, %xmm9
        movdqa    %xmm5, %xmm11
        paddd     352(%rsp), %xmm3
        pslld     $9, %xmm11
        psrld     $23, %xmm5
        movdqa    %xmm13, %xmm15
        por       %xmm5, %xmm11
        movdqa    %xmm3, %xmm5
        pslld     $9, %xmm5
        psrld     $23, %xmm3
        pxor      %xmm14, %xmm15
        por       %xmm3, %xmm5
        paddd     %xmm6, %xmm12
        pxor      %xmm9, %xmm15
        movdqa    %xmm8, %xmm3
        paddd     %xmm15, %xmm12
        pxor      %xmm7, %xmm3
        paddd     %xmm6, %xmm1
        paddd     208(%rsp), %xmm12
        pxor      %xmm11, %xmm3
        movdqa    %xmm4, %xmm10
        paddd     %xmm3, %xmm1
        pxor      %xmm2, %xmm10
        movdqa    %xmm12, %xmm3
        paddd     224(%rsp), %xmm1
        paddd     %xmm6, %xmm0
        pxor      %xmm5, %xmm10
        pslld     $11, %xmm3
        psrld     $21, %xmm12
        paddd     %xmm10, %xmm0
        por       %xmm12, %xmm3
        movdqa    %xmm1, %xmm12
        paddd     240(%rsp), %xmm0
        pslld     $11, %xmm12
        psrld     $21, %xmm1
        paddd     %xmm6, %xmm14
        por       %xmm1, %xmm12
        movdqa    %xmm0, %xmm1
        pslld     $11, %xmm1
        psrld     $21, %xmm0
        por       %xmm0, %xmm1
        movdqa    %xmm13, %xmm0
        pxor      %xmm9, %xmm0
        movdqa    %xmm8, %xmm10
        pxor      %xmm3, %xmm0
        pxor      %xmm11, %xmm10
        paddd     %xmm0, %xmm14
        paddd     %xmm6, %xmm7
        paddd     528(%rsp), %xmm14
        pxor      %xmm12, %xmm10
        movdqa    %xmm4, %xmm15
        paddd     %xmm10, %xmm7
        pxor      %xmm5, %xmm15
        movdqa    %xmm14, %xmm0
        paddd     544(%rsp), %xmm7
        paddd     %xmm6, %xmm2
        pxor      %xmm1, %xmm15
        pslld     $15, %xmm0
        psrld     $17, %xmm14
        paddd     %xmm15, %xmm2
        por       %xmm14, %xmm0
        movdqa    %xmm7, %xmm14
        paddd     464(%rsp), %xmm2
        pslld     $15, %xmm14
        psrld     $17, %xmm7
        movdqa    %xmm1, %xmm15
        por       %xmm7, %xmm14
        movdqa    %xmm2, %xmm7
        pslld     $15, %xmm7
        psrld     $17, %xmm2
        por       %xmm2, %xmm7
        movdqa    %xmm3, %xmm2
        pxor      %xmm9, %xmm2
        paddd     %xmm6, %xmm13
        pxor      %xmm0, %xmm2
        movdqa    %xmm12, %xmm10
        pxor      %xmm5, %xmm15
        paddd     %xmm2, %xmm13
        pxor      %xmm11, %xmm10
        paddd     %xmm6, %xmm4
        pxor      %xmm7, %xmm15
        paddd     %xmm6, %xmm8
        paddd     64(%rsp), %xmm13
        pxor      %xmm14, %xmm10
        paddd     %xmm15, %xmm4
        paddd     %xmm10, %xmm8
        paddd     96(%rsp), %xmm4
        movdqa    %xmm13, %xmm15
        paddd     80(%rsp), %xmm8
        pslld     $3, %xmm15
        psrld     $29, %xmm13
        movdqa    %xmm4, %xmm2
        por       %xmm13, %xmm15
        movdqa    %xmm8, %xmm10
        pslld     $3, %xmm2
        psrld     $29, %xmm4
        movdqa    %xmm7, %xmm13
        pslld     $3, %xmm10
        psrld     $29, %xmm8
        por       %xmm4, %xmm2
        movdqa    %xmm0, %xmm4
        pxor      %xmm1, %xmm13
        por       %xmm8, %xmm10
        pxor      %xmm3, %xmm4
        movdqa    %xmm14, %xmm8
        paddd     %xmm6, %xmm5
        pxor      %xmm2, %xmm13
        paddd     %xmm6, %xmm9
        pxor      %xmm15, %xmm4
        pxor      %xmm12, %xmm8
        paddd     %xmm13, %xmm5
        paddd     %xmm4, %xmm9
        paddd     320(%rsp), %xmm5
        paddd     %xmm6, %xmm11
        pxor      %xmm10, %xmm8
        movdqa    %xmm5, %xmm4
        paddd     256(%rsp), %xmm9
        paddd     %xmm8, %xmm11
        paddd     336(%rsp), %xmm11
        movdqa    %xmm9, %xmm13
        pslld     $9, %xmm4
        psrld     $23, %xmm5
        pslld     $9, %xmm13
        psrld     $23, %xmm9
        movdqa    %xmm11, %xmm8
        por       %xmm5, %xmm4
        movdqa    %xmm15, %xmm5
        por       %xmm9, %xmm13
        pslld     $9, %xmm8
        psrld     $23, %xmm11
        pxor      %xmm0, %xmm5
        por       %xmm11, %xmm8
        paddd     %xmm6, %xmm3
        pxor      %xmm13, %xmm5
        movdqa    %xmm10, %xmm9
        movdqa    %xmm2, %xmm11
        paddd     %xmm5, %xmm3
        pxor      %xmm14, %xmm9
        pxor      %xmm7, %xmm11
        paddd     %xmm6, %xmm12
        paddd     160(%rsp), %xmm3
        pxor      %xmm8, %xmm9
        paddd     %xmm6, %xmm1
        pxor      %xmm4, %xmm11
        paddd     %xmm9, %xmm12
        paddd     %xmm11, %xmm1
        movdqa    %xmm3, %xmm9
        psrld     $21, %xmm3
        paddd     128(%rsp), %xmm1
        pslld     $11, %xmm9
        por       %xmm3, %xmm9
        movdqa    %xmm1, %xmm3
        paddd     144(%rsp), %xmm12
        pslld     $11, %xmm3
        psrld     $21, %xmm1
        movdqa    %xmm12, %xmm5
        por       %xmm1, %xmm3
        movdqa    %xmm13, %xmm1
        pslld     $11, %xmm5
        psrld     $21, %xmm12
        pxor      %xmm15, %xmm1
        por       %xmm12, %xmm5
        paddd     %xmm6, %xmm0
        pxor      %xmm9, %xmm1
        paddd     %xmm6, %xmm14
        movdqa    %xmm8, %xmm12
        paddd     %xmm6, %xmm7
        movdqa    %xmm4, %xmm6
        paddd     %xmm1, %xmm0
        pxor      %xmm10, %xmm12
        pxor      %xmm2, %xmm6
        pxor      %xmm5, %xmm12
        paddd     448(%rsp), %xmm0
        pxor      %xmm3, %xmm6
        paddd     %xmm12, %xmm14
        paddd     %xmm6, %xmm7
        movdqa    %xmm0, %xmm6
        psrld     $17, %xmm0
        paddd     800(%rsp), %xmm14
        pslld     $15, %xmm6
        paddd     768(%rsp), %xmm7
        por       %xmm0, %xmm6
        movdqa    %xmm14, %xmm1
        movdqa    %xmm7, %xmm0
        pslld     $15, %xmm1
        psrld     $17, %xmm14
        pslld     $15, %xmm0
        psrld     $17, %xmm7
        por       %xmm14, %xmm1
        por       %xmm7, %xmm0
        je        ..B8.6
..B8.5:
        movdqa    .L_2il0floatpacket.484(%rip), %xmm7
        movdqa    .L_2il0floatpacket.485(%rip), %xmm11
        paddd     %xmm7, %xmm15
        movdqa    .L_2il0floatpacket.486(%rip), %xmm12
        paddd     %xmm11, %xmm6
        movdqa    .L_2il0floatpacket.487(%rip), %xmm14
        paddd     %xmm12, %xmm9
        paddd     %xmm14, %xmm13
        paddd     %xmm7, %xmm10
        paddd     %xmm11, %xmm1
        paddd     %xmm12, %xmm5
        paddd     %xmm14, %xmm8
        paddd     %xmm7, %xmm2
        paddd     %xmm11, %xmm0
        paddd     %xmm12, %xmm3
        paddd     %xmm14, %xmm4
        movdqa    %xmm15, (%rsi)
        movdqa    %xmm6, 16(%rsi)
        movdqa    %xmm9, 32(%rsi)
        movdqa    %xmm13, 48(%rsi)
        movdqa    %xmm10, 64(%rsi)
        movdqa    %xmm1, 80(%rsi)
        movdqa    %xmm5, 96(%rsi)
        movdqa    %xmm8, 112(%rsi)
        movdqa    %xmm2, 128(%rsi)
        movdqa    %xmm0, 144(%rsi)
        movdqa    %xmm3, 160(%rsi)
        movdqa    %xmm4, 176(%rsi)
        addq      $840, %rsp
..___tag_value_SSEmd4body.214:
        ret       
..___tag_value_SSEmd4body.215:
..B8.6:
        paddd     (%rsp), %xmm15
        paddd     48(%rsp), %xmm6
        paddd     32(%rsp), %xmm9
        paddd     16(%rsp), %xmm13
        paddd     64(%rsi), %xmm10
        paddd     80(%rsi), %xmm1
        paddd     96(%rsi), %xmm5
        paddd     112(%rsi), %xmm8
        paddd     128(%rsi), %xmm2
        paddd     144(%rsi), %xmm0
        paddd     160(%rsi), %xmm3
        paddd     176(%rsi), %xmm4
        movdqa    %xmm15, (%rsi)
        movdqa    %xmm6, 16(%rsi)
        movdqa    %xmm9, 32(%rsi)
        movdqa    %xmm13, 48(%rsi)
        movdqa    %xmm10, 64(%rsi)
        movdqa    %xmm1, 80(%rsi)
        movdqa    %xmm5, 96(%rsi)
        movdqa    %xmm8, 112(%rsi)
        movdqa    %xmm2, 128(%rsi)
        movdqa    %xmm0, 144(%rsi)
        movdqa    %xmm3, 160(%rsi)
        movdqa    %xmm4, 176(%rsi)
..B8.7:
        addq      $840, %rsp
..___tag_value_SSEmd4body.216:
        ret       
        .align    16,0x90
..___tag_value_SSEmd4body.217:
	.type	SSEmd4body,@function
	.size	SSEmd4body,.-SSEmd4body
	.data
# -- End  SSEmd4body
	.text
# -- Begin  SSESHA1body
       .align    16,0x90
	.globl SSESHA1body
SSESHA1body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B9.1:
..___tag_value_SSESHA1body.218:
        subq      $904, %rsp
..___tag_value_SSESHA1body.220:
        testq     %rdx, %rdx
        je        ..B9.10
..B9.2:
        movdqa    (%rdx), %xmm2
        movdqa    16(%rdx), %xmm1
        movdqa    32(%rdx), %xmm6
        movdqa    48(%rdx), %xmm4
        movdqa    64(%rdx), %xmm11
        movdqa    80(%rdx), %xmm13
        movdqa    96(%rdx), %xmm8
        movdqa    112(%rdx), %xmm12
        movdqa    128(%rdx), %xmm5
        movdqa    144(%rdx), %xmm3
..B9.3:
        movdqa    464(%rdi), %xmm0
        movdqa    %xmm6, %xmm10
        movdqa    %xmm0, 304(%rsp)
        pxor      %xmm4, %xmm10
        pxor      384(%rdi), %xmm0
        pand      %xmm1, %xmm10
        pxor      288(%rdi), %xmm0
        pxor      %xmm4, %xmm10
        pxor      256(%rdi), %xmm0
        paddd     %xmm10, %xmm11
        movdqa    %xmm0, %xmm9
        movdqa    %xmm13, %xmm10
        paddd     %xmm0, %xmm9
        psrld     $31, %xmm0
        movdqa    208(%rdi), %xmm7
        por       %xmm0, %xmm9
        movdqa    %xmm12, %xmm0
        pslld     $5, %xmm10
        movdqa    %xmm7, 688(%rsp)
        pxor      %xmm5, %xmm0
        pxor      128(%rdi), %xmm7
        pand      %xmm8, %xmm0
        pxor      32(%rdi), %xmm7
        pxor      %xmm5, %xmm0
        pxor      (%rdi), %xmm7
        paddd     %xmm0, %xmm3
        movdqa    %xmm9, 256(%rsp)
        movdqa    %xmm13, %xmm9
        movdqa    %xmm7, %xmm15
        psrld     $27, %xmm9
        movdqa    %xmm1, %xmm0
        paddd     %xmm7, %xmm15
        psrld     $31, %xmm7
        por       %xmm9, %xmm10
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        movdqa    400(%rdi), %xmm9
        por       %xmm7, %xmm15
        movdqa    %xmm2, %xmm7
        movdqa    %xmm2, %xmm14
        paddd     %xmm10, %xmm3
        por       %xmm1, %xmm0
        movdqa    480(%rdi), %xmm10
        movdqa    %xmm8, %xmm1
        movdqa    %xmm10, 656(%rsp)
        pslld     $5, %xmm7
        psrld     $27, %xmm14
        pslld     $30, %xmm1
        psrld     $2, %xmm8
        pxor      %xmm9, %xmm10
        pxor      304(%rdi), %xmm10
        por       %xmm14, %xmm7
        movdqa    144(%rdi), %xmm14
        por       %xmm8, %xmm1
        movdqa    224(%rdi), %xmm8
        paddd     %xmm7, %xmm11
        pxor      272(%rdi), %xmm10
        movdqa    %xmm8, 288(%rsp)
        pxor      %xmm14, %xmm8
        movdqa    %xmm9, 768(%rsp)
        movdqa    %xmm10, %xmm9
        pxor      48(%rdi), %xmm8
        paddd     %xmm10, %xmm9
        pxor      16(%rdi), %xmm8
        psrld     $31, %xmm10
        movdqa    .L_2il0floatpacket.547(%rip), %xmm7
        por       %xmm10, %xmm9
        movdqa    %xmm14, 848(%rsp)
        paddd     %xmm7, %xmm11
        movdqa    %xmm8, %xmm14
        movdqa    %xmm6, %xmm10
        paddd     (%rdi), %xmm11
        paddd     %xmm8, %xmm14
        psrld     $31, %xmm8
        pxor      %xmm0, %xmm10
        movdqa    %xmm9, 224(%rsp)
        por       %xmm8, %xmm14
        pand      %xmm2, %xmm10
        movdqa    %xmm11, %xmm8
        movdqa    %xmm11, %xmm9
        paddd     %xmm7, %xmm3
        movdqa    %xmm14, 240(%rsp)
        pxor      %xmm6, %xmm10
        pslld     $5, %xmm8
        psrld     $27, %xmm9
        movdqa    %xmm12, %xmm14
        paddd     %xmm10, %xmm4
        paddd     256(%rdi), %xmm3
        por       %xmm9, %xmm8
        pxor      %xmm1, %xmm14
        paddd     %xmm8, %xmm4
        pand      %xmm13, %xmm14
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm9
        pxor      %xmm12, %xmm14
        pslld     $5, %xmm8
        psrld     $27, %xmm9
        paddd     %xmm14, %xmm5
        por       %xmm9, %xmm8
        movdqa    160(%rdi), %xmm14
        paddd     %xmm8, %xmm5
        movdqa    240(%rdi), %xmm8
        movdqa    %xmm2, %xmm9
        movdqa    %xmm13, %xmm10
        pslld     $30, %xmm9
        movdqa    %xmm8, 704(%rsp)
        psrld     $2, %xmm2
        pslld     $30, %xmm10
        psrld     $2, %xmm13
        pxor      %xmm14, %xmm8
        por       %xmm2, %xmm9
        movdqa    416(%rdi), %xmm2
        por       %xmm13, %xmm10
        movdqa    496(%rdi), %xmm13
        paddd     %xmm7, %xmm4
        pxor      64(%rdi), %xmm8
        paddd     %xmm7, %xmm5
        pxor      32(%rdi), %xmm8
        movdqa    %xmm13, 720(%rsp)
        pxor      %xmm2, %xmm13
        movdqa    %xmm14, 784(%rsp)
        movdqa    %xmm8, %xmm14
        movdqa    %xmm2, 736(%rsp)
        movdqa    %xmm9, %xmm2
        pxor      320(%rdi), %xmm13
        paddd     %xmm8, %xmm14
        pxor      288(%rdi), %xmm13
        psrld     $31, %xmm8
        pxor      %xmm0, %xmm2
        por       %xmm8, %xmm14
        movdqa    %xmm13, %xmm8
        pand      %xmm11, %xmm2
        paddd     16(%rdi), %xmm4
        paddd     %xmm13, %xmm8
        psrld     $31, %xmm13
        pxor      %xmm0, %xmm2
        por       %xmm13, %xmm8
        paddd     %xmm2, %xmm6
        movdqa    %xmm4, %xmm2
        movdqa    %xmm4, %xmm13
        pslld     $5, %xmm2
        psrld     $27, %xmm13
        por       %xmm13, %xmm2
        movdqa    %xmm10, %xmm13
        pxor      %xmm1, %xmm13
        paddd     %xmm2, %xmm6
        pand      %xmm3, %xmm13
        paddd     %xmm7, %xmm6
        paddd     272(%rdi), %xmm5
        pxor      %xmm1, %xmm13
        paddd     %xmm13, %xmm12
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm2
        pslld     $5, %xmm13
        psrld     $27, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm11, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm11
        por       %xmm11, %xmm2
        movdqa    %xmm3, %xmm11
        pslld     $30, %xmm11
        psrld     $2, %xmm3
        por       %xmm3, %xmm11
        paddd     %xmm13, %xmm12
        movdqa    176(%rdi), %xmm3
        paddd     %xmm7, %xmm12
        movdqa    %xmm3, 752(%rsp)
        pxor      %xmm15, %xmm3
        movdqa    432(%rdi), %xmm13
        pxor      80(%rdi), %xmm3
        movdqa    %xmm13, 800(%rsp)
        pxor      48(%rdi), %xmm3
        pxor      256(%rsp), %xmm13
        movdqa    %xmm15, 272(%rsp)
        movdqa    %xmm3, %xmm15
        pxor      336(%rdi), %xmm13
        paddd     %xmm3, %xmm15
        pxor      304(%rdi), %xmm13
        psrld     $31, %xmm3
        por       %xmm3, %xmm15
        movdqa    %xmm13, %xmm3
        paddd     %xmm13, %xmm3
        psrld     $31, %xmm13
        paddd     32(%rdi), %xmm6
        por       %xmm13, %xmm3
        movdqa    %xmm15, 176(%rsp)
        movdqa    %xmm6, %xmm15
        movdqa    %xmm3, 160(%rsp)
        movdqa    %xmm6, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm3
        movdqa    %xmm2, %xmm13
        por       %xmm3, %xmm15
        movdqa    %xmm11, %xmm3
        pxor      %xmm9, %xmm13
        pxor      %xmm10, %xmm3
        pand      %xmm4, %xmm13
        pand      %xmm5, %xmm3
        pxor      %xmm9, %xmm13
        paddd     288(%rdi), %xmm12
        pxor      %xmm10, %xmm3
        paddd     %xmm13, %xmm0
        paddd     %xmm3, %xmm1
        movdqa    %xmm12, %xmm3
        movdqa    %xmm12, %xmm13
        pslld     $5, %xmm3
        psrld     $27, %xmm13
        por       %xmm13, %xmm3
        paddd     %xmm15, %xmm0
        paddd     %xmm3, %xmm1
        movdqa    %xmm4, %xmm3
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        movdqa    192(%rdi), %xmm15
        por       %xmm4, %xmm3
        movdqa    %xmm5, %xmm4
        psrld     $2, %xmm5
        movdqa    %xmm15, 816(%rsp)
        pslld     $30, %xmm4
        pxor      240(%rsp), %xmm15
        por       %xmm5, %xmm4
        movdqa    448(%rdi), %xmm5
        paddd     %xmm7, %xmm0
        pxor      96(%rdi), %xmm15
        paddd     %xmm7, %xmm1
        movdqa    %xmm5, 832(%rsp)
        pxor      64(%rdi), %xmm15
        pxor      224(%rsp), %xmm5
        movdqa    %xmm15, %xmm13
        pxor      352(%rdi), %xmm5
        paddd     %xmm15, %xmm13
        pxor      320(%rdi), %xmm5
        psrld     $31, %xmm15
        por       %xmm15, %xmm13
        movdqa    %xmm5, %xmm15
        paddd     %xmm5, %xmm15
        psrld     $31, %xmm5
        por       %xmm5, %xmm15
        movdqa    %xmm3, %xmm5
        pxor      %xmm2, %xmm5
        pand      %xmm6, %xmm5
        paddd     48(%rdi), %xmm0
        pxor      %xmm2, %xmm5
        movdqa    %xmm15, 608(%rsp)
        paddd     %xmm5, %xmm9
        movdqa    %xmm0, %xmm5
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm5
        psrld     $27, %xmm15
        por       %xmm15, %xmm5
        movdqa    %xmm4, %xmm15
        pxor      %xmm11, %xmm15
        paddd     %xmm5, %xmm9
        pand      %xmm12, %xmm15
        paddd     %xmm7, %xmm9
        paddd     304(%rdi), %xmm1
        pxor      %xmm11, %xmm15
        paddd     %xmm15, %xmm10
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm5
        pslld     $5, %xmm15
        psrld     $27, %xmm5
        por       %xmm5, %xmm15
        movdqa    %xmm6, %xmm5
        paddd     %xmm15, %xmm10
        pslld     $30, %xmm5
        movdqa    208(%rdi), %xmm15
        psrld     $2, %xmm6
        movdqa    %xmm14, 208(%rsp)
        pxor      %xmm14, %xmm15
        movdqa    464(%rdi), %xmm14
        por       %xmm6, %xmm5
        pxor      %xmm8, %xmm14
        movdqa    %xmm12, %xmm6
        pxor      368(%rdi), %xmm14
        pslld     $30, %xmm6
        pxor      112(%rdi), %xmm15
        psrld     $2, %xmm12
        pxor      336(%rdi), %xmm14
        por       %xmm12, %xmm6
        pxor      80(%rdi), %xmm15
        paddd     %xmm7, %xmm10
        movdqa    %xmm8, 192(%rsp)
        movdqa    %xmm14, %xmm8
        movdqa    %xmm15, %xmm12
        paddd     %xmm14, %xmm8
        psrld     $31, %xmm14
        paddd     %xmm15, %xmm12
        paddd     64(%rdi), %xmm9
        psrld     $31, %xmm15
        por       %xmm14, %xmm8
        por       %xmm15, %xmm12
        movdqa    %xmm8, 576(%rsp)
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm8
        pslld     $5, %xmm15
        psrld     $27, %xmm8
        movdqa    %xmm5, %xmm14
        por       %xmm8, %xmm15
        movdqa    %xmm6, %xmm8
        pxor      %xmm3, %xmm14
        pxor      %xmm4, %xmm8
        pand      %xmm0, %xmm14
        pand      %xmm1, %xmm8
        paddd     320(%rdi), %xmm10
        pxor      %xmm3, %xmm14
        pxor      %xmm4, %xmm8
        paddd     %xmm14, %xmm2
        paddd     %xmm8, %xmm11
        movdqa    %xmm10, %xmm8
        movdqa    %xmm10, %xmm14
        pslld     $5, %xmm8
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm2
        por       %xmm14, %xmm8
        paddd     %xmm7, %xmm2
        paddd     %xmm8, %xmm11
        movdqa    %xmm0, %xmm8
        pslld     $30, %xmm8
        psrld     $2, %xmm0
        movdqa    224(%rdi), %xmm15
        por       %xmm0, %xmm8
        movdqa    %xmm1, %xmm0
        psrld     $2, %xmm1
        pxor      176(%rsp), %xmm15
        pslld     $30, %xmm0
        pxor      128(%rdi), %xmm15
        por       %xmm1, %xmm0
        movdqa    480(%rdi), %xmm1
        paddd     %xmm7, %xmm11
        pxor      96(%rdi), %xmm15
        pxor      160(%rsp), %xmm1
        movdqa    %xmm15, %xmm14
        pxor      384(%rdi), %xmm1
        paddd     %xmm15, %xmm14
        pxor      352(%rdi), %xmm1
        psrld     $31, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm1, %xmm15
        paddd     %xmm1, %xmm15
        psrld     $31, %xmm1
        por       %xmm1, %xmm15
        movdqa    %xmm8, %xmm1
        pxor      %xmm5, %xmm1
        pand      %xmm9, %xmm1
        pxor      %xmm5, %xmm1
        paddd     %xmm1, %xmm3
        movdqa    %xmm0, %xmm1
        paddd     80(%rdi), %xmm2
        pxor      %xmm6, %xmm1
        movdqa    %xmm14, 560(%rsp)
        movdqa    %xmm2, %xmm14
        movdqa    %xmm15, 512(%rsp)
        movdqa    %xmm2, %xmm15
        pand      %xmm10, %xmm1
        pslld     $5, %xmm15
        paddd     336(%rdi), %xmm11
        psrld     $27, %xmm14
        pxor      %xmm6, %xmm1
        por       %xmm14, %xmm15
        paddd     %xmm1, %xmm4
        movdqa    %xmm11, %xmm1
        movdqa    %xmm11, %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm3
        por       %xmm14, %xmm1
        paddd     %xmm7, %xmm3
        paddd     %xmm1, %xmm4
        movdqa    %xmm9, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm9
        por       %xmm9, %xmm1
        movdqa    %xmm10, %xmm9
        pslld     $30, %xmm9
        psrld     $2, %xmm10
        por       %xmm10, %xmm9
        paddd     %xmm7, %xmm4
        movdqa    240(%rdi), %xmm10
        pxor      %xmm13, %xmm10
        pxor      144(%rdi), %xmm10
        movdqa    496(%rdi), %xmm14
        pxor      112(%rdi), %xmm10
        pxor      608(%rsp), %xmm14
        movdqa    %xmm13, 640(%rsp)
        movdqa    %xmm10, %xmm13
        pxor      400(%rdi), %xmm14
        paddd     %xmm10, %xmm13
        pxor      368(%rdi), %xmm14
        psrld     $31, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm14, %xmm15
        movdqa    %xmm1, %xmm10
        paddd     %xmm14, %xmm15
        paddd     96(%rdi), %xmm3
        psrld     $31, %xmm14
        pxor      %xmm8, %xmm10
        por       %xmm14, %xmm15
        movdqa    %xmm13, 496(%rsp)
        pand      %xmm2, %xmm10
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm13
        paddd     352(%rdi), %xmm4
        pxor      %xmm8, %xmm10
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        movdqa    %xmm15, 448(%rsp)
        paddd     %xmm10, %xmm5
        por       %xmm13, %xmm14
        movdqa    %xmm9, %xmm10
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm13
        pxor      %xmm0, %xmm10
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        pand      %xmm11, %xmm10
        por       %xmm13, %xmm15
        movdqa    %xmm11, %xmm13
        movdqa    %xmm12, 592(%rsp)
        pxor      %xmm0, %xmm10
        pxor      272(%rsp), %xmm12
        pslld     $30, %xmm13
        psrld     $2, %xmm11
        paddd     %xmm14, %xmm5
        pxor      160(%rdi), %xmm12
        paddd     %xmm10, %xmm6
        movdqa    128(%rdi), %xmm14
        movdqa    %xmm2, %xmm10
        por       %xmm11, %xmm13
        pslld     $30, %xmm10
        movdqa    576(%rsp), %xmm11
        psrld     $2, %xmm2
        pxor      256(%rsp), %xmm11
        pxor      %xmm14, %xmm12
        pxor      416(%rdi), %xmm11
        paddd     %xmm15, %xmm6
        por       %xmm2, %xmm10
        movdqa    %xmm12, %xmm15
        movdqa    384(%rdi), %xmm2
        paddd     %xmm12, %xmm15
        pxor      %xmm2, %xmm11
        psrld     $31, %xmm12
        por       %xmm12, %xmm15
        movdqa    %xmm11, %xmm12
        paddd     %xmm11, %xmm12
        psrld     $31, %xmm11
        paddd     %xmm7, %xmm5
        por       %xmm11, %xmm12
        movdqa    %xmm10, %xmm11
        paddd     %xmm7, %xmm6
        paddd     112(%rdi), %xmm5
        pxor      %xmm1, %xmm11
        movdqa    %xmm15, 432(%rsp)
        pand      %xmm3, %xmm11
        movdqa    %xmm12, 320(%rsp)
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm12
        pxor      %xmm1, %xmm11
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        paddd     %xmm11, %xmm8
        por       %xmm12, %xmm15
        paddd     %xmm15, %xmm8
        paddd     %xmm7, %xmm8
        paddd     %xmm14, %xmm8
        movdqa    %xmm13, %xmm14
        paddd     368(%rdi), %xmm6
        pxor      %xmm9, %xmm14
        pand      %xmm4, %xmm14
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        pxor      %xmm9, %xmm14
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        paddd     %xmm14, %xmm0
        por       %xmm11, %xmm12
        paddd     %xmm12, %xmm0
        paddd     %xmm7, %xmm0
        paddd     %xmm2, %xmm0
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        por       %xmm3, %xmm2
        movdqa    %xmm4, %xmm3
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        por       %xmm4, %xmm3
        movdqa    560(%rsp), %xmm4
        pxor      240(%rsp), %xmm4
        movdqa    512(%rsp), %xmm12
        pxor      176(%rdi), %xmm4
        pxor      224(%rsp), %xmm12
        pxor      144(%rdi), %xmm4
        pxor      432(%rdi), %xmm12
        movdqa    %xmm4, %xmm11
        pxor      400(%rdi), %xmm12
        paddd     %xmm4, %xmm11
        psrld     $31, %xmm4
        movdqa    %xmm12, %xmm14
        por       %xmm4, %xmm11
        movdqa    %xmm2, %xmm4
        paddd     %xmm12, %xmm14
        psrld     $31, %xmm12
        pxor      %xmm10, %xmm4
        por       %xmm12, %xmm14
        movdqa    %xmm11, 464(%rsp)
        pand      %xmm5, %xmm4
        movdqa    %xmm14, 336(%rsp)
..B9.19:
        pxor      %xmm10, %xmm4
        movdqa    %xmm8, %xmm11
        paddd     %xmm4, %xmm1
        movdqa    %xmm8, %xmm4
        pslld     $5, %xmm4
        psrld     $27, %xmm11
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm14
        por       %xmm11, %xmm4
        movdqa    %xmm3, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm14
        paddd     %xmm4, %xmm1
        pxor      %xmm13, %xmm15
        por       %xmm14, %xmm12
        movdqa    %xmm5, %xmm11
        movdqa    496(%rsp), %xmm14
        movdqa    %xmm6, %xmm4
        pxor      208(%rsp), %xmm14
        pand      %xmm6, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm5
        pslld     $30, %xmm4
        psrld     $2, %xmm6
        pxor      816(%rsp), %xmm14
        pxor      %xmm13, %xmm15
        por       %xmm5, %xmm11
        por       %xmm6, %xmm4
        movdqa    784(%rsp), %xmm6
        paddd     %xmm15, %xmm9
        movdqa    448(%rsp), %xmm5
        pxor      %xmm6, %xmm14
        pxor      192(%rsp), %xmm5
        paddd     %xmm12, %xmm9
        pxor      832(%rsp), %xmm5
        movdqa    %xmm14, %xmm12
        movdqa    736(%rsp), %xmm15
        paddd     %xmm14, %xmm12
        pxor      %xmm15, %xmm5
        psrld     $31, %xmm14
        por       %xmm14, %xmm12
        movdqa    %xmm5, %xmm14
        paddd     %xmm5, %xmm14
        psrld     $31, %xmm5
        paddd     %xmm7, %xmm1
        por       %xmm5, %xmm14
        movdqa    %xmm2, %xmm5
        paddd     %xmm7, %xmm9
        paddd     848(%rsp), %xmm1
        pxor      %xmm11, %xmm5
        movdqa    %xmm12, 480(%rsp)
        pand      %xmm8, %xmm5
        movdqa    %xmm14, 352(%rsp)
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm14
        pxor      %xmm2, %xmm5
        pslld     $5, %xmm12
        psrld     $27, %xmm14
        paddd     %xmm5, %xmm10
        por       %xmm14, %xmm12
        paddd     %xmm12, %xmm10
        movdqa    %xmm8, %xmm12
        paddd     %xmm7, %xmm10
        pslld     $30, %xmm12
        paddd     %xmm6, %xmm10
        movdqa    %xmm3, %xmm6
        paddd     768(%rsp), %xmm9
        pxor      %xmm4, %xmm6
        pand      %xmm0, %xmm6
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm5
        pxor      %xmm3, %xmm6
        pslld     $5, %xmm14
        psrld     $27, %xmm5
        paddd     %xmm6, %xmm13
        por       %xmm5, %xmm14
        paddd     %xmm14, %xmm13
        movdqa    %xmm0, %xmm5
        paddd     %xmm7, %xmm13
        pslld     $30, %xmm5
        paddd     %xmm15, %xmm13
        psrld     $2, %xmm0
        movdqa    432(%rsp), %xmm15
        por       %xmm0, %xmm5
        pxor      176(%rsp), %xmm15
        psrld     $2, %xmm8
        pxor      688(%rsp), %xmm15
        por       %xmm8, %xmm12
        movdqa    752(%rsp), %xmm0
        movdqa    320(%rsp), %xmm6
        pxor      %xmm0, %xmm15
        pxor      160(%rsp), %xmm6
        movdqa    %xmm15, %xmm14
        pxor      304(%rsp), %xmm6
        paddd     %xmm15, %xmm14
        movdqa    800(%rsp), %xmm8
        psrld     $31, %xmm15
        pxor      %xmm8, %xmm6
        por       %xmm15, %xmm14
        movdqa    %xmm6, %xmm15
        paddd     %xmm6, %xmm15
        psrld     $31, %xmm6
        por       %xmm6, %xmm15
        movdqa    %xmm12, %xmm6
        pxor      %xmm11, %xmm6
        movdqa    %xmm14, 528(%rsp)
        pand      %xmm1, %xmm6
        movdqa    %xmm15, 368(%rsp)
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm15
        pxor      %xmm11, %xmm6
        pslld     $5, %xmm14
        psrld     $27, %xmm15
        paddd     %xmm6, %xmm2
        por       %xmm15, %xmm14
        paddd     %xmm14, %xmm2
        movdqa    %xmm13, %xmm15
        paddd     %xmm7, %xmm2
        movdqa    %xmm13, %xmm6
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm0
        pxor      %xmm4, %xmm0
        pslld     $5, %xmm15
        pand      %xmm9, %xmm0
        psrld     $27, %xmm6
        pxor      %xmm4, %xmm0
        por       %xmm6, %xmm15
        paddd     %xmm0, %xmm3
        movdqa    %xmm1, %xmm6
        movdqa    464(%rsp), %xmm14
        paddd     %xmm15, %xmm3
        pxor      640(%rsp), %xmm14
        paddd     %xmm7, %xmm3
        pslld     $30, %xmm6
        psrld     $2, %xmm1
        pxor      288(%rsp), %xmm14
        paddd     %xmm8, %xmm3
        movdqa    336(%rsp), %xmm0
        por       %xmm1, %xmm6
        movdqa    816(%rsp), %xmm1
        movdqa    %xmm9, %xmm8
        pxor      608(%rsp), %xmm0
        pslld     $30, %xmm8
        psrld     $2, %xmm9
        pxor      %xmm1, %xmm14
        pxor      656(%rsp), %xmm0
        por       %xmm9, %xmm8
        movdqa    832(%rsp), %xmm9
        movdqa    %xmm14, %xmm15
        pxor      %xmm9, %xmm0
        paddd     %xmm14, %xmm15
        psrld     $31, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm0, %xmm14
        paddd     %xmm0, %xmm14
        psrld     $31, %xmm0
        por       %xmm0, %xmm14
        movdqa    %xmm6, %xmm0
        pxor      %xmm12, %xmm0
        movdqa    %xmm15, 544(%rsp)
        pand      %xmm10, %xmm0
        movdqa    %xmm14, 384(%rsp)
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm15
        pxor      %xmm12, %xmm0
        pslld     $5, %xmm14
        psrld     $27, %xmm15
        paddd     %xmm0, %xmm11
        por       %xmm15, %xmm14
        paddd     %xmm14, %xmm11
        movdqa    %xmm3, %xmm15
        paddd     %xmm7, %xmm11
        movdqa    %xmm3, %xmm0
        paddd     %xmm1, %xmm11
        movdqa    %xmm8, %xmm1
        pxor      %xmm5, %xmm1
        pslld     $5, %xmm15
        pand      %xmm13, %xmm1
        psrld     $27, %xmm0
        pxor      %xmm5, %xmm1
        por       %xmm0, %xmm15
        paddd     %xmm1, %xmm4
        movdqa    %xmm13, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm13
        paddd     %xmm15, %xmm4
        movdqa    %xmm10, %xmm0
        por       %xmm13, %xmm1
        paddd     %xmm7, %xmm4
        movdqa    592(%rsp), %xmm13
        pslld     $30, %xmm0
        pxor      480(%rsp), %xmm13
        psrld     $2, %xmm10
        pxor      704(%rsp), %xmm13
        paddd     %xmm9, %xmm4
        movdqa    688(%rsp), %xmm9
        por       %xmm10, %xmm0
        movdqa    576(%rsp), %xmm10
        pxor      %xmm9, %xmm13
        pxor      352(%rsp), %xmm10
        movdqa    %xmm13, %xmm15
        pxor      720(%rsp), %xmm10
        paddd     %xmm13, %xmm15
        movdqa    304(%rsp), %xmm14
        psrld     $31, %xmm13
        pxor      %xmm14, %xmm10
        por       %xmm13, %xmm15
        movdqa    %xmm10, %xmm13
        paddd     %xmm10, %xmm13
        psrld     $31, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm0, %xmm10
        pxor      %xmm6, %xmm10
        movdqa    %xmm15, 624(%rsp)
        pand      %xmm2, %xmm10
        movdqa    %xmm13, 400(%rsp)
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm15
        pxor      %xmm6, %xmm10
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        paddd     %xmm10, %xmm12
        por       %xmm15, %xmm13
        paddd     %xmm13, %xmm12
        movdqa    %xmm4, %xmm15
        paddd     %xmm7, %xmm12
        movdqa    %xmm4, %xmm10
        paddd     %xmm9, %xmm12
        movdqa    %xmm1, %xmm9
        pxor      %xmm8, %xmm9
        pslld     $5, %xmm15
        pand      %xmm3, %xmm9
        psrld     $27, %xmm10
        pxor      %xmm8, %xmm9
        por       %xmm10, %xmm15
        paddd     %xmm9, %xmm5
        movdqa    %xmm2, %xmm10
        paddd     %xmm15, %xmm5
        pslld     $30, %xmm10
        paddd     %xmm7, %xmm5
        psrld     $2, %xmm2
        paddd     %xmm14, %xmm5
        por       %xmm2, %xmm10
        movdqa    560(%rsp), %xmm14
        movdqa    %xmm3, %xmm2
        pxor      528(%rsp), %xmm14
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        pxor      272(%rsp), %xmm14
        por       %xmm3, %xmm2
        movdqa    288(%rsp), %xmm3
        movdqa    512(%rsp), %xmm9
        pxor      %xmm3, %xmm14
        pxor      368(%rsp), %xmm9
        movdqa    %xmm14, %xmm13
        pxor      256(%rsp), %xmm9
        paddd     %xmm14, %xmm13
        movdqa    656(%rsp), %xmm15
        psrld     $31, %xmm14
        pxor      %xmm15, %xmm9
        por       %xmm14, %xmm13
        movdqa    %xmm9, %xmm14
        paddd     %xmm9, %xmm14
        psrld     $31, %xmm9
        por       %xmm9, %xmm14
        movdqa    %xmm10, %xmm9
        pxor      %xmm0, %xmm9
        movdqa    %xmm13, 672(%rsp)
        pand      %xmm11, %xmm9
        movdqa    %xmm14, 416(%rsp)
        movdqa    %xmm12, %xmm13
        movdqa    %xmm12, %xmm14
        pxor      %xmm0, %xmm9
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        paddd     %xmm9, %xmm6
        por       %xmm14, %xmm13
        paddd     %xmm13, %xmm6
        movdqa    %xmm5, %xmm14
        paddd     %xmm7, %xmm6
        movdqa    %xmm5, %xmm9
        paddd     %xmm3, %xmm6
        movdqa    %xmm2, %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm9
        pxor      %xmm1, %xmm3
        por       %xmm9, %xmm14
        movdqa    %xmm11, %xmm9
        pand      %xmm4, %xmm3
        pslld     $30, %xmm9
        psrld     $2, %xmm11
        movdqa    496(%rsp), %xmm13
        pxor      %xmm1, %xmm3
        por       %xmm11, %xmm9
        movdqa    %xmm4, %xmm11
        pxor      544(%rsp), %xmm13
        paddd     %xmm3, %xmm8
        pslld     $30, %xmm11
        psrld     $2, %xmm4
        pxor      240(%rsp), %xmm13
        paddd     %xmm14, %xmm8
        movdqa    448(%rsp), %xmm3
        por       %xmm4, %xmm11
        movdqa    704(%rsp), %xmm4
        paddd     %xmm7, %xmm8
        pxor      384(%rsp), %xmm3
        pxor      %xmm4, %xmm13
        pxor      224(%rsp), %xmm3
        paddd     %xmm15, %xmm8
        movdqa    720(%rsp), %xmm15
        movdqa    %xmm13, %xmm14
        pxor      %xmm15, %xmm3
        paddd     %xmm13, %xmm14
        psrld     $31, %xmm13
        por       %xmm13, %xmm14
        movdqa    %xmm3, %xmm13
        paddd     %xmm3, %xmm13
        psrld     $31, %xmm3
        por       %xmm3, %xmm13
        movdqa    %xmm9, %xmm3
        pxor      %xmm10, %xmm3
        movdqa    %xmm14, 144(%rsp)
        pand      %xmm12, %xmm3
        movdqa    %xmm13, 128(%rsp)
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm14
        pxor      %xmm10, %xmm3
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        paddd     %xmm3, %xmm0
        por       %xmm14, %xmm13
        paddd     %xmm13, %xmm0
        movdqa    %xmm8, %xmm14
        paddd     %xmm7, %xmm0
        movdqa    %xmm8, %xmm3
        paddd     %xmm4, %xmm0
        movdqa    %xmm11, %xmm4
        pxor      %xmm2, %xmm4
        pslld     $5, %xmm14
        pand      %xmm5, %xmm4
        psrld     $27, %xmm3
        pxor      %xmm2, %xmm4
        por       %xmm3, %xmm14
        movdqa    %xmm12, %xmm3
        paddd     %xmm4, %xmm1
        pslld     $30, %xmm3
        psrld     $2, %xmm12
        paddd     %xmm14, %xmm1
        por       %xmm12, %xmm3
        movdqa    432(%rsp), %xmm12
        movdqa    %xmm5, %xmm4
        pxor      624(%rsp), %xmm12
        paddd     %xmm7, %xmm1
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        pxor      208(%rsp), %xmm12
        paddd     %xmm15, %xmm1
        movdqa    272(%rsp), %xmm15
        por       %xmm5, %xmm4
        movdqa    320(%rsp), %xmm5
        pxor      %xmm15, %xmm12
        pxor      400(%rsp), %xmm5
        movdqa    %xmm12, %xmm13
        pxor      192(%rsp), %xmm5
        paddd     %xmm12, %xmm13
        movdqa    256(%rsp), %xmm14
        psrld     $31, %xmm12
        pxor      %xmm14, %xmm5
        por       %xmm12, %xmm13
        movdqa    %xmm5, %xmm12
        paddd     %xmm5, %xmm12
        psrld     $31, %xmm5
        por       %xmm5, %xmm12
        movdqa    %xmm3, %xmm5
        pxor      %xmm9, %xmm5
        movdqa    %xmm13, 112(%rsp)
        pand      %xmm6, %xmm5
        movdqa    %xmm12, 96(%rsp)
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm13
        pxor      %xmm9, %xmm5
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        paddd     %xmm5, %xmm10
        por       %xmm13, %xmm12
        paddd     %xmm12, %xmm10
        movdqa    %xmm1, %xmm13
        paddd     %xmm7, %xmm10
        movdqa    %xmm1, %xmm5
        paddd     %xmm15, %xmm10
        movdqa    %xmm4, %xmm15
        pxor      %xmm11, %xmm15
        pslld     $5, %xmm13
        pand      %xmm8, %xmm15
        psrld     $27, %xmm5
        pxor      %xmm11, %xmm15
        por       %xmm5, %xmm13
        paddd     %xmm15, %xmm2
        movdqa    %xmm6, %xmm5
        paddd     %xmm13, %xmm2
        pslld     $30, %xmm5
        paddd     %xmm7, %xmm2
        psrld     $2, %xmm6
        paddd     %xmm14, %xmm2
        por       %xmm6, %xmm5
        movdqa    464(%rsp), %xmm14
        movdqa    %xmm8, %xmm6
        pxor      672(%rsp), %xmm14
        pslld     $30, %xmm6
        psrld     $2, %xmm8
        pxor      176(%rsp), %xmm14
        por       %xmm8, %xmm6
        movdqa    240(%rsp), %xmm13
        movdqa    336(%rsp), %xmm8
        pxor      %xmm13, %xmm14
        pxor      416(%rsp), %xmm8
        movdqa    %xmm14, %xmm15
        pxor      160(%rsp), %xmm8
        paddd     %xmm14, %xmm15
        movdqa    224(%rsp), %xmm12
        psrld     $31, %xmm14
        pxor      %xmm12, %xmm8
        por       %xmm14, %xmm15
        movdqa    %xmm8, %xmm14
        paddd     %xmm8, %xmm14
        psrld     $31, %xmm8
        por       %xmm8, %xmm14
        movdqa    %xmm5, %xmm8
        pxor      %xmm3, %xmm8
        movdqa    %xmm15, 80(%rsp)
        pand      %xmm0, %xmm8
        movdqa    %xmm14, 32(%rsp)
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm15
        pxor      %xmm3, %xmm8
        pslld     $5, %xmm14
        psrld     $27, %xmm15
        paddd     %xmm8, %xmm9
        por       %xmm15, %xmm14
        paddd     %xmm14, %xmm9
        movdqa    %xmm2, %xmm15
        paddd     %xmm7, %xmm9
        movdqa    %xmm2, %xmm8
        paddd     %xmm13, %xmm9
        movdqa    %xmm6, %xmm13
        pxor      %xmm4, %xmm13
        pslld     $5, %xmm15
        pand      %xmm1, %xmm13
        psrld     $27, %xmm8
        pxor      %xmm4, %xmm13
        por       %xmm8, %xmm15
        paddd     %xmm13, %xmm11
        movdqa    %xmm0, %xmm8
        paddd     %xmm15, %xmm11
        pslld     $30, %xmm8
        paddd     %xmm7, %xmm11
        psrld     $2, %xmm0
        paddd     %xmm12, %xmm11
        por       %xmm0, %xmm8
        movdqa    144(%rsp), %xmm12
        movdqa    %xmm1, %xmm0
        pxor      480(%rsp), %xmm12
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        pxor      640(%rsp), %xmm12
        por       %xmm1, %xmm0
        movdqa    208(%rsp), %xmm15
        movdqa    128(%rsp), %xmm1
        pxor      %xmm15, %xmm12
        pxor      352(%rsp), %xmm1
        movdqa    %xmm12, %xmm13
        pxor      608(%rsp), %xmm1
        paddd     %xmm12, %xmm13
        movdqa    192(%rsp), %xmm14
        psrld     $31, %xmm12
        pxor      %xmm14, %xmm1
        por       %xmm12, %xmm13
        movdqa    %xmm1, %xmm12
        paddd     %xmm1, %xmm12
        psrld     $31, %xmm1
        por       %xmm1, %xmm12
        movdqa    %xmm8, %xmm1
        pxor      %xmm5, %xmm1
        movdqa    %xmm13, 64(%rsp)
        pand      %xmm10, %xmm1
        movdqa    %xmm12, 16(%rsp)
        movdqa    %xmm9, %xmm12
        movdqa    %xmm9, %xmm13
        pxor      %xmm5, %xmm1
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        paddd     %xmm1, %xmm3
        por       %xmm13, %xmm12
        paddd     %xmm12, %xmm3
        movdqa    %xmm11, %xmm13
        paddd     %xmm7, %xmm3
        movdqa    %xmm11, %xmm1
        paddd     %xmm15, %xmm3
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm1
        pxor      %xmm6, %xmm15
        por       %xmm1, %xmm13
        movdqa    %xmm10, %xmm1
        pand      %xmm2, %xmm15
        pslld     $30, %xmm1
        psrld     $2, %xmm10
        pxor      %xmm6, %xmm15
        por       %xmm10, %xmm1
        movdqa    %xmm2, %xmm10
        paddd     %xmm15, %xmm4
        pslld     $30, %xmm10
        psrld     $2, %xmm2
        paddd     %xmm13, %xmm4
        por       %xmm2, %xmm10
        movdqa    112(%rsp), %xmm2
        paddd     %xmm7, %xmm4
        pxor      528(%rsp), %xmm2
        paddd     %xmm14, %xmm4
        pxor      592(%rsp), %xmm2
        movdqa    176(%rsp), %xmm14
        movdqa    96(%rsp), %xmm13
        pxor      %xmm14, %xmm2
        pxor      368(%rsp), %xmm13
        movdqa    %xmm2, %xmm12
        pxor      576(%rsp), %xmm13
        paddd     %xmm2, %xmm12
        movdqa    160(%rsp), %xmm15
        psrld     $31, %xmm2
        pxor      %xmm15, %xmm13
        por       %xmm2, %xmm12
        movdqa    %xmm13, %xmm2
        paddd     %xmm13, %xmm2
        psrld     $31, %xmm13
        por       %xmm13, %xmm2
        movdqa    %xmm1, %xmm13
        pxor      %xmm8, %xmm13
        movdqa    %xmm12, 48(%rsp)
        pand      %xmm9, %xmm13
        movdqa    %xmm2, (%rsp)
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm2
        pxor      %xmm8, %xmm13
        pslld     $5, %xmm12
        psrld     $27, %xmm2
        paddd     %xmm13, %xmm5
        por       %xmm2, %xmm12
        paddd     %xmm12, %xmm5
        movdqa    %xmm4, %xmm12
        paddd     %xmm7, %xmm5
        movdqa    %xmm4, %xmm2
        paddd     %xmm14, %xmm5
        movdqa    %xmm10, %xmm14
        pxor      %xmm0, %xmm14
        pslld     $5, %xmm12
        pand      %xmm11, %xmm14
        psrld     $27, %xmm2
        pxor      %xmm0, %xmm14
        por       %xmm2, %xmm12
        paddd     %xmm14, %xmm6
        movdqa    %xmm9, %xmm13
        paddd     %xmm12, %xmm6
        pslld     $30, %xmm13
        paddd     %xmm7, %xmm6
        psrld     $2, %xmm9
        paddd     %xmm15, %xmm6
..B9.18:
        movdqa    80(%rsp), %xmm7
        por       %xmm9, %xmm13
        pxor      544(%rsp), %xmm7
        movdqa    %xmm11, %xmm14
        movdqa    32(%rsp), %xmm15
        pslld     $30, %xmm14
        pxor      560(%rsp), %xmm7
        psrld     $2, %xmm11
        movdqa    640(%rsp), %xmm9
        por       %xmm11, %xmm14
        pxor      384(%rsp), %xmm15
        pxor      %xmm9, %xmm7
        pxor      512(%rsp), %xmm15
        movdqa    %xmm7, %xmm12
        movdqa    608(%rsp), %xmm2
        paddd     %xmm7, %xmm12
        pxor      %xmm2, %xmm15
        psrld     $31, %xmm7
        movdqa    %xmm15, %xmm11
        por       %xmm7, %xmm12
        paddd     %xmm15, %xmm11
        psrld     $31, %xmm15
        movdqa    %xmm1, %xmm7
        por       %xmm15, %xmm11
        movdqa    %xmm12, 832(%rsp)
        pxor      %xmm13, %xmm7
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm12
        pxor      %xmm3, %xmm7
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        paddd     %xmm7, %xmm8
        por       %xmm12, %xmm15
        movdqa    %xmm6, %xmm12
        movdqa    .L_2il0floatpacket.548(%rip), %xmm7
        paddd     %xmm15, %xmm8
        paddd     %xmm7, %xmm8
        movdqa    %xmm6, %xmm15
        paddd     %xmm9, %xmm8
        movdqa    %xmm10, %xmm9
        pxor      %xmm14, %xmm9
        pslld     $5, %xmm15
        pxor      %xmm4, %xmm9
        psrld     $27, %xmm12
        paddd     %xmm9, %xmm0
        por       %xmm12, %xmm15
        paddd     %xmm15, %xmm0
        paddd     %xmm7, %xmm0
        paddd     %xmm2, %xmm0
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        movdqa    %xmm11, 784(%rsp)
        por       %xmm3, %xmm2
        movdqa    64(%rsp), %xmm11
        movdqa    %xmm4, %xmm3
        pxor      624(%rsp), %xmm11
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        pxor      496(%rsp), %xmm11
        por       %xmm4, %xmm3
        movdqa    592(%rsp), %xmm9
        movdqa    16(%rsp), %xmm4
        pxor      %xmm9, %xmm11
        pxor      400(%rsp), %xmm4
        movdqa    %xmm11, %xmm15
        pxor      448(%rsp), %xmm4
        paddd     %xmm11, %xmm15
        movdqa    576(%rsp), %xmm12
        psrld     $31, %xmm11
        pxor      %xmm12, %xmm4
        por       %xmm11, %xmm15
        movdqa    %xmm4, %xmm11
        paddd     %xmm4, %xmm11
        psrld     $31, %xmm4
        por       %xmm4, %xmm11
        movdqa    %xmm2, %xmm4
        movdqa    %xmm15, 816(%rsp)
        pxor      %xmm13, %xmm4
        movdqa    %xmm11, 768(%rsp)
        movdqa    %xmm8, %xmm11
        movdqa    %xmm8, %xmm15
        pxor      %xmm5, %xmm4
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm4, %xmm1
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm1
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm4
        paddd     %xmm7, %xmm1
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        paddd     %xmm9, %xmm1
        movdqa    %xmm3, %xmm9
        por       %xmm4, %xmm15
        movdqa    %xmm5, %xmm4
        pxor      %xmm14, %xmm9
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        pxor      %xmm6, %xmm9
        movdqa    48(%rsp), %xmm11
        por       %xmm5, %xmm4
        movdqa    %xmm6, %xmm5
        paddd     %xmm9, %xmm10
        pxor      672(%rsp), %xmm11
        pslld     $30, %xmm5
        psrld     $2, %xmm6
        paddd     %xmm15, %xmm10
        pxor      432(%rsp), %xmm11
        por       %xmm6, %xmm5
        movdqa    560(%rsp), %xmm9
        paddd     %xmm7, %xmm10
        movdqa    (%rsp), %xmm6
        pxor      %xmm9, %xmm11
        pxor      416(%rsp), %xmm6
        paddd     %xmm12, %xmm10
        pxor      320(%rsp), %xmm6
        movdqa    %xmm11, %xmm15
        movdqa    512(%rsp), %xmm12
        paddd     %xmm11, %xmm15
        pxor      %xmm12, %xmm6
        psrld     $31, %xmm11
        por       %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm6, %xmm11
        psrld     $31, %xmm6
        por       %xmm6, %xmm11
        movdqa    %xmm4, %xmm6
        movdqa    %xmm15, 800(%rsp)
        pxor      %xmm2, %xmm6
        movdqa    %xmm11, 736(%rsp)
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm15
        pxor      %xmm8, %xmm6
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm6, %xmm13
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm13
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm6
        paddd     %xmm7, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm6
        paddd     %xmm9, %xmm13
        movdqa    %xmm5, %xmm9
        por       %xmm6, %xmm15
        movdqa    %xmm8, %xmm6
        pxor      %xmm3, %xmm9
        pslld     $30, %xmm6
        psrld     $2, %xmm8
        pxor      %xmm0, %xmm9
        por       %xmm8, %xmm6
        movdqa    %xmm0, %xmm8
        paddd     %xmm9, %xmm14
        pslld     $30, %xmm8
        psrld     $2, %xmm0
        paddd     %xmm15, %xmm14
        por       %xmm0, %xmm8
        paddd     %xmm7, %xmm14
        movdqa    144(%rsp), %xmm0
        paddd     %xmm12, %xmm14
        pxor      832(%rsp), %xmm0
        pxor      464(%rsp), %xmm0
        movdqa    496(%rsp), %xmm12
        movdqa    128(%rsp), %xmm9
        pxor      %xmm12, %xmm0
        pxor      784(%rsp), %xmm9
        movdqa    %xmm0, %xmm11
        pxor      336(%rsp), %xmm9
        paddd     %xmm0, %xmm11
        movdqa    448(%rsp), %xmm15
        psrld     $31, %xmm0
        pxor      %xmm15, %xmm9
        por       %xmm0, %xmm11
        movdqa    %xmm9, %xmm0
        paddd     %xmm9, %xmm0
        psrld     $31, %xmm9
        por       %xmm9, %xmm0
        movdqa    %xmm6, %xmm9
        movdqa    %xmm11, 848(%rsp)
        pxor      %xmm4, %xmm9
        movdqa    %xmm0, 752(%rsp)
        movdqa    %xmm13, %xmm0
        movdqa    %xmm13, %xmm11
        pxor      %xmm1, %xmm9
        pslld     $5, %xmm0
        psrld     $27, %xmm11
        paddd     %xmm9, %xmm2
        por       %xmm11, %xmm0
        paddd     %xmm0, %xmm2
        movdqa    %xmm14, %xmm11
        paddd     %xmm7, %xmm2
        movdqa    %xmm14, %xmm9
        paddd     %xmm12, %xmm2
        movdqa    %xmm8, %xmm12
        pxor      %xmm5, %xmm12
        pslld     $5, %xmm11
        pxor      %xmm10, %xmm12
        psrld     $27, %xmm9
        paddd     %xmm12, %xmm3
        por       %xmm9, %xmm11
        paddd     %xmm11, %xmm3
        movdqa    %xmm10, %xmm11
        pslld     $30, %xmm11
        psrld     $2, %xmm10
        por       %xmm10, %xmm11
        movdqa    %xmm1, %xmm9
        movdqa    112(%rsp), %xmm10
        paddd     %xmm7, %xmm3
        pxor      816(%rsp), %xmm10
        pslld     $30, %xmm9
        pxor      480(%rsp), %xmm10
        psrld     $2, %xmm1
        movdqa    432(%rsp), %xmm0
        paddd     %xmm15, %xmm3
        movdqa    96(%rsp), %xmm12
        pxor      %xmm0, %xmm10
        pxor      768(%rsp), %xmm12
        por       %xmm1, %xmm9
        pxor      352(%rsp), %xmm12
        movdqa    %xmm10, %xmm15
        movdqa    320(%rsp), %xmm1
        paddd     %xmm10, %xmm15
        pxor      %xmm1, %xmm12
        psrld     $31, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm12, %xmm10
        paddd     %xmm12, %xmm10
        psrld     $31, %xmm12
        por       %xmm12, %xmm10
        movdqa    %xmm9, %xmm12
        movdqa    %xmm15, 720(%rsp)
        pxor      %xmm6, %xmm12
        movdqa    %xmm10, 688(%rsp)
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm15
        pxor      %xmm13, %xmm12
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm12, %xmm4
        por       %xmm15, %xmm10
        paddd     %xmm10, %xmm4
        movdqa    %xmm3, %xmm15
        paddd     %xmm7, %xmm4
        movdqa    %xmm3, %xmm12
        paddd     %xmm0, %xmm4
        movdqa    %xmm11, %xmm0
        pxor      %xmm8, %xmm0
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        pxor      %xmm14, %xmm0
        por       %xmm12, %xmm15
        movdqa    %xmm13, %xmm12
        paddd     %xmm0, %xmm5
        pslld     $30, %xmm12
        psrld     $2, %xmm13
        paddd     %xmm15, %xmm5
        por       %xmm13, %xmm12
        paddd     %xmm7, %xmm5
        movdqa    80(%rsp), %xmm13
        paddd     %xmm1, %xmm5
        pxor      800(%rsp), %xmm13
        movdqa    %xmm14, %xmm0
        pxor      528(%rsp), %xmm13
        pslld     $30, %xmm0
        movdqa    464(%rsp), %xmm15
        psrld     $2, %xmm14
        movdqa    32(%rsp), %xmm1
        pxor      %xmm15, %xmm13
        pxor      736(%rsp), %xmm1
        por       %xmm14, %xmm0
        pxor      368(%rsp), %xmm1
        movdqa    %xmm13, %xmm14
        movdqa    336(%rsp), %xmm10
        paddd     %xmm13, %xmm14
        pxor      %xmm10, %xmm1
        psrld     $31, %xmm13
        por       %xmm13, %xmm14
        movdqa    %xmm1, %xmm13
        paddd     %xmm1, %xmm13
        psrld     $31, %xmm1
        por       %xmm1, %xmm13
        movdqa    %xmm12, %xmm1
        movdqa    %xmm14, 704(%rsp)
        pxor      %xmm9, %xmm1
        movdqa    %xmm13, 656(%rsp)
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm13
        pxor      %xmm2, %xmm1
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm1, %xmm6
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm6
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm1
        paddd     %xmm7, %xmm6
        pslld     $5, %xmm13
        psrld     $27, %xmm1
        paddd     %xmm15, %xmm6
        movdqa    %xmm0, %xmm15
        por       %xmm1, %xmm13
        movdqa    %xmm2, %xmm1
        pxor      %xmm11, %xmm15
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        pxor      %xmm3, %xmm15
        movdqa    64(%rsp), %xmm14
        por       %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        paddd     %xmm15, %xmm8
        pxor      848(%rsp), %xmm14
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        paddd     %xmm13, %xmm8
        pxor      544(%rsp), %xmm14
        por       %xmm3, %xmm2
        movdqa    480(%rsp), %xmm15
        paddd     %xmm7, %xmm8
        movdqa    16(%rsp), %xmm3
        pxor      %xmm15, %xmm14
        pxor      752(%rsp), %xmm3
        paddd     %xmm10, %xmm8
        pxor      384(%rsp), %xmm3
        movdqa    %xmm14, %xmm13
        movdqa    352(%rsp), %xmm10
        paddd     %xmm14, %xmm13
        pxor      %xmm10, %xmm3
        psrld     $31, %xmm14
        por       %xmm14, %xmm13
        movdqa    %xmm3, %xmm14
        paddd     %xmm3, %xmm14
        psrld     $31, %xmm3
        por       %xmm3, %xmm14
        movdqa    %xmm1, %xmm3
        movdqa    %xmm13, 256(%rsp)
        pxor      %xmm12, %xmm3
        movdqa    %xmm14, 272(%rsp)
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm13
        pxor      %xmm4, %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm3, %xmm9
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm9
        movdqa    %xmm8, %xmm13
        movdqa    %xmm8, %xmm3
        paddd     %xmm7, %xmm9
        pslld     $5, %xmm13
        psrld     $27, %xmm3
        paddd     %xmm15, %xmm9
        movdqa    %xmm2, %xmm15
        por       %xmm3, %xmm13
        movdqa    %xmm4, %xmm3
        pxor      %xmm0, %xmm15
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        pxor      %xmm5, %xmm15
        movdqa    48(%rsp), %xmm14
        por       %xmm4, %xmm3
        movdqa    %xmm5, %xmm4
        paddd     %xmm15, %xmm11
        pxor      720(%rsp), %xmm14
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        paddd     %xmm13, %xmm11
        pxor      624(%rsp), %xmm14
        por       %xmm5, %xmm4
        movdqa    528(%rsp), %xmm15
        paddd     %xmm7, %xmm11
        movdqa    (%rsp), %xmm5
        pxor      %xmm15, %xmm14
        pxor      688(%rsp), %xmm5
        paddd     %xmm10, %xmm11
        pxor      400(%rsp), %xmm5
        movdqa    %xmm14, %xmm13
        movdqa    368(%rsp), %xmm10
        paddd     %xmm14, %xmm13
        pxor      %xmm10, %xmm5
        psrld     $31, %xmm14
        por       %xmm14, %xmm13
        movdqa    %xmm5, %xmm14
        paddd     %xmm5, %xmm14
        psrld     $31, %xmm5
        por       %xmm5, %xmm14
        movdqa    %xmm3, %xmm5
        movdqa    %xmm13, 240(%rsp)
        pxor      %xmm1, %xmm5
        movdqa    %xmm14, 304(%rsp)
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm13
        pxor      %xmm6, %xmm5
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm5, %xmm12
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm12
        movdqa    %xmm11, %xmm13
        paddd     %xmm7, %xmm12
        movdqa    %xmm11, %xmm5
        paddd     %xmm15, %xmm12
        movdqa    %xmm4, %xmm15
        pxor      %xmm2, %xmm15
        pslld     $5, %xmm13
        pxor      %xmm8, %xmm15
        psrld     $27, %xmm5
        paddd     %xmm15, %xmm0
        por       %xmm5, %xmm13
        paddd     %xmm13, %xmm0
        movdqa    %xmm6, %xmm5
        paddd     %xmm7, %xmm0
        pslld     $30, %xmm5
        psrld     $2, %xmm6
        paddd     %xmm10, %xmm0
        movdqa    704(%rsp), %xmm10
        por       %xmm6, %xmm5
        movdqa    %xmm8, %xmm6
        psrld     $2, %xmm8
        pxor      832(%rsp), %xmm10
        pslld     $30, %xmm6
        pxor      672(%rsp), %xmm10
        por       %xmm8, %xmm6
        movdqa    544(%rsp), %xmm13
        movdqa    656(%rsp), %xmm8
        pxor      %xmm13, %xmm10
        pxor      784(%rsp), %xmm8
        movdqa    %xmm10, %xmm15
        pxor      416(%rsp), %xmm8
        paddd     %xmm10, %xmm15
        movdqa    384(%rsp), %xmm14
        psrld     $31, %xmm10
        pxor      %xmm14, %xmm8
        por       %xmm10, %xmm15
        movdqa    %xmm8, %xmm10
        paddd     %xmm8, %xmm10
        psrld     $31, %xmm8
        por       %xmm8, %xmm10
        movdqa    %xmm5, %xmm8
        movdqa    %xmm15, 224(%rsp)
        pxor      %xmm3, %xmm8
        movdqa    %xmm10, 288(%rsp)
        movdqa    %xmm12, %xmm10
        movdqa    %xmm12, %xmm15
        pxor      %xmm9, %xmm8
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm8, %xmm1
        por       %xmm15, %xmm10
        paddd     %xmm10, %xmm1
        movdqa    %xmm0, %xmm15
        paddd     %xmm7, %xmm1
        movdqa    %xmm0, %xmm8
        paddd     %xmm13, %xmm1
        movdqa    %xmm6, %xmm13
        pxor      %xmm4, %xmm13
        pslld     $5, %xmm15
        pxor      %xmm11, %xmm13
        psrld     $27, %xmm8
        paddd     %xmm13, %xmm2
        por       %xmm8, %xmm15
        paddd     %xmm15, %xmm2
        movdqa    %xmm9, %xmm8
        paddd     %xmm7, %xmm2
        pslld     $30, %xmm8
        psrld     $2, %xmm9
        paddd     %xmm14, %xmm2
        movdqa    256(%rsp), %xmm14
        por       %xmm9, %xmm8
        movdqa    %xmm11, %xmm9
        psrld     $2, %xmm11
        pxor      816(%rsp), %xmm14
        pslld     $30, %xmm9
        pxor      144(%rsp), %xmm14
        por       %xmm11, %xmm9
        movdqa    624(%rsp), %xmm15
        movdqa    272(%rsp), %xmm11
        pxor      %xmm15, %xmm14
        pxor      768(%rsp), %xmm11
        movdqa    %xmm14, %xmm13
        pxor      128(%rsp), %xmm11
        paddd     %xmm14, %xmm13
        movdqa    400(%rsp), %xmm10
        psrld     $31, %xmm14
        pxor      %xmm10, %xmm11
        por       %xmm14, %xmm13
        movdqa    %xmm11, %xmm14
        paddd     %xmm11, %xmm14
        psrld     $31, %xmm11
        por       %xmm11, %xmm14
        movdqa    %xmm8, %xmm11
        movdqa    %xmm13, 208(%rsp)
        pxor      %xmm5, %xmm11
        movdqa    %xmm14, 176(%rsp)
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm13
        pxor      %xmm12, %xmm11
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm11, %xmm3
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm3
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm11
        paddd     %xmm7, %xmm3
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        paddd     %xmm15, %xmm3
        movdqa    %xmm9, %xmm15
        por       %xmm11, %xmm13
        movdqa    %xmm12, %xmm11
        pxor      %xmm6, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm12
        pxor      %xmm0, %xmm15
        por       %xmm12, %xmm11
        movdqa    %xmm0, %xmm12
        paddd     %xmm15, %xmm4
        pslld     $30, %xmm12
        psrld     $2, %xmm0
        paddd     %xmm13, %xmm4
        por       %xmm0, %xmm12
        paddd     %xmm7, %xmm4
        movdqa    240(%rsp), %xmm0
        paddd     %xmm10, %xmm4
        pxor      800(%rsp), %xmm0
        pxor      112(%rsp), %xmm0
        movdqa    672(%rsp), %xmm10
        movdqa    304(%rsp), %xmm13
        pxor      %xmm10, %xmm0
        pxor      736(%rsp), %xmm13
        movdqa    %xmm0, %xmm14
        pxor      96(%rsp), %xmm13
        paddd     %xmm0, %xmm14
        movdqa    416(%rsp), %xmm15
        psrld     $31, %xmm0
        pxor      %xmm15, %xmm13
        por       %xmm0, %xmm14
        movdqa    %xmm13, %xmm0
        paddd     %xmm13, %xmm0
        psrld     $31, %xmm13
        por       %xmm13, %xmm0
        movdqa    %xmm11, %xmm13
        movdqa    %xmm14, 192(%rsp)
        pxor      %xmm8, %xmm13
        movdqa    %xmm0, 160(%rsp)
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm0
        pxor      %xmm1, %xmm13
        pslld     $5, %xmm14
        psrld     $27, %xmm0
        paddd     %xmm13, %xmm5
        por       %xmm0, %xmm14
        paddd     %xmm14, %xmm5
        movdqa    %xmm4, %xmm13
        paddd     %xmm7, %xmm5
        movdqa    %xmm4, %xmm0
        paddd     %xmm10, %xmm5
        movdqa    %xmm12, %xmm10
        pxor      %xmm9, %xmm10
        pslld     $5, %xmm13
        pxor      %xmm2, %xmm10
        psrld     $27, %xmm0
        paddd     %xmm10, %xmm6
        por       %xmm0, %xmm13
        movdqa    %xmm1, %xmm0
        paddd     %xmm13, %xmm6
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        paddd     %xmm7, %xmm6
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        paddd     %xmm15, %xmm6
        pslld     $30, %xmm1
        psrld     $2, %xmm2
..B9.17:
        movdqa    224(%rsp), %xmm13
        por       %xmm2, %xmm1
        pxor      848(%rsp), %xmm13
        pxor      80(%rsp), %xmm13
        movdqa    144(%rsp), %xmm10
        movdqa    288(%rsp), %xmm2
        pxor      %xmm10, %xmm13
        pxor      752(%rsp), %xmm2
        movdqa    %xmm13, %xmm15
        pxor      32(%rsp), %xmm2
        paddd     %xmm13, %xmm15
        movdqa    128(%rsp), %xmm14
        psrld     $31, %xmm13
        pxor      %xmm14, %xmm2
        por       %xmm13, %xmm15
        movdqa    %xmm2, %xmm13
        paddd     %xmm2, %xmm13
        psrld     $31, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm0, %xmm2
        movdqa    %xmm15, 624(%rsp)
        pxor      %xmm11, %xmm2
        movdqa    %xmm13, 544(%rsp)
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm13
        pxor      %xmm3, %xmm2
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm2, %xmm8
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm8
        movdqa    %xmm6, %xmm2
        paddd     %xmm7, %xmm8
        movdqa    %xmm6, %xmm13
        paddd     %xmm10, %xmm8
        movdqa    %xmm12, %xmm10
        pxor      %xmm1, %xmm10
        pslld     $5, %xmm2
        pxor      %xmm4, %xmm10
        psrld     $27, %xmm13
        paddd     %xmm10, %xmm9
        por       %xmm13, %xmm2
        paddd     %xmm2, %xmm9
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        movdqa    208(%rsp), %xmm15
        por       %xmm3, %xmm2
        movdqa    %xmm4, %xmm3
        psrld     $2, %xmm4
        pxor      720(%rsp), %xmm15
        pslld     $30, %xmm3
        pxor      64(%rsp), %xmm15
        por       %xmm4, %xmm3
        movdqa    112(%rsp), %xmm10
        paddd     %xmm7, %xmm9
        movdqa    176(%rsp), %xmm4
        pxor      %xmm10, %xmm15
        pxor      688(%rsp), %xmm4
        paddd     %xmm14, %xmm9
        pxor      16(%rsp), %xmm4
        movdqa    %xmm15, %xmm13
        movdqa    96(%rsp), %xmm14
        paddd     %xmm15, %xmm13
        pxor      %xmm14, %xmm4
        psrld     $31, %xmm15
        por       %xmm15, %xmm13
        movdqa    %xmm4, %xmm15
        paddd     %xmm4, %xmm15
        psrld     $31, %xmm4
        por       %xmm4, %xmm15
        movdqa    %xmm0, %xmm4
        movdqa    %xmm13, 640(%rsp)
        pxor      %xmm2, %xmm4
        movdqa    %xmm15, 560(%rsp)
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, %xmm13
        pxor      %xmm5, %xmm4
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm4, %xmm11
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm11
        movdqa    %xmm9, %xmm4
        paddd     %xmm7, %xmm11
        movdqa    %xmm9, %xmm13
        paddd     %xmm10, %xmm11
        movdqa    %xmm3, %xmm10
        pxor      %xmm1, %xmm10
        pslld     $5, %xmm4
        pxor      %xmm6, %xmm10
        psrld     $27, %xmm13
        paddd     %xmm10, %xmm12
        por       %xmm13, %xmm4
        paddd     %xmm4, %xmm12
        movdqa    %xmm5, %xmm4
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        movdqa    192(%rsp), %xmm15
        por       %xmm5, %xmm4
        movdqa    %xmm6, %xmm5
        psrld     $2, %xmm6
        pxor      704(%rsp), %xmm15
        pslld     $30, %xmm5
        pxor      48(%rsp), %xmm15
        por       %xmm6, %xmm5
        movdqa    80(%rsp), %xmm10
        paddd     %xmm7, %xmm12
        movdqa    160(%rsp), %xmm6
        pxor      %xmm10, %xmm15
        pxor      656(%rsp), %xmm6
        paddd     %xmm14, %xmm12
        pxor      (%rsp), %xmm6
        movdqa    %xmm15, %xmm13
        movdqa    32(%rsp), %xmm14
        paddd     %xmm15, %xmm13
        pxor      %xmm14, %xmm6
        psrld     $31, %xmm15
        por       %xmm15, %xmm13
        movdqa    %xmm6, %xmm15
        paddd     %xmm6, %xmm15
        psrld     $31, %xmm6
        por       %xmm6, %xmm15
        movdqa    %xmm4, %xmm6
        movdqa    %xmm13, 672(%rsp)
        pxor      %xmm2, %xmm6
        movdqa    %xmm15, 576(%rsp)
        movdqa    %xmm11, %xmm15
        movdqa    %xmm11, %xmm13
        pxor      %xmm8, %xmm6
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm6, %xmm0
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm0
        movdqa    %xmm12, %xmm6
        paddd     %xmm7, %xmm0
        movdqa    %xmm12, %xmm13
        paddd     %xmm10, %xmm0
        movdqa    %xmm5, %xmm10
        pxor      %xmm3, %xmm10
        pslld     $5, %xmm6
        pxor      %xmm9, %xmm10
        psrld     $27, %xmm13
        paddd     %xmm10, %xmm1
        por       %xmm13, %xmm6
        paddd     %xmm6, %xmm1
        movdqa    %xmm8, %xmm6
        paddd     %xmm7, %xmm1
        pslld     $30, %xmm6
        paddd     %xmm14, %xmm1
        psrld     $2, %xmm8
        movdqa    256(%rsp), %xmm14
        por       %xmm8, %xmm6
        pxor      624(%rsp), %xmm14
        movdqa    %xmm9, %xmm8
        pxor      832(%rsp), %xmm14
        pslld     $30, %xmm8
        movdqa    64(%rsp), %xmm15
        psrld     $2, %xmm9
        movdqa    272(%rsp), %xmm10
        pxor      %xmm15, %xmm14
        pxor      544(%rsp), %xmm10
        por       %xmm9, %xmm8
        pxor      784(%rsp), %xmm10
        movdqa    %xmm14, %xmm13
        movdqa    16(%rsp), %xmm9
        paddd     %xmm14, %xmm13
        pxor      %xmm9, %xmm10
        psrld     $31, %xmm14
        por       %xmm14, %xmm13
        movdqa    %xmm10, %xmm14
        paddd     %xmm10, %xmm14
        psrld     $31, %xmm10
        por       %xmm10, %xmm14
        movdqa    %xmm6, %xmm10
        movdqa    %xmm13, 864(%rsp)
        pxor      %xmm4, %xmm10
        movdqa    %xmm14, 592(%rsp)
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm14
        pxor      %xmm11, %xmm10
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        paddd     %xmm10, %xmm2
        por       %xmm14, %xmm13
        paddd     %xmm13, %xmm2
        movdqa    %xmm1, %xmm14
        paddd     %xmm7, %xmm2
        movdqa    %xmm1, %xmm10
        paddd     %xmm15, %xmm2
        movdqa    %xmm8, %xmm15
        pxor      %xmm5, %xmm15
        pslld     $5, %xmm14
        pxor      %xmm12, %xmm15
        psrld     $27, %xmm10
        paddd     %xmm15, %xmm3
        por       %xmm10, %xmm14
        movdqa    240(%rsp), %xmm15
        paddd     %xmm14, %xmm3
        movdqa    %xmm11, %xmm10
        paddd     %xmm7, %xmm3
        pxor      640(%rsp), %xmm15
        pslld     $30, %xmm10
        psrld     $2, %xmm11
        paddd     %xmm9, %xmm3
        pxor      816(%rsp), %xmm15
        por       %xmm11, %xmm10
        movdqa    48(%rsp), %xmm13
        movdqa    %xmm12, %xmm11
        movdqa    304(%rsp), %xmm9
        pslld     $30, %xmm11
        pxor      560(%rsp), %xmm9
        psrld     $2, %xmm12
        pxor      %xmm13, %xmm15
        por       %xmm12, %xmm11
        pxor      768(%rsp), %xmm9
        movdqa    %xmm15, %xmm14
        movdqa    (%rsp), %xmm12
        paddd     %xmm15, %xmm14
        pxor      %xmm12, %xmm9
        psrld     $31, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm9, %xmm15
        paddd     %xmm9, %xmm15
        psrld     $31, %xmm9
        por       %xmm9, %xmm15
        movdqa    %xmm10, %xmm9
        movdqa    %xmm14, 880(%rsp)
        pxor      %xmm6, %xmm9
        movdqa    %xmm15, 608(%rsp)
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm14
        pxor      %xmm0, %xmm9
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        paddd     %xmm9, %xmm4
        por       %xmm14, %xmm15
        paddd     %xmm15, %xmm4
        movdqa    %xmm3, %xmm14
        paddd     %xmm7, %xmm4
        movdqa    %xmm3, %xmm9
        paddd     %xmm13, %xmm4
        movdqa    %xmm11, %xmm13
        pxor      %xmm8, %xmm13
        pslld     $5, %xmm14
        pxor      %xmm1, %xmm13
        psrld     $27, %xmm9
        paddd     %xmm13, %xmm5
        por       %xmm9, %xmm14
        paddd     %xmm14, %xmm5
        movdqa    %xmm1, %xmm9
        paddd     %xmm7, %xmm5
        pslld     $30, %xmm9
        movdqa    224(%rsp), %xmm15
        paddd     %xmm12, %xmm5
        movdqa    %xmm0, %xmm12
        psrld     $2, %xmm0
        pxor      672(%rsp), %xmm15
        pslld     $30, %xmm12
        psrld     $2, %xmm1
        por       %xmm0, %xmm12
        pxor      800(%rsp), %xmm15
        por       %xmm1, %xmm9
        movdqa    832(%rsp), %xmm1
        movdqa    288(%rsp), %xmm0
        pxor      %xmm1, %xmm15
        pxor      576(%rsp), %xmm0
        movdqa    %xmm15, %xmm13
        pxor      736(%rsp), %xmm0
        paddd     %xmm15, %xmm13
        movdqa    784(%rsp), %xmm14
        psrld     $31, %xmm15
        pxor      %xmm14, %xmm0
        por       %xmm15, %xmm13
        movdqa    %xmm0, %xmm15
        paddd     %xmm0, %xmm15
        psrld     $31, %xmm0
        por       %xmm0, %xmm15
        movdqa    %xmm12, %xmm0
        movdqa    %xmm13, 480(%rsp)
        pxor      %xmm10, %xmm0
        movdqa    %xmm15, 400(%rsp)
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm13
        pxor      %xmm2, %xmm0
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm0, %xmm6
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm6
        movdqa    %xmm5, %xmm13
        paddd     %xmm7, %xmm6
        movdqa    %xmm5, %xmm0
        paddd     %xmm1, %xmm6
        movdqa    %xmm9, %xmm1
        pxor      %xmm11, %xmm1
        pslld     $5, %xmm13
        pxor      %xmm3, %xmm1
        psrld     $27, %xmm0
        paddd     %xmm1, %xmm8
        movdqa    %xmm2, %xmm1
        por       %xmm0, %xmm13
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        paddd     %xmm13, %xmm8
        por       %xmm2, %xmm1
        paddd     %xmm7, %xmm8
        movdqa    208(%rsp), %xmm2
        paddd     %xmm14, %xmm8
        pxor      864(%rsp), %xmm2
        movdqa    %xmm3, %xmm0
        pxor      848(%rsp), %xmm2
        pslld     $30, %xmm0
        movdqa    816(%rsp), %xmm14
        psrld     $2, %xmm3
        movdqa    176(%rsp), %xmm13
        pxor      %xmm14, %xmm2
        pxor      592(%rsp), %xmm13
        por       %xmm3, %xmm0
        pxor      752(%rsp), %xmm13
        movdqa    %xmm2, %xmm15
        movdqa    768(%rsp), %xmm3
        paddd     %xmm2, %xmm15
        pxor      %xmm3, %xmm13
        psrld     $31, %xmm2
        por       %xmm2, %xmm15
        movdqa    %xmm13, %xmm2
        paddd     %xmm13, %xmm2
        psrld     $31, %xmm13
        por       %xmm13, %xmm2
        movdqa    %xmm1, %xmm13
        movdqa    %xmm15, 496(%rsp)
        pxor      %xmm12, %xmm13
        movdqa    %xmm2, 416(%rsp)
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm2
        pxor      %xmm4, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm2
        paddd     %xmm13, %xmm10
        por       %xmm2, %xmm15
        paddd     %xmm15, %xmm10
        movdqa    %xmm8, %xmm2
        paddd     %xmm7, %xmm10
        movdqa    %xmm8, %xmm13
        paddd     %xmm14, %xmm10
        movdqa    %xmm0, %xmm14
        pxor      %xmm9, %xmm14
        pslld     $5, %xmm2
        psrld     $27, %xmm13
        pxor      %xmm5, %xmm14
        por       %xmm13, %xmm2
        movdqa    %xmm5, %xmm13
        paddd     %xmm14, %xmm11
        pslld     $30, %xmm13
        psrld     $2, %xmm5
        paddd     %xmm2, %xmm11
        movdqa    %xmm4, %xmm14
        por       %xmm5, %xmm13
        movdqa    192(%rsp), %xmm5
        paddd     %xmm7, %xmm11
        pxor      880(%rsp), %xmm5
        pslld     $30, %xmm14
        psrld     $2, %xmm4
        paddd     %xmm3, %xmm11
        pxor      720(%rsp), %xmm5
        por       %xmm4, %xmm14
        movdqa    800(%rsp), %xmm3
        movdqa    160(%rsp), %xmm4
        pxor      %xmm3, %xmm5
        pxor      608(%rsp), %xmm4
        movdqa    %xmm5, %xmm15
        pxor      688(%rsp), %xmm4
        paddd     %xmm5, %xmm15
        movdqa    736(%rsp), %xmm2
        psrld     $31, %xmm5
        pxor      %xmm2, %xmm4
        por       %xmm5, %xmm15
        movdqa    %xmm4, %xmm5
        paddd     %xmm4, %xmm5
        psrld     $31, %xmm4
        por       %xmm4, %xmm5
        movdqa    %xmm14, %xmm4
        movdqa    %xmm15, 448(%rsp)
        pxor      %xmm1, %xmm4
        movdqa    %xmm5, 352(%rsp)
        movdqa    %xmm10, %xmm5
        movdqa    %xmm10, %xmm15
        pxor      %xmm6, %xmm4
        pslld     $5, %xmm5
        psrld     $27, %xmm15
        paddd     %xmm4, %xmm12
        por       %xmm15, %xmm5
        paddd     %xmm5, %xmm12
        movdqa    %xmm11, %xmm15
        paddd     %xmm7, %xmm12
        movdqa    %xmm11, %xmm4
        paddd     %xmm3, %xmm12
        movdqa    %xmm13, %xmm3
        pxor      %xmm0, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        pxor      %xmm8, %xmm3
        por       %xmm4, %xmm15
        movdqa    %xmm6, %xmm4
        paddd     %xmm3, %xmm9
        pslld     $30, %xmm4
        psrld     $2, %xmm6
        paddd     %xmm15, %xmm9
        por       %xmm6, %xmm4
        movdqa    %xmm8, %xmm3
        movdqa    480(%rsp), %xmm6
        paddd     %xmm7, %xmm9
        pxor      624(%rsp), %xmm6
        pslld     $30, %xmm3
        psrld     $2, %xmm8
        paddd     %xmm2, %xmm9
        pxor      704(%rsp), %xmm6
        por       %xmm8, %xmm3
        movdqa    848(%rsp), %xmm2
        movdqa    400(%rsp), %xmm8
        pxor      %xmm2, %xmm6
        pxor      544(%rsp), %xmm8
        movdqa    %xmm6, %xmm15
        pxor      656(%rsp), %xmm8
        paddd     %xmm6, %xmm15
        movdqa    752(%rsp), %xmm5
        psrld     $31, %xmm6
        pxor      %xmm5, %xmm8
        por       %xmm6, %xmm15
        movdqa    %xmm8, %xmm6
        paddd     %xmm8, %xmm6
        psrld     $31, %xmm8
        por       %xmm8, %xmm6
        movdqa    %xmm4, %xmm8
        movdqa    %xmm15, 368(%rsp)
        pxor      %xmm14, %xmm8
        movdqa    %xmm6, 320(%rsp)
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm6
        pxor      %xmm10, %xmm8
        pslld     $5, %xmm15
        psrld     $27, %xmm6
        paddd     %xmm8, %xmm1
        por       %xmm6, %xmm15
        paddd     %xmm15, %xmm1
        movdqa    %xmm9, %xmm6
        paddd     %xmm7, %xmm1
        movdqa    %xmm9, %xmm8
        paddd     %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        pxor      %xmm13, %xmm2
        pslld     $5, %xmm6
        pxor      %xmm11, %xmm2
        psrld     $27, %xmm8
        paddd     %xmm2, %xmm0
        movdqa    %xmm10, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm10
        por       %xmm10, %xmm2
        movdqa    %xmm11, %xmm10
        pslld     $30, %xmm10
        psrld     $2, %xmm11
        por       %xmm8, %xmm6
        por       %xmm11, %xmm10
        movdqa    496(%rsp), %xmm11
        paddd     %xmm6, %xmm0
        pxor      640(%rsp), %xmm11
        paddd     %xmm7, %xmm0
        pxor      256(%rsp), %xmm11
        paddd     %xmm5, %xmm0
        movdqa    720(%rsp), %xmm6
        movdqa    416(%rsp), %xmm7
        pxor      %xmm6, %xmm11
        pxor      560(%rsp), %xmm7
        movdqa    %xmm11, %xmm5
        pxor      272(%rsp), %xmm7
        paddd     %xmm11, %xmm5
        movdqa    688(%rsp), %xmm15
        psrld     $31, %xmm11
        pxor      %xmm15, %xmm7
        por       %xmm11, %xmm5
        movdqa    %xmm7, %xmm11
        paddd     %xmm7, %xmm11
        psrld     $31, %xmm7
        por       %xmm7, %xmm11
        movdqa    %xmm12, %xmm7
        movdqa    %xmm5, 432(%rsp)
        movdqa    %xmm12, %xmm5
        por       %xmm2, %xmm7
        pand      %xmm2, %xmm5
        pand      %xmm4, %xmm7
        movdqa    %xmm11, 336(%rsp)
        por       %xmm7, %xmm5
        movdqa    %xmm1, %xmm7
        movdqa    %xmm1, %xmm11
        pslld     $5, %xmm7
        psrld     $27, %xmm11
        paddd     %xmm5, %xmm14
        por       %xmm11, %xmm7
        movdqa    .L_2il0floatpacket.549(%rip), %xmm8
        paddd     %xmm7, %xmm14
        paddd     %xmm8, %xmm14
        movdqa    %xmm9, %xmm7
        paddd     %xmm6, %xmm14
        movdqa    %xmm9, %xmm6
        por       %xmm10, %xmm6
        pand      %xmm10, %xmm7
        pand      %xmm3, %xmm6
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm5
        por       %xmm6, %xmm7
        pslld     $5, %xmm11
        psrld     $27, %xmm5
        paddd     %xmm7, %xmm13
        por       %xmm5, %xmm11
        movdqa    448(%rsp), %xmm5
        paddd     %xmm11, %xmm13
        movdqa    %xmm12, %xmm7
        paddd     %xmm8, %xmm13
        pxor      672(%rsp), %xmm5
        pslld     $30, %xmm7
        psrld     $2, %xmm12
        paddd     %xmm15, %xmm13
        pxor      240(%rsp), %xmm5
        por       %xmm12, %xmm7
        movdqa    704(%rsp), %xmm12
        movdqa    %xmm9, %xmm6
        movdqa    352(%rsp), %xmm15
        pslld     $30, %xmm6
        pxor      576(%rsp), %xmm15
        psrld     $2, %xmm9
        pxor      %xmm12, %xmm5
        por       %xmm9, %xmm6
        pxor      304(%rsp), %xmm15
        movdqa    %xmm5, %xmm11
        movdqa    656(%rsp), %xmm9
        paddd     %xmm5, %xmm11
        pxor      %xmm9, %xmm15
        psrld     $31, %xmm5
        por       %xmm5, %xmm11
        movdqa    %xmm15, %xmm5
        paddd     %xmm15, %xmm5
        psrld     $31, %xmm15
        por       %xmm15, %xmm5
        movdqa    %xmm1, %xmm15
        movdqa    %xmm5, 384(%rsp)
        movdqa    %xmm1, %xmm5
        por       %xmm7, %xmm15
        pand      %xmm7, %xmm5
        pand      %xmm2, %xmm15
        por       %xmm15, %xmm5
        movdqa    %xmm13, %xmm15
        movdqa    %xmm11, 464(%rsp)
        paddd     %xmm5, %xmm4
        movdqa    %xmm14, %xmm5
        movdqa    %xmm14, %xmm11
        pslld     $5, %xmm5
        psrld     $27, %xmm11
        por       %xmm11, %xmm5
        movdqa    %xmm13, %xmm11
        paddd     %xmm5, %xmm4
        movdqa    %xmm0, %xmm5
        paddd     %xmm8, %xmm4
        pand      %xmm6, %xmm5
        paddd     %xmm12, %xmm4
        movdqa    %xmm0, %xmm12
        por       %xmm6, %xmm12
        pslld     $5, %xmm15
        pand      %xmm10, %xmm12
        psrld     $27, %xmm11
        por       %xmm12, %xmm5
        por       %xmm11, %xmm15
        paddd     %xmm5, %xmm3
        paddd     %xmm15, %xmm3
        paddd     %xmm8, %xmm3
        paddd     %xmm9, %xmm3
..B9.16:
        movdqa    %xmm1, %xmm5
        psrld     $2, %xmm1
        pslld     $30, %xmm5
        movdqa    368(%rsp), %xmm9
        por       %xmm1, %xmm5
        movdqa    %xmm0, %xmm1
        psrld     $2, %xmm0
        pxor      864(%rsp), %xmm9
        pslld     $30, %xmm1
        pxor      224(%rsp), %xmm9
        por       %xmm0, %xmm1
        movdqa    256(%rsp), %xmm12
        movdqa    320(%rsp), %xmm0
        pxor      %xmm12, %xmm9
        pxor      592(%rsp), %xmm0
        movdqa    %xmm9, %xmm15
        pxor      288(%rsp), %xmm0
        paddd     %xmm9, %xmm15
        movdqa    272(%rsp), %xmm11
        psrld     $31, %xmm9
        pxor      %xmm11, %xmm0
        por       %xmm9, %xmm15
        movdqa    %xmm0, %xmm9
        paddd     %xmm0, %xmm9
        psrld     $31, %xmm0
        por       %xmm0, %xmm9
        movdqa    %xmm14, %xmm0
        movdqa    %xmm9, 656(%rsp)
        movdqa    %xmm14, %xmm9
        por       %xmm5, %xmm0
        pand      %xmm5, %xmm9
        pand      %xmm7, %xmm0
        movdqa    %xmm15, 704(%rsp)
        por       %xmm0, %xmm9
        movdqa    %xmm4, %xmm0
        movdqa    %xmm4, %xmm15
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        paddd     %xmm9, %xmm2
        por       %xmm15, %xmm0
        paddd     %xmm0, %xmm2
        movdqa    %xmm13, %xmm0
        paddd     %xmm8, %xmm2
        pand      %xmm1, %xmm0
        paddd     %xmm12, %xmm2
        movdqa    %xmm13, %xmm12
        por       %xmm1, %xmm12
        movdqa    %xmm3, %xmm15
        pand      %xmm6, %xmm12
        movdqa    %xmm3, %xmm9
        por       %xmm12, %xmm0
        pslld     $5, %xmm15
        paddd     %xmm0, %xmm10
        movdqa    %xmm14, %xmm0
        psrld     $27, %xmm9
        pslld     $30, %xmm0
        psrld     $2, %xmm14
        por       %xmm9, %xmm15
        movdqa    432(%rsp), %xmm9
        por       %xmm14, %xmm0
        movdqa    %xmm13, %xmm14
        psrld     $2, %xmm13
        pxor      880(%rsp), %xmm9
        pslld     $30, %xmm14
        pxor      208(%rsp), %xmm9
        paddd     %xmm15, %xmm10
        movdqa    240(%rsp), %xmm12
        por       %xmm13, %xmm14
        movdqa    336(%rsp), %xmm13
        paddd     %xmm8, %xmm10
        pxor      608(%rsp), %xmm13
        pxor      %xmm12, %xmm9
        pxor      176(%rsp), %xmm13
        paddd     %xmm11, %xmm10
        movdqa    304(%rsp), %xmm11
        movdqa    %xmm9, %xmm15
        pxor      %xmm11, %xmm13
        paddd     %xmm9, %xmm15
        psrld     $31, %xmm9
        por       %xmm9, %xmm15
        movdqa    %xmm13, %xmm9
        paddd     %xmm13, %xmm9
        psrld     $31, %xmm13
        por       %xmm13, %xmm9
        movdqa    %xmm4, %xmm13
        movdqa    %xmm9, 688(%rsp)
        movdqa    %xmm4, %xmm9
        por       %xmm0, %xmm13
        pand      %xmm0, %xmm9
        pand      %xmm5, %xmm13
        movdqa    %xmm15, 752(%rsp)
        por       %xmm13, %xmm9
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        paddd     %xmm9, %xmm7
        por       %xmm15, %xmm13
        paddd     %xmm13, %xmm7
        movdqa    %xmm3, %xmm13
        paddd     %xmm8, %xmm7
        pand      %xmm14, %xmm13
        paddd     %xmm12, %xmm7
        movdqa    %xmm3, %xmm12
        por       %xmm14, %xmm12
        movdqa    %xmm10, %xmm15
        pand      %xmm1, %xmm12
        movdqa    %xmm10, %xmm9
        por       %xmm12, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm9
        paddd     %xmm13, %xmm6
        por       %xmm9, %xmm15
        movdqa    %xmm4, %xmm13
        paddd     %xmm15, %xmm6
        pslld     $30, %xmm13
        paddd     %xmm8, %xmm6
        psrld     $2, %xmm4
        paddd     %xmm11, %xmm6
        por       %xmm4, %xmm13
        movdqa    464(%rsp), %xmm11
        movdqa    %xmm3, %xmm4
        pxor      480(%rsp), %xmm11
        pslld     $30, %xmm4
        pxor      192(%rsp), %xmm11
        psrld     $2, %xmm3
        movdqa    224(%rsp), %xmm15
        por       %xmm3, %xmm4
        movdqa    384(%rsp), %xmm9
        pxor      %xmm15, %xmm11
        pxor      400(%rsp), %xmm9
        movdqa    %xmm11, %xmm12
        pxor      160(%rsp), %xmm9
        paddd     %xmm11, %xmm12
        movdqa    288(%rsp), %xmm3
        psrld     $31, %xmm11
        pxor      %xmm3, %xmm9
        por       %xmm11, %xmm12
        movdqa    %xmm9, %xmm11
        paddd     %xmm9, %xmm11
        psrld     $31, %xmm9
        por       %xmm9, %xmm11
        movdqa    %xmm2, %xmm9
        movdqa    %xmm12, 768(%rsp)
        movdqa    %xmm2, %xmm12
        por       %xmm13, %xmm9
        pand      %xmm13, %xmm12
        pand      %xmm0, %xmm9
        por       %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        movdqa    %xmm11, 720(%rsp)
        paddd     %xmm12, %xmm5
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm11
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        por       %xmm11, %xmm12
        movdqa    %xmm6, %xmm11
        paddd     %xmm12, %xmm5
        movdqa    %xmm10, %xmm12
        paddd     %xmm8, %xmm5
        pand      %xmm4, %xmm12
        paddd     %xmm15, %xmm5
        movdqa    %xmm10, %xmm15
        por       %xmm4, %xmm15
        pslld     $5, %xmm9
        pand      %xmm14, %xmm15
        psrld     $27, %xmm11
        por       %xmm15, %xmm12
        por       %xmm11, %xmm9
        paddd     %xmm12, %xmm1
        paddd     %xmm9, %xmm1
        movdqa    %xmm10, %xmm9
        paddd     %xmm8, %xmm1
        pslld     $30, %xmm9
        movdqa    496(%rsp), %xmm15
        paddd     %xmm3, %xmm1
        movdqa    %xmm2, %xmm3
        psrld     $2, %xmm2
        pxor      704(%rsp), %xmm15
        pslld     $30, %xmm3
        psrld     $2, %xmm10
        por       %xmm2, %xmm3
        pxor      624(%rsp), %xmm15
        por       %xmm10, %xmm9
        movdqa    208(%rsp), %xmm2
        movdqa    416(%rsp), %xmm10
        pxor      %xmm2, %xmm15
        pxor      656(%rsp), %xmm10
        movdqa    %xmm15, %xmm12
        pxor      544(%rsp), %xmm10
        paddd     %xmm15, %xmm12
        movdqa    176(%rsp), %xmm11
        psrld     $31, %xmm15
        pxor      %xmm11, %xmm10
        por       %xmm15, %xmm12
        movdqa    %xmm10, %xmm15
        paddd     %xmm10, %xmm15
        psrld     $31, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm7, %xmm10
        movdqa    %xmm12, 784(%rsp)
        movdqa    %xmm7, %xmm12
        por       %xmm3, %xmm10
        pand      %xmm3, %xmm12
        pand      %xmm13, %xmm10
        movdqa    %xmm15, 736(%rsp)
        por       %xmm10, %xmm12
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm12, %xmm0
        por       %xmm15, %xmm10
        paddd     %xmm10, %xmm0
        movdqa    %xmm6, %xmm10
        paddd     %xmm8, %xmm0
        pand      %xmm9, %xmm10
        paddd     %xmm2, %xmm0
        movdqa    %xmm6, %xmm2
        por       %xmm9, %xmm2
        movdqa    %xmm1, %xmm15
        pand      %xmm4, %xmm2
        movdqa    %xmm1, %xmm12
        por       %xmm2, %xmm10
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        paddd     %xmm10, %xmm14
        por       %xmm12, %xmm15
        movdqa    %xmm7, %xmm10
        paddd     %xmm15, %xmm14
        pslld     $30, %xmm10
        paddd     %xmm8, %xmm14
        psrld     $2, %xmm7
        paddd     %xmm11, %xmm14
        por       %xmm7, %xmm10
        movdqa    448(%rsp), %xmm11
        movdqa    %xmm6, %xmm7
        pxor      752(%rsp), %xmm11
        pslld     $30, %xmm7
        psrld     $2, %xmm6
        pxor      640(%rsp), %xmm11
        por       %xmm6, %xmm7
        movdqa    192(%rsp), %xmm2
        movdqa    352(%rsp), %xmm6
        pxor      %xmm2, %xmm11
        pxor      688(%rsp), %xmm6
        movdqa    %xmm11, %xmm15
        pxor      560(%rsp), %xmm6
        paddd     %xmm11, %xmm15
        movdqa    160(%rsp), %xmm12
        psrld     $31, %xmm11
        pxor      %xmm12, %xmm6
        por       %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm6, %xmm11
        psrld     $31, %xmm6
        por       %xmm6, %xmm11
        movdqa    %xmm5, %xmm6
        movdqa    %xmm11, 128(%rsp)
        movdqa    %xmm5, %xmm11
        por       %xmm10, %xmm6
        pand      %xmm10, %xmm11
        pand      %xmm3, %xmm6
        movdqa    %xmm15, 144(%rsp)
        por       %xmm6, %xmm11
        movdqa    %xmm0, %xmm6
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm6
        psrld     $27, %xmm15
        paddd     %xmm11, %xmm13
        por       %xmm15, %xmm6
        paddd     %xmm6, %xmm13
        movdqa    %xmm1, %xmm6
        paddd     %xmm8, %xmm13
        pand      %xmm7, %xmm6
        paddd     %xmm2, %xmm13
        movdqa    %xmm1, %xmm2
        por       %xmm7, %xmm2
        movdqa    %xmm14, %xmm15
        pand      %xmm9, %xmm2
        movdqa    %xmm14, %xmm11
        por       %xmm2, %xmm6
        pslld     $5, %xmm15
        psrld     $27, %xmm11
        movdqa    %xmm1, %xmm2
        paddd     %xmm6, %xmm4
        por       %xmm11, %xmm15
        pslld     $30, %xmm2
        psrld     $2, %xmm1
        paddd     %xmm15, %xmm4
        por       %xmm1, %xmm2
        movdqa    368(%rsp), %xmm1
        paddd     %xmm8, %xmm4
        pxor      768(%rsp), %xmm1
        paddd     %xmm12, %xmm4
        pxor      672(%rsp), %xmm1
        movdqa    %xmm5, %xmm6
        movdqa    624(%rsp), %xmm12
        pslld     $30, %xmm6
        movdqa    320(%rsp), %xmm11
        psrld     $2, %xmm5
        pxor      720(%rsp), %xmm11
        pxor      %xmm12, %xmm1
        pxor      576(%rsp), %xmm11
        por       %xmm5, %xmm6
        movdqa    544(%rsp), %xmm5
        movdqa    %xmm1, %xmm15
        pxor      %xmm5, %xmm11
        paddd     %xmm1, %xmm15
        psrld     $31, %xmm1
        por       %xmm1, %xmm15
        movdqa    %xmm11, %xmm1
        paddd     %xmm11, %xmm1
        psrld     $31, %xmm11
        por       %xmm11, %xmm1
        movdqa    %xmm0, %xmm11
        movdqa    %xmm1, 512(%rsp)
        movdqa    %xmm0, %xmm1
        por       %xmm6, %xmm11
        pand      %xmm6, %xmm1
        pand      %xmm10, %xmm11
        movdqa    %xmm15, 528(%rsp)
        por       %xmm11, %xmm1
        movdqa    %xmm13, %xmm11
        movdqa    %xmm13, %xmm15
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm1, %xmm3
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm3
        movdqa    %xmm14, %xmm11
        paddd     %xmm8, %xmm3
        pand      %xmm2, %xmm11
        paddd     %xmm12, %xmm3
        movdqa    %xmm14, %xmm12
        por       %xmm2, %xmm12
        movdqa    %xmm4, %xmm15
        pand      %xmm7, %xmm12
        movdqa    %xmm4, %xmm1
        por       %xmm12, %xmm11
        pslld     $5, %xmm15
        paddd     %xmm11, %xmm9
        psrld     $27, %xmm1
        movdqa    %xmm14, %xmm11
        por       %xmm1, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm14
        paddd     %xmm15, %xmm9
        por       %xmm14, %xmm11
        movdqa    432(%rsp), %xmm14
        paddd     %xmm8, %xmm9
        pxor      784(%rsp), %xmm14
        paddd     %xmm5, %xmm9
        pxor      864(%rsp), %xmm14
        movdqa    %xmm0, %xmm12
        movdqa    640(%rsp), %xmm5
        pslld     $30, %xmm12
        movdqa    336(%rsp), %xmm1
        psrld     $2, %xmm0
        pxor      736(%rsp), %xmm1
        pxor      %xmm5, %xmm14
        pxor      592(%rsp), %xmm1
        por       %xmm0, %xmm12
        movdqa    560(%rsp), %xmm0
        movdqa    %xmm14, %xmm15
        pxor      %xmm0, %xmm1
        paddd     %xmm14, %xmm15
        psrld     $31, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm1, %xmm14
        paddd     %xmm1, %xmm14
        psrld     $31, %xmm1
        por       %xmm1, %xmm14
        movdqa    %xmm13, %xmm1
        movdqa    %xmm15, 80(%rsp)
        movdqa    %xmm13, %xmm15
        por       %xmm12, %xmm1
        pand      %xmm12, %xmm15
        pand      %xmm6, %xmm1
        movdqa    %xmm14, 64(%rsp)
        por       %xmm1, %xmm15
        movdqa    %xmm3, %xmm1
        movdqa    %xmm3, %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm10
        por       %xmm14, %xmm1
        paddd     %xmm1, %xmm10
        movdqa    %xmm4, %xmm1
        paddd     %xmm8, %xmm10
        pand      %xmm11, %xmm1
        paddd     %xmm5, %xmm10
        movdqa    %xmm4, %xmm5
        por       %xmm11, %xmm5
        movdqa    %xmm9, %xmm14
        pand      %xmm2, %xmm5
        movdqa    %xmm9, %xmm15
        por       %xmm5, %xmm1
        pslld     $5, %xmm14
        paddd     %xmm1, %xmm7
        psrld     $27, %xmm15
        movdqa    %xmm4, %xmm1
        por       %xmm15, %xmm14
        pslld     $30, %xmm1
        psrld     $2, %xmm4
        paddd     %xmm14, %xmm7
        movdqa    %xmm13, %xmm5
        por       %xmm4, %xmm1
        paddd     %xmm8, %xmm7
        movdqa    464(%rsp), %xmm4
        pslld     $30, %xmm5
        pxor      144(%rsp), %xmm4
        psrld     $2, %xmm13
        pxor      880(%rsp), %xmm4
        paddd     %xmm0, %xmm7
        movdqa    672(%rsp), %xmm0
        por       %xmm13, %xmm5
        movdqa    384(%rsp), %xmm13
        pxor      %xmm0, %xmm4
        pxor      128(%rsp), %xmm13
        movdqa    %xmm4, %xmm15
        pxor      608(%rsp), %xmm13
        paddd     %xmm4, %xmm15
        movdqa    576(%rsp), %xmm14
        psrld     $31, %xmm4
        pxor      %xmm14, %xmm13
        por       %xmm4, %xmm15
        movdqa    %xmm13, %xmm4
        paddd     %xmm13, %xmm4
        psrld     $31, %xmm13
        por       %xmm13, %xmm4
        movdqa    %xmm3, %xmm13
        movdqa    %xmm4, 96(%rsp)
        movdqa    %xmm3, %xmm4
        por       %xmm5, %xmm13
        pand      %xmm5, %xmm4
        pand      %xmm12, %xmm13
        movdqa    %xmm15, 112(%rsp)
        por       %xmm13, %xmm4
        movdqa    %xmm10, %xmm13
        movdqa    %xmm10, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        paddd     %xmm4, %xmm6
        por       %xmm15, %xmm13
        paddd     %xmm13, %xmm6
        movdqa    %xmm9, %xmm13
        paddd     %xmm8, %xmm6
        pand      %xmm1, %xmm13
        paddd     %xmm0, %xmm6
        movdqa    %xmm9, %xmm0
        por       %xmm1, %xmm0
        movdqa    %xmm7, %xmm15
        pand      %xmm11, %xmm0
        movdqa    %xmm7, %xmm4
        por       %xmm0, %xmm13
        movdqa    %xmm3, %xmm0
        pslld     $30, %xmm0
        psrld     $2, %xmm3
        paddd     %xmm13, %xmm2
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        por       %xmm3, %xmm0
        movdqa    528(%rsp), %xmm3
        movdqa    %xmm9, %xmm13
        pxor      704(%rsp), %xmm3
        por       %xmm4, %xmm15
        pslld     $30, %xmm13
        psrld     $2, %xmm9
        pxor      480(%rsp), %xmm3
        paddd     %xmm15, %xmm2
        movdqa    864(%rsp), %xmm4
        por       %xmm9, %xmm13
        movdqa    512(%rsp), %xmm9
        paddd     %xmm8, %xmm2
        pxor      656(%rsp), %xmm9
        pxor      %xmm4, %xmm3
        pxor      400(%rsp), %xmm9
        paddd     %xmm14, %xmm2
        movdqa    592(%rsp), %xmm15
        movdqa    %xmm3, %xmm14
        pxor      %xmm15, %xmm9
        paddd     %xmm3, %xmm14
        psrld     $31, %xmm3
        por       %xmm3, %xmm14
        movdqa    %xmm9, %xmm3
        paddd     %xmm9, %xmm3
        psrld     $31, %xmm9
        por       %xmm9, %xmm3
        movdqa    %xmm10, %xmm9
        movdqa    %xmm3, (%rsp)
        movdqa    %xmm10, %xmm3
        por       %xmm0, %xmm9
        pand      %xmm0, %xmm3
        pand      %xmm5, %xmm9
        movdqa    %xmm14, 16(%rsp)
        por       %xmm9, %xmm3
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm14
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        paddd     %xmm3, %xmm12
        por       %xmm14, %xmm9
        paddd     %xmm9, %xmm12
        movdqa    %xmm7, %xmm9
        paddd     %xmm8, %xmm12
        pand      %xmm13, %xmm9
        paddd     %xmm4, %xmm12
        movdqa    %xmm7, %xmm4
        por       %xmm13, %xmm4
        movdqa    %xmm2, %xmm14
        pand      %xmm1, %xmm4
        movdqa    %xmm2, %xmm3
        por       %xmm4, %xmm9
        pslld     $5, %xmm14
        psrld     $27, %xmm3
        paddd     %xmm9, %xmm11
        por       %xmm3, %xmm14
        movdqa    %xmm7, %xmm4
        movdqa    80(%rsp), %xmm3
        paddd     %xmm14, %xmm11
        pxor      752(%rsp), %xmm3
        paddd     %xmm8, %xmm11
        pslld     $30, %xmm4
        psrld     $2, %xmm7
        pxor      496(%rsp), %xmm3
        paddd     %xmm15, %xmm11
        movdqa    64(%rsp), %xmm15
        movdqa    %xmm10, %xmm9
        por       %xmm7, %xmm4
        pslld     $30, %xmm9
        movdqa    880(%rsp), %xmm7
        psrld     $2, %xmm10
        pxor      688(%rsp), %xmm15
        pxor      %xmm7, %xmm3
        pxor      416(%rsp), %xmm15
        por       %xmm10, %xmm9
        movdqa    608(%rsp), %xmm10
        movdqa    %xmm3, %xmm14
        pxor      %xmm10, %xmm15
        paddd     %xmm3, %xmm14
        psrld     $31, %xmm3
        por       %xmm3, %xmm14
        movdqa    %xmm15, %xmm3
        paddd     %xmm15, %xmm3
        psrld     $31, %xmm15
        por       %xmm15, %xmm3
        movdqa    %xmm6, %xmm15
        movdqa    %xmm3, 32(%rsp)
        movdqa    %xmm6, %xmm3
        por       %xmm9, %xmm15
        pand      %xmm9, %xmm3
        pand      %xmm0, %xmm15
        por       %xmm15, %xmm3
        movdqa    %xmm11, %xmm15
        movdqa    %xmm14, 48(%rsp)
        paddd     %xmm3, %xmm5
        movdqa    %xmm12, %xmm3
        movdqa    %xmm12, %xmm14
        pslld     $5, %xmm3
        psrld     $27, %xmm14
        por       %xmm14, %xmm3
        movdqa    %xmm11, %xmm14
        paddd     %xmm3, %xmm5
        movdqa    %xmm2, %xmm3
        paddd     %xmm8, %xmm5
        pand      %xmm4, %xmm3
        paddd     %xmm7, %xmm5
        movdqa    %xmm2, %xmm7
        por       %xmm4, %xmm7
        pslld     $5, %xmm15
        pand      %xmm13, %xmm7
        psrld     $27, %xmm14
        por       %xmm7, %xmm3
        por       %xmm14, %xmm15
        paddd     %xmm3, %xmm1
        paddd     %xmm15, %xmm1
        paddd     %xmm8, %xmm1
        paddd     %xmm10, %xmm1
..B9.15:
        movdqa    %xmm6, %xmm3
        psrld     $2, %xmm6
        pslld     $30, %xmm3
        movdqa    112(%rsp), %xmm7
        por       %xmm6, %xmm3
        movdqa    %xmm2, %xmm6
        psrld     $2, %xmm2
        pxor      768(%rsp), %xmm7
        pslld     $30, %xmm6
        pxor      448(%rsp), %xmm7
        por       %xmm2, %xmm6
        movdqa    480(%rsp), %xmm10
        movdqa    96(%rsp), %xmm2
        pxor      %xmm10, %xmm7
        pxor      720(%rsp), %xmm2
        movdqa    %xmm7, %xmm15
        pxor      352(%rsp), %xmm2
        paddd     %xmm7, %xmm15
        movdqa    400(%rsp), %xmm14
        psrld     $31, %xmm7
        pxor      %xmm14, %xmm2
        por       %xmm7, %xmm15
        movdqa    %xmm2, %xmm7
        paddd     %xmm2, %xmm7
        psrld     $31, %xmm2
        por       %xmm2, %xmm7
        movdqa    %xmm12, %xmm2
        movdqa    %xmm7, 208(%rsp)
        movdqa    %xmm12, %xmm7
        por       %xmm3, %xmm2
        pand      %xmm3, %xmm7
        pand      %xmm9, %xmm2
        movdqa    %xmm15, 240(%rsp)
        por       %xmm2, %xmm7
        movdqa    %xmm5, %xmm2
        movdqa    %xmm5, %xmm15
        pslld     $5, %xmm2
        psrld     $27, %xmm15
        paddd     %xmm7, %xmm0
        por       %xmm15, %xmm2
        paddd     %xmm2, %xmm0
        movdqa    %xmm11, %xmm2
        paddd     %xmm8, %xmm0
        pand      %xmm6, %xmm2
        paddd     %xmm10, %xmm0
        movdqa    %xmm11, %xmm10
        por       %xmm6, %xmm10
        movdqa    %xmm1, %xmm15
        pand      %xmm4, %xmm10
        movdqa    %xmm1, %xmm7
        por       %xmm10, %xmm2
        pslld     $5, %xmm15
        paddd     %xmm2, %xmm13
        movdqa    %xmm12, %xmm2
        psrld     $27, %xmm7
        pslld     $30, %xmm2
        psrld     $2, %xmm12
        por       %xmm7, %xmm15
        movdqa    16(%rsp), %xmm7
        por       %xmm12, %xmm2
        movdqa    %xmm11, %xmm12
        psrld     $2, %xmm11
        pxor      784(%rsp), %xmm7
        pslld     $30, %xmm12
        pxor      368(%rsp), %xmm7
        paddd     %xmm15, %xmm13
        movdqa    496(%rsp), %xmm10
        por       %xmm11, %xmm12
        movdqa    (%rsp), %xmm11
        paddd     %xmm8, %xmm13
        pxor      736(%rsp), %xmm11
        pxor      %xmm10, %xmm7
        pxor      320(%rsp), %xmm11
        paddd     %xmm14, %xmm13
        movdqa    416(%rsp), %xmm14
        movdqa    %xmm7, %xmm15
        pxor      %xmm14, %xmm11
        paddd     %xmm7, %xmm15
        psrld     $31, %xmm7
        por       %xmm7, %xmm15
        movdqa    %xmm11, %xmm7
        paddd     %xmm11, %xmm7
        psrld     $31, %xmm11
        por       %xmm11, %xmm7
        movdqa    %xmm5, %xmm11
        movdqa    %xmm7, 272(%rsp)
        movdqa    %xmm5, %xmm7
        por       %xmm2, %xmm11
        pand      %xmm2, %xmm7
        pand      %xmm3, %xmm11
        movdqa    %xmm15, 288(%rsp)
        por       %xmm11, %xmm7
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm7, %xmm9
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm9
        movdqa    %xmm1, %xmm11
        paddd     %xmm8, %xmm9
        pand      %xmm12, %xmm11
        paddd     %xmm10, %xmm9
        movdqa    %xmm1, %xmm10
        por       %xmm12, %xmm10
        movdqa    %xmm13, %xmm15
        pand      %xmm6, %xmm10
        movdqa    %xmm13, %xmm7
        por       %xmm10, %xmm11
        pslld     $5, %xmm15
        psrld     $27, %xmm7
        paddd     %xmm11, %xmm4
        por       %xmm7, %xmm15
        movdqa    %xmm5, %xmm11
        paddd     %xmm15, %xmm4
        pslld     $30, %xmm11
        paddd     %xmm8, %xmm4
        psrld     $2, %xmm5
        paddd     %xmm14, %xmm4
        por       %xmm5, %xmm11
        movdqa    48(%rsp), %xmm14
        movdqa    %xmm1, %xmm5
        pxor      144(%rsp), %xmm14
        pslld     $30, %xmm5
        psrld     $2, %xmm1
        pxor      432(%rsp), %xmm14
        por       %xmm1, %xmm5
        movdqa    448(%rsp), %xmm7
        movdqa    32(%rsp), %xmm1
        pxor      %xmm7, %xmm14
        pxor      128(%rsp), %xmm1
        movdqa    %xmm14, %xmm15
        pxor      336(%rsp), %xmm1
        paddd     %xmm14, %xmm15
        movdqa    352(%rsp), %xmm10
        psrld     $31, %xmm14
        pxor      %xmm10, %xmm1
        por       %xmm14, %xmm15
        movdqa    %xmm1, %xmm14
        paddd     %xmm1, %xmm14
        psrld     $31, %xmm1
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        movdqa    %xmm14, 576(%rsp)
        movdqa    %xmm0, %xmm14
        por       %xmm11, %xmm1
        pand      %xmm11, %xmm14
        pand      %xmm2, %xmm1
        movdqa    %xmm15, 608(%rsp)
        por       %xmm1, %xmm14
        movdqa    %xmm9, %xmm1
        movdqa    %xmm9, %xmm15
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm3
        por       %xmm15, %xmm1
        paddd     %xmm1, %xmm3
        movdqa    %xmm13, %xmm1
        paddd     %xmm8, %xmm3
        pand      %xmm5, %xmm1
        paddd     %xmm7, %xmm3
        movdqa    %xmm13, %xmm7
        por       %xmm5, %xmm7
        movdqa    %xmm4, %xmm15
        pand      %xmm12, %xmm7
        movdqa    %xmm4, %xmm14
        por       %xmm7, %xmm1
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        paddd     %xmm1, %xmm6
        por       %xmm14, %xmm15
        movdqa    %xmm0, %xmm1
        paddd     %xmm15, %xmm6
        movdqa    %xmm13, %xmm7
        paddd     %xmm8, %xmm6
        pslld     $30, %xmm1
        paddd     %xmm10, %xmm6
        psrld     $2, %xmm0
        movdqa    528(%rsp), %xmm10
        pslld     $30, %xmm7
        pxor      240(%rsp), %xmm10
        psrld     $2, %xmm13
        pxor      464(%rsp), %xmm10
        por       %xmm0, %xmm1
        movdqa    512(%rsp), %xmm0
        por       %xmm13, %xmm7
        movdqa    368(%rsp), %xmm13
        pxor      208(%rsp), %xmm0
        pxor      %xmm13, %xmm10
        pxor      384(%rsp), %xmm0
        movdqa    %xmm10, %xmm14
        movdqa    320(%rsp), %xmm15
        paddd     %xmm10, %xmm14
        pxor      %xmm15, %xmm0
        psrld     $31, %xmm10
        por       %xmm10, %xmm14
        movdqa    %xmm0, %xmm10
        paddd     %xmm0, %xmm10
        psrld     $31, %xmm0
        por       %xmm0, %xmm10
        movdqa    %xmm9, %xmm0
        movdqa    %xmm10, 624(%rsp)
        movdqa    %xmm9, %xmm10
        por       %xmm1, %xmm0
        pand      %xmm1, %xmm10
        pand      %xmm11, %xmm0
        movdqa    %xmm14, 640(%rsp)
        por       %xmm0, %xmm10
        movdqa    %xmm3, %xmm0
        movdqa    %xmm3, %xmm14
        pslld     $5, %xmm0
        psrld     $27, %xmm14
        paddd     %xmm10, %xmm2
        por       %xmm14, %xmm0
        paddd     %xmm0, %xmm2
        movdqa    %xmm4, %xmm0
        paddd     %xmm8, %xmm2
        pand      %xmm7, %xmm0
        paddd     %xmm13, %xmm2
        movdqa    %xmm4, %xmm13
        por       %xmm7, %xmm13
        movdqa    %xmm6, %xmm14
        pand      %xmm5, %xmm13
        movdqa    %xmm6, %xmm10
        por       %xmm13, %xmm0
        pslld     $5, %xmm14
        psrld     $27, %xmm10
        paddd     %xmm0, %xmm12
        por       %xmm10, %xmm14
        movdqa    %xmm9, %xmm0
        paddd     %xmm14, %xmm12
        movdqa    %xmm4, %xmm13
        paddd     %xmm8, %xmm12
        pslld     $30, %xmm0
        paddd     %xmm15, %xmm12
        psrld     $2, %xmm9
        movdqa    80(%rsp), %xmm15
        pslld     $30, %xmm13
        pxor      288(%rsp), %xmm15
        psrld     $2, %xmm4
        pxor      704(%rsp), %xmm15
        por       %xmm9, %xmm0
        movdqa    432(%rsp), %xmm9
        por       %xmm4, %xmm13
        movdqa    64(%rsp), %xmm4
        pxor      %xmm9, %xmm15
        pxor      272(%rsp), %xmm4
        movdqa    %xmm15, %xmm10
        pxor      656(%rsp), %xmm4
        paddd     %xmm15, %xmm10
        movdqa    336(%rsp), %xmm14
        psrld     $31, %xmm15
        pxor      %xmm14, %xmm4
        por       %xmm15, %xmm10
        movdqa    %xmm4, %xmm15
        paddd     %xmm4, %xmm15
        psrld     $31, %xmm4
        por       %xmm4, %xmm15
        movdqa    %xmm3, %xmm4
        movdqa    %xmm10, 192(%rsp)
        movdqa    %xmm3, %xmm10
        por       %xmm0, %xmm4
        pand      %xmm0, %xmm10
        pand      %xmm1, %xmm4
        movdqa    %xmm15, 176(%rsp)
        por       %xmm4, %xmm10
        movdqa    %xmm2, %xmm4
        movdqa    %xmm2, %xmm15
        pslld     $5, %xmm4
        psrld     $27, %xmm15
        paddd     %xmm10, %xmm11
        por       %xmm15, %xmm4
        paddd     %xmm4, %xmm11
        movdqa    %xmm6, %xmm4
        paddd     %xmm8, %xmm11
        pand      %xmm13, %xmm4
        paddd     %xmm9, %xmm11
        movdqa    %xmm6, %xmm9
        por       %xmm13, %xmm9
        movdqa    %xmm12, %xmm15
        pand      %xmm7, %xmm9
        movdqa    %xmm12, %xmm10
        por       %xmm9, %xmm4
        pslld     $5, %xmm15
        psrld     $27, %xmm10
        movdqa    %xmm3, %xmm9
        paddd     %xmm4, %xmm5
        por       %xmm10, %xmm15
        pslld     $30, %xmm9
        psrld     $2, %xmm3
        paddd     %xmm15, %xmm5
        por       %xmm3, %xmm9
        movdqa    112(%rsp), %xmm3
        movdqa    %xmm6, %xmm4
        pxor      608(%rsp), %xmm3
        paddd     %xmm8, %xmm5
        pslld     $30, %xmm4
        psrld     $2, %xmm6
        pxor      752(%rsp), %xmm3
        paddd     %xmm14, %xmm5
        movdqa    96(%rsp), %xmm14
        por       %xmm6, %xmm4
        movdqa    464(%rsp), %xmm6
        pxor      576(%rsp), %xmm14
        pxor      %xmm6, %xmm3
        pxor      688(%rsp), %xmm14
        movdqa    %xmm3, %xmm15
        movdqa    384(%rsp), %xmm10
        paddd     %xmm3, %xmm15
        pxor      %xmm10, %xmm14
        psrld     $31, %xmm3
        por       %xmm3, %xmm15
        movdqa    %xmm14, %xmm3
        paddd     %xmm14, %xmm3
        psrld     $31, %xmm14
        por       %xmm14, %xmm3
        movdqa    %xmm2, %xmm14
        movdqa    %xmm3, 224(%rsp)
        movdqa    %xmm2, %xmm3
        por       %xmm9, %xmm14
        pand      %xmm9, %xmm3
        pand      %xmm0, %xmm14
        movdqa    %xmm15, 256(%rsp)
        por       %xmm14, %xmm3
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, %xmm15
        pslld     $5, %xmm14
        psrld     $27, %xmm15
        paddd     %xmm3, %xmm1
        por       %xmm15, %xmm14
        paddd     %xmm14, %xmm1
        movdqa    %xmm12, %xmm14
        paddd     %xmm8, %xmm1
        pand      %xmm4, %xmm14
        paddd     %xmm6, %xmm1
        movdqa    %xmm12, %xmm6
        por       %xmm4, %xmm6
        movdqa    %xmm5, %xmm15
        pand      %xmm13, %xmm6
        movdqa    %xmm5, %xmm3
        por       %xmm6, %xmm14
        movdqa    %xmm12, %xmm6
        pslld     $30, %xmm6
        psrld     $2, %xmm12
        paddd     %xmm14, %xmm7
        pslld     $5, %xmm15
        psrld     $27, %xmm3
        movdqa    %xmm2, %xmm14
        por       %xmm12, %xmm6
        por       %xmm3, %xmm15
        movdqa    16(%rsp), %xmm12
        pslld     $30, %xmm14
        pxor      640(%rsp), %xmm12
        psrld     $2, %xmm2
        pxor      768(%rsp), %xmm12
        paddd     %xmm15, %xmm7
        movdqa    704(%rsp), %xmm3
        por       %xmm2, %xmm14
        movdqa    (%rsp), %xmm2
        paddd     %xmm8, %xmm7
        pxor      624(%rsp), %xmm2
        pxor      %xmm3, %xmm12
        pxor      720(%rsp), %xmm2
        paddd     %xmm10, %xmm7
        movdqa    656(%rsp), %xmm10
        movdqa    %xmm12, %xmm15
        pxor      %xmm10, %xmm2
        paddd     %xmm12, %xmm15
        psrld     $31, %xmm12
        por       %xmm12, %xmm15
        movdqa    %xmm2, %xmm12
        paddd     %xmm2, %xmm12
        psrld     $31, %xmm2
        por       %xmm2, %xmm12
        movdqa    %xmm11, %xmm2
        movdqa    %xmm15, 544(%rsp)
        movdqa    %xmm11, %xmm15
        por       %xmm14, %xmm2
        pand      %xmm14, %xmm15
        pand      %xmm9, %xmm2
        movdqa    %xmm12, 304(%rsp)
        por       %xmm2, %xmm15
        movdqa    %xmm1, %xmm2
        movdqa    %xmm1, %xmm12
        pslld     $5, %xmm2
        psrld     $27, %xmm12
        paddd     %xmm15, %xmm0
        por       %xmm12, %xmm2
        paddd     %xmm2, %xmm0
        movdqa    %xmm5, %xmm2
        paddd     %xmm8, %xmm0
        movdqa    %xmm7, %xmm12
        paddd     %xmm3, %xmm0
        movdqa    %xmm5, %xmm3
        por       %xmm6, %xmm3
        movdqa    %xmm7, %xmm15
        pand      %xmm6, %xmm2
        pand      %xmm4, %xmm3
        pslld     $5, %xmm12
        psrld     $27, %xmm15
        por       %xmm3, %xmm2
        por       %xmm15, %xmm12
        movdqa    48(%rsp), %xmm15
        movdqa    %xmm11, %xmm3
        pxor      192(%rsp), %xmm15
        paddd     %xmm2, %xmm13
        pslld     $30, %xmm3
        psrld     $2, %xmm11
        pxor      784(%rsp), %xmm15
        paddd     %xmm12, %xmm13
        movdqa    752(%rsp), %xmm12
        por       %xmm11, %xmm3
        movdqa    32(%rsp), %xmm11
        movdqa    %xmm5, %xmm2
        pxor      176(%rsp), %xmm11
        paddd     %xmm8, %xmm13
        pslld     $30, %xmm2
        psrld     $2, %xmm5
        pxor      %xmm12, %xmm15
        paddd     %xmm10, %xmm13
        pxor      736(%rsp), %xmm11
        por       %xmm5, %xmm2
        movdqa    688(%rsp), %xmm5
        movdqa    %xmm15, %xmm10
        pxor      %xmm5, %xmm11
        paddd     %xmm15, %xmm10
        psrld     $31, %xmm15
        por       %xmm15, %xmm10
        movdqa    %xmm11, %xmm15
        paddd     %xmm11, %xmm15
        psrld     $31, %xmm11
        por       %xmm11, %xmm15
        movdqa    %xmm1, %xmm11
        movdqa    %xmm15, 560(%rsp)
        movdqa    %xmm1, %xmm15
        por       %xmm3, %xmm11
        pand      %xmm3, %xmm15
        pand      %xmm14, %xmm11
        por       %xmm11, %xmm15
        movdqa    %xmm0, %xmm11
        paddd     %xmm15, %xmm9
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm15
        psrld     $27, %xmm11
        por       %xmm11, %xmm15
        movdqa    %xmm7, %xmm11
        paddd     %xmm15, %xmm9
        pand      %xmm2, %xmm11
        paddd     %xmm8, %xmm9
        movdqa    %xmm13, %xmm15
        paddd     %xmm12, %xmm9
        movdqa    %xmm7, %xmm12
        por       %xmm2, %xmm12
        psrld     $27, %xmm15
        pand      %xmm6, %xmm12
        por       %xmm12, %xmm11
        paddd     %xmm11, %xmm4
        movdqa    %xmm13, %xmm11
        pslld     $5, %xmm11
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm4
        movdqa    %xmm1, %xmm11
        paddd     %xmm8, %xmm4
        movdqa    %xmm7, %xmm8
        pslld     $30, %xmm8
        psrld     $2, %xmm7
        por       %xmm7, %xmm8
        paddd     %xmm5, %xmm4
        movdqa    256(%rsp), %xmm7
        pslld     $30, %xmm11
        pxor      240(%rsp), %xmm7
        psrld     $2, %xmm1
        pxor      144(%rsp), %xmm7
        por       %xmm1, %xmm11
        movdqa    768(%rsp), %xmm15
        movdqa    224(%rsp), %xmm5
        pxor      %xmm15, %xmm7
        pxor      208(%rsp), %xmm5
        movdqa    %xmm7, %xmm12
        pxor      128(%rsp), %xmm5
        paddd     %xmm7, %xmm12
        movdqa    720(%rsp), %xmm1
        psrld     $31, %xmm7
        pxor      %xmm1, %xmm5
        por       %xmm7, %xmm12
        movdqa    %xmm5, %xmm7
        paddd     %xmm5, %xmm7
        psrld     $31, %xmm5
        por       %xmm5, %xmm7
        movdqa    %xmm11, %xmm5
        movdqa    %xmm12, 832(%rsp)
        pxor      %xmm3, %xmm5
        movdqa    %xmm7, 672(%rsp)
        movdqa    %xmm9, %xmm12
        movdqa    %xmm9, %xmm7
        pxor      %xmm0, %xmm5
        pslld     $5, %xmm12
        psrld     $27, %xmm7
        paddd     %xmm5, %xmm14
        por       %xmm7, %xmm12
        movdqa    .L_2il0floatpacket.550(%rip), %xmm5
        paddd     %xmm12, %xmm14
        paddd     %xmm5, %xmm14
        movdqa    %xmm4, %xmm12
        paddd     %xmm15, %xmm14
        movdqa    %xmm8, %xmm15
        pxor      %xmm2, %xmm15
        movdqa    %xmm4, %xmm7
        pxor      %xmm13, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm7
        paddd     %xmm15, %xmm6
        por       %xmm7, %xmm12
        paddd     %xmm12, %xmm6
        paddd     %xmm5, %xmm6
        paddd     %xmm1, %xmm6
        movdqa    %xmm0, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm0
        movdqa    544(%rsp), %xmm15
        por       %xmm0, %xmm1
        movdqa    %xmm13, %xmm0
        psrld     $2, %xmm13
        movdqa    304(%rsp), %xmm12
        pslld     $30, %xmm0
        pxor      288(%rsp), %xmm15
        por       %xmm13, %xmm0
        pxor      272(%rsp), %xmm12
        pxor      528(%rsp), %xmm15
        movdqa    784(%rsp), %xmm13
        pxor      512(%rsp), %xmm12
        pxor      %xmm13, %xmm15
        movdqa    736(%rsp), %xmm7
        pxor      %xmm7, %xmm12
        movdqa    %xmm12, 800(%rsp)
        movdqa    %xmm15, %xmm12
        paddd     %xmm15, %xmm12
        psrld     $31, %xmm15
        movdqa    %xmm15, 160(%rsp)
        movdqa    %xmm1, %xmm15
        pxor      %xmm11, %xmm15
        pxor      %xmm9, %xmm15
        movdqa    %xmm12, 816(%rsp)
        paddd     %xmm15, %xmm3
        movdqa    %xmm14, %xmm15
        movdqa    %xmm14, %xmm12
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        por       %xmm12, %xmm15
        movdqa    %xmm6, %xmm12
        paddd     %xmm15, %xmm3
        movdqa    %xmm6, %xmm15
        paddd     %xmm5, %xmm3
        pslld     $5, %xmm15
        paddd     %xmm13, %xmm3
        movdqa    %xmm0, %xmm13
        pxor      %xmm8, %xmm13
        psrld     $27, %xmm12
        pxor      %xmm4, %xmm13
        por       %xmm12, %xmm15
        paddd     %xmm13, %xmm2
        movdqa    %xmm9, %xmm12
        paddd     %xmm15, %xmm2
        pslld     $30, %xmm12
        paddd     %xmm5, %xmm2
        psrld     $2, %xmm9
        paddd     %xmm7, %xmm2
        movdqa    %xmm4, %xmm7
        pslld     $30, %xmm7
        psrld     $2, %xmm4
        movdqa    %xmm10, 592(%rsp)
        por       %xmm4, %xmm7
        pxor      608(%rsp), %xmm10
        por       %xmm9, %xmm12
        movdqa    560(%rsp), %xmm4
        pxor      80(%rsp), %xmm10
        pxor      576(%rsp), %xmm4
        pxor      144(%rsp), %xmm10
        pxor      64(%rsp), %xmm4
..B9.14:
        movdqa    128(%rsp), %xmm13
        movdqa    %xmm12, %xmm9
        pxor      %xmm13, %xmm4
        pxor      %xmm1, %xmm9
        movdqa    %xmm4, 352(%rsp)
        movdqa    %xmm10, %xmm4
        paddd     %xmm10, %xmm4
        psrld     $31, %xmm10
        movdqa    %xmm10, 368(%rsp)
        pxor      %xmm14, %xmm9
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm10
        paddd     %xmm9, %xmm11
        pslld     $5, %xmm15
        psrld     $27, %xmm10
        movdqa    %xmm7, %xmm9
        movdqa    %xmm4, 320(%rsp)
        por       %xmm10, %xmm15
        pxor      %xmm0, %xmm9
        movdqa    %xmm2, %xmm4
        movdqa    %xmm2, %xmm10
        pxor      %xmm6, %xmm9
        pslld     $5, %xmm4
        psrld     $27, %xmm10
        paddd     %xmm9, %xmm8
        por       %xmm10, %xmm4
        paddd     %xmm4, %xmm8
        movdqa    %xmm14, %xmm4
        pslld     $30, %xmm4
        psrld     $2, %xmm14
        por       %xmm14, %xmm4
        movdqa    %xmm6, %xmm14
        pslld     $30, %xmm14
        psrld     $2, %xmm6
        paddd     %xmm5, %xmm8
        por       %xmm6, %xmm14
        movdqa    832(%rsp), %xmm6
        paddd     %xmm13, %xmm8
        pxor      640(%rsp), %xmm6
        paddd     %xmm15, %xmm11
        movdqa    112(%rsp), %xmm13
        paddd     %xmm5, %xmm11
        movdqa    528(%rsp), %xmm15
        pxor      %xmm13, %xmm6
        movdqa    672(%rsp), %xmm9
        pxor      %xmm15, %xmm6
        movdqa    %xmm6, 336(%rsp)
        movdqa    %xmm12, %xmm6
        pxor      624(%rsp), %xmm9
        pxor      %xmm4, %xmm6
        pxor      96(%rsp), %xmm9
        pxor      %xmm3, %xmm6
        movdqa    512(%rsp), %xmm10
        paddd     %xmm6, %xmm1
        paddd     144(%rsp), %xmm11
        pxor      %xmm10, %xmm9
        movdqa    %xmm9, 384(%rsp)
        movdqa    %xmm11, %xmm6
        movdqa    %xmm11, %xmm9
        pslld     $5, %xmm6
        psrld     $27, %xmm9
        por       %xmm9, %xmm6
        movdqa    %xmm8, %xmm9
        paddd     %xmm6, %xmm1
        movdqa    %xmm8, %xmm6
        paddd     %xmm5, %xmm1
        pslld     $5, %xmm9
        paddd     %xmm15, %xmm1
        movdqa    %xmm7, %xmm15
        psrld     $27, %xmm6
        pxor      %xmm14, %xmm15
        por       %xmm6, %xmm9
        movdqa    %xmm3, %xmm6
        pxor      %xmm2, %xmm15
        pslld     $30, %xmm6
        psrld     $2, %xmm3
        paddd     %xmm15, %xmm0
        por       %xmm3, %xmm6
        movdqa    %xmm2, %xmm3
        paddd     %xmm9, %xmm0
        pslld     $30, %xmm3
        psrld     $2, %xmm2
        paddd     %xmm5, %xmm0
        por       %xmm2, %xmm3
        movdqa    %xmm6, %xmm2
        paddd     %xmm10, %xmm0
        pxor      %xmm4, %xmm2
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm9
        pxor      %xmm11, %xmm2
        pslld     $5, %xmm10
        psrld     $27, %xmm9
        paddd     %xmm2, %xmm12
        por       %xmm9, %xmm10
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm2
        pslld     $5, %xmm9
        psrld     $27, %xmm2
        movdqa    %xmm3, %xmm15
        por       %xmm2, %xmm9
        movdqa    %xmm11, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm11
        paddd     %xmm10, %xmm12
        pxor      %xmm14, %xmm15
        por       %xmm11, %xmm2
        movdqa    %xmm8, %xmm11
        paddd     %xmm5, %xmm12
        pxor      %xmm8, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm8
        paddd     80(%rsp), %xmm12
        paddd     %xmm15, %xmm7
        por       %xmm8, %xmm11
        movdqa    %xmm2, %xmm8
        paddd     %xmm9, %xmm7
        pxor      %xmm6, %xmm8
        movdqa    %xmm12, %xmm10
        movdqa    %xmm12, %xmm9
        pxor      %xmm1, %xmm8
        pslld     $5, %xmm10
        psrld     $27, %xmm9
        paddd     %xmm8, %xmm4
        por       %xmm9, %xmm10
        paddd     %xmm5, %xmm7
        paddd     %xmm10, %xmm4
        movdqa    %xmm1, %xmm8
        paddd     %xmm5, %xmm4
        movdqa    %xmm0, %xmm9
        paddd     %xmm13, %xmm4
        movdqa    %xmm11, %xmm13
        pxor      %xmm3, %xmm13
        pslld     $30, %xmm8
        paddd     64(%rsp), %xmm7
        pxor      %xmm0, %xmm13
        paddd     %xmm13, %xmm14
        movdqa    %xmm7, %xmm13
        movdqa    %xmm7, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        psrld     $2, %xmm1
        por       %xmm15, %xmm13
        pslld     $30, %xmm9
        paddd     %xmm13, %xmm14
        psrld     $2, %xmm0
        paddd     %xmm5, %xmm14
        por       %xmm1, %xmm8
        por       %xmm0, %xmm9
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm0
        movdqa    %xmm8, %xmm1
        paddd     96(%rsp), %xmm14
        pslld     $5, %xmm13
        psrld     $27, %xmm0
        movdqa    %xmm9, %xmm10
        pxor      %xmm2, %xmm1
        por       %xmm0, %xmm13
        pxor      %xmm11, %xmm10
        movdqa    %xmm14, %xmm0
        movdqa    %xmm14, %xmm15
        pxor      %xmm12, %xmm1
        pxor      %xmm7, %xmm10
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        paddd     %xmm1, %xmm6
        paddd     %xmm10, %xmm3
        por       %xmm15, %xmm0
        movdqa    %xmm12, %xmm1
        paddd     %xmm0, %xmm3
        pslld     $30, %xmm1
        psrld     $2, %xmm12
        movdqa    %xmm7, %xmm0
        paddd     %xmm13, %xmm6
        por       %xmm12, %xmm1
        pslld     $30, %xmm0
        psrld     $2, %xmm7
        paddd     %xmm5, %xmm6
        por       %xmm7, %xmm0
        movdqa    %xmm1, %xmm7
        paddd     16(%rsp), %xmm6
        paddd     %xmm5, %xmm3
        pxor      %xmm8, %xmm7
        movdqa    %xmm6, %xmm12
        paddd     (%rsp), %xmm3
        pxor      %xmm4, %xmm7
        movdqa    %xmm6, %xmm13
        movdqa    %xmm0, %xmm10
        paddd     %xmm7, %xmm2
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        pxor      %xmm9, %xmm10
        movdqa    %xmm3, %xmm7
        movdqa    %xmm3, %xmm15
        por       %xmm13, %xmm12
        pxor      %xmm14, %xmm10
        pslld     $5, %xmm7
        psrld     $27, %xmm15
        paddd     %xmm12, %xmm2
        paddd     %xmm10, %xmm11
        por       %xmm15, %xmm7
        movdqa    %xmm4, %xmm12
        paddd     %xmm7, %xmm11
        pslld     $30, %xmm12
        psrld     $2, %xmm4
        movdqa    %xmm14, %xmm7
        por       %xmm4, %xmm12
        pslld     $30, %xmm7
        psrld     $2, %xmm14
        paddd     %xmm5, %xmm2
        por       %xmm14, %xmm7
        movdqa    %xmm12, %xmm14
        paddd     48(%rsp), %xmm2
        pxor      %xmm1, %xmm14
        paddd     %xmm5, %xmm11
        pxor      %xmm6, %xmm14
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm13
        paddd     32(%rsp), %xmm11
        paddd     %xmm14, %xmm8
        pslld     $5, %xmm10
        psrld     $27, %xmm13
        movdqa    %xmm7, %xmm15
        movdqa    %xmm6, %xmm14
        por       %xmm13, %xmm10
        pxor      %xmm0, %xmm15
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm4
        pslld     $30, %xmm14
        psrld     $2, %xmm6
        pxor      %xmm3, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm4
        por       %xmm6, %xmm14
        movdqa    %xmm3, %xmm6
        paddd     %xmm15, %xmm9
        por       %xmm4, %xmm13
        pslld     $30, %xmm6
        psrld     $2, %xmm3
        paddd     %xmm13, %xmm9
        por       %xmm3, %xmm6
        movdqa    %xmm14, %xmm3
        paddd     %xmm5, %xmm9
        pxor      %xmm12, %xmm3
        paddd     208(%rsp), %xmm9
        paddd     %xmm10, %xmm8
        pxor      %xmm2, %xmm3
        movdqa    %xmm6, %xmm15
        paddd     %xmm5, %xmm8
        paddd     %xmm3, %xmm1
        pxor      %xmm7, %xmm15
        movdqa    %xmm9, %xmm3
        movdqa    %xmm9, %xmm4
        pxor      %xmm11, %xmm15
        paddd     240(%rsp), %xmm8
        pslld     $5, %xmm3
        psrld     $27, %xmm4
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, %xmm13
        paddd     %xmm15, %xmm0
        por       %xmm4, %xmm3
        pslld     $5, %xmm10
        psrld     $27, %xmm13
        paddd     %xmm3, %xmm0
        movdqa    %xmm2, %xmm15
        por       %xmm13, %xmm10
        paddd     %xmm5, %xmm0
        pslld     $30, %xmm15
        psrld     $2, %xmm2
        movdqa    %xmm11, %xmm13
        paddd     272(%rsp), %xmm0
        por       %xmm2, %xmm15
        pslld     $30, %xmm13
        psrld     $2, %xmm11
        paddd     %xmm10, %xmm1
        por       %xmm11, %xmm13
        movdqa    %xmm15, %xmm2
        movdqa    %xmm0, %xmm4
        movdqa    %xmm0, %xmm10
        paddd     %xmm5, %xmm1
        pxor      %xmm14, %xmm2
        movdqa    %xmm13, %xmm3
        pslld     $5, %xmm4
        psrld     $27, %xmm10
        paddd     288(%rsp), %xmm1
        pxor      %xmm8, %xmm2
        pxor      %xmm6, %xmm3
        por       %xmm10, %xmm4
        movdqa    %xmm8, %xmm10
        paddd     %xmm2, %xmm12
        movdqa    %xmm1, %xmm2
        movdqa    %xmm1, %xmm11
        pxor      %xmm9, %xmm3
        pslld     $30, %xmm10
        psrld     $2, %xmm8
        pslld     $5, %xmm2
        psrld     $27, %xmm11
        paddd     %xmm3, %xmm7
        por       %xmm8, %xmm10
        por       %xmm11, %xmm2
        paddd     %xmm4, %xmm7
        movdqa    %xmm10, %xmm8
        paddd     %xmm2, %xmm12
        paddd     %xmm5, %xmm7
        pxor      %xmm15, %xmm8
        paddd     %xmm5, %xmm12
        paddd     576(%rsp), %xmm7
        movdqa    %xmm9, %xmm11
        pxor      %xmm1, %xmm8
        pslld     $30, %xmm11
        paddd     608(%rsp), %xmm12
        psrld     $2, %xmm9
        paddd     %xmm8, %xmm14
        movdqa    %xmm7, %xmm4
        movdqa    %xmm7, %xmm8
        por       %xmm9, %xmm11
        movdqa    %xmm12, %xmm2
        movdqa    %xmm12, %xmm9
        pslld     $5, %xmm4
        psrld     $27, %xmm8
        pslld     $5, %xmm2
        psrld     $27, %xmm9
        movdqa    %xmm11, %xmm3
        por       %xmm8, %xmm4
        movdqa    %xmm1, %xmm8
        por       %xmm9, %xmm2
        pxor      %xmm13, %xmm3
        pslld     $30, %xmm8
        psrld     $2, %xmm1
        movdqa    %xmm0, %xmm9
        pxor      %xmm0, %xmm3
        por       %xmm1, %xmm8
        pslld     $30, %xmm9
        psrld     $2, %xmm0
        paddd     %xmm2, %xmm14
        por       %xmm0, %xmm9
        movdqa    %xmm8, %xmm0
        paddd     %xmm5, %xmm14
        pxor      %xmm10, %xmm0
        paddd     %xmm3, %xmm6
        paddd     640(%rsp), %xmm14
        pxor      %xmm12, %xmm0
        paddd     %xmm4, %xmm6
        paddd     %xmm0, %xmm15
        movdqa    %xmm14, %xmm0
        movdqa    %xmm14, %xmm1
        paddd     %xmm5, %xmm6
        pslld     $5, %xmm0
        psrld     $27, %xmm1
        movdqa    %xmm9, %xmm2
        paddd     624(%rsp), %xmm6
        por       %xmm1, %xmm0
        paddd     %xmm0, %xmm15
        pxor      %xmm11, %xmm2
        movdqa    %xmm6, %xmm4
        movdqa    %xmm6, %xmm3
        movdqa    %xmm12, %xmm0
        pxor      %xmm7, %xmm2
        pslld     $5, %xmm4
        psrld     $27, %xmm3
        pslld     $30, %xmm0
        psrld     $2, %xmm12
        paddd     %xmm5, %xmm15
        paddd     %xmm2, %xmm13
        por       %xmm3, %xmm4
        por       %xmm12, %xmm0
        movdqa    %xmm7, %xmm12
        paddd     %xmm4, %xmm13
        paddd     192(%rsp), %xmm15
        pslld     $30, %xmm12
        psrld     $2, %xmm7
        paddd     %xmm5, %xmm13
        por       %xmm7, %xmm12
        movdqa    %xmm15, %xmm2
        movdqa    %xmm15, %xmm1
        pslld     $5, %xmm2
        paddd     176(%rsp), %xmm13
        psrld     $27, %xmm1
        movdqa    %xmm12, %xmm3
        movdqa    %xmm0, %xmm7
        por       %xmm1, %xmm2
        pxor      %xmm9, %xmm3
        movdqa    %xmm13, %xmm1
        movdqa    %xmm13, %xmm4
        pxor      %xmm8, %xmm7
        pxor      %xmm6, %xmm3
        pslld     $5, %xmm1
        psrld     $27, %xmm4
        pxor      %xmm14, %xmm7
        paddd     %xmm3, %xmm11
        por       %xmm4, %xmm1
        paddd     %xmm7, %xmm10
        paddd     %xmm1, %xmm11
        movdqa    %xmm14, %xmm1
        movdqa    %xmm6, %xmm7
        paddd     %xmm2, %xmm10
        pslld     $30, %xmm1
        psrld     $2, %xmm14
        pslld     $30, %xmm7
        psrld     $2, %xmm6
        paddd     %xmm5, %xmm10
        por       %xmm14, %xmm1
        por       %xmm6, %xmm7
        movdqa    %xmm1, %xmm14
        paddd     256(%rsp), %xmm10
        movdqa    %xmm7, %xmm3
        pxor      %xmm0, %xmm14
        movdqa    %xmm10, %xmm2
        movdqa    %xmm10, %xmm6
        pxor      %xmm12, %xmm3
        pxor      %xmm15, %xmm14
        pslld     $5, %xmm2
        psrld     $27, %xmm6
        pxor      %xmm13, %xmm3
        paddd     %xmm14, %xmm8
        por       %xmm6, %xmm2
        paddd     %xmm3, %xmm9
        movdqa    %xmm15, %xmm3
        paddd     %xmm5, %xmm11
        paddd     %xmm2, %xmm8
        pslld     $30, %xmm3
        psrld     $2, %xmm15
        movdqa    %xmm13, %xmm2
        por       %xmm15, %xmm3
        paddd     224(%rsp), %xmm11
        pslld     $30, %xmm2
        psrld     $2, %xmm13
        movdqa    %xmm11, %xmm4
        movdqa    %xmm11, %xmm14
        por       %xmm13, %xmm2
        movdqa    %xmm3, %xmm13
        paddd     %xmm5, %xmm8
        pslld     $5, %xmm4
        psrld     $27, %xmm14
        pxor      %xmm1, %xmm13
        por       %xmm14, %xmm4
        paddd     544(%rsp), %xmm8
        pxor      %xmm10, %xmm13
        movdqa    %xmm2, %xmm14
        paddd     %xmm13, %xmm0
        movdqa    %xmm8, %xmm13
        movdqa    %xmm8, %xmm15
        pxor      %xmm7, %xmm14
        paddd     %xmm4, %xmm9
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        pxor      %xmm11, %xmm14
        paddd     %xmm5, %xmm9
        por       %xmm15, %xmm13
        paddd     %xmm14, %xmm12
        movdqa    %xmm10, %xmm14
        paddd     %xmm13, %xmm0
        paddd     304(%rsp), %xmm9
        pslld     $30, %xmm14
        psrld     $2, %xmm10
        movdqa    %xmm11, %xmm13
        paddd     %xmm5, %xmm0
        movdqa    %xmm9, %xmm4
        movdqa    %xmm9, %xmm6
        por       %xmm10, %xmm14
        pslld     $30, %xmm13
        psrld     $2, %xmm11
        paddd     592(%rsp), %xmm0
        pslld     $5, %xmm4
        psrld     $27, %xmm6
        por       %xmm11, %xmm13
        movdqa    %xmm14, %xmm11
        por       %xmm6, %xmm4
        pxor      %xmm3, %xmm11
        movdqa    %xmm0, %xmm6
        movdqa    %xmm0, %xmm10
        pxor      %xmm8, %xmm11
        pslld     $5, %xmm6
        psrld     $27, %xmm10
        paddd     %xmm11, %xmm1
        por       %xmm10, %xmm6
        paddd     %xmm4, %xmm12
        paddd     %xmm6, %xmm1
        movdqa    %xmm8, %xmm6
        paddd     %xmm5, %xmm12
        movdqa    %xmm13, %xmm11
        pslld     $30, %xmm6
        psrld     $2, %xmm8
        pxor      %xmm2, %xmm11
        paddd     560(%rsp), %xmm12
        por       %xmm8, %xmm6
        pxor      %xmm9, %xmm11
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm4
        movdqa    %xmm6, %xmm8
        paddd     %xmm5, %xmm1
        paddd     %xmm11, %xmm7
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        movdqa    %xmm9, %xmm11
        pxor      %xmm14, %xmm8
        paddd     832(%rsp), %xmm1
        por       %xmm4, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm9
        pxor      %xmm0, %xmm8
        paddd     %xmm15, %xmm7
        por       %xmm9, %xmm11
        paddd     %xmm8, %xmm3
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm9
        paddd     %xmm5, %xmm7
        pslld     $5, %xmm8
        psrld     $27, %xmm9
        movdqa    %xmm11, %xmm10
        paddd     672(%rsp), %xmm7
        por       %xmm9, %xmm8
        paddd     %xmm8, %xmm3
        pxor      %xmm13, %xmm10
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm15
        pxor      %xmm12, %xmm10
        pslld     $5, %xmm8
        psrld     $27, %xmm15
        paddd     %xmm10, %xmm2
        por       %xmm15, %xmm8
        paddd     %xmm5, %xmm3
        paddd     %xmm8, %xmm2
        movdqa    %xmm0, %xmm8
        movdqa    816(%rsp), %xmm4
        pslld     $30, %xmm8
        psrld     $2, %xmm0
        paddd     %xmm5, %xmm2
        por       160(%rsp), %xmm4
        por       %xmm0, %xmm8
        movdqa    %xmm12, %xmm0
        paddd     %xmm4, %xmm3
        movdqa    800(%rsp), %xmm4
        pslld     $30, %xmm0
        psrld     $2, %xmm12
        movdqa    %xmm4, %xmm9
        por       %xmm12, %xmm0
        movdqa    %xmm8, %xmm12
        paddd     %xmm4, %xmm9
        psrld     $31, %xmm4
        pxor      %xmm6, %xmm12
        por       %xmm4, %xmm9
        pxor      %xmm1, %xmm12
        paddd     %xmm9, %xmm2
        movdqa    368(%rsp), %xmm10
        paddd     %xmm12, %xmm14
        movdqa    352(%rsp), %xmm4
        movdqa    384(%rsp), %xmm12
..B9.13:
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm9
        pslld     $5, %xmm15
        psrld     $27, %xmm9
        por       %xmm9, %xmm15
        movdqa    320(%rsp), %xmm9
        paddd     %xmm15, %xmm14
        paddd     %xmm5, %xmm14
        por       %xmm10, %xmm9
        movdqa    %xmm0, %xmm10
        paddd     %xmm9, %xmm14
        pxor      %xmm11, %xmm10
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm9
        pxor      %xmm7, %xmm10
        pslld     $5, %xmm15
        psrld     $27, %xmm9
        paddd     %xmm10, %xmm13
        por       %xmm9, %xmm15
        movdqa    %xmm4, %xmm9
        paddd     %xmm15, %xmm13
        paddd     %xmm4, %xmm9
        psrld     $31, %xmm4
        movdqa    %xmm1, %xmm10
        paddd     %xmm5, %xmm13
        por       %xmm4, %xmm9
        pslld     $30, %xmm10
        psrld     $2, %xmm1
        paddd     %xmm9, %xmm13
        por       %xmm1, %xmm10
        movdqa    %xmm7, %xmm9
        movdqa    %xmm8, %xmm1
        pslld     $30, %xmm9
        psrld     $2, %xmm7
        pxor      %xmm10, %xmm1
        por       %xmm7, %xmm9
        pxor      %xmm3, %xmm1
        movdqa    %xmm14, %xmm7
        movdqa    %xmm14, %xmm4
        paddd     %xmm1, %xmm6
        pslld     $5, %xmm7
        movdqa    336(%rsp), %xmm1
        psrld     $27, %xmm4
        por       %xmm4, %xmm7
        movdqa    %xmm1, %xmm4
        paddd     %xmm7, %xmm6
        paddd     %xmm1, %xmm4
        psrld     $31, %xmm1
        paddd     %xmm5, %xmm6
        por       %xmm1, %xmm4
        movdqa    %xmm0, %xmm15
        paddd     %xmm4, %xmm6
        pxor      %xmm9, %xmm15
        movdqa    %xmm13, %xmm4
        movdqa    %xmm13, %xmm1
        pxor      %xmm2, %xmm15
        pslld     $5, %xmm4
        psrld     $27, %xmm1
        paddd     %xmm15, %xmm11
        por       %xmm1, %xmm4
        movdqa    %xmm2, %xmm1
        paddd     %xmm4, %xmm11
        movdqa    %xmm3, %xmm4
        paddd     %xmm5, %xmm11
        movdqa    %xmm12, %xmm5
        paddd     %xmm12, %xmm5
        psrld     $31, %xmm12
        por       %xmm12, %xmm5
        pslld     $30, %xmm4
        psrld     $2, %xmm3
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        paddd     %xmm5, %xmm11
        por       %xmm3, %xmm4
        por       %xmm2, %xmm1
        je        ..B9.9
..B9.4:
        movdqa    (%rdx), %xmm2
        movdqa    16(%rdx), %xmm3
        paddd     %xmm2, %xmm6
        movdqa    32(%rdx), %xmm5
        paddd     %xmm3, %xmm14
        movdqa    48(%rdx), %xmm7
        paddd     %xmm5, %xmm4
        movdqa    64(%rdx), %xmm12
        paddd     %xmm7, %xmm10
        movdqa    80(%rdx), %xmm15
        paddd     %xmm12, %xmm8
        movdqa    96(%rdx), %xmm2
        paddd     %xmm15, %xmm11
        movdqa    112(%rdx), %xmm3
        paddd     %xmm2, %xmm13
        movdqa    128(%rdx), %xmm5
        paddd     %xmm3, %xmm1
        movdqa    144(%rdx), %xmm7
        paddd     %xmm5, %xmm9
        paddd     %xmm7, %xmm0
..B9.5:
        movdqa    %xmm6, (%rsi)
        testl     %ecx, %ecx
        movdqa    %xmm14, 16(%rsi)
        movdqa    %xmm4, 32(%rsi)
        movdqa    %xmm10, 48(%rsi)
        movdqa    %xmm8, 64(%rsi)
        je        ..B9.7
..B9.6:
        movdqa    %xmm11, 256(%rsi)
        movdqa    %xmm13, 272(%rsi)
        movdqa    %xmm1, 288(%rsi)
        movdqa    %xmm9, 304(%rsi)
        movdqa    %xmm0, 320(%rsi)
        addq      $904, %rsp
..___tag_value_SSESHA1body.221:
        ret       
..___tag_value_SSESHA1body.222:
..B9.7:
        movdqa    %xmm11, 80(%rsi)
        movdqa    %xmm13, 96(%rsi)
        movdqa    %xmm1, 112(%rsi)
        movdqa    %xmm9, 128(%rsi)
        movdqa    %xmm0, 144(%rsi)
..B9.8:
        addq      $904, %rsp
..___tag_value_SSESHA1body.223:
        ret       
..___tag_value_SSESHA1body.224:
..B9.9:
        movdqa    .L_2il0floatpacket.542(%rip), %xmm2
        movdqa    .L_2il0floatpacket.543(%rip), %xmm3
        paddd     %xmm2, %xmm6
        movdqa    .L_2il0floatpacket.544(%rip), %xmm5
        paddd     %xmm3, %xmm14
        movdqa    .L_2il0floatpacket.545(%rip), %xmm7
        paddd     %xmm5, %xmm4
        movdqa    .L_2il0floatpacket.546(%rip), %xmm12
        paddd     %xmm7, %xmm10
        paddd     %xmm12, %xmm8
        paddd     %xmm2, %xmm11
        paddd     %xmm3, %xmm13
        paddd     %xmm5, %xmm1
        paddd     %xmm7, %xmm9
        paddd     %xmm12, %xmm0
        jmp       ..B9.5
..B9.10:
        movdqa    .L_2il0floatpacket.542(%rip), %xmm2
        movdqa    .L_2il0floatpacket.543(%rip), %xmm1
        movdqa    %xmm2, %xmm13
        movdqa    .L_2il0floatpacket.544(%rip), %xmm6
        movdqa    %xmm1, %xmm8
        movdqa    .L_2il0floatpacket.545(%rip), %xmm4
        movdqa    %xmm6, %xmm12
        movdqa    .L_2il0floatpacket.546(%rip), %xmm11
        movdqa    %xmm4, %xmm5
        movdqa    %xmm11, %xmm3
        jmp       ..B9.3
        .align    16,0x90
..___tag_value_SSESHA1body.225:
	.type	SSESHA1body,@function
	.size	SSESHA1body,.-SSESHA1body
	.data
# -- End  SSESHA1body
	.bss
	.align 4
	.align 4
	.globl debug
debug:
	.type	debug,@object
	.size	debug,4
	.space 4	# pad
	.section .rodata, "a"
	.space 8, 0x00 	# pad
	.align 16
.L_2il0floatpacket.61:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.61,@object
	.size	.L_2il0floatpacket.61,16
	.align 16
.L_2il0floatpacket.62:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.62,@object
	.size	.L_2il0floatpacket.62,16
	.align 16
.L_2il0floatpacket.63:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.63,@object
	.size	.L_2il0floatpacket.63,16
	.align 16
.L_2il0floatpacket.64:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.64,@object
	.size	.L_2il0floatpacket.64,16
	.align 16
.L_2il0floatpacket.65:
	.long	0xd76aa478,0xd76aa478,0xd76aa478,0xd76aa478
	.type	.L_2il0floatpacket.65,@object
	.size	.L_2il0floatpacket.65,16
	.align 16
.L_2il0floatpacket.66:
	.long	0xe8c7b756,0xe8c7b756,0xe8c7b756,0xe8c7b756
	.type	.L_2il0floatpacket.66,@object
	.size	.L_2il0floatpacket.66,16
	.align 16
.L_2il0floatpacket.67:
	.long	0x242070db,0x242070db,0x242070db,0x242070db
	.type	.L_2il0floatpacket.67,@object
	.size	.L_2il0floatpacket.67,16
	.align 16
.L_2il0floatpacket.68:
	.long	0xc1bdceee,0xc1bdceee,0xc1bdceee,0xc1bdceee
	.type	.L_2il0floatpacket.68,@object
	.size	.L_2il0floatpacket.68,16
	.align 16
.L_2il0floatpacket.69:
	.long	0xf57c0faf,0xf57c0faf,0xf57c0faf,0xf57c0faf
	.type	.L_2il0floatpacket.69,@object
	.size	.L_2il0floatpacket.69,16
	.align 16
.L_2il0floatpacket.70:
	.long	0x4787c62a,0x4787c62a,0x4787c62a,0x4787c62a
	.type	.L_2il0floatpacket.70,@object
	.size	.L_2il0floatpacket.70,16
	.align 16
.L_2il0floatpacket.71:
	.long	0xa8304613,0xa8304613,0xa8304613,0xa8304613
	.type	.L_2il0floatpacket.71,@object
	.size	.L_2il0floatpacket.71,16
	.align 16
.L_2il0floatpacket.72:
	.long	0xfd469501,0xfd469501,0xfd469501,0xfd469501
	.type	.L_2il0floatpacket.72,@object
	.size	.L_2il0floatpacket.72,16
	.align 16
.L_2il0floatpacket.73:
	.long	0x698098d8,0x698098d8,0x698098d8,0x698098d8
	.type	.L_2il0floatpacket.73,@object
	.size	.L_2il0floatpacket.73,16
	.align 16
.L_2il0floatpacket.74:
	.long	0x8b44f7af,0x8b44f7af,0x8b44f7af,0x8b44f7af
	.type	.L_2il0floatpacket.74,@object
	.size	.L_2il0floatpacket.74,16
	.align 16
.L_2il0floatpacket.75:
	.long	0xffff5bb1,0xffff5bb1,0xffff5bb1,0xffff5bb1
	.type	.L_2il0floatpacket.75,@object
	.size	.L_2il0floatpacket.75,16
	.align 16
.L_2il0floatpacket.76:
	.long	0x895cd7be,0x895cd7be,0x895cd7be,0x895cd7be
	.type	.L_2il0floatpacket.76,@object
	.size	.L_2il0floatpacket.76,16
	.align 16
.L_2il0floatpacket.77:
	.long	0x6b901122,0x6b901122,0x6b901122,0x6b901122
	.type	.L_2il0floatpacket.77,@object
	.size	.L_2il0floatpacket.77,16
	.align 16
.L_2il0floatpacket.78:
	.long	0xfd987193,0xfd987193,0xfd987193,0xfd987193
	.type	.L_2il0floatpacket.78,@object
	.size	.L_2il0floatpacket.78,16
	.align 16
.L_2il0floatpacket.79:
	.long	0xa679438e,0xa679438e,0xa679438e,0xa679438e
	.type	.L_2il0floatpacket.79,@object
	.size	.L_2il0floatpacket.79,16
	.align 16
.L_2il0floatpacket.80:
	.long	0x49b40821,0x49b40821,0x49b40821,0x49b40821
	.type	.L_2il0floatpacket.80,@object
	.size	.L_2il0floatpacket.80,16
	.align 16
.L_2il0floatpacket.81:
	.long	0xf61e2562,0xf61e2562,0xf61e2562,0xf61e2562
	.type	.L_2il0floatpacket.81,@object
	.size	.L_2il0floatpacket.81,16
	.align 16
.L_2il0floatpacket.82:
	.long	0xc040b340,0xc040b340,0xc040b340,0xc040b340
	.type	.L_2il0floatpacket.82,@object
	.size	.L_2il0floatpacket.82,16
	.align 16
.L_2il0floatpacket.83:
	.long	0x265e5a51,0x265e5a51,0x265e5a51,0x265e5a51
	.type	.L_2il0floatpacket.83,@object
	.size	.L_2il0floatpacket.83,16
	.align 16
.L_2il0floatpacket.84:
	.long	0xe9b6c7aa,0xe9b6c7aa,0xe9b6c7aa,0xe9b6c7aa
	.type	.L_2il0floatpacket.84,@object
	.size	.L_2il0floatpacket.84,16
	.align 16
.L_2il0floatpacket.85:
	.long	0xd62f105d,0xd62f105d,0xd62f105d,0xd62f105d
	.type	.L_2il0floatpacket.85,@object
	.size	.L_2il0floatpacket.85,16
	.align 16
.L_2il0floatpacket.86:
	.long	0x02441453,0x02441453,0x02441453,0x02441453
	.type	.L_2il0floatpacket.86,@object
	.size	.L_2il0floatpacket.86,16
	.align 16
.L_2il0floatpacket.87:
	.long	0xd8a1e681,0xd8a1e681,0xd8a1e681,0xd8a1e681
	.type	.L_2il0floatpacket.87,@object
	.size	.L_2il0floatpacket.87,16
	.align 16
.L_2il0floatpacket.88:
	.long	0xe7d3fbc8,0xe7d3fbc8,0xe7d3fbc8,0xe7d3fbc8
	.type	.L_2il0floatpacket.88,@object
	.size	.L_2il0floatpacket.88,16
	.align 16
.L_2il0floatpacket.89:
	.long	0x21e1cde6,0x21e1cde6,0x21e1cde6,0x21e1cde6
	.type	.L_2il0floatpacket.89,@object
	.size	.L_2il0floatpacket.89,16
	.align 16
.L_2il0floatpacket.90:
	.long	0xc33707d6,0xc33707d6,0xc33707d6,0xc33707d6
	.type	.L_2il0floatpacket.90,@object
	.size	.L_2il0floatpacket.90,16
	.align 16
.L_2il0floatpacket.91:
	.long	0xf4d50d87,0xf4d50d87,0xf4d50d87,0xf4d50d87
	.type	.L_2il0floatpacket.91,@object
	.size	.L_2il0floatpacket.91,16
	.align 16
.L_2il0floatpacket.92:
	.long	0x455a14ed,0x455a14ed,0x455a14ed,0x455a14ed
	.type	.L_2il0floatpacket.92,@object
	.size	.L_2il0floatpacket.92,16
	.align 16
.L_2il0floatpacket.93:
	.long	0xa9e3e905,0xa9e3e905,0xa9e3e905,0xa9e3e905
	.type	.L_2il0floatpacket.93,@object
	.size	.L_2il0floatpacket.93,16
	.align 16
.L_2il0floatpacket.94:
	.long	0xfcefa3f8,0xfcefa3f8,0xfcefa3f8,0xfcefa3f8
	.type	.L_2il0floatpacket.94,@object
	.size	.L_2il0floatpacket.94,16
	.align 16
.L_2il0floatpacket.95:
	.long	0x676f02d9,0x676f02d9,0x676f02d9,0x676f02d9
	.type	.L_2il0floatpacket.95,@object
	.size	.L_2il0floatpacket.95,16
	.align 16
.L_2il0floatpacket.96:
	.long	0x8d2a4c8a,0x8d2a4c8a,0x8d2a4c8a,0x8d2a4c8a
	.type	.L_2il0floatpacket.96,@object
	.size	.L_2il0floatpacket.96,16
	.align 16
.L_2il0floatpacket.97:
	.long	0xfffa3942,0xfffa3942,0xfffa3942,0xfffa3942
	.type	.L_2il0floatpacket.97,@object
	.size	.L_2il0floatpacket.97,16
	.align 16
.L_2il0floatpacket.98:
	.long	0x8771f681,0x8771f681,0x8771f681,0x8771f681
	.type	.L_2il0floatpacket.98,@object
	.size	.L_2il0floatpacket.98,16
	.align 16
.L_2il0floatpacket.99:
	.long	0x6d9d6122,0x6d9d6122,0x6d9d6122,0x6d9d6122
	.type	.L_2il0floatpacket.99,@object
	.size	.L_2il0floatpacket.99,16
	.align 16
.L_2il0floatpacket.100:
	.long	0xfde5380c,0xfde5380c,0xfde5380c,0xfde5380c
	.type	.L_2il0floatpacket.100,@object
	.size	.L_2il0floatpacket.100,16
	.align 16
.L_2il0floatpacket.101:
	.long	0xa4beea44,0xa4beea44,0xa4beea44,0xa4beea44
	.type	.L_2il0floatpacket.101,@object
	.size	.L_2il0floatpacket.101,16
	.align 16
.L_2il0floatpacket.102:
	.long	0x4bdecfa9,0x4bdecfa9,0x4bdecfa9,0x4bdecfa9
	.type	.L_2il0floatpacket.102,@object
	.size	.L_2il0floatpacket.102,16
	.align 16
.L_2il0floatpacket.103:
	.long	0xf6bb4b60,0xf6bb4b60,0xf6bb4b60,0xf6bb4b60
	.type	.L_2il0floatpacket.103,@object
	.size	.L_2il0floatpacket.103,16
	.align 16
.L_2il0floatpacket.104:
	.long	0xbebfbc70,0xbebfbc70,0xbebfbc70,0xbebfbc70
	.type	.L_2il0floatpacket.104,@object
	.size	.L_2il0floatpacket.104,16
	.align 16
.L_2il0floatpacket.105:
	.long	0x289b7ec6,0x289b7ec6,0x289b7ec6,0x289b7ec6
	.type	.L_2il0floatpacket.105,@object
	.size	.L_2il0floatpacket.105,16
	.align 16
.L_2il0floatpacket.106:
	.long	0xeaa127fa,0xeaa127fa,0xeaa127fa,0xeaa127fa
	.type	.L_2il0floatpacket.106,@object
	.size	.L_2il0floatpacket.106,16
	.align 16
.L_2il0floatpacket.107:
	.long	0xd4ef3085,0xd4ef3085,0xd4ef3085,0xd4ef3085
	.type	.L_2il0floatpacket.107,@object
	.size	.L_2il0floatpacket.107,16
	.align 16
.L_2il0floatpacket.108:
	.long	0x04881d05,0x04881d05,0x04881d05,0x04881d05
	.type	.L_2il0floatpacket.108,@object
	.size	.L_2il0floatpacket.108,16
	.align 16
.L_2il0floatpacket.109:
	.long	0xd9d4d039,0xd9d4d039,0xd9d4d039,0xd9d4d039
	.type	.L_2il0floatpacket.109,@object
	.size	.L_2il0floatpacket.109,16
	.align 16
.L_2il0floatpacket.110:
	.long	0xe6db99e5,0xe6db99e5,0xe6db99e5,0xe6db99e5
	.type	.L_2il0floatpacket.110,@object
	.size	.L_2il0floatpacket.110,16
	.align 16
.L_2il0floatpacket.111:
	.long	0x1fa27cf8,0x1fa27cf8,0x1fa27cf8,0x1fa27cf8
	.type	.L_2il0floatpacket.111,@object
	.size	.L_2il0floatpacket.111,16
	.align 16
.L_2il0floatpacket.112:
	.long	0xc4ac5665,0xc4ac5665,0xc4ac5665,0xc4ac5665
	.type	.L_2il0floatpacket.112,@object
	.size	.L_2il0floatpacket.112,16
	.align 16
.L_2il0floatpacket.113:
	.long	0xf4292244,0xf4292244,0xf4292244,0xf4292244
	.type	.L_2il0floatpacket.113,@object
	.size	.L_2il0floatpacket.113,16
	.align 16
.L_2il0floatpacket.114:
	.long	0x432aff97,0x432aff97,0x432aff97,0x432aff97
	.type	.L_2il0floatpacket.114,@object
	.size	.L_2il0floatpacket.114,16
	.align 16
.L_2il0floatpacket.115:
	.long	0xab9423a7,0xab9423a7,0xab9423a7,0xab9423a7
	.type	.L_2il0floatpacket.115,@object
	.size	.L_2il0floatpacket.115,16
	.align 16
.L_2il0floatpacket.116:
	.long	0xfc93a039,0xfc93a039,0xfc93a039,0xfc93a039
	.type	.L_2il0floatpacket.116,@object
	.size	.L_2il0floatpacket.116,16
	.align 16
.L_2il0floatpacket.117:
	.long	0x655b59c3,0x655b59c3,0x655b59c3,0x655b59c3
	.type	.L_2il0floatpacket.117,@object
	.size	.L_2il0floatpacket.117,16
	.align 16
.L_2il0floatpacket.118:
	.long	0x8f0ccc92,0x8f0ccc92,0x8f0ccc92,0x8f0ccc92
	.type	.L_2il0floatpacket.118,@object
	.size	.L_2il0floatpacket.118,16
	.align 16
.L_2il0floatpacket.119:
	.long	0xffeff47d,0xffeff47d,0xffeff47d,0xffeff47d
	.type	.L_2il0floatpacket.119,@object
	.size	.L_2il0floatpacket.119,16
	.align 16
.L_2il0floatpacket.120:
	.long	0x85845dd1,0x85845dd1,0x85845dd1,0x85845dd1
	.type	.L_2il0floatpacket.120,@object
	.size	.L_2il0floatpacket.120,16
	.align 16
.L_2il0floatpacket.121:
	.long	0x6fa87e4f,0x6fa87e4f,0x6fa87e4f,0x6fa87e4f
	.type	.L_2il0floatpacket.121,@object
	.size	.L_2il0floatpacket.121,16
	.align 16
.L_2il0floatpacket.122:
	.long	0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0
	.type	.L_2il0floatpacket.122,@object
	.size	.L_2il0floatpacket.122,16
	.align 16
.L_2il0floatpacket.123:
	.long	0xa3014314,0xa3014314,0xa3014314,0xa3014314
	.type	.L_2il0floatpacket.123,@object
	.size	.L_2il0floatpacket.123,16
	.align 16
.L_2il0floatpacket.124:
	.long	0x4e0811a1,0x4e0811a1,0x4e0811a1,0x4e0811a1
	.type	.L_2il0floatpacket.124,@object
	.size	.L_2il0floatpacket.124,16
	.align 16
.L_2il0floatpacket.125:
	.long	0xf7537e82,0xf7537e82,0xf7537e82,0xf7537e82
	.type	.L_2il0floatpacket.125,@object
	.size	.L_2il0floatpacket.125,16
	.align 16
.L_2il0floatpacket.126:
	.long	0xbd3af235,0xbd3af235,0xbd3af235,0xbd3af235
	.type	.L_2il0floatpacket.126,@object
	.size	.L_2il0floatpacket.126,16
	.align 16
.L_2il0floatpacket.127:
	.long	0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb
	.type	.L_2il0floatpacket.127,@object
	.size	.L_2il0floatpacket.127,16
	.align 16
.L_2il0floatpacket.128:
	.long	0xeb86d391,0xeb86d391,0xeb86d391,0xeb86d391
	.type	.L_2il0floatpacket.128,@object
	.size	.L_2il0floatpacket.128,16
	.align 16
.L_2il0floatpacket.129:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.129,@object
	.size	.L_2il0floatpacket.129,16
	.align 16
.L_2il0floatpacket.454:
	.long	0x00000003,0x00000003,0x00000003,0x00000003
	.type	.L_2il0floatpacket.454,@object
	.size	.L_2il0floatpacket.454,16
	.align 16
.L_2il0floatpacket.455:
	.long	0x00000000,0x00000001,0x00000002,0x00000003
	.type	.L_2il0floatpacket.455,@object
	.size	.L_2il0floatpacket.455,16
	.align 16
.L_2il0floatpacket.456:
	.long	0x00000004,0x00000005,0x00000006,0x00000007
	.type	.L_2il0floatpacket.456,@object
	.size	.L_2il0floatpacket.456,16
	.align 16
.L_2il0floatpacket.457:
	.long	0x00000008,0x00000009,0x0000000a,0x0000000b
	.type	.L_2il0floatpacket.457,@object
	.size	.L_2il0floatpacket.457,16
	.align 16
.L_2il0floatpacket.458:
	.long	0x0000000c,0x0000000d,0x0000000e,0x0000000f
	.type	.L_2il0floatpacket.458,@object
	.size	.L_2il0floatpacket.458,16
	.align 16
.L_2il0floatpacket.459:
	.long	0x00000010,0x00000011,0x00000012,0x00000013
	.type	.L_2il0floatpacket.459,@object
	.size	.L_2il0floatpacket.459,16
	.align 16
.L_2il0floatpacket.460:
	.long	0x00000014,0x00000015,0x00000016,0x00000017
	.type	.L_2il0floatpacket.460,@object
	.size	.L_2il0floatpacket.460,16
	.align 16
.L_2il0floatpacket.461:
	.long	0x00000018,0x00000019,0x0000001a,0x0000001b
	.type	.L_2il0floatpacket.461,@object
	.size	.L_2il0floatpacket.461,16
	.align 16
.L_2il0floatpacket.462:
	.long	0x0000001c,0x0000001d,0x0000001e,0x0000001f
	.type	.L_2il0floatpacket.462,@object
	.size	.L_2il0floatpacket.462,16
	.align 16
.L_2il0floatpacket.484:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.484,@object
	.size	.L_2il0floatpacket.484,16
	.align 16
.L_2il0floatpacket.485:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.485,@object
	.size	.L_2il0floatpacket.485,16
	.align 16
.L_2il0floatpacket.486:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.486,@object
	.size	.L_2il0floatpacket.486,16
	.align 16
.L_2il0floatpacket.487:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.487,@object
	.size	.L_2il0floatpacket.487,16
	.align 16
.L_2il0floatpacket.488:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.488,@object
	.size	.L_2il0floatpacket.488,16
	.align 16
.L_2il0floatpacket.489:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.489,@object
	.size	.L_2il0floatpacket.489,16
	.align 16
.L_2il0floatpacket.542:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.542,@object
	.size	.L_2il0floatpacket.542,16
	.align 16
.L_2il0floatpacket.543:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.543,@object
	.size	.L_2il0floatpacket.543,16
	.align 16
.L_2il0floatpacket.544:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.544,@object
	.size	.L_2il0floatpacket.544,16
	.align 16
.L_2il0floatpacket.545:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.545,@object
	.size	.L_2il0floatpacket.545,16
	.align 16
.L_2il0floatpacket.546:
	.long	0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0
	.type	.L_2il0floatpacket.546,@object
	.size	.L_2il0floatpacket.546,16
	.align 16
.L_2il0floatpacket.547:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.547,@object
	.size	.L_2il0floatpacket.547,16
	.align 16
.L_2il0floatpacket.548:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.548,@object
	.size	.L_2il0floatpacket.548,16
	.align 16
.L_2il0floatpacket.549:
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
	.type	.L_2il0floatpacket.549,@object
	.size	.L_2il0floatpacket.549,16
	.align 16
.L_2il0floatpacket.550:
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
	.type	.L_2il0floatpacket.550,@object
	.size	.L_2il0floatpacket.550,16
	.align 4
.L_2__STRING.3:
	.byte	0
	.byte	0
	.type	.L_2__STRING.3,@object
	.size	.L_2__STRING.3,2
	.section .rodata.str1.4, "aMS",@progbits,1
	.align 4
	.align 4
.L_2__STRING.2:
	.byte	36
	.byte	97
	.byte	112
	.byte	114
	.byte	49
	.byte	36
	.byte	0
	.type	.L_2__STRING.2,@object
	.size	.L_2__STRING.2,7
	.space 1, 0x00 	# pad
	.align 4
.L_2__STRING.1:
	.byte	36
	.byte	49
	.byte	36
	.byte	0
	.type	.L_2__STRING.1,@object
	.size	.L_2__STRING.1,4
	.data
	.section .note.GNU-stack, ""
// -- Begin DWARF2 SEGMENT .eh_frame
	.section .eh_frame,"a",@progbits
.eh_frame_seg:
	.align 8
	.4byte 0x00000014
	.8byte 0x7801000100000000
	.8byte 0x0000019008070c10
	.4byte 0x00000000
	.4byte 0x00000014
	.4byte 0x0000001c
	.8byte ..___tag_value_sse_debug.1
	.8byte ..___tag_value_sse_debug.3-..___tag_value_sse_debug.1
	.4byte 0x00000034
	.4byte 0x00000034
	.8byte ..___tag_value_mmxput.4
	.8byte ..___tag_value_mmxput.12-..___tag_value_mmxput.4
	.byte 0x04
	.4byte ..___tag_value_mmxput.6-..___tag_value_mmxput.4
	.4byte 0x02860383
	.2byte 0x048f
	.byte 0x04
	.4byte ..___tag_value_mmxput.9-..___tag_value_mmxput.6
	.2byte 0x04cf
	.4byte ..___tag_value_mmxput.10-..___tag_value_mmxput.9
	.2byte 0x04c3
	.4byte ..___tag_value_mmxput.11-..___tag_value_mmxput.10
	.4byte 0x000000c6
	.4byte 0x00000074
	.4byte 0x0000006c
	.8byte ..___tag_value_mmxput2.13
	.8byte ..___tag_value_mmxput2.37-..___tag_value_mmxput2.13
	.byte 0x04
	.4byte ..___tag_value_mmxput2.15-..___tag_value_mmxput2.13
	.4byte 0x028c100e
	.byte 0x04
	.4byte ..___tag_value_mmxput2.17-..___tag_value_mmxput2.15
	.4byte 0x038d180e
	.byte 0x04
	.4byte ..___tag_value_mmxput2.19-..___tag_value_mmxput2.17
	.4byte 0x048e200e
	.byte 0x04
	.4byte ..___tag_value_mmxput2.21-..___tag_value_mmxput2.19
	.4byte 0x058f280e
	.byte 0x04
	.4byte ..___tag_value_mmxput2.23-..___tag_value_mmxput2.21
	.4byte 0x0683300e
	.byte 0x04
	.4byte ..___tag_value_mmxput2.27-..___tag_value_mmxput2.23
	.2byte 0x04c3
	.4byte ..___tag_value_mmxput2.28-..___tag_value_mmxput2.27
	.4byte 0x04cf280e
	.4byte ..___tag_value_mmxput2.30-..___tag_value_mmxput2.28
	.4byte 0x04ce200e
	.4byte ..___tag_value_mmxput2.32-..___tag_value_mmxput2.30
	.4byte 0x04cd180e
	.4byte ..___tag_value_mmxput2.34-..___tag_value_mmxput2.32
	.4byte 0x04cc100e
	.4byte ..___tag_value_mmxput2.36-..___tag_value_mmxput2.34
	.8byte 0x000000000000080e
	.4byte 0x0000008c
	.4byte 0x000000e4
	.8byte ..___tag_value_dispatch.38
	.8byte ..___tag_value_dispatch.84-..___tag_value_dispatch.38
	.byte 0x04
	.4byte ..___tag_value_dispatch.40-..___tag_value_dispatch.38
	.4byte 0x028c100e
	.byte 0x04
	.4byte ..___tag_value_dispatch.42-..___tag_value_dispatch.40
	.4byte 0x038d180e
	.byte 0x04
	.4byte ..___tag_value_dispatch.44-..___tag_value_dispatch.42
	.4byte 0x048e200e
	.byte 0x04
	.4byte ..___tag_value_dispatch.46-..___tag_value_dispatch.44
	.4byte 0x058f280e
	.byte 0x04
	.4byte ..___tag_value_dispatch.48-..___tag_value_dispatch.46
	.4byte 0x0683300e
	.byte 0x04
	.4byte ..___tag_value_dispatch.50-..___tag_value_dispatch.48
	.4byte 0x0786380e
	.byte 0x04
	.4byte ..___tag_value_dispatch.52-..___tag_value_dispatch.50
	.2byte 0x600e
	.byte 0x04
	.4byte ..___tag_value_dispatch.71-..___tag_value_dispatch.52
	.4byte 0x04c6380e
	.4byte ..___tag_value_dispatch.73-..___tag_value_dispatch.71
	.4byte 0x04c3300e
	.4byte ..___tag_value_dispatch.75-..___tag_value_dispatch.73
	.4byte 0x04cf280e
	.4byte ..___tag_value_dispatch.77-..___tag_value_dispatch.75
	.4byte 0x04ce200e
	.4byte ..___tag_value_dispatch.79-..___tag_value_dispatch.77
	.4byte 0x04cd180e
	.4byte ..___tag_value_dispatch.81-..___tag_value_dispatch.79
	.4byte 0x04cc100e
	.4byte ..___tag_value_dispatch.83-..___tag_value_dispatch.81
	.4byte 0x0000080e
	.2byte 0x0000
	.4byte 0x00000084
	.4byte 0x00000174
	.8byte ..___tag_value_mmxput3.85
	.8byte ..___tag_value_mmxput3.111-..___tag_value_mmxput3.85
	.byte 0x04
	.4byte ..___tag_value_mmxput3.87-..___tag_value_mmxput3.85
	.4byte 0x028c100e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.89-..___tag_value_mmxput3.87
	.4byte 0x038d180e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.91-..___tag_value_mmxput3.89
	.4byte 0x048e200e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.93-..___tag_value_mmxput3.91
	.4byte 0x058f280e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.95-..___tag_value_mmxput3.93
	.4byte 0x0683300e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.97-..___tag_value_mmxput3.95
	.4byte 0x0786380e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.99-..___tag_value_mmxput3.97
	.2byte 0x04c6
	.4byte ..___tag_value_mmxput3.100-..___tag_value_mmxput3.99
	.4byte 0x04c3300e
	.4byte ..___tag_value_mmxput3.102-..___tag_value_mmxput3.100
	.4byte 0x04cf280e
	.4byte ..___tag_value_mmxput3.104-..___tag_value_mmxput3.102
	.4byte 0x04ce200e
	.4byte ..___tag_value_mmxput3.106-..___tag_value_mmxput3.104
	.4byte 0x04cd180e
	.4byte ..___tag_value_mmxput3.108-..___tag_value_mmxput3.106
	.4byte 0x04cc100e
	.4byte ..___tag_value_mmxput3.110-..___tag_value_mmxput3.108
	.4byte 0x0000080e
	.2byte 0x0000
	.byte 0x00
	.4byte 0x00000034
	.4byte 0x000001fc
	.8byte ..___tag_value_SSEmd5body.112
	.8byte ..___tag_value_SSEmd5body.118-..___tag_value_SSEmd5body.112
	.byte 0x04
	.4byte ..___tag_value_SSEmd5body.114-..___tag_value_SSEmd5body.112
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd5body.115-..___tag_value_SSEmd5body.114
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSEmd5body.116-..___tag_value_SSEmd5body.115
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd5body.117-..___tag_value_SSEmd5body.116
	.4byte 0x0000080e
	.4byte 0x000000a4
	.4byte 0x00000234
	.8byte ..___tag_value_md5cryptsse.119
	.8byte ..___tag_value_md5cryptsse.210-..___tag_value_md5cryptsse.119
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.121-..___tag_value_md5cryptsse.119
	.4byte 0x028c100e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.123-..___tag_value_md5cryptsse.121
	.4byte 0x038d180e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.125-..___tag_value_md5cryptsse.123
	.4byte 0x048e200e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.127-..___tag_value_md5cryptsse.125
	.4byte 0x058f280e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.129-..___tag_value_md5cryptsse.127
	.4byte 0x0683300e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.131-..___tag_value_md5cryptsse.129
	.4byte 0x0786380e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.133-..___tag_value_md5cryptsse.131
	.4byte 0x0436a00e
	.4byte ..___tag_value_md5cryptsse.190-..___tag_value_md5cryptsse.133
	.4byte 0x04c6380e
	.4byte ..___tag_value_md5cryptsse.192-..___tag_value_md5cryptsse.190
	.4byte 0x04c3300e
	.4byte ..___tag_value_md5cryptsse.194-..___tag_value_md5cryptsse.192
	.4byte 0x04cf280e
	.4byte ..___tag_value_md5cryptsse.196-..___tag_value_md5cryptsse.194
	.4byte 0x04ce200e
	.4byte ..___tag_value_md5cryptsse.198-..___tag_value_md5cryptsse.196
	.4byte 0x04cd180e
	.4byte ..___tag_value_md5cryptsse.200-..___tag_value_md5cryptsse.198
	.4byte 0x04cc100e
	.4byte ..___tag_value_md5cryptsse.202-..___tag_value_md5cryptsse.200
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.203-..___tag_value_md5cryptsse.202
	.8byte 0x8c0786068336a00e
	.8byte 0x00058f048e038d02
	.4byte 0x00000000
	.2byte 0x0000
	.4byte 0x00000034
	.4byte 0x000002dc
	.8byte ..___tag_value_SSEmd4body.211
	.8byte ..___tag_value_SSEmd4body.217-..___tag_value_SSEmd4body.211
	.byte 0x04
	.4byte ..___tag_value_SSEmd4body.213-..___tag_value_SSEmd4body.211
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd4body.214-..___tag_value_SSEmd4body.213
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSEmd4body.215-..___tag_value_SSEmd4body.214
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd4body.216-..___tag_value_SSEmd4body.215
	.4byte 0x0000080e
	.4byte 0x0000003c
	.4byte 0x00000314
	.8byte ..___tag_value_SSESHA1body.218
	.8byte ..___tag_value_SSESHA1body.225-..___tag_value_SSESHA1body.218
	.byte 0x04
	.4byte ..___tag_value_SSESHA1body.220-..___tag_value_SSESHA1body.218
	.4byte 0x0407900e
	.4byte ..___tag_value_SSESHA1body.221-..___tag_value_SSESHA1body.220
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSESHA1body.222-..___tag_value_SSESHA1body.221
	.4byte 0x0407900e
	.4byte ..___tag_value_SSESHA1body.223-..___tag_value_SSESHA1body.222
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSESHA1body.224-..___tag_value_SSESHA1body.223
	.4byte 0x0007900e
	.byte 0x00
# End
