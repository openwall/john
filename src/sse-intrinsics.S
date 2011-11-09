# -- Machine type EFI2
# mark_description "Intel(R) C Intel(R) 64 Compiler XE for applications running on Intel(R) 64, Version 12.0.3.174 Build 2011030";
# mark_description "9";
# mark_description "-S -o sse-intrinsics.S -O3 -fno-builtin -DUSING_ICC_S_FILE -funroll-loops -c -Wall";
	.file "sse-intrinsics.c"
	.text
..TXTST0:
# -- Begin  sse_debug
# mark_begin;
       .align    16,0x90
	.globl sse_debug
sse_debug:
..B1.1:                         # Preds ..B1.0
..___tag_value_sse_debug.1:                                     #52.1
        movl      $1, debug(%rip)                               #53.2
        ret                                                     #54.1
        .align    16,0x90
..___tag_value_sse_debug.3:                                     #
                                # LOE
# mark_end;
	.type	sse_debug,@function
	.size	sse_debug,.-sse_debug
	.data
# -- End  sse_debug
	.text
# -- Begin  mmxput
# mark_begin;
       .align    16,0x90
	.globl mmxput
mmxput:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %edx
# parameter 4: %ecx
# parameter 5: %r8
# parameter 6: %r9d
..B2.1:                         # Preds ..B2.0
..___tag_value_mmxput.4:                                        #176.1
        movl      %esi, %eax                                    #180.41
        shrl      $2, %eax                                      #180.41
        shll      $8, %eax                                      #180.47
        lea       (%rdx,%rdx,2), %r10d                          #180.65
        shll      $8, %r10d                                     #180.65
        addq      %rax, %rdi                                    #180.26
        addq      %r10, %rdi                                    #180.26
        testl     %r9d, %r9d                                    #181.12
        jbe       ..B2.8        # Prob 50%                      #181.12
                                # LOE rbx rbp rdi r8 r12 r13 r14 r15 ecx esi r9d
..B2.2:                         # Preds ..B2.1
        movl      %r9d, %r10d                                   #181.2
        movl      $1, %eax                                      #181.2
        shrl      $1, %r10d                                     #181.2
        xorl      %edx, %edx                                    #181.2
        testl     %r10d, %r10d                                  #181.2
        jbe       ..B2.6        # Prob 10%                      #181.2
                                # LOE rbx rbp rdi r8 r12 r13 r14 r15 eax edx ecx esi r9d r10d
..B2.3:                         # Preds ..B2.2
        movl      %esi, %eax                                    #182.9
        andl      $3, %eax                                      #182.9
        shll      $2, %eax                                      #182.9
        movq      %r15, -24(%rsp)                               #182.9
..___tag_value_mmxput.6:                                        #
        movq      %rbx, -16(%rsp)                               #182.9
..___tag_value_mmxput.8:                                        #
        movq      %rbp, -8(%rsp)                                #182.9
..___tag_value_mmxput.10:                                       #
                                # LOE rdi r8 r12 r13 r14 eax edx ecx esi r9d r10d
..B2.4:                         # Preds ..B2.4 ..B2.3
        lea       (%rcx,%rdx,2), %ebp                           #182.9
        movl      %ebp, %r15d                                   #182.9
        movl      %ebp, %r11d                                   #182.9
        andl      $-4, %r15d                                    #182.9
        lea       (%rdx,%rdx), %ebx                             #182.3
        shll      $2, %r15d                                     #182.9
        andl      $3, %r11d                                     #182.9
        addl      %eax, %r15d                                   #182.9
        incl      %ebp                                          #182.3
        addl      %r11d, %r15d                                  #182.9
        lea       1(%rdx,%rdx), %r11d                           #182.3
        incl      %edx                                          #181.2
        movzbl    (%rbx,%r8), %ebx                              #182.39
        movb      %bl, (%r15,%rdi)                              #182.3
        movl      %ebp, %ebx                                    #182.9
        andl      $-4, %ebx                                     #182.9
        andl      $3, %ebp                                      #182.9
        shll      $2, %ebx                                      #182.9
        addl      %eax, %ebx                                    #182.9
        addl      %ebp, %ebx                                    #182.9
        cmpl      %r10d, %edx                                   #181.2
        movzbl    (%r11,%r8), %ebp                              #182.39
        movb      %bpl, (%rbx,%rdi)                             #182.3
        jb        ..B2.4        # Prob 63%                      #181.2
                                # LOE rdi r8 r12 r13 r14 eax edx ecx esi r9d r10d
..B2.5:                         # Preds ..B2.4
        movq      -24(%rsp), %r15                               #
..___tag_value_mmxput.15:                                       #
        lea       1(%rdx,%rdx), %eax                            #181.2
        movq      -16(%rsp), %rbx                               #
..___tag_value_mmxput.16:                                       #
        movq      -8(%rsp), %rbp                                #
..___tag_value_mmxput.17:                                       #
                                # LOE rbx rbp rdi r8 r12 r13 r14 r15 eax ecx esi r9d
..B2.6:                         # Preds ..B2.5 ..B2.2
        lea       -1(%rax), %edx                                #181.2
        cmpl      %edx, %r9d                                    #181.2
        jbe       ..B2.8        # Prob 10%                      #181.2
                                # LOE rdx rbx rbp rdi r8 r12 r13 r14 r15 eax ecx esi
..B2.7:                         # Preds ..B2.6
        andl      $3, %esi                                      #182.9
        lea       -1(%rax,%rcx), %ecx                           #182.3
        movl      %ecx, %eax                                    #182.9
        andl      $3, %ecx                                      #182.9
        andl      $-4, %eax                                     #182.9
        addl      %eax, %esi                                    #182.9
        shll      $2, %esi                                      #182.9
        addl      %ecx, %esi                                    #182.9
        movzbl    (%rdx,%r8), %r8d                              #182.39
        movb      %r8b, (%rsi,%rdi)                             #182.3
                                # LOE rbx rbp r12 r13 r14 r15
..B2.8:                         # Preds ..B2.6 ..B2.1 ..B2.7
        ret                                                     #184.1
        .align    16,0x90
..___tag_value_mmxput.18:                                       #
                                # LOE
# mark_end;
	.type	mmxput,@function
	.size	mmxput,.-mmxput
	.data
# -- End  mmxput
	.text
# -- Begin  mmxput2
# mark_begin;
       .align    16,0x90
	.globl mmxput2
mmxput2:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %rdx
..B3.1:                         # Preds ..B3.0
..___tag_value_mmxput2.19:                                      #187.1
        pushq     %r12                                          #187.1
..___tag_value_mmxput2.21:                                      #
        pushq     %r13                                          #187.1
..___tag_value_mmxput2.23:                                      #
        pushq     %r14                                          #187.1
..___tag_value_mmxput2.25:                                      #
        pushq     %r15                                          #187.1
..___tag_value_mmxput2.27:                                      #
        pushq     %rbx                                          #187.1
..___tag_value_mmxput2.29:                                      #
        movq      %rdx, %r13                                    #
        lea       (%rsi,%rsi,2), %eax                           #191.40
        xorl      %esi, %esi                                    #192.2
        shll      $8, %eax                                      #191.40
        movl      %esi, %r14d                                   #
        addq      %rax, %rdi                                    #191.26
        movl      %esi, %ebx                                    #
        movl      %esi, %r12d                                   #
        movq      %rdi, %r15                                    #
                                # LOE rbp r13 r15 ebx r12d r14d
..B3.2:                         # Preds ..B3.3 ..B3.1
        movl      %ebx, %edi                                    #193.11
        movl      $64, %edx                                     #193.3
        movl      %r14d, %esi                                   #193.48
        addq      %r15, %rdi                                    #193.11
        addq      %r13, %rsi                                    #193.48
        call      memcpy                                        #193.3
                                # LOE rbp r13 r15 ebx r12d r14d
..B3.3:                         # Preds ..B3.2
        incl      %r12d                                         #192.2
        addl      $64, %r14d                                    #192.2
        addl      $256, %ebx                                    #192.2
        cmpl      $3, %r12d                                     #192.2
        jb        ..B3.2        # Prob 66%                      #192.2
                                # LOE rbp r13 r15 ebx r12d r14d
..B3.4:                         # Preds ..B3.3
..___tag_value_mmxput2.31:                                      #194.1
        popq      %rbx                                          #194.1
..___tag_value_mmxput2.32:                                      #
        popq      %r15                                          #194.1
..___tag_value_mmxput2.34:                                      #
        popq      %r14                                          #194.1
..___tag_value_mmxput2.36:                                      #
        popq      %r13                                          #194.1
..___tag_value_mmxput2.38:                                      #
        popq      %r12                                          #194.1
..___tag_value_mmxput2.40:                                      #
        ret                                                     #194.1
        .align    16,0x90
..___tag_value_mmxput2.41:                                      #
                                # LOE
# mark_end;
	.type	mmxput2,@function
	.size	mmxput2,.-mmxput2
	.data
# -- End  mmxput2
	.text
# -- Begin  dispatch
# mark_begin;
       .align    16,0x90
	.globl dispatch
dispatch:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B4.1:                         # Preds ..B4.0
..___tag_value_dispatch.42:                                     #235.1
        pushq     %r12                                          #235.1
..___tag_value_dispatch.44:                                     #
        pushq     %r13                                          #235.1
..___tag_value_dispatch.46:                                     #
        pushq     %r14                                          #235.1
..___tag_value_dispatch.48:                                     #
        pushq     %r15                                          #235.1
..___tag_value_dispatch.50:                                     #
        pushq     %rbx                                          #235.1
..___tag_value_dispatch.52:                                     #
        pushq     %rbp                                          #235.1
..___tag_value_dispatch.54:                                     #
        subq      $24, %rsp                                     #235.1
..___tag_value_dispatch.56:                                     #
        xorl      %eax, %eax                                    #239.6
        movq      %rdx, %r15                                    #239.6
        movl      %eax, %r13d                                   #239.6
        movl      %ecx, %r14d                                   #239.6
        movq      %rsi, %r12                                    #239.6
        movq      %rdi, %rbx                                    #239.6
                                # LOE rbx r12 r15 r13d r14d
..B4.2:                         # Preds ..B4.56 ..B4.1
        movl      %r13d, %ebp                                   #241.12
        movl      $818089009, %eax                              #241.12
        shrl      $1, %ebp                                      #241.12
        mull      %ebp                                          #241.12
        shrl      $2, %edx                                      #241.12
        imull     $42, %edx, %ebp                               #241.12
        negl      %ebp                                          #241.12
        addl      %r13d, %ebp                                   #241.12
        cmpl      $40, %ebp                                     #241.3
        ja        ..B4.54       # Prob 50%                      #241.3
                                # LOE rbx rbp r12 r15 r13d r14d
..B4.3:                         # Preds ..B4.2
        movq      ..1..TPKT.6_0.0.6(,%rbp,8), %r8               #241.3
        jmp       *%r8                                          #241.3
                                # LOE rbx r12 r15 r13d r14d
..1.6_0.TAG.015.0.6:
..B4.19:                        # Preds ..B4.3
        movl      $1, %esi                                      #249.5
        movq      %rbx, %rdi                                    #249.5
        movq      %r15, %rdx                                    #249.5
        movl      %esi, %ecx                                    #249.5
        xorl      %r8d, %r8d                                    #249.5
        movq      %r12, %r9                                     #249.5
        movl      $1, %ebp                                      #248.5
        call      mmxput3                                       #249.5
        jmp       ..B4.55       # Prob 100%                     #249.5
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.01c.0.6:
..1.6_0.TAG.0e.0.6:
..B4.25:                        # Preds ..B4.3 ..B4.3
        xorl      %ecx, %ecx                                    #277.5
        movl      $5, %ebp                                      #276.5
        movl      %r13d, (%rsp)                                 #
        movl      %ecx, %r13d                                   #
        movq      %r15, 8(%rsp)                                 #
        movl      %ecx, %r15d                                   #
        movl      %r14d, 16(%rsp)                               #
        movl      %ecx, %r14d                                   #
                                # LOE rbx rbp r12 r13 r14d r15d
..B4.26:                        # Preds ..B4.27 ..B4.25
        movl      $64, %edx                                     #277.5
        movl      %r14d, %esi                                   #277.5
        addq      %r12, %rsi                                    #277.5
        lea       3840(%rbx,%r13), %rdi                         #277.5
        call      memcpy                                        #277.5
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.27:                        # Preds ..B4.26
        incl      %r15d                                         #277.5
        addl      $64, %r14d                                    #277.5
        addl      $256, %r13d                                   #277.5
        cmpl      $3, %r15d                                     #277.5
        jb        ..B4.26       # Prob 66%                      #277.5
                                # LOE rbx rbp r12 r13 r14d r15d
..B4.28:                        # Preds ..B4.27
        movl      (%rsp), %r13d                                 #
        movq      8(%rsp), %r15                                 #
        movl      16(%rsp), %r14d                               #
        jmp       ..B4.55       # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.023.0.6:
..1.6_0.TAG.07.0.6:
..B4.34:                        # Preds ..B4.3 ..B4.3
        movq      %rbx, %rdi                                    #272.5
        movl      $4, %esi                                      #272.5
        movq      %r15, %rdx                                    #272.5
        movl      $1, %ecx                                      #272.5
        movl      %r14d, %r8d                                   #272.5
        movq      %r12, %r9                                     #272.5
        movl      $4, %ebp                                      #271.5
        call      mmxput3                                       #272.5
        jmp       ..B4.55       # Prob 100%                     #272.5
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.024.0.6:
..1.6_0.TAG.01e.0.6:
..1.6_0.TAG.018.0.6:
..1.6_0.TAG.012.0.6:
..1.6_0.TAG.0c.0.6:
..1.6_0.TAG.06.0.6:
..B4.36:                        # Preds ..B4.3 ..B4.3 ..B4.3 ..B4.3 ..B4.3
                                #       ..B4.3
        xorl      %ecx, %ecx                                    #267.5
        movl      $3, %ebp                                      #266.5
        movl      %r13d, (%rsp)                                 #
        movl      %ecx, %r13d                                   #
        movq      %r15, 8(%rsp)                                 #
        movl      %ecx, %r15d                                   #
        movl      %r14d, 16(%rsp)                               #
        movl      %ecx, %r14d                                   #
                                # LOE rbx rbp r12 r13 r14d r15d
..B4.37:                        # Preds ..B4.38 ..B4.36
        movl      $64, %edx                                     #267.5
        movl      %r14d, %esi                                   #267.5
        addq      %r12, %rsi                                    #267.5
        lea       2304(%rbx,%r13), %rdi                         #267.5
        call      memcpy                                        #267.5
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.38:                        # Preds ..B4.37
        incl      %r15d                                         #267.5
        addl      $64, %r14d                                    #267.5
        addl      $256, %r13d                                   #267.5
        cmpl      $3, %r15d                                     #267.5
        jb        ..B4.37       # Prob 66%                      #267.5
                                # LOE rbx rbp r12 r13 r14d r15d
..B4.39:                        # Preds ..B4.38
        movl      (%rsp), %r13d                                 #
        movq      8(%rsp), %r15                                 #
        movl      16(%rsp), %r14d                               #
        jmp       ..B4.55       # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.027.0.6:
..1.6_0.TAG.021.0.6:
..1.6_0.TAG.01b.0.6:
..1.6_0.TAG.0f.0.6:
..1.6_0.TAG.09.0.6:
..1.6_0.TAG.03.0.6:
..B4.42:                        # Preds ..B4.3 ..B4.3 ..B4.3 ..B4.3 ..B4.3
                                #       ..B4.3
        movl      $2, %esi                                      #258.5
        movq      %rbx, %rdi                                    #258.5
        movq      %r15, %rdx                                    #258.5
        movl      %esi, %ecx                                    #258.5
        xorl      %r8d, %r8d                                    #258.5
        movq      %r12, %r9                                     #258.5
        movl      $2, %ebp                                      #257.5
        call      mmxput3                                       #258.5
        jmp       ..B4.55       # Prob 100%                     #258.5
                                # LOE rbx rbp r12 r15 r13d r14d
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
..B4.44:                        # Preds ..B4.3 ..B4.3 ..B4.3 ..B4.3 ..B4.3
                                #       ..B4.3 ..B4.3 ..B4.3 ..B4.3 ..B4.3
                                #       ..B4.3 ..B4.3
        xorl      %ecx, %ecx                                    #292.5
        movl      $6, %ebp                                      #291.5
        movl      %r13d, (%rsp)                                 #
        movl      %ecx, %r13d                                   #
        movq      %r15, 8(%rsp)                                 #
        movl      %ecx, %r15d                                   #
        movl      %r14d, 16(%rsp)                               #
        movl      %ecx, %r14d                                   #
                                # LOE rbx rbp r12 r13 r14d r15d
..B4.45:                        # Preds ..B4.46 ..B4.44
        movl      $64, %edx                                     #292.5
        movl      %r14d, %esi                                   #292.5
        addq      %r12, %rsi                                    #292.5
        lea       4608(%rbx,%r13), %rdi                         #292.5
        call      memcpy                                        #292.5
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.46:                        # Preds ..B4.45
        incl      %r15d                                         #292.5
        addl      $64, %r14d                                    #292.5
        addl      $256, %r13d                                   #292.5
        cmpl      $3, %r15d                                     #292.5
        jb        ..B4.45       # Prob 66%                      #292.5
                                # LOE rbx rbp r12 r13 r14d r15d
..B4.47:                        # Preds ..B4.46
        movl      (%rsp), %r13d                                 #
        movq      8(%rsp), %r15                                 #
        movl      16(%rsp), %r14d                               #
        jmp       ..B4.55       # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.00.0.6:
..B4.50:                        # Preds ..B4.3
        xorl      %ecx, %ecx                                    #245.5
        xorl      %ebp, %ebp                                    #244.5
        movl      %r13d, (%rsp)                                 #
        movl      %ecx, %r13d                                   #
        movq      %r15, 8(%rsp)                                 #
        movl      %ecx, %r15d                                   #
        movl      %r14d, 16(%rsp)                               #
        movl      %ecx, %r14d                                   #
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.51:                        # Preds ..B4.52 ..B4.50
        movl      %r14d, %edi                                   #245.5
        movl      $64, %edx                                     #245.5
        movl      %r15d, %esi                                   #245.5
        addq      %rbx, %rdi                                    #245.5
        addq      %r12, %rsi                                    #245.5
        call      memcpy                                        #245.5
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.52:                        # Preds ..B4.51
        incl      %r13d                                         #245.5
        addl      $64, %r15d                                    #245.5
        addl      $256, %r14d                                   #245.5
        cmpl      $3, %r13d                                     #245.5
        jb        ..B4.51       # Prob 66%                      #245.5
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.53:                        # Preds ..B4.52
        movl      (%rsp), %r13d                                 #
        movq      8(%rsp), %r15                                 #
        movl      16(%rsp), %r14d                               #
        jmp       ..B4.55       # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.DEFAULT.0.6:
..B4.54:                        # Preds ..B4.3 ..B4.2
        movq      %rbx, %rdi                                    #296.5
        movl      $7, %esi                                      #296.5
        movq      %r15, %rdx                                    #296.5
        movl      $2, %ecx                                      #296.5
        movl      %r14d, %r8d                                   #296.5
        movq      %r12, %r9                                     #296.5
        movl      $7, %ebp                                      #295.5
        call      mmxput3                                       #296.5
                                # LOE rbx rbp r12 r15 r13d r14d
..B4.55:                        # Preds ..B4.53 ..B4.47 ..B4.42 ..B4.39 ..B4.34
                                #       ..B4.28 ..B4.19 ..B4.54
        movq      %r12, %rsi                                    #299.3
        lea       (%rbp,%rbp,2), %rdi                           #299.25
        shlq      $8, %rdi                                      #299.25
        movl      $1, %edx                                      #299.3
        addq      %rbx, %rdi                                    #299.25
        call      SSEmd5body                                    #299.3
                                # LOE rbx r12 r15 r13d r14d
..B4.56:                        # Preds ..B4.55
        incl      %r13d                                         #239.17
        cmpl      $1000, %r13d                                  #239.12
        jb        ..B4.2        # Prob 99%                      #239.12
                                # LOE rbx r12 r15 r13d r14d
..B4.57:                        # Preds ..B4.56
        addq      $24, %rsp                                     #301.1
..___tag_value_dispatch.57:                                     #
        popq      %rbp                                          #301.1
..___tag_value_dispatch.59:                                     #
        popq      %rbx                                          #301.1
..___tag_value_dispatch.61:                                     #
        popq      %r15                                          #301.1
..___tag_value_dispatch.63:                                     #
        popq      %r14                                          #301.1
..___tag_value_dispatch.65:                                     #
        popq      %r13                                          #301.1
..___tag_value_dispatch.67:                                     #
        popq      %r12                                          #301.1
..___tag_value_dispatch.69:                                     #
        ret                                                     #301.1
        .align    16,0x90
..___tag_value_dispatch.70:                                     #
                                # LOE
# mark_end;
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
# mark_begin;
       .align    16,0x90
	.globl mmxput3
mmxput3:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %rdx
# parameter 4: %ecx
# parameter 5: %r8d
# parameter 6: %r9
..B5.1:                         # Preds ..B5.0
..___tag_value_mmxput3.71:                                      #197.1
        pushq     %r12                                          #197.1
..___tag_value_mmxput3.73:                                      #
        pushq     %r13                                          #197.1
..___tag_value_mmxput3.75:                                      #
        pushq     %r14                                          #197.1
..___tag_value_mmxput3.77:                                      #
        pushq     %r15                                          #197.1
..___tag_value_mmxput3.79:                                      #
        pushq     %rbx                                          #197.1
..___tag_value_mmxput3.81:                                      #
        pushq     %rbp                                          #197.1
..___tag_value_mmxput3.83:                                      #
        xorl      %r10d, %r10d                                  #204.2
        movl      %ecx, -16(%rsp)                               #
        lea       (%rsi,%rsi,2), %eax                           #206.41
        xorl      %esi, %esi                                    #
        shll      $8, %eax                                      #206.41
        addq      %rax, %rdi                                    #206.27
        xorl      %eax, %eax                                    #
        movq      %rdi, -24(%rsp)                               #
                                # LOE rax rdx r9 esi r8d r10d
..B5.2:                         # Preds ..B5.14 ..B5.1
        movl      %esi, %ebp                                    #206.27
        lea       (,%r10,4), %ebx                               #209.4
        addq      -24(%rsp), %rbp                               #206.27
        movl      (%rdx,%rbx,4), %r14d                          #196.6
        imull     -16(%rsp), %r14d                              #209.32
        addl      %r8d, %r14d                                   #209.39
        movl      %r14d, %r12d                                  #210.16
        andl      $3, %r12d                                     #210.16
        shll      $3, %r12d                                     #210.19
        testl     %r12d, %r12d                                  #211.7
        je        ..B5.4        # Prob 50%                      #211.7
                                # LOE rax rdx rbp r9 ebx esi r8d r10d r12d r14d
..B5.3:                         # Preds ..B5.2
        andl      $-4, %r14d                                    #213.20
        movl      %r12d, %r13d                                  #214.61
        shll      $2, %r14d                                     #214.34
        negl      %r13d                                         #214.61
        movl      %r13d, %ecx                                   #214.61
        movl      $-1, %r15d                                    #214.61
        shrl      %cl, %r15d                                    #214.61
        movl      %r12d, %ecx                                   #215.80
        andl      (%r14,%rbp), %r15d                            #214.23
        movl      %r15d, (%r14,%rbp)                            #214.23
        movl      (%r9,%rax,4), %edi                            #196.6
        shll      %cl, %edi                                     #215.80
        movl      %r12d, %ecx                                   #216.81
        orl       %edi, %r15d                                   #215.23
        lea       4(%rax), %edi                                 #216.63
        movl      %r15d, (%r14,%rbp)                            #215.23
        movl      (%r9,%rax,4), %r15d                           #196.6
        movl      (%r9,%rdi,4), %r11d                           #196.6
        shll      %cl, %r11d                                    #216.81
        movl      %r13d, %ecx                                   #216.128
        shrl      %cl, %r15d                                    #216.128
        movl      %r12d, %ecx                                   #217.81
        orl       %r15d, %r11d                                  #216.128
        movl      %r11d, 16(%r14,%rbp)                          #216.23
        lea       8(%rax), %r11d                                #217.63
        movl      (%r9,%rdi,4), %edi                            #196.6
        movl      (%r9,%r11,4), %r15d                           #196.6
        shll      %cl, %r15d                                    #217.81
        movl      %r13d, %ecx                                   #217.128
        shrl      %cl, %edi                                     #217.128
        movl      %r12d, %ecx                                   #218.83
        orl       %edi, %r15d                                   #217.128
        lea       12(%rax), %edi                                #218.64
        movl      %r15d, 32(%r14,%rbp)                          #217.23
        movl      (%r9,%r11,4), %r11d                           #196.6
        movl      (%r9,%rdi,4), %r15d                           #196.6
        shll      %cl, %r15d                                    #218.83
        movl      %r13d, %ecx                                   #218.130
        shrl      %cl, %r11d                                    #218.130
        movl      %r12d, %ecx                                   #219.60
        orl       %r11d, %r15d                                  #218.130
        movl      $-1, %r11d                                    #219.60
        shll      %cl, %r11d                                    #219.60
        movl      %r13d, %ecx                                   #220.88
        andl      64(%r14,%rbp), %r11d                          #219.23
        movl      %r15d, 48(%r14,%rbp)                          #218.23
        movl      %r11d, 64(%r14,%rbp)                          #219.23
        movl      (%r9,%rdi,4), %r12d                           #196.6
        shrl      %cl, %r12d                                    #220.88
        orl       %r12d, %r11d                                  #220.23
        movl      %r11d, 64(%r14,%rbp)                          #220.23
        jmp       ..B5.5        # Prob 100%                     #220.23
                                # LOE rdx rbp r9 eax ebx esi r8d r10d
..B5.4:                         # Preds ..B5.2
        shll      $2, %r14d                                     #224.33
        lea       4(%rax), %edi                                 #225.61
        lea       8(%rax), %r12d                                #226.61
        lea       12(%rax), %r15d                               #227.62
        movl      (%r9,%rax,4), %ecx                            #196.6
        movl      %ecx, (%r14,%rbp)                             #224.23
        movl      (%r9,%rdi,4), %r11d                           #196.6
        movl      %r11d, 16(%r14,%rbp)                          #225.23
        movl      (%r9,%r12,4), %r13d                           #196.6
        movl      %r13d, 32(%r14,%rbp)                          #226.23
        movl      (%r9,%r15,4), %ecx                            #196.6
        movl      %ecx, 48(%r14,%rbp)                           #227.23
                                # LOE rdx rbp r9 eax ebx esi r8d r10d
..B5.5:                         # Preds ..B5.3 ..B5.4
        lea       1(%rbx), %ecx                                 #209.11
        movl      (%rdx,%rcx,4), %r13d                          #196.6
        imull     -16(%rsp), %r13d                              #209.32
        addl      %r8d, %r13d                                   #209.39
        movl      %r13d, %r14d                                  #210.16
        andl      $3, %r14d                                     #210.16
        shll      $3, %r14d                                     #210.19
        testl     %r14d, %r14d                                  #211.7
        je        ..B5.7        # Prob 50%                      #211.7
                                # LOE rdx rbp r9 eax ebx esi r8d r10d r13d r14d
..B5.6:                         # Preds ..B5.5
        andl      $-4, %r13d                                    #213.20
        movl      %r14d, %r15d                                  #214.61
        shll      $2, %r13d                                     #214.34
        negl      %r15d                                         #214.61
        lea       1(%rax), %edi                                 #215.62
        movl      %r15d, %ecx                                   #214.61
        movl      $-1, %r11d                                    #214.61
        shrl      %cl, %r11d                                    #214.61
        movl      %r14d, %ecx                                   #215.80
        andl      4(%r13,%rbp), %r11d                           #214.23
        movl      %r11d, 4(%r13,%rbp)                           #214.23
        movl      (%r9,%rdi,4), %r12d                           #196.6
        shll      %cl, %r12d                                    #215.80
        movl      %r14d, %ecx                                   #216.81
        orl       %r12d, %r11d                                  #215.23
        movl      %r11d, 4(%r13,%rbp)                           #215.23
        lea       5(%rax), %r11d                                #216.63
        movl      (%r9,%rdi,4), %edi                            #196.6
        movl      (%r9,%r11,4), %r12d                           #196.6
        shll      %cl, %r12d                                    #216.81
        movl      %r15d, %ecx                                   #216.128
        shrl      %cl, %edi                                     #216.128
        movl      %r14d, %ecx                                   #217.81
        orl       %edi, %r12d                                   #216.128
        movl      %r12d, 20(%r13,%rbp)                          #216.23
        lea       9(%rax), %r12d                                #217.63
        movl      (%r9,%r11,4), %r11d                           #196.6
        movl      (%r9,%r12,4), %edi                            #196.6
        shll      %cl, %edi                                     #217.81
        movl      %r15d, %ecx                                   #217.128
        shrl      %cl, %r11d                                    #217.128
        movl      %r14d, %ecx                                   #218.83
        orl       %r11d, %edi                                   #217.128
        movl      %edi, 36(%r13,%rbp)                           #217.23
        lea       13(%rax), %edi                                #218.64
        movl      (%r9,%r12,4), %r12d                           #196.6
        movl      (%r9,%rdi,4), %r11d                           #196.6
        shll      %cl, %r11d                                    #218.83
        movl      %r15d, %ecx                                   #218.130
        shrl      %cl, %r12d                                    #218.130
        movl      %r14d, %ecx                                   #219.60
        orl       %r12d, %r11d                                  #218.130
        movl      %r11d, 52(%r13,%rbp)                          #218.23
        movl      $-1, %r11d                                    #219.60
        shll      %cl, %r11d                                    #219.60
        movl      %r15d, %ecx                                   #220.88
        andl      68(%r13,%rbp), %r11d                          #219.23
        movl      %r11d, 68(%r13,%rbp)                          #219.23
        movl      (%r9,%rdi,4), %r14d                           #196.6
        shrl      %cl, %r14d                                    #220.88
        orl       %r14d, %r11d                                  #220.23
        movl      %r11d, 68(%r13,%rbp)                          #220.23
        jmp       ..B5.8        # Prob 100%                     #220.23
                                # LOE rdx rbp r9 eax ebx esi r8d r10d
..B5.7:                         # Preds ..B5.5
        shll      $2, %r13d                                     #224.33
        lea       1(%rax), %ecx                                 #224.59
        lea       5(%rax), %r11d                                #225.61
        lea       9(%rax), %r14d                                #226.61
        movl      (%r9,%rcx,4), %edi                            #196.6
        lea       13(%rax), %ecx                                #227.62
        movl      %edi, 4(%r13,%rbp)                            #224.23
        movl      (%r9,%r11,4), %r12d                           #196.6
        movl      %r12d, 20(%r13,%rbp)                          #225.23
        movl      (%r9,%r14,4), %r15d                           #196.6
        movl      %r15d, 36(%r13,%rbp)                          #226.23
        movl      (%r9,%rcx,4), %edi                            #196.6
        movl      %edi, 52(%r13,%rbp)                           #227.23
                                # LOE rdx rbp r9 eax ebx esi r8d r10d
..B5.8:                         # Preds ..B5.6 ..B5.7
        lea       2(%rbx), %ecx                                 #209.11
        movl      (%rdx,%rcx,4), %r13d                          #196.6
        imull     -16(%rsp), %r13d                              #209.32
        addl      %r8d, %r13d                                   #209.39
        movl      %r13d, %r14d                                  #210.16
        andl      $3, %r14d                                     #210.16
        shll      $3, %r14d                                     #210.19
        testl     %r14d, %r14d                                  #211.7
        je        ..B5.10       # Prob 50%                      #211.7
                                # LOE rdx rbp r9 eax ebx esi r8d r10d r13d r14d
..B5.9:                         # Preds ..B5.8
        andl      $-4, %r13d                                    #213.20
        movl      %r14d, %r15d                                  #214.61
        shll      $2, %r13d                                     #214.34
        negl      %r15d                                         #214.61
        lea       2(%rax), %edi                                 #215.62
        movl      %r15d, %ecx                                   #214.61
        movl      $-1, %r11d                                    #214.61
        shrl      %cl, %r11d                                    #214.61
        movl      %r14d, %ecx                                   #215.80
        andl      8(%r13,%rbp), %r11d                           #214.23
        movl      %r11d, 8(%r13,%rbp)                           #214.23
        movl      (%r9,%rdi,4), %r12d                           #196.6
        shll      %cl, %r12d                                    #215.80
        movl      %r14d, %ecx                                   #216.81
        orl       %r12d, %r11d                                  #215.23
        movl      %r11d, 8(%r13,%rbp)                           #215.23
        lea       6(%rax), %r11d                                #216.63
        movl      (%r9,%rdi,4), %edi                            #196.6
        movl      (%r9,%r11,4), %r12d                           #196.6
        shll      %cl, %r12d                                    #216.81
        movl      %r15d, %ecx                                   #216.128
        shrl      %cl, %edi                                     #216.128
        movl      %r14d, %ecx                                   #217.81
        orl       %edi, %r12d                                   #216.128
        movl      %r12d, 24(%r13,%rbp)                          #216.23
        lea       10(%rax), %r12d                               #217.63
        movl      (%r9,%r11,4), %r11d                           #196.6
        movl      (%r9,%r12,4), %edi                            #196.6
        shll      %cl, %edi                                     #217.81
        movl      %r15d, %ecx                                   #217.128
        shrl      %cl, %r11d                                    #217.128
        movl      %r14d, %ecx                                   #218.83
        orl       %r11d, %edi                                   #217.128
        movl      %edi, 40(%r13,%rbp)                           #217.23
        lea       14(%rax), %edi                                #218.64
        movl      (%r9,%r12,4), %r12d                           #196.6
        movl      (%r9,%rdi,4), %r11d                           #196.6
        shll      %cl, %r11d                                    #218.83
        movl      %r15d, %ecx                                   #218.130
        shrl      %cl, %r12d                                    #218.130
        movl      %r14d, %ecx                                   #219.60
        orl       %r12d, %r11d                                  #218.130
        movl      %r11d, 56(%r13,%rbp)                          #218.23
        movl      $-1, %r11d                                    #219.60
        shll      %cl, %r11d                                    #219.60
        movl      %r15d, %ecx                                   #220.88
        andl      72(%r13,%rbp), %r11d                          #219.23
        movl      %r11d, 72(%r13,%rbp)                          #219.23
        movl      (%r9,%rdi,4), %r14d                           #196.6
        shrl      %cl, %r14d                                    #220.88
        orl       %r14d, %r11d                                  #220.23
        movl      %r11d, 72(%r13,%rbp)                          #220.23
        jmp       ..B5.11       # Prob 100%                     #220.23
                                # LOE rdx rbp r9 eax ebx esi r8d r10d
..B5.10:                        # Preds ..B5.8
        shll      $2, %r13d                                     #224.33
        lea       2(%rax), %ecx                                 #224.59
        lea       6(%rax), %r11d                                #225.61
        lea       10(%rax), %r14d                               #226.61
        movl      (%r9,%rcx,4), %edi                            #196.6
        lea       14(%rax), %ecx                                #227.62
        movl      %edi, 8(%r13,%rbp)                            #224.23
        movl      (%r9,%r11,4), %r12d                           #196.6
        movl      %r12d, 24(%r13,%rbp)                          #225.23
        movl      (%r9,%r14,4), %r15d                           #196.6
        movl      %r15d, 40(%r13,%rbp)                          #226.23
        movl      (%r9,%rcx,4), %edi                            #196.6
        movl      %edi, 56(%r13,%rbp)                           #227.23
                                # LOE rdx rbp r9 eax ebx esi r8d r10d
..B5.11:                        # Preds ..B5.9 ..B5.10
        addl      $3, %ebx                                      #209.11
        movl      (%rdx,%rbx,4), %r14d                          #196.6
        imull     -16(%rsp), %r14d                              #209.32
        addl      %r8d, %r14d                                   #209.39
        movl      %r14d, %r15d                                  #210.16
        andl      $3, %r15d                                     #210.16
        shll      $3, %r15d                                     #210.19
        testl     %r15d, %r15d                                  #211.7
        je        ..B5.13       # Prob 50%                      #211.7
                                # LOE rdx rbp r9 eax esi r8d r10d r14d r15d
..B5.12:                        # Preds ..B5.11
        andl      $-4, %r14d                                    #213.20
        movl      %r15d, %r13d                                  #214.61
        shll      $2, %r14d                                     #214.34
        negl      %r13d                                         #214.61
        lea       3(%rax), %r12d                                #215.62
        movl      %r13d, %ecx                                   #214.61
        movl      $-1, %edi                                     #214.61
        lea       7(%rax), %r11d                                #216.63
        shrl      %cl, %edi                                     #214.61
        movl      %r15d, %ecx                                   #215.80
        andl      12(%r14,%rbp), %edi                           #214.23
        movl      %edi, 12(%r14,%rbp)                           #214.23
        movl      (%r9,%r12,4), %ebx                            #196.6
        shll      %cl, %ebx                                     #215.80
        movl      %r15d, %ecx                                   #216.81
        orl       %ebx, %edi                                    #215.23
        movl      %edi, 12(%r14,%rbp)                           #215.23
        movl      (%r9,%r11,4), %edi                            #196.6
        shll      %cl, %edi                                     #216.81
        movl      %r13d, %ecx                                   #216.128
        movl      (%r9,%r12,4), %ebx                            #196.6
        shrl      %cl, %ebx                                     #216.128
        movl      %r15d, %ecx                                   #217.81
        orl       %ebx, %edi                                    #216.128
        movl      %edi, 28(%r14,%rbp)                           #216.23
        lea       11(%rax), %edi                                #217.63
        movl      (%r9,%r11,4), %r12d                           #196.6
        movl      (%r9,%rdi,4), %ebx                            #196.6
        shll      %cl, %ebx                                     #217.81
        movl      %r13d, %ecx                                   #217.128
        shrl      %cl, %r12d                                    #217.128
        movl      %r15d, %ecx                                   #218.83
        orl       %r12d, %ebx                                   #217.128
        movl      %ebx, 44(%r14,%rbp)                           #217.23
        lea       15(%rax), %ebx                                #218.64
        movl      (%r9,%rdi,4), %edi                            #196.6
        movl      (%r9,%rbx,4), %r11d                           #196.6
        shll      %cl, %r11d                                    #218.83
        movl      %r13d, %ecx                                   #218.130
        shrl      %cl, %edi                                     #218.130
        movl      %r15d, %ecx                                   #219.60
        orl       %edi, %r11d                                   #218.130
        movl      $-1, %edi                                     #219.60
        shll      %cl, %edi                                     #219.60
        movl      %r13d, %ecx                                   #220.88
        andl      76(%r14,%rbp), %edi                           #219.23
        movl      %r11d, 60(%r14,%rbp)                          #218.23
        movl      %edi, 76(%r14,%rbp)                           #219.23
        movl      (%r9,%rbx,4), %r15d                           #196.6
        shrl      %cl, %r15d                                    #220.88
        orl       %r15d, %edi                                   #220.23
        movl      %edi, 76(%r14,%rbp)                           #220.23
        jmp       ..B5.14       # Prob 100%                     #220.23
                                # LOE rdx r9 eax esi r8d r10d
..B5.13:                        # Preds ..B5.11
        shll      $2, %r14d                                     #224.33
        lea       3(%rax), %ecx                                 #224.59
        lea       7(%rax), %edi                                 #225.61
        lea       11(%rax), %r12d                               #226.61
        lea       15(%rax), %r15d                               #227.62
        movl      (%r9,%rcx,4), %ebx                            #196.6
        movl      %ebx, 12(%r14,%rbp)                           #224.23
        movl      (%r9,%rdi,4), %r11d                           #196.6
        movl      %r11d, 28(%r14,%rbp)                          #225.23
        movl      (%r9,%r12,4), %r13d                           #196.6
        movl      %r13d, 44(%r14,%rbp)                          #226.23
        movl      (%r9,%r15,4), %ecx                            #196.6
        movl      %ecx, 60(%r14,%rbp)                           #227.23
                                # LOE rdx r9 eax esi r8d r10d
..B5.14:                        # Preds ..B5.12 ..B5.13
        incl      %r10d                                         #204.2
        addl      $256, %esi                                    #204.2
        addl      $16, %eax                                     #204.2
        cmpl      $3, %r10d                                     #204.2
        jb        ..B5.2        # Prob 66%                      #204.2
                                # LOE rax rdx r9 esi r8d r10d
..B5.15:                        # Preds ..B5.14
..___tag_value_mmxput3.85:                                      #232.1
        popq      %rbp                                          #232.1
..___tag_value_mmxput3.86:                                      #
        popq      %rbx                                          #232.1
..___tag_value_mmxput3.88:                                      #
        popq      %r15                                          #232.1
..___tag_value_mmxput3.90:                                      #
        popq      %r14                                          #232.1
..___tag_value_mmxput3.92:                                      #
        popq      %r13                                          #232.1
..___tag_value_mmxput3.94:                                      #
        popq      %r12                                          #232.1
..___tag_value_mmxput3.96:                                      #
        ret                                                     #232.1
        .align    16,0x90
..___tag_value_mmxput3.97:                                      #
                                # LOE
# mark_end;
	.type	mmxput3,@function
	.size	mmxput3,.-mmxput3
	.data
# -- End  mmxput3
	.text
# -- Begin  SSEmd5body
# mark_begin;
       .align    16,0x90
	.globl SSEmd5body
SSEmd5body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %edx
..B6.1:                         # Preds ..B6.0
..___tag_value_SSEmd5body.98:                                   #57.1
        subq      $776, %rsp                                    #57.1
..___tag_value_SSEmd5body.100:                                  #
        testl     %edx, %edx                                    #68.5
        je        ..B6.3        # Prob 50%                      #68.5
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15
..B6.2:                         # Preds ..B6.1
        movdqa    .L_2il0floatpacket.61(%rip), %xmm1            #72.11
        movdqa    .L_2il0floatpacket.62(%rip), %xmm15           #73.11
        movdqa    %xmm1, %xmm11                                 #72.11
        movdqa    .L_2il0floatpacket.63(%rip), %xmm10           #74.11
        movdqa    %xmm15, %xmm9                                 #73.11
        movdqa    .L_2il0floatpacket.64(%rip), %xmm3            #75.11
        movdqa    %xmm10, %xmm2                                 #74.11
        movdqa    %xmm3, %xmm5                                  #75.11
        movdqa    %xmm1, %xmm13                                 #72.11
        movdqa    %xmm15, %xmm0                                 #73.11
        movdqa    %xmm10, %xmm4                                 #74.11
        movdqa    %xmm3, %xmm6                                  #75.11
        jmp       ..B6.4        # Prob 100%                     #75.11
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm9 xmm10 xmm11 xmm13 xmm15
..B6.3:                         # Preds ..B6.1
        movdqa    (%rsi), %xmm1                                 #56.6
        movdqa    16(%rsi), %xmm15                              #56.6
        movdqa    32(%rsi), %xmm10                              #56.6
        movdqa    48(%rsi), %xmm3                               #56.6
        movdqa    64(%rsi), %xmm11                              #56.6
        movdqa    80(%rsi), %xmm9                               #56.6
        movdqa    96(%rsi), %xmm2                               #56.6
        movdqa    112(%rsi), %xmm5                              #56.6
        movdqa    128(%rsi), %xmm13                             #56.6
        movdqa    144(%rsi), %xmm0                              #56.6
        movdqa    160(%rsi), %xmm4                              #56.6
        movdqa    176(%rsi), %xmm6                              #56.6
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm9 xmm10 xmm11 xmm13 xmm15
..B6.4:                         # Preds ..B6.2 ..B6.3
        movdqa    %xmm10, %xmm8                                 #90.3
        movdqa    %xmm2, %xmm14                                 #90.3
        pxor      %xmm3, %xmm8                                  #90.3
        pxor      %xmm5, %xmm14                                 #90.3
        movdqa    .L_2il0floatpacket.65(%rip), %xmm12           #90.3
        pand      %xmm15, %xmm8                                 #90.3
        paddd     %xmm12, %xmm1                                 #90.3
        pxor      %xmm3, %xmm8                                  #90.3
        movdqa    (%rdi), %xmm7                                 #56.6
        paddd     %xmm8, %xmm1                                  #90.3
        movdqa    %xmm7, 704(%rsp)                              #56.6
        paddd     %xmm7, %xmm1                                  #90.3
        movdqa    %xmm4, %xmm7                                  #90.3
        pand      %xmm9, %xmm14                                 #90.3
        pxor      %xmm6, %xmm7                                  #90.3
        paddd     %xmm12, %xmm11                                #90.3
        pand      %xmm0, %xmm7                                  #90.3
        pxor      %xmm5, %xmm14                                 #90.3
        paddd     %xmm12, %xmm13                                #90.3
        pxor      %xmm6, %xmm7                                  #90.3
        paddd     %xmm14, %xmm11                                #90.3
        paddd     %xmm7, %xmm13                                 #90.3
        movdqa    512(%rdi), %xmm14                             #56.6
        movdqa    256(%rdi), %xmm8                              #56.6
        paddd     %xmm14, %xmm13                                #90.3
        movdqa    %xmm8, 688(%rsp)                              #56.6
        paddd     %xmm8, %xmm11                                 #90.3
        movdqa    %xmm14, 384(%rsp)                             #56.6
        movdqa    %xmm1, %xmm8                                  #90.3
        movdqa    %xmm13, %xmm14                                #90.3
        pslld     $7, %xmm8                                     #90.3
        psrld     $25, %xmm1                                    #90.3
        pslld     $7, %xmm14                                    #90.3
        psrld     $25, %xmm13                                   #90.3
        por       %xmm1, %xmm8                                  #90.3
        movdqa    %xmm11, %xmm7                                 #90.3
        por       %xmm13, %xmm14                                #90.3
        movdqa    %xmm15, %xmm13                                #91.3
        paddd     %xmm15, %xmm8                                 #90.3
        pslld     $7, %xmm7                                     #90.3
        psrld     $25, %xmm11                                   #90.3
        pxor      %xmm10, %xmm13                                #91.3
        por       %xmm11, %xmm7                                 #90.3
        movdqa    .L_2il0floatpacket.66(%rip), %xmm11           #91.3
        pand      %xmm8, %xmm13                                 #91.3
        paddd     %xmm11, %xmm3                                 #91.3
        pxor      %xmm10, %xmm13                                #91.3
        paddd     %xmm13, %xmm3                                 #91.3
        paddd     %xmm11, %xmm5                                 #91.3
        movdqa    %xmm9, %xmm13                                 #91.3
        paddd     %xmm11, %xmm6                                 #91.3
        movdqa    %xmm0, %xmm11                                 #91.3
        paddd     %xmm9, %xmm7                                  #90.3
        paddd     %xmm0, %xmm14                                 #90.3
        pxor      %xmm2, %xmm13                                 #91.3
        pxor      %xmm4, %xmm11                                 #91.3
        pand      %xmm7, %xmm13                                 #91.3
        pand      %xmm14, %xmm11                                #91.3
        pxor      %xmm2, %xmm13                                 #91.3
        pxor      %xmm4, %xmm11                                 #91.3
        paddd     %xmm13, %xmm5                                 #91.3
        movdqa    16(%rdi), %xmm1                               #56.6
        paddd     %xmm11, %xmm6                                 #91.3
        movdqa    272(%rdi), %xmm12                             #56.6
        paddd     %xmm1, %xmm3                                  #91.3
        movdqa    528(%rdi), %xmm13                             #56.6
        paddd     %xmm12, %xmm5                                 #91.3
        paddd     %xmm13, %xmm6                                 #91.3
        movdqa    %xmm3, %xmm11                                 #91.3
        movdqa    %xmm1, 144(%rsp)                              #56.6
        movdqa    %xmm6, %xmm1                                  #91.3
        movdqa    %xmm12, 112(%rsp)                             #56.6
        movdqa    %xmm5, %xmm12                                 #91.3
        pslld     $12, %xmm11                                   #91.3
        psrld     $20, %xmm3                                    #91.3
        pslld     $12, %xmm12                                   #91.3
        psrld     $20, %xmm5                                    #91.3
        pslld     $12, %xmm1                                    #91.3
        psrld     $20, %xmm6                                    #91.3
        por       %xmm3, %xmm11                                 #91.3
        por       %xmm5, %xmm12                                 #91.3
        movdqa    .L_2il0floatpacket.67(%rip), %xmm5            #92.3
        por       %xmm6, %xmm1                                  #91.3
        movdqa    %xmm15, %xmm6                                 #92.3
        paddd     %xmm8, %xmm11                                 #91.3
        movdqa    %xmm13, 96(%rsp)                              #56.6
        paddd     %xmm5, %xmm10                                 #92.3
        pxor      %xmm8, %xmm6                                  #92.3
        paddd     %xmm5, %xmm2                                  #92.3
        movdqa    %xmm9, %xmm13                                 #92.3
        paddd     %xmm5, %xmm4                                  #92.3
        movdqa    %xmm0, %xmm5                                  #92.3
        paddd     %xmm7, %xmm12                                 #91.3
        paddd     %xmm14, %xmm1                                 #91.3
        pand      %xmm11, %xmm6                                 #92.3
        pxor      %xmm7, %xmm13                                 #92.3
        pxor      %xmm14, %xmm5                                 #92.3
        pxor      %xmm15, %xmm6                                 #92.3
        pand      %xmm12, %xmm13                                #92.3
        pand      %xmm1, %xmm5                                  #92.3
        paddd     %xmm6, %xmm10                                 #92.3
        movdqa    32(%rdi), %xmm3                               #56.6
        pxor      %xmm9, %xmm13                                 #92.3
        pxor      %xmm0, %xmm5                                  #92.3
        paddd     %xmm3, %xmm10                                 #92.3
        movdqa    %xmm3, (%rsp)                                 #56.6
        paddd     %xmm13, %xmm2                                 #92.3
        movdqa    288(%rdi), %xmm6                              #56.6
        paddd     %xmm5, %xmm4                                  #92.3
        movdqa    544(%rdi), %xmm3                              #56.6
        paddd     %xmm6, %xmm2                                  #92.3
        paddd     %xmm3, %xmm4                                  #92.3
        movdqa    %xmm10, %xmm13                                #92.3
        movdqa    %xmm3, 32(%rsp)                               #56.6
        movdqa    %xmm2, %xmm5                                  #92.3
        movdqa    %xmm4, %xmm3                                  #92.3
        pslld     $17, %xmm13                                   #92.3
        psrld     $15, %xmm10                                   #92.3
        pslld     $17, %xmm5                                    #92.3
        psrld     $15, %xmm2                                    #92.3
        pslld     $17, %xmm3                                    #92.3
        psrld     $15, %xmm4                                    #92.3
        por       %xmm10, %xmm13                                #92.3
        movdqa    %xmm6, 16(%rsp)                               #56.6
        por       %xmm2, %xmm5                                  #92.3
        movdqa    .L_2il0floatpacket.68(%rip), %xmm6            #93.3
        por       %xmm4, %xmm3                                  #92.3
        movdqa    %xmm11, %xmm4                                 #93.3
        movdqa    %xmm12, %xmm2                                 #93.3
        paddd     %xmm11, %xmm13                                #92.3
        paddd     %xmm12, %xmm5                                 #92.3
        paddd     %xmm6, %xmm15                                 #93.3
        pxor      %xmm8, %xmm4                                  #93.3
        paddd     %xmm6, %xmm9                                  #93.3
        pxor      %xmm7, %xmm2                                  #93.3
        paddd     %xmm6, %xmm0                                  #93.3
        movdqa    %xmm1, %xmm6                                  #93.3
        paddd     %xmm1, %xmm3                                  #92.3
        pand      %xmm13, %xmm4                                 #93.3
        pand      %xmm5, %xmm2                                  #93.3
        pxor      %xmm14, %xmm6                                 #93.3
        pxor      %xmm8, %xmm4                                  #93.3
        pxor      %xmm7, %xmm2                                  #93.3
        pand      %xmm3, %xmm6                                  #93.3
        paddd     %xmm4, %xmm15                                 #93.3
        movdqa    48(%rdi), %xmm10                              #56.6
        paddd     %xmm2, %xmm9                                  #93.3
        movdqa    304(%rdi), %xmm4                              #56.6
        pxor      %xmm14, %xmm6                                 #93.3
        movdqa    %xmm10, 256(%rsp)                             #56.6
        paddd     %xmm10, %xmm15                                #93.3
        movdqa    560(%rdi), %xmm10                             #56.6
        paddd     %xmm4, %xmm9                                  #93.3
        paddd     %xmm6, %xmm0                                  #93.3
        movdqa    %xmm15, %xmm6                                 #93.3
        movdqa    %xmm10, 288(%rsp)                             #56.6
        paddd     %xmm10, %xmm0                                 #93.3
        movdqa    %xmm9, %xmm10                                 #93.3
        psrld     $10, %xmm9                                    #93.3
        pslld     $22, %xmm10                                   #93.3
        pslld     $22, %xmm6                                    #93.3
        por       %xmm9, %xmm10                                 #93.3
        movdqa    %xmm0, %xmm9                                  #93.3
        psrld     $10, %xmm15                                   #93.3
        pslld     $22, %xmm9                                    #93.3
        psrld     $10, %xmm0                                    #93.3
        por       %xmm15, %xmm6                                 #93.3
        por       %xmm0, %xmm9                                  #93.3
        movdqa    %xmm13, %xmm0                                 #94.3
        paddd     %xmm13, %xmm6                                 #93.3
        pxor      %xmm11, %xmm0                                 #94.3
        movdqa    %xmm4, 272(%rsp)                              #56.6
        pand      %xmm6, %xmm0                                  #94.3
        movdqa    .L_2il0floatpacket.69(%rip), %xmm4            #94.3
        pxor      %xmm11, %xmm0                                 #94.3
        paddd     %xmm4, %xmm8                                  #94.3
        paddd     %xmm4, %xmm7                                  #94.3
        paddd     %xmm0, %xmm8                                  #94.3
        movdqa    %xmm5, %xmm0                                  #94.3
        paddd     %xmm4, %xmm14                                 #94.3
        movdqa    %xmm3, %xmm4                                  #94.3
        paddd     %xmm5, %xmm10                                 #93.3
        paddd     %xmm3, %xmm9                                  #93.3
        pxor      %xmm12, %xmm0                                 #94.3
        pxor      %xmm1, %xmm4                                  #94.3
        movdqa    64(%rdi), %xmm15                              #56.6
        pand      %xmm10, %xmm0                                 #94.3
        pand      %xmm9, %xmm4                                  #94.3
        paddd     %xmm15, %xmm8                                 #94.3
        pxor      %xmm12, %xmm0                                 #94.3
        pxor      %xmm1, %xmm4                                  #94.3
        movdqa    %xmm15, 48(%rsp)                              #56.6
        paddd     %xmm0, %xmm7                                  #94.3
        movdqa    320(%rdi), %xmm15                             #56.6
        paddd     %xmm4, %xmm14                                 #94.3
        movdqa    %xmm8, %xmm4                                  #94.3
        paddd     %xmm15, %xmm7                                 #94.3
        pslld     $7, %xmm4                                     #94.3
        psrld     $25, %xmm8                                    #94.3
        por       %xmm8, %xmm4                                  #94.3
        movdqa    %xmm7, %xmm8                                  #94.3
        movdqa    576(%rdi), %xmm2                              #56.6
        pslld     $7, %xmm8                                     #94.3
        psrld     $25, %xmm7                                    #94.3
        paddd     %xmm2, %xmm14                                 #94.3
        por       %xmm7, %xmm8                                  #94.3
        movdqa    %xmm6, %xmm7                                  #95.3
        movdqa    %xmm15, 80(%rsp)                              #56.6
        paddd     %xmm6, %xmm4                                  #94.3
        movdqa    %xmm14, %xmm15                                #94.3
        pxor      %xmm13, %xmm7                                 #95.3
        movdqa    .L_2il0floatpacket.70(%rip), %xmm0            #95.3
        pslld     $7, %xmm15                                    #94.3
        psrld     $25, %xmm14                                   #94.3
        pand      %xmm4, %xmm7                                  #95.3
        por       %xmm14, %xmm15                                #94.3
        paddd     %xmm0, %xmm11                                 #95.3
        pxor      %xmm13, %xmm7                                 #95.3
        paddd     %xmm0, %xmm12                                 #95.3
        paddd     %xmm0, %xmm1                                  #95.3
        movdqa    %xmm9, %xmm0                                  #95.3
        paddd     %xmm9, %xmm15                                 #94.3
        paddd     %xmm7, %xmm11                                 #95.3
        movdqa    %xmm10, %xmm7                                 #95.3
        pxor      %xmm3, %xmm0                                  #95.3
        paddd     %xmm10, %xmm8                                 #94.3
        pxor      %xmm5, %xmm7                                  #95.3
        pand      %xmm15, %xmm0                                 #95.3
        pand      %xmm8, %xmm7                                  #95.3
        pxor      %xmm3, %xmm0                                  #95.3
        pxor      %xmm5, %xmm7                                  #95.3
        movdqa    %xmm2, 64(%rsp)                               #56.6
        paddd     %xmm0, %xmm1                                  #95.3
        movdqa    80(%rdi), %xmm14                              #56.6
        paddd     %xmm7, %xmm12                                 #95.3
        movdqa    592(%rdi), %xmm2                              #56.6
        paddd     %xmm14, %xmm11                                #95.3
        movdqa    %xmm14, 432(%rsp)                             #56.6
        paddd     %xmm2, %xmm1                                  #95.3
        movdqa    336(%rdi), %xmm14                             #56.6
        movdqa    %xmm11, %xmm0                                 #95.3
        movdqa    %xmm14, 448(%rsp)                             #56.6
        paddd     %xmm14, %xmm12                                #95.3
        movdqa    %xmm1, %xmm14                                 #95.3
        pslld     $12, %xmm0                                    #95.3
        psrld     $20, %xmm11                                   #95.3
        movdqa    %xmm12, %xmm7                                 #95.3
        pslld     $12, %xmm14                                   #95.3
        psrld     $20, %xmm1                                    #95.3
        por       %xmm11, %xmm0                                 #95.3
        pslld     $12, %xmm7                                    #95.3
        psrld     $20, %xmm12                                   #95.3
        por       %xmm1, %xmm14                                 #95.3
        movdqa    %xmm4, %xmm1                                  #96.3
        paddd     %xmm4, %xmm0                                  #95.3
        movdqa    %xmm2, 416(%rsp)                              #56.6
        por       %xmm12, %xmm7                                 #95.3
        pxor      %xmm6, %xmm1                                  #96.3
        movdqa    %xmm8, %xmm12                                 #96.3
        movdqa    .L_2il0floatpacket.71(%rip), %xmm2            #96.3
        paddd     %xmm8, %xmm7                                  #95.3
        pand      %xmm0, %xmm1                                  #96.3
        pxor      %xmm10, %xmm12                                #96.3
        paddd     %xmm2, %xmm13                                 #96.3
        paddd     %xmm2, %xmm5                                  #96.3
        paddd     %xmm2, %xmm3                                  #96.3
        movdqa    %xmm15, %xmm2                                 #96.3
        pxor      %xmm6, %xmm1                                  #96.3
        pand      %xmm7, %xmm12                                 #96.3
        paddd     %xmm15, %xmm14                                #95.3
        pxor      %xmm9, %xmm2                                  #96.3
        movdqa    96(%rdi), %xmm11                              #56.6
        paddd     %xmm1, %xmm13                                 #96.3
        pxor      %xmm10, %xmm12                                #96.3
        pand      %xmm14, %xmm2                                 #96.3
        movdqa    352(%rdi), %xmm1                              #56.6
        paddd     %xmm11, %xmm13                                #96.3
        paddd     %xmm12, %xmm5                                 #96.3
        pxor      %xmm9, %xmm2                                  #96.3
        movdqa    %xmm11, 192(%rsp)                             #56.6
        paddd     %xmm1, %xmm5                                  #96.3
        movdqa    %xmm1, 176(%rsp)                              #56.6
        movdqa    %xmm13, %xmm1                                 #96.3
        movdqa    608(%rdi), %xmm11                             #56.6
        paddd     %xmm2, %xmm3                                  #96.3
        pslld     $17, %xmm1                                    #96.3
        psrld     $15, %xmm13                                   #96.3
        paddd     %xmm11, %xmm3                                 #96.3
        por       %xmm13, %xmm1                                 #96.3
        movdqa    %xmm5, %xmm13                                 #96.3
        movdqa    %xmm3, %xmm2                                  #96.3
        pslld     $17, %xmm13                                   #96.3
        psrld     $15, %xmm5                                    #96.3
        pslld     $17, %xmm2                                    #96.3
        psrld     $15, %xmm3                                    #96.3
        por       %xmm5, %xmm13                                 #96.3
        movdqa    %xmm0, %xmm5                                  #97.3
        por       %xmm3, %xmm2                                  #96.3
        movdqa    %xmm7, %xmm12                                 #97.3
        movdqa    .L_2il0floatpacket.72(%rip), %xmm3            #97.3
        paddd     %xmm0, %xmm1                                  #96.3
        pxor      %xmm4, %xmm5                                  #97.3
        paddd     %xmm7, %xmm13                                 #96.3
        paddd     %xmm3, %xmm6                                  #97.3
        paddd     %xmm3, %xmm10                                 #97.3
        pxor      %xmm8, %xmm12                                 #97.3
        paddd     %xmm3, %xmm9                                  #97.3
        movdqa    %xmm14, %xmm3                                 #97.3
        pand      %xmm1, %xmm5                                  #97.3
        paddd     %xmm14, %xmm2                                 #96.3
        pand      %xmm13, %xmm12                                #97.3
        pxor      %xmm15, %xmm3                                 #97.3
        pxor      %xmm4, %xmm5                                  #97.3
        pxor      %xmm8, %xmm12                                 #97.3
        pand      %xmm2, %xmm3                                  #97.3
        movdqa    %xmm11, 160(%rsp)                             #56.6
        paddd     %xmm5, %xmm6                                  #97.3
        movdqa    368(%rdi), %xmm5                              #56.6
        paddd     %xmm12, %xmm10                                #97.3
        movdqa    112(%rdi), %xmm11                             #56.6
        pxor      %xmm15, %xmm3                                 #97.3
        movdqa    %xmm5, 560(%rsp)                              #56.6
        paddd     %xmm11, %xmm6                                 #97.3
        paddd     %xmm5, %xmm10                                 #97.3
        paddd     %xmm3, %xmm9                                  #97.3
        movdqa    624(%rdi), %xmm5                              #56.6
        movdqa    %xmm10, %xmm3                                 #97.3
        movdqa    %xmm5, 544(%rsp)                              #56.6
        paddd     %xmm5, %xmm9                                  #97.3
        movdqa    %xmm6, %xmm5                                  #97.3
        psrld     $10, %xmm6                                    #97.3
        pslld     $22, %xmm5                                    #97.3
        pslld     $22, %xmm3                                    #97.3
        por       %xmm6, %xmm5                                  #97.3
        psrld     $10, %xmm10                                   #97.3
        movdqa    %xmm9, %xmm6                                  #97.3
        por       %xmm10, %xmm3                                 #97.3
        pslld     $22, %xmm6                                    #97.3
        psrld     $10, %xmm9                                    #97.3
        movdqa    %xmm1, %xmm10                                 #98.3
        paddd     %xmm1, %xmm5                                  #97.3
        por       %xmm9, %xmm6                                  #97.3
        pxor      %xmm0, %xmm10                                 #98.3
        movdqa    .L_2il0floatpacket.73(%rip), %xmm9            #98.3
        pand      %xmm5, %xmm10                                 #98.3
        paddd     %xmm9, %xmm4                                  #98.3
        paddd     %xmm9, %xmm8                                  #98.3
        movdqa    %xmm13, %xmm12                                #98.3
        paddd     %xmm9, %xmm15                                 #98.3
        movdqa    %xmm2, %xmm9                                  #98.3
        paddd     %xmm13, %xmm3                                 #97.3
        paddd     %xmm2, %xmm6                                  #97.3
        pxor      %xmm0, %xmm10                                 #98.3
        pxor      %xmm7, %xmm12                                 #98.3
        pxor      %xmm14, %xmm9                                 #98.3
        movdqa    %xmm11, 592(%rsp)                             #56.6
        paddd     %xmm10, %xmm4                                 #98.3
        movdqa    128(%rdi), %xmm11                             #56.6
        pand      %xmm3, %xmm12                                 #98.3
        pand      %xmm6, %xmm9                                  #98.3
        paddd     %xmm11, %xmm4                                 #98.3
        pxor      %xmm7, %xmm12                                 #98.3
        pxor      %xmm14, %xmm9                                 #98.3
        movdqa    384(%rdi), %xmm10                             #56.6
        paddd     %xmm12, %xmm8                                 #98.3
        paddd     %xmm9, %xmm15                                 #98.3
        movdqa    %xmm4, %xmm9                                  #98.3
        paddd     %xmm10, %xmm8                                 #98.3
        pslld     $7, %xmm9                                     #98.3
        psrld     $25, %xmm4                                    #98.3
        movdqa    %xmm10, 352(%rsp)                             #56.6
        por       %xmm4, %xmm9                                  #98.3
        movdqa    640(%rdi), %xmm10                             #56.6
        movdqa    %xmm8, %xmm4                                  #98.3
        paddd     %xmm10, %xmm15                                #98.3
        pslld     $7, %xmm4                                     #98.3
        psrld     $25, %xmm8                                    #98.3
        paddd     %xmm5, %xmm9                                  #98.3
        por       %xmm8, %xmm4                                  #98.3
        movdqa    %xmm15, %xmm8                                 #98.3
        movdqa    %xmm11, 368(%rsp)                             #56.6
        pslld     $7, %xmm8                                     #98.3
        psrld     $25, %xmm15                                   #98.3
        movdqa    %xmm5, %xmm11                                 #99.3
        por       %xmm15, %xmm8                                 #98.3
        pxor      %xmm1, %xmm11                                 #99.3
        movdqa    .L_2il0floatpacket.74(%rip), %xmm15           #99.3
        pand      %xmm9, %xmm11                                 #99.3
        movdqa    %xmm10, 336(%rsp)                             #56.6
        paddd     %xmm15, %xmm0                                 #99.3
        paddd     %xmm15, %xmm7                                 #99.3
        movdqa    %xmm3, %xmm10                                 #99.3
        paddd     %xmm15, %xmm14                                #99.3
        movdqa    %xmm6, %xmm15                                 #99.3
        paddd     %xmm3, %xmm4                                  #98.3
        paddd     %xmm6, %xmm8                                  #98.3
        pxor      %xmm1, %xmm11                                 #99.3
        pxor      %xmm13, %xmm10                                #99.3
        pxor      %xmm2, %xmm15                                 #99.3
        paddd     %xmm11, %xmm0                                 #99.3
        movdqa    144(%rdi), %xmm12                             #56.6
        pand      %xmm4, %xmm10                                 #99.3
        pand      %xmm8, %xmm15                                 #99.3
        paddd     %xmm12, %xmm0                                 #99.3
        pxor      %xmm13, %xmm10                                #99.3
        pxor      %xmm2, %xmm15                                 #99.3
        movdqa    400(%rdi), %xmm11                             #56.6
        paddd     %xmm10, %xmm7                                 #99.3
        paddd     %xmm15, %xmm14                                #99.3
        movdqa    %xmm0, %xmm15                                 #99.3
        paddd     %xmm11, %xmm7                                 #99.3
        pslld     $12, %xmm15                                   #99.3
        psrld     $20, %xmm0                                    #99.3
        movdqa    %xmm12, 128(%rsp)                             #56.6
        por       %xmm0, %xmm15                                 #99.3
        movdqa    656(%rdi), %xmm12                             #56.6
        movdqa    %xmm7, %xmm0                                  #99.3
        paddd     %xmm12, %xmm14                                #99.3
        pslld     $12, %xmm0                                    #99.3
        psrld     $20, %xmm7                                    #99.3
        paddd     %xmm9, %xmm15                                 #99.3
        por       %xmm7, %xmm0                                  #99.3
        movdqa    %xmm14, %xmm7                                 #99.3
        pslld     $12, %xmm7                                    #99.3
        psrld     $20, %xmm14                                   #99.3
        por       %xmm14, %xmm7                                 #99.3
        movdqa    %xmm9, %xmm14                                 #100.3
        movdqa    %xmm12, 224(%rsp)                             #56.6
        movdqa    %xmm4, %xmm12                                 #100.3
        movdqa    .L_2il0floatpacket.75(%rip), %xmm10           #100.3
        pxor      %xmm5, %xmm14                                 #100.3
        paddd     %xmm4, %xmm0                                  #99.3
        paddd     %xmm10, %xmm1                                 #100.3
        paddd     %xmm10, %xmm13                                #100.3
        pxor      %xmm3, %xmm12                                 #100.3
        paddd     %xmm10, %xmm2                                 #100.3
        movdqa    %xmm8, %xmm10                                 #100.3
        pand      %xmm15, %xmm14                                #100.3
        paddd     %xmm8, %xmm7                                  #99.3
        pand      %xmm0, %xmm12                                 #100.3
        pxor      %xmm6, %xmm10                                 #100.3
        pxor      %xmm5, %xmm14                                 #100.3
        pxor      %xmm3, %xmm12                                 #100.3
        pand      %xmm7, %xmm10                                 #100.3
        paddd     %xmm14, %xmm1                                 #100.3
        movdqa    %xmm11, 208(%rsp)                             #56.6
        paddd     %xmm12, %xmm13                                #100.3
        movdqa    416(%rdi), %xmm14                             #56.6
        pxor      %xmm6, %xmm10                                 #100.3
        movdqa    160(%rdi), %xmm11                             #56.6
        paddd     %xmm14, %xmm13                                #100.3
        movdqa    %xmm14, 496(%rsp)                             #56.6
        paddd     %xmm11, %xmm1                                 #100.3
        movdqa    672(%rdi), %xmm14                             #56.6
        paddd     %xmm10, %xmm2                                 #100.3
        movdqa    %xmm14, 512(%rsp)                             #56.6
        paddd     %xmm14, %xmm2                                 #100.3
        movdqa    %xmm1, %xmm14                                 #100.3
        psrld     $15, %xmm1                                    #100.3
        pslld     $17, %xmm14                                   #100.3
        por       %xmm1, %xmm14                                 #100.3
        movdqa    %xmm13, %xmm1                                 #100.3
        pslld     $17, %xmm1                                    #100.3
        psrld     $15, %xmm13                                   #100.3
        por       %xmm13, %xmm1                                 #100.3
        movdqa    %xmm2, %xmm13                                 #100.3
        pslld     $17, %xmm13                                   #100.3
        psrld     $15, %xmm2                                    #100.3
        por       %xmm2, %xmm13                                 #100.3
        movdqa    %xmm15, %xmm2                                 #101.3
        paddd     %xmm15, %xmm14                                #100.3
        pxor      %xmm9, %xmm2                                  #101.3
        movdqa    .L_2il0floatpacket.76(%rip), %xmm10           #101.3
        pand      %xmm14, %xmm2                                 #101.3
        paddd     %xmm10, %xmm5                                 #101.3
        pxor      %xmm9, %xmm2                                  #101.3
        paddd     %xmm2, %xmm5                                  #101.3
        paddd     %xmm0, %xmm1                                  #100.3
        movdqa    432(%rdi), %xmm2                              #56.6
        paddd     %xmm7, %xmm13                                 #100.3
        movdqa    %xmm2, 304(%rsp)                              #56.6
        movdqa    %xmm0, %xmm2                                  #101.3
        pxor      %xmm4, %xmm2                                  #101.3
        paddd     %xmm10, %xmm3                                 #101.3
        movdqa    %xmm11, 528(%rsp)                             #56.6
        pand      %xmm1, %xmm2                                  #101.3
        movdqa    176(%rdi), %xmm11                             #56.6
        pxor      %xmm4, %xmm2                                  #101.3
        movdqa    %xmm11, 240(%rsp)                             #56.6
        paddd     %xmm11, %xmm5                                 #101.3
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm13 xmm14 xmm15
..B6.11:                        # Preds ..B6.4
        movdqa    %xmm7, %xmm12                                 #101.3
        paddd     %xmm10, %xmm6                                 #101.3
        pxor      %xmm8, %xmm12                                 #101.3
        paddd     %xmm2, %xmm3                                  #101.3
        pand      %xmm13, %xmm12                                #101.3
        pxor      %xmm8, %xmm12                                 #101.3
        movdqa    304(%rsp), %xmm2                              #101.3
        paddd     %xmm12, %xmm6                                 #101.3
        movdqa    %xmm5, %xmm12                                 #101.3
        paddd     %xmm2, %xmm3                                  #101.3
        pslld     $22, %xmm12                                   #101.3
        psrld     $10, %xmm5                                    #101.3
        movdqa    688(%rdi), %xmm11                             #56.6
        por       %xmm5, %xmm12                                 #101.3
        movdqa    %xmm3, %xmm5                                  #101.3
        paddd     %xmm11, %xmm6                                 #101.3
        pslld     $22, %xmm5                                    #101.3
        psrld     $10, %xmm3                                    #101.3
        por       %xmm3, %xmm5                                  #101.3
        movdqa    %xmm6, %xmm3                                  #101.3
        pslld     $22, %xmm3                                    #101.3
        psrld     $10, %xmm6                                    #101.3
        por       %xmm6, %xmm3                                  #101.3
        movdqa    %xmm14, %xmm6                                 #102.3
        paddd     %xmm14, %xmm12                                #101.3
        pxor      %xmm15, %xmm6                                 #102.3
        movdqa    %xmm11, 320(%rsp)                             #56.6
        pand      %xmm12, %xmm6                                 #102.3
        movdqa    .L_2il0floatpacket.77(%rip), %xmm11           #102.3
        pxor      %xmm15, %xmm6                                 #102.3
        paddd     %xmm11, %xmm9                                 #102.3
        paddd     %xmm1, %xmm5                                  #101.3
        paddd     %xmm6, %xmm9                                  #102.3
        movdqa    %xmm1, %xmm6                                  #102.3
        pxor      %xmm0, %xmm6                                  #102.3
        paddd     %xmm11, %xmm4                                 #102.3
        pand      %xmm5, %xmm6                                  #102.3
        paddd     %xmm11, %xmm8                                 #102.3
        movdqa    %xmm13, %xmm11                                #102.3
        paddd     %xmm13, %xmm3                                 #101.3
        movdqa    192(%rdi), %xmm10                             #56.6
        pxor      %xmm0, %xmm6                                  #102.3
        pxor      %xmm7, %xmm11                                 #102.3
        paddd     %xmm10, %xmm9                                 #102.3
        movdqa    %xmm10, 624(%rsp)                             #56.6
        paddd     %xmm6, %xmm4                                  #102.3
        movdqa    448(%rdi), %xmm10                             #56.6
        pand      %xmm3, %xmm11                                 #102.3
        paddd     %xmm10, %xmm4                                 #102.3
        pxor      %xmm7, %xmm11                                 #102.3
        movdqa    %xmm10, 608(%rsp)                             #56.6
        paddd     %xmm11, %xmm8                                 #102.3
        movdqa    %xmm9, %xmm11                                 #102.3
        movdqa    %xmm4, %xmm10                                 #102.3
        pslld     $7, %xmm11                                    #102.3
        psrld     $25, %xmm9                                    #102.3
        pslld     $7, %xmm10                                    #102.3
        psrld     $25, %xmm4                                    #102.3
        movdqa    704(%rdi), %xmm6                              #56.6
        por       %xmm9, %xmm11                                 #102.3
        por       %xmm4, %xmm10                                 #102.3
        movdqa    %xmm14, %xmm4                                 #103.3
        paddd     %xmm6, %xmm8                                  #102.3
        paddd     %xmm12, %xmm11                                #102.3
        pxor      %xmm12, %xmm4                                 #103.3
        paddd     %xmm5, %xmm10                                 #102.3
        movdqa    %xmm6, 640(%rsp)                              #56.6
        movdqa    %xmm8, %xmm6                                  #102.3
        movdqa    .L_2il0floatpacket.78(%rip), %xmm9            #103.3
        pand      %xmm11, %xmm4                                 #103.3
        pslld     $7, %xmm6                                     #102.3
        psrld     $25, %xmm8                                    #102.3
        paddd     %xmm9, %xmm15                                 #103.3
        pxor      %xmm14, %xmm4                                 #103.3
        por       %xmm8, %xmm6                                  #102.3
        paddd     %xmm4, %xmm15                                 #103.3
        paddd     %xmm9, %xmm0                                  #103.3
        movdqa    %xmm1, %xmm4                                  #103.3
        paddd     %xmm9, %xmm7                                  #103.3
        movdqa    %xmm13, %xmm9                                 #103.3
        paddd     %xmm3, %xmm6                                  #102.3
        pxor      %xmm5, %xmm4                                  #103.3
        pxor      %xmm3, %xmm9                                  #103.3
        pand      %xmm10, %xmm4                                 #103.3
        movdqa    208(%rdi), %xmm8                              #56.6
        pand      %xmm6, %xmm9                                  #103.3
        paddd     %xmm8, %xmm15                                 #103.3
        pxor      %xmm1, %xmm4                                  #103.3
        pxor      %xmm13, %xmm9                                 #103.3
        paddd     %xmm4, %xmm0                                  #103.3
        movdqa    %xmm8, 400(%rsp)                              #56.6
        paddd     %xmm9, %xmm7                                  #103.3
        movdqa    464(%rdi), %xmm8                              #56.6
        movdqa    %xmm15, %xmm9                                 #103.3
        movdqa    720(%rdi), %xmm4                              #56.6
        paddd     %xmm8, %xmm0                                  #103.3
        pslld     $12, %xmm9                                    #103.3
        psrld     $20, %xmm15                                   #103.3
        movdqa    %xmm4, 480(%rsp)                              #56.6
        paddd     %xmm4, %xmm7                                  #103.3
        por       %xmm15, %xmm9                                 #103.3
        movdqa    %xmm0, %xmm4                                  #103.3
        movdqa    %xmm11, %xmm15                                #104.3
        paddd     %xmm11, %xmm9                                 #103.3
        pslld     $12, %xmm4                                    #103.3
        psrld     $20, %xmm0                                    #103.3
        pxor      %xmm12, %xmm15                                #104.3
        por       %xmm0, %xmm4                                  #103.3
        movdqa    %xmm8, 464(%rsp)                              #56.6
        movdqa    %xmm7, %xmm0                                  #103.3
        movdqa    .L_2il0floatpacket.79(%rip), %xmm8            #104.3
        pand      %xmm9, %xmm15                                 #104.3
        pslld     $12, %xmm0                                    #103.3
        psrld     $20, %xmm7                                    #103.3
        paddd     %xmm8, %xmm14                                 #104.3
        pxor      %xmm12, %xmm15                                #104.3
        por       %xmm7, %xmm0                                  #103.3
        paddd     %xmm15, %xmm14                                #104.3
        paddd     %xmm8, %xmm1                                  #104.3
        movdqa    %xmm10, %xmm15                                #104.3
        paddd     %xmm8, %xmm13                                 #104.3
        movdqa    %xmm6, %xmm8                                  #104.3
        paddd     %xmm10, %xmm4                                 #103.3
        paddd     %xmm6, %xmm0                                  #103.3
        pxor      %xmm5, %xmm15                                 #104.3
        pxor      %xmm3, %xmm8                                  #104.3
        movdqa    224(%rdi), %xmm7                              #56.6
        pand      %xmm4, %xmm15                                 #104.3
        pand      %xmm0, %xmm8                                  #104.3
        paddd     %xmm7, %xmm14                                 #104.3
        pxor      %xmm5, %xmm15                                 #104.3
        pxor      %xmm3, %xmm8                                  #104.3
        movdqa    %xmm7, 672(%rsp)                              #56.6
        paddd     %xmm15, %xmm1                                 #104.3
        movdqa    480(%rdi), %xmm7                              #56.6
        paddd     %xmm8, %xmm13                                 #104.3
        movdqa    %xmm14, %xmm8                                 #104.3
        paddd     %xmm7, %xmm1                                  #104.3
        pslld     $17, %xmm8                                    #104.3
        psrld     $15, %xmm14                                   #104.3
        movdqa    %xmm7, 656(%rsp)                              #56.6
        por       %xmm14, %xmm8                                 #104.3
        movdqa    %xmm1, %xmm7                                  #104.3
        movdqa    %xmm9, %xmm14                                 #105.3
        paddd     736(%rdi), %xmm13                             #104.3
        paddd     %xmm9, %xmm8                                  #104.3
        pslld     $17, %xmm7                                    #104.3
        psrld     $15, %xmm1                                    #104.3
        pxor      %xmm11, %xmm14                                #105.3
        por       %xmm1, %xmm7                                  #104.3
        movdqa    .L_2il0floatpacket.80(%rip), %xmm1            #105.3
        movdqa    %xmm13, %xmm15                                #104.3
        pand      %xmm8, %xmm14                                 #105.3
        pslld     $17, %xmm15                                   #104.3
        psrld     $15, %xmm13                                   #104.3
        paddd     %xmm1, %xmm12                                 #105.3
        pxor      %xmm11, %xmm14                                #105.3
        por       %xmm13, %xmm15                                #104.3
        paddd     %xmm14, %xmm12                                #105.3
        paddd     %xmm1, %xmm5                                  #105.3
        movdqa    %xmm4, %xmm14                                 #105.3
        paddd     %xmm1, %xmm3                                  #105.3
        movdqa    %xmm0, %xmm1                                  #105.3
        paddd     %xmm4, %xmm7                                  #104.3
        paddd     %xmm0, %xmm15                                 #104.3
        pxor      %xmm10, %xmm14                                #105.3
        pxor      %xmm6, %xmm1                                  #105.3
        pand      %xmm7, %xmm14                                 #105.3
        movdqa    240(%rdi), %xmm13                             #56.6
        pand      %xmm15, %xmm1                                 #105.3
        paddd     %xmm13, %xmm12                                #105.3
        pxor      %xmm10, %xmm14                                #105.3
        pxor      %xmm6, %xmm1                                  #105.3
        paddd     %xmm14, %xmm5                                 #105.3
        paddd     %xmm1, %xmm3                                  #105.3
        movdqa    %xmm12, %xmm1                                 #105.3
        paddd     496(%rdi), %xmm5                              #105.3
        pslld     $22, %xmm1                                    #105.3
        psrld     $10, %xmm12                                   #105.3
        por       %xmm12, %xmm1                                 #105.3
        movdqa    %xmm5, %xmm12                                 #105.3
        paddd     752(%rdi), %xmm3                              #105.3
        pslld     $22, %xmm12                                   #105.3
        psrld     $10, %xmm5                                    #105.3
        paddd     %xmm8, %xmm1                                  #105.3
        por       %xmm5, %xmm12                                 #105.3
        movdqa    %xmm3, %xmm5                                  #105.3
        pslld     $22, %xmm5                                    #105.3
        psrld     $10, %xmm3                                    #105.3
        por       %xmm3, %xmm5                                  #105.3
        movdqa    %xmm8, %xmm3                                  #108.3
        pxor      %xmm1, %xmm3                                  #108.3
        paddd     %xmm15, %xmm5                                 #105.3
        movdqa    .L_2il0floatpacket.81(%rip), %xmm14           #108.3
        pand      %xmm9, %xmm3                                  #108.3
        paddd     %xmm14, %xmm11                                #108.3
        pxor      %xmm8, %xmm3                                  #108.3
        paddd     %xmm14, %xmm10                                #108.3
        paddd     %xmm14, %xmm6                                 #108.3
        movdqa    %xmm15, %xmm14                                #108.3
        paddd     %xmm7, %xmm12                                 #105.3
        paddd     %xmm3, %xmm11                                 #108.3
        movdqa    %xmm7, %xmm3                                  #108.3
        pxor      %xmm5, %xmm14                                 #108.3
        pxor      %xmm12, %xmm3                                 #108.3
        pand      %xmm0, %xmm14                                 #108.3
        pand      %xmm4, %xmm3                                  #108.3
        pxor      %xmm15, %xmm14                                #108.3
        pxor      %xmm7, %xmm3                                  #108.3
        paddd     144(%rsp), %xmm11                             #108.3
        paddd     %xmm14, %xmm6                                 #108.3
        paddd     96(%rsp), %xmm6                               #108.3
        paddd     %xmm3, %xmm10                                 #108.3
        movdqa    %xmm11, %xmm3                                 #108.3
        psrld     $27, %xmm11                                   #108.3
        pslld     $5, %xmm3                                     #108.3
        movdqa    %xmm6, %xmm14                                 #108.3
        paddd     112(%rsp), %xmm10                             #108.3
        por       %xmm11, %xmm3                                 #108.3
        pslld     $5, %xmm14                                    #108.3
        psrld     $27, %xmm6                                    #108.3
        paddd     %xmm1, %xmm3                                  #108.3
        movdqa    %xmm10, %xmm11                                #108.3
        por       %xmm6, %xmm14                                 #108.3
        movdqa    %xmm1, %xmm6                                  #109.3
        pslld     $5, %xmm11                                    #108.3
        psrld     $27, %xmm10                                   #108.3
        pxor      %xmm3, %xmm6                                  #109.3
        por       %xmm10, %xmm11                                #108.3
        movdqa    .L_2il0floatpacket.82(%rip), %xmm10           #109.3
        pand      %xmm8, %xmm6                                  #109.3
        paddd     %xmm10, %xmm9                                 #109.3
        pxor      %xmm1, %xmm6                                  #109.3
        paddd     %xmm12, %xmm11                                #108.3
        paddd     %xmm5, %xmm14                                 #108.3
        paddd     %xmm6, %xmm9                                  #109.3
        paddd     %xmm10, %xmm4                                 #109.3
        movdqa    %xmm12, %xmm6                                 #109.3
        paddd     %xmm10, %xmm0                                 #109.3
        movdqa    %xmm5, %xmm10                                 #109.3
        pxor      %xmm11, %xmm6                                 #109.3
        pxor      %xmm14, %xmm10                                #109.3
        pand      %xmm7, %xmm6                                  #109.3
        pand      %xmm15, %xmm10                                #109.3
        pxor      %xmm12, %xmm6                                 #109.3
        paddd     192(%rsp), %xmm9                              #109.3
        pxor      %xmm5, %xmm10                                 #109.3
        paddd     %xmm6, %xmm4                                  #109.3
        paddd     %xmm10, %xmm0                                 #109.3
        movdqa    %xmm9, %xmm10                                 #109.3
        psrld     $23, %xmm9                                    #109.3
        paddd     176(%rsp), %xmm4                              #109.3
        pslld     $9, %xmm10                                    #109.3
        por       %xmm9, %xmm10                                 #109.3
        movdqa    %xmm4, %xmm9                                  #109.3
        paddd     160(%rsp), %xmm0                              #109.3
        pslld     $9, %xmm9                                     #109.3
        psrld     $23, %xmm4                                    #109.3
        paddd     %xmm3, %xmm10                                 #109.3
        por       %xmm4, %xmm9                                  #109.3
        movdqa    %xmm0, %xmm4                                  #109.3
        movdqa    %xmm3, %xmm6                                  #110.3
        pslld     $9, %xmm4                                     #109.3
        psrld     $23, %xmm0                                    #109.3
        pxor      %xmm10, %xmm6                                 #110.3
        por       %xmm0, %xmm4                                  #109.3
        pand      %xmm1, %xmm6                                  #110.3
        movdqa    .L_2il0floatpacket.83(%rip), %xmm0            #110.3
        pxor      %xmm3, %xmm6                                  #110.3
        paddd     %xmm0, %xmm8                                  #110.3
        paddd     %xmm11, %xmm9                                 #109.3
        paddd     %xmm6, %xmm8                                  #110.3
        movdqa    %xmm11, %xmm6                                 #110.3
        pxor      %xmm9, %xmm6                                  #110.3
        paddd     %xmm0, %xmm7                                  #110.3
        pand      %xmm12, %xmm6                                 #110.3
        paddd     %xmm14, %xmm4                                 #109.3
        pxor      %xmm11, %xmm6                                 #110.3
        paddd     %xmm0, %xmm15                                 #110.3
        paddd     %xmm6, %xmm7                                  #110.3
        paddd     %xmm2, %xmm7                                  #110.3
        movdqa    %xmm14, %xmm2                                 #110.3
        pxor      %xmm4, %xmm2                                  #110.3
        paddd     240(%rsp), %xmm8                              #110.3
        pand      %xmm5, %xmm2                                  #110.3
        pxor      %xmm14, %xmm2                                 #110.3
        movdqa    %xmm8, %xmm0                                  #110.3
        paddd     %xmm2, %xmm15                                 #110.3
        pslld     $14, %xmm0                                    #110.3
        psrld     $18, %xmm8                                    #110.3
        movdqa    %xmm7, %xmm2                                  #110.3
        paddd     688(%rdi), %xmm15                             #110.3
        por       %xmm8, %xmm0                                  #110.3
        pslld     $14, %xmm2                                    #110.3
        psrld     $18, %xmm7                                    #110.3
        paddd     %xmm10, %xmm0                                 #110.3
        por       %xmm7, %xmm2                                  #110.3
        movdqa    %xmm15, %xmm6                                 #110.3
        movdqa    %xmm10, %xmm7                                 #111.3
        pslld     $14, %xmm6                                    #110.3
        psrld     $18, %xmm15                                   #110.3
        pxor      %xmm0, %xmm7                                  #111.3
        paddd     %xmm9, %xmm2                                  #110.3
        movdqa    .L_2il0floatpacket.84(%rip), %xmm8            #111.3
        por       %xmm15, %xmm6                                 #110.3
        pand      %xmm3, %xmm7                                  #111.3
        movdqa    %xmm9, %xmm15                                 #111.3
        paddd     %xmm8, %xmm1                                  #111.3
        pxor      %xmm10, %xmm7                                 #111.3
        pxor      %xmm2, %xmm15                                 #111.3
        paddd     %xmm4, %xmm6                                  #110.3
        paddd     %xmm7, %xmm1                                  #111.3
        pand      %xmm11, %xmm15                                #111.3
        movdqa    %xmm4, %xmm7                                  #111.3
        paddd     %xmm8, %xmm12                                 #111.3
        paddd     704(%rsp), %xmm1                              #111.3
        pxor      %xmm9, %xmm15                                 #111.3
        pxor      %xmm6, %xmm7                                  #111.3
        paddd     %xmm15, %xmm12                                #111.3
        paddd     %xmm8, %xmm5                                  #111.3
        pand      %xmm14, %xmm7                                 #111.3
        movdqa    %xmm1, %xmm8                                  #111.3
        pxor      %xmm4, %xmm7                                  #111.3
        paddd     688(%rsp), %xmm12                             #111.3
        pslld     $20, %xmm8                                    #111.3
        psrld     $12, %xmm1                                    #111.3
        paddd     %xmm7, %xmm5                                  #111.3
        por       %xmm1, %xmm8                                  #111.3
        movdqa    %xmm12, %xmm1                                 #111.3
        paddd     384(%rsp), %xmm5                              #111.3
        pslld     $20, %xmm1                                    #111.3
        psrld     $12, %xmm12                                   #111.3
        paddd     %xmm0, %xmm8                                  #111.3
        por       %xmm12, %xmm1                                 #111.3
        movdqa    %xmm5, %xmm12                                 #111.3
        pslld     $20, %xmm12                                   #111.3
        psrld     $12, %xmm5                                    #111.3
        por       %xmm5, %xmm12                                 #111.3
        movdqa    %xmm0, %xmm5                                  #112.3
        pxor      %xmm8, %xmm5                                  #112.3
        paddd     %xmm2, %xmm1                                  #111.3
        movdqa    .L_2il0floatpacket.85(%rip), %xmm15           #112.3
        pand      %xmm10, %xmm5                                 #112.3
        paddd     %xmm15, %xmm3                                 #112.3
        pxor      %xmm0, %xmm5                                  #112.3
        paddd     %xmm6, %xmm12                                 #111.3
        paddd     %xmm5, %xmm3                                  #112.3
        movdqa    %xmm2, %xmm7                                  #112.3
        movdqa    %xmm6, %xmm5                                  #112.3
        pxor      %xmm1, %xmm7                                  #112.3
        pxor      %xmm12, %xmm5                                 #112.3
        pand      %xmm9, %xmm7                                  #112.3
        pand      %xmm4, %xmm5                                  #112.3
        paddd     432(%rsp), %xmm3                              #112.3
        paddd     %xmm15, %xmm11                                #112.3
        pxor      %xmm2, %xmm7                                  #112.3
        paddd     %xmm15, %xmm14                                #112.3
        pxor      %xmm6, %xmm5                                  #112.3
        paddd     %xmm7, %xmm11                                 #112.3
        paddd     %xmm5, %xmm14                                 #112.3
        movdqa    %xmm3, %xmm5                                  #112.3
        paddd     448(%rsp), %xmm11                             #112.3
        pslld     $5, %xmm5                                     #112.3
        psrld     $27, %xmm3                                    #112.3
        movdqa    %xmm1, %xmm7                                  #113.3
        por       %xmm3, %xmm5                                  #112.3
        movdqa    %xmm11, %xmm3                                 #112.3
        paddd     416(%rsp), %xmm14                             #112.3
        pslld     $5, %xmm3                                     #112.3
        psrld     $27, %xmm11                                   #112.3
        paddd     %xmm8, %xmm5                                  #112.3
        por       %xmm11, %xmm3                                 #112.3
        movdqa    %xmm14, %xmm11                                #112.3
        pslld     $5, %xmm11                                    #112.3
        psrld     $27, %xmm14                                   #112.3
        por       %xmm14, %xmm11                                #112.3
        movdqa    %xmm8, %xmm14                                 #113.3
        pxor      %xmm5, %xmm14                                 #113.3
        paddd     %xmm1, %xmm3                                  #112.3
        movdqa    .L_2il0floatpacket.86(%rip), %xmm15           #113.3
        pand      %xmm0, %xmm14                                 #113.3
        paddd     %xmm15, %xmm10                                #113.3
        pxor      %xmm8, %xmm14                                 #113.3
        paddd     %xmm12, %xmm11                                #112.3
        paddd     %xmm14, %xmm10                                #113.3
        movdqa    %xmm12, %xmm14                                #113.3
        pxor      %xmm3, %xmm7                                  #113.3
        pxor      %xmm11, %xmm14                                #113.3
        pand      %xmm2, %xmm7                                  #113.3
        pand      %xmm6, %xmm14                                 #113.3
        paddd     %xmm15, %xmm9                                 #113.3
        paddd     528(%rsp), %xmm10                             #113.3
        pxor      %xmm1, %xmm7                                  #113.3
        paddd     %xmm15, %xmm4                                 #113.3
        pxor      %xmm12, %xmm14                                #113.3
        paddd     %xmm7, %xmm9                                  #113.3
        paddd     %xmm14, %xmm4                                 #113.3
        movdqa    %xmm10, %xmm14                                #113.3
        psrld     $23, %xmm10                                   #113.3
        paddd     496(%rsp), %xmm9                              #113.3
        pslld     $9, %xmm14                                    #113.3
        por       %xmm10, %xmm14                                #113.3
        movdqa    %xmm9, %xmm10                                 #113.3
        paddd     512(%rsp), %xmm4                              #113.3
        pslld     $9, %xmm10                                    #113.3
        psrld     $23, %xmm9                                    #113.3
        paddd     %xmm5, %xmm14                                 #113.3
        por       %xmm9, %xmm10                                 #113.3
        movdqa    %xmm4, %xmm9                                  #113.3
        pslld     $9, %xmm9                                     #113.3
        psrld     $23, %xmm4                                    #113.3
        por       %xmm4, %xmm9                                  #113.3
        movdqa    %xmm5, %xmm4                                  #114.3
        pxor      %xmm14, %xmm4                                 #114.3
        paddd     %xmm3, %xmm10                                 #113.3
        movdqa    .L_2il0floatpacket.87(%rip), %xmm7            #114.3
        pand      %xmm8, %xmm4                                  #114.3
        paddd     %xmm7, %xmm0                                  #114.3
        pxor      %xmm5, %xmm4                                  #114.3
        paddd     %xmm4, %xmm0                                  #114.3
        paddd     %xmm11, %xmm9                                 #113.3
        movdqa    %xmm13, 576(%rsp)                             #56.6
        paddd     %xmm13, %xmm0                                 #114.3
        movdqa    %xmm3, %xmm13                                 #114.3
        paddd     %xmm7, %xmm2                                  #114.3
        pxor      %xmm10, %xmm13                                #114.3
        paddd     %xmm7, %xmm6                                  #114.3
        pand      %xmm1, %xmm13                                 #114.3
        movdqa    %xmm11, %xmm7                                 #114.3
        pxor      %xmm3, %xmm13                                 #114.3
        pxor      %xmm9, %xmm7                                  #114.3
        paddd     %xmm13, %xmm2                                 #114.3
        pand      %xmm12, %xmm7                                 #114.3
        movdqa    496(%rdi), %xmm13                             #114.3
        movdqa    %xmm0, %xmm4                                  #114.3
        paddd     %xmm13, %xmm2                                 #114.3
        pxor      %xmm11, %xmm7                                 #114.3
        pslld     $14, %xmm4                                    #114.3
        psrld     $18, %xmm0                                    #114.3
        paddd     %xmm7, %xmm6                                  #114.3
        por       %xmm0, %xmm4                                  #114.3
        movdqa    752(%rdi), %xmm7                              #114.3
        movdqa    %xmm2, %xmm0                                  #114.3
        paddd     %xmm7, %xmm6                                  #114.3
        pslld     $14, %xmm0                                    #114.3
        psrld     $18, %xmm2                                    #114.3
        paddd     %xmm14, %xmm4                                 #114.3
        por       %xmm2, %xmm0                                  #114.3
        movdqa    %xmm6, %xmm2                                  #114.3
        pslld     $14, %xmm2                                    #114.3
        psrld     $18, %xmm6                                    #114.3
        por       %xmm6, %xmm2                                  #114.3
        movdqa    %xmm14, %xmm6                                 #115.3
        pxor      %xmm4, %xmm6                                  #115.3
        paddd     %xmm10, %xmm0                                 #114.3
        movdqa    .L_2il0floatpacket.88(%rip), %xmm15           #115.3
        pand      %xmm5, %xmm6                                  #115.3
        paddd     %xmm15, %xmm8                                 #115.3
        pxor      %xmm14, %xmm6                                 #115.3
        paddd     %xmm6, %xmm8                                  #115.3
        movdqa    %xmm10, %xmm6                                 #115.3
        pxor      %xmm0, %xmm6                                  #115.3
        paddd     %xmm9, %xmm2                                  #114.3
        pand      %xmm3, %xmm6                                  #115.3
        paddd     %xmm15, %xmm1                                 #115.3
        paddd     48(%rsp), %xmm8                               #115.3
        pxor      %xmm10, %xmm6                                 #115.3
        paddd     %xmm15, %xmm12                                #115.3
        movdqa    %xmm9, %xmm15                                 #115.3
        paddd     %xmm6, %xmm1                                  #115.3
        pxor      %xmm2, %xmm15                                 #115.3
        movdqa    %xmm8, %xmm6                                  #115.3
        pand      %xmm11, %xmm15                                #115.3
        paddd     80(%rsp), %xmm1                               #115.3
        pslld     $20, %xmm6                                    #115.3
        psrld     $12, %xmm8                                    #115.3
        pxor      %xmm9, %xmm15                                 #115.3
        por       %xmm8, %xmm6                                  #115.3
        movdqa    %xmm1, %xmm8                                  #115.3
        paddd     %xmm15, %xmm12                                #115.3
        pslld     $20, %xmm8                                    #115.3
        psrld     $12, %xmm1                                    #115.3
        paddd     %xmm4, %xmm6                                  #115.3
        paddd     64(%rsp), %xmm12                              #115.3
        por       %xmm1, %xmm8                                  #115.3
        movdqa    736(%rdi), %xmm1                              #115.3
                                # LOE rbx rbp rsi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm11 xmm12 xmm13 xmm14
..B6.10:                        # Preds ..B6.11
        movdqa    %xmm7, 752(%rsp)                              #
        movdqa    %xmm12, %xmm7                                 #115.3
        pslld     $20, %xmm7                                    #115.3
        psrld     $12, %xmm12                                   #115.3
        por       %xmm12, %xmm7                                 #115.3
        movdqa    %xmm4, %xmm12                                 #116.3
        pxor      %xmm6, %xmm12                                 #116.3
        paddd     %xmm0, %xmm8                                  #115.3
        movdqa    %xmm13, 736(%rsp)                             #
        pand      %xmm14, %xmm12                                #116.3
        movdqa    .L_2il0floatpacket.89(%rip), %xmm13           #116.3
        pxor      %xmm4, %xmm12                                 #116.3
        paddd     %xmm13, %xmm5                                 #116.3
        paddd     %xmm2, %xmm7                                  #115.3
        paddd     %xmm12, %xmm5                                 #116.3
        movdqa    %xmm0, %xmm15                                 #116.3
        movdqa    %xmm2, %xmm12                                 #116.3
        pxor      %xmm8, %xmm15                                 #116.3
        pxor      %xmm7, %xmm12                                 #116.3
        pand      %xmm10, %xmm15                                #116.3
        pand      %xmm9, %xmm12                                 #116.3
        paddd     %xmm13, %xmm3                                 #116.3
        paddd     128(%rsp), %xmm5                              #116.3
        pxor      %xmm0, %xmm15                                 #116.3
        paddd     %xmm13, %xmm11                                #116.3
        pxor      %xmm2, %xmm12                                 #116.3
        paddd     %xmm15, %xmm3                                 #116.3
        paddd     %xmm12, %xmm11                                #116.3
        movdqa    %xmm5, %xmm12                                 #116.3
        psrld     $27, %xmm5                                    #116.3
        paddd     208(%rsp), %xmm3                              #116.3
        pslld     $5, %xmm12                                    #116.3
        por       %xmm5, %xmm12                                 #116.3
        movdqa    %xmm3, %xmm5                                  #116.3
        paddd     224(%rsp), %xmm11                             #116.3
        pslld     $5, %xmm5                                     #116.3
        psrld     $27, %xmm3                                    #116.3
        paddd     %xmm6, %xmm12                                 #116.3
        por       %xmm3, %xmm5                                  #116.3
        movdqa    %xmm11, %xmm3                                 #116.3
        pslld     $5, %xmm3                                     #116.3
        psrld     $27, %xmm11                                   #116.3
        por       %xmm11, %xmm3                                 #116.3
        movdqa    %xmm6, %xmm11                                 #117.3
        pxor      %xmm12, %xmm11                                #117.3
        paddd     %xmm8, %xmm5                                  #116.3
        movdqa    .L_2il0floatpacket.90(%rip), %xmm15           #117.3
        pand      %xmm4, %xmm11                                 #117.3
        paddd     %xmm15, %xmm14                                #117.3
        pxor      %xmm6, %xmm11                                 #117.3
        movdqa    %xmm8, %xmm13                                 #117.3
        paddd     %xmm7, %xmm3                                  #116.3
        paddd     %xmm11, %xmm14                                #117.3
        pxor      %xmm5, %xmm13                                 #117.3
        movdqa    %xmm7, %xmm11                                 #117.3
        pand      %xmm0, %xmm13                                 #117.3
        pxor      %xmm3, %xmm11                                 #117.3
        paddd     %xmm15, %xmm10                                #117.3
        pxor      %xmm8, %xmm13                                 #117.3
        pand      %xmm2, %xmm11                                 #117.3
        paddd     %xmm13, %xmm10                                #117.3
        paddd     %xmm15, %xmm9                                 #117.3
        pxor      %xmm7, %xmm11                                 #117.3
        movdqa    %xmm3, %xmm15                                 #118.3
        paddd     656(%rsp), %xmm10                             #117.3
        paddd     %xmm11, %xmm9                                 #117.3
        paddd     672(%rsp), %xmm14                             #117.3
        paddd     %xmm1, %xmm9                                  #117.3
        movdqa    %xmm1, 720(%rsp)                              #
        movdqa    %xmm10, %xmm1                                 #117.3
        movdqa    %xmm14, %xmm11                                #117.3
        pslld     $9, %xmm1                                     #117.3
        psrld     $23, %xmm10                                   #117.3
        pslld     $9, %xmm11                                    #117.3
        psrld     $23, %xmm14                                   #117.3
        por       %xmm10, %xmm1                                 #117.3
        movdqa    %xmm9, %xmm10                                 #117.3
        por       %xmm14, %xmm11                                #117.3
        pslld     $9, %xmm10                                    #117.3
        psrld     $23, %xmm9                                    #117.3
        paddd     %xmm12, %xmm11                                #117.3
        paddd     %xmm5, %xmm1                                  #117.3
        por       %xmm9, %xmm10                                 #117.3
        movdqa    %xmm12, %xmm14                                #118.3
        movdqa    %xmm5, %xmm9                                  #118.3
        pxor      %xmm11, %xmm14                                #118.3
        pxor      %xmm1, %xmm9                                  #118.3
        paddd     %xmm3, %xmm10                                 #117.3
        movdqa    .L_2il0floatpacket.91(%rip), %xmm13           #118.3
        pand      %xmm6, %xmm14                                 #118.3
        pand      %xmm8, %xmm9                                  #118.3
        paddd     %xmm13, %xmm4                                 #118.3
        pxor      %xmm12, %xmm14                                #118.3
        paddd     %xmm13, %xmm0                                 #118.3
        pxor      %xmm5, %xmm9                                  #118.3
        pxor      %xmm10, %xmm15                                #118.3
        paddd     %xmm14, %xmm4                                 #118.3
        paddd     %xmm9, %xmm0                                  #118.3
        pand      %xmm7, %xmm15                                 #118.3
        paddd     %xmm13, %xmm2                                 #118.3
        paddd     256(%rsp), %xmm4                              #118.3
        pxor      %xmm3, %xmm15                                 #118.3
        paddd     272(%rsp), %xmm0                              #118.3
        paddd     %xmm15, %xmm2                                 #118.3
        movdqa    %xmm4, %xmm15                                 #118.3
        movdqa    %xmm0, %xmm14                                 #118.3
        paddd     288(%rsp), %xmm2                              #118.3
        pslld     $14, %xmm15                                   #118.3
        psrld     $18, %xmm4                                    #118.3
        pslld     $14, %xmm14                                   #118.3
        psrld     $18, %xmm0                                    #118.3
        por       %xmm4, %xmm15                                 #118.3
        por       %xmm0, %xmm14                                 #118.3
        movdqa    %xmm2, %xmm0                                  #118.3
        paddd     %xmm11, %xmm15                                #118.3
        pslld     $14, %xmm0                                    #118.3
        psrld     $18, %xmm2                                    #118.3
        movdqa    %xmm11, %xmm4                                 #119.3
        movdqa    .L_2il0floatpacket.92(%rip), %xmm9            #119.3
        por       %xmm2, %xmm0                                  #118.3
        pxor      %xmm15, %xmm4                                 #119.3
        paddd     %xmm1, %xmm14                                 #118.3
        paddd     %xmm10, %xmm0                                 #118.3
        paddd     %xmm9, %xmm6                                  #119.3
        pand      %xmm12, %xmm4                                 #119.3
        paddd     %xmm9, %xmm8                                  #119.3
        movdqa    %xmm1, %xmm2                                  #119.3
        paddd     %xmm9, %xmm7                                  #119.3
        movdqa    %xmm10, %xmm9                                 #119.3
        pxor      %xmm11, %xmm4                                 #119.3
        pxor      %xmm14, %xmm2                                 #119.3
        pxor      %xmm0, %xmm9                                  #119.3
        paddd     %xmm4, %xmm6                                  #119.3
        pand      %xmm5, %xmm2                                  #119.3
        movdqa    368(%rsp), %xmm4                              #119.3
        pand      %xmm3, %xmm9                                  #119.3
        paddd     %xmm4, %xmm6                                  #119.3
        pxor      %xmm1, %xmm2                                  #119.3
        pxor      %xmm10, %xmm9                                 #119.3
        paddd     %xmm2, %xmm8                                  #119.3
        movdqa    352(%rsp), %xmm2                              #119.3
        paddd     %xmm9, %xmm7                                  #119.3
        movdqa    %xmm6, %xmm9                                  #119.3
        paddd     %xmm2, %xmm8                                  #119.3
        pslld     $20, %xmm9                                    #119.3
        psrld     $12, %xmm6                                    #119.3
        por       %xmm6, %xmm9                                  #119.3
        movdqa    %xmm8, %xmm6                                  #119.3
        paddd     336(%rsp), %xmm7                              #119.3
        pslld     $20, %xmm6                                    #119.3
        psrld     $12, %xmm8                                    #119.3
        paddd     %xmm15, %xmm9                                 #119.3
        por       %xmm8, %xmm6                                  #119.3
        movdqa    %xmm7, %xmm8                                  #119.3
        pslld     $20, %xmm8                                    #119.3
        psrld     $12, %xmm7                                    #119.3
        por       %xmm7, %xmm8                                  #119.3
        movdqa    %xmm15, %xmm7                                 #120.3
        pxor      %xmm9, %xmm7                                  #120.3
        paddd     %xmm14, %xmm6                                 #119.3
        movdqa    .L_2il0floatpacket.93(%rip), %xmm13           #120.3
        pand      %xmm11, %xmm7                                 #120.3
        paddd     %xmm13, %xmm12                                #120.3
        pxor      %xmm15, %xmm7                                 #120.3
        paddd     %xmm7, %xmm12                                 #120.3
        movdqa    %xmm14, %xmm7                                 #120.3
        pxor      %xmm6, %xmm7                                  #120.3
        paddd     %xmm0, %xmm8                                  #119.3
        paddd     %xmm13, %xmm5                                 #120.3
        pand      %xmm1, %xmm7                                  #120.3
        paddd     %xmm13, %xmm3                                 #120.3
        movdqa    %xmm0, %xmm13                                 #120.3
        pxor      %xmm14, %xmm7                                 #120.3
        pxor      %xmm8, %xmm13                                 #120.3
        paddd     400(%rsp), %xmm12                             #120.3
        paddd     %xmm7, %xmm5                                  #120.3
        pand      %xmm10, %xmm13                                #120.3
        movdqa    %xmm12, %xmm7                                 #120.3
        paddd     464(%rsp), %xmm5                              #120.3
        pxor      %xmm0, %xmm13                                 #120.3
        paddd     %xmm13, %xmm3                                 #120.3
        pslld     $5, %xmm7                                     #120.3
        psrld     $27, %xmm12                                   #120.3
        movdqa    %xmm5, %xmm13                                 #120.3
        paddd     480(%rsp), %xmm3                              #120.3
        por       %xmm12, %xmm7                                 #120.3
        pslld     $5, %xmm13                                    #120.3
        psrld     $27, %xmm5                                    #120.3
        paddd     %xmm9, %xmm7                                  #120.3
        por       %xmm5, %xmm13                                 #120.3
        movdqa    %xmm3, %xmm5                                  #120.3
        movdqa    %xmm9, %xmm12                                 #121.3
        pslld     $5, %xmm5                                     #120.3
        psrld     $27, %xmm3                                    #120.3
        pxor      %xmm7, %xmm12                                 #121.3
        por       %xmm3, %xmm5                                  #120.3
        movdqa    .L_2il0floatpacket.94(%rip), %xmm3            #121.3
        pand      %xmm15, %xmm12                                #121.3
        paddd     %xmm3, %xmm11                                 #121.3
        pxor      %xmm9, %xmm12                                 #121.3
        paddd     %xmm6, %xmm13                                 #120.3
        paddd     %xmm8, %xmm5                                  #120.3
        paddd     %xmm12, %xmm11                                #121.3
        paddd     %xmm3, %xmm1                                  #121.3
        movdqa    %xmm6, %xmm12                                 #121.3
        paddd     %xmm3, %xmm10                                 #121.3
        movdqa    %xmm8, %xmm3                                  #121.3
        pxor      %xmm13, %xmm12                                #121.3
        pxor      %xmm5, %xmm3                                  #121.3
        pand      %xmm14, %xmm12                                #121.3
        pand      %xmm0, %xmm3                                  #121.3
        pxor      %xmm6, %xmm12                                 #121.3
        paddd     (%rsp), %xmm11                                #121.3
        pxor      %xmm8, %xmm3                                  #121.3
        paddd     %xmm12, %xmm1                                 #121.3
        paddd     %xmm3, %xmm10                                 #121.3
        movdqa    %xmm11, %xmm3                                 #121.3
        psrld     $23, %xmm11                                   #121.3
        paddd     16(%rsp), %xmm1                               #121.3
        pslld     $9, %xmm3                                     #121.3
        por       %xmm11, %xmm3                                 #121.3
        movdqa    %xmm1, %xmm11                                 #121.3
        paddd     32(%rsp), %xmm10                              #121.3
        pslld     $9, %xmm11                                    #121.3
        psrld     $23, %xmm1                                    #121.3
        paddd     %xmm7, %xmm3                                  #121.3
        por       %xmm1, %xmm11                                 #121.3
        movdqa    %xmm10, %xmm12                                #121.3
        movdqa    %xmm7, %xmm1                                  #122.3
        pslld     $9, %xmm12                                    #121.3
        psrld     $23, %xmm10                                   #121.3
        pxor      %xmm3, %xmm1                                  #122.3
        por       %xmm10, %xmm12                                #121.3
        pand      %xmm9, %xmm1                                  #122.3
        movdqa    .L_2il0floatpacket.95(%rip), %xmm10           #122.3
        pxor      %xmm7, %xmm1                                  #122.3
        paddd     %xmm10, %xmm15                                #122.3
        paddd     %xmm13, %xmm11                                #121.3
        paddd     %xmm1, %xmm15                                 #122.3
        movdqa    %xmm13, %xmm1                                 #122.3
        paddd     %xmm5, %xmm12                                 #121.3
        paddd     %xmm10, %xmm14                                #122.3
        pxor      %xmm11, %xmm1                                 #122.3
        paddd     %xmm10, %xmm0                                 #122.3
        movdqa    %xmm5, %xmm10                                 #122.3
        pand      %xmm6, %xmm1                                  #122.3
        pxor      %xmm12, %xmm10                                #122.3
        pxor      %xmm13, %xmm1                                 #122.3
        pand      %xmm8, %xmm10                                 #122.3
        paddd     %xmm1, %xmm14                                 #122.3
        paddd     592(%rsp), %xmm15                             #122.3
        pxor      %xmm5, %xmm10                                 #122.3
        paddd     560(%rsp), %xmm14                             #122.3
        paddd     %xmm10, %xmm0                                 #122.3
        movdqa    %xmm15, %xmm10                                #122.3
        psrld     $18, %xmm15                                   #122.3
        pslld     $14, %xmm10                                   #122.3
        movdqa    %xmm14, %xmm1                                 #122.3
        paddd     544(%rsp), %xmm0                              #122.3
        por       %xmm15, %xmm10                                #122.3
        pslld     $14, %xmm1                                    #122.3
        psrld     $18, %xmm14                                   #122.3
        paddd     %xmm3, %xmm10                                 #122.3
        por       %xmm14, %xmm1                                 #122.3
        movdqa    %xmm0, %xmm15                                 #122.3
        movdqa    %xmm3, %xmm14                                 #123.3
        pslld     $14, %xmm15                                   #122.3
        psrld     $18, %xmm0                                    #122.3
        pxor      %xmm10, %xmm14                                #123.3
        por       %xmm0, %xmm15                                 #122.3
        movdqa    .L_2il0floatpacket.96(%rip), %xmm0            #123.3
        pand      %xmm7, %xmm14                                 #123.3
        paddd     %xmm0, %xmm9                                  #123.3
        pxor      %xmm3, %xmm14                                 #123.3
        paddd     %xmm11, %xmm1                                 #122.3
        paddd     %xmm14, %xmm9                                 #123.3
        movdqa    %xmm11, %xmm14                                #123.3
        paddd     %xmm12, %xmm15                                #122.3
        pxor      %xmm1, %xmm14                                 #123.3
        paddd     %xmm0, %xmm6                                  #123.3
        pand      %xmm13, %xmm14                                #123.3
        paddd     %xmm0, %xmm8                                  #123.3
        movdqa    %xmm12, %xmm0                                 #123.3
        pxor      %xmm11, %xmm14                                #123.3
        paddd     624(%rsp), %xmm9                              #123.3
        pxor      %xmm15, %xmm0                                 #123.3
        paddd     %xmm14, %xmm6                                 #123.3
        pand      %xmm5, %xmm0                                  #123.3
        movdqa    %xmm9, %xmm14                                 #123.3
        pxor      %xmm12, %xmm0                                 #123.3
        paddd     608(%rsp), %xmm6                              #123.3
        pslld     $20, %xmm14                                   #123.3
        psrld     $12, %xmm9                                    #123.3
        paddd     %xmm0, %xmm8                                  #123.3
        por       %xmm9, %xmm14                                 #123.3
        movdqa    %xmm6, %xmm9                                  #123.3
        paddd     640(%rsp), %xmm8                              #123.3
        pslld     $20, %xmm9                                    #123.3
        psrld     $12, %xmm6                                    #123.3
        movdqa    %xmm10, %xmm0                                 #126.3
        por       %xmm6, %xmm9                                  #123.3
        movdqa    %xmm8, %xmm6                                  #123.3
        pslld     $20, %xmm6                                    #123.3
        psrld     $12, %xmm8                                    #123.3
        paddd     %xmm10, %xmm14                                #123.3
        por       %xmm8, %xmm6                                  #123.3
        movdqa    .L_2il0floatpacket.97(%rip), %xmm8            #126.3
        pxor      %xmm3, %xmm0                                  #126.3
        paddd     %xmm8, %xmm7                                  #126.3
        pxor      %xmm14, %xmm0                                 #126.3
        paddd     %xmm0, %xmm7                                  #126.3
        paddd     %xmm8, %xmm13                                 #126.3
        movdqa    %xmm1, %xmm0                                  #126.3
        paddd     %xmm8, %xmm5                                  #126.3
        movdqa    %xmm15, %xmm8                                 #126.3
        paddd     %xmm1, %xmm9                                  #123.3
        paddd     %xmm15, %xmm6                                 #123.3
        pxor      %xmm11, %xmm0                                 #126.3
        pxor      %xmm12, %xmm8                                 #126.3
        pxor      %xmm9, %xmm0                                  #126.3
        paddd     432(%rsp), %xmm7                              #126.3
        pxor      %xmm6, %xmm8                                  #126.3
        paddd     %xmm0, %xmm13                                 #126.3
        paddd     %xmm8, %xmm5                                  #126.3
        movdqa    %xmm7, %xmm8                                  #126.3
        psrld     $28, %xmm7                                    #126.3
        paddd     448(%rsp), %xmm13                             #126.3
        pslld     $4, %xmm8                                     #126.3
        por       %xmm7, %xmm8                                  #126.3
        movdqa    %xmm13, %xmm7                                 #126.3
        paddd     416(%rsp), %xmm5                              #126.3
        pslld     $4, %xmm7                                     #126.3
        psrld     $28, %xmm13                                   #126.3
        paddd     %xmm14, %xmm8                                 #126.3
        por       %xmm13, %xmm7                                 #126.3
        movdqa    %xmm5, %xmm13                                 #126.3
        pslld     $4, %xmm13                                    #126.3
        psrld     $28, %xmm5                                    #126.3
        por       %xmm5, %xmm13                                 #126.3
        movdqa    %xmm14, %xmm5                                 #127.3
        movdqa    .L_2il0floatpacket.98(%rip), %xmm0            #127.3
        pxor      %xmm10, %xmm5                                 #127.3
        paddd     %xmm0, %xmm3                                  #127.3
        pxor      %xmm8, %xmm5                                  #127.3
        paddd     %xmm5, %xmm3                                  #127.3
        paddd     %xmm9, %xmm7                                  #126.3
        paddd     %xmm4, %xmm3                                  #127.3
        movdqa    %xmm9, %xmm4                                  #127.3
        pxor      %xmm1, %xmm4                                  #127.3
        paddd     %xmm0, %xmm11                                 #127.3
        pxor      %xmm7, %xmm4                                  #127.3
        paddd     %xmm0, %xmm12                                 #127.3
        movdqa    %xmm6, %xmm0                                  #127.3
        paddd     %xmm6, %xmm13                                 #126.3
        paddd     %xmm4, %xmm11                                 #127.3
        pxor      %xmm15, %xmm0                                 #127.3
        paddd     %xmm2, %xmm11                                 #127.3
        pxor      %xmm13, %xmm0                                 #127.3
        paddd     %xmm0, %xmm12                                 #127.3
        movdqa    %xmm3, %xmm0                                  #127.3
        movdqa    %xmm11, %xmm4                                 #127.3
        pslld     $11, %xmm0                                    #127.3
        paddd     336(%rsp), %xmm12                             #127.3
        psrld     $21, %xmm3                                    #127.3
        pslld     $11, %xmm4                                    #127.3
        psrld     $21, %xmm11                                   #127.3
        por       %xmm3, %xmm0                                  #127.3
        por       %xmm11, %xmm4                                 #127.3
        movdqa    %xmm12, %xmm3                                 #127.3
        movdqa    %xmm8, %xmm11                                 #128.3
        movdqa    .L_2il0floatpacket.99(%rip), %xmm5            #128.3
        paddd     %xmm8, %xmm0                                  #127.3
        pslld     $11, %xmm3                                    #127.3
        psrld     $21, %xmm12                                   #127.3
        pxor      %xmm14, %xmm11                                #128.3
        movdqa    %xmm7, %xmm2                                  #128.3
        paddd     %xmm7, %xmm4                                  #127.3
        por       %xmm12, %xmm3                                 #127.3
        paddd     %xmm5, %xmm10                                 #128.3
        pxor      %xmm0, %xmm11                                 #128.3
        pxor      %xmm9, %xmm2                                  #128.3
        movdqa    %xmm13, %xmm12                                #128.3
        paddd     %xmm13, %xmm3                                 #127.3
        paddd     %xmm11, %xmm10                                #128.3
        paddd     %xmm5, %xmm1                                  #128.3
        pxor      %xmm4, %xmm2                                  #128.3
        pxor      %xmm6, %xmm12                                 #128.3
        paddd     %xmm2, %xmm1                                  #128.3
        paddd     240(%rsp), %xmm10                             #128.3
        paddd     %xmm5, %xmm15                                 #128.3
        pxor      %xmm3, %xmm12                                 #128.3
        movdqa    %xmm10, %xmm2                                 #128.3
        paddd     304(%rsp), %xmm1                              #128.3
        paddd     %xmm12, %xmm15                                #128.3
        paddd     320(%rsp), %xmm15                             #128.3
        pslld     $16, %xmm2                                    #128.3
        psrld     $16, %xmm10                                   #128.3
        movdqa    %xmm1, %xmm11                                 #128.3
        por       %xmm10, %xmm2                                 #128.3
        pslld     $16, %xmm11                                   #128.3
        psrld     $16, %xmm1                                    #128.3
        movdqa    %xmm15, %xmm10                                #128.3
        por       %xmm1, %xmm11                                 #128.3
        pslld     $16, %xmm10                                   #128.3
        psrld     $16, %xmm15                                   #128.3
        movdqa    %xmm0, %xmm1                                  #129.3
        movdqa    .L_2il0floatpacket.100(%rip), %xmm5           #129.3
        paddd     %xmm0, %xmm2                                  #128.3
        por       %xmm15, %xmm10                                #128.3
        pxor      %xmm8, %xmm1                                  #129.3
        movdqa    %xmm4, %xmm15                                 #129.3
        paddd     %xmm4, %xmm11                                 #128.3
        paddd     %xmm5, %xmm14                                 #129.3
        pxor      %xmm2, %xmm1                                  #129.3
        pxor      %xmm7, %xmm15                                 #129.3
        paddd     %xmm1, %xmm14                                 #129.3
        paddd     %xmm5, %xmm9                                  #129.3
        pxor      %xmm11, %xmm15                                #129.3
        movdqa    %xmm3, %xmm1                                  #129.3
        paddd     %xmm3, %xmm10                                 #128.3
        paddd     %xmm15, %xmm9                                 #129.3
        pxor      %xmm13, %xmm1                                 #129.3
        paddd     656(%rsp), %xmm9                              #129.3
        paddd     %xmm5, %xmm6                                  #129.3
        pxor      %xmm10, %xmm1                                 #129.3
        movdqa    %xmm9, %xmm12                                 #129.3
        paddd     %xmm1, %xmm6                                  #129.3
        pslld     $23, %xmm12                                   #129.3
        movdqa    720(%rsp), %xmm1                              #129.3
        psrld     $9, %xmm9                                     #129.3
        paddd     672(%rsp), %xmm14                             #129.3
        paddd     %xmm1, %xmm6                                  #129.3
        movdqa    %xmm14, %xmm5                                 #129.3
        por       %xmm9, %xmm12                                 #129.3
        movdqa    %xmm6, %xmm9                                  #129.3
        pslld     $23, %xmm5                                    #129.3
        psrld     $9, %xmm14                                    #129.3
        pslld     $23, %xmm9                                    #129.3
        psrld     $9, %xmm6                                     #129.3
        por       %xmm14, %xmm5                                 #129.3
        por       %xmm6, %xmm9                                  #129.3
        movdqa    %xmm2, %xmm6                                  #130.3
        movdqa    .L_2il0floatpacket.101(%rip), %xmm15          #130.3
        paddd     %xmm2, %xmm5                                  #129.3
        pxor      %xmm0, %xmm6                                  #130.3
        paddd     %xmm15, %xmm8                                 #130.3
        pxor      %xmm5, %xmm6                                  #130.3
        movdqa    %xmm11, %xmm14                                #130.3
        paddd     %xmm6, %xmm8                                  #130.3
        movdqa    %xmm10, %xmm6                                 #130.3
        paddd     %xmm11, %xmm12                                #129.3
        paddd     %xmm10, %xmm9                                 #129.3
        pxor      %xmm4, %xmm14                                 #130.3
        pxor      %xmm3, %xmm6                                  #130.3
        paddd     144(%rsp), %xmm8                              #130.3
        paddd     %xmm15, %xmm7                                 #130.3
        pxor      %xmm12, %xmm14                                #130.3
        paddd     %xmm15, %xmm13                                #130.3
        pxor      %xmm9, %xmm6                                  #130.3
        paddd     %xmm14, %xmm7                                 #130.3
        paddd     %xmm6, %xmm13                                 #130.3
        movdqa    %xmm8, %xmm6                                  #130.3
        paddd     112(%rsp), %xmm7                              #130.3
        pslld     $4, %xmm6                                     #130.3
        psrld     $28, %xmm8                                    #130.3
        paddd     96(%rsp), %xmm13                              #130.3
        por       %xmm8, %xmm6                                  #130.3
        movdqa    %xmm7, %xmm8                                  #130.3
        psrld     $28, %xmm7                                    #130.3
        pslld     $4, %xmm8                                     #130.3
        movdqa    %xmm13, %xmm14                                #130.3
        por       %xmm7, %xmm8                                  #130.3
        pslld     $4, %xmm14                                    #130.3
        psrld     $28, %xmm13                                   #130.3
        movdqa    %xmm5, %xmm7                                  #131.3
        paddd     %xmm5, %xmm6                                  #130.3
        por       %xmm13, %xmm14                                #130.3
        movdqa    .L_2il0floatpacket.102(%rip), %xmm13          #131.3
        pxor      %xmm2, %xmm7                                  #131.3
        paddd     %xmm13, %xmm0                                 #131.3
        pxor      %xmm6, %xmm7                                  #131.3
        paddd     %xmm7, %xmm0                                  #131.3
        paddd     %xmm12, %xmm8                                 #130.3
        paddd     48(%rsp), %xmm0                               #131.3
        paddd     %xmm9, %xmm14                                 #130.3
        movdqa    752(%rsp), %xmm7                              #131.3
        paddd     %xmm13, %xmm4                                 #131.3
        movdqa    736(%rsp), %xmm13                             #131.3
                                # LOE rbx rbp rsi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm11 xmm12 xmm13 xmm14
..B6.9:                         # Preds ..B6.10
        movdqa    %xmm1, 720(%rsp)                              #
        movdqa    %xmm12, %xmm1                                 #131.3
        pxor      %xmm11, %xmm1                                 #131.3
        movdqa    %xmm9, %xmm15                                 #131.3
        pxor      %xmm8, %xmm1                                  #131.3
        pxor      %xmm10, %xmm15                                #131.3
        paddd     %xmm1, %xmm4                                  #131.3
        movdqa    %xmm0, %xmm1                                  #131.3
        paddd     80(%rsp), %xmm4                               #131.3
        pxor      %xmm14, %xmm15                                #131.3
        paddd     .L_2il0floatpacket.102(%rip), %xmm3           #131.3
        pslld     $11, %xmm1                                    #131.3
        psrld     $21, %xmm0                                    #131.3
        paddd     %xmm15, %xmm3                                 #131.3
        por       %xmm0, %xmm1                                  #131.3
        movdqa    %xmm4, %xmm0                                  #131.3
        paddd     64(%rsp), %xmm3                               #131.3
        pslld     $11, %xmm0                                    #131.3
        psrld     $21, %xmm4                                    #131.3
        movdqa    %xmm6, %xmm15                                 #132.3
        por       %xmm4, %xmm0                                  #131.3
        movdqa    %xmm3, %xmm4                                  #131.3
        pslld     $11, %xmm4                                    #131.3
        psrld     $21, %xmm3                                    #131.3
        paddd     %xmm6, %xmm1                                  #131.3
        por       %xmm3, %xmm4                                  #131.3
        movdqa    .L_2il0floatpacket.103(%rip), %xmm3           #132.3
        pxor      %xmm5, %xmm15                                 #132.3
        paddd     %xmm3, %xmm2                                  #132.3
        pxor      %xmm1, %xmm15                                 #132.3
        paddd     %xmm15, %xmm2                                 #132.3
        paddd     %xmm3, %xmm11                                 #132.3
        movdqa    %xmm8, %xmm15                                 #132.3
        paddd     %xmm3, %xmm10                                 #132.3
        movdqa    %xmm14, %xmm3                                 #132.3
        paddd     %xmm8, %xmm0                                  #131.3
        paddd     %xmm14, %xmm4                                 #131.3
        pxor      %xmm12, %xmm15                                #132.3
        pxor      %xmm9, %xmm3                                  #132.3
        pxor      %xmm0, %xmm15                                 #132.3
        paddd     592(%rsp), %xmm2                              #132.3
        pxor      %xmm4, %xmm3                                  #132.3
        paddd     %xmm15, %xmm11                                #132.3
        paddd     %xmm3, %xmm10                                 #132.3
        movdqa    %xmm2, %xmm3                                  #132.3
        psrld     $16, %xmm2                                    #132.3
        paddd     560(%rsp), %xmm11                             #132.3
        pslld     $16, %xmm3                                    #132.3
        por       %xmm2, %xmm3                                  #132.3
        movdqa    %xmm11, %xmm2                                 #132.3
        paddd     544(%rsp), %xmm10                             #132.3
        pslld     $16, %xmm2                                    #132.3
        psrld     $16, %xmm11                                   #132.3
        movdqa    %xmm6, %xmm15                                 #133.3
        por       %xmm11, %xmm2                                 #132.3
        movdqa    %xmm10, %xmm11                                #132.3
        pslld     $16, %xmm11                                   #132.3
        psrld     $16, %xmm10                                   #132.3
        paddd     %xmm1, %xmm3                                  #132.3
        por       %xmm10, %xmm11                                #132.3
        movdqa    .L_2il0floatpacket.104(%rip), %xmm10          #133.3
        pxor      %xmm1, %xmm15                                 #133.3
        paddd     %xmm10, %xmm5                                 #133.3
        pxor      %xmm3, %xmm15                                 #133.3
        paddd     %xmm15, %xmm5                                 #133.3
        paddd     %xmm10, %xmm12                                #133.3
        movdqa    %xmm8, %xmm15                                 #133.3
        paddd     %xmm10, %xmm9                                 #133.3
        movdqa    %xmm14, %xmm10                                #133.3
        paddd     %xmm0, %xmm2                                  #132.3
        paddd     %xmm4, %xmm11                                 #132.3
        pxor      %xmm0, %xmm15                                 #133.3
        pxor      %xmm4, %xmm10                                 #133.3
        pxor      %xmm2, %xmm15                                 #133.3
        paddd     528(%rsp), %xmm5                              #133.3
        pxor      %xmm11, %xmm10                                #133.3
        paddd     %xmm15, %xmm12                                #133.3
        paddd     %xmm10, %xmm9                                 #133.3
        movdqa    %xmm5, %xmm10                                 #133.3
        psrld     $9, %xmm5                                     #133.3
        paddd     496(%rsp), %xmm12                             #133.3
        pslld     $23, %xmm10                                   #133.3
        por       %xmm5, %xmm10                                 #133.3
        movdqa    %xmm12, %xmm5                                 #133.3
        paddd     512(%rsp), %xmm9                              #133.3
        pslld     $23, %xmm5                                    #133.3
        psrld     $9, %xmm12                                    #133.3
        movdqa    %xmm3, %xmm15                                 #134.3
        por       %xmm12, %xmm5                                 #133.3
        movdqa    %xmm9, %xmm12                                 #133.3
        pslld     $23, %xmm12                                   #133.3
        psrld     $9, %xmm9                                     #133.3
        paddd     %xmm3, %xmm10                                 #133.3
        por       %xmm9, %xmm12                                 #133.3
        movdqa    .L_2il0floatpacket.105(%rip), %xmm9           #134.3
        pxor      %xmm1, %xmm15                                 #134.3
        paddd     %xmm9, %xmm6                                  #134.3
        pxor      %xmm10, %xmm15                                #134.3
        paddd     %xmm15, %xmm6                                 #134.3
        paddd     %xmm9, %xmm8                                  #134.3
        movdqa    %xmm2, %xmm15                                 #134.3
        paddd     %xmm9, %xmm14                                 #134.3
        movdqa    %xmm11, %xmm9                                 #134.3
        paddd     %xmm2, %xmm5                                  #133.3
        paddd     %xmm11, %xmm12                                #133.3
        pxor      %xmm0, %xmm15                                 #134.3
        pxor      %xmm4, %xmm9                                  #134.3
        pxor      %xmm5, %xmm15                                 #134.3
        paddd     400(%rsp), %xmm6                              #134.3
        pxor      %xmm12, %xmm9                                 #134.3
        paddd     %xmm15, %xmm8                                 #134.3
        paddd     %xmm9, %xmm14                                 #134.3
        movdqa    %xmm6, %xmm9                                  #134.3
        psrld     $28, %xmm6                                    #134.3
        paddd     464(%rsp), %xmm8                              #134.3
        pslld     $4, %xmm9                                     #134.3
        por       %xmm6, %xmm9                                  #134.3
        movdqa    %xmm8, %xmm6                                  #134.3
        paddd     480(%rsp), %xmm14                             #134.3
        pslld     $4, %xmm6                                     #134.3
        psrld     $28, %xmm8                                    #134.3
        movdqa    %xmm10, %xmm15                                #135.3
        por       %xmm8, %xmm6                                  #134.3
        movdqa    %xmm14, %xmm8                                 #134.3
        pslld     $4, %xmm8                                     #134.3
        psrld     $28, %xmm14                                   #134.3
        paddd     %xmm10, %xmm9                                 #134.3
        por       %xmm14, %xmm8                                 #134.3
        movdqa    .L_2il0floatpacket.106(%rip), %xmm14          #135.3
        pxor      %xmm3, %xmm15                                 #135.3
        paddd     %xmm14, %xmm1                                 #135.3
        pxor      %xmm9, %xmm15                                 #135.3
        paddd     %xmm14, %xmm0                                 #135.3
        paddd     %xmm14, %xmm4                                 #135.3
        movdqa    %xmm12, %xmm14                                #135.3
        paddd     %xmm12, %xmm8                                 #134.3
        paddd     %xmm15, %xmm1                                 #135.3
        movdqa    %xmm5, %xmm15                                 #135.3
        pxor      %xmm11, %xmm14                                #135.3
        paddd     %xmm5, %xmm6                                  #134.3
        pxor      %xmm2, %xmm15                                 #135.3
        pxor      %xmm8, %xmm14                                 #135.3
        paddd     704(%rsp), %xmm1                              #135.3
        pxor      %xmm6, %xmm15                                 #135.3
        paddd     %xmm14, %xmm4                                 #135.3
        paddd     %xmm15, %xmm0                                 #135.3
        paddd     384(%rsp), %xmm4                              #135.3
        movdqa    %xmm1, %xmm14                                 #135.3
        paddd     688(%rsp), %xmm0                              #135.3
        pslld     $11, %xmm14                                   #135.3
        psrld     $21, %xmm1                                    #135.3
        movdqa    %xmm4, %xmm15                                 #135.3
        por       %xmm1, %xmm14                                 #135.3
        movdqa    %xmm0, %xmm1                                  #135.3
        pslld     $11, %xmm15                                   #135.3
        psrld     $21, %xmm4                                    #135.3
        pslld     $11, %xmm1                                    #135.3
        psrld     $21, %xmm0                                    #135.3
        por       %xmm4, %xmm15                                 #135.3
        movdqa    %xmm9, %xmm4                                  #136.3
        paddd     %xmm9, %xmm14                                 #135.3
        por       %xmm0, %xmm1                                  #135.3
        movdqa    .L_2il0floatpacket.107(%rip), %xmm0           #136.3
        pxor      %xmm10, %xmm4                                 #136.3
        paddd     %xmm0, %xmm3                                  #136.3
        pxor      %xmm14, %xmm4                                 #136.3
        paddd     %xmm4, %xmm3                                  #136.3
        paddd     %xmm0, %xmm2                                  #136.3
        movdqa    %xmm6, %xmm4                                  #136.3
        paddd     %xmm0, %xmm11                                 #136.3
        movdqa    %xmm8, %xmm0                                  #136.3
        paddd     %xmm6, %xmm1                                  #135.3
        paddd     %xmm8, %xmm15                                 #135.3
        pxor      %xmm5, %xmm4                                  #136.3
        pxor      %xmm12, %xmm0                                 #136.3
        pxor      %xmm1, %xmm4                                  #136.3
        paddd     256(%rsp), %xmm3                              #136.3
        pxor      %xmm15, %xmm0                                 #136.3
        paddd     %xmm4, %xmm2                                  #136.3
        paddd     %xmm0, %xmm11                                 #136.3
        movdqa    %xmm3, %xmm0                                  #136.3
        psrld     $16, %xmm3                                    #136.3
        paddd     272(%rsp), %xmm2                              #136.3
        pslld     $16, %xmm0                                    #136.3
        por       %xmm3, %xmm0                                  #136.3
        movdqa    %xmm2, %xmm3                                  #136.3
        paddd     288(%rsp), %xmm11                             #136.3
        pslld     $16, %xmm3                                    #136.3
        psrld     $16, %xmm2                                    #136.3
        paddd     %xmm14, %xmm0                                 #136.3
        por       %xmm2, %xmm3                                  #136.3
        movdqa    %xmm11, %xmm2                                 #136.3
        pslld     $16, %xmm2                                    #136.3
        psrld     $16, %xmm11                                   #136.3
        por       %xmm11, %xmm2                                 #136.3
        movdqa    %xmm14, %xmm11                                #137.3
        movdqa    .L_2il0floatpacket.108(%rip), %xmm4           #137.3
        pxor      %xmm9, %xmm11                                 #137.3
        paddd     %xmm4, %xmm10                                 #137.3
        pxor      %xmm0, %xmm11                                 #137.3
        paddd     %xmm11, %xmm10                                #137.3
        movdqa    %xmm1, %xmm11                                 #137.3
        paddd     %xmm1, %xmm3                                  #136.3
        pxor      %xmm6, %xmm11                                 #137.3
        paddd     192(%rsp), %xmm10                             #137.3
        paddd     %xmm4, %xmm5                                  #137.3
        pxor      %xmm3, %xmm11                                 #137.3
        paddd     %xmm4, %xmm12                                 #137.3
        movdqa    %xmm15, %xmm4                                 #137.3
        paddd     %xmm15, %xmm2                                 #136.3
        paddd     %xmm11, %xmm5                                 #137.3
        pxor      %xmm8, %xmm4                                  #137.3
        movdqa    %xmm10, %xmm11                                #137.3
        pxor      %xmm2, %xmm4                                  #137.3
        paddd     176(%rsp), %xmm5                              #137.3
        pslld     $23, %xmm11                                   #137.3
        psrld     $9, %xmm10                                    #137.3
        paddd     %xmm4, %xmm12                                 #137.3
        por       %xmm10, %xmm11                                #137.3
        movdqa    %xmm5, %xmm10                                 #137.3
        paddd     160(%rsp), %xmm12                             #137.3
        pslld     $23, %xmm10                                   #137.3
        psrld     $9, %xmm5                                     #137.3
        movdqa    %xmm0, %xmm4                                  #138.3
        por       %xmm5, %xmm10                                 #137.3
        movdqa    %xmm12, %xmm5                                 #137.3
        pslld     $23, %xmm5                                    #137.3
        psrld     $9, %xmm12                                    #137.3
        paddd     %xmm0, %xmm11                                 #137.3
        por       %xmm12, %xmm5                                 #137.3
        movdqa    .L_2il0floatpacket.109(%rip), %xmm12          #138.3
        pxor      %xmm14, %xmm4                                 #138.3
        paddd     %xmm12, %xmm9                                 #138.3
        pxor      %xmm11, %xmm4                                 #138.3
        paddd     %xmm4, %xmm9                                  #138.3
        paddd     %xmm12, %xmm6                                 #138.3
        movdqa    %xmm3, %xmm4                                  #138.3
        paddd     %xmm12, %xmm8                                 #138.3
        movdqa    %xmm2, %xmm12                                 #138.3
        paddd     %xmm3, %xmm10                                 #137.3
        paddd     %xmm2, %xmm5                                  #137.3
        pxor      %xmm1, %xmm4                                  #138.3
        pxor      %xmm15, %xmm12                                #138.3
        pxor      %xmm10, %xmm4                                 #138.3
        paddd     128(%rsp), %xmm9                              #138.3
        pxor      %xmm5, %xmm12                                 #138.3
        paddd     %xmm4, %xmm6                                  #138.3
        paddd     %xmm12, %xmm8                                 #138.3
        movdqa    %xmm9, %xmm12                                 #138.3
        psrld     $28, %xmm9                                    #138.3
        paddd     208(%rsp), %xmm6                              #138.3
        pslld     $4, %xmm12                                    #138.3
        por       %xmm9, %xmm12                                 #138.3
        movdqa    %xmm6, %xmm9                                  #138.3
        paddd     224(%rsp), %xmm8                              #138.3
        pslld     $4, %xmm9                                     #138.3
        psrld     $28, %xmm6                                    #138.3
        movdqa    %xmm11, %xmm4                                 #139.3
        por       %xmm6, %xmm9                                  #138.3
        movdqa    %xmm8, %xmm6                                  #138.3
        pslld     $4, %xmm6                                     #138.3
        psrld     $28, %xmm8                                    #138.3
        paddd     %xmm11, %xmm12                                #138.3
        por       %xmm8, %xmm6                                  #138.3
        movdqa    .L_2il0floatpacket.110(%rip), %xmm8           #139.3
        pxor      %xmm0, %xmm4                                  #139.3
        paddd     %xmm8, %xmm14                                 #139.3
        pxor      %xmm12, %xmm4                                 #139.3
        paddd     %xmm4, %xmm14                                 #139.3
        movdqa    %xmm10, %xmm4                                 #139.3
        paddd     %xmm10, %xmm9                                 #138.3
        paddd     %xmm8, %xmm1                                  #139.3
        pxor      %xmm3, %xmm4                                  #139.3
        paddd     %xmm8, %xmm15                                 #139.3
        movdqa    %xmm5, %xmm8                                  #139.3
        paddd     %xmm5, %xmm6                                  #138.3
        pxor      %xmm9, %xmm4                                  #139.3
        pxor      %xmm2, %xmm8                                  #139.3
        paddd     624(%rsp), %xmm14                             #139.3
        paddd     %xmm4, %xmm1                                  #139.3
        pxor      %xmm6, %xmm8                                  #139.3
        paddd     608(%rsp), %xmm1                              #139.3
        paddd     %xmm8, %xmm15                                 #139.3
        movdqa    %xmm14, %xmm8                                 #139.3
        psrld     $21, %xmm14                                   #139.3
        paddd     640(%rsp), %xmm15                             #139.3
        pslld     $11, %xmm8                                    #139.3
        movdqa    %xmm1, %xmm4                                  #139.3
        por       %xmm14, %xmm8                                 #139.3
        pslld     $11, %xmm4                                    #139.3
        psrld     $21, %xmm1                                    #139.3
        movdqa    %xmm15, %xmm14                                #139.3
        por       %xmm1, %xmm4                                  #139.3
        pslld     $11, %xmm14                                   #139.3
        psrld     $21, %xmm15                                   #139.3
        movdqa    %xmm12, %xmm1                                 #140.3
        paddd     %xmm12, %xmm8                                 #139.3
        por       %xmm15, %xmm14                                #139.3
        pxor      %xmm11, %xmm1                                 #140.3
        movdqa    .L_2il0floatpacket.111(%rip), %xmm15          #140.3
        pxor      %xmm8, %xmm1                                  #140.3
        paddd     %xmm15, %xmm0                                 #140.3
        paddd     %xmm9, %xmm4                                  #139.3
        paddd     %xmm1, %xmm0                                  #140.3
        movdqa    %xmm9, %xmm1                                  #140.3
        paddd     %xmm15, %xmm3                                 #140.3
        pxor      %xmm10, %xmm1                                 #140.3
        paddd     %xmm15, %xmm2                                 #140.3
        movdqa    %xmm6, %xmm15                                 #140.3
        paddd     %xmm6, %xmm14                                 #139.3
        pxor      %xmm4, %xmm1                                  #140.3
        pxor      %xmm5, %xmm15                                 #140.3
        paddd     %xmm1, %xmm3                                  #140.3
        pxor      %xmm14, %xmm15                                #140.3
        paddd     %xmm13, %xmm3                                 #140.3
        paddd     %xmm15, %xmm2                                 #140.3
        movdqa    %xmm7, 752(%rsp)                              #
        paddd     %xmm7, %xmm2                                  #140.3
        movdqa    %xmm3, %xmm7                                  #140.3
        psrld     $16, %xmm3                                    #140.3
        paddd     576(%rsp), %xmm0                              #140.3
        pslld     $16, %xmm7                                    #140.3
        movdqa    %xmm0, %xmm1                                  #140.3
        por       %xmm3, %xmm7                                  #140.3
        movdqa    %xmm2, %xmm3                                  #140.3
        pslld     $16, %xmm1                                    #140.3
        psrld     $16, %xmm0                                    #140.3
        pslld     $16, %xmm3                                    #140.3
        psrld     $16, %xmm2                                    #140.3
        por       %xmm0, %xmm1                                  #140.3
        movdqa    %xmm4, %xmm0                                  #141.3
        por       %xmm2, %xmm3                                  #140.3
        movdqa    %xmm8, %xmm2                                  #141.3
        paddd     %xmm4, %xmm7                                  #140.3
        movdqa    .L_2il0floatpacket.112(%rip), %xmm15          #141.3
        pxor      %xmm9, %xmm0                                  #141.3
        paddd     %xmm8, %xmm1                                  #140.3
        pxor      %xmm12, %xmm2                                 #141.3
        paddd     %xmm15, %xmm10                                #141.3
        pxor      %xmm7, %xmm0                                  #141.3
        paddd     %xmm15, %xmm11                                #141.3
        pxor      %xmm1, %xmm2                                  #141.3
        paddd     %xmm0, %xmm10                                 #141.3
        movdqa    %xmm14, %xmm0                                 #141.3
        paddd     %xmm2, %xmm11                                 #141.3
        paddd     %xmm14, %xmm3                                 #140.3
        pxor      %xmm6, %xmm0                                  #141.3
        paddd     %xmm15, %xmm5                                 #141.3
        paddd     (%rsp), %xmm11                                #141.3
        pxor      %xmm3, %xmm0                                  #141.3
        paddd     16(%rsp), %xmm10                              #141.3
        movdqa    %xmm11, %xmm2                                 #141.3
        paddd     %xmm0, %xmm5                                  #141.3
        movdqa    %xmm10, %xmm0                                 #141.3
        pslld     $23, %xmm2                                    #141.3
        psrld     $9, %xmm11                                    #141.3
        paddd     32(%rsp), %xmm5                               #141.3
        pslld     $23, %xmm0                                    #141.3
        psrld     $9, %xmm10                                    #141.3
        por       %xmm11, %xmm2                                 #141.3
        por       %xmm10, %xmm0                                 #141.3
        movdqa    %xmm5, %xmm10                                 #141.3
        movdqa    %xmm8, %xmm15                                 #144.3
        pcmpeqd   %xmm11, %xmm11                                #144.3
        paddd     %xmm1, %xmm2                                  #141.3
        pslld     $23, %xmm10                                   #141.3
        psrld     $9, %xmm5                                     #141.3
        pandn     %xmm11, %xmm15                                #144.3
        por       %xmm5, %xmm10                                 #141.3
        por       %xmm2, %xmm15                                 #144.3
        movdqa    .L_2il0floatpacket.113(%rip), %xmm5           #144.3
        pxor      %xmm1, %xmm15                                 #144.3
        paddd     %xmm5, %xmm12                                 #144.3
        paddd     %xmm5, %xmm9                                  #144.3
        paddd     %xmm15, %xmm12                                #144.3
        movdqa    %xmm4, %xmm15                                 #144.3
        paddd     %xmm5, %xmm6                                  #144.3
        movdqa    %xmm14, %xmm5                                 #144.3
        paddd     %xmm7, %xmm0                                  #141.3
        paddd     %xmm3, %xmm10                                 #141.3
        pandn     %xmm11, %xmm15                                #144.3
        pandn     %xmm11, %xmm5                                 #144.3
        por       %xmm0, %xmm15                                 #144.3
        por       %xmm10, %xmm5                                 #144.3
        paddd     704(%rsp), %xmm12                             #144.3
        pxor      %xmm7, %xmm15                                 #144.3
        pxor      %xmm3, %xmm5                                  #144.3
        paddd     %xmm15, %xmm9                                 #144.3
        paddd     %xmm5, %xmm6                                  #144.3
        movdqa    %xmm12, %xmm5                                 #144.3
        paddd     688(%rsp), %xmm9                              #144.3
        pslld     $6, %xmm5                                     #144.3
        psrld     $26, %xmm12                                   #144.3
        movdqa    %xmm1, %xmm15                                 #145.3
        por       %xmm12, %xmm5                                 #144.3
        movdqa    %xmm9, %xmm12                                 #144.3
        paddd     384(%rsp), %xmm6                              #144.3
        pslld     $6, %xmm12                                    #144.3
        psrld     $26, %xmm9                                    #144.3
        paddd     %xmm2, %xmm5                                  #144.3
        por       %xmm9, %xmm12                                 #144.3
        movdqa    %xmm6, %xmm9                                  #144.3
        pslld     $6, %xmm9                                     #144.3
        psrld     $26, %xmm6                                    #144.3
        pandn     %xmm11, %xmm15                                #145.3
        por       %xmm6, %xmm9                                  #144.3
        movdqa    .L_2il0floatpacket.114(%rip), %xmm6           #145.3
        por       %xmm5, %xmm15                                 #145.3
        paddd     %xmm6, %xmm8                                  #145.3
        pxor      %xmm2, %xmm15                                 #145.3
        paddd     %xmm15, %xmm8                                 #145.3
        paddd     %xmm6, %xmm4                                  #145.3
        movdqa    %xmm7, %xmm15                                 #145.3
        paddd     %xmm6, %xmm14                                 #145.3
        movdqa    %xmm3, %xmm6                                  #145.3
        paddd     %xmm0, %xmm12                                 #144.3
        paddd     %xmm10, %xmm9                                 #144.3
        pandn     %xmm11, %xmm15                                #145.3
        pandn     %xmm11, %xmm6                                 #145.3
        por       %xmm12, %xmm15                                #145.3
        por       %xmm9, %xmm6                                  #145.3
        pxor      %xmm0, %xmm15                                 #145.3
        paddd     592(%rsp), %xmm8                              #145.3
        pxor      %xmm10, %xmm6                                 #145.3
        paddd     %xmm15, %xmm4                                 #145.3
        paddd     %xmm6, %xmm14                                 #145.3
        movdqa    %xmm8, %xmm6                                  #145.3
        psrld     $22, %xmm8                                    #145.3
        paddd     560(%rsp), %xmm4                              #145.3
        pslld     $10, %xmm6                                    #145.3
        por       %xmm8, %xmm6                                  #145.3
        movdqa    %xmm4, %xmm8                                  #145.3
        paddd     544(%rsp), %xmm14                             #145.3
        pslld     $10, %xmm8                                    #145.3
        psrld     $22, %xmm4                                    #145.3
        movdqa    %xmm2, %xmm15                                 #146.3
        por       %xmm4, %xmm8                                  #145.3
        movdqa    %xmm14, %xmm4                                 #145.3
        paddd     %xmm5, %xmm6                                  #145.3
        pslld     $10, %xmm4                                    #145.3
        psrld     $22, %xmm14                                   #145.3
        pandn     %xmm11, %xmm15                                #146.3
        por       %xmm14, %xmm4                                 #145.3
        por       %xmm6, %xmm15                                 #146.3
        movdqa    .L_2il0floatpacket.115(%rip), %xmm14          #146.3
        pxor      %xmm5, %xmm15                                 #146.3
        paddd     %xmm14, %xmm1                                 #146.3
        paddd     %xmm14, %xmm7                                 #146.3
        paddd     %xmm15, %xmm1                                 #146.3
        movdqa    %xmm0, %xmm15                                 #146.3
        paddd     %xmm14, %xmm3                                 #146.3
        movdqa    %xmm10, %xmm14                                #146.3
        paddd     %xmm12, %xmm8                                 #145.3
        paddd     %xmm9, %xmm4                                  #145.3
        pandn     %xmm11, %xmm15                                #146.3
        pandn     %xmm11, %xmm14                                #146.3
        por       %xmm8, %xmm15                                 #146.3
        por       %xmm4, %xmm14                                 #146.3
        paddd     672(%rsp), %xmm1                              #146.3
        pxor      %xmm12, %xmm15                                #146.3
        pxor      %xmm9, %xmm14                                 #146.3
        paddd     %xmm15, %xmm7                                 #146.3
        paddd     %xmm14, %xmm3                                 #146.3
        movdqa    %xmm1, %xmm14                                 #146.3
        paddd     656(%rsp), %xmm7                              #146.3
        pslld     $15, %xmm14                                   #146.3
        psrld     $17, %xmm1                                    #146.3
        por       %xmm1, %xmm14                                 #146.3
        movdqa    %xmm7, %xmm1                                  #146.3
        paddd     720(%rsp), %xmm3                              #146.3
        pslld     $15, %xmm1                                    #146.3
        psrld     $17, %xmm7                                    #146.3
        movdqa    %xmm3, %xmm15                                 #146.3
        por       %xmm7, %xmm1                                  #146.3
        movdqa    %xmm5, %xmm7                                  #147.3
        paddd     %xmm6, %xmm14                                 #146.3
        pslld     $15, %xmm15                                   #146.3
        psrld     $17, %xmm3                                    #146.3
        pandn     %xmm11, %xmm7                                 #147.3
        por       %xmm3, %xmm15                                 #146.3
        por       %xmm14, %xmm7                                 #147.3
        movdqa    .L_2il0floatpacket.116(%rip), %xmm3           #147.3
        pxor      %xmm6, %xmm7                                  #147.3
        paddd     %xmm3, %xmm2                                  #147.3
        paddd     %xmm8, %xmm1                                  #146.3
        paddd     %xmm4, %xmm15                                 #146.3
        paddd     %xmm7, %xmm2                                  #147.3
        movdqa    752(%rsp), %xmm7                              #147.3
                                # LOE rbx rbp rsi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm12 xmm13 xmm14 xmm15
..B6.8:                         # Preds ..B6.9
        movdqa    %xmm7, 752(%rsp)                              #
        paddd     %xmm3, %xmm0                                  #147.3
        movdqa    %xmm12, %xmm11                                #147.3
        pcmpeqd   %xmm7, %xmm7                                  #147.3
        paddd     %xmm3, %xmm10                                 #147.3
        movdqa    %xmm9, %xmm3                                  #147.3
        pandn     %xmm7, %xmm11                                 #147.3
        pandn     %xmm7, %xmm3                                  #147.3
        por       %xmm1, %xmm11                                 #147.3
        por       %xmm15, %xmm3                                 #147.3
        paddd     432(%rsp), %xmm2                              #147.3
        pxor      %xmm8, %xmm11                                 #147.3
        pxor      %xmm4, %xmm3                                  #147.3
        paddd     %xmm11, %xmm0                                 #147.3
        paddd     %xmm3, %xmm10                                 #147.3
        movdqa    %xmm2, %xmm3                                  #147.3
        paddd     448(%rsp), %xmm0                              #147.3
        pslld     $21, %xmm3                                    #147.3
        psrld     $11, %xmm2                                    #147.3
        movdqa    %xmm6, %xmm11                                 #148.3
        por       %xmm2, %xmm3                                  #147.3
        movdqa    %xmm0, %xmm2                                  #147.3
        paddd     416(%rsp), %xmm10                             #147.3
        pslld     $21, %xmm2                                    #147.3
        psrld     $11, %xmm0                                    #147.3
        paddd     %xmm14, %xmm3                                 #147.3
        por       %xmm0, %xmm2                                  #147.3
        movdqa    %xmm10, %xmm0                                 #147.3
        pslld     $21, %xmm0                                    #147.3
        psrld     $11, %xmm10                                   #147.3
        pandn     %xmm7, %xmm11                                 #148.3
        por       %xmm10, %xmm0                                 #147.3
        movdqa    .L_2il0floatpacket.117(%rip), %xmm10          #148.3
        por       %xmm3, %xmm11                                 #148.3
        paddd     %xmm10, %xmm5                                 #148.3
        pxor      %xmm14, %xmm11                                #148.3
        paddd     %xmm11, %xmm5                                 #148.3
        paddd     %xmm10, %xmm12                                #148.3
        movdqa    %xmm8, %xmm11                                 #148.3
        paddd     %xmm10, %xmm9                                 #148.3
        movdqa    %xmm4, %xmm10                                 #148.3
        paddd     %xmm1, %xmm2                                  #147.3
        paddd     %xmm15, %xmm0                                 #147.3
        pandn     %xmm7, %xmm11                                 #148.3
        pandn     %xmm7, %xmm10                                 #148.3
        por       %xmm2, %xmm11                                 #148.3
        por       %xmm0, %xmm10                                 #148.3
        pxor      %xmm1, %xmm11                                 #148.3
        paddd     624(%rsp), %xmm5                              #148.3
        pxor      %xmm15, %xmm10                                #148.3
        paddd     %xmm11, %xmm12                                #148.3
        paddd     %xmm10, %xmm9                                 #148.3
        movdqa    %xmm5, %xmm10                                 #148.3
        psrld     $26, %xmm5                                    #148.3
        paddd     608(%rsp), %xmm12                             #148.3
        pslld     $6, %xmm10                                    #148.3
        por       %xmm5, %xmm10                                 #148.3
        movdqa    %xmm12, %xmm5                                 #148.3
        paddd     640(%rsp), %xmm9                              #148.3
        pslld     $6, %xmm5                                     #148.3
        psrld     $26, %xmm12                                   #148.3
        paddd     %xmm3, %xmm10                                 #148.3
        por       %xmm12, %xmm5                                 #148.3
        movdqa    %xmm9, %xmm12                                 #148.3
        pslld     $6, %xmm12                                    #148.3
        psrld     $26, %xmm9                                    #148.3
        por       %xmm9, %xmm12                                 #148.3
        movdqa    %xmm14, %xmm9                                 #149.3
        pandn     %xmm7, %xmm9                                  #149.3
        paddd     %xmm2, %xmm5                                  #148.3
        movdqa    .L_2il0floatpacket.118(%rip), %xmm11          #149.3
        por       %xmm10, %xmm9                                 #149.3
        paddd     %xmm11, %xmm6                                 #149.3
        pxor      %xmm3, %xmm9                                  #149.3
        paddd     %xmm9, %xmm6                                  #149.3
        movdqa    %xmm1, %xmm9                                  #149.3
        pandn     %xmm7, %xmm9                                  #149.3
        paddd     %xmm11, %xmm8                                 #149.3
        por       %xmm5, %xmm9                                  #149.3
        paddd     %xmm11, %xmm4                                 #149.3
        movdqa    %xmm15, %xmm11                                #149.3
        paddd     %xmm0, %xmm12                                 #148.3
        paddd     256(%rsp), %xmm6                              #149.3
        pxor      %xmm2, %xmm9                                  #149.3
        pandn     %xmm7, %xmm11                                 #149.3
        paddd     %xmm9, %xmm8                                  #149.3
        por       %xmm12, %xmm11                                #149.3
        movdqa    %xmm6, %xmm9                                  #149.3
        paddd     272(%rsp), %xmm8                              #149.3
        pxor      %xmm0, %xmm11                                 #149.3
        pslld     $10, %xmm9                                    #149.3
        psrld     $22, %xmm6                                    #149.3
        paddd     %xmm11, %xmm4                                 #149.3
        por       %xmm6, %xmm9                                  #149.3
        movdqa    %xmm8, %xmm6                                  #149.3
        psrld     $22, %xmm8                                    #149.3
        paddd     288(%rsp), %xmm4                              #149.3
        pslld     $10, %xmm6                                    #149.3
        por       %xmm8, %xmm6                                  #149.3
        movdqa    %xmm4, %xmm8                                  #149.3
        movdqa    %xmm3, %xmm11                                 #150.3
        paddd     %xmm10, %xmm9                                 #149.3
        pslld     $10, %xmm8                                    #149.3
        psrld     $22, %xmm4                                    #149.3
        pandn     %xmm7, %xmm11                                 #150.3
        por       %xmm4, %xmm8                                  #149.3
        movdqa    .L_2il0floatpacket.119(%rip), %xmm4           #150.3
        por       %xmm9, %xmm11                                 #150.3
        paddd     %xmm4, %xmm14                                 #150.3
        pxor      %xmm10, %xmm11                                #150.3
        paddd     %xmm11, %xmm14                                #150.3
        paddd     %xmm4, %xmm1                                  #150.3
        movdqa    %xmm2, %xmm11                                 #150.3
        paddd     %xmm4, %xmm15                                 #150.3
        movdqa    %xmm0, %xmm4                                  #150.3
        paddd     %xmm5, %xmm6                                  #149.3
        paddd     %xmm12, %xmm8                                 #149.3
        pandn     %xmm7, %xmm11                                 #150.3
        pandn     %xmm7, %xmm4                                  #150.3
        por       %xmm6, %xmm11                                 #150.3
        por       %xmm8, %xmm4                                  #150.3
        pxor      %xmm5, %xmm11                                 #150.3
        paddd     528(%rsp), %xmm14                             #150.3
        pxor      %xmm12, %xmm4                                 #150.3
        paddd     %xmm11, %xmm1                                 #150.3
        paddd     %xmm4, %xmm15                                 #150.3
        movdqa    %xmm14, %xmm4                                 #150.3
        psrld     $17, %xmm14                                   #150.3
        paddd     496(%rsp), %xmm1                              #150.3
        pslld     $15, %xmm4                                    #150.3
        por       %xmm14, %xmm4                                 #150.3
        movdqa    %xmm1, %xmm14                                 #150.3
        paddd     512(%rsp), %xmm15                             #150.3
        pslld     $15, %xmm14                                   #150.3
        psrld     $17, %xmm1                                    #150.3
        movdqa    %xmm10, %xmm11                                #151.3
        por       %xmm1, %xmm14                                 #150.3
        movdqa    %xmm15, %xmm1                                 #150.3
        paddd     %xmm9, %xmm4                                  #150.3
        pslld     $15, %xmm1                                    #150.3
        psrld     $17, %xmm15                                   #150.3
        pandn     %xmm7, %xmm11                                 #151.3
        por       %xmm15, %xmm1                                 #150.3
        por       %xmm4, %xmm11                                 #151.3
        movdqa    .L_2il0floatpacket.120(%rip), %xmm15          #151.3
        pxor      %xmm9, %xmm11                                 #151.3
        paddd     %xmm15, %xmm3                                 #151.3
        paddd     %xmm6, %xmm14                                 #150.3
        paddd     %xmm11, %xmm3                                 #151.3
        movdqa    %xmm5, %xmm11                                 #151.3
        pandn     %xmm7, %xmm11                                 #151.3
        paddd     %xmm15, %xmm2                                 #151.3
        por       %xmm14, %xmm11                                #151.3
        paddd     %xmm15, %xmm0                                 #151.3
        movdqa    %xmm12, %xmm15                                #151.3
        paddd     %xmm8, %xmm1                                  #150.3
        pxor      %xmm6, %xmm11                                 #151.3
        pandn     %xmm7, %xmm15                                 #151.3
        paddd     %xmm11, %xmm2                                 #151.3
        por       %xmm1, %xmm15                                 #151.3
        paddd     144(%rsp), %xmm3                              #151.3
        pxor      %xmm8, %xmm15                                 #151.3
        paddd     112(%rsp), %xmm2                              #151.3
        paddd     %xmm15, %xmm0                                 #151.3
        movdqa    %xmm3, %xmm11                                 #151.3
        movdqa    %xmm2, %xmm15                                 #151.3
        paddd     96(%rsp), %xmm0                               #151.3
        pslld     $21, %xmm11                                   #151.3
        psrld     $11, %xmm3                                    #151.3
        pslld     $21, %xmm15                                   #151.3
        psrld     $11, %xmm2                                    #151.3
        por       %xmm3, %xmm11                                 #151.3
        por       %xmm2, %xmm15                                 #151.3
        movdqa    %xmm0, %xmm2                                  #151.3
        movdqa    %xmm9, %xmm3                                  #152.3
        paddd     %xmm4, %xmm11                                 #151.3
        pslld     $21, %xmm2                                    #151.3
        psrld     $11, %xmm0                                    #151.3
        pandn     %xmm7, %xmm3                                  #152.3
        por       %xmm0, %xmm2                                  #151.3
        movdqa    .L_2il0floatpacket.121(%rip), %xmm0           #152.3
        por       %xmm11, %xmm3                                 #152.3
        paddd     %xmm0, %xmm10                                 #152.3
        pxor      %xmm4, %xmm3                                  #152.3
        paddd     %xmm3, %xmm10                                 #152.3
        paddd     %xmm0, %xmm5                                  #152.3
        movdqa    %xmm6, %xmm3                                  #152.3
        paddd     %xmm0, %xmm12                                 #152.3
        movdqa    %xmm8, %xmm0                                  #152.3
        paddd     %xmm14, %xmm15                                #151.3
        paddd     %xmm1, %xmm2                                  #151.3
        pandn     %xmm7, %xmm3                                  #152.3
        pandn     %xmm7, %xmm0                                  #152.3
        por       %xmm15, %xmm3                                 #152.3
        por       %xmm2, %xmm0                                  #152.3
        pxor      %xmm14, %xmm3                                 #152.3
        paddd     368(%rsp), %xmm10                             #152.3
        pxor      %xmm1, %xmm0                                  #152.3
        paddd     %xmm3, %xmm5                                  #152.3
        paddd     %xmm0, %xmm12                                 #152.3
        movdqa    %xmm10, %xmm0                                 #152.3
        psrld     $26, %xmm10                                   #152.3
        paddd     352(%rsp), %xmm5                              #152.3
        pslld     $6, %xmm0                                     #152.3
        por       %xmm10, %xmm0                                 #152.3
        movdqa    %xmm5, %xmm10                                 #152.3
        paddd     336(%rsp), %xmm12                             #152.3
        pslld     $6, %xmm10                                    #152.3
        psrld     $26, %xmm5                                    #152.3
        paddd     %xmm11, %xmm0                                 #152.3
        por       %xmm5, %xmm10                                 #152.3
        movdqa    %xmm12, %xmm5                                 #152.3
        pslld     $6, %xmm5                                     #152.3
        psrld     $26, %xmm12                                   #152.3
        por       %xmm12, %xmm5                                 #152.3
        movdqa    %xmm4, %xmm12                                 #153.3
        pandn     %xmm7, %xmm12                                 #153.3
        paddd     %xmm15, %xmm10                                #152.3
        movdqa    .L_2il0floatpacket.122(%rip), %xmm3           #153.3
        por       %xmm0, %xmm12                                 #153.3
        paddd     %xmm3, %xmm9                                  #153.3
        pxor      %xmm11, %xmm12                                #153.3
        paddd     %xmm12, %xmm9                                 #153.3
        movdqa    %xmm14, %xmm12                                #153.3
        pandn     %xmm7, %xmm12                                 #153.3
        paddd     %xmm3, %xmm6                                  #153.3
        por       %xmm10, %xmm12                                #153.3
        paddd     %xmm2, %xmm5                                  #152.3
        pxor      %xmm15, %xmm12                                #153.3
        paddd     %xmm3, %xmm8                                  #153.3
        paddd     576(%rsp), %xmm9                              #153.3
        paddd     %xmm12, %xmm6                                 #153.3
        paddd     %xmm13, %xmm6                                 #153.3
        movdqa    %xmm1, %xmm13                                 #153.3
        movdqa    %xmm9, %xmm12                                 #153.3
        pandn     %xmm7, %xmm13                                 #153.3
        pslld     $10, %xmm12                                   #153.3
        psrld     $22, %xmm9                                    #153.3
        por       %xmm5, %xmm13                                 #153.3
        por       %xmm9, %xmm12                                 #153.3
        movdqa    %xmm6, %xmm9                                  #153.3
        pxor      %xmm2, %xmm13                                 #153.3
        pslld     $10, %xmm9                                    #153.3
        psrld     $22, %xmm6                                    #153.3
        paddd     %xmm13, %xmm8                                 #153.3
        por       %xmm6, %xmm9                                  #153.3
        movdqa    %xmm11, %xmm6                                 #154.3
        paddd     %xmm0, %xmm12                                 #153.3
        paddd     752(%rsp), %xmm8                              #153.3
        pandn     %xmm7, %xmm6                                  #154.3
        movdqa    .L_2il0floatpacket.123(%rip), %xmm3           #154.3
        movdqa    %xmm8, %xmm13                                 #153.3
        por       %xmm12, %xmm6                                 #154.3
        pslld     $10, %xmm13                                   #153.3
        psrld     $22, %xmm8                                    #153.3
        paddd     %xmm3, %xmm4                                  #154.3
        pxor      %xmm0, %xmm6                                  #154.3
        por       %xmm8, %xmm13                                 #153.3
        paddd     %xmm6, %xmm4                                  #154.3
        movdqa    %xmm15, %xmm8                                 #154.3
        movdqa    %xmm2, %xmm6                                  #154.3
        paddd     %xmm10, %xmm9                                 #153.3
        paddd     %xmm5, %xmm13                                 #153.3
        pandn     %xmm7, %xmm8                                  #154.3
        pandn     %xmm7, %xmm6                                  #154.3
        por       %xmm9, %xmm8                                  #154.3
        por       %xmm13, %xmm6                                 #154.3
        paddd     %xmm3, %xmm14                                 #154.3
        paddd     192(%rsp), %xmm4                              #154.3
        pxor      %xmm10, %xmm8                                 #154.3
        paddd     %xmm3, %xmm1                                  #154.3
        pxor      %xmm5, %xmm6                                  #154.3
        paddd     %xmm8, %xmm14                                 #154.3
        paddd     %xmm6, %xmm1                                  #154.3
        movdqa    %xmm4, %xmm6                                  #154.3
        psrld     $17, %xmm4                                    #154.3
        paddd     176(%rsp), %xmm14                             #154.3
        pslld     $15, %xmm6                                    #154.3
        por       %xmm4, %xmm6                                  #154.3
        movdqa    %xmm14, %xmm4                                 #154.3
        paddd     160(%rsp), %xmm1                              #154.3
        pslld     $15, %xmm4                                    #154.3
        psrld     $17, %xmm14                                   #154.3
        paddd     %xmm12, %xmm6                                 #154.3
        por       %xmm14, %xmm4                                 #154.3
        movdqa    %xmm1, %xmm14                                 #154.3
        pslld     $15, %xmm14                                   #154.3
        psrld     $17, %xmm1                                    #154.3
        por       %xmm1, %xmm14                                 #154.3
        movdqa    %xmm0, %xmm1                                  #155.3
        pandn     %xmm7, %xmm1                                  #155.3
        paddd     %xmm13, %xmm14                                #154.3
        movdqa    .L_2il0floatpacket.124(%rip), %xmm8           #155.3
        por       %xmm6, %xmm1                                  #155.3
        paddd     %xmm8, %xmm11                                 #155.3
        pxor      %xmm12, %xmm1                                 #155.3
        paddd     %xmm1, %xmm11                                 #155.3
        movdqa    %xmm5, %xmm1                                  #155.3
        pandn     %xmm7, %xmm1                                  #155.3
        paddd     %xmm8, %xmm2                                  #155.3
        por       %xmm14, %xmm1                                 #155.3
        movdqa    %xmm10, %xmm3                                 #155.3
        pxor      %xmm13, %xmm1                                 #155.3
        paddd     %xmm9, %xmm4                                  #154.3
        paddd     %xmm1, %xmm2                                  #155.3
        pandn     %xmm7, %xmm3                                  #155.3
        paddd     400(%rsp), %xmm11                             #155.3
        paddd     %xmm8, %xmm15                                 #155.3
        paddd     480(%rsp), %xmm2                              #155.3
        por       %xmm4, %xmm3                                  #155.3
        movdqa    %xmm11, %xmm8                                 #155.3
        movdqa    %xmm2, %xmm1                                  #155.3
        pxor      %xmm9, %xmm3                                  #155.3
        pslld     $21, %xmm8                                    #155.3
        psrld     $11, %xmm11                                   #155.3
        pslld     $21, %xmm1                                    #155.3
        psrld     $11, %xmm2                                    #155.3
        paddd     %xmm3, %xmm15                                 #155.3
        por       %xmm11, %xmm8                                 #155.3
        por       %xmm2, %xmm1                                  #155.3
        movdqa    %xmm12, %xmm2                                 #156.3
        paddd     %xmm6, %xmm8                                  #155.3
        paddd     464(%rsp), %xmm15                             #155.3
        pandn     %xmm7, %xmm2                                  #156.3
        movdqa    .L_2il0floatpacket.125(%rip), %xmm11          #156.3
        movdqa    %xmm15, %xmm3                                 #155.3
        por       %xmm8, %xmm2                                  #156.3
        pslld     $21, %xmm3                                    #155.3
        psrld     $11, %xmm15                                   #155.3
        paddd     %xmm11, %xmm0                                 #156.3
        pxor      %xmm6, %xmm2                                  #156.3
        por       %xmm15, %xmm3                                 #155.3
        paddd     %xmm2, %xmm0                                  #156.3
        movdqa    %xmm9, %xmm15                                 #156.3
        movdqa    %xmm13, %xmm2                                 #156.3
        paddd     %xmm4, %xmm3                                  #155.3
        paddd     %xmm14, %xmm1                                 #155.3
        pandn     %xmm7, %xmm15                                 #156.3
        pandn     %xmm7, %xmm2                                  #156.3
        por       %xmm3, %xmm15                                 #156.3
        por       %xmm1, %xmm2                                  #156.3
        paddd     %xmm11, %xmm10                                #156.3
        paddd     48(%rsp), %xmm0                               #156.3
        pxor      %xmm4, %xmm15                                 #156.3
        paddd     %xmm11, %xmm5                                 #156.3
        pxor      %xmm14, %xmm2                                 #156.3
        paddd     %xmm15, %xmm10                                #156.3
        paddd     %xmm2, %xmm5                                  #156.3
        movdqa    %xmm0, %xmm15                                 #156.3
        psrld     $26, %xmm0                                    #156.3
        paddd     64(%rsp), %xmm5                               #156.3
        pslld     $6, %xmm15                                    #156.3
        por       %xmm0, %xmm15                                 #156.3
        movdqa    %xmm5, %xmm0                                  #156.3
        paddd     80(%rsp), %xmm10                              #156.3
        pslld     $6, %xmm0                                     #156.3
        psrld     $26, %xmm5                                    #156.3
        movdqa    %xmm10, %xmm2                                 #156.3
        por       %xmm5, %xmm0                                  #156.3
        movdqa    %xmm6, %xmm5                                  #157.3
        paddd     %xmm8, %xmm15                                 #156.3
        pslld     $6, %xmm2                                     #156.3
        psrld     $26, %xmm10                                   #156.3
        pandn     %xmm7, %xmm5                                  #157.3
        movdqa    .L_2il0floatpacket.126(%rip), %xmm11          #157.3
        por       %xmm10, %xmm2                                 #156.3
        por       %xmm15, %xmm5                                 #157.3
        movdqa    %xmm4, %xmm10                                 #157.3
        paddd     %xmm3, %xmm2                                  #156.3
        paddd     %xmm11, %xmm12                                #157.3
        pxor      %xmm8, %xmm5                                  #157.3
        pandn     %xmm7, %xmm10                                 #157.3
        paddd     %xmm5, %xmm12                                 #157.3
        por       %xmm2, %xmm10                                 #157.3
        movdqa    %xmm14, %xmm5                                 #157.3
        paddd     %xmm1, %xmm0                                  #156.3
        paddd     %xmm11, %xmm9                                 #157.3
        pxor      %xmm3, %xmm10                                 #157.3
        pandn     %xmm7, %xmm5                                  #157.3
        paddd     %xmm10, %xmm9                                 #157.3
        por       %xmm0, %xmm5                                  #157.3
        paddd     %xmm11, %xmm13                                #157.3
        paddd     240(%rsp), %xmm12                             #157.3
        pxor      %xmm1, %xmm5                                  #157.3
        paddd     304(%rsp), %xmm9                              #157.3
        paddd     %xmm5, %xmm13                                 #157.3
        movdqa    %xmm12, %xmm11                                #157.3
        movdqa    %xmm9, %xmm10                                 #157.3
        paddd     320(%rsp), %xmm13                             #157.3
        pslld     $10, %xmm11                                   #157.3
        psrld     $22, %xmm12                                   #157.3
        pslld     $10, %xmm10                                   #157.3
        psrld     $22, %xmm9                                    #157.3
        por       %xmm12, %xmm11                                #157.3
        por       %xmm9, %xmm10                                 #157.3
        movdqa    %xmm13, %xmm5                                 #157.3
        movdqa    %xmm8, %xmm9                                  #158.3
        paddd     %xmm15, %xmm11                                #157.3
        pslld     $10, %xmm5                                    #157.3
        psrld     $22, %xmm13                                   #157.3
        pandn     %xmm7, %xmm9                                  #158.3
        por       %xmm13, %xmm5                                 #157.3
        movdqa    .L_2il0floatpacket.127(%rip), %xmm13          #158.3
        por       %xmm11, %xmm9                                 #158.3
        paddd     %xmm13, %xmm6                                 #158.3
        pxor      %xmm15, %xmm9                                 #158.3
        paddd     %xmm9, %xmm6                                  #158.3
        movdqa    %xmm3, %xmm12                                 #158.3
        movdqa    %xmm1, %xmm9                                  #158.3
        paddd     %xmm2, %xmm10                                 #157.3
        paddd     %xmm0, %xmm5                                  #157.3
        pandn     %xmm7, %xmm12                                 #158.3
        pandn     %xmm7, %xmm9                                  #158.3
        por       %xmm10, %xmm12                                #158.3
        por       %xmm5, %xmm9                                  #158.3
        paddd     %xmm13, %xmm4                                 #158.3
        paddd     (%rsp), %xmm6                                 #158.3
        pxor      %xmm2, %xmm12                                 #158.3
        paddd     %xmm13, %xmm14                                #158.3
        pxor      %xmm0, %xmm9                                  #158.3
        paddd     %xmm12, %xmm4                                 #158.3
        paddd     %xmm9, %xmm14                                 #158.3
        movdqa    %xmm6, %xmm9                                  #158.3
        psrld     $17, %xmm6                                    #158.3
        paddd     16(%rsp), %xmm4                               #158.3
        pslld     $15, %xmm9                                    #158.3
        por       %xmm6, %xmm9                                  #158.3
        movdqa    %xmm4, %xmm6                                  #158.3
        paddd     32(%rsp), %xmm14                              #158.3
        pslld     $15, %xmm6                                    #158.3
        psrld     $17, %xmm4                                    #158.3
        paddd     %xmm11, %xmm9                                 #158.3
        por       %xmm4, %xmm6                                  #158.3
        movdqa    %xmm14, %xmm4                                 #158.3
        pslld     $15, %xmm4                                    #158.3
        psrld     $17, %xmm14                                   #158.3
        por       %xmm14, %xmm4                                 #158.3
        movdqa    %xmm15, %xmm14                                #159.3
        pandn     %xmm7, %xmm14                                 #159.3
        movdqa    %xmm2, %xmm12                                 #159.3
        movdqa    .L_2il0floatpacket.128(%rip), %xmm13          #159.3
        paddd     %xmm10, %xmm6                                 #158.3
        por       %xmm9, %xmm14                                 #159.3
        pandn     %xmm7, %xmm12                                 #159.3
        paddd     %xmm13, %xmm8                                 #159.3
        pxor      %xmm11, %xmm14                                #159.3
        por       %xmm6, %xmm12                                 #159.3
        paddd     %xmm14, %xmm8                                 #159.3
        paddd     %xmm13, %xmm3                                 #159.3
        pxor      %xmm10, %xmm12                                #159.3
        paddd     128(%rsp), %xmm8                              #159.3
        paddd     %xmm12, %xmm3                                 #159.3
        movdqa    %xmm0, %xmm12                                 #159.3
        paddd     %xmm5, %xmm4                                  #158.3
        pandn     %xmm7, %xmm12                                 #159.3
        movdqa    %xmm8, %xmm7                                  #159.3
        pslld     $21, %xmm7                                    #159.3
        psrld     $11, %xmm8                                    #159.3
        por       %xmm8, %xmm7                                  #159.3
        por       %xmm4, %xmm12                                 #159.3
        paddd     %xmm9, %xmm7                                  #159.3
        paddd     %xmm13, %xmm1                                 #159.3
        pxor      %xmm5, %xmm12                                 #159.3
        paddd     208(%rsp), %xmm3                              #159.3
        paddd     %xmm12, %xmm1                                 #159.3
        paddd     .L_2il0floatpacket.62(%rip), %xmm7            #163.10
        movdqa    .L_2il0floatpacket.61(%rip), %xmm12           #162.10
        paddd     .L_2il0floatpacket.63(%rip), %xmm9            #164.10
        paddd     %xmm12, %xmm15                                #162.10
        paddd     .L_2il0floatpacket.64(%rip), %xmm11           #165.10
        paddd     %xmm12, %xmm2                                 #162.10
        movdqa    %xmm7, 16(%rsi)                               #56.6
        movdqa    %xmm3, %xmm7                                  #159.3
        paddd     224(%rsp), %xmm1                              #159.3
        pslld     $21, %xmm7                                    #159.3
        movdqa    %xmm15, (%rsi)                                #56.6
        psrld     $11, %xmm3                                    #159.3
        movdqa    %xmm9, 32(%rsi)                               #56.6
        movdqa    %xmm11, 48(%rsi)                              #56.6
                                # LOE rbx rbp rsi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm10
..B6.7:                         # Preds ..B6.8
        movdqa    %xmm2, 64(%rsi)                               #56.6
        movdqa    %xmm1, %xmm2                                  #159.3
        pslld     $21, %xmm2                                    #159.3
        psrld     $11, %xmm1                                    #159.3
        por       %xmm3, %xmm7                                  #159.3
        por       %xmm1, %xmm2                                  #159.3
        movdqa    .L_2il0floatpacket.62(%rip), %xmm3            #163.10
        paddd     %xmm6, %xmm7                                  #159.3
        movdqa    .L_2il0floatpacket.63(%rip), %xmm8            #164.10
        paddd     %xmm4, %xmm2                                  #159.3
        movdqa    .L_2il0floatpacket.64(%rip), %xmm9            #165.10
        paddd     %xmm3, %xmm7                                  #163.10
        paddd     .L_2il0floatpacket.61(%rip), %xmm0            #162.10
        paddd     %xmm8, %xmm6                                  #164.10
        paddd     %xmm9, %xmm10                                 #165.10
        paddd     %xmm3, %xmm2                                  #163.10
        paddd     %xmm8, %xmm4                                  #164.10
        paddd     %xmm9, %xmm5                                  #165.10
        movdqa    %xmm7, 80(%rsi)                               #56.6
        movdqa    %xmm6, 96(%rsi)                               #56.6
        movdqa    %xmm10, 112(%rsi)                             #56.6
        movdqa    %xmm0, 128(%rsi)                              #56.6
        movdqa    %xmm2, 144(%rsi)                              #56.6
        movdqa    %xmm4, 160(%rsi)                              #56.6
        movdqa    %xmm5, 176(%rsi)                              #56.6
        addq      $776, %rsp                                    #171.1
..___tag_value_SSEmd5body.101:                                  #
        ret                                                     #171.1
        .align    16,0x90
..___tag_value_SSEmd5body.102:                                  #
                                # LOE
# mark_end;
	.type	SSEmd5body,@function
	.size	SSEmd5body,.-SSEmd5body
	.data
# -- End  SSEmd5body
	.text
# -- Begin  md5cryptsse
# mark_begin;
       .align    16,0x90
	.globl md5cryptsse
md5cryptsse:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B7.1:                         # Preds ..B7.0
..___tag_value_md5cryptsse.103:                                 #305.1
        pushq     %r12                                          #305.1
..___tag_value_md5cryptsse.105:                                 #
        pushq     %r13                                          #305.1
..___tag_value_md5cryptsse.107:                                 #
        pushq     %r14                                          #305.1
..___tag_value_md5cryptsse.109:                                 #
        pushq     %r15                                          #305.1
..___tag_value_md5cryptsse.111:                                 #
        pushq     %rbx                                          #305.1
..___tag_value_md5cryptsse.113:                                 #
        pushq     %rbp                                          #305.1
..___tag_value_md5cryptsse.115:                                 #
        subq      $6824, %rsp                                   #305.1
..___tag_value_md5cryptsse.117:                                 #
        movq      %rsi, %rbx                                    #305.1
        movq      %rdx, 6488(%rsp)                              #305.1
        lea       6144(%rsp), %r15                              #321.9
        movq      %rdi, %r13                                    #305.1
        movq      %r15, %rdi                                    #321.2
        xorl      %esi, %esi                                    #321.2
        movl      $192, %edx                                    #321.2
        movl      %ecx, %r14d                                   #305.1
        call      memset                                        #321.2
                                # LOE rbx r12 r13 r15 r14d
..B7.2:                         # Preds ..B7.1
        xorl      %esi, %esi                                    #322.2
        lea       (%rsp), %rbp                                  #322.9
        movq      %rbp, %rdi                                    #322.2
        movl      $6144, %edx                                   #322.2
        call      memset                                        #322.2
                                # LOE rbx rbp r12 r13 r15 r14d
..B7.3:                         # Preds ..B7.2
        movq      %rbx, %rdi                                    #323.12
        call      strlen                                        #323.12
                                # LOE rax rbx rbp r12 r13 r15 r14d
..B7.202:                       # Preds ..B7.3
        movq      %rax, %rcx                                    #323.27
                                # LOE rcx rbx rbp r12 r13 r15 r14d
..B7.4:                         # Preds ..B7.202
        movl      %ecx, %eax                                    #323.12
        xorl      %edx, %edx                                    #324.2
        movl      %ecx, %esi                                    #375.26
        movl      %eax, %ecx                                    #
        shrl      $1, %ecx                                      #
        movl      %ecx, 6696(%rsp)                              #
        movq      %rsi, 6704(%rsp)                              #
        lea       (,%rax,8), %edi                               #364.100
        movl      %edi, 6712(%rsp)                              #
        movq      %r13, 6720(%rsp)                              #
        movq      %rbx, 6728(%rsp)                              #
        movl      %edx, %ebx                                    #
        movl      %r14d, 6736(%rsp)                             #
        movl      %eax, %r14d                                   #
                                # LOE ebx r14d
..B7.5:                         # Preds ..B7.137 ..B7.4
        movl      %ebx, %r13d                                   #326.30
        shlq      $4, %r13                                      #326.30
        addq      6720(%rsp), %r13                              #326.30
        movq      %r13, %rdi                                    #326.15
        call      strlen                                        #326.15
                                # LOE rax r13 ebx r14d
..B7.6:                         # Preds ..B7.5
        movl      %ebx, %r12d                                   #328.3
        movl      %eax, %esi                                    #326.15
        shrl      $2, %r12d                                     #328.3
        movl      %r12d, %ecx                                   #328.3
        shll      $8, %ecx                                      #328.3
        movl      %ebx, %r15d                                   #326.3
        testl     %esi, %esi                                    #328.3
        movl      %esi, 6760(%rsp,%r15,4)                       #326.3
        lea       (%rsp,%rcx), %rdi                             #328.3
        jbe       ..B7.13       # Prob 50%                      #328.3
                                # LOE rcx rdi r13 r15 ebx esi r12d r14d
..B7.7:                         # Preds ..B7.6
        movl      %esi, %r8d                                    #328.3
        movl      %ebx, %ebp                                    #328.3
        shrl      $1, %r8d                                      #328.3
        andl      $3, %ebp                                      #328.3
        movl      $1, %r9d                                      #328.3
        xorl      %eax, %eax                                    #328.3
        testl     %r8d, %r8d                                    #328.3
        jbe       ..B7.11       # Prob 10%                      #328.3
                                # LOE rcx rdi r13 r15 eax ebx ebp esi r8d r9d r12d r14d
..B7.8:                         # Preds ..B7.7
        lea       (,%rbp,4), %edx                               #328.3
                                # LOE rcx rdi r13 r15 eax edx ebx ebp esi r8d r12d r14d
..B7.9:                         # Preds ..B7.9 ..B7.8
        lea       16(%rax,%rax), %r9d                           #328.3
        movl      %r9d, %r10d                                   #328.3
        lea       (%rax,%rax), %r11d                            #328.3
        andl      $-4, %r10d                                    #328.3
        andl      $3, %r9d                                      #328.3
        shll      $2, %r10d                                     #328.3
        addl      %edx, %r10d                                   #328.3
        addl      %r9d, %r10d                                   #328.3
        movzbl    (%r11,%r13), %r9d                             #328.3
        movb      %r9b, (%r10,%rdi)                             #328.3
        lea       17(%rax,%rax), %r10d                          #328.3
        movl      %r10d, %r11d                                  #328.3
        lea       1(%rax,%rax), %r9d                            #328.3
        andl      $-4, %r11d                                    #328.3
        andl      $3, %r10d                                     #328.3
        shll      $2, %r11d                                     #328.3
        incl      %eax                                          #328.3
        addl      %edx, %r11d                                   #328.3
        addl      %r10d, %r11d                                  #328.3
        cmpl      %r8d, %eax                                    #328.3
        movzbl    (%r9,%r13), %r9d                              #328.3
        movb      %r9b, (%r11,%rdi)                             #328.3
        jb        ..B7.9        # Prob 64%                      #328.3
                                # LOE rcx rdi r13 r15 eax edx ebx ebp esi r8d r12d r14d
..B7.10:                        # Preds ..B7.9
        lea       1(%rax,%rax), %r9d                            #328.3
                                # LOE rcx rdi r13 r15 ebx ebp esi r9d r12d r14d
..B7.11:                        # Preds ..B7.7 ..B7.10
        lea       -1(%r9), %r8d                                 #328.3
        cmpl      %r8d, %esi                                    #328.3
        jbe       ..B7.14       # Prob 10%                      #328.3
                                # LOE rcx rdi r8 r13 r15 ebx ebp esi r9d r12d r14d
..B7.12:                        # Preds ..B7.11
        addl      $15, %r9d                                     #328.3
        movl      %r9d, %r10d                                   #328.3
        andl      $3, %r9d                                      #328.3
        andl      $-4, %r10d                                    #328.3
        addl      %ebp, %r10d                                   #328.3
        shll      $2, %r10d                                     #328.3
        addl      %r9d, %r10d                                   #328.3
        movzbl    (%r8,%r13), %r9d                              #328.3
        movb      %r9b, (%r10,%rdi)                             #328.3
        jmp       ..B7.14       # Prob 100%                     #328.3
                                # LOE rcx rdi r13 r15 ebx ebp esi r12d r14d
..B7.13:                        # Preds ..B7.6
        movl      %ebx, %ebp                                    #329.3
        andl      $3, %ebp                                      #329.3
                                # LOE rcx rdi r13 r15 ebx ebp esi r12d r14d
..B7.14:                        # Preds ..B7.12 ..B7.11 ..B7.13
        lea       16(%rsi), %r8d                                #329.35
        movl      %r8d, %r11d                                   #329.3
        andl      $3, %r8d                                      #329.3
        andl      $-4, %r11d                                    #329.3
        addl      %ebp, %r11d                                   #329.3
        shll      $2, %r11d                                     #329.3
        addl      %r8d, %r11d                                   #329.3
        testl     %esi, %esi                                    #331.3
        movb      $128, (%r11,%rdi)                             #329.3
        jbe       ..B7.21       # Prob 50%                      #331.3
                                # LOE rcx rdi r11 r13 r15 ebx ebp esi r12d r14d
..B7.15:                        # Preds ..B7.14
        movl      %esi, %r10d                                   #331.3
        movl      $1, %r9d                                      #331.3
        shrl      $1, %r10d                                     #331.3
        xorl      %r8d, %r8d                                    #331.3
        testl     %r10d, %r10d                                  #331.3
        jbe       ..B7.19       # Prob 10%                      #331.3
                                # LOE rcx rdi r11 r13 r15 ebx ebp esi r8d r9d r10d r12d r14d
..B7.16:                        # Preds ..B7.15
        movl      %r14d, 6808(%rsp)                             #331.3
        lea       (,%rbp,4), %r9d                               #331.3
                                # LOE rcx rdi r11 r13 r15 ebx ebp esi r8d r9d r10d r12d
..B7.17:                        # Preds ..B7.17 ..B7.16
        lea       (%r8,%r8), %r14d                              #331.3
        movl      %r14d, %eax                                   #331.3
        andl      $-4, %eax                                     #331.3
        shll      $2, %eax                                      #331.3
        movl      %r14d, %edx                                   #331.3
        addl      %r9d, %eax                                    #331.3
        andl      $3, %r14d                                     #331.3
        addl      %r14d, %eax                                   #331.3
        movzbl    (%rdx,%r13), %r14d                            #331.3
        movb      %r14b, 768(%rax,%rdi)                         #331.3
        lea       1(%r8,%r8), %r14d                             #331.3
        movl      %r14d, %edx                                   #331.3
        incl      %r8d                                          #331.3
        andl      $-4, %edx                                     #331.3
        shll      $2, %edx                                      #331.3
        movl      %r14d, %eax                                   #331.3
        addl      %r9d, %edx                                    #331.3
        andl      $3, %r14d                                     #331.3
        addl      %r14d, %edx                                   #331.3
        cmpl      %r10d, %r8d                                   #331.3
        movzbl    (%rax,%r13), %eax                             #331.3
        movb      %al, 768(%rdx,%rdi)                           #331.3
        jb        ..B7.17       # Prob 64%                      #331.3
                                # LOE rcx rdi r11 r13 r15 ebx ebp esi r8d r9d r10d r12d
..B7.18:                        # Preds ..B7.17
        movl      6808(%rsp), %r14d                             #
        lea       1(%r8,%r8), %r9d                              #331.3
                                # LOE rcx rdi r11 r13 r15 ebx ebp esi r9d r12d r14d
..B7.19:                        # Preds ..B7.18 ..B7.15
        decl      %r9d                                          #331.3
        cmpl      %r9d, %esi                                    #331.3
        jbe       ..B7.211      # Prob 10%                      #331.3
                                # LOE rcx rdi r11 r13 r15 ebx ebp esi r9d r12d r14d
..B7.20:                        # Preds ..B7.19
        movl      %r9d, %r8d                                    #331.3
        lea       1536(%rsp,%rcx), %rax                         #334.3
        andl      $-4, %r8d                                     #331.3
        addl      %ebp, %r8d                                    #331.3
        movl      %r9d, %r10d                                   #331.3
        andl      $3, %r9d                                      #331.3
        shll      $2, %r8d                                      #331.3
        addl      %r9d, %r8d                                    #331.3
        movzbl    (%r10,%r13), %r9d                             #331.3
        movb      %r9b, 768(%r8,%rdi)                           #331.3
        movb      $128, 768(%r11,%rdi)                          #332.3
        jmp       ..B7.22       # Prob 100%                     #332.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r12d r14d
..B7.21:                        # Preds ..B7.14 ..B7.211
        movb      $128, 768(%r11,%rdi)                          #332.3
        lea       1536(%rsp,%rcx), %rax                         #334.3
        jbe       ..B7.34       # Prob 50%                      #334.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r12d r14d
..B7.22:                        # Preds ..B7.21 ..B7.20
        movl      %esi, %r11d                                   #334.3
        movl      $1, %r8d                                      #334.3
        shrl      $1, %r11d                                     #334.3
        xorl      %r10d, %r10d                                  #334.3
        testl     %r11d, %r11d                                  #334.3
        jbe       ..B7.26       # Prob 10%                      #334.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r8d r10d r11d r12d r14d
..B7.23:                        # Preds ..B7.22
        movl      %r14d, 6808(%rsp)                             #334.3
        lea       (,%rbp,4), %r9d                               #334.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r9d r10d r11d r12d
..B7.24:                        # Preds ..B7.24 ..B7.23
        lea       (%r10,%r10), %r14d                            #334.3
        movl      %r14d, %edx                                   #334.3
        andl      $-4, %edx                                     #334.3
        shll      $2, %edx                                      #334.3
        movl      %r14d, %r8d                                   #334.3
        addl      %r9d, %edx                                    #334.3
        andl      $3, %r14d                                     #334.3
        addl      %r14d, %edx                                   #334.3
        lea       1(%r10,%r10), %r14d                           #334.3
        incl      %r10d                                         #334.3
        movzbl    (%r8,%r13), %r8d                              #334.3
        movb      %r8b, (%rdx,%rax)                             #334.3
        movl      %r14d, %r8d                                   #334.3
        andl      $-4, %r8d                                     #334.3
        shll      $2, %r8d                                      #334.3
        movl      %r14d, %edx                                   #334.3
        addl      %r9d, %r8d                                    #334.3
        andl      $3, %r14d                                     #334.3
        addl      %r14d, %r8d                                   #334.3
        cmpl      %r11d, %r10d                                  #334.3
        movzbl    (%rdx,%r13), %r14d                            #334.3
        movb      %r14b, (%r8,%rax)                             #334.3
        jb        ..B7.24       # Prob 64%                      #334.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r9d r10d r11d r12d
..B7.25:                        # Preds ..B7.24
        movl      6808(%rsp), %r14d                             #
        lea       1(%r10,%r10), %r8d                            #334.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r8d r12d r14d
..B7.26:                        # Preds ..B7.25 ..B7.22
        decl      %r8d                                          #334.3
        cmpl      %r8d, %esi                                    #334.3
        jbe       ..B7.28       # Prob 10%                      #334.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r8d r12d r14d
..B7.27:                        # Preds ..B7.26
        movl      %r8d, %r9d                                    #334.3
        andl      $-4, %r9d                                     #334.3
        addl      %ebp, %r9d                                    #334.3
        movl      %r8d, %r10d                                   #334.3
        andl      $3, %r8d                                      #334.3
        shll      $2, %r9d                                      #334.3
        addl      %r8d, %r9d                                    #334.3
        movzbl    (%r10,%r13), %r8d                             #334.3
        movb      %r8b, (%r9,%rax)                              #334.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r12d r14d
..B7.28:                        # Preds ..B7.27 ..B7.26
        movl      %esi, %r10d                                   #335.3
        movl      $1, %r8d                                      #335.3
        shrl      $1, %r10d                                     #335.3
        xorl      %r9d, %r9d                                    #335.3
        testl     %r10d, %r10d                                  #335.3
        jbe       ..B7.32       # Prob 10%                      #335.3
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r8d r9d r10d r12d r14d
..B7.29:                        # Preds ..B7.28
        movl      %ebx, 6664(%rsp)                              #335.3
        lea       (,%rbp,4), %r8d                               #335.3
        movl      %r14d, 6808(%rsp)                             #335.3
                                # LOE rax rcx rdi r13 r15 ebp esi r8d r9d r10d r12d
..B7.30:                        # Preds ..B7.30 ..B7.29
        lea       (%rsi,%r9,2), %ebx                            #335.3
        movl      %ebx, %r14d                                   #335.3
        movl      %ebx, %r11d                                   #335.3
        andl      $-4, %r14d                                    #335.3
        lea       (%r9,%r9), %edx                               #335.3
        shll      $2, %r14d                                     #335.3
        andl      $3, %r11d                                     #335.3
        addl      %r8d, %r14d                                   #335.3
        incl      %ebx                                          #335.3
        addl      %r11d, %r14d                                  #335.3
        lea       1(%r9,%r9), %r11d                             #335.3
        incl      %r9d                                          #335.3
        movzbl    (%rdx,%r13), %edx                             #335.3
        movb      %dl, (%r14,%rax)                              #335.3
        movl      %ebx, %edx                                    #335.3
        andl      $-4, %edx                                     #335.3
        andl      $3, %ebx                                      #335.3
        shll      $2, %edx                                      #335.3
        addl      %r8d, %edx                                    #335.3
        addl      %ebx, %edx                                    #335.3
        cmpl      %r10d, %r9d                                   #335.3
        movzbl    (%r11,%r13), %ebx                             #335.3
        movb      %bl, (%rdx,%rax)                              #335.3
        jb        ..B7.30       # Prob 64%                      #335.3
                                # LOE rax rcx rdi r13 r15 ebp esi r8d r9d r10d r12d
..B7.31:                        # Preds ..B7.30
        movl      6664(%rsp), %ebx                              #
        lea       1(%r9,%r9), %r8d                              #335.3
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rcx rdi r13 r15 ebx ebp esi r8d r12d r14d
..B7.32:                        # Preds ..B7.31 ..B7.28
        lea       -1(%r8), %r9d                                 #335.3
        cmpl      %r9d, %esi                                    #335.3
        jbe       ..B7.34       # Prob 10%                      #335.3
                                # LOE rax rcx rdi r9 r13 r15 ebx ebp esi r8d r12d r14d
..B7.33:                        # Preds ..B7.32
        lea       -1(%r8,%rsi), %r8d                            #335.3
        movl      %r8d, %r10d                                   #335.3
        andl      $3, %r8d                                      #335.3
        andl      $-4, %r10d                                    #335.3
        addl      %ebp, %r10d                                   #335.3
        shll      $2, %r10d                                     #335.3
        addl      %r8d, %r10d                                   #335.3
        movzbl    (%r9,%r13), %r11d                             #335.3
        movb      %r11b, (%r10,%rax)                            #335.3
                                # LOE rcx rdi r13 r15 ebx ebp esi r12d r14d
..B7.34:                        # Preds ..B7.21 ..B7.32 ..B7.33
        lea       16(%rsi,%rsi), %r8d                           #336.37
        movl      %r8d, %eax                                    #336.3
        andl      $3, %r8d                                      #336.3
        andl      $-4, %eax                                     #336.3
        lea       (%rsi,%rsi), %edx                             #336.35
        addl      %ebp, %eax                                    #336.3
        shll      $2, %eax                                      #336.3
        addl      %r8d, %eax                                    #336.3
        testl     %esi, %esi                                    #338.3
        movb      $128, 1536(%rax,%rdi)                         #336.3
        jbe       ..B7.47       # Prob 50%                      #338.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.35:                        # Preds ..B7.34
        movl      %esi, %r9d                                    #338.3
        movl      $1, %r8d                                      #338.3
        shrl      $1, %r9d                                      #338.3
        xorl      %r10d, %r10d                                  #338.3
        testl     %r9d, %r9d                                    #338.3
        jbe       ..B7.39       # Prob 10%                      #338.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r9d r10d r12d r14d
..B7.36:                        # Preds ..B7.35
        movl      %ebx, 6664(%rsp)                              #338.3
        lea       (,%rbp,4), %r8d                               #338.3
        movl      %r14d, 6808(%rsp)                             #338.3
                                # LOE rax rcx rdi r13 r15 edx ebp esi r8d r9d r10d r12d
..B7.37:                        # Preds ..B7.37 ..B7.36
        lea       16(%r10,%r10), %ebx                           #338.3
        movl      %ebx, %r11d                                   #338.3
        lea       (%r10,%r10), %r14d                            #338.3
        andl      $-4, %r11d                                    #338.3
        andl      $3, %ebx                                      #338.3
        shll      $2, %r11d                                     #338.3
        addl      %r8d, %r11d                                   #338.3
        addl      %ebx, %r11d                                   #338.3
        movzbl    (%r14,%r13), %ebx                             #338.3
        movb      %bl, 2304(%r11,%rdi)                          #338.3
        lea       17(%r10,%r10), %r11d                          #338.3
        movl      %r11d, %r14d                                  #338.3
        lea       1(%r10,%r10), %ebx                            #338.3
        andl      $-4, %r14d                                    #338.3
        andl      $3, %r11d                                     #338.3
        shll      $2, %r14d                                     #338.3
        incl      %r10d                                         #338.3
        addl      %r8d, %r14d                                   #338.3
        addl      %r11d, %r14d                                  #338.3
        cmpl      %r9d, %r10d                                   #338.3
        movzbl    (%rbx,%r13), %ebx                             #338.3
        movb      %bl, 2304(%r14,%rdi)                          #338.3
        jb        ..B7.37       # Prob 64%                      #338.3
                                # LOE rax rcx rdi r13 r15 edx ebp esi r8d r9d r10d r12d
..B7.38:                        # Preds ..B7.37
        movl      6664(%rsp), %ebx                              #
        lea       1(%r10,%r10), %r8d                            #338.3
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.39:                        # Preds ..B7.38 ..B7.35
        lea       -1(%r8), %r9d                                 #338.3
        cmpl      %r9d, %esi                                    #338.3
        jbe       ..B7.41       # Prob 10%                      #338.3
                                # LOE rax rcx rdi r9 r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.40:                        # Preds ..B7.39
        addl      $15, %r8d                                     #338.3
        movl      %r8d, %r10d                                   #338.3
        andl      $3, %r8d                                      #338.3
        andl      $-4, %r10d                                    #338.3
        addl      %ebp, %r10d                                   #338.3
        shll      $2, %r10d                                     #338.3
        addl      %r8d, %r10d                                   #338.3
        movzbl    (%r9,%r13), %r8d                              #338.3
        movb      %r8b, 2304(%r10,%rdi)                         #338.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.41:                        # Preds ..B7.40 ..B7.39
        movl      %esi, %r9d                                    #339.3
        movl      $1, %r8d                                      #339.3
        shrl      $1, %r9d                                      #339.3
        xorl      %r10d, %r10d                                  #339.3
        testl     %r9d, %r9d                                    #339.3
        jbe       ..B7.45       # Prob 10%                      #339.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r9d r10d r12d r14d
..B7.42:                        # Preds ..B7.41
        movq      %r15, 6672(%rsp)                              #339.3
        lea       (,%rbp,4), %r8d                               #339.3
        movl      %ebx, 6664(%rsp)                              #339.3
        movl      %r14d, 6808(%rsp)                             #339.3
                                # LOE rax rcx rdi r13 edx ebp esi r8d r9d r10d r12d
..B7.43:                        # Preds ..B7.43 ..B7.42
        lea       (%r10,%r10), %ebx                             #339.3
        lea       16(%rbx,%rsi), %r11d                          #339.3
        movl      %r11d, %r15d                                  #339.3
        movl      %r11d, %r14d                                  #339.3
        andl      $-4, %r15d                                    #339.3
        andl      $3, %r14d                                     #339.3
        shll      $2, %r15d                                     #339.3
        incl      %r11d                                         #339.3
        addl      %r8d, %r15d                                   #339.3
        addl      %r14d, %r15d                                  #339.3
        lea       1(%r10,%r10), %r14d                           #339.3
        incl      %r10d                                         #339.3
        movzbl    (%rbx,%r13), %ebx                             #339.3
        movb      %bl, 2304(%r15,%rdi)                          #339.3
        movl      %r11d, %ebx                                   #339.3
        andl      $-4, %ebx                                     #339.3
        andl      $3, %r11d                                     #339.3
        shll      $2, %ebx                                      #339.3
        addl      %r8d, %ebx                                    #339.3
        addl      %r11d, %ebx                                   #339.3
        cmpl      %r9d, %r10d                                   #339.3
        movzbl    (%r14,%r13), %r11d                            #339.3
        movb      %r11b, 2304(%rbx,%rdi)                        #339.3
        jb        ..B7.43       # Prob 64%                      #339.3
                                # LOE rax rcx rdi r13 edx ebp esi r8d r9d r10d r12d
..B7.44:                        # Preds ..B7.43
        movq      6672(%rsp), %r15                              #
        lea       1(%r10,%r10), %r8d                            #339.3
        movl      6664(%rsp), %ebx                              #
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.45:                        # Preds ..B7.44 ..B7.41
        lea       -1(%r8), %r9d                                 #339.3
        cmpl      %r9d, %esi                                    #339.3
        jbe       ..B7.210      # Prob 10%                      #339.3
                                # LOE rax rcx rdi r9 r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.46:                        # Preds ..B7.45
        lea       15(%r8,%rsi), %r8d                            #339.3
        movl      %r8d, %r10d                                   #339.3
        andl      $3, %r8d                                      #339.3
        andl      $-4, %r10d                                    #339.3
        addl      %ebp, %r10d                                   #339.3
        shll      $2, %r10d                                     #339.3
        addl      %r8d, %r10d                                   #339.3
        movzbl    (%r9,%r13), %r11d                             #339.3
        movb      %r11b, 2304(%r10,%rdi)                        #339.3
        movb      $128, 2304(%rax,%rdi)                         #340.3
        lea       3072(%rsp,%rcx), %rax                         #342.3
        jmp       ..B7.48       # Prob 100%                     #342.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.47:                        # Preds ..B7.34 ..B7.210
        movb      $128, 2304(%rax,%rdi)                         #340.3
        lea       3072(%rsp,%rcx), %rax                         #342.3
        jbe       ..B7.54       # Prob 50%                      #342.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.48:                        # Preds ..B7.47 ..B7.46
        movl      %esi, %r9d                                    #342.3
        movl      $1, %r8d                                      #342.3
        shrl      $1, %r9d                                      #342.3
        xorl      %r10d, %r10d                                  #342.3
        testl     %r9d, %r9d                                    #342.3
        jbe       ..B7.52       # Prob 10%                      #342.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r9d r10d r12d r14d
..B7.49:                        # Preds ..B7.48
        movl      %ebx, 6664(%rsp)                              #342.3
        lea       (,%rbp,4), %r8d                               #342.3
        movl      %r14d, 6808(%rsp)                             #342.3
                                # LOE rax rcx rdi r13 r15 edx ebp esi r8d r9d r10d r12d
..B7.50:                        # Preds ..B7.50 ..B7.49
        lea       (%r10,%r10), %r14d                            #342.3
        movl      %r14d, %ebx                                   #342.3
        andl      $-4, %ebx                                     #342.3
        shll      $2, %ebx                                      #342.3
        movl      %r14d, %r11d                                  #342.3
        addl      %r8d, %ebx                                    #342.3
        andl      $3, %r14d                                     #342.3
        addl      %r14d, %ebx                                   #342.3
        lea       1(%r10,%r10), %r14d                           #342.3
        incl      %r10d                                         #342.3
        movzbl    (%r11,%r13), %r11d                            #342.3
        movb      %r11b, (%rbx,%rax)                            #342.3
        movl      %r14d, %r11d                                  #342.3
        andl      $-4, %r11d                                    #342.3
        shll      $2, %r11d                                     #342.3
        movl      %r14d, %ebx                                   #342.3
        addl      %r8d, %r11d                                   #342.3
        andl      $3, %r14d                                     #342.3
        addl      %r14d, %r11d                                  #342.3
        cmpl      %r9d, %r10d                                   #342.3
        movzbl    (%rbx,%r13), %ebx                             #342.3
        movb      %bl, (%r11,%rax)                              #342.3
        jb        ..B7.50       # Prob 64%                      #342.3
                                # LOE rax rcx rdi r13 r15 edx ebp esi r8d r9d r10d r12d
..B7.51:                        # Preds ..B7.50
        movl      6664(%rsp), %ebx                              #
        lea       1(%r10,%r10), %r8d                            #342.3
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.52:                        # Preds ..B7.51 ..B7.48
        decl      %r8d                                          #342.3
        cmpl      %r8d, %esi                                    #342.3
        jbe       ..B7.54       # Prob 10%                      #342.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.53:                        # Preds ..B7.52
        movl      %r8d, %r9d                                    #342.3
        andl      $-4, %r9d                                     #342.3
        addl      %ebp, %r9d                                    #342.3
        movl      %r8d, %r10d                                   #342.3
        andl      $3, %r8d                                      #342.3
        shll      $2, %r9d                                      #342.3
        addl      %r8d, %r9d                                    #342.3
        movzbl    (%r10,%r13), %r8d                             #342.3
        movb      %r8b, (%r9,%rax)                              #342.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.54:                        # Preds ..B7.47 ..B7.52 ..B7.53
        testl     %r14d, %r14d                                  #343.3
        jbe       ..B7.61       # Prob 50%                      #343.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.55:                        # Preds ..B7.54
        movl      $1, %r10d                                     #343.3
        xorl      %r9d, %r9d                                    #343.3
        cmpl      $0, 6696(%rsp)                                #343.3
        jbe       ..B7.59       # Prob 10%                      #343.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r9d r10d r12d r14d
..B7.56:                        # Preds ..B7.55
        movq      %r15, 6672(%rsp)                              #343.3
        lea       (,%rbp,4), %r8d                               #343.3
        movq      %r13, 6680(%rsp)                              #343.3
        movl      %ebx, 6664(%rsp)                              #343.3
        movl      %r14d, 6808(%rsp)                             #343.3
        movl      6696(%rsp), %r10d                             #343.3
        movq      6728(%rsp), %r11                              #343.3
                                # LOE rax rcx rdi r11 edx ebp esi r8d r9d r10d r12d
..B7.57:                        # Preds ..B7.57 ..B7.56
        lea       (%rsi,%r9,2), %r13d                           #343.3
        movl      %r13d, %r15d                                  #343.3
        movl      %r13d, %r14d                                  #343.3
        andl      $-4, %r15d                                    #343.3
        lea       (%r9,%r9), %ebx                               #343.3
        shll      $2, %r15d                                     #343.3
        andl      $3, %r14d                                     #343.3
        addl      %r8d, %r15d                                   #343.3
        incl      %r13d                                         #343.3
        addl      %r14d, %r15d                                  #343.3
        lea       1(%r9,%r9), %r14d                             #343.3
        incl      %r9d                                          #343.3
        movzbl    (%rbx,%r11), %ebx                             #343.3
        movb      %bl, (%r15,%rax)                              #343.3
        movl      %r13d, %ebx                                   #343.3
        andl      $-4, %ebx                                     #343.3
        andl      $3, %r13d                                     #343.3
        shll      $2, %ebx                                      #343.3
        addl      %r8d, %ebx                                    #343.3
        addl      %r13d, %ebx                                   #343.3
        cmpl      %r10d, %r9d                                   #343.3
        movzbl    (%r14,%r11), %r13d                            #343.3
        movb      %r13b, (%rbx,%rax)                            #343.3
        jb        ..B7.57       # Prob 64%                      #343.3
                                # LOE rax rcx rdi r11 edx ebp esi r8d r9d r10d r12d
..B7.58:                        # Preds ..B7.57
        movq      6672(%rsp), %r15                              #
        lea       1(%r9,%r9), %r10d                             #343.3
        movq      6680(%rsp), %r13                              #
        movl      6664(%rsp), %ebx                              #
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r10d r12d r14d
..B7.59:                        # Preds ..B7.58 ..B7.55
        lea       -1(%r10), %r8d                                #343.3
        cmpl      %r8d, %r14d                                   #343.3
        jbe       ..B7.61       # Prob 10%                      #343.3
                                # LOE rax rcx rdi r8 r13 r15 edx ebx ebp esi r10d r12d r14d
..B7.60:                        # Preds ..B7.59
        lea       -1(%r10,%rsi), %r9d                           #343.3
        movl      %r9d, %r10d                                   #343.3
        andl      $3, %r9d                                      #343.3
        andl      $-4, %r10d                                    #343.3
        addl      %ebp, %r10d                                   #343.3
        shll      $2, %r10d                                     #343.3
        addl      %r9d, %r10d                                   #343.3
        movq      6728(%rsp), %r11                              #343.3
        movzbl    (%r8,%r11), %r8d                              #343.3
        movb      %r8b, (%r10,%rax)                             #343.3
                                # LOE rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.61:                        # Preds ..B7.54 ..B7.59 ..B7.60
        lea       16(%r14,%rsi), %r9d                           #344.43
        movl      %r9d, 6744(%rsp)                              #344.43
        movl      %r9d, %eax                                    #344.3
        andl      $-4, %eax                                     #344.3
        andl      $3, %r9d                                      #344.3
        addl      %ebp, %eax                                    #344.3
        lea       (%r14,%rsi), %r8d                             #344.33
        shll      $2, %eax                                      #344.3
        addl      %r9d, %eax                                    #344.3
        testl     %r14d, %r14d                                  #346.3
        movl      %r8d, 6752(%rsp)                              #344.33
        movb      $128, 3072(%rax,%rdi)                         #344.3
        jbe       ..B7.69       # Prob 50%                      #346.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.62:                        # Preds ..B7.61
        movl      $1, %r9d                                      #346.3
        xorl      %r10d, %r10d                                  #346.3
        cmpl      $0, 6696(%rsp)                                #346.3
        jbe       ..B7.66       # Prob 10%                      #346.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r9d r10d r12d r14d
..B7.63:                        # Preds ..B7.62
        movl      %ebx, 6664(%rsp)                              #346.3
        lea       (,%rbp,4), %r9d                               #346.3
        movq      %r13, 6680(%rsp)                              #346.3
        movl      %r14d, 6808(%rsp)                             #346.3
        movl      6696(%rsp), %ebx                              #346.3
        movq      6728(%rsp), %r8                               #346.3
                                # LOE rax rcx rdi r8 r15 edx ebx ebp esi r9d r10d r12d
..B7.64:                        # Preds ..B7.64 ..B7.63
        lea       16(%r10,%r10), %r11d                          #346.3
        movl      %r11d, %r13d                                  #346.3
        lea       (%r10,%r10), %r14d                            #346.3
        andl      $-4, %r13d                                    #346.3
        andl      $3, %r11d                                     #346.3
        shll      $2, %r13d                                     #346.3
        addl      %r9d, %r13d                                   #346.3
        addl      %r11d, %r13d                                  #346.3
        movzbl    (%r14,%r8), %r11d                             #346.3
        movb      %r11b, 3840(%r13,%rdi)                        #346.3
        lea       17(%r10,%r10), %r13d                          #346.3
        movl      %r13d, %r14d                                  #346.3
        lea       1(%r10,%r10), %r11d                           #346.3
        andl      $-4, %r14d                                    #346.3
        andl      $3, %r13d                                     #346.3
        shll      $2, %r14d                                     #346.3
        incl      %r10d                                         #346.3
        addl      %r9d, %r14d                                   #346.3
        addl      %r13d, %r14d                                  #346.3
        cmpl      %ebx, %r10d                                   #346.3
        movzbl    (%r11,%r8), %r11d                             #346.3
        movb      %r11b, 3840(%r14,%rdi)                        #346.3
        jb        ..B7.64       # Prob 64%                      #346.3
                                # LOE rax rcx rdi r8 r15 edx ebx ebp esi r9d r10d r12d
..B7.65:                        # Preds ..B7.64
        movq      6680(%rsp), %r13                              #
        lea       1(%r10,%r10), %r9d                            #346.3
        movl      6664(%rsp), %ebx                              #
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r9d r12d r14d
..B7.66:                        # Preds ..B7.65 ..B7.62
        lea       -1(%r9), %r8d                                 #346.3
        cmpl      %r8d, %r14d                                   #346.3
        jbe       ..B7.196      # Prob 10%                      #346.3
                                # LOE rax rcx rdi r8 r13 r15 edx ebx ebp esi r9d r12d r14d
..B7.67:                        # Preds ..B7.66
        addl      $15, %r9d                                     #346.3
        movl      %r9d, %r10d                                   #346.3
        andl      $3, %r9d                                      #346.3
        andl      $-4, %r10d                                    #346.3
        addl      %ebp, %r10d                                   #346.3
        shll      $2, %r10d                                     #346.3
        addl      %r9d, %r10d                                   #346.3
        movq      6728(%rsp), %r9                               #346.3
        testl     %esi, %esi                                    #347.3
        movzbl    (%r8,%r9), %r11d                              #346.3
        movb      %r11b, 3840(%r10,%rdi)                        #346.3
        ja        ..B7.70       # Prob 50%                      #347.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.68:                        # Preds ..B7.67
        movb      $128, 3840(%rax,%rdi)                         #348.3
        lea       4608(%rsp,%rcx), %rax                         #350.3
        jmp       ..B7.77       # Prob 100%                     #350.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.69:                        # Preds ..B7.61
        testl     %esi, %esi                                    #347.3
        jbe       ..B7.83       # Prob 50%                      #347.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.70:                        # Preds ..B7.69 ..B7.196 ..B7.67
        movl      %esi, %r9d                                    #347.3
        movl      $1, %r8d                                      #347.3
        shrl      $1, %r9d                                      #347.3
        xorl      %r10d, %r10d                                  #347.3
        testl     %r9d, %r9d                                    #347.3
        jbe       ..B7.74       # Prob 10%                      #347.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r9d r10d r12d r14d
..B7.71:                        # Preds ..B7.70
        movl      %esi, 6688(%rsp)                              #347.3
        lea       (,%rbp,4), %r8d                               #347.3
        movq      %r15, 6672(%rsp)                              #347.3
        movl      %ebx, 6664(%rsp)                              #347.3
                                # LOE rax rcx rdi r13 edx ebp r8d r9d r10d r12d r14d
..B7.72:                        # Preds ..B7.72 ..B7.71
        lea       (%r14,%r10,2), %esi                           #347.28
        lea       16(%rsi), %r11d                               #347.3
        addl      $17, %esi                                     #347.3
        movl      %r11d, %r15d                                  #347.3
        lea       (%r10,%r10), %ebx                             #347.3
        andl      $-4, %r15d                                    #347.3
        andl      $3, %r11d                                     #347.3
        shll      $2, %r15d                                     #347.3
        addl      %r8d, %r15d                                   #347.3
        addl      %r11d, %r15d                                  #347.3
        lea       1(%r10,%r10), %r11d                           #347.3
        incl      %r10d                                         #347.3
        movzbl    (%rbx,%r13), %ebx                             #347.3
        movb      %bl, 3840(%r15,%rdi)                          #347.3
        movl      %esi, %ebx                                    #347.3
        andl      $-4, %ebx                                     #347.3
        andl      $3, %esi                                      #347.3
        shll      $2, %ebx                                      #347.3
        addl      %r8d, %ebx                                    #347.3
        addl      %esi, %ebx                                    #347.3
        cmpl      %r9d, %r10d                                   #347.3
        movzbl    (%r11,%r13), %esi                             #347.3
        movb      %sil, 3840(%rbx,%rdi)                         #347.3
        jb        ..B7.72       # Prob 64%                      #347.3
                                # LOE rax rcx rdi r13 edx ebp r8d r9d r10d r12d r14d
..B7.73:                        # Preds ..B7.72
        movl      6688(%rsp), %esi                              #
        lea       1(%r10,%r10), %r8d                            #347.3
        movq      6672(%rsp), %r15                              #
        movl      6664(%rsp), %ebx                              #
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.74:                        # Preds ..B7.73 ..B7.70
        lea       -1(%r8), %r9d                                 #347.3
        cmpl      %r9d, %esi                                    #347.3
        jbe       ..B7.76       # Prob 10%                      #347.3
                                # LOE rax rcx rdi r9 r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.75:                        # Preds ..B7.74
        lea       15(%r14,%r8), %r8d                            #347.3
        movl      %r8d, %r10d                                   #347.3
        andl      $3, %r8d                                      #347.3
        andl      $-4, %r10d                                    #347.3
        addl      %ebp, %r10d                                   #347.3
        shll      $2, %r10d                                     #347.3
        addl      %r8d, %r10d                                   #347.3
        movzbl    (%r9,%r13), %r11d                             #347.3
        movb      %r11b, 3840(%r10,%rdi)                        #347.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.76:                        # Preds ..B7.74 ..B7.75
        movb      $128, 3840(%rax,%rdi)                         #348.3
        lea       4608(%rsp,%rcx), %rax                         #350.3
        testl     %r14d, %r14d                                  #350.3
        jbe       ..B7.208      # Prob 50%                      #350.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.77:                        # Preds ..B7.68 ..B7.197 ..B7.76
        movl      $1, %r8d                                      #350.3
        xorl      %r9d, %r9d                                    #350.3
        cmpl      $0, 6696(%rsp)                                #350.3
        jbe       ..B7.81       # Prob 10%                      #350.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r8d r9d r12d r14d
..B7.78:                        # Preds ..B7.77
        movl      %ebx, 6664(%rsp)                              #350.3
        lea       (,%rbp,4), %r8d                               #350.3
        movl      %r14d, 6808(%rsp)                             #350.3
        movl      6696(%rsp), %ecx                              #350.3
        movq      6728(%rsp), %rbx                              #350.3
                                # LOE rax rbx rdi r13 r15 edx ecx ebp esi r8d r9d r12d
..B7.79:                        # Preds ..B7.79 ..B7.78
        lea       16(%r9,%r9), %r10d                            #350.3
        movl      %r10d, %r11d                                  #350.3
        lea       (%r9,%r9), %r14d                              #350.3
        andl      $-4, %r11d                                    #350.3
        andl      $3, %r10d                                     #350.3
        shll      $2, %r11d                                     #350.3
        addl      %r8d, %r11d                                   #350.3
        addl      %r10d, %r11d                                  #350.3
        movzbl    (%r14,%rbx), %r10d                            #350.3
        movb      %r10b, (%r11,%rax)                            #350.3
        lea       17(%r9,%r9), %r11d                            #350.3
        movl      %r11d, %r14d                                  #350.3
        lea       1(%r9,%r9), %r10d                             #350.3
        andl      $-4, %r14d                                    #350.3
        andl      $3, %r11d                                     #350.3
        shll      $2, %r14d                                     #350.3
        incl      %r9d                                          #350.3
        addl      %r8d, %r14d                                   #350.3
        addl      %r11d, %r14d                                  #350.3
        cmpl      %ecx, %r9d                                    #350.3
        movzbl    (%r10,%rbx), %r10d                            #350.3
        movb      %r10b, (%r14,%rax)                            #350.3
        jb        ..B7.79       # Prob 64%                      #350.3
                                # LOE rax rbx rdi r13 r15 edx ecx ebp esi r8d r9d r12d
..B7.80:                        # Preds ..B7.79
        movl      6664(%rsp), %ebx                              #
        lea       1(%r9,%r9), %r8d                              #350.3
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.81:                        # Preds ..B7.80 ..B7.77
        lea       -1(%r8), %ecx                                 #350.3
        cmpl      %ecx, %r14d                                   #350.3
        jbe       ..B7.208      # Prob 10%                      #350.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.82:                        # Preds ..B7.81
        addl      $15, %r8d                                     #350.3
        movl      %r8d, %r9d                                    #350.3
        andl      $3, %r8d                                      #350.3
        andl      $-4, %r9d                                     #350.3
        addl      %ebp, %r9d                                    #350.3
        shll      $2, %r9d                                      #350.3
        addl      %r8d, %r9d                                    #350.3
        movq      6728(%rsp), %r8                               #350.3
        testl     %esi, %esi                                    #350.3
        movzbl    (%rcx,%r8), %r10d                             #350.3
        movb      %r10b, (%r9,%rax)                             #350.3
        ja        ..B7.85       # Prob 50%                      #350.3
        jmp       ..B7.97       # Prob 100%                     #350.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.83:                        # Preds ..B7.69
        movb      $128, 3840(%rax,%rdi)                         #348.3
        lea       4608(%rsp,%rcx), %rax                         #350.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.84:                        # Preds ..B7.83
        jbe       ..B7.97       # Prob 50%                      #351.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.85:                        # Preds ..B7.82 ..B7.208 ..B7.84
        movl      %esi, %ecx                                    #351.3
        movl      $1, %r8d                                      #351.3
        shrl      $1, %ecx                                      #351.3
        xorl      %r9d, %r9d                                    #351.3
        testl     %ecx, %ecx                                    #351.3
        jbe       ..B7.89       # Prob 10%                      #351.3
                                # LOE rax rdi r13 r15 edx ecx ebx ebp esi r8d r9d r12d r14d
..B7.86:                        # Preds ..B7.85
        movq      %r15, 6672(%rsp)                              #351.3
        lea       (,%rbp,4), %r8d                               #351.3
        movl      %ebx, 6664(%rsp)                              #351.3
                                # LOE rax rdi r13 edx ecx ebp esi r8d r9d r12d r14d
..B7.87:                        # Preds ..B7.87 ..B7.86
        lea       (%r14,%r9,2), %r10d                           #351.28
        lea       16(%r10), %r11d                               #351.3
        addl      $17, %r10d                                    #351.3
        movl      %r11d, %r15d                                  #351.3
        lea       (%r9,%r9), %ebx                               #351.3
        andl      $-4, %r15d                                    #351.3
        andl      $3, %r11d                                     #351.3
        shll      $2, %r15d                                     #351.3
        addl      %r8d, %r15d                                   #351.3
        addl      %r11d, %r15d                                  #351.3
        lea       1(%r9,%r9), %r11d                             #351.3
        incl      %r9d                                          #351.3
        movzbl    (%rbx,%r13), %ebx                             #351.3
        movb      %bl, (%r15,%rax)                              #351.3
        movl      %r10d, %ebx                                   #351.3
        andl      $-4, %ebx                                     #351.3
        andl      $3, %r10d                                     #351.3
        shll      $2, %ebx                                      #351.3
        addl      %r8d, %ebx                                    #351.3
        addl      %r10d, %ebx                                   #351.3
        cmpl      %ecx, %r9d                                    #351.3
        movzbl    (%r11,%r13), %r10d                            #351.3
        movb      %r10b, (%rbx,%rax)                            #351.3
        jb        ..B7.87       # Prob 64%                      #351.3
                                # LOE rax rdi r13 edx ecx ebp esi r8d r9d r12d r14d
..B7.88:                        # Preds ..B7.87
        movq      6672(%rsp), %r15                              #
        lea       1(%r9,%r9), %r8d                              #351.3
        movl      6664(%rsp), %ebx                              #
                                # LOE rax rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.89:                        # Preds ..B7.88 ..B7.85
        lea       -1(%r8), %ecx                                 #351.3
        cmpl      %ecx, %esi                                    #351.3
        jbe       ..B7.91       # Prob 10%                      #351.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.90:                        # Preds ..B7.89
        lea       15(%r8,%r14), %r8d                            #351.3
        movl      %r8d, %r9d                                    #351.3
        andl      $3, %r8d                                      #351.3
        andl      $-4, %r9d                                     #351.3
        addl      %ebp, %r9d                                    #351.3
        shll      $2, %r9d                                      #351.3
        addl      %r8d, %r9d                                    #351.3
        movzbl    (%rcx,%r13), %r10d                            #351.3
        movb      %r10b, (%r9,%rax)                             #351.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.91:                        # Preds ..B7.90 ..B7.89
        movl      %esi, %r8d                                    #352.3
        movl      $1, %ecx                                      #352.3
        shrl      $1, %r8d                                      #352.3
        xorl      %r9d, %r9d                                    #352.3
        testl     %r8d, %r8d                                    #352.3
        jbe       ..B7.95       # Prob 10%                      #352.3
                                # LOE rax rdi r13 r15 edx ecx ebx ebp esi r8d r9d r12d r14d
..B7.92:                        # Preds ..B7.91
        movq      %r15, 6672(%rsp)                              #352.3
        lea       (,%rbp,4), %ecx                               #352.3
        movl      %ebx, 6664(%rsp)                              #352.3
        movl      %r14d, 6808(%rsp)                             #352.3
        movl      6744(%rsp), %r10d                             #352.3
                                # LOE rax rdi r13 edx ecx ebp esi r8d r9d r10d r12d
..B7.93:                        # Preds ..B7.93 ..B7.92
        lea       (%r10,%r9,2), %r11d                           #352.3
        movl      %r11d, %r15d                                  #352.3
        movl      %r11d, %r14d                                  #352.3
        andl      $-4, %r15d                                    #352.3
        lea       (%r9,%r9), %ebx                               #352.3
        shll      $2, %r15d                                     #352.3
        andl      $3, %r14d                                     #352.3
        addl      %ecx, %r15d                                   #352.3
        incl      %r11d                                         #352.3
        addl      %r14d, %r15d                                  #352.3
        lea       1(%r9,%r9), %r14d                             #352.3
        incl      %r9d                                          #352.3
        movzbl    (%rbx,%r13), %ebx                             #352.3
        movb      %bl, (%r15,%rax)                              #352.3
        movl      %r11d, %ebx                                   #352.3
        andl      $-4, %ebx                                     #352.3
        andl      $3, %r11d                                     #352.3
        shll      $2, %ebx                                      #352.3
        addl      %ecx, %ebx                                    #352.3
        addl      %r11d, %ebx                                   #352.3
        cmpl      %r8d, %r9d                                    #352.3
        movzbl    (%r14,%r13), %r11d                            #352.3
        movb      %r11b, (%rbx,%rax)                            #352.3
        jb        ..B7.93       # Prob 64%                      #352.3
                                # LOE rax rdi r13 edx ecx ebp esi r8d r9d r10d r12d
..B7.94:                        # Preds ..B7.93
        movq      6672(%rsp), %r15                              #
        lea       1(%r9,%r9), %ecx                              #352.3
        movl      6664(%rsp), %ebx                              #
        movl      6808(%rsp), %r14d                             #
                                # LOE rax rdi r13 r15 edx ecx ebx ebp esi r12d r14d
..B7.95:                        # Preds ..B7.94 ..B7.91
        lea       -1(%rcx), %r9d                                #352.3
        cmpl      %r9d, %esi                                    #352.3
        jbe       ..B7.97       # Prob 10%                      #352.3
                                # LOE rax rdi r9 r13 r15 edx ecx ebx ebp esi r12d r14d
..B7.96:                        # Preds ..B7.95
        movl      6744(%rsp), %r8d                              #352.3
        lea       -1(%rcx,%r8), %ecx                            #352.3
        movl      %ecx, %r10d                                   #352.3
        andl      $3, %ecx                                      #352.3
        andl      $-4, %r10d                                    #352.3
        addl      %ebp, %r10d                                   #352.3
        shll      $2, %r10d                                     #352.3
        addl      %ecx, %r10d                                   #352.3
        movzbl    (%r9,%r13), %r11d                             #352.3
        movb      %r11b, (%r10,%rax)                            #352.3
                                # LOE rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.97:                        # Preds ..B7.82 ..B7.208 ..B7.84 ..B7.95 ..B7.96
                                #      
        lea       16(%r14,%rsi,2), %ecx                         #353.35
        movl      %ecx, %r9d                                    #353.3
        andl      $3, %ecx                                      #353.3
        andl      $-4, %r9d                                     #353.3
        addl      %ebp, %r9d                                    #353.3
        shll      $2, %r9d                                      #353.3
        addl      %ecx, %r9d                                    #353.3
        testl     %esi, %esi                                    #355.3
        movb      $128, 4608(%r9,%rdi)                          #353.3
        jbe       ..B7.104      # Prob 50%                      #355.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r12d r14d
..B7.98:                        # Preds ..B7.97
        movl      %esi, %r11d                                   #355.3
        movl      $1, %ecx                                      #355.3
        shrl      $1, %r11d                                     #355.3
        xorl      %r10d, %r10d                                  #355.3
        testl     %r11d, %r11d                                  #355.3
        jbe       ..B7.102      # Prob 10%                      #355.3
                                # LOE rdi r9 r13 r15 edx ecx ebx ebp esi r10d r11d r12d r14d
..B7.99:                        # Preds ..B7.98
        movl      %r14d, 6808(%rsp)                             #355.3
        lea       (,%rbp,4), %r8d                               #355.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r8d r10d r11d r12d
..B7.100:                       # Preds ..B7.100 ..B7.99
        lea       (%r10,%r10), %r14d                            #355.3
        movl      %r14d, %eax                                   #355.3
        andl      $-4, %eax                                     #355.3
        shll      $2, %eax                                      #355.3
        movl      %r14d, %ecx                                   #355.3
        addl      %r8d, %eax                                    #355.3
        andl      $3, %r14d                                     #355.3
        addl      %r14d, %eax                                   #355.3
        lea       1(%r10,%r10), %r14d                           #355.3
        incl      %r10d                                         #355.3
        movzbl    (%rcx,%r13), %ecx                             #355.3
        movb      %cl, 5376(%rax,%rdi)                          #355.3
        movl      %r14d, %ecx                                   #355.3
        andl      $-4, %ecx                                     #355.3
        shll      $2, %ecx                                      #355.3
        movl      %r14d, %eax                                   #355.3
        addl      %r8d, %ecx                                    #355.3
        andl      $3, %r14d                                     #355.3
        addl      %r14d, %ecx                                   #355.3
        cmpl      %r11d, %r10d                                  #355.3
        movzbl    (%rax,%r13), %eax                             #355.3
        movb      %al, 5376(%rcx,%rdi)                          #355.3
        jb        ..B7.100      # Prob 64%                      #355.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r8d r10d r11d r12d
..B7.101:                       # Preds ..B7.100
        movl      6808(%rsp), %r14d                             #
        lea       1(%r10,%r10), %ecx                            #355.3
                                # LOE rdi r9 r13 r15 edx ecx ebx ebp esi r12d r14d
..B7.102:                       # Preds ..B7.101 ..B7.98
        decl      %ecx                                          #355.3
        cmpl      %ecx, %esi                                    #355.3
        jbe       ..B7.198      # Prob 10%                      #355.3
                                # LOE rdi r9 r13 r15 edx ecx ebx ebp esi r12d r14d
..B7.103:                       # Preds ..B7.102
        movl      %ecx, %r8d                                    #355.3
        andl      $-4, %r8d                                     #355.3
        addl      %ebp, %r8d                                    #355.3
        movl      %ecx, %r10d                                   #355.3
        andl      $3, %ecx                                      #355.3
        shll      $2, %r8d                                      #355.3
        addl      %ecx, %r8d                                    #355.3
        testl     %r14d, %r14d                                  #356.3
        movzbl    (%r10,%r13), %ecx                             #355.3
        movb      %cl, 5376(%r8,%rdi)                           #355.3
        ja        ..B7.105      # Prob 50%                      #356.3
        jmp       ..B7.112      # Prob 100%                     #356.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r12d r14d
..B7.104:                       # Preds ..B7.97
        testl     %r14d, %r14d                                  #356.3
        jbe       ..B7.118      # Prob 50%                      #356.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r12d r14d
..B7.105:                       # Preds ..B7.104 ..B7.198 ..B7.103
        movl      $1, %r8d                                      #356.3
        xorl      %ecx, %ecx                                    #356.3
        cmpl      $0, 6696(%rsp)                                #356.3
        jbe       ..B7.109      # Prob 10%                      #356.3
                                # LOE rdi r9 r13 r15 edx ecx ebx ebp esi r8d r12d r14d
..B7.106:                       # Preds ..B7.105
        movq      %r13, 6680(%rsp)                              #356.3
        lea       (,%rbp,4), %eax                               #356.3
        movl      %ebx, 6664(%rsp)                              #356.3
        movl      %r14d, 6808(%rsp)                             #356.3
        movl      6696(%rsp), %r8d                              #356.3
        movq      6728(%rsp), %r10                              #356.3
                                # LOE rdi r9 r10 r15 eax edx ecx ebp esi r8d r12d
..B7.107:                       # Preds ..B7.107 ..B7.106
        lea       (%rsi,%rcx,2), %r11d                          #356.3
        movl      %r11d, %r14d                                  #356.3
        movl      %r11d, %r13d                                  #356.3
        andl      $-4, %r14d                                    #356.3
        lea       (%rcx,%rcx), %ebx                             #356.3
        shll      $2, %r14d                                     #356.3
        andl      $3, %r13d                                     #356.3
        addl      %eax, %r14d                                   #356.3
        incl      %r11d                                         #356.3
        addl      %r13d, %r14d                                  #356.3
        lea       1(%rcx,%rcx), %r13d                           #356.3
        incl      %ecx                                          #356.3
        movzbl    (%rbx,%r10), %ebx                             #356.3
        movb      %bl, 5376(%r14,%rdi)                          #356.3
        movl      %r11d, %ebx                                   #356.3
        andl      $-4, %ebx                                     #356.3
        andl      $3, %r11d                                     #356.3
        shll      $2, %ebx                                      #356.3
        addl      %eax, %ebx                                    #356.3
        addl      %r11d, %ebx                                   #356.3
        cmpl      %r8d, %ecx                                    #356.3
        movzbl    (%r13,%r10), %r11d                            #356.3
        movb      %r11b, 5376(%rbx,%rdi)                        #356.3
        jb        ..B7.107      # Prob 64%                      #356.3
                                # LOE rdi r9 r10 r15 eax edx ecx ebp esi r8d r12d
..B7.108:                       # Preds ..B7.107
        movq      6680(%rsp), %r13                              #
        lea       1(%rcx,%rcx), %r8d                            #356.3
        movl      6664(%rsp), %ebx                              #
        movl      6808(%rsp), %r14d                             #
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.109:                       # Preds ..B7.108 ..B7.105
        lea       -1(%r8), %ecx                                 #356.3
        cmpl      %ecx, %r14d                                   #356.3
        jbe       ..B7.111      # Prob 10%                      #356.3
                                # LOE rcx rdi r9 r13 r15 edx ebx ebp esi r8d r12d r14d
..B7.110:                       # Preds ..B7.109
        lea       -1(%r8,%rsi), %r8d                            #356.3
        movl      %r8d, %r10d                                   #356.3
        andl      $3, %r8d                                      #356.3
        andl      $-4, %r10d                                    #356.3
        addl      %ebp, %r10d                                   #356.3
        shll      $2, %r10d                                     #356.3
        addl      %r8d, %r10d                                   #356.3
        movq      6728(%rsp), %r11                              #356.3
        movzbl    (%rcx,%r11), %ecx                             #356.3
        movb      %cl, 5376(%r10,%rdi)                          #356.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r12d r14d
..B7.111:                       # Preds ..B7.109 ..B7.110
        testl     %esi, %esi                                    #357.3
        jbe       ..B7.118      # Prob 50%                      #357.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r12d r14d
..B7.112:                       # Preds ..B7.103 ..B7.198 ..B7.111
        movl      %esi, %ecx                                    #357.3
        movl      $1, %r10d                                     #357.3
        shrl      $1, %ecx                                      #357.3
        xorl      %r8d, %r8d                                    #357.3
        testl     %ecx, %ecx                                    #357.3
        jbe       ..B7.116      # Prob 10%                      #357.3
                                # LOE rdi r9 r13 r15 edx ecx ebx ebp esi r8d r10d r12d r14d
..B7.113:                       # Preds ..B7.112
        movq      %r15, 6672(%rsp)                              #357.3
        lea       (,%rbp,4), %eax                               #357.3
        movl      %ebx, 6664(%rsp)                              #357.3
        movl      %r14d, 6808(%rsp)                             #357.3
        movl      6752(%rsp), %r10d                             #357.3
                                # LOE rdi r9 r13 eax edx ecx ebp esi r8d r10d r12d
..B7.114:                       # Preds ..B7.114 ..B7.113
        lea       (%r10,%r8,2), %r11d                           #357.3
        movl      %r11d, %r15d                                  #357.3
        movl      %r11d, %r14d                                  #357.3
        andl      $-4, %r15d                                    #357.3
        lea       (%r8,%r8), %ebx                               #357.3
        shll      $2, %r15d                                     #357.3
        andl      $3, %r14d                                     #357.3
        addl      %eax, %r15d                                   #357.3
        incl      %r11d                                         #357.3
        addl      %r14d, %r15d                                  #357.3
        lea       1(%r8,%r8), %r14d                             #357.3
        incl      %r8d                                          #357.3
        movzbl    (%rbx,%r13), %ebx                             #357.3
        movb      %bl, 5376(%r15,%rdi)                          #357.3
        movl      %r11d, %ebx                                   #357.3
        andl      $-4, %ebx                                     #357.3
        andl      $3, %r11d                                     #357.3
        shll      $2, %ebx                                      #357.3
        addl      %eax, %ebx                                    #357.3
        addl      %r11d, %ebx                                   #357.3
        cmpl      %ecx, %r8d                                    #357.3
        movzbl    (%r14,%r13), %r11d                            #357.3
        movb      %r11b, 5376(%rbx,%rdi)                        #357.3
        jb        ..B7.114      # Prob 64%                      #357.3
                                # LOE rdi r9 r13 eax edx ecx ebp esi r8d r10d r12d
..B7.115:                       # Preds ..B7.114
        movq      6672(%rsp), %r15                              #
        lea       1(%r8,%r8), %r10d                             #357.3
        movl      6664(%rsp), %ebx                              #
        movl      6808(%rsp), %r14d                             #
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r10d r12d r14d
..B7.116:                       # Preds ..B7.115 ..B7.112
        lea       -1(%r10), %r8d                                #357.3
        cmpl      %r8d, %esi                                    #357.3
        jbe       ..B7.118      # Prob 10%                      #357.3
                                # LOE rdi r8 r9 r13 r15 edx ebx ebp esi r10d r12d r14d
..B7.117:                       # Preds ..B7.116
        movl      6752(%rsp), %ecx                              #357.3
        lea       -1(%r10,%rcx), %r10d                          #357.3
        movl      %r10d, %r11d                                  #357.3
        andl      $3, %r10d                                     #357.3
        andl      $-4, %r11d                                    #357.3
        addl      %ebp, %r11d                                   #357.3
        shll      $2, %r11d                                     #357.3
        addl      %r10d, %r11d                                  #357.3
        movzbl    (%r8,%r13), %ecx                              #357.3
        movb      %cl, 5376(%r11,%rdi)                          #357.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r12d r14d
..B7.118:                       # Preds ..B7.104 ..B7.116 ..B7.111 ..B7.117
        movl      %r12d, %ecx                                   #360.70
        shll      $6, %ecx                                      #360.70
        shll      $3, %esi                                      #360.92
        shll      $3, %edx                                      #362.94
        movl      6712(%rsp), %r11d                             #364.100
        movb      $128, 5376(%r9,%rdi)                          #358.3
        lea       56(%rbp,%rcx), %r8d                           #360.70
        lea       6496(%rsp), %rdi                              #369.3
        lea       128(%rsi), %r9d                               #360.92
        lea       128(%rdx), %r10d                              #362.94
        lea       128(%rsi,%r11), %esi                          #364.100
        movl      %r9d, (%rsp,%r8,4)                            #360.38
        lea       128(%rdx,%r11), %ecx                          #366.102
        movl      %r9d, 768(%rsp,%r8,4)                         #361.38
        movl      %r10d, 1536(%rsp,%r8,4)                       #362.38
        movl      %r10d, 2304(%rsp,%r8,4)                       #363.38
        movl      %esi, 3072(%rsp,%r8,4)                        #364.38
        movl      %esi, 3840(%rsp,%r8,4)                        #365.38
        movl      %ecx, 4608(%rsp,%r8,4)                        #366.38
        movl      %ecx, 5376(%rsp,%r8,4)                        #367.38
        call      MD5_Init                                      #369.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.119:                       # Preds ..B7.118
        movq      %r13, %rsi                                    #370.3
        lea       6496(%rsp), %rdi                              #370.3
        movl      6760(%rsp,%r15,4), %edx                       #370.28
        call      MD5_Update                                    #370.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.120:                       # Preds ..B7.119
        cmpl      $1, 6736(%rsp)                                #371.18
        je        ..B7.199      # Prob 16%                      #371.18
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.121:                       # Preds ..B7.120
        movl      $.L_2__STRING.2, %esi                         #374.4
        lea       6496(%rsp), %rdi                              #374.4
        movl      $3, %edx                                      #374.4
        call      MD5_Update                                    #374.4
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.122:                       # Preds ..B7.121 ..B7.199
        movq      6728(%rsp), %rsi                              #375.3
        lea       6496(%rsp), %rdi                              #375.3
        movq      6704(%rsp), %rdx                              #375.3
        call      MD5_Update                                    #375.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.123:                       # Preds ..B7.122
        lea       6336(%rsp), %rdi                              #376.3
        call      MD5_Init                                      #376.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.124:                       # Preds ..B7.123
        movq      %r13, %rsi                                    #377.3
        lea       6336(%rsp), %rdi                              #377.3
        movl      6760(%rsp,%r15,4), %edx                       #377.29
        call      MD5_Update                                    #377.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.125:                       # Preds ..B7.124
        movq      6728(%rsp), %rsi                              #378.3
        lea       6336(%rsp), %rdi                              #378.3
        movq      6704(%rsp), %rdx                              #378.3
        call      MD5_Update                                    #378.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.126:                       # Preds ..B7.125
        movq      %r13, %rsi                                    #379.3
        lea       6336(%rsp), %rdi                              #379.3
        movl      6760(%rsp,%r15,4), %edx                       #379.29
        call      MD5_Update                                    #379.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.127:                       # Preds ..B7.126
        lea       6648(%rsp), %rdi                              #380.3
        lea       6336(%rsp), %rsi                              #380.3
        call      MD5_Final                                     #380.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.128:                       # Preds ..B7.127
        movl      6760(%rsp,%r15,4), %edx                       #381.24
        lea       6496(%rsp), %rdi                              #381.3
        lea       6648(%rsp), %rsi                              #381.3
        call      MD5_Update                                    #381.3
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.129:                       # Preds ..B7.128
        movl      6760(%rsp,%r15,4), %r15d                      #382.9
        testl     %r15d, %r15d                                  #382.19
        je        ..B7.136      # Prob 10%                      #382.19
                                # LOE r13 ebx ebp r12d r14d r15d
..B7.131:                       # Preds ..B7.129 ..B7.134
        testl     $1, %r15d                                     #383.9
        je        ..B7.133      # Prob 50%                      #383.9
                                # LOE r13 ebx ebp r12d r14d r15d
..B7.132:                       # Preds ..B7.131
        movl      $.L_2__STRING.3, %esi                         #384.5
        lea       6496(%rsp), %rdi                              #384.5
        movl      $1, %edx                                      #384.5
        call      MD5_Update                                    #384.5
        jmp       ..B7.134      # Prob 100%                     #384.5
                                # LOE r13 ebx ebp r12d r14d r15d
..B7.133:                       # Preds ..B7.131
        movq      %r13, %rsi                                    #386.5
        lea       6496(%rsp), %rdi                              #386.5
        movl      $1, %edx                                      #386.5
        call      MD5_Update                                    #386.5
                                # LOE r13 ebx ebp r12d r14d r15d
..B7.134:                       # Preds ..B7.133 ..B7.132
        shrl      $1, %r15d                                     #382.21
        testl     %r15d, %r15d                                  #382.19
        jne       ..B7.131      # Prob 82%                      #382.19
                                # LOE r13 ebx ebp r12d r14d r15d
..B7.136:                       # Preds ..B7.134 ..B7.129
        lea       6648(%rsp), %rdi                              #387.3
        lea       6496(%rsp), %rsi                              #387.3
        call      MD5_Final                                     #387.3
                                # LOE ebx ebp r12d r14d
..B7.137:                       # Preds ..B7.136
        shll      $4, %r12d                                     #388.12
        incl      %ebx                                          #324.2
        movl      6648(%rsp), %esi                              #388.26
        cmpl      $12, %ebx                                     #324.2
        movl      6652(%rsp), %r8d                              #389.30
        movl      6656(%rsp), %r10d                             #390.30
        movl      6660(%rsp), %r11d                             #391.31
        lea       (%rbp,%r12), %ecx                             #388.20
        lea       4(%r12,%rbp), %edi                            #389.25
        lea       8(%r12,%rbp), %r9d                            #390.25
        lea       12(%r12,%rbp), %ebp                           #391.25
        movl      %esi, 6144(%rsp,%rcx,4)                       #388.3
        movl      %r8d, 6144(%rsp,%rdi,4)                       #389.3
        movl      %r10d, 6144(%rsp,%r9,4)                       #390.3
        movl      %r11d, 6144(%rsp,%rbp,4)                      #391.3
        jb        ..B7.5        # Prob 91%                      #324.2
                                # LOE ebx r14d
..B7.138:                       # Preds ..B7.137
        movl      %r14d, %eax                                   #
        lea       (%rsp), %rbp                                  #
        xorl      %r13d, %r13d                                  #393.2
        lea       6144(%rsp), %r15                              #
        movl      %eax, %r14d                                   #
        lea       2304(%rsp), %rdx                              #
        lea       4608(%rsp), %rbx                              #
                                # LOE rbx rbp r15 r13d r14d
..B7.139:                       # Preds ..B7.193 ..B7.138
        movl      %r13d, %ecx                                   #393.2
        movl      $818089009, %eax                              #393.2
        shrl      $1, %ecx                                      #393.2
        mull      %ecx                                          #393.2
        shrl      $2, %edx                                      #393.2
        imull     $42, %edx, %edx                               #393.2
        negl      %edx                                          #393.2
        addl      %r13d, %edx                                   #393.2
        cmpl      $40, %edx                                     #393.2
        ja        ..B7.191      # Prob 50%                      #393.2
                                # LOE rdx rbx rbp r15 r13d r14d
..B7.140:                       # Preds ..B7.139
        movq      ..1..TPKT.6_0.0.6.38(,%rdx,8), %rcx           #393.2
        jmp       *%rcx                                         #393.2
                                # LOE rbx rbp r15 r13d r14d
..1.6_0.TAG.015.0.6.38:
..B7.156:                       # Preds ..B7.140
        movl      $1, %esi                                      #393.2
        movq      %rbp, %rdi                                    #393.2
        movl      %esi, %ecx                                    #393.2
        lea       6760(%rsp), %rdx                              #393.2
        xorl      %r8d, %r8d                                    #393.2
        movq      %r15, %r9                                     #393.2
        movl      $1, %r12d                                     #393.2
        call      mmxput3                                       #393.2
        jmp       ..B7.192      # Prob 100%                     #393.2
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.01c.0.6.38:
..1.6_0.TAG.0e.0.6.38:
..B7.162:                       # Preds ..B7.140 ..B7.140
        xorl      %ecx, %ecx                                    #393.2
        movl      $5, %r12d                                     #393.2
        lea       3840(%rsp), %rbx                              #
        movl      %ecx, %ebp                                    #
        movl      %r13d, 6664(%rsp)                             #
        movl      %ecx, %r13d                                   #
        movl      %r14d, 6808(%rsp)                             #
        movl      %ecx, %r14d                                   #
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.163:                       # Preds ..B7.164 ..B7.162
        movl      %r13d, %edi                                   #393.2
        movl      $64, %edx                                     #393.2
        movl      %ebp, %esi                                    #393.2
        addq      %rbx, %rdi                                    #393.2
        addq      %r15, %rsi                                    #393.2
        call      memcpy                                        #393.2
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.164:                       # Preds ..B7.163
        incl      %r14d                                         #393.2
        addl      $64, %ebp                                     #393.2
        addl      $256, %r13d                                   #393.2
        cmpl      $3, %r14d                                     #393.2
        jb        ..B7.163      # Prob 66%                      #393.2
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.165:                       # Preds ..B7.164
        movl      6664(%rsp), %r13d                             #
        lea       4608(%rsp), %rbx                              #
        movl      6808(%rsp), %r14d                             #
        lea       (%rsp), %rbp                                  #
        jmp       ..B7.192      # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.023.0.6.38:
..1.6_0.TAG.07.0.6.38:
..B7.171:                       # Preds ..B7.140 ..B7.140
        movq      %rbp, %rdi                                    #393.2
        movl      $4, %esi                                      #393.2
        movl      $1, %ecx                                      #393.2
        lea       6760(%rsp), %rdx                              #393.2
        movl      %r14d, %r8d                                   #393.2
        movq      %r15, %r9                                     #393.2
        movl      $4, %r12d                                     #393.2
        call      mmxput3                                       #393.2
        jmp       ..B7.192      # Prob 100%                     #393.2
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.024.0.6.38:
..1.6_0.TAG.01e.0.6.38:
..1.6_0.TAG.018.0.6.38:
..1.6_0.TAG.012.0.6.38:
..1.6_0.TAG.0c.0.6.38:
..1.6_0.TAG.06.0.6.38:
..B7.173:                       # Preds ..B7.140 ..B7.140 ..B7.140 ..B7.140 ..B7.140
                                #       ..B7.140
        xorl      %ecx, %ecx                                    #393.2
        movl      $3, %r12d                                     #393.2
        lea       2304(%rsp), %rbx                              #
        movl      %ecx, %ebp                                    #
        movl      %r13d, 6664(%rsp)                             #
        movl      %ecx, %r13d                                   #
        movl      %r14d, 6808(%rsp)                             #
        movl      %ecx, %r14d                                   #
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.174:                       # Preds ..B7.175 ..B7.173
        movl      %r13d, %edi                                   #393.2
        movl      $64, %edx                                     #393.2
        movl      %ebp, %esi                                    #393.2
        addq      %rbx, %rdi                                    #393.2
        addq      %r15, %rsi                                    #393.2
        call      memcpy                                        #393.2
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.175:                       # Preds ..B7.174
        incl      %r14d                                         #393.2
        addl      $64, %ebp                                     #393.2
        addl      $256, %r13d                                   #393.2
        cmpl      $3, %r14d                                     #393.2
        jb        ..B7.174      # Prob 66%                      #393.2
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.176:                       # Preds ..B7.175
        movl      6664(%rsp), %r13d                             #
        lea       4608(%rsp), %rbx                              #
        movl      6808(%rsp), %r14d                             #
        lea       (%rsp), %rbp                                  #
        jmp       ..B7.192      # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.027.0.6.38:
..1.6_0.TAG.021.0.6.38:
..1.6_0.TAG.01b.0.6.38:
..1.6_0.TAG.0f.0.6.38:
..1.6_0.TAG.09.0.6.38:
..1.6_0.TAG.03.0.6.38:
..B7.179:                       # Preds ..B7.140 ..B7.140 ..B7.140 ..B7.140 ..B7.140
                                #       ..B7.140
        movl      $2, %esi                                      #393.2
        movq      %rbp, %rdi                                    #393.2
        movl      %esi, %ecx                                    #393.2
        lea       6760(%rsp), %rdx                              #393.2
        xorl      %r8d, %r8d                                    #393.2
        movq      %r15, %r9                                     #393.2
        movl      $2, %r12d                                     #393.2
        call      mmxput3                                       #393.2
        jmp       ..B7.192      # Prob 100%                     #393.2
                                # LOE rbx rbp r12 r15 r13d r14d
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
..B7.181:                       # Preds ..B7.140 ..B7.140 ..B7.140 ..B7.140 ..B7.140
                                #       ..B7.140 ..B7.140 ..B7.140 ..B7.140 ..B7.140
                                #       ..B7.140 ..B7.140
        xorl      %ecx, %ecx                                    #393.2
        movl      $6, %r12d                                     #393.2
        movl      %ecx, %ebp                                    #
        movl      %r13d, 6664(%rsp)                             #
        movl      %ecx, %r13d                                   #
        movl      %r14d, 6808(%rsp)                             #
        movl      %ecx, %r14d                                   #
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.182:                       # Preds ..B7.183 ..B7.181
        movl      %r14d, %edi                                   #393.2
        movl      $64, %edx                                     #393.2
        movl      %r13d, %esi                                   #393.2
        addq      %rbx, %rdi                                    #393.2
        addq      %r15, %rsi                                    #393.2
        call      memcpy                                        #393.2
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.183:                       # Preds ..B7.182
        incl      %ebp                                          #393.2
        addl      $64, %r13d                                    #393.2
        addl      $256, %r14d                                   #393.2
        cmpl      $3, %ebp                                      #393.2
        jb        ..B7.182      # Prob 66%                      #393.2
                                # LOE rbx r12 r15 ebp r13d r14d
..B7.184:                       # Preds ..B7.183
        movl      6664(%rsp), %r13d                             #
        lea       (%rsp), %rbp                                  #
        movl      6808(%rsp), %r14d                             #
        jmp       ..B7.192      # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.00.0.6.38:
..B7.187:                       # Preds ..B7.140
        xorl      %ecx, %ecx                                    #393.2
        xorl      %r12d, %r12d                                  #393.2
        movl      %ecx, %ebx                                    #
        movl      %r13d, 6664(%rsp)                             #
        movl      %ecx, %r13d                                   #
        movl      %r14d, 6808(%rsp)                             #
        movl      %ecx, %r14d                                   #
                                # LOE rbp r12 r15 ebx r13d r14d
..B7.188:                       # Preds ..B7.189 ..B7.187
        movl      %r14d, %edi                                   #393.2
        movl      $64, %edx                                     #393.2
        movl      %r13d, %esi                                   #393.2
        addq      %rbp, %rdi                                    #393.2
        addq      %r15, %rsi                                    #393.2
        call      memcpy                                        #393.2
                                # LOE rbp r12 r15 ebx r13d r14d
..B7.189:                       # Preds ..B7.188
        incl      %ebx                                          #393.2
        addl      $64, %r13d                                    #393.2
        addl      $256, %r14d                                   #393.2
        cmpl      $3, %ebx                                      #393.2
        jb        ..B7.188      # Prob 66%                      #393.2
                                # LOE rbp r12 r15 ebx r13d r14d
..B7.190:                       # Preds ..B7.189
        movl      6664(%rsp), %r13d                             #
        lea       4608(%rsp), %rbx                              #
        movl      6808(%rsp), %r14d                             #
        jmp       ..B7.192      # Prob 100%                     #
                                # LOE rbx rbp r12 r15 r13d r14d
..1.6_0.TAG.DEFAULT.0.6.38:
..B7.191:                       # Preds ..B7.140 ..B7.139
        movq      %rbp, %rdi                                    #393.2
        movl      $7, %esi                                      #393.2
        movl      $2, %ecx                                      #393.2
        lea       6760(%rsp), %rdx                              #393.2
        movl      %r14d, %r8d                                   #393.2
        movq      %r15, %r9                                     #393.2
        movl      $7, %r12d                                     #393.2
        call      mmxput3                                       #393.2
                                # LOE rbx rbp r12 r15 r13d r14d
..B7.192:                       # Preds ..B7.190 ..B7.184 ..B7.179 ..B7.176 ..B7.171
                                #       ..B7.165 ..B7.156 ..B7.191
        movq      %r15, %rsi                                    #393.2
        lea       (%r12,%r12,2), %rdi                           #393.2
        shlq      $8, %rdi                                      #393.2
        movl      $1, %edx                                      #393.2
        addq      %rbp, %rdi                                    #393.2
        call      SSEmd5body                                    #393.2
                                # LOE rbx rbp r15 r13d r14d
..B7.193:                       # Preds ..B7.192
        incl      %r13d                                         #393.2
        cmpl      $1000, %r13d                                  #393.2
        jb        ..B7.139      # Prob 99%                      #393.2
                                # LOE rbx rbp r15 r13d r14d
..B7.194:                       # Preds ..B7.193
        movq      %r15, %rsi                                    #394.2
        movl      $192, %edx                                    #394.2
        movq      6488(%rsp), %rdi                              #394.2
        call      memcpy                                        #394.2
                                # LOE r12
..B7.195:                       # Preds ..B7.194
        addq      $6824, %rsp                                   #395.1
..___tag_value_md5cryptsse.118:                                 #
        popq      %rbp                                          #395.1
..___tag_value_md5cryptsse.120:                                 #
        popq      %rbx                                          #395.1
..___tag_value_md5cryptsse.122:                                 #
        popq      %r15                                          #395.1
..___tag_value_md5cryptsse.124:                                 #
        popq      %r14                                          #395.1
..___tag_value_md5cryptsse.126:                                 #
        popq      %r13                                          #395.1
..___tag_value_md5cryptsse.128:                                 #
        popq      %r12                                          #395.1
..___tag_value_md5cryptsse.130:                                 #
        ret                                                     #395.1
..___tag_value_md5cryptsse.131:                                 #
                                # LOE
..B7.196:                       # Preds ..B7.66                 # Infreq
        testl     %esi, %esi                                    #347.3
        ja        ..B7.70       # Prob 50%                      #347.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.197:                       # Preds ..B7.196                # Infreq
        movb      $128, 3840(%rax,%rdi)                         #348.3
        lea       4608(%rsp,%rcx), %rax                         #350.3
        jmp       ..B7.77       # Prob 100%                     #350.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.198:                       # Preds ..B7.102                # Infreq
        testl     %r14d, %r14d                                  #356.3
        ja        ..B7.105      # Prob 50%                      #356.3
        jmp       ..B7.112      # Prob 100%                     #356.3
                                # LOE rdi r9 r13 r15 edx ebx ebp esi r12d r14d
..B7.199:                       # Preds ..B7.120                # Infreq
        movl      $.L_2__STRING.1, %esi                         #372.4
        lea       6496(%rsp), %rdi                              #372.4
        movl      $6, %edx                                      #372.4
        call      MD5_Update                                    #372.4
        jmp       ..B7.122      # Prob 100%                     #372.4
                                # LOE r13 r15 ebx ebp r12d r14d
..B7.208:                       # Preds ..B7.76 ..B7.81         # Infreq
        testl     %esi, %esi                                    #328.3
        ja        ..B7.85       # Prob 50%                      #328.3
        jmp       ..B7.97       # Prob 100%                     #328.3
                                # LOE rax rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.210:                       # Preds ..B7.45                 # Infreq
        testl     %esi, %esi                                    #328.3
        jmp       ..B7.47       # Prob 100%                     #328.3
                                # LOE rax rcx rdi r13 r15 edx ebx ebp esi r12d r14d
..B7.211:                       # Preds ..B7.19                 # Infreq
        testl     %esi, %esi                                    #328.3
        jmp       ..B7.21       # Prob 100%                     #328.3
        .align    16,0x90
..___tag_value_md5cryptsse.138:                                 #
                                # LOE rcx rdi r11 r13 r15 ebx ebp esi r12d r14d
# mark_end;
	.type	md5cryptsse,@function
	.size	md5cryptsse,.-md5cryptsse
	.section .rodata, "a"
	.space 24	# pad
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
# mark_begin;
       .align    16,0x90
	.globl SSEmd4body
SSEmd4body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %edx
..B8.1:                         # Preds ..B8.0
..___tag_value_SSEmd4body.139:                                  #423.1
        subq      $776, %rsp                                    #423.1
..___tag_value_SSEmd4body.141:                                  #
        testl     %edx, %edx                                    #433.5
        je        ..B8.3        # Prob 50%                      #433.5
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15
..B8.2:                         # Preds ..B8.1
        movdqa    .L_2il0floatpacket.474(%rip), %xmm1           #437.11
        movdqa    .L_2il0floatpacket.475(%rip), %xmm3           #438.11
        movdqa    %xmm1, %xmm4                                  #437.11
        movdqa    .L_2il0floatpacket.476(%rip), %xmm2           #439.11
        movdqa    %xmm3, %xmm5                                  #438.11
        movdqa    .L_2il0floatpacket.477(%rip), %xmm9           #440.11
        movdqa    %xmm2, %xmm14                                 #439.11
        movdqa    %xmm9, %xmm10                                 #440.11
        movdqa    %xmm1, %xmm7                                  #437.11
        movdqa    %xmm3, %xmm13                                 #438.11
        movdqa    %xmm2, %xmm15                                 #439.11
        movdqa    %xmm9, %xmm11                                 #440.11
        jmp       ..B8.4        # Prob 100%                     #440.11
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15 xmm1 xmm2 xmm3 xmm4 xmm5 xmm7 xmm9 xmm10 xmm11 xmm13 xmm14 xmm15
..B8.3:                         # Preds ..B8.1
        movdqa    (%rsi), %xmm1                                 #422.6
        movdqa    16(%rsi), %xmm3                               #422.6
        movdqa    32(%rsi), %xmm2                               #422.6
        movdqa    48(%rsi), %xmm9                               #422.6
        movdqa    64(%rsi), %xmm4                               #422.6
        movdqa    80(%rsi), %xmm5                               #422.6
        movdqa    96(%rsi), %xmm14                              #422.6
        movdqa    112(%rsi), %xmm10                             #422.6
        movdqa    128(%rsi), %xmm7                              #422.6
        movdqa    144(%rsi), %xmm13                             #422.6
        movdqa    160(%rsi), %xmm15                             #422.6
        movdqa    176(%rsi), %xmm11                             #422.6
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15 xmm1 xmm2 xmm3 xmm4 xmm5 xmm7 xmm9 xmm10 xmm11 xmm13 xmm14 xmm15
..B8.4:                         # Preds ..B8.2 ..B8.3
        movdqa    %xmm2, %xmm6                                  #456.3
        movdqa    %xmm14, %xmm12                                #456.3
        pxor      %xmm9, %xmm6                                  #456.3
        pxor      %xmm0, %xmm0                                  #455.9
        pand      %xmm3, %xmm6                                  #456.3
        paddd     %xmm0, %xmm1                                  #456.3
        pxor      %xmm9, %xmm6                                  #456.3
        pxor      %xmm10, %xmm12                                #456.3
        movdqa    (%rdi), %xmm8                                 #422.6
        paddd     %xmm6, %xmm1                                  #456.3
        movdqa    %xmm8, 720(%rsp)                              #422.6
        paddd     %xmm8, %xmm1                                  #456.3
        movdqa    %xmm15, %xmm8                                 #456.3
        pand      %xmm5, %xmm12                                 #456.3
        pxor      %xmm11, %xmm8                                 #456.3
        paddd     %xmm0, %xmm4                                  #456.3
        pxor      %xmm10, %xmm12                                #456.3
        pand      %xmm13, %xmm8                                 #456.3
        movdqa    256(%rdi), %xmm6                              #422.6
        paddd     %xmm12, %xmm4                                 #456.3
        paddd     %xmm0, %xmm7                                  #456.3
        pxor      %xmm11, %xmm8                                 #456.3
        movdqa    512(%rdi), %xmm12                             #422.6
        paddd     %xmm6, %xmm4                                  #456.3
        paddd     %xmm8, %xmm7                                  #456.3
        movdqa    %xmm1, %xmm8                                  #456.3
        movdqa    %xmm12, 752(%rsp)                             #422.6
        paddd     %xmm12, %xmm7                                 #456.3
        movdqa    %xmm4, %xmm12                                 #456.3
        psrld     $29, %xmm4                                    #456.3
        pslld     $3, %xmm12                                    #456.3
        pslld     $3, %xmm8                                     #456.3
        psrld     $29, %xmm1                                    #456.3
        por       %xmm4, %xmm12                                 #456.3
        movdqa    %xmm3, %xmm4                                  #457.3
        por       %xmm1, %xmm8                                  #456.3
        pxor      %xmm2, %xmm4                                  #457.3
        paddd     %xmm0, %xmm9                                  #457.3
        movdqa    %xmm6, 736(%rsp)                              #422.6
        movdqa    %xmm7, %xmm6                                  #456.3
        pand      %xmm8, %xmm4                                  #457.3
        pslld     $3, %xmm6                                     #456.3
        psrld     $29, %xmm7                                    #456.3
        pxor      %xmm2, %xmm4                                  #457.3
        movdqa    %xmm5, %xmm1                                  #457.3
        por       %xmm7, %xmm6                                  #456.3
        movdqa    16(%rdi), %xmm7                               #422.6
        paddd     %xmm4, %xmm9                                  #457.3
        pxor      %xmm14, %xmm1                                 #457.3
        paddd     %xmm7, %xmm9                                  #457.3
        movdqa    %xmm7, 48(%rsp)                               #422.6
        pand      %xmm12, %xmm1                                 #457.3
        movdqa    %xmm13, %xmm7                                 #457.3
        paddd     %xmm0, %xmm10                                 #457.3
        pxor      %xmm14, %xmm1                                 #457.3
        pxor      %xmm15, %xmm7                                 #457.3
        movdqa    272(%rdi), %xmm4                              #422.6
        paddd     %xmm1, %xmm10                                 #457.3
        pand      %xmm6, %xmm7                                  #457.3
        paddd     %xmm4, %xmm10                                 #457.3
        movdqa    %xmm4, 112(%rsp)                              #422.6
        paddd     %xmm0, %xmm11                                 #457.3
        pxor      %xmm15, %xmm7                                 #457.3
        movdqa    %xmm9, %xmm4                                  #457.3
        movdqa    528(%rdi), %xmm1                              #422.6
        paddd     %xmm7, %xmm11                                 #457.3
        pslld     $7, %xmm4                                     #457.3
        psrld     $25, %xmm9                                    #457.3
        paddd     %xmm1, %xmm11                                 #457.3
        por       %xmm9, %xmm4                                  #457.3
        movdqa    %xmm3, %xmm9                                  #458.3
        movdqa    %xmm10, %xmm7                                 #457.3
        movdqa    %xmm1, 128(%rsp)                              #422.6
        movdqa    %xmm11, %xmm1                                 #457.3
        pxor      %xmm8, %xmm9                                  #458.3
        pslld     $7, %xmm1                                     #457.3
        psrld     $25, %xmm11                                   #457.3
        pand      %xmm4, %xmm9                                  #458.3
        pslld     $7, %xmm7                                     #457.3
        psrld     $25, %xmm10                                   #457.3
        por       %xmm11, %xmm1                                 #457.3
        paddd     %xmm0, %xmm2                                  #458.3
        pxor      %xmm3, %xmm9                                  #458.3
        movdqa    %xmm5, %xmm11                                 #458.3
        por       %xmm10, %xmm7                                 #457.3
        paddd     %xmm9, %xmm2                                  #458.3
        movdqa    32(%rdi), %xmm10                              #422.6
        pxor      %xmm12, %xmm11                                #458.3
        movdqa    %xmm10, 208(%rsp)                             #422.6
        paddd     %xmm10, %xmm2                                 #458.3
        pand      %xmm7, %xmm11                                 #458.3
        movdqa    %xmm13, %xmm10                                #458.3
        paddd     %xmm0, %xmm14                                 #458.3
        pxor      %xmm5, %xmm11                                 #458.3
        pxor      %xmm6, %xmm10                                 #458.3
        paddd     %xmm11, %xmm14                                #458.3
        movdqa    288(%rdi), %xmm9                              #422.6
        pand      %xmm1, %xmm10                                 #458.3
        paddd     %xmm9, %xmm14                                 #458.3
        paddd     %xmm0, %xmm15                                 #458.3
        pxor      %xmm13, %xmm10                                #458.3
        paddd     %xmm0, %xmm3                                  #459.3
        paddd     %xmm10, %xmm15                                #458.3
        movdqa    %xmm14, %xmm10                                #458.3
        movdqa    %xmm9, 224(%rsp)                              #422.6
        movdqa    %xmm2, %xmm9                                  #458.3
        pslld     $11, %xmm10                                   #458.3
        psrld     $21, %xmm14                                   #458.3
        movdqa    544(%rdi), %xmm11                             #422.6
        pslld     $11, %xmm9                                    #458.3
        psrld     $21, %xmm2                                    #458.3
        por       %xmm14, %xmm10                                #458.3
        movdqa    %xmm4, %xmm14                                 #459.3
        paddd     %xmm11, %xmm15                                #458.3
        por       %xmm2, %xmm9                                  #458.3
        pxor      %xmm8, %xmm14                                 #459.3
        movdqa    %xmm11, 240(%rsp)                             #422.6
        movdqa    %xmm15, %xmm11                                #458.3
        pand      %xmm9, %xmm14                                 #459.3
        pslld     $11, %xmm11                                   #458.3
        psrld     $21, %xmm15                                   #458.3
        pxor      %xmm8, %xmm14                                 #459.3
        por       %xmm15, %xmm11                                #458.3
        paddd     %xmm14, %xmm3                                 #459.3
        movdqa    48(%rdi), %xmm15                              #422.6
        movdqa    %xmm7, %xmm2                                  #459.3
        movdqa    %xmm15, (%rsp)                                #422.6
        paddd     %xmm15, %xmm3                                 #459.3
        pxor      %xmm12, %xmm2                                 #459.3
        movdqa    %xmm1, %xmm15                                 #459.3
        pand      %xmm10, %xmm2                                 #459.3
        pxor      %xmm6, %xmm15                                 #459.3
        paddd     %xmm0, %xmm5                                  #459.3
        pxor      %xmm12, %xmm2                                 #459.3
        pand      %xmm11, %xmm15                                #459.3
        paddd     %xmm2, %xmm5                                  #459.3
        movdqa    304(%rdi), %xmm14                             #422.6
        paddd     %xmm0, %xmm13                                 #459.3
        pxor      %xmm6, %xmm15                                 #459.3
        paddd     %xmm14, %xmm5                                 #459.3
        movdqa    560(%rdi), %xmm2                              #422.6
        paddd     %xmm15, %xmm13                                #459.3
        paddd     %xmm2, %xmm13                                 #459.3
        movdqa    %xmm5, %xmm15                                 #459.3
        movdqa    %xmm14, 16(%rsp)                              #422.6
        movdqa    %xmm3, %xmm14                                 #459.3
        movdqa    %xmm2, 32(%rsp)                               #422.6
        pslld     $19, %xmm15                                   #459.3
        psrld     $13, %xmm5                                    #459.3
        movdqa    %xmm13, %xmm2                                 #459.3
        pslld     $19, %xmm14                                   #459.3
        psrld     $13, %xmm3                                    #459.3
        por       %xmm5, %xmm15                                 #459.3
        pslld     $19, %xmm2                                    #459.3
        psrld     $13, %xmm13                                   #459.3
        movdqa    %xmm9, %xmm5                                  #460.3
        por       %xmm3, %xmm14                                 #459.3
        por       %xmm13, %xmm2                                 #459.3
        pxor      %xmm4, %xmm5                                  #460.3
        movdqa    %xmm10, %xmm13                                #460.3
        pand      %xmm14, %xmm5                                 #460.3
        pxor      %xmm7, %xmm13                                 #460.3
        paddd     %xmm0, %xmm8                                  #460.3
        pxor      %xmm4, %xmm5                                  #460.3
        pand      %xmm15, %xmm13                                #460.3
        paddd     %xmm5, %xmm8                                  #460.3
        movdqa    64(%rdi), %xmm3                               #422.6
        paddd     %xmm0, %xmm12                                 #460.3
        pxor      %xmm7, %xmm13                                 #460.3
        paddd     %xmm3, %xmm8                                  #460.3
        movdqa    320(%rdi), %xmm5                              #422.6
        paddd     %xmm13, %xmm12                                #460.3
        movdqa    %xmm5, 432(%rsp)                              #422.6
        paddd     %xmm5, %xmm12                                 #460.3
        movdqa    %xmm8, %xmm5                                  #460.3
        psrld     $29, %xmm8                                    #460.3
        movdqa    %xmm3, 416(%rsp)                              #422.6
        movdqa    %xmm11, %xmm3                                 #460.3
        pslld     $3, %xmm5                                     #460.3
        pxor      %xmm1, %xmm3                                  #460.3
        por       %xmm8, %xmm5                                  #460.3
        movdqa    %xmm12, %xmm8                                 #460.3
        pand      %xmm2, %xmm3                                  #460.3
        pslld     $3, %xmm8                                     #460.3
        psrld     $29, %xmm12                                   #460.3
        paddd     %xmm0, %xmm6                                  #460.3
        pxor      %xmm1, %xmm3                                  #460.3
        por       %xmm12, %xmm8                                 #460.3
        movdqa    %xmm14, %xmm12                                #461.3
        paddd     %xmm3, %xmm6                                  #460.3
        movdqa    576(%rdi), %xmm13                             #422.6
        pxor      %xmm9, %xmm12                                 #461.3
        paddd     %xmm13, %xmm6                                 #460.3
        pand      %xmm5, %xmm12                                 #461.3
        movdqa    %xmm6, %xmm3                                  #460.3
        paddd     %xmm0, %xmm4                                  #461.3
        pxor      %xmm9, %xmm12                                 #461.3
        pslld     $3, %xmm3                                     #460.3
        movdqa    %xmm13, 448(%rsp)                             #422.6
        psrld     $29, %xmm6                                    #460.3
        paddd     %xmm12, %xmm4                                 #461.3
        movdqa    %xmm15, %xmm12                                #461.3
        movdqa    %xmm2, %xmm13                                 #461.3
        por       %xmm6, %xmm3                                  #460.3
        pxor      %xmm10, %xmm12                                #461.3
        pxor      %xmm11, %xmm13                                #461.3
        pand      %xmm8, %xmm12                                 #461.3
        pand      %xmm3, %xmm13                                 #461.3
        movdqa    80(%rdi), %xmm6                               #422.6
        paddd     %xmm0, %xmm7                                  #461.3
        pxor      %xmm10, %xmm12                                #461.3
        paddd     %xmm0, %xmm1                                  #461.3
        pxor      %xmm11, %xmm13                                #461.3
        paddd     %xmm6, %xmm4                                  #461.3
        paddd     %xmm12, %xmm7                                 #461.3
        paddd     %xmm13, %xmm1                                 #461.3
        movdqa    592(%rdi), %xmm12                             #422.6
        paddd     %xmm0, %xmm9                                  #462.3
        movdqa    %xmm6, 144(%rsp)                              #422.6
        paddd     %xmm12, %xmm1                                 #461.3
        movdqa    336(%rdi), %xmm6                              #422.6
        movdqa    %xmm3, %xmm13                                 #462.3
        movdqa    %xmm12, 176(%rsp)                             #422.6
        movdqa    %xmm4, %xmm12                                 #461.3
        paddd     %xmm6, %xmm7                                  #461.3
        pslld     $7, %xmm12                                    #461.3
        psrld     $25, %xmm4                                    #461.3
        pxor      %xmm2, %xmm13                                 #462.3
        por       %xmm4, %xmm12                                 #461.3
        movdqa    %xmm7, %xmm4                                  #461.3
        pslld     $7, %xmm4                                     #461.3
        psrld     $25, %xmm7                                    #461.3
        por       %xmm7, %xmm4                                  #461.3
        movdqa    %xmm5, %xmm7                                  #462.3
        pxor      %xmm14, %xmm7                                 #462.3
        paddd     %xmm0, %xmm10                                 #462.3
        pand      %xmm12, %xmm7                                 #462.3
        paddd     %xmm0, %xmm11                                 #462.3
        movdqa    %xmm6, 160(%rsp)                              #422.6
        movdqa    %xmm1, %xmm6                                  #461.3
        pxor      %xmm14, %xmm7                                 #462.3
        pslld     $7, %xmm6                                     #461.3
        psrld     $25, %xmm1                                    #461.3
        paddd     %xmm7, %xmm9                                  #462.3
        movdqa    %xmm8, %xmm7                                  #462.3
        por       %xmm1, %xmm6                                  #461.3
        pxor      %xmm15, %xmm7                                 #462.3
        pand      %xmm6, %xmm13                                 #462.3
        pand      %xmm4, %xmm7                                  #462.3
        pxor      %xmm2, %xmm13                                 #462.3
        movdqa    96(%rdi), %xmm1                               #422.6
        pxor      %xmm15, %xmm7                                 #462.3
        paddd     %xmm1, %xmm9                                  #462.3
        paddd     %xmm7, %xmm10                                 #462.3
        movdqa    608(%rdi), %xmm7                              #422.6
        paddd     %xmm13, %xmm11                                #462.3
        movdqa    %xmm1, 336(%rsp)                              #422.6
        paddd     %xmm7, %xmm11                                 #462.3
        movdqa    352(%rdi), %xmm1                              #422.6
        paddd     %xmm0, %xmm14                                 #463.3
        movdqa    %xmm7, 368(%rsp)                              #422.6
        movdqa    %xmm9, %xmm7                                  #462.3
        paddd     %xmm1, %xmm10                                 #462.3
        pslld     $11, %xmm7                                    #462.3
        psrld     $21, %xmm9                                    #462.3
        movdqa    %xmm6, %xmm13                                 #463.3
        por       %xmm9, %xmm7                                  #462.3
        movdqa    %xmm10, %xmm9                                 #462.3
        pslld     $11, %xmm9                                    #462.3
        psrld     $21, %xmm10                                   #462.3
        por       %xmm10, %xmm9                                 #462.3
        movdqa    %xmm12, %xmm10                                #463.3
        pxor      %xmm5, %xmm10                                 #463.3
        pxor      %xmm3, %xmm13                                 #463.3
        pand      %xmm7, %xmm10                                 #463.3
        paddd     %xmm0, %xmm15                                 #463.3
        movdqa    %xmm1, 352(%rsp)                              #422.6
        movdqa    %xmm11, %xmm1                                 #462.3
        pxor      %xmm5, %xmm10                                 #463.3
        pslld     $11, %xmm1                                    #462.3
        psrld     $21, %xmm11                                   #462.3
        paddd     %xmm10, %xmm14                                #463.3
        movdqa    %xmm4, %xmm10                                 #463.3
        por       %xmm11, %xmm1                                 #462.3
        pxor      %xmm8, %xmm10                                 #463.3
        pand      %xmm1, %xmm13                                 #463.3
        pand      %xmm9, %xmm10                                 #463.3
        paddd     %xmm0, %xmm2                                  #463.3
        movdqa    112(%rdi), %xmm11                             #422.6
        pxor      %xmm8, %xmm10                                 #463.3
        pxor      %xmm3, %xmm13                                 #463.3
        paddd     %xmm11, %xmm14                                #463.3
        paddd     %xmm10, %xmm15                                #463.3
        paddd     %xmm13, %xmm2                                 #463.3
        movdqa    624(%rdi), %xmm10                             #422.6
        paddd     %xmm0, %xmm5                                  #464.3
        movdqa    %xmm10, 64(%rsp)                              #422.6
        paddd     %xmm10, %xmm2                                 #463.3
        movdqa    %xmm14, %xmm10                                #463.3
        psrld     $13, %xmm14                                   #463.3
        pslld     $19, %xmm10                                   #463.3
        movdqa    %xmm2, %xmm13                                 #463.3
        movdqa    %xmm11, 96(%rsp)                              #422.6
        por       %xmm14, %xmm10                                #463.3
        movdqa    368(%rdi), %xmm11                             #422.6
        movdqa    %xmm7, %xmm14                                 #464.3
        paddd     %xmm11, %xmm15                                #463.3
        pxor      %xmm12, %xmm14                                #464.3
        movdqa    %xmm11, 80(%rsp)                              #422.6
        movdqa    %xmm15, %xmm11                                #463.3
        pand      %xmm10, %xmm14                                #464.3
        pslld     $19, %xmm11                                   #463.3
        psrld     $13, %xmm15                                   #463.3
        pxor      %xmm12, %xmm14                                #464.3
        por       %xmm15, %xmm11                                #463.3
        pslld     $19, %xmm13                                   #463.3
        movdqa    128(%rdi), %xmm15                             #422.6
        psrld     $13, %xmm2                                    #463.3
        paddd     %xmm14, %xmm5                                 #464.3
        por       %xmm2, %xmm13                                 #463.3
        movdqa    %xmm15, 624(%rsp)                             #422.6
        paddd     %xmm15, %xmm5                                 #464.3
        movdqa    %xmm9, %xmm2                                  #464.3
        movdqa    %xmm1, %xmm15                                 #464.3
        pxor      %xmm4, %xmm2                                  #464.3
        pxor      %xmm6, %xmm15                                 #464.3
        pand      %xmm11, %xmm2                                 #464.3
        pand      %xmm13, %xmm15                                #464.3
        paddd     %xmm0, %xmm8                                  #464.3
        pxor      %xmm4, %xmm2                                  #464.3
        paddd     %xmm0, %xmm3                                  #464.3
        pxor      %xmm6, %xmm15                                 #464.3
        paddd     %xmm2, %xmm8                                  #464.3
        paddd     %xmm15, %xmm3                                 #464.3
        movdqa    640(%rdi), %xmm2                              #422.6
        paddd     %xmm0, %xmm12                                 #465.3
        movdqa    384(%rdi), %xmm14                             #422.6
        paddd     %xmm2, %xmm3                                  #464.3
        movdqa    %xmm2, 592(%rsp)                              #422.6
        movdqa    %xmm5, %xmm2                                  #464.3
        paddd     %xmm14, %xmm8                                 #464.3
        pslld     $3, %xmm2                                     #464.3
        psrld     $29, %xmm5                                    #464.3
        movdqa    %xmm11, %xmm15                                #465.3
        por       %xmm5, %xmm2                                  #464.3
        movdqa    %xmm8, %xmm5                                  #464.3
        pslld     $3, %xmm5                                     #464.3
        psrld     $29, %xmm8                                    #464.3
        por       %xmm8, %xmm5                                  #464.3
        movdqa    %xmm3, %xmm8                                  #464.3
        pslld     $3, %xmm8                                     #464.3
        psrld     $29, %xmm3                                    #464.3
        por       %xmm3, %xmm8                                  #464.3
        movdqa    %xmm10, %xmm3                                 #465.3
        pxor      %xmm7, %xmm3                                  #465.3
        pxor      %xmm9, %xmm15                                 #465.3
        pand      %xmm2, %xmm3                                  #465.3
        pand      %xmm5, %xmm15                                 #465.3
        pxor      %xmm7, %xmm3                                  #465.3
        paddd     %xmm0, %xmm4                                  #465.3
        movdqa    %xmm14, 576(%rsp)                             #422.6
        paddd     %xmm3, %xmm12                                 #465.3
        movdqa    144(%rdi), %xmm14                             #422.6
        pxor      %xmm9, %xmm15                                 #465.3
        movdqa    %xmm14, 320(%rsp)                             #422.6
        paddd     %xmm14, %xmm12                                #465.3
        movdqa    %xmm13, %xmm14                                #465.3
        paddd     %xmm15, %xmm4                                 #465.3
        pxor      %xmm1, %xmm14                                 #465.3
        paddd     %xmm0, %xmm6                                  #465.3
        pand      %xmm8, %xmm14                                 #465.3
        paddd     %xmm0, %xmm7                                  #466.3
        movdqa    400(%rdi), %xmm3                              #422.6
        pxor      %xmm1, %xmm14                                 #465.3
        movdqa    %xmm3, 304(%rsp)                              #422.6
        paddd     %xmm3, %xmm4                                  #465.3
        movdqa    656(%rdi), %xmm3                              #422.6
        paddd     %xmm14, %xmm6                                 #465.3
        movdqa    %xmm3, 288(%rsp)                              #422.6
        paddd     %xmm3, %xmm6                                  #465.3
        movdqa    %xmm12, %xmm3                                 #465.3
        psrld     $25, %xmm12                                   #465.3
        pslld     $7, %xmm3                                     #465.3
        movdqa    %xmm5, %xmm15                                 #466.3
        por       %xmm12, %xmm3                                 #465.3
        movdqa    %xmm4, %xmm12                                 #465.3
        pslld     $7, %xmm12                                    #465.3
        psrld     $25, %xmm4                                    #465.3
        por       %xmm4, %xmm12                                 #465.3
        movdqa    %xmm6, %xmm4                                  #465.3
        pslld     $7, %xmm4                                     #465.3
        psrld     $25, %xmm6                                    #465.3
        por       %xmm6, %xmm4                                  #465.3
        movdqa    %xmm2, %xmm6                                  #466.3
        pxor      %xmm10, %xmm6                                 #466.3
        pxor      %xmm11, %xmm15                                #466.3
        pand      %xmm3, %xmm6                                  #466.3
        pand      %xmm12, %xmm15                                #466.3
        pxor      %xmm10, %xmm6                                 #466.3
        paddd     %xmm0, %xmm9                                  #466.3
        movdqa    160(%rdi), %xmm14                             #422.6
        paddd     %xmm6, %xmm7                                  #466.3
        movdqa    %xmm14, 496(%rsp)                             #422.6
        paddd     %xmm14, %xmm7                                 #466.3
        movdqa    %xmm8, %xmm14                                 #466.3
        pxor      %xmm11, %xmm15                                #466.3
        pxor      %xmm13, %xmm14                                #466.3
        paddd     %xmm15, %xmm9                                 #466.3
        pand      %xmm4, %xmm14                                 #466.3
        paddd     %xmm0, %xmm1                                  #466.3
        movdqa    416(%rdi), %xmm6                              #422.6
        pxor      %xmm13, %xmm14                                #466.3
        movdqa    %xmm6, 528(%rsp)                              #422.6
        paddd     %xmm6, %xmm9                                  #466.3
        movdqa    672(%rdi), %xmm6                              #422.6
        paddd     %xmm14, %xmm1                                 #466.3
        movdqa    %xmm6, 512(%rsp)                              #422.6
        paddd     %xmm6, %xmm1                                  #466.3
        movdqa    %xmm7, %xmm6                                  #466.3
        psrld     $21, %xmm7                                    #466.3
        pslld     $11, %xmm6                                    #466.3
        paddd     %xmm0, %xmm10                                 #467.3
        por       %xmm7, %xmm6                                  #466.3
        movdqa    %xmm9, %xmm7                                  #466.3
        pslld     $11, %xmm7                                    #466.3
        psrld     $21, %xmm9                                    #466.3
        por       %xmm9, %xmm7                                  #466.3
        movdqa    %xmm1, %xmm9                                  #466.3
        pslld     $11, %xmm9                                    #466.3
        psrld     $21, %xmm1                                    #466.3
        por       %xmm1, %xmm9                                  #466.3
        movdqa    %xmm3, %xmm1                                  #467.3
        pxor      %xmm2, %xmm1                                  #467.3
        movdqa    %xmm12, %xmm15                                #467.3
        pand      %xmm6, %xmm1                                  #467.3
        pxor      %xmm5, %xmm15                                 #467.3
        pxor      %xmm2, %xmm1                                  #467.3
        pand      %xmm7, %xmm15                                 #467.3
        movdqa    176(%rdi), %xmm14                             #422.6
        paddd     %xmm1, %xmm10                                 #467.3
        movdqa    %xmm14, 192(%rsp)                             #422.6
        paddd     %xmm14, %xmm10                                #467.3
        movdqa    %xmm4, %xmm14                                 #467.3
        paddd     %xmm0, %xmm11                                 #467.3
        pxor      %xmm8, %xmm14                                 #467.3
        pxor      %xmm5, %xmm15                                 #467.3
        pand      %xmm9, %xmm14                                 #467.3
        paddd     %xmm15, %xmm11                                #467.3
        movdqa    432(%rdi), %xmm1                              #422.6
        paddd     %xmm0, %xmm13                                 #467.3
        pxor      %xmm8, %xmm14                                 #467.3
        paddd     %xmm1, %xmm11                                 #467.3
        movdqa    %xmm1, 256(%rsp)                              #422.6
        paddd     %xmm14, %xmm13                                #467.3
        movdqa    688(%rdi), %xmm1                              #422.6
        movdqa    %xmm7, %xmm15                                 #468.3
        movdqa    %xmm1, 272(%rsp)                              #422.6
        paddd     %xmm1, %xmm13                                 #467.3
        movdqa    %xmm10, %xmm1                                 #467.3
        psrld     $13, %xmm10                                   #467.3
        pslld     $19, %xmm1                                    #467.3
        paddd     %xmm0, %xmm2                                  #468.3
        por       %xmm10, %xmm1                                 #467.3
        movdqa    %xmm11, %xmm10                                #467.3
        pslld     $19, %xmm10                                   #467.3
        psrld     $13, %xmm11                                   #467.3
        por       %xmm11, %xmm10                                #467.3
        movdqa    %xmm13, %xmm11                                #467.3
        pslld     $19, %xmm11                                   #467.3
        psrld     $13, %xmm13                                   #467.3
        por       %xmm13, %xmm11                                #467.3
        movdqa    %xmm6, %xmm13                                 #468.3
        pxor      %xmm3, %xmm13                                 #468.3
        paddd     %xmm0, %xmm5                                  #468.3
        pand      %xmm1, %xmm13                                 #468.3
        pxor      %xmm12, %xmm15                                #468.3
        paddd     %xmm0, %xmm8                                  #468.3
        movdqa    %xmm9, %xmm0                                  #468.3
        pxor      %xmm3, %xmm13                                 #468.3
        pand      %xmm10, %xmm15                                #468.3
        pxor      %xmm4, %xmm0                                  #468.3
        paddd     %xmm13, %xmm2                                 #468.3
        movdqa    192(%rdi), %xmm14                             #422.6
        pxor      %xmm12, %xmm15                                #468.3
        pand      %xmm11, %xmm0                                 #468.3
        paddd     %xmm14, %xmm2                                 #468.3
        movdqa    448(%rdi), %xmm13                             #422.6
        paddd     %xmm15, %xmm5                                 #468.3
        pxor      %xmm4, %xmm0                                  #468.3
        paddd     %xmm13, %xmm5                                 #468.3
        movdqa    %xmm13, 672(%rsp)                             #422.6
        paddd     %xmm0, %xmm8                                  #468.3
        movdqa    704(%rdi), %xmm13                             #422.6
        movdqa    %xmm2, %xmm0                                  #468.3
        movdqa    %xmm13, 656(%rsp)                             #422.6
        paddd     %xmm13, %xmm8                                 #468.3
        pslld     $3, %xmm0                                     #468.3
        psrld     $29, %xmm2                                    #468.3
        movdqa    %xmm5, %xmm13                                 #468.3
        por       %xmm2, %xmm0                                  #468.3
        movdqa    %xmm14, 640(%rsp)                             #422.6
        pslld     $3, %xmm13                                    #468.3
        psrld     $29, %xmm5                                    #468.3
                                # LOE rbx rbp rsi rdi r12 r13 r14 r15 xmm0 xmm1 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm11 xmm12 xmm13
..B8.9:                         # Preds ..B8.4
        movdqa    %xmm8, %xmm2                                  #468.3
        movdqa    %xmm10, %xmm15                                #469.3
        pslld     $3, %xmm2                                     #468.3
        psrld     $29, %xmm8                                    #468.3
        por       %xmm5, %xmm13                                 #468.3
        pxor      %xmm7, %xmm15                                 #469.3
        por       %xmm8, %xmm2                                  #468.3
        pand      %xmm13, %xmm15                                #469.3
        pxor      %xmm8, %xmm8                                  #469.3
        movdqa    %xmm1, %xmm14                                 #469.3
        paddd     %xmm8, %xmm12                                 #469.3
        pxor      %xmm7, %xmm15                                 #469.3
        pxor      %xmm6, %xmm14                                 #469.3
        paddd     %xmm15, %xmm12                                #469.3
        movdqa    %xmm11, %xmm15                                #469.3
        pand      %xmm0, %xmm14                                 #469.3
        pxor      %xmm9, %xmm15                                 #469.3
        paddd     %xmm8, %xmm3                                  #469.3
        pxor      %xmm6, %xmm14                                 #469.3
        pand      %xmm2, %xmm15                                 #469.3
        paddd     %xmm14, %xmm3                                 #469.3
        paddd     %xmm8, %xmm4                                  #469.3
        movdqa    464(%rdi), %xmm14                             #422.6
        pxor      %xmm9, %xmm15                                 #469.3
        movdqa    %xmm14, 480(%rsp)                             #422.6
        paddd     %xmm14, %xmm12                                #469.3
        movdqa    720(%rdi), %xmm14                             #422.6
        paddd     %xmm15, %xmm4                                 #469.3
        movdqa    208(%rdi), %xmm5                              #422.6
        paddd     %xmm14, %xmm4                                 #469.3
        movdqa    %xmm14, 400(%rsp)                             #422.6
        paddd     %xmm5, %xmm3                                  #469.3
        movdqa    %xmm4, %xmm14                                 #469.3
        movdqa    %xmm3, %xmm15                                 #469.3
        pslld     $7, %xmm14                                    #469.3
        psrld     $25, %xmm4                                    #469.3
        pslld     $7, %xmm15                                    #469.3
        psrld     $25, %xmm3                                    #469.3
        por       %xmm4, %xmm14                                 #469.3
        movdqa    %xmm0, %xmm4                                  #470.3
        por       %xmm3, %xmm15                                 #469.3
        pxor      %xmm1, %xmm4                                  #470.3
        pand      %xmm15, %xmm4                                 #470.3
        movdqa    %xmm12, %xmm3                                 #469.3
        paddd     %xmm8, %xmm6                                  #470.3
        pxor      %xmm1, %xmm4                                  #470.3
        pslld     $7, %xmm3                                     #469.3
        psrld     $25, %xmm12                                   #469.3
        paddd     %xmm4, %xmm6                                  #470.3
        movdqa    %xmm10, %xmm4                                 #470.3
        por       %xmm12, %xmm3                                 #469.3
        pxor      %xmm13, %xmm4                                 #470.3
        pand      %xmm3, %xmm4                                  #470.3
        paddd     %xmm8, %xmm7                                  #470.3
        pxor      %xmm10, %xmm4                                 #470.3
        paddd     %xmm8, %xmm9                                  #470.3
        paddd     %xmm4, %xmm7                                  #470.3
        movdqa    %xmm11, %xmm4                                 #470.3
        pxor      %xmm2, %xmm4                                  #470.3
        paddd     %xmm8, %xmm1                                  #471.3
        movdqa    224(%rdi), %xmm12                             #422.6
        pand      %xmm14, %xmm4                                 #470.3
        paddd     %xmm12, %xmm6                                 #470.3
        pxor      %xmm11, %xmm4                                 #470.3
        movdqa    %xmm12, 608(%rsp)                             #422.6
        paddd     %xmm4, %xmm9                                  #470.3
        movdqa    480(%rdi), %xmm12                             #422.6
        movdqa    %xmm6, %xmm4                                  #470.3
        paddd     %xmm12, %xmm7                                 #470.3
        pslld     $11, %xmm4                                    #470.3
        psrld     $21, %xmm6                                    #470.3
        paddd     %xmm8, %xmm10                                 #471.3
        movdqa    %xmm12, 544(%rsp)                             #422.6
        por       %xmm6, %xmm4                                  #470.3
        movdqa    736(%rdi), %xmm12                             #422.6
        movdqa    %xmm7, %xmm6                                  #470.3
        paddd     %xmm12, %xmm9                                 #470.3
        pslld     $11, %xmm6                                    #470.3
        psrld     $21, %xmm7                                    #470.3
        paddd     %xmm8, %xmm11                                 #471.3
        por       %xmm7, %xmm6                                  #470.3
        movdqa    %xmm9, %xmm7                                  #470.3
        pslld     $11, %xmm7                                    #470.3
        psrld     $21, %xmm9                                    #470.3
        por       %xmm9, %xmm7                                  #470.3
        movdqa    %xmm0, %xmm9                                  #471.3
        pxor      %xmm15, %xmm9                                 #471.3
        movdqa    %xmm14, %xmm8                                 #471.3
        pand      %xmm4, %xmm9                                  #471.3
        pxor      %xmm2, %xmm8                                  #471.3
        pxor      %xmm0, %xmm9                                  #471.3
        pand      %xmm7, %xmm8                                  #471.3
        paddd     %xmm9, %xmm1                                  #471.3
        movdqa    %xmm3, %xmm9                                  #471.3
        pxor      %xmm13, %xmm9                                 #471.3
        pxor      %xmm2, %xmm8                                  #471.3
        movdqa    %xmm12, 560(%rsp)                             #422.6
        pand      %xmm6, %xmm9                                  #471.3
        movdqa    240(%rdi), %xmm12                             #422.6
        pxor      %xmm13, %xmm9                                 #471.3
        paddd     %xmm12, %xmm1                                 #471.3
        paddd     %xmm9, %xmm10                                 #471.3
        movdqa    752(%rdi), %xmm9                              #422.6
        paddd     %xmm8, %xmm11                                 #471.3
        movdqa    %xmm1, %xmm8                                  #471.3
        paddd     %xmm9, %xmm11                                 #471.3
        movdqa    %xmm12, 384(%rsp)                             #422.6
        pslld     $19, %xmm8                                    #471.3
        movdqa    496(%rdi), %xmm12                             #422.6
        psrld     $13, %xmm1                                    #471.3
        paddd     %xmm12, %xmm10                                #471.3
        por       %xmm1, %xmm8                                  #471.3
        movdqa    %xmm11, %xmm1                                 #471.3
        psrld     $13, %xmm11                                   #471.3
        movdqa    %xmm12, 688(%rsp)                             #422.6
        pslld     $19, %xmm1                                    #471.3
        movdqa    %xmm9, 704(%rsp)                              #422.6
        movdqa    %xmm10, %xmm9                                 #471.3
        movdqa    %xmm4, %xmm12                                 #475.3
        pslld     $19, %xmm9                                    #471.3
        psrld     $13, %xmm10                                   #471.3
        por       %xmm11, %xmm1                                 #471.3
        por       %xmm15, %xmm12                                #475.3
        movdqa    %xmm4, %xmm11                                 #475.3
        por       %xmm10, %xmm9                                 #471.3
        pand      %xmm8, %xmm12                                 #475.3
        movdqa    .L_2il0floatpacket.478(%rip), %xmm10          #474.9
        pand      %xmm15, %xmm11                                #475.3
        paddd     %xmm10, %xmm0                                 #475.3
        por       %xmm11, %xmm12                                #475.3
        paddd     %xmm12, %xmm0                                 #475.3
        movdqa    %xmm6, %xmm12                                 #475.3
        por       %xmm3, %xmm12                                 #475.3
        movdqa    %xmm6, %xmm11                                 #475.3
        pand      %xmm9, %xmm12                                 #475.3
        pand      %xmm3, %xmm11                                 #475.3
        paddd     %xmm10, %xmm13                                #475.3
        por       %xmm11, %xmm12                                #475.3
        paddd     %xmm12, %xmm13                                #475.3
        movdqa    %xmm7, %xmm12                                 #475.3
        por       %xmm14, %xmm12                                #475.3
        movdqa    %xmm7, %xmm11                                 #475.3
        pand      %xmm1, %xmm12                                 #475.3
        pand      %xmm14, %xmm11                                #475.3
        paddd     736(%rsp), %xmm13                             #475.3
        paddd     %xmm10, %xmm2                                 #475.3
        por       %xmm11, %xmm12                                #475.3
        paddd     %xmm10, %xmm15                                #476.3
        paddd     %xmm12, %xmm2                                 #475.3
        movdqa    %xmm13, %xmm12                                #475.3
        paddd     752(%rsp), %xmm2                              #475.3
        pslld     $3, %xmm12                                    #475.3
        psrld     $29, %xmm13                                   #475.3
        paddd     %xmm10, %xmm3                                 #476.3
        paddd     720(%rsp), %xmm0                              #475.3
        por       %xmm13, %xmm12                                #475.3
        movdqa    %xmm2, %xmm13                                 #475.3
        movdqa    %xmm0, %xmm11                                 #475.3
        pslld     $3, %xmm13                                    #475.3
        psrld     $29, %xmm2                                    #475.3
        pslld     $3, %xmm11                                    #475.3
        psrld     $29, %xmm0                                    #475.3
        por       %xmm2, %xmm13                                 #475.3
        movdqa    %xmm8, %xmm2                                  #476.3
        por       %xmm0, %xmm11                                 #475.3
        por       %xmm4, %xmm2                                  #476.3
        movdqa    %xmm8, %xmm0                                  #476.3
        pand      %xmm11, %xmm2                                 #476.3
        pand      %xmm4, %xmm0                                  #476.3
        paddd     %xmm10, %xmm14                                #476.3
        por       %xmm0, %xmm2                                  #476.3
        movdqa    %xmm9, %xmm0                                  #476.3
        paddd     %xmm2, %xmm15                                 #476.3
        movdqa    %xmm9, %xmm2                                  #476.3
        por       %xmm6, %xmm2                                  #476.3
        pand      %xmm6, %xmm0                                  #476.3
        pand      %xmm12, %xmm2                                 #476.3
        paddd     %xmm10, %xmm4                                 #477.3
        por       %xmm0, %xmm2                                  #476.3
        movdqa    %xmm1, %xmm0                                  #476.3
        paddd     %xmm2, %xmm3                                  #476.3
        movdqa    %xmm1, %xmm2                                  #476.3
        por       %xmm7, %xmm2                                  #476.3
        pand      %xmm7, %xmm0                                  #476.3
        pand      %xmm13, %xmm2                                 #476.3
        paddd     %xmm10, %xmm6                                 #477.3
        paddd     416(%rsp), %xmm15                             #476.3
        por       %xmm0, %xmm2                                  #476.3
        paddd     %xmm2, %xmm14                                 #476.3
        movdqa    %xmm15, %xmm0                                 #476.3
        paddd     448(%rsp), %xmm14                             #476.3
        pslld     $5, %xmm0                                     #476.3
        psrld     $27, %xmm15                                   #476.3
        paddd     %xmm10, %xmm7                                 #477.3
        paddd     432(%rsp), %xmm3                              #476.3
        por       %xmm15, %xmm0                                 #476.3
        movdqa    %xmm14, %xmm15                                #476.3
        movdqa    %xmm3, %xmm2                                  #476.3
        pslld     $5, %xmm15                                    #476.3
        psrld     $27, %xmm14                                   #476.3
        pslld     $5, %xmm2                                     #476.3
        psrld     $27, %xmm3                                    #476.3
        por       %xmm14, %xmm15                                #476.3
        movdqa    %xmm11, %xmm14                                #477.3
        por       %xmm3, %xmm2                                  #476.3
        por       %xmm8, %xmm14                                 #477.3
        movdqa    %xmm11, %xmm3                                 #477.3
        pand      %xmm0, %xmm14                                 #477.3
        pand      %xmm8, %xmm3                                  #477.3
        paddd     %xmm10, %xmm8                                 #478.3
        por       %xmm3, %xmm14                                 #477.3
        movdqa    %xmm12, %xmm3                                 #477.3
        paddd     %xmm14, %xmm4                                 #477.3
        movdqa    %xmm12, %xmm14                                #477.3
        por       %xmm9, %xmm14                                 #477.3
        pand      %xmm9, %xmm3                                  #477.3
        pand      %xmm2, %xmm14                                 #477.3
        paddd     %xmm10, %xmm9                                 #478.3
        por       %xmm3, %xmm14                                 #477.3
        movdqa    %xmm13, %xmm3                                 #477.3
        paddd     %xmm14, %xmm6                                 #477.3
        movdqa    %xmm13, %xmm14                                #477.3
        por       %xmm1, %xmm14                                 #477.3
        pand      %xmm1, %xmm3                                  #477.3
        paddd     624(%rsp), %xmm4                              #477.3
        pand      %xmm15, %xmm14                                #477.3
        por       %xmm3, %xmm14                                 #477.3
        movdqa    %xmm4, %xmm3                                  #477.3
        paddd     576(%rsp), %xmm6                              #477.3
        pslld     $9, %xmm3                                     #477.3
        psrld     $23, %xmm4                                    #477.3
        paddd     %xmm14, %xmm7                                 #477.3
        por       %xmm4, %xmm3                                  #477.3
        movdqa    %xmm6, %xmm4                                  #477.3
        paddd     592(%rsp), %xmm7                              #477.3
        pslld     $9, %xmm4                                     #477.3
        psrld     $23, %xmm6                                    #477.3
        movdqa    %xmm0, %xmm14                                 #478.3
        por       %xmm6, %xmm4                                  #477.3
        movdqa    %xmm7, %xmm6                                  #477.3
        pslld     $9, %xmm6                                     #477.3
        psrld     $23, %xmm7                                    #477.3
        por       %xmm7, %xmm6                                  #477.3
        por       %xmm11, %xmm14                                #478.3
        movdqa    %xmm0, %xmm7                                  #478.3
        pand      %xmm3, %xmm14                                 #478.3
        pand      %xmm11, %xmm7                                 #478.3
        paddd     %xmm10, %xmm1                                 #478.3
        por       %xmm7, %xmm14                                 #478.3
        movdqa    %xmm2, %xmm7                                  #478.3
        paddd     %xmm14, %xmm8                                 #478.3
        movdqa    %xmm2, %xmm14                                 #478.3
        por       %xmm12, %xmm14                                #478.3
        pand      %xmm12, %xmm7                                 #478.3
        pand      %xmm4, %xmm14                                 #478.3
        paddd     %xmm10, %xmm11                                #479.3
        por       %xmm7, %xmm14                                 #478.3
        movdqa    %xmm15, %xmm7                                 #478.3
        paddd     %xmm14, %xmm9                                 #478.3
        movdqa    %xmm15, %xmm14                                #478.3
        por       %xmm13, %xmm14                                #478.3
        pand      %xmm13, %xmm7                                 #478.3
        pand      %xmm6, %xmm14                                 #478.3
        paddd     %xmm10, %xmm12                                #479.3
        paddd     640(%rsp), %xmm8                              #478.3
        por       %xmm7, %xmm14                                 #478.3
        paddd     672(%rsp), %xmm9                              #478.3
        paddd     %xmm14, %xmm1                                 #478.3
        movdqa    %xmm8, %xmm14                                 #478.3
        psrld     $19, %xmm8                                    #478.3
        paddd     656(%rsp), %xmm1                              #478.3
        pslld     $13, %xmm14                                   #478.3
        movdqa    %xmm9, %xmm7                                  #478.3
        por       %xmm8, %xmm14                                 #478.3
        pslld     $13, %xmm7                                    #478.3
        psrld     $19, %xmm9                                    #478.3
        movdqa    %xmm1, %xmm8                                  #478.3
        por       %xmm9, %xmm7                                  #478.3
        pslld     $13, %xmm8                                    #478.3
        psrld     $19, %xmm1                                    #478.3
        movdqa    %xmm3, %xmm9                                  #479.3
        por       %xmm1, %xmm8                                  #478.3
        por       %xmm0, %xmm9                                  #479.3
        movdqa    %xmm3, %xmm1                                  #479.3
        pand      %xmm14, %xmm9                                 #479.3
        pand      %xmm0, %xmm1                                  #479.3
        por       %xmm1, %xmm9                                  #479.3
        movdqa    %xmm4, %xmm1                                  #479.3
        paddd     %xmm9, %xmm11                                 #479.3
        movdqa    %xmm4, %xmm9                                  #479.3
        por       %xmm2, %xmm9                                  #479.3
        pand      %xmm2, %xmm1                                  #479.3
        pand      %xmm7, %xmm9                                  #479.3
        paddd     %xmm10, %xmm13                                #479.3
        por       %xmm1, %xmm9                                  #479.3
        movdqa    %xmm6, %xmm1                                  #479.3
        paddd     %xmm9, %xmm12                                 #479.3
        movdqa    %xmm6, %xmm9                                  #479.3
        por       %xmm15, %xmm9                                 #479.3
        pand      %xmm15, %xmm1                                 #479.3
        pand      %xmm8, %xmm9                                  #479.3
        paddd     %xmm10, %xmm0                                 #480.3
        paddd     48(%rsp), %xmm11                              #479.3
        por       %xmm1, %xmm9                                  #479.3
        paddd     %xmm9, %xmm13                                 #479.3
        movdqa    %xmm11, %xmm9                                 #479.3
        paddd     112(%rsp), %xmm12                             #479.3
        pslld     $3, %xmm9                                     #479.3
        psrld     $29, %xmm11                                   #479.3
        movdqa    %xmm14, %xmm1                                 #480.3
        por       %xmm11, %xmm9                                 #479.3
        movdqa    %xmm12, %xmm11                                #479.3
        paddd     128(%rsp), %xmm13                             #479.3
        pslld     $3, %xmm11                                    #479.3
        psrld     $29, %xmm12                                   #479.3
        por       %xmm3, %xmm1                                  #480.3
        por       %xmm12, %xmm11                                #479.3
        movdqa    %xmm13, %xmm12                                #479.3
        pslld     $3, %xmm12                                    #479.3
        psrld     $29, %xmm13                                   #479.3
        por       %xmm13, %xmm12                                #479.3
        movdqa    %xmm14, %xmm13                                #480.3
        pand      %xmm9, %xmm1                                  #480.3
        pand      %xmm3, %xmm13                                 #480.3
        por       %xmm13, %xmm1                                 #480.3
        movdqa    %xmm7, %xmm13                                 #480.3
        paddd     %xmm1, %xmm0                                  #480.3
        movdqa    %xmm7, %xmm1                                  #480.3
        por       %xmm4, %xmm1                                  #480.3
        pand      %xmm4, %xmm13                                 #480.3
        pand      %xmm11, %xmm1                                 #480.3
        paddd     %xmm10, %xmm2                                 #480.3
        por       %xmm13, %xmm1                                 #480.3
        movdqa    %xmm8, %xmm13                                 #480.3
        paddd     %xmm1, %xmm2                                  #480.3
        movdqa    %xmm8, %xmm1                                  #480.3
        por       %xmm6, %xmm1                                  #480.3
        pand      %xmm6, %xmm13                                 #480.3
        paddd     144(%rsp), %xmm0                              #480.3
        pand      %xmm12, %xmm1                                 #480.3
        paddd     %xmm10, %xmm15                                #480.3
        por       %xmm13, %xmm1                                 #480.3
        movdqa    %xmm0, %xmm13                                 #480.3
        paddd     %xmm1, %xmm15                                 #480.3
        paddd     160(%rsp), %xmm2                              #480.3
        pslld     $5, %xmm13                                    #480.3
        psrld     $27, %xmm0                                    #480.3
        paddd     %xmm10, %xmm3                                 #481.3
        paddd     176(%rsp), %xmm15                             #480.3
        por       %xmm0, %xmm13                                 #480.3
        movdqa    %xmm2, %xmm0                                  #480.3
        psrld     $27, %xmm2                                    #480.3
        pslld     $5, %xmm0                                     #480.3
        movdqa    %xmm15, %xmm1                                 #480.3
        por       %xmm2, %xmm0                                  #480.3
        pslld     $5, %xmm1                                     #480.3
        psrld     $27, %xmm15                                   #480.3
        movdqa    %xmm9, %xmm2                                  #481.3
        por       %xmm15, %xmm1                                 #480.3
        por       %xmm14, %xmm2                                 #481.3
        movdqa    %xmm9, %xmm15                                 #481.3
        pand      %xmm13, %xmm2                                 #481.3
        pand      %xmm14, %xmm15                                #481.3
        paddd     %xmm10, %xmm4                                 #481.3
        por       %xmm15, %xmm2                                 #481.3
        movdqa    %xmm11, %xmm15                                #481.3
        paddd     %xmm2, %xmm3                                  #481.3
        movdqa    %xmm11, %xmm2                                 #481.3
        por       %xmm7, %xmm2                                  #481.3
        pand      %xmm7, %xmm15                                 #481.3
        pand      %xmm0, %xmm2                                  #481.3
        paddd     %xmm10, %xmm6                                 #481.3
        por       %xmm15, %xmm2                                 #481.3
        movdqa    %xmm12, %xmm15                                #481.3
        paddd     %xmm2, %xmm4                                  #481.3
        movdqa    %xmm12, %xmm2                                 #481.3
        por       %xmm8, %xmm2                                  #481.3
        pand      %xmm8, %xmm15                                 #481.3
        pand      %xmm1, %xmm2                                  #481.3
        paddd     %xmm10, %xmm14                                #482.3
        paddd     320(%rsp), %xmm3                              #481.3
        por       %xmm15, %xmm2                                 #481.3
        paddd     %xmm2, %xmm6                                  #481.3
        movdqa    %xmm3, %xmm2                                  #481.3
        paddd     304(%rsp), %xmm4                              #481.3
        pslld     $9, %xmm2                                     #481.3
        psrld     $23, %xmm3                                    #481.3
        movdqa    %xmm13, %xmm15                                #482.3
        por       %xmm3, %xmm2                                  #481.3
        movdqa    %xmm4, %xmm3                                  #481.3
        paddd     288(%rsp), %xmm6                              #481.3
        pslld     $9, %xmm3                                     #481.3
        psrld     $23, %xmm4                                    #481.3
        por       %xmm9, %xmm15                                 #482.3
        por       %xmm4, %xmm3                                  #481.3
        movdqa    %xmm6, %xmm4                                  #481.3
        pslld     $9, %xmm4                                     #481.3
        psrld     $23, %xmm6                                    #481.3
        por       %xmm6, %xmm4                                  #481.3
        movdqa    %xmm13, %xmm6                                 #482.3
        pand      %xmm2, %xmm15                                 #482.3
        pand      %xmm9, %xmm6                                  #482.3
        por       %xmm6, %xmm15                                 #482.3
        movdqa    %xmm0, %xmm6                                  #482.3
        paddd     %xmm15, %xmm14                                #482.3
        por       %xmm11, %xmm6                                 #482.3
        movdqa    %xmm5, 464(%rsp)                              #422.6
        paddd     %xmm5, %xmm14                                 #482.3
        movdqa    %xmm0, %xmm5                                  #482.3
        pand      %xmm3, %xmm6                                  #482.3
        pand      %xmm11, %xmm5                                 #482.3
        paddd     %xmm10, %xmm7                                 #482.3
        por       %xmm5, %xmm6                                  #482.3
        movdqa    %xmm1, %xmm5                                  #482.3
        por       %xmm12, %xmm5                                 #482.3
        movdqa    %xmm1, %xmm15                                 #482.3
        paddd     %xmm6, %xmm7                                  #482.3
        pand      %xmm4, %xmm5                                  #482.3
        pand      %xmm12, %xmm15                                #482.3
        paddd     %xmm10, %xmm8                                 #482.3
        paddd     464(%rdi), %xmm7                              #482.3
        por       %xmm15, %xmm5                                 #482.3
        paddd     %xmm5, %xmm8                                  #482.3
        movdqa    %xmm7, %xmm6                                  #482.3
        paddd     720(%rdi), %xmm8                              #482.3
        movdqa    %xmm14, %xmm5                                 #482.3
        pslld     $13, %xmm6                                    #482.3
        psrld     $19, %xmm7                                    #482.3
        pslld     $13, %xmm5                                    #482.3
        psrld     $19, %xmm14                                   #482.3
        por       %xmm7, %xmm6                                  #482.3
        movdqa    %xmm8, %xmm7                                  #482.3
        por       %xmm14, %xmm5                                 #482.3
        pslld     $13, %xmm7                                    #482.3
        psrld     $19, %xmm8                                    #482.3
        movdqa    %xmm2, %xmm14                                 #483.3
        por       %xmm8, %xmm7                                  #482.3
        por       %xmm13, %xmm14                                #483.3
        movdqa    %xmm2, %xmm8                                  #483.3
        pand      %xmm5, %xmm14                                 #483.3
        pand      %xmm13, %xmm8                                 #483.3
        movdqa    %xmm3, %xmm15                                 #483.3
        paddd     %xmm10, %xmm9                                 #483.3
        por       %xmm8, %xmm14                                 #483.3
        por       %xmm0, %xmm15                                 #483.3
        movdqa    %xmm3, %xmm8                                  #483.3
        paddd     %xmm14, %xmm9                                 #483.3
        pand      %xmm6, %xmm15                                 #483.3
        pand      %xmm0, %xmm8                                  #483.3
        movdqa    %xmm4, %xmm14                                 #483.3
        por       %xmm8, %xmm15                                 #483.3
        por       %xmm1, %xmm14                                 #483.3
        movdqa    %xmm4, %xmm8                                  #483.3
        pand      %xmm7, %xmm14                                 #483.3
        pand      %xmm1, %xmm8                                  #483.3
        paddd     %xmm10, %xmm12                                #483.3
        por       %xmm8, %xmm14                                 #483.3
        paddd     %xmm10, %xmm11                                #483.3
        paddd     208(%rsp), %xmm9                              #483.3
        paddd     %xmm14, %xmm12                                #483.3
        paddd     240(%rsp), %xmm12                             #483.3
        paddd     %xmm15, %xmm11                                #483.3
        movdqa    %xmm9, %xmm8                                  #483.3
        psrld     $29, %xmm9                                    #483.3
        paddd     224(%rsp), %xmm11                             #483.3
        pslld     $3, %xmm8                                     #483.3
        movdqa    %xmm12, %xmm14                                #483.3
        por       %xmm9, %xmm8                                  #483.3
        movdqa    %xmm11, %xmm9                                 #483.3
        pslld     $3, %xmm14                                    #483.3
        psrld     $29, %xmm12                                   #483.3
        pslld     $3, %xmm9                                     #483.3
        psrld     $29, %xmm11                                   #483.3
        por       %xmm12, %xmm14                                #483.3
        movdqa    %xmm5, %xmm12                                 #484.3
        por       %xmm11, %xmm9                                 #483.3
        por       %xmm2, %xmm12                                 #484.3
        movdqa    %xmm5, %xmm11                                 #484.3
        pand      %xmm8, %xmm12                                 #484.3
        pand      %xmm2, %xmm11                                 #484.3
        movdqa    %xmm6, %xmm15                                 #484.3
        paddd     %xmm10, %xmm13                                #484.3
        por       %xmm11, %xmm12                                #484.3
        por       %xmm3, %xmm15                                 #484.3
        movdqa    %xmm6, %xmm11                                 #484.3
        paddd     %xmm12, %xmm13                                #484.3
        pand      %xmm9, %xmm15                                 #484.3
        pand      %xmm3, %xmm11                                 #484.3
        movdqa    %xmm7, %xmm12                                 #484.3
        por       %xmm11, %xmm15                                #484.3
        por       %xmm4, %xmm12                                 #484.3
        movdqa    %xmm7, %xmm11                                 #484.3
        pand      %xmm14, %xmm12                                #484.3
        pand      %xmm4, %xmm11                                 #484.3
        paddd     336(%rsp), %xmm13                             #484.3
        paddd     %xmm10, %xmm1                                 #484.3
        por       %xmm11, %xmm12                                #484.3
        paddd     %xmm10, %xmm0                                 #484.3
        paddd     %xmm12, %xmm1                                 #484.3
        movdqa    %xmm13, %xmm12                                #484.3
        paddd     368(%rsp), %xmm1                              #484.3
        paddd     %xmm15, %xmm0                                 #484.3
        pslld     $5, %xmm12                                    #484.3
        psrld     $27, %xmm13                                   #484.3
        paddd     352(%rsp), %xmm0                              #484.3
        por       %xmm13, %xmm12                                #484.3
        movdqa    %xmm1, %xmm13                                 #484.3
        movdqa    %xmm0, %xmm11                                 #484.3
        pslld     $5, %xmm13                                    #484.3
        psrld     $27, %xmm1                                    #484.3
        pslld     $5, %xmm11                                    #484.3
        psrld     $27, %xmm0                                    #484.3
        por       %xmm1, %xmm13                                 #484.3
        movdqa    %xmm8, %xmm1                                  #485.3
        por       %xmm0, %xmm11                                 #484.3
        por       %xmm5, %xmm1                                  #485.3
        movdqa    %xmm8, %xmm0                                  #485.3
        pand      %xmm12, %xmm1                                 #485.3
        pand      %xmm5, %xmm0                                  #485.3
        paddd     %xmm10, %xmm2                                 #485.3
        por       %xmm0, %xmm1                                  #485.3
                                # LOE rbx rbp rsi r12 r13 r14 r15 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm11 xmm12 xmm13 xmm14
..B8.8:                         # Preds ..B8.9
        movdqa    %xmm9, %xmm15                                 #485.3
        movdqa    %xmm9, %xmm0                                  #485.3
        por       %xmm6, %xmm15                                 #485.3
        pand      %xmm6, %xmm0                                  #485.3
        pand      %xmm11, %xmm15                                #485.3
        paddd     %xmm10, %xmm3                                 #485.3
        por       %xmm0, %xmm15                                 #485.3
        paddd     %xmm1, %xmm2                                  #485.3
        paddd     %xmm15, %xmm3                                 #485.3
        movdqa    %xmm14, %xmm15                                #485.3
        movdqa    496(%rsp), %xmm1                              #485.3
        por       %xmm7, %xmm15                                 #485.3
        movdqa    %xmm14, %xmm0                                 #485.3
        paddd     %xmm1, %xmm2                                  #485.3
        pand      %xmm13, %xmm15                                #485.3
        pand      %xmm7, %xmm0                                  #485.3
        por       %xmm0, %xmm15                                 #485.3
        movdqa    %xmm2, %xmm0                                  #485.3
        paddd     528(%rsp), %xmm3                              #485.3
        paddd     %xmm10, %xmm4                                 #485.3
        pslld     $9, %xmm0                                     #485.3
        psrld     $23, %xmm2                                    #485.3
        paddd     %xmm15, %xmm4                                 #485.3
        por       %xmm2, %xmm0                                  #485.3
        movdqa    %xmm3, %xmm2                                  #485.3
        psrld     $23, %xmm3                                    #485.3
        paddd     512(%rsp), %xmm4                              #485.3
        pslld     $9, %xmm2                                     #485.3
        por       %xmm3, %xmm2                                  #485.3
        movdqa    %xmm4, %xmm3                                  #485.3
        pslld     $9, %xmm3                                     #485.3
        psrld     $23, %xmm4                                    #485.3
        movdqa    %xmm12, %xmm15                                #486.3
        por       %xmm4, %xmm3                                  #485.3
        por       %xmm8, %xmm15                                 #486.3
        movdqa    %xmm12, %xmm4                                 #486.3
        pand      %xmm0, %xmm15                                 #486.3
        pand      %xmm8, %xmm4                                  #486.3
        paddd     %xmm10, %xmm5                                 #486.3
        por       %xmm4, %xmm15                                 #486.3
        paddd     %xmm15, %xmm5                                 #486.3
        movdqa    %xmm11, %xmm15                                #486.3
        por       %xmm9, %xmm15                                 #486.3
        movdqa    %xmm11, %xmm4                                 #486.3
        pand      %xmm2, %xmm15                                 #486.3
        pand      %xmm9, %xmm4                                  #486.3
        paddd     %xmm10, %xmm6                                 #486.3
        por       %xmm4, %xmm15                                 #486.3
        paddd     %xmm15, %xmm6                                 #486.3
        movdqa    %xmm13, %xmm15                                #486.3
        por       %xmm14, %xmm15                                #486.3
        movdqa    %xmm13, %xmm4                                 #486.3
        paddd     608(%rsp), %xmm5                              #486.3
        pand      %xmm3, %xmm15                                 #486.3
        pand      %xmm14, %xmm4                                 #486.3
        paddd     %xmm10, %xmm7                                 #486.3
        por       %xmm4, %xmm15                                 #486.3
        movdqa    %xmm5, %xmm4                                  #486.3
        paddd     544(%rsp), %xmm6                              #486.3
        pslld     $13, %xmm4                                    #486.3
        psrld     $19, %xmm5                                    #486.3
        paddd     %xmm15, %xmm7                                 #486.3
        por       %xmm5, %xmm4                                  #486.3
        movdqa    %xmm6, %xmm5                                  #486.3
        paddd     560(%rsp), %xmm7                              #486.3
        pslld     $13, %xmm5                                    #486.3
        psrld     $19, %xmm6                                    #486.3
        movdqa    %xmm12, %xmm15                                #487.3
        por       %xmm6, %xmm5                                  #486.3
        movdqa    %xmm7, %xmm6                                  #486.3
        pslld     $13, %xmm6                                    #486.3
        psrld     $19, %xmm7                                    #486.3
        por       %xmm7, %xmm6                                  #486.3
        por       %xmm0, %xmm15                                 #487.3
        movdqa    %xmm12, %xmm7                                 #487.3
        pand      %xmm4, %xmm15                                 #487.3
        pand      %xmm0, %xmm7                                  #487.3
        paddd     %xmm10, %xmm8                                 #487.3
        por       %xmm7, %xmm15                                 #487.3
        movdqa    %xmm11, %xmm7                                 #487.3
        paddd     %xmm15, %xmm8                                 #487.3
        movdqa    %xmm11, %xmm15                                #487.3
        por       %xmm2, %xmm15                                 #487.3
        pand      %xmm2, %xmm7                                  #487.3
        pand      %xmm5, %xmm15                                 #487.3
        paddd     %xmm10, %xmm9                                 #487.3
        por       %xmm7, %xmm15                                 #487.3
        movdqa    %xmm13, %xmm7                                 #487.3
        paddd     %xmm15, %xmm9                                 #487.3
        movdqa    %xmm13, %xmm15                                #487.3
        por       %xmm3, %xmm15                                 #487.3
        pand      %xmm3, %xmm7                                  #487.3
        paddd     (%rsp), %xmm8                                 #487.3
        pand      %xmm6, %xmm15                                 #487.3
        por       %xmm7, %xmm15                                 #487.3
        movdqa    %xmm8, %xmm7                                  #487.3
        paddd     16(%rsp), %xmm9                               #487.3
        paddd     %xmm10, %xmm14                                #487.3
        pslld     $3, %xmm7                                     #487.3
        psrld     $29, %xmm8                                    #487.3
        paddd     %xmm15, %xmm14                                #487.3
        por       %xmm8, %xmm7                                  #487.3
        movdqa    %xmm9, %xmm8                                  #487.3
        psrld     $29, %xmm9                                    #487.3
        paddd     32(%rsp), %xmm14                              #487.3
        pslld     $3, %xmm8                                     #487.3
        por       %xmm9, %xmm8                                  #487.3
        movdqa    %xmm14, %xmm9                                 #487.3
        pslld     $3, %xmm9                                     #487.3
        psrld     $29, %xmm14                                   #487.3
        movdqa    %xmm4, %xmm15                                 #488.3
        por       %xmm14, %xmm9                                 #487.3
        por       %xmm0, %xmm15                                 #488.3
        movdqa    %xmm4, %xmm14                                 #488.3
        pand      %xmm7, %xmm15                                 #488.3
        pand      %xmm0, %xmm14                                 #488.3
        paddd     %xmm10, %xmm12                                #488.3
        por       %xmm14, %xmm15                                #488.3
        paddd     %xmm15, %xmm12                                #488.3
        movdqa    %xmm5, %xmm15                                 #488.3
        por       %xmm2, %xmm15                                 #488.3
        movdqa    %xmm5, %xmm14                                 #488.3
        pand      %xmm8, %xmm15                                 #488.3
        pand      %xmm2, %xmm14                                 #488.3
        paddd     %xmm10, %xmm11                                #488.3
        por       %xmm14, %xmm15                                #488.3
        paddd     %xmm15, %xmm11                                #488.3
        movdqa    %xmm6, %xmm15                                 #488.3
        por       %xmm3, %xmm15                                 #488.3
        movdqa    %xmm6, %xmm14                                 #488.3
        paddd     96(%rsp), %xmm12                              #488.3
        pand      %xmm9, %xmm15                                 #488.3
        pand      %xmm3, %xmm14                                 #488.3
        paddd     %xmm10, %xmm13                                #488.3
        por       %xmm14, %xmm15                                #488.3
        movdqa    %xmm12, %xmm14                                #488.3
        paddd     80(%rsp), %xmm11                              #488.3
        pslld     $5, %xmm14                                    #488.3
        psrld     $27, %xmm12                                   #488.3
        paddd     %xmm15, %xmm13                                #488.3
        por       %xmm12, %xmm14                                #488.3
        movdqa    %xmm11, %xmm12                                #488.3
        paddd     64(%rsp), %xmm13                              #488.3
        pslld     $5, %xmm12                                    #488.3
        psrld     $27, %xmm11                                   #488.3
        movdqa    %xmm7, %xmm15                                 #489.3
        por       %xmm11, %xmm12                                #488.3
        movdqa    %xmm13, %xmm11                                #488.3
        pslld     $5, %xmm11                                    #488.3
        psrld     $27, %xmm13                                   #488.3
        por       %xmm13, %xmm11                                #488.3
        por       %xmm4, %xmm15                                 #489.3
        movdqa    %xmm7, %xmm13                                 #489.3
        pand      %xmm14, %xmm15                                #489.3
        pand      %xmm4, %xmm13                                 #489.3
        paddd     %xmm10, %xmm0                                 #489.3
        por       %xmm13, %xmm15                                #489.3
        movdqa    %xmm8, %xmm13                                 #489.3
        paddd     %xmm15, %xmm0                                 #489.3
        movdqa    %xmm8, %xmm15                                 #489.3
        por       %xmm5, %xmm15                                 #489.3
        pand      %xmm5, %xmm13                                 #489.3
        pand      %xmm12, %xmm15                                #489.3
        paddd     %xmm10, %xmm2                                 #489.3
        por       %xmm13, %xmm15                                #489.3
        movdqa    %xmm9, %xmm13                                 #489.3
        paddd     %xmm15, %xmm2                                 #489.3
        movdqa    %xmm9, %xmm15                                 #489.3
        por       %xmm6, %xmm15                                 #489.3
        pand      %xmm6, %xmm13                                 #489.3
        paddd     192(%rsp), %xmm0                              #489.3
        pand      %xmm11, %xmm15                                #489.3
        paddd     %xmm10, %xmm3                                 #489.3
        por       %xmm13, %xmm15                                #489.3
        movdqa    %xmm0, %xmm13                                 #489.3
        paddd     %xmm15, %xmm3                                 #489.3
        paddd     256(%rsp), %xmm2                              #489.3
        pslld     $9, %xmm13                                    #489.3
        psrld     $23, %xmm0                                    #489.3
        paddd     %xmm10, %xmm4                                 #490.3
        paddd     272(%rsp), %xmm3                              #489.3
        por       %xmm0, %xmm13                                 #489.3
        movdqa    %xmm2, %xmm0                                  #489.3
        psrld     $23, %xmm2                                    #489.3
        pslld     $9, %xmm0                                     #489.3
        movdqa    %xmm3, %xmm15                                 #489.3
        por       %xmm2, %xmm0                                  #489.3
        pslld     $9, %xmm15                                    #489.3
        psrld     $23, %xmm3                                    #489.3
        movdqa    %xmm14, %xmm2                                 #490.3
        por       %xmm3, %xmm15                                 #489.3
        por       %xmm7, %xmm2                                  #490.3
        movdqa    %xmm14, %xmm3                                 #490.3
        pand      %xmm13, %xmm2                                 #490.3
        pand      %xmm7, %xmm3                                  #490.3
        paddd     %xmm10, %xmm5                                 #490.3
        por       %xmm3, %xmm2                                  #490.3
        movdqa    %xmm12, %xmm3                                 #490.3
        paddd     %xmm2, %xmm4                                  #490.3
        movdqa    %xmm12, %xmm2                                 #490.3
        por       %xmm8, %xmm2                                  #490.3
        pand      %xmm8, %xmm3                                  #490.3
        pand      %xmm0, %xmm2                                  #490.3
        paddd     %xmm10, %xmm6                                 #490.3
        por       %xmm3, %xmm2                                  #490.3
        movdqa    %xmm11, %xmm3                                 #490.3
        por       %xmm9, %xmm3                                  #490.3
        movdqa    %xmm11, %xmm10                                #490.3
        paddd     %xmm2, %xmm5                                  #490.3
        pand      %xmm15, %xmm3                                 #490.3
        pand      %xmm9, %xmm10                                 #490.3
        paddd     688(%rsp), %xmm5                              #490.3
        por       %xmm10, %xmm3                                 #490.3
        paddd     %xmm3, %xmm6                                  #490.3
        movdqa    %xmm5, %xmm10                                 #490.3
        paddd     704(%rsp), %xmm6                              #490.3
        pslld     $13, %xmm10                                   #490.3
        psrld     $19, %xmm5                                    #490.3
        paddd     384(%rsp), %xmm4                              #490.3
        por       %xmm5, %xmm10                                 #490.3
        movdqa    %xmm6, %xmm5                                  #490.3
        movdqa    %xmm4, %xmm2                                  #490.3
        pslld     $13, %xmm5                                    #490.3
        psrld     $19, %xmm6                                    #490.3
        pslld     $13, %xmm2                                    #490.3
        psrld     $19, %xmm4                                    #490.3
        por       %xmm6, %xmm5                                  #490.3
        movdqa    %xmm13, %xmm6                                 #494.3
        movdqa    .L_2il0floatpacket.479(%rip), %xmm3           #493.9
        por       %xmm4, %xmm2                                  #490.3
        pxor      %xmm14, %xmm6                                 #494.3
        paddd     %xmm3, %xmm7                                  #494.3
        pxor      %xmm2, %xmm6                                  #494.3
        movdqa    %xmm0, %xmm4                                  #494.3
        paddd     %xmm6, %xmm7                                  #494.3
        movdqa    %xmm15, %xmm6                                 #494.3
        pxor      %xmm12, %xmm4                                 #494.3
        pxor      %xmm11, %xmm6                                 #494.3
        paddd     720(%rsp), %xmm7                              #494.3
        paddd     %xmm3, %xmm8                                  #494.3
        pxor      %xmm10, %xmm4                                 #494.3
        paddd     %xmm3, %xmm9                                  #494.3
        pxor      %xmm5, %xmm6                                  #494.3
        paddd     %xmm4, %xmm8                                  #494.3
        paddd     %xmm6, %xmm9                                  #494.3
        movdqa    %xmm7, %xmm6                                  #494.3
        paddd     736(%rsp), %xmm8                              #494.3
        pslld     $3, %xmm6                                     #494.3
        psrld     $29, %xmm7                                    #494.3
        paddd     %xmm3, %xmm14                                 #495.3
        por       %xmm7, %xmm6                                  #494.3
        movdqa    %xmm8, %xmm7                                  #494.3
        paddd     752(%rsp), %xmm9                              #494.3
        pslld     $3, %xmm7                                     #494.3
        psrld     $29, %xmm8                                    #494.3
        movdqa    %xmm10, %xmm4                                 #495.3
        por       %xmm8, %xmm7                                  #494.3
        movdqa    %xmm9, %xmm8                                  #494.3
        pslld     $3, %xmm8                                     #494.3
        psrld     $29, %xmm9                                    #494.3
        por       %xmm9, %xmm8                                  #494.3
        movdqa    %xmm2, %xmm9                                  #495.3
        pxor      %xmm13, %xmm9                                 #495.3
        pxor      %xmm0, %xmm4                                  #495.3
        pxor      %xmm6, %xmm9                                  #495.3
        paddd     %xmm3, %xmm12                                 #495.3
        paddd     %xmm9, %xmm14                                 #495.3
        movdqa    %xmm5, %xmm9                                  #495.3
        pxor      %xmm15, %xmm9                                 #495.3
        pxor      %xmm7, %xmm4                                  #495.3
        paddd     624(%rsp), %xmm14                             #495.3
        paddd     %xmm3, %xmm11                                 #495.3
        pxor      %xmm8, %xmm9                                  #495.3
        paddd     %xmm4, %xmm12                                 #495.3
        paddd     %xmm9, %xmm11                                 #495.3
        movdqa    %xmm14, %xmm9                                 #495.3
        paddd     576(%rsp), %xmm12                             #495.3
        pslld     $9, %xmm9                                     #495.3
        psrld     $23, %xmm14                                   #495.3
        paddd     %xmm3, %xmm13                                 #496.3
        por       %xmm14, %xmm9                                 #495.3
        movdqa    %xmm12, %xmm14                                #495.3
        paddd     592(%rsp), %xmm11                             #495.3
        pslld     $9, %xmm14                                    #495.3
        psrld     $23, %xmm12                                   #495.3
        movdqa    %xmm7, %xmm4                                  #496.3
        por       %xmm12, %xmm14                                #495.3
        movdqa    %xmm11, %xmm12                                #495.3
        pslld     $9, %xmm12                                    #495.3
        psrld     $23, %xmm11                                   #495.3
        por       %xmm11, %xmm12                                #495.3
        movdqa    %xmm6, %xmm11                                 #496.3
        pxor      %xmm2, %xmm11                                 #496.3
        pxor      %xmm10, %xmm4                                 #496.3
        pxor      %xmm9, %xmm11                                 #496.3
        paddd     %xmm3, %xmm0                                  #496.3
        paddd     %xmm11, %xmm13                                #496.3
        movdqa    %xmm8, %xmm11                                 #496.3
        pxor      %xmm5, %xmm11                                 #496.3
        pxor      %xmm14, %xmm4                                 #496.3
        paddd     416(%rsp), %xmm13                             #496.3
        paddd     %xmm3, %xmm15                                 #496.3
        pxor      %xmm12, %xmm11                                #496.3
        paddd     %xmm4, %xmm0                                  #496.3
        paddd     %xmm11, %xmm15                                #496.3
        movdqa    %xmm13, %xmm11                                #496.3
        paddd     432(%rsp), %xmm0                              #496.3
        pslld     $11, %xmm11                                   #496.3
        psrld     $21, %xmm13                                   #496.3
        movdqa    %xmm14, %xmm4                                 #497.3
        por       %xmm13, %xmm11                                #496.3
        movdqa    %xmm0, %xmm13                                 #496.3
        paddd     448(%rsp), %xmm15                             #496.3
        pslld     $11, %xmm13                                   #496.3
        psrld     $21, %xmm0                                    #496.3
        paddd     %xmm3, %xmm2                                  #497.3
        por       %xmm0, %xmm13                                 #496.3
        movdqa    %xmm15, %xmm0                                 #496.3
        pslld     $11, %xmm0                                    #496.3
        psrld     $21, %xmm15                                   #496.3
        por       %xmm15, %xmm0                                 #496.3
        movdqa    %xmm9, %xmm15                                 #497.3
        pxor      %xmm6, %xmm15                                 #497.3
        pxor      %xmm7, %xmm4                                  #497.3
        pxor      %xmm11, %xmm15                                #497.3
        paddd     %xmm3, %xmm10                                 #497.3
        paddd     %xmm15, %xmm2                                 #497.3
        pxor      %xmm13, %xmm4                                 #497.3
        movdqa    %xmm12, %xmm15                                #497.3
        paddd     %xmm4, %xmm10                                 #497.3
        pxor      %xmm8, %xmm15                                 #497.3
        paddd     %xmm3, %xmm5                                  #497.3
        paddd     672(%rsp), %xmm10                             #497.3
        pxor      %xmm0, %xmm15                                 #497.3
        paddd     %xmm15, %xmm5                                 #497.3
        movdqa    %xmm10, %xmm15                                #497.3
        paddd     656(%rsp), %xmm5                              #497.3
        pslld     $15, %xmm15                                   #497.3
        psrld     $17, %xmm10                                   #497.3
        paddd     %xmm3, %xmm6                                  #498.3
        paddd     640(%rsp), %xmm2                              #497.3
        por       %xmm10, %xmm15                                #497.3
        movdqa    %xmm5, %xmm10                                 #497.3
        movdqa    %xmm2, %xmm4                                  #497.3
        pslld     $15, %xmm10                                   #497.3
        psrld     $17, %xmm5                                    #497.3
        pslld     $15, %xmm4                                    #497.3
        psrld     $17, %xmm2                                    #497.3
        por       %xmm5, %xmm10                                 #497.3
        movdqa    %xmm11, %xmm5                                 #498.3
        por       %xmm2, %xmm4                                  #497.3
        pxor      %xmm9, %xmm5                                  #498.3
        pxor      %xmm4, %xmm5                                  #498.3
        movdqa    %xmm13, %xmm2                                 #498.3
        paddd     %xmm5, %xmm6                                  #498.3
        movdqa    %xmm0, %xmm5                                  #498.3
        pxor      %xmm14, %xmm2                                 #498.3
        pxor      %xmm12, %xmm5                                 #498.3
        paddd     208(%rsp), %xmm6                              #498.3
        paddd     %xmm3, %xmm7                                  #498.3
        pxor      %xmm15, %xmm2                                 #498.3
        paddd     %xmm3, %xmm8                                  #498.3
        pxor      %xmm10, %xmm5                                 #498.3
        paddd     %xmm2, %xmm7                                  #498.3
        paddd     %xmm5, %xmm8                                  #498.3
        movdqa    %xmm6, %xmm5                                  #498.3
        paddd     224(%rsp), %xmm7                              #498.3
        pslld     $3, %xmm5                                     #498.3
        psrld     $29, %xmm6                                    #498.3
        paddd     %xmm3, %xmm9                                  #499.3
        por       %xmm6, %xmm5                                  #498.3
        movdqa    %xmm7, %xmm6                                  #498.3
        paddd     240(%rsp), %xmm8                              #498.3
        pslld     $3, %xmm6                                     #498.3
        psrld     $29, %xmm7                                    #498.3
        paddd     %xmm3, %xmm14                                 #499.3
        por       %xmm7, %xmm6                                  #498.3
        movdqa    %xmm8, %xmm7                                  #498.3
        pslld     $3, %xmm7                                     #498.3
        psrld     $29, %xmm8                                    #498.3
        por       %xmm8, %xmm7                                  #498.3
        movdqa    %xmm4, %xmm8                                  #499.3
        pxor      %xmm11, %xmm8                                 #499.3
        movdqa    %xmm10, %xmm2                                 #499.3
        pxor      %xmm5, %xmm8                                  #499.3
        pxor      %xmm0, %xmm2                                  #499.3
        paddd     %xmm8, %xmm9                                  #499.3
        paddd     %xmm3, %xmm12                                 #499.3
        paddd     %xmm1, %xmm9                                  #499.3
        movdqa    %xmm15, %xmm1                                 #499.3
        pxor      %xmm13, %xmm1                                 #499.3
        pxor      %xmm7, %xmm2                                  #499.3
        pxor      %xmm6, %xmm1                                  #499.3
        paddd     %xmm2, %xmm12                                 #499.3
        paddd     %xmm1, %xmm14                                 #499.3
        movdqa    %xmm9, %xmm2                                  #499.3
        paddd     528(%rsp), %xmm14                             #499.3
        pslld     $9, %xmm2                                     #499.3
        movdqa    %xmm14, %xmm1                                 #499.3
        psrld     $23, %xmm14                                   #499.3
        paddd     512(%rsp), %xmm12                             #499.3
        pslld     $9, %xmm1                                     #499.3
        psrld     $23, %xmm9                                    #499.3
        por       %xmm14, %xmm1                                 #499.3
        movdqa    %xmm12, %xmm14                                #499.3
        por       %xmm9, %xmm2                                  #499.3
        pslld     $9, %xmm14                                    #499.3
        psrld     $23, %xmm12                                   #499.3
        movdqa    %xmm7, %xmm9                                  #500.3
        por       %xmm12, %xmm14                                #499.3
        movdqa    %xmm5, %xmm12                                 #500.3
        movdqa    %xmm6, %xmm8                                  #500.3
        pxor      %xmm10, %xmm9                                 #500.3
        pxor      %xmm4, %xmm12                                 #500.3
        pxor      %xmm15, %xmm8                                 #500.3
        paddd     %xmm3, %xmm0                                  #500.3
        pxor      %xmm14, %xmm9                                 #500.3
        paddd     %xmm3, %xmm11                                 #500.3
        pxor      %xmm2, %xmm12                                 #500.3
        paddd     %xmm3, %xmm13                                 #500.3
        pxor      %xmm1, %xmm8                                  #500.3
        paddd     %xmm9, %xmm0                                  #500.3
        paddd     368(%rsp), %xmm0                              #500.3
        paddd     %xmm12, %xmm11                                #500.3
        paddd     %xmm8, %xmm13                                 #500.3
        movdqa    %xmm0, %xmm12                                 #500.3
        paddd     336(%rsp), %xmm11                             #500.3
        pslld     $11, %xmm12                                   #500.3
        paddd     352(%rsp), %xmm13                             #500.3
        movdqa    %xmm11, %xmm9                                 #500.3
        movdqa    %xmm13, %xmm8                                 #500.3
        psrld     $21, %xmm0                                    #500.3
        pslld     $11, %xmm9                                    #500.3
        psrld     $21, %xmm11                                   #500.3
        pslld     $11, %xmm8                                    #500.3
        psrld     $21, %xmm13                                   #500.3
        por       %xmm0, %xmm12                                 #500.3
        movdqa    %xmm2, %xmm0                                  #501.3
        por       %xmm11, %xmm9                                 #500.3
        por       %xmm13, %xmm8                                 #500.3
        pxor      %xmm5, %xmm0                                  #501.3
        movdqa    %xmm1, %xmm13                                 #501.3
        paddd     %xmm3, %xmm4                                  #501.3
        pxor      %xmm9, %xmm0                                  #501.3
        pxor      %xmm6, %xmm13                                 #501.3
        paddd     %xmm0, %xmm4                                  #501.3
        paddd     %xmm3, %xmm15                                 #501.3
        pxor      %xmm8, %xmm13                                 #501.3
        movdqa    %xmm14, %xmm0                                 #501.3
        paddd     %xmm13, %xmm15                                #501.3
        paddd     608(%rsp), %xmm4                              #501.3
        pxor      %xmm7, %xmm0                                  #501.3
        paddd     544(%rsp), %xmm15                             #501.3
        paddd     %xmm3, %xmm10                                 #501.3
        pxor      %xmm12, %xmm0                                 #501.3
        movdqa    %xmm4, %xmm11                                 #501.3
        paddd     %xmm0, %xmm10                                 #501.3
        pslld     $15, %xmm11                                   #501.3
        psrld     $17, %xmm4                                    #501.3
        movdqa    %xmm15, %xmm0                                 #501.3
        paddd     560(%rsp), %xmm10                             #501.3
        por       %xmm4, %xmm11                                 #501.3
        pslld     $15, %xmm0                                    #501.3
        psrld     $17, %xmm15                                   #501.3
        movdqa    %xmm8, %xmm4                                  #502.3
        por       %xmm15, %xmm0                                 #501.3
        movdqa    %xmm10, %xmm13                                #501.3
        pxor      %xmm1, %xmm4                                  #502.3
        pslld     $15, %xmm13                                   #501.3
        psrld     $17, %xmm10                                   #501.3
        paddd     %xmm3, %xmm6                                  #502.3
        pxor      %xmm0, %xmm4                                  #502.3
        movdqa    %xmm12, %xmm15                                #502.3
        por       %xmm10, %xmm13                                #501.3
        movdqa    %xmm9, %xmm10                                 #502.3
        paddd     %xmm4, %xmm6                                  #502.3
        pxor      %xmm14, %xmm15                                #502.3
        pxor      %xmm2, %xmm10                                 #502.3
        paddd     112(%rsp), %xmm6                              #502.3
        paddd     %xmm3, %xmm7                                  #502.3
        pxor      %xmm13, %xmm15                                #502.3
        paddd     %xmm3, %xmm5                                  #502.3
        pxor      %xmm11, %xmm10                                #502.3
        paddd     %xmm15, %xmm7                                 #502.3
        movdqa    %xmm6, %xmm4                                  #502.3
        paddd     %xmm10, %xmm5                                 #502.3
        paddd     128(%rsp), %xmm7                              #502.3
        pslld     $3, %xmm4                                     #502.3
        psrld     $29, %xmm6                                    #502.3
        paddd     %xmm3, %xmm2                                  #503.3
        paddd     48(%rsp), %xmm5                               #502.3
        por       %xmm6, %xmm4                                  #502.3
        movdqa    %xmm7, %xmm6                                  #502.3
        movdqa    %xmm5, %xmm10                                 #502.3
        pslld     $3, %xmm6                                     #502.3
        psrld     $29, %xmm7                                    #502.3
        pslld     $3, %xmm10                                    #502.3
        psrld     $29, %xmm5                                    #502.3
        por       %xmm7, %xmm6                                  #502.3
        movdqa    %xmm11, %xmm7                                 #503.3
        por       %xmm5, %xmm10                                 #502.3
        pxor      %xmm9, %xmm7                                  #503.3
        pxor      %xmm10, %xmm7                                 #503.3
        movdqa    %xmm0, %xmm5                                  #503.3
        paddd     %xmm7, %xmm2                                  #503.3
        pxor      %xmm8, %xmm5                                  #503.3
        paddd     320(%rsp), %xmm2                              #503.3
        paddd     %xmm3, %xmm1                                  #503.3
        pxor      %xmm4, %xmm5                                  #503.3
                                # LOE rbx rbp rsi r12 r13 r14 r15 xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm8 xmm9 xmm10 xmm11 xmm12 xmm13 xmm14
..B8.7:                         # Preds ..B8.8
        movdqa    %xmm13, %xmm7                                 #503.3
        paddd     %xmm5, %xmm1                                  #503.3
        pxor      %xmm12, %xmm7                                 #503.3
        movdqa    %xmm2, %xmm5                                  #503.3
        paddd     304(%rsp), %xmm1                              #503.3
        paddd     %xmm3, %xmm14                                 #503.3
        pxor      %xmm6, %xmm7                                  #503.3
        pslld     $9, %xmm5                                     #503.3
        psrld     $23, %xmm2                                    #503.3
        paddd     %xmm7, %xmm14                                 #503.3
        por       %xmm2, %xmm5                                  #503.3
        movdqa    %xmm1, %xmm2                                  #503.3
        paddd     288(%rsp), %xmm14                             #503.3
        pslld     $9, %xmm2                                     #503.3
        psrld     $23, %xmm1                                    #503.3
        paddd     %xmm3, %xmm9                                  #504.3
        por       %xmm1, %xmm2                                  #503.3
        movdqa    %xmm14, %xmm1                                 #503.3
        pslld     $9, %xmm1                                     #503.3
        psrld     $23, %xmm14                                   #503.3
        por       %xmm14, %xmm1                                 #503.3
        movdqa    %xmm10, %xmm14                                #504.3
        pxor      %xmm11, %xmm14                                #504.3
        movdqa    %xmm4, %xmm15                                 #504.3
        pxor      %xmm5, %xmm14                                 #504.3
        pxor      %xmm0, %xmm15                                 #504.3
        paddd     %xmm14, %xmm9                                 #504.3
        paddd     %xmm3, %xmm8                                  #504.3
        paddd     144(%rsp), %xmm9                              #504.3
        pxor      %xmm2, %xmm15                                 #504.3
        movdqa    %xmm6, %xmm7                                  #504.3
        paddd     %xmm15, %xmm8                                 #504.3
        pxor      %xmm13, %xmm7                                 #504.3
        movdqa    %xmm9, %xmm14                                 #504.3
        paddd     160(%rsp), %xmm8                              #504.3
        paddd     %xmm3, %xmm12                                 #504.3
        pxor      %xmm1, %xmm7                                  #504.3
        pslld     $11, %xmm14                                   #504.3
        psrld     $21, %xmm9                                    #504.3
        paddd     %xmm7, %xmm12                                 #504.3
        por       %xmm9, %xmm14                                 #504.3
        movdqa    %xmm8, %xmm9                                  #504.3
        paddd     176(%rsp), %xmm12                             #504.3
        pslld     $11, %xmm9                                    #504.3
        psrld     $21, %xmm8                                    #504.3
        paddd     %xmm3, %xmm11                                 #505.3
        por       %xmm8, %xmm9                                  #504.3
        movdqa    %xmm12, %xmm8                                 #504.3
        pslld     $11, %xmm8                                    #504.3
        psrld     $21, %xmm12                                   #504.3
        por       %xmm12, %xmm8                                 #504.3
        movdqa    %xmm10, %xmm12                                #505.3
        pxor      %xmm5, %xmm12                                 #505.3
        movdqa    %xmm4, %xmm7                                  #505.3
        pxor      %xmm14, %xmm12                                #505.3
        pxor      %xmm2, %xmm7                                  #505.3
        paddd     %xmm12, %xmm11                                #505.3
        paddd     %xmm3, %xmm0                                  #505.3
        paddd     464(%rsp), %xmm11                             #505.3
        pxor      %xmm9, %xmm7                                  #505.3
        movdqa    %xmm6, %xmm15                                 #505.3
        paddd     %xmm7, %xmm0                                  #505.3
        pxor      %xmm1, %xmm15                                 #505.3
        movdqa    %xmm11, %xmm12                                #505.3
        paddd     480(%rsp), %xmm0                              #505.3
        paddd     %xmm3, %xmm13                                 #505.3
        pxor      %xmm8, %xmm15                                 #505.3
        pslld     $15, %xmm12                                   #505.3
        psrld     $17, %xmm11                                   #505.3
        paddd     %xmm15, %xmm13                                #505.3
        por       %xmm11, %xmm12                                #505.3
        movdqa    %xmm0, %xmm11                                 #505.3
        paddd     400(%rsp), %xmm13                             #505.3
        pslld     $15, %xmm11                                   #505.3
        psrld     $17, %xmm0                                    #505.3
        movdqa    %xmm8, %xmm15                                 #506.3
        por       %xmm0, %xmm11                                 #505.3
        movdqa    %xmm13, %xmm0                                 #505.3
        pslld     $15, %xmm0                                    #505.3
        psrld     $17, %xmm13                                   #505.3
        por       %xmm13, %xmm0                                 #505.3
        movdqa    %xmm14, %xmm13                                #506.3
        pxor      %xmm5, %xmm13                                 #506.3
        paddd     %xmm3, %xmm10                                 #506.3
        pxor      %xmm12, %xmm13                                #506.3
        movdqa    %xmm9, %xmm7                                  #506.3
        pxor      %xmm1, %xmm15                                 #506.3
        paddd     %xmm13, %xmm10                                #506.3
        pxor      %xmm2, %xmm7                                  #506.3
        paddd     %xmm3, %xmm6                                  #506.3
        pxor      %xmm0, %xmm15                                 #506.3
        paddd     %xmm3, %xmm4                                  #506.3
        paddd     (%rsp), %xmm10                                #506.3
        pxor      %xmm11, %xmm7                                 #506.3
        paddd     %xmm15, %xmm6                                 #506.3
        paddd     %xmm7, %xmm4                                  #506.3
        paddd     32(%rsp), %xmm6                               #506.3
        movdqa    %xmm10, %xmm13                                #506.3
        paddd     16(%rsp), %xmm4                               #506.3
        pslld     $3, %xmm13                                    #506.3
        psrld     $29, %xmm10                                   #506.3
        movdqa    %xmm6, %xmm7                                  #506.3
        por       %xmm10, %xmm13                                #506.3
        movdqa    %xmm4, %xmm10                                 #506.3
        pslld     $3, %xmm7                                     #506.3
        psrld     $29, %xmm6                                    #506.3
        pslld     $3, %xmm10                                    #506.3
        psrld     $29, %xmm4                                    #506.3
        por       %xmm6, %xmm7                                  #506.3
        movdqa    %xmm12, %xmm6                                 #507.3
        por       %xmm4, %xmm10                                 #506.3
        pxor      %xmm14, %xmm6                                 #507.3
        movdqa    %xmm11, %xmm4                                 #507.3
        paddd     %xmm3, %xmm5                                  #507.3
        pxor      %xmm13, %xmm6                                 #507.3
        pxor      %xmm9, %xmm4                                  #507.3
        paddd     %xmm6, %xmm5                                  #507.3
        paddd     %xmm3, %xmm2                                  #507.3
        pxor      %xmm10, %xmm4                                 #507.3
        movdqa    %xmm0, %xmm6                                  #507.3
        paddd     192(%rsp), %xmm5                              #507.3
        paddd     %xmm4, %xmm2                                  #507.3
        pxor      %xmm8, %xmm6                                  #507.3
        paddd     %xmm3, %xmm1                                  #507.3
        paddd     256(%rsp), %xmm2                              #507.3
        pxor      %xmm7, %xmm6                                  #507.3
        movdqa    %xmm5, %xmm4                                  #507.3
        paddd     %xmm6, %xmm1                                  #507.3
        pslld     $9, %xmm4                                     #507.3
        psrld     $23, %xmm5                                    #507.3
        movdqa    %xmm2, %xmm6                                  #507.3
        por       %xmm5, %xmm4                                  #507.3
        paddd     272(%rsp), %xmm1                              #507.3
        pslld     $9, %xmm6                                     #507.3
        psrld     $23, %xmm2                                    #507.3
        movdqa    %xmm10, %xmm5                                 #508.3
        por       %xmm2, %xmm6                                  #507.3
        movdqa    %xmm1, %xmm2                                  #507.3
        pxor      %xmm11, %xmm5                                 #508.3
        pslld     $9, %xmm2                                     #507.3
        psrld     $23, %xmm1                                    #507.3
        paddd     %xmm3, %xmm9                                  #508.3
        pxor      %xmm6, %xmm5                                  #508.3
        movdqa    %xmm7, %xmm15                                 #508.3
        por       %xmm1, %xmm2                                  #507.3
        movdqa    %xmm13, %xmm1                                 #508.3
        paddd     %xmm5, %xmm9                                  #508.3
        pxor      %xmm0, %xmm15                                 #508.3
        paddd     80(%rsp), %xmm9                               #508.3
        pxor      %xmm12, %xmm1                                 #508.3
        paddd     %xmm3, %xmm8                                  #508.3
        pxor      %xmm2, %xmm15                                 #508.3
        paddd     %xmm3, %xmm14                                 #508.3
        pxor      %xmm4, %xmm1                                  #508.3
        paddd     %xmm15, %xmm8                                 #508.3
        movdqa    %xmm9, %xmm15                                 #508.3
        paddd     64(%rsp), %xmm8                               #508.3
        paddd     %xmm1, %xmm14                                 #508.3
        pslld     $11, %xmm15                                   #508.3
        psrld     $21, %xmm9                                    #508.3
        paddd     96(%rsp), %xmm14                              #508.3
        por       %xmm9, %xmm15                                 #508.3
        movdqa    %xmm8, %xmm9                                  #508.3
        movdqa    %xmm14, %xmm1                                 #508.3
        pslld     $11, %xmm9                                    #508.3
        psrld     $21, %xmm8                                    #508.3
        pslld     $11, %xmm1                                    #508.3
        psrld     $21, %xmm14                                   #508.3
        por       %xmm8, %xmm9                                  #508.3
        paddd     %xmm3, %xmm12                                 #509.3
        movdqa    %xmm4, %xmm8                                  #509.3
        paddd     %xmm3, %xmm11                                 #509.3
        movdqa    %xmm6, %xmm5                                  #509.3
        paddd     %xmm3, %xmm0                                  #509.3
        movdqa    %xmm2, %xmm3                                  #509.3
        por       %xmm14, %xmm1                                 #508.3
        pxor      %xmm13, %xmm8                                 #509.3
        pxor      %xmm10, %xmm5                                 #509.3
        pxor      %xmm7, %xmm3                                  #509.3
        pxor      %xmm1, %xmm8                                  #509.3
        pxor      %xmm15, %xmm5                                 #509.3
        pxor      %xmm9, %xmm3                                  #509.3
        paddd     %xmm8, %xmm12                                 #509.3
        paddd     %xmm5, %xmm11                                 #509.3
        paddd     %xmm3, %xmm0                                  #509.3
        movdqa    .L_2il0floatpacket.474(%rip), %xmm8           #513.10
        movdqa    .L_2il0floatpacket.477(%rip), %xmm5           #516.10
        paddd     %xmm8, %xmm10                                 #513.10
        paddd     384(%rsp), %xmm12                             #509.3
        paddd     %xmm5, %xmm4                                  #516.10
        paddd     688(%rsp), %xmm11                             #509.3
        movdqa    %xmm12, %xmm3                                 #509.3
        paddd     704(%rsp), %xmm0                              #509.3
        pslld     $15, %xmm3                                    #509.3
        movdqa    %xmm4, 48(%rsi)                               #422.6
        movdqa    %xmm11, %xmm4                                 #509.3
        movdqa    %xmm10, 64(%rsi)                              #422.6
        movdqa    %xmm0, %xmm10                                 #509.3
        psrld     $17, %xmm12                                   #509.3
        pslld     $15, %xmm4                                    #509.3
        psrld     $17, %xmm11                                   #509.3
        pslld     $15, %xmm10                                   #509.3
        psrld     $17, %xmm0                                    #509.3
        por       %xmm12, %xmm3                                 #509.3
        movdqa    .L_2il0floatpacket.475(%rip), %xmm12          #514.10
        por       %xmm11, %xmm4                                 #509.3
        movdqa    .L_2il0floatpacket.476(%rip), %xmm14          #515.10
        por       %xmm0, %xmm10                                 #509.3
        paddd     %xmm8, %xmm13                                 #513.10
        paddd     %xmm12, %xmm3                                 #514.10
        paddd     %xmm14, %xmm1                                 #515.10
        paddd     %xmm12, %xmm4                                 #514.10
        paddd     %xmm14, %xmm15                                #515.10
        paddd     %xmm5, %xmm6                                  #516.10
        paddd     %xmm8, %xmm7                                  #513.10
        paddd     %xmm12, %xmm10                                #514.10
        paddd     %xmm14, %xmm9                                 #515.10
        paddd     %xmm5, %xmm2                                  #516.10
        movdqa    %xmm13, (%rsi)                                #422.6
        movdqa    %xmm3, 16(%rsi)                               #422.6
        movdqa    %xmm1, 32(%rsi)                               #422.6
        movdqa    %xmm4, 80(%rsi)                               #422.6
        movdqa    %xmm15, 96(%rsi)                              #422.6
        movdqa    %xmm6, 112(%rsi)                              #422.6
        movdqa    %xmm7, 128(%rsi)                              #422.6
        movdqa    %xmm10, 144(%rsi)                             #422.6
        movdqa    %xmm9, 160(%rsi)                              #422.6
        movdqa    %xmm2, 176(%rsi)                              #422.6
        addq      $776, %rsp                                    #522.1
..___tag_value_SSEmd4body.142:                                  #
        ret                                                     #522.1
        .align    16,0x90
..___tag_value_SSEmd4body.143:                                  #
                                # LOE
# mark_end;
	.type	SSEmd4body,@function
	.size	SSEmd4body,.-SSEmd4body
	.data
# -- End  SSEmd4body
	.text
# -- Begin  SSESHA1body
# mark_begin;
       .align    16,0x90
	.globl SSESHA1body
SSESHA1body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B9.1:                         # Preds ..B9.0
..___tag_value_SSESHA1body.144:                                 #562.1
        xorl      %eax, %eax                                    #573.2
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 eax ecx
..B9.2:                         # Preds ..B9.2 ..B9.1
        lea       13(%rax), %r8d                                #575.3
        lea       8(%rax), %r9d                                 #575.3
        shlq      $4, %r8                                       #575.3
        lea       93(%rax), %r10d                               #575.3
        lea       88(%rax), %r11d                               #575.3
        shlq      $4, %r9                                       #575.3
        movdqa    (%rdi,%r8), %xmm0                             #561.6
        lea       2(%rax), %r8d                                 #575.3
        shlq      $4, %r10                                      #575.3
        shlq      $4, %r8                                       #575.3
        pxor      (%rdi,%r9), %xmm0                             #575.3
        lea       82(%rax), %r9d                                #575.3
        shlq      $4, %r11                                      #575.3
        movdqa    (%rdi,%r10), %xmm2                            #561.6
        movl      %eax, %r10d                                   #575.3
        shlq      $4, %r9                                       #575.3
        shlq      $4, %r10                                      #575.3
        pxor      (%rdi,%r8), %xmm0                             #575.3
        lea       80(%rax), %r8d                                #575.3
        pxor      (%rdi,%r11), %xmm2                            #575.3
        shlq      $4, %r8                                       #575.3
        pxor      (%rdi,%r9), %xmm2                             #575.3
        lea       16(%rax), %r9d                                #575.3
        pxor      (%rdi,%r10), %xmm0                            #575.3
        lea       96(%rax), %r10d                               #575.3
        movdqa    %xmm0, %xmm1                                  #575.3
        pslld     $1, %xmm1                                     #575.3
        shlq      $4, %r9                                       #575.3
        psrld     $31, %xmm0                                    #575.3
        shlq      $4, %r10                                      #575.3
        incl      %eax                                          #573.2
        pxor      (%rdi,%r8), %xmm2                             #575.3
        por       %xmm0, %xmm1                                  #575.3
        movdqa    %xmm2, %xmm3                                  #575.3
        psrld     $31, %xmm2                                    #575.3
        pslld     $1, %xmm3                                     #575.3
        cmpl      $64, %eax                                     #573.2
        movdqa    %xmm1, (%rdi,%r9)                             #561.6
        por       %xmm2, %xmm3                                  #575.3
        movdqa    %xmm3, (%rdi,%r10)                            #561.6
        jb        ..B9.2        # Prob 98%                      #573.2
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 eax ecx
..B9.3:                         # Preds ..B9.2
        testq     %rdx, %rdx                                    #578.6
        je        ..B9.12       # Prob 12%                      #578.6
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx
..B9.4:                         # Preds ..B9.3
        movdqa    (%rdx), %xmm7                                 #561.6
        movdqa    16(%rdx), %xmm1                               #561.6
        movdqa    32(%rdx), %xmm6                               #561.6
        movdqa    48(%rdx), %xmm2                               #561.6
        movdqa    64(%rdx), %xmm11                              #561.6
        movdqa    80(%rdx), %xmm10                              #561.6
        movdqa    96(%rdx), %xmm5                               #561.6
        movdqa    112(%rdx), %xmm9                              #561.6
        movdqa    128(%rdx), %xmm3                              #561.6
        movdqa    144(%rdx), %xmm0                              #561.6
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx xmm0 xmm1 xmm2 xmm3 xmm5 xmm6 xmm7 xmm9 xmm10 xmm11
..B9.5:                         # Preds ..B9.12 ..B9.4
        movdqa    %xmm6, %xmm12                                 #602.2
        movdqa    %xmm7, %xmm8                                  #602.2
        pxor      %xmm2, %xmm12                                 #602.2
        movdqa    %xmm7, %xmm14                                 #602.2
        pand      %xmm1, %xmm12                                 #602.2
        movdqa    %xmm9, %xmm13                                 #602.2
        pxor      %xmm2, %xmm12                                 #602.2
        pslld     $5, %xmm8                                     #602.2
        psrld     $27, %xmm14                                   #602.2
        pxor      %xmm3, %xmm13                                 #602.2
        paddd     %xmm12, %xmm11                                #602.2
        por       %xmm14, %xmm8                                 #602.2
        pand      %xmm5, %xmm13                                 #602.2
        movdqa    %xmm10, %xmm14                                #602.2
        movdqa    %xmm10, %xmm12                                #602.2
        paddd     %xmm8, %xmm11                                 #602.2
        movdqa    .L_2il0floatpacket.503(%rip), %xmm4           #601.8
        pxor      %xmm3, %xmm13                                 #602.2
        pslld     $5, %xmm14                                    #602.2
        psrld     $27, %xmm12                                   #602.2
        paddd     %xmm4, %xmm11                                 #602.2
        paddd     %xmm13, %xmm0                                 #602.2
        por       %xmm12, %xmm14                                #602.2
        movdqa    %xmm1, %xmm8                                  #602.2
        movdqa    %xmm5, %xmm13                                 #602.2
        paddd     %xmm14, %xmm0                                 #602.2
        paddd     (%rdi), %xmm11                                #602.2
        pslld     $30, %xmm8                                    #602.2
        psrld     $2, %xmm1                                     #602.2
        pslld     $30, %xmm13                                   #602.2
        psrld     $2, %xmm5                                     #602.2
        paddd     %xmm4, %xmm0                                  #602.2
        por       %xmm1, %xmm8                                  #602.2
        por       %xmm5, %xmm13                                 #602.2
        movdqa    %xmm11, %xmm1                                 #603.2
        movdqa    %xmm11, %xmm12                                #603.2
        movdqa    %xmm9, %xmm14                                 #603.2
        pslld     $5, %xmm1                                     #603.2
        paddd     1280(%rdi), %xmm0                             #602.2
        psrld     $27, %xmm12                                   #603.2
        pxor      %xmm13, %xmm14                                #603.2
        por       %xmm12, %xmm1                                 #603.2
        pand      %xmm10, %xmm14                                #603.2
        movdqa    %xmm0, %xmm12                                 #603.2
        movdqa    %xmm0, %xmm15                                 #603.2
        movdqa    %xmm6, %xmm5                                  #603.2
        pxor      %xmm9, %xmm14                                 #603.2
        pslld     $5, %xmm12                                    #603.2
        psrld     $27, %xmm15                                   #603.2
        pxor      %xmm8, %xmm5                                  #603.2
        paddd     %xmm14, %xmm3                                 #603.2
        por       %xmm15, %xmm12                                #603.2
        movdqa    %xmm7, %xmm14                                 #603.2
        movdqa    %xmm10, %xmm15                                #603.2
        pand      %xmm7, %xmm5                                  #603.2
        pslld     $30, %xmm14                                   #603.2
        psrld     $2, %xmm7                                     #603.2
        pslld     $30, %xmm15                                   #603.2
        psrld     $2, %xmm10                                    #603.2
        pxor      %xmm6, %xmm5                                  #603.2
        paddd     %xmm12, %xmm3                                 #603.2
        por       %xmm7, %xmm14                                 #603.2
        por       %xmm10, %xmm15                                #603.2
        paddd     %xmm5, %xmm2                                  #603.2
        paddd     %xmm4, %xmm3                                  #603.2
        movdqa    %xmm14, %xmm7                                 #604.2
        movdqa    %xmm15, %xmm12                                #604.2
        paddd     %xmm1, %xmm2                                  #603.2
        paddd     1296(%rdi), %xmm3                             #603.2
        pxor      %xmm8, %xmm7                                  #604.2
        pxor      %xmm13, %xmm12                                #604.2
        paddd     %xmm4, %xmm2                                  #603.2
        pand      %xmm11, %xmm7                                 #604.2
        pand      %xmm0, %xmm12                                 #604.2
        movdqa    %xmm3, %xmm1                                  #604.2
        movdqa    %xmm3, %xmm5                                  #604.2
        paddd     16(%rdi), %xmm2                               #603.2
        pxor      %xmm8, %xmm7                                  #604.2
        pxor      %xmm13, %xmm12                                #604.2
        pslld     $5, %xmm1                                     #604.2
        psrld     $27, %xmm5                                    #604.2
        paddd     %xmm7, %xmm6                                  #604.2
        movdqa    %xmm2, %xmm7                                  #604.2
        movdqa    %xmm2, %xmm10                                 #604.2
        paddd     %xmm12, %xmm9                                 #604.2
        por       %xmm5, %xmm1                                  #604.2
        pslld     $5, %xmm7                                     #604.2
        psrld     $27, %xmm10                                   #604.2
        paddd     %xmm1, %xmm9                                  #604.2
        movdqa    %xmm11, %xmm1                                 #604.2
        por       %xmm10, %xmm7                                 #604.2
        pslld     $30, %xmm1                                    #604.2
        psrld     $2, %xmm11                                    #604.2
        movdqa    %xmm0, %xmm5                                  #604.2
        paddd     %xmm7, %xmm6                                  #604.2
        por       %xmm11, %xmm1                                 #604.2
        pslld     $30, %xmm5                                    #604.2
        psrld     $2, %xmm0                                     #604.2
        paddd     %xmm4, %xmm6                                  #604.2
        por       %xmm0, %xmm5                                  #604.2
        movdqa    %xmm1, %xmm0                                  #605.2
        movdqa    %xmm5, %xmm12                                 #605.2
        paddd     32(%rdi), %xmm6                               #604.2
        pxor      %xmm14, %xmm0                                 #605.2
        pand      %xmm2, %xmm0                                  #605.2
        movdqa    %xmm6, %xmm7                                  #605.2
        movdqa    %xmm6, %xmm11                                 #605.2
        pxor      %xmm14, %xmm0                                 #605.2
        pslld     $5, %xmm7                                     #605.2
        psrld     $27, %xmm11                                   #605.2
        paddd     %xmm0, %xmm8                                  #605.2
        por       %xmm11, %xmm7                                 #605.2
        paddd     %xmm7, %xmm8                                  #605.2
        movdqa    %xmm2, %xmm7                                  #605.2
        pxor      %xmm15, %xmm12                                #605.2
        pslld     $30, %xmm7                                    #605.2
        psrld     $2, %xmm2                                     #605.2
        movdqa    %xmm3, %xmm11                                 #605.2
        pand      %xmm3, %xmm12                                 #605.2
        por       %xmm2, %xmm7                                  #605.2
        pslld     $30, %xmm11                                   #605.2
        psrld     $2, %xmm3                                     #605.2
        paddd     %xmm4, %xmm8                                  #605.2
        por       %xmm3, %xmm11                                 #605.2
        movdqa    %xmm7, %xmm3                                  #606.2
        pxor      %xmm15, %xmm12                                #605.2
        paddd     48(%rdi), %xmm8                               #605.2
        pxor      %xmm1, %xmm3                                  #606.2
        paddd     %xmm4, %xmm9                                  #604.2
        paddd     %xmm12, %xmm13                                #605.2
        pand      %xmm6, %xmm3                                  #606.2
        movdqa    %xmm8, %xmm12                                 #606.2
        movdqa    %xmm8, %xmm2                                  #606.2
        pxor      %xmm1, %xmm3                                  #606.2
        paddd     1312(%rdi), %xmm9                             #604.2
        pslld     $5, %xmm12                                    #606.2
        psrld     $27, %xmm2                                    #606.2
        movdqa    %xmm9, %xmm10                                 #605.2
        movdqa    %xmm9, %xmm0                                  #605.2
        paddd     %xmm3, %xmm14                                 #606.2
        por       %xmm2, %xmm12                                 #606.2
        pslld     $5, %xmm10                                    #605.2
        psrld     $27, %xmm0                                    #605.2
        paddd     %xmm12, %xmm14                                #606.2
        movdqa    %xmm11, %xmm3                                 #606.2
        movdqa    %xmm6, %xmm12                                 #606.2
        por       %xmm0, %xmm10                                 #605.2
        pxor      %xmm5, %xmm3                                  #606.2
        pslld     $30, %xmm12                                   #606.2
        psrld     $2, %xmm6                                     #606.2
        movdqa    %xmm9, %xmm2                                  #606.2
        paddd     %xmm10, %xmm13                                #605.2
        pand      %xmm9, %xmm3                                  #606.2
        por       %xmm6, %xmm12                                 #606.2
        pslld     $30, %xmm2                                    #606.2
        psrld     $2, %xmm9                                     #606.2
        paddd     %xmm4, %xmm13                                 #605.2
        paddd     %xmm4, %xmm14                                 #606.2
        por       %xmm9, %xmm2                                  #606.2
        movdqa    %xmm12, %xmm9                                 #607.2
        paddd     1328(%rdi), %xmm13                            #605.2
        pxor      %xmm5, %xmm3                                  #606.2
        paddd     64(%rdi), %xmm14                              #606.2
        pxor      %xmm7, %xmm9                                  #607.2
        paddd     %xmm3, %xmm15                                 #606.2
        movdqa    %xmm13, %xmm10                                #606.2
        movdqa    %xmm13, %xmm0                                 #606.2
        pand      %xmm8, %xmm9                                  #607.2
        movdqa    %xmm14, %xmm3                                 #607.2
        movdqa    %xmm14, %xmm6                                 #607.2
        pslld     $5, %xmm10                                    #606.2
        psrld     $27, %xmm0                                    #606.2
        pxor      %xmm7, %xmm9                                  #607.2
        pslld     $5, %xmm3                                     #607.2
        psrld     $27, %xmm6                                    #607.2
        por       %xmm0, %xmm10                                 #606.2
        paddd     %xmm9, %xmm1                                  #607.2
        por       %xmm6, %xmm3                                  #607.2
        paddd     %xmm10, %xmm15                                #606.2
        paddd     %xmm3, %xmm1                                  #607.2
        movdqa    %xmm8, %xmm3                                  #607.2
        paddd     %xmm4, %xmm15                                 #606.2
        movdqa    %xmm2, %xmm9                                  #607.2
        pslld     $30, %xmm3                                    #607.2
        psrld     $2, %xmm8                                     #607.2
        pxor      %xmm11, %xmm9                                 #607.2
        paddd     1344(%rdi), %xmm15                            #606.2
        por       %xmm8, %xmm3                                  #607.2
        paddd     %xmm4, %xmm1                                  #607.2
        pand      %xmm13, %xmm9                                 #607.2
        movdqa    %xmm15, %xmm10                                #607.2
        movdqa    %xmm15, %xmm0                                 #607.2
        movdqa    %xmm13, %xmm6                                 #607.2
        movdqa    %xmm3, %xmm8                                  #608.2
        paddd     80(%rdi), %xmm1                               #607.2
        pxor      %xmm11, %xmm9                                 #607.2
        pslld     $5, %xmm10                                    #607.2
        psrld     $27, %xmm0                                    #607.2
        pslld     $30, %xmm6                                    #607.2
        psrld     $2, %xmm13                                    #607.2
        pxor      %xmm12, %xmm8                                 #608.2
        paddd     %xmm9, %xmm5                                  #607.2
        por       %xmm0, %xmm10                                 #607.2
        por       %xmm13, %xmm6                                 #607.2
        pand      %xmm14, %xmm8                                 #608.2
        movdqa    %xmm1, %xmm9                                  #608.2
        movdqa    %xmm1, %xmm13                                 #608.2
        paddd     %xmm10, %xmm5                                 #607.2
        pxor      %xmm12, %xmm8                                 #608.2
        pslld     $5, %xmm9                                     #608.2
        psrld     $27, %xmm13                                   #608.2
        paddd     %xmm4, %xmm5                                  #607.2
        paddd     %xmm8, %xmm7                                  #608.2
        por       %xmm13, %xmm9                                 #608.2
        paddd     1360(%rdi), %xmm5                             #607.2
        paddd     %xmm9, %xmm7                                  #608.2
        movdqa    %xmm14, %xmm9                                 #608.2
        movdqa    %xmm6, %xmm0                                  #608.2
        movdqa    %xmm5, %xmm8                                  #608.2
        movdqa    %xmm5, %xmm10                                 #608.2
        pslld     $30, %xmm9                                    #608.2
        psrld     $2, %xmm14                                    #608.2
        pxor      %xmm2, %xmm0                                  #608.2
        pslld     $5, %xmm8                                     #608.2
        psrld     $27, %xmm10                                   #608.2
        por       %xmm14, %xmm9                                 #608.2
        paddd     %xmm4, %xmm7                                  #608.2
        pand      %xmm15, %xmm0                                 #608.2
        por       %xmm10, %xmm8                                 #608.2
        movdqa    %xmm15, %xmm10                                #608.2
        movdqa    %xmm9, %xmm14                                 #609.2
        pxor      %xmm2, %xmm0                                  #608.2
        paddd     96(%rdi), %xmm7                               #608.2
        pslld     $30, %xmm10                                   #608.2
        psrld     $2, %xmm15                                    #608.2
        pxor      %xmm3, %xmm14                                 #609.2
        paddd     %xmm0, %xmm11                                 #608.2
        por       %xmm15, %xmm10                                #608.2
        pand      %xmm1, %xmm14                                 #609.2
        movdqa    %xmm7, %xmm0                                  #609.2
        movdqa    %xmm7, %xmm15                                 #609.2
        pxor      %xmm3, %xmm14                                 #609.2
        pslld     $5, %xmm0                                     #609.2
        psrld     $27, %xmm15                                   #609.2
        paddd     %xmm8, %xmm11                                 #608.2
        paddd     %xmm14, %xmm12                                #609.2
        por       %xmm15, %xmm0                                 #609.2
        paddd     %xmm4, %xmm11                                 #608.2
        paddd     %xmm0, %xmm12                                 #609.2
        movdqa    %xmm10, %xmm8                                 #609.2
        movdqa    %xmm1, %xmm0                                  #609.2
        pxor      %xmm6, %xmm8                                  #609.2
        paddd     1376(%rdi), %xmm11                            #608.2
        pslld     $30, %xmm0                                    #609.2
        psrld     $2, %xmm1                                     #609.2
        pand      %xmm5, %xmm8                                  #609.2
        movdqa    %xmm11, %xmm14                                #609.2
        movdqa    %xmm11, %xmm13                                #609.2
        por       %xmm1, %xmm0                                  #609.2
        movdqa    %xmm5, %xmm1                                  #609.2
        pxor      %xmm6, %xmm8                                  #609.2
        pslld     $5, %xmm14                                    #609.2
        psrld     $27, %xmm13                                   #609.2
        pslld     $30, %xmm1                                    #609.2
        psrld     $2, %xmm5                                     #609.2
        paddd     %xmm8, %xmm2                                  #609.2
        por       %xmm13, %xmm14                                #609.2
        por       %xmm5, %xmm1                                  #609.2
        movdqa    %xmm0, %xmm5                                  #610.2
        paddd     %xmm14, %xmm2                                 #609.2
        pxor      %xmm9, %xmm5                                  #610.2
        paddd     %xmm4, %xmm2                                  #609.2
        pand      %xmm7, %xmm5                                  #610.2
        movdqa    %xmm1, %xmm14                                 #610.2
        paddd     1392(%rdi), %xmm2                             #609.2
        pxor      %xmm9, %xmm5                                  #610.2
        pxor      %xmm10, %xmm14                                #610.2
        paddd     %xmm5, %xmm3                                  #610.2
        pand      %xmm11, %xmm14                                #610.2
        movdqa    %xmm2, %xmm5                                  #610.2
        movdqa    %xmm2, %xmm15                                 #610.2
        pxor      %xmm10, %xmm14                                #610.2
        pslld     $5, %xmm5                                     #610.2
        psrld     $27, %xmm15                                   #610.2
        paddd     %xmm14, %xmm6                                 #610.2
        por       %xmm15, %xmm5                                 #610.2
        paddd     %xmm5, %xmm6                                  #610.2
        movdqa    %xmm7, %xmm5                                  #610.2
        pslld     $30, %xmm5                                    #610.2
        psrld     $2, %xmm7                                     #610.2
        por       %xmm7, %xmm5                                  #610.2
        movdqa    %xmm11, %xmm7                                 #610.2
        pslld     $30, %xmm7                                    #610.2
        psrld     $2, %xmm11                                    #610.2
        paddd     %xmm4, %xmm12                                 #609.2
        por       %xmm11, %xmm7                                 #610.2
        movdqa    %xmm5, %xmm11                                 #611.2
        paddd     %xmm4, %xmm6                                  #610.2
        paddd     112(%rdi), %xmm12                             #609.2
        pxor      %xmm0, %xmm11                                 #611.2
        pand      %xmm12, %xmm11                                #611.2
        movdqa    %xmm7, %xmm14                                 #611.2
        paddd     1408(%rdi), %xmm6                             #610.2
        pxor      %xmm0, %xmm11                                 #611.2
        pxor      %xmm1, %xmm14                                 #611.2
        paddd     %xmm11, %xmm9                                 #611.2
        pand      %xmm2, %xmm14                                 #611.2
        movdqa    %xmm6, %xmm11                                 #611.2
        movdqa    %xmm6, %xmm15                                 #611.2
        pxor      %xmm1, %xmm14                                 #611.2
        pslld     $5, %xmm11                                    #611.2
        psrld     $27, %xmm15                                   #611.2
        paddd     %xmm14, %xmm10                                #611.2
        por       %xmm15, %xmm11                                #611.2
        movdqa    %xmm12, %xmm13                                #610.2
        movdqa    %xmm12, %xmm8                                 #610.2
        paddd     %xmm11, %xmm10                                #611.2
        movdqa    %xmm12, %xmm11                                #611.2
        pslld     $5, %xmm13                                    #610.2
        psrld     $27, %xmm8                                    #610.2
        pslld     $30, %xmm11                                   #611.2
        psrld     $2, %xmm12                                    #611.2
        por       %xmm8, %xmm13                                 #610.2
        por       %xmm12, %xmm11                                #611.2
        movdqa    %xmm2, %xmm12                                 #611.2
        paddd     %xmm13, %xmm3                                 #610.2
        pslld     $30, %xmm12                                   #611.2
        psrld     $2, %xmm2                                     #611.2
        paddd     %xmm4, %xmm3                                  #610.2
        por       %xmm2, %xmm12                                 #611.2
        movdqa    %xmm11, %xmm2                                 #612.2
        paddd     %xmm4, %xmm10                                 #611.2
        paddd     128(%rdi), %xmm3                              #610.2
        pxor      %xmm5, %xmm2                                  #612.2
        pand      %xmm3, %xmm2                                  #612.2
        movdqa    %xmm12, %xmm14                                #612.2
        paddd     1424(%rdi), %xmm10                            #611.2
        pxor      %xmm5, %xmm2                                  #612.2
        pxor      %xmm7, %xmm14                                 #612.2
        paddd     %xmm2, %xmm0                                  #612.2
        pand      %xmm6, %xmm14                                 #612.2
        movdqa    %xmm10, %xmm2                                 #612.2
        movdqa    %xmm10, %xmm15                                #612.2
        pxor      %xmm7, %xmm14                                 #612.2
        pslld     $5, %xmm2                                     #612.2
        psrld     $27, %xmm15                                   #612.2
        paddd     %xmm14, %xmm1                                 #612.2
        por       %xmm15, %xmm2                                 #612.2
        movdqa    %xmm3, %xmm13                                 #611.2
        movdqa    %xmm3, %xmm8                                  #611.2
        paddd     %xmm2, %xmm1                                  #612.2
        movdqa    %xmm3, %xmm2                                  #612.2
        pslld     $5, %xmm13                                    #611.2
        psrld     $27, %xmm8                                    #611.2
        pslld     $30, %xmm2                                    #612.2
        psrld     $2, %xmm3                                     #612.2
        por       %xmm8, %xmm13                                 #611.2
        por       %xmm3, %xmm2                                  #612.2
        movdqa    %xmm6, %xmm3                                  #612.2
        paddd     %xmm13, %xmm9                                 #611.2
        pslld     $30, %xmm3                                    #612.2
        psrld     $2, %xmm6                                     #612.2
        paddd     %xmm4, %xmm9                                  #611.2
        por       %xmm6, %xmm3                                  #612.2
        movdqa    %xmm2, %xmm6                                  #613.2
        paddd     %xmm4, %xmm1                                  #612.2
        paddd     144(%rdi), %xmm9                              #611.2
        pxor      %xmm11, %xmm6                                 #613.2
        pand      %xmm9, %xmm6                                  #613.2
        movdqa    %xmm3, %xmm14                                 #613.2
        paddd     1440(%rdi), %xmm1                             #612.2
        pxor      %xmm11, %xmm6                                 #613.2
        pxor      %xmm12, %xmm14                                #613.2
        paddd     %xmm6, %xmm5                                  #613.2
        pand      %xmm10, %xmm14                                #613.2
        movdqa    %xmm1, %xmm6                                  #613.2
        movdqa    %xmm1, %xmm15                                 #613.2
        pxor      %xmm12, %xmm14                                #613.2
        pslld     $5, %xmm6                                     #613.2
        psrld     $27, %xmm15                                   #613.2
        paddd     %xmm14, %xmm7                                 #613.2
        por       %xmm15, %xmm6                                 #613.2
        movdqa    %xmm9, %xmm13                                 #612.2
        movdqa    %xmm9, %xmm8                                  #612.2
        paddd     %xmm6, %xmm7                                  #613.2
        movdqa    %xmm9, %xmm6                                  #613.2
        pslld     $5, %xmm13                                    #612.2
        psrld     $27, %xmm8                                    #612.2
        pslld     $30, %xmm6                                    #613.2
        psrld     $2, %xmm9                                     #613.2
        por       %xmm8, %xmm13                                 #612.2
        por       %xmm9, %xmm6                                  #613.2
        movdqa    %xmm10, %xmm9                                 #613.2
        paddd     %xmm13, %xmm0                                 #612.2
        pslld     $30, %xmm9                                    #613.2
        psrld     $2, %xmm10                                    #613.2
        paddd     %xmm4, %xmm0                                  #612.2
        por       %xmm10, %xmm9                                 #613.2
        movdqa    %xmm6, %xmm10                                 #614.2
        paddd     %xmm4, %xmm7                                  #613.2
        paddd     160(%rdi), %xmm0                              #612.2
        pxor      %xmm2, %xmm10                                 #614.2
        pand      %xmm0, %xmm10                                 #614.2
        movdqa    %xmm9, %xmm14                                 #614.2
        paddd     1456(%rdi), %xmm7                             #613.2
        movdqa    %xmm0, %xmm13                                 #613.2
        movdqa    %xmm0, %xmm8                                  #613.2
        pxor      %xmm2, %xmm10                                 #614.2
        pxor      %xmm3, %xmm14                                 #614.2
        pslld     $5, %xmm13                                    #613.2
        psrld     $27, %xmm8                                    #613.2
        paddd     %xmm10, %xmm11                                #614.2
        pand      %xmm1, %xmm14                                 #614.2
        movdqa    %xmm7, %xmm10                                 #614.2
        movdqa    %xmm7, %xmm15                                 #614.2
        por       %xmm8, %xmm13                                 #613.2
        pxor      %xmm3, %xmm14                                 #614.2
        pslld     $5, %xmm10                                    #614.2
        psrld     $27, %xmm15                                   #614.2
        paddd     %xmm13, %xmm5                                 #613.2
        paddd     %xmm14, %xmm12                                #614.2
        por       %xmm15, %xmm10                                #614.2
        paddd     %xmm4, %xmm5                                  #613.2
        paddd     %xmm10, %xmm12                                #614.2
        movdqa    %xmm0, %xmm10                                 #614.2
        psrld     $2, %xmm0                                     #614.2
        paddd     176(%rdi), %xmm5                              #613.2
        pslld     $30, %xmm10                                   #614.2
        movdqa    %xmm5, %xmm13                                 #614.2
        movdqa    %xmm5, %xmm8                                  #614.2
        por       %xmm0, %xmm10                                 #614.2
        movdqa    %xmm1, %xmm0                                  #614.2
        pslld     $5, %xmm13                                    #614.2
        psrld     $27, %xmm8                                    #614.2
        pslld     $30, %xmm0                                    #614.2
        psrld     $2, %xmm1                                     #614.2
        por       %xmm8, %xmm13                                 #614.2
        por       %xmm1, %xmm0                                  #614.2
        movdqa    %xmm10, %xmm1                                 #615.2
        paddd     %xmm13, %xmm11                                #614.2
        pxor      %xmm6, %xmm1                                  #615.2
        paddd     %xmm4, %xmm11                                 #614.2
        paddd     %xmm4, %xmm12                                 #614.2
        pand      %xmm5, %xmm1                                  #615.2
        movdqa    %xmm0, %xmm14                                 #615.2
        pxor      %xmm6, %xmm1                                  #615.2
        paddd     192(%rdi), %xmm11                             #614.2
        pxor      %xmm9, %xmm14                                 #615.2
        paddd     1472(%rdi), %xmm12                            #614.2
        paddd     %xmm1, %xmm2                                  #615.2
        movdqa    %xmm11, %xmm13                                #615.2
        movdqa    %xmm11, %xmm8                                 #615.2
        pand      %xmm7, %xmm14                                 #615.2
        movdqa    %xmm12, %xmm1                                 #615.2
        movdqa    %xmm12, %xmm15                                #615.2
        pslld     $5, %xmm13                                    #615.2
        psrld     $27, %xmm8                                    #615.2
        pxor      %xmm9, %xmm14                                 #615.2
        pslld     $5, %xmm1                                     #615.2
        psrld     $27, %xmm15                                   #615.2
        por       %xmm8, %xmm13                                 #615.2
        paddd     %xmm14, %xmm3                                 #615.2
        por       %xmm15, %xmm1                                 #615.2
        paddd     %xmm13, %xmm2                                 #615.2
        paddd     %xmm1, %xmm3                                  #615.2
        paddd     %xmm4, %xmm2                                  #615.2
        paddd     %xmm4, %xmm3                                  #615.2
        movdqa    %xmm5, %xmm1                                  #615.2
        paddd     1488(%rdi), %xmm3                             #615.2
        pslld     $30, %xmm1                                    #615.2
        paddd     208(%rdi), %xmm2                              #615.2
        psrld     $2, %xmm5                                     #615.2
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm9 xmm10 xmm11 xmm12
..B9.19:                        # Preds ..B9.5
        por       %xmm5, %xmm1                                  #615.2
        movdqa    %xmm7, %xmm5                                  #615.2
        pslld     $30, %xmm5                                    #615.2
        psrld     $2, %xmm7                                     #615.2
        movdqa    %xmm10, %xmm14                                #616.2
        por       %xmm7, %xmm5                                  #615.2
        pxor      %xmm1, %xmm14                                 #616.2
        movdqa    %xmm0, %xmm8                                  #616.2
        pand      %xmm11, %xmm14                                #616.2
        pxor      %xmm5, %xmm8                                  #616.2
        pxor      %xmm10, %xmm14                                #616.2
        pand      %xmm12, %xmm8                                 #616.2
        paddd     %xmm14, %xmm6                                 #616.2
        pxor      %xmm0, %xmm8                                  #616.2
        movdqa    %xmm3, %xmm14                                 #616.2
        movdqa    %xmm3, %xmm7                                  #616.2
        paddd     %xmm8, %xmm9                                  #616.2
        pslld     $5, %xmm14                                    #616.2
        psrld     $27, %xmm7                                    #616.2
        movdqa    %xmm11, %xmm8                                 #616.2
        movdqa    %xmm2, %xmm13                                 #616.2
        movdqa    %xmm2, %xmm15                                 #616.2
        por       %xmm7, %xmm14                                 #616.2
        pslld     $30, %xmm8                                    #616.2
        psrld     $2, %xmm11                                    #616.2
        movdqa    %xmm12, %xmm7                                 #616.2
        pslld     $5, %xmm13                                    #616.2
        psrld     $27, %xmm15                                   #616.2
        por       %xmm11, %xmm8                                 #616.2
        pslld     $30, %xmm7                                    #616.2
        psrld     $2, %xmm12                                    #616.2
        por       %xmm15, %xmm13                                #616.2
        por       %xmm12, %xmm7                                 #616.2
        movdqa    %xmm8, %xmm12                                 #617.2
        paddd     %xmm13, %xmm6                                 #616.2
        paddd     %xmm14, %xmm9                                 #616.2
        pxor      %xmm1, %xmm12                                 #617.2
        paddd     %xmm4, %xmm6                                  #616.2
        paddd     %xmm4, %xmm9                                  #616.2
        pand      %xmm2, %xmm12                                 #617.2
        movdqa    %xmm7, %xmm14                                 #617.2
        pxor      %xmm1, %xmm12                                 #617.2
        paddd     224(%rdi), %xmm6                              #616.2
        pxor      %xmm5, %xmm14                                 #617.2
        paddd     1504(%rdi), %xmm9                             #616.2
        paddd     %xmm12, %xmm10                                #617.2
        movdqa    %xmm6, %xmm12                                 #617.2
        movdqa    %xmm6, %xmm11                                 #617.2
        pand      %xmm3, %xmm14                                 #617.2
        movdqa    %xmm9, %xmm13                                 #617.2
        movdqa    %xmm9, %xmm15                                 #617.2
        pslld     $5, %xmm12                                    #617.2
        psrld     $27, %xmm11                                   #617.2
        pxor      %xmm5, %xmm14                                 #617.2
        pslld     $5, %xmm13                                    #617.2
        psrld     $27, %xmm15                                   #617.2
        por       %xmm11, %xmm12                                #617.2
        paddd     %xmm14, %xmm0                                 #617.2
        por       %xmm15, %xmm13                                #617.2
        movdqa    %xmm2, %xmm11                                 #617.2
        paddd     %xmm13, %xmm0                                 #617.2
        pslld     $30, %xmm11                                   #617.2
        psrld     $2, %xmm2                                     #617.2
        movdqa    %xmm3, %xmm13                                 #617.2
        por       %xmm2, %xmm11                                 #617.2
        pslld     $30, %xmm13                                   #617.2
        psrld     $2, %xmm3                                     #617.2
        paddd     %xmm4, %xmm0                                  #617.2
        por       %xmm3, %xmm13                                 #617.2
        movdqa    %xmm11, %xmm3                                 #618.2
        pxor      %xmm8, %xmm3                                  #618.2
        paddd     %xmm12, %xmm10                                #617.2
        paddd     1520(%rdi), %xmm0                             #617.2
        pand      %xmm6, %xmm3                                  #618.2
        pxor      %xmm8, %xmm3                                  #618.2
        movdqa    %xmm0, %xmm15                                 #618.2
        movdqa    %xmm0, %xmm14                                 #618.2
        paddd     %xmm4, %xmm10                                 #617.2
        paddd     %xmm3, %xmm1                                  #618.2
        movdqa    %xmm13, %xmm3                                 #618.2
        pslld     $5, %xmm15                                    #618.2
        psrld     $27, %xmm14                                   #618.2
        paddd     240(%rdi), %xmm10                             #617.2
        pxor      %xmm7, %xmm3                                  #618.2
        por       %xmm14, %xmm15                                #618.2
        movdqa    %xmm6, %xmm14                                 #618.2
        movdqa    %xmm10, %xmm12                                #618.2
        movdqa    %xmm10, %xmm2                                 #618.2
        pand      %xmm9, %xmm3                                  #618.2
        pslld     $30, %xmm14                                   #618.2
        psrld     $2, %xmm6                                     #618.2
        pslld     $5, %xmm12                                    #618.2
        psrld     $27, %xmm2                                    #618.2
        pxor      %xmm7, %xmm3                                  #618.2
        por       %xmm6, %xmm14                                 #618.2
        por       %xmm2, %xmm12                                 #618.2
        paddd     %xmm3, %xmm5                                  #618.2
        movdqa    %xmm14, %xmm6                                 #619.2
        paddd     %xmm12, %xmm1                                 #618.2
        paddd     %xmm15, %xmm5                                 #618.2
        movdqa    %xmm9, %xmm15                                 #618.2
        pxor      %xmm11, %xmm6                                 #619.2
        paddd     %xmm4, %xmm1                                  #618.2
        pslld     $30, %xmm15                                   #618.2
        psrld     $2, %xmm9                                     #618.2
        pand      %xmm10, %xmm6                                 #619.2
        paddd     256(%rdi), %xmm1                              #618.2
        paddd     %xmm4, %xmm5                                  #618.2
        por       %xmm9, %xmm15                                 #618.2
        pxor      %xmm11, %xmm6                                 #619.2
        paddd     1536(%rdi), %xmm5                             #618.2
        paddd     %xmm6, %xmm8                                  #619.2
        movdqa    %xmm1, %xmm6                                  #619.2
        movdqa    %xmm1, %xmm9                                  #619.2
        movdqa    %xmm15, %xmm12                                #619.2
        pslld     $5, %xmm6                                     #619.2
        psrld     $27, %xmm9                                    #619.2
        pxor      %xmm13, %xmm12                                #619.2
        movdqa    %xmm5, %xmm2                                  #619.2
        movdqa    %xmm5, %xmm3                                  #619.2
        por       %xmm9, %xmm6                                  #619.2
        pand      %xmm0, %xmm12                                 #619.2
        pslld     $5, %xmm2                                     #619.2
        psrld     $27, %xmm3                                    #619.2
        paddd     %xmm6, %xmm8                                  #619.2
        pxor      %xmm13, %xmm12                                #619.2
        por       %xmm3, %xmm2                                  #619.2
        movdqa    %xmm0, %xmm3                                  #619.2
        paddd     %xmm4, %xmm8                                  #619.2
        paddd     %xmm12, %xmm7                                 #619.2
        pslld     $30, %xmm3                                    #619.2
        psrld     $2, %xmm0                                     #619.2
        paddd     272(%rdi), %xmm8                              #619.2
        paddd     %xmm2, %xmm7                                  #619.2
        por       %xmm0, %xmm3                                  #619.2
        paddd     %xmm4, %xmm7                                  #619.2
        movdqa    %xmm10, %xmm2                                 #619.2
        movdqa    %xmm8, %xmm12                                 #620.2
        movdqa    %xmm8, %xmm6                                  #620.2
        movdqa    %xmm3, %xmm9                                  #620.2
        paddd     1552(%rdi), %xmm7                             #619.2
        pslld     $30, %xmm2                                    #619.2
        psrld     $2, %xmm10                                    #619.2
        pslld     $5, %xmm12                                    #620.2
        psrld     $27, %xmm6                                    #620.2
        pxor      %xmm15, %xmm9                                 #620.2
        por       %xmm10, %xmm2                                 #619.2
        por       %xmm6, %xmm12                                 #620.2
        pand      %xmm5, %xmm9                                  #620.2
        movdqa    %xmm7, %xmm6                                  #620.2
        movdqa    %xmm7, %xmm10                                 #620.2
        pxor      %xmm15, %xmm9                                 #620.2
        pslld     $5, %xmm6                                     #620.2
        psrld     $27, %xmm10                                   #620.2
        movdqa    %xmm2, %xmm0                                  #620.2
        paddd     %xmm9, %xmm13                                 #620.2
        por       %xmm10, %xmm6                                 #620.2
        pxor      %xmm14, %xmm0                                 #620.2
        paddd     %xmm6, %xmm13                                 #620.2
        movdqa    %xmm1, %xmm6                                  #620.2
        pand      %xmm1, %xmm0                                  #620.2
        pslld     $30, %xmm6                                    #620.2
        psrld     $2, %xmm1                                     #620.2
        movdqa    %xmm5, %xmm9                                  #620.2
        pxor      %xmm14, %xmm0                                 #620.2
        por       %xmm1, %xmm6                                  #620.2
        pslld     $30, %xmm9                                    #620.2
        psrld     $2, %xmm5                                     #620.2
        paddd     %xmm0, %xmm11                                 #620.2
        por       %xmm5, %xmm9                                  #620.2
        movdqa    %xmm6, %xmm5                                  #621.2
        paddd     %xmm12, %xmm11                                #620.2
        pxor      %xmm2, %xmm5                                  #621.2
        paddd     %xmm4, %xmm11                                 #620.2
        paddd     %xmm4, %xmm13                                 #620.2
        pand      %xmm8, %xmm5                                  #621.2
        movdqa    %xmm9, %xmm12                                 #621.2
        pxor      %xmm2, %xmm5                                  #621.2
        paddd     1568(%rdi), %xmm13                            #620.2
        pxor      %xmm3, %xmm12                                 #621.2
        paddd     288(%rdi), %xmm11                             #620.2
        paddd     %xmm5, %xmm14                                 #621.2
        movdqa    %xmm11, %xmm0                                 #621.2
        movdqa    %xmm11, %xmm1                                 #621.2
        pand      %xmm7, %xmm12                                 #621.2
        movdqa    %xmm13, %xmm10                                #621.2
        movdqa    %xmm13, %xmm5                                 #621.2
        pslld     $5, %xmm0                                     #621.2
        psrld     $27, %xmm1                                    #621.2
        pxor      %xmm3, %xmm12                                 #621.2
        pslld     $5, %xmm10                                    #621.2
        psrld     $27, %xmm5                                    #621.2
        por       %xmm1, %xmm0                                  #621.2
        paddd     %xmm12, %xmm15                                #621.2
        por       %xmm5, %xmm10                                 #621.2
        movdqa    %xmm8, %xmm12                                 #621.2
        paddd     %xmm0, %xmm14                                 #621.2
        paddd     %xmm10, %xmm15                                #621.2
        pslld     $30, %xmm12                                   #621.2
        psrld     $2, %xmm8                                     #621.2
        paddd     %xmm4, %xmm14                                 #621.2
        paddd     %xmm4, %xmm15                                 #621.2
        por       %xmm8, %xmm12                                 #621.2
        movdqa    %xmm7, %xmm4                                  #621.2
        paddd     304(%rdi), %xmm14                             #621.2
        pslld     $30, %xmm4                                    #621.2
        psrld     $2, %xmm7                                     #621.2
        movdqa    %xmm12, %xmm8                                 #624.2
        por       %xmm7, %xmm4                                  #621.2
        pxor      %xmm6, %xmm8                                  #624.2
        movdqa    %xmm14, %xmm5                                 #624.2
        movdqa    %xmm14, %xmm7                                 #624.2
        pxor      %xmm11, %xmm8                                 #624.2
        pslld     $5, %xmm5                                     #624.2
        psrld     $27, %xmm7                                    #624.2
        paddd     %xmm8, %xmm2                                  #624.2
        por       %xmm7, %xmm5                                  #624.2
        movdqa    %xmm4, %xmm8                                  #624.2
        paddd     1584(%rdi), %xmm15                            #621.2
        paddd     %xmm5, %xmm2                                  #624.2
        movdqa    %xmm11, %xmm5                                 #624.2
        pxor      %xmm9, %xmm8                                  #624.2
        movdqa    .L_2il0floatpacket.504(%rip), %xmm0           #623.8
        movdqa    %xmm15, %xmm10                                #624.2
        movdqa    %xmm15, %xmm1                                 #624.2
        pslld     $30, %xmm5                                    #624.2
        psrld     $2, %xmm11                                    #624.2
        paddd     %xmm0, %xmm2                                  #624.2
        pxor      %xmm13, %xmm8                                 #624.2
        pslld     $5, %xmm10                                    #624.2
        psrld     $27, %xmm1                                    #624.2
        por       %xmm11, %xmm5                                 #624.2
        movdqa    %xmm13, %xmm7                                 #624.2
        paddd     %xmm8, %xmm3                                  #624.2
        paddd     320(%rdi), %xmm2                              #624.2
        por       %xmm1, %xmm10                                 #624.2
        pslld     $30, %xmm7                                    #624.2
        psrld     $2, %xmm13                                    #624.2
        movdqa    %xmm5, %xmm11                                 #625.2
        paddd     %xmm10, %xmm3                                 #624.2
        por       %xmm13, %xmm7                                 #624.2
        pxor      %xmm12, %xmm11                                #625.2
        movdqa    %xmm2, %xmm8                                  #625.2
        movdqa    %xmm2, %xmm13                                 #625.2
        paddd     %xmm0, %xmm3                                  #624.2
        pxor      %xmm14, %xmm11                                #625.2
        pslld     $5, %xmm8                                     #625.2
        psrld     $27, %xmm13                                   #625.2
        paddd     1600(%rdi), %xmm3                             #624.2
        paddd     %xmm11, %xmm6                                 #625.2
        por       %xmm13, %xmm8                                 #625.2
        movdqa    %xmm3, %xmm11                                 #625.2
        paddd     %xmm8, %xmm6                                  #625.2
        movdqa    %xmm3, %xmm10                                 #625.2
        movdqa    %xmm14, %xmm8                                 #625.2
        movdqa    %xmm7, %xmm1                                  #625.2
        pslld     $5, %xmm11                                    #625.2
        psrld     $27, %xmm10                                   #625.2
        pslld     $30, %xmm8                                    #625.2
        psrld     $2, %xmm14                                    #625.2
        paddd     %xmm0, %xmm6                                  #625.2
        pxor      %xmm4, %xmm1                                  #625.2
        por       %xmm10, %xmm11                                #625.2
        por       %xmm14, %xmm8                                 #625.2
        movdqa    %xmm15, %xmm10                                #625.2
        pxor      %xmm15, %xmm1                                 #625.2
        paddd     336(%rdi), %xmm6                              #625.2
        pslld     $30, %xmm10                                   #625.2
        psrld     $2, %xmm15                                    #625.2
        movdqa    %xmm8, %xmm14                                 #626.2
        paddd     %xmm1, %xmm9                                  #625.2
        por       %xmm15, %xmm10                                #625.2
        pxor      %xmm5, %xmm14                                 #626.2
        movdqa    %xmm6, %xmm1                                  #626.2
        movdqa    %xmm6, %xmm15                                 #626.2
        paddd     %xmm11, %xmm9                                 #625.2
        pxor      %xmm2, %xmm14                                 #626.2
        pslld     $5, %xmm1                                     #626.2
        psrld     $27, %xmm15                                   #626.2
        paddd     %xmm0, %xmm9                                  #625.2
        paddd     %xmm14, %xmm12                                #626.2
        por       %xmm15, %xmm1                                 #626.2
        paddd     1616(%rdi), %xmm9                             #625.2
        paddd     %xmm1, %xmm12                                 #626.2
        movdqa    %xmm10, %xmm11                                #626.2
        movdqa    %xmm2, %xmm1                                  #626.2
        pxor      %xmm7, %xmm11                                 #626.2
        movdqa    %xmm9, %xmm14                                 #626.2
        movdqa    %xmm9, %xmm13                                 #626.2
        pslld     $30, %xmm1                                    #626.2
        psrld     $2, %xmm2                                     #626.2
        pxor      %xmm3, %xmm11                                 #626.2
        pslld     $5, %xmm14                                    #626.2
        psrld     $27, %xmm13                                   #626.2
        por       %xmm2, %xmm1                                  #626.2
        movdqa    %xmm3, %xmm2                                  #626.2
        paddd     %xmm11, %xmm4                                 #626.2
        por       %xmm13, %xmm14                                #626.2
        pslld     $30, %xmm2                                    #626.2
        psrld     $2, %xmm3                                     #626.2
        paddd     %xmm14, %xmm4                                 #626.2
        por       %xmm3, %xmm2                                  #626.2
        movdqa    %xmm1, %xmm3                                  #627.2
        paddd     %xmm0, %xmm4                                  #626.2
        pxor      %xmm8, %xmm3                                  #627.2
        movdqa    %xmm2, %xmm14                                 #627.2
        paddd     1632(%rdi), %xmm4                             #626.2
        pxor      %xmm6, %xmm3                                  #627.2
        paddd     %xmm3, %xmm5                                  #627.2
        pxor      %xmm10, %xmm14                                #627.2
        movdqa    %xmm4, %xmm3                                  #627.2
        movdqa    %xmm4, %xmm15                                 #627.2
        pxor      %xmm9, %xmm14                                 #627.2
        pslld     $5, %xmm3                                     #627.2
        psrld     $27, %xmm15                                   #627.2
        paddd     %xmm14, %xmm7                                 #627.2
        por       %xmm15, %xmm3                                 #627.2
        paddd     %xmm0, %xmm12                                 #626.2
        paddd     %xmm3, %xmm7                                  #627.2
        movdqa    %xmm6, %xmm3                                  #627.2
        pslld     $30, %xmm3                                    #627.2
        psrld     $2, %xmm6                                     #627.2
        por       %xmm6, %xmm3                                  #627.2
        movdqa    %xmm9, %xmm6                                  #627.2
        pslld     $30, %xmm6                                    #627.2
        psrld     $2, %xmm9                                     #627.2
        por       %xmm9, %xmm6                                  #627.2
        movdqa    %xmm3, %xmm9                                  #628.2
        paddd     352(%rdi), %xmm12                             #626.2
        paddd     %xmm0, %xmm7                                  #627.2
        pxor      %xmm1, %xmm9                                  #628.2
        movdqa    %xmm6, %xmm14                                 #628.2
        paddd     1648(%rdi), %xmm7                             #627.2
        pxor      %xmm12, %xmm9                                 #628.2
        paddd     %xmm9, %xmm8                                  #628.2
        pxor      %xmm2, %xmm14                                 #628.2
        movdqa    %xmm7, %xmm9                                  #628.2
        movdqa    %xmm7, %xmm15                                 #628.2
        pxor      %xmm4, %xmm14                                 #628.2
        pslld     $5, %xmm9                                     #628.2
        psrld     $27, %xmm15                                   #628.2
        paddd     %xmm14, %xmm10                                #628.2
        por       %xmm15, %xmm9                                 #628.2
        movdqa    %xmm12, %xmm13                                #627.2
        movdqa    %xmm12, %xmm11                                #627.2
        paddd     %xmm9, %xmm10                                 #628.2
        movdqa    %xmm12, %xmm9                                 #628.2
        pslld     $5, %xmm13                                    #627.2
        psrld     $27, %xmm11                                   #627.2
        pslld     $30, %xmm9                                    #628.2
        psrld     $2, %xmm12                                    #628.2
        por       %xmm11, %xmm13                                #627.2
        por       %xmm12, %xmm9                                 #628.2
        movdqa    %xmm4, %xmm12                                 #628.2
        paddd     %xmm13, %xmm5                                 #627.2
        pslld     $30, %xmm12                                   #628.2
        psrld     $2, %xmm4                                     #628.2
        paddd     %xmm0, %xmm5                                  #627.2
        por       %xmm4, %xmm12                                 #628.2
        movdqa    %xmm9, %xmm4                                  #629.2
        paddd     368(%rdi), %xmm5                              #627.2
        paddd     %xmm0, %xmm10                                 #628.2
        pxor      %xmm3, %xmm4                                  #629.2
        movdqa    %xmm12, %xmm14                                #629.2
        paddd     1664(%rdi), %xmm10                            #628.2
        pxor      %xmm5, %xmm4                                  #629.2
        paddd     %xmm4, %xmm1                                  #629.2
        pxor      %xmm6, %xmm14                                 #629.2
        movdqa    %xmm10, %xmm4                                 #629.2
        movdqa    %xmm10, %xmm15                                #629.2
        pxor      %xmm7, %xmm14                                 #629.2
        pslld     $5, %xmm4                                     #629.2
        psrld     $27, %xmm15                                   #629.2
        paddd     %xmm14, %xmm2                                 #629.2
        por       %xmm15, %xmm4                                 #629.2
        movdqa    %xmm5, %xmm13                                 #628.2
        movdqa    %xmm5, %xmm11                                 #628.2
        paddd     %xmm4, %xmm2                                  #629.2
        movdqa    %xmm5, %xmm4                                  #629.2
        pslld     $5, %xmm13                                    #628.2
        psrld     $27, %xmm11                                   #628.2
        pslld     $30, %xmm4                                    #629.2
        psrld     $2, %xmm5                                     #629.2
        por       %xmm11, %xmm13                                #628.2
        por       %xmm5, %xmm4                                  #629.2
        movdqa    %xmm7, %xmm5                                  #629.2
        paddd     %xmm13, %xmm8                                 #628.2
        pslld     $30, %xmm5                                    #629.2
        psrld     $2, %xmm7                                     #629.2
        paddd     %xmm0, %xmm8                                  #628.2
        por       %xmm7, %xmm5                                  #629.2
        movdqa    %xmm4, %xmm7                                  #630.2
        paddd     384(%rdi), %xmm8                              #628.2
        paddd     %xmm0, %xmm2                                  #629.2
        pxor      %xmm9, %xmm7                                  #630.2
        movdqa    %xmm5, %xmm14                                 #630.2
        paddd     1680(%rdi), %xmm2                             #629.2
        pxor      %xmm8, %xmm7                                  #630.2
        paddd     %xmm7, %xmm3                                  #630.2
        pxor      %xmm12, %xmm14                                #630.2
        movdqa    %xmm2, %xmm7                                  #630.2
        movdqa    %xmm2, %xmm15                                 #630.2
        movdqa    %xmm8, %xmm13                                 #629.2
        movdqa    %xmm8, %xmm11                                 #629.2
        pxor      %xmm10, %xmm14                                #630.2
        pslld     $5, %xmm7                                     #630.2
        psrld     $27, %xmm15                                   #630.2
        pslld     $5, %xmm13                                    #629.2
        psrld     $27, %xmm11                                   #629.2
        paddd     %xmm14, %xmm6                                 #630.2
        por       %xmm15, %xmm7                                 #630.2
        por       %xmm11, %xmm13                                #629.2
        paddd     %xmm7, %xmm6                                  #630.2
        movdqa    %xmm8, %xmm7                                  #630.2
        paddd     %xmm13, %xmm1                                 #629.2
        pslld     $30, %xmm7                                    #630.2
        psrld     $2, %xmm8                                     #630.2
        paddd     %xmm0, %xmm1                                  #629.2
        por       %xmm8, %xmm7                                  #630.2
        movdqa    %xmm10, %xmm8                                 #630.2
        paddd     400(%rdi), %xmm1                              #629.2
        pslld     $30, %xmm8                                    #630.2
        psrld     $2, %xmm10                                    #630.2
        movdqa    %xmm1, %xmm13                                 #630.2
        movdqa    %xmm1, %xmm11                                 #630.2
        por       %xmm10, %xmm8                                 #630.2
        movdqa    %xmm7, %xmm10                                 #631.2
        pslld     $5, %xmm13                                    #630.2
        psrld     $27, %xmm11                                   #630.2
        paddd     %xmm0, %xmm6                                  #630.2
        pxor      %xmm4, %xmm10                                 #631.2
        por       %xmm11, %xmm13                                #630.2
        paddd     1696(%rdi), %xmm6                             #630.2
        pxor      %xmm1, %xmm10                                 #631.2
        movdqa    %xmm8, %xmm14                                 #631.2
        paddd     %xmm13, %xmm3                                 #630.2
        paddd     %xmm10, %xmm9                                 #631.2
        pxor      %xmm5, %xmm14                                 #631.2
        movdqa    %xmm6, %xmm10                                 #631.2
        movdqa    %xmm6, %xmm15                                 #631.2
        paddd     %xmm0, %xmm3                                  #630.2
        pxor      %xmm2, %xmm14                                 #631.2
        pslld     $5, %xmm10                                    #631.2
        psrld     $27, %xmm15                                   #631.2
        paddd     416(%rdi), %xmm3                              #630.2
        paddd     %xmm14, %xmm12                                #631.2
        por       %xmm15, %xmm10                                #631.2
        movdqa    %xmm3, %xmm13                                 #631.2
        movdqa    %xmm3, %xmm11                                 #631.2
        paddd     %xmm10, %xmm12                                #631.2
        movdqa    %xmm1, %xmm10                                 #631.2
        pslld     $5, %xmm13                                    #631.2
        psrld     $27, %xmm11                                   #631.2
        pslld     $30, %xmm10                                   #631.2
        psrld     $2, %xmm1                                     #631.2
        por       %xmm11, %xmm13                                #631.2
        por       %xmm1, %xmm10                                 #631.2
        movdqa    %xmm2, %xmm1                                  #631.2
        paddd     %xmm13, %xmm9                                 #631.2
        pslld     $30, %xmm1                                    #631.2
        psrld     $2, %xmm2                                     #631.2
        paddd     %xmm0, %xmm9                                  #631.2
        por       %xmm2, %xmm1                                  #631.2
        movdqa    %xmm10, %xmm2                                 #632.2
        paddd     432(%rdi), %xmm9                              #631.2
        paddd     %xmm0, %xmm12                                 #631.2
        pxor      %xmm7, %xmm2                                  #632.2
        movdqa    %xmm9, %xmm13                                 #632.2
        paddd     1712(%rdi), %xmm12                            #631.2
        pxor      %xmm3, %xmm2                                  #632.2
        movdqa    %xmm9, %xmm11                                 #632.2
        movdqa    %xmm1, %xmm14                                 #632.2
        paddd     %xmm2, %xmm4                                  #632.2
        pslld     $5, %xmm13                                    #632.2
        psrld     $27, %xmm11                                   #632.2
        pxor      %xmm8, %xmm14                                 #632.2
        movdqa    %xmm12, %xmm2                                 #632.2
        movdqa    %xmm12, %xmm15                                #632.2
        por       %xmm11, %xmm13                                #632.2
        pxor      %xmm6, %xmm14                                 #632.2
        pslld     $5, %xmm2                                     #632.2
        psrld     $27, %xmm15                                   #632.2
        paddd     %xmm13, %xmm4                                 #632.2
        paddd     %xmm14, %xmm5                                 #632.2
        por       %xmm15, %xmm2                                 #632.2
        paddd     %xmm0, %xmm4                                  #632.2
        paddd     %xmm2, %xmm5                                  #632.2
        movdqa    1728(%rdi), %xmm2                             #561.6
        paddd     %xmm0, %xmm5                                  #632.2
        paddd     448(%rdi), %xmm4                              #632.2
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm12
..B9.18:                        # Preds ..B9.19
        paddd     %xmm2, %xmm5                                  #632.2
        movdqa    %xmm3, %xmm2                                  #632.2
        pslld     $30, %xmm2                                    #632.2
        psrld     $2, %xmm3                                     #632.2
        por       %xmm3, %xmm2                                  #632.2
        movdqa    %xmm10, %xmm13                                #633.2
        pxor      %xmm2, %xmm13                                 #633.2
        movdqa    %xmm6, %xmm11                                 #632.2
        pxor      %xmm9, %xmm13                                 #633.2
        pslld     $30, %xmm11                                   #632.2
        psrld     $2, %xmm6                                     #632.2
        paddd     %xmm13, %xmm7                                 #633.2
        movdqa    %xmm4, %xmm13                                 #633.2
        movdqa    %xmm4, %xmm14                                 #633.2
        por       %xmm6, %xmm11                                 #632.2
        pslld     $5, %xmm13                                    #633.2
        psrld     $27, %xmm14                                   #633.2
        movdqa    %xmm1, %xmm3                                  #633.2
        por       %xmm14, %xmm13                                #633.2
        pxor      %xmm11, %xmm3                                 #633.2
        movdqa    %xmm5, %xmm15                                 #633.2
        movdqa    %xmm5, %xmm6                                  #633.2
        paddd     %xmm13, %xmm7                                 #633.2
        pxor      %xmm12, %xmm3                                 #633.2
        pslld     $5, %xmm15                                    #633.2
        psrld     $27, %xmm6                                    #633.2
        paddd     %xmm0, %xmm7                                  #633.2
        paddd     %xmm3, %xmm8                                  #633.2
        por       %xmm6, %xmm15                                 #633.2
        movdqa    %xmm9, %xmm3                                  #633.2
        movdqa    %xmm12, %xmm6                                 #633.2
        paddd     %xmm15, %xmm8                                 #633.2
        paddd     464(%rdi), %xmm7                              #633.2
        pslld     $30, %xmm3                                    #633.2
        psrld     $2, %xmm9                                     #633.2
        pslld     $30, %xmm6                                    #633.2
        psrld     $2, %xmm12                                    #633.2
        paddd     %xmm0, %xmm8                                  #633.2
        por       %xmm9, %xmm3                                  #633.2
        por       %xmm12, %xmm6                                 #633.2
        movdqa    %xmm7, %xmm9                                  #634.2
        movdqa    %xmm7, %xmm13                                 #634.2
        paddd     1744(%rdi), %xmm8                             #633.2
        pslld     $5, %xmm9                                     #634.2
        psrld     $27, %xmm13                                   #634.2
        movdqa    %xmm6, %xmm14                                 #634.2
        por       %xmm13, %xmm9                                 #634.2
        pxor      %xmm11, %xmm14                                #634.2
        movdqa    %xmm8, %xmm13                                 #634.2
        movdqa    %xmm8, %xmm15                                 #634.2
        movdqa    %xmm3, %xmm12                                 #634.2
        pxor      %xmm5, %xmm14                                 #634.2
        pslld     $5, %xmm13                                    #634.2
        psrld     $27, %xmm15                                   #634.2
        pxor      %xmm2, %xmm12                                 #634.2
        paddd     %xmm14, %xmm1                                 #634.2
        por       %xmm15, %xmm13                                #634.2
        pxor      %xmm4, %xmm12                                 #634.2
        paddd     %xmm13, %xmm1                                 #634.2
        movdqa    %xmm4, %xmm13                                 #634.2
        paddd     %xmm12, %xmm10                                #634.2
        pslld     $30, %xmm13                                   #634.2
        psrld     $2, %xmm4                                     #634.2
        movdqa    %xmm5, %xmm12                                 #634.2
        por       %xmm4, %xmm13                                 #634.2
        pslld     $30, %xmm12                                   #634.2
        psrld     $2, %xmm5                                     #634.2
        paddd     %xmm9, %xmm10                                 #634.2
        paddd     %xmm0, %xmm1                                  #634.2
        por       %xmm5, %xmm12                                 #634.2
        movdqa    %xmm13, %xmm5                                 #635.2
        paddd     %xmm0, %xmm10                                 #634.2
        paddd     1760(%rdi), %xmm1                             #634.2
        pxor      %xmm3, %xmm5                                  #635.2
        paddd     480(%rdi), %xmm10                             #634.2
        pxor      %xmm7, %xmm5                                  #635.2
        movdqa    %xmm12, %xmm9                                 #635.2
        movdqa    %xmm1, %xmm15                                 #635.2
        movdqa    %xmm1, %xmm14                                 #635.2
        paddd     %xmm5, %xmm2                                  #635.2
        movdqa    %xmm10, %xmm5                                 #635.2
        movdqa    %xmm10, %xmm4                                 #635.2
        pxor      %xmm6, %xmm9                                  #635.2
        pslld     $5, %xmm15                                    #635.2
        psrld     $27, %xmm14                                   #635.2
        pslld     $5, %xmm5                                     #635.2
        psrld     $27, %xmm4                                    #635.2
        pxor      %xmm8, %xmm9                                  #635.2
        por       %xmm14, %xmm15                                #635.2
        movdqa    %xmm7, %xmm14                                 #635.2
        por       %xmm4, %xmm5                                  #635.2
        paddd     %xmm9, %xmm11                                 #635.2
        pslld     $30, %xmm14                                   #635.2
        psrld     $2, %xmm7                                     #635.2
        paddd     %xmm5, %xmm2                                  #635.2
        paddd     %xmm15, %xmm11                                #635.2
        por       %xmm7, %xmm14                                 #635.2
        paddd     %xmm0, %xmm2                                  #635.2
        paddd     %xmm0, %xmm11                                 #635.2
        movdqa    %xmm8, %xmm15                                 #635.2
        movdqa    %xmm14, %xmm7                                 #636.2
        pslld     $30, %xmm15                                   #635.2
        paddd     496(%rdi), %xmm2                              #635.2
        psrld     $2, %xmm8                                     #635.2
        paddd     1776(%rdi), %xmm11                            #635.2
        pxor      %xmm13, %xmm7                                 #636.2
        por       %xmm8, %xmm15                                 #635.2
        pxor      %xmm10, %xmm7                                 #636.2
        movdqa    %xmm2, %xmm5                                  #636.2
        movdqa    %xmm2, %xmm8                                  #636.2
        movdqa    %xmm11, %xmm4                                 #636.2
        movdqa    %xmm11, %xmm9                                 #636.2
        paddd     %xmm7, %xmm3                                  #636.2
        pslld     $5, %xmm5                                     #636.2
        psrld     $27, %xmm8                                    #636.2
        movdqa    %xmm15, %xmm7                                 #636.2
        pslld     $5, %xmm4                                     #636.2
        psrld     $27, %xmm9                                    #636.2
        por       %xmm8, %xmm5                                  #636.2
        pxor      %xmm12, %xmm7                                 #636.2
        por       %xmm9, %xmm4                                  #636.2
        movdqa    %xmm10, %xmm9                                 #636.2
        paddd     %xmm5, %xmm3                                  #636.2
        pxor      %xmm1, %xmm7                                  #636.2
        pslld     $30, %xmm9                                    #636.2
        psrld     $2, %xmm10                                    #636.2
        paddd     %xmm0, %xmm3                                  #636.2
        paddd     %xmm7, %xmm6                                  #636.2
        por       %xmm10, %xmm9                                 #636.2
        movdqa    %xmm1, %xmm7                                  #636.2
        paddd     512(%rdi), %xmm3                              #636.2
        pslld     $30, %xmm7                                    #636.2
        psrld     $2, %xmm1                                     #636.2
        movdqa    %xmm9, %xmm10                                 #637.2
        por       %xmm1, %xmm7                                  #636.2
        pxor      %xmm14, %xmm10                                #637.2
        movdqa    %xmm3, %xmm5                                  #637.2
        movdqa    %xmm3, %xmm1                                  #637.2
        paddd     %xmm4, %xmm6                                  #636.2
        pxor      %xmm2, %xmm10                                 #637.2
        pslld     $5, %xmm5                                     #637.2
        psrld     $27, %xmm1                                    #637.2
        paddd     %xmm0, %xmm6                                  #636.2
        paddd     %xmm10, %xmm13                                #637.2
        por       %xmm1, %xmm5                                  #637.2
        movdqa    %xmm7, %xmm10                                 #637.2
        paddd     1792(%rdi), %xmm6                             #636.2
        paddd     %xmm5, %xmm13                                 #637.2
        movdqa    %xmm2, %xmm5                                  #637.2
        pxor      %xmm15, %xmm10                                #637.2
        movdqa    %xmm6, %xmm4                                  #637.2
        movdqa    %xmm6, %xmm8                                  #637.2
        pslld     $30, %xmm5                                    #637.2
        psrld     $2, %xmm2                                     #637.2
        pxor      %xmm11, %xmm10                                #637.2
        pslld     $5, %xmm4                                     #637.2
        psrld     $27, %xmm8                                    #637.2
        por       %xmm2, %xmm5                                  #637.2
        movdqa    %xmm11, %xmm2                                 #637.2
        paddd     %xmm0, %xmm13                                 #637.2
        paddd     %xmm10, %xmm12                                #637.2
        por       %xmm8, %xmm4                                  #637.2
        pslld     $30, %xmm2                                    #637.2
        psrld     $2, %xmm11                                    #637.2
        paddd     528(%rdi), %xmm13                             #637.2
        paddd     %xmm4, %xmm12                                 #637.2
        por       %xmm11, %xmm2                                 #637.2
        movdqa    %xmm5, %xmm11                                 #638.2
        paddd     %xmm0, %xmm12                                 #637.2
        pxor      %xmm9, %xmm11                                 #638.2
        movdqa    %xmm13, %xmm1                                 #638.2
        movdqa    %xmm13, %xmm10                                #638.2
        paddd     1808(%rdi), %xmm12                            #637.2
        pxor      %xmm3, %xmm11                                 #638.2
        pslld     $5, %xmm1                                     #638.2
        psrld     $27, %xmm10                                   #638.2
        movdqa    %xmm2, %xmm8                                  #638.2
        paddd     %xmm11, %xmm14                                #638.2
        por       %xmm10, %xmm1                                 #638.2
        pxor      %xmm7, %xmm8                                  #638.2
        movdqa    %xmm12, %xmm11                                #638.2
        movdqa    %xmm12, %xmm4                                 #638.2
        movdqa    %xmm3, %xmm10                                 #638.2
        pxor      %xmm6, %xmm8                                  #638.2
        pslld     $5, %xmm11                                    #638.2
        psrld     $27, %xmm4                                    #638.2
        pslld     $30, %xmm10                                   #638.2
        psrld     $2, %xmm3                                     #638.2
        paddd     %xmm8, %xmm15                                 #638.2
        por       %xmm4, %xmm11                                 #638.2
        por       %xmm3, %xmm10                                 #638.2
        paddd     %xmm1, %xmm14                                 #638.2
        paddd     %xmm11, %xmm15                                #638.2
        movdqa    %xmm6, %xmm11                                 #638.2
        movdqa    %xmm10, %xmm3                                 #639.2
        paddd     %xmm0, %xmm14                                 #638.2
        pslld     $30, %xmm11                                   #638.2
        psrld     $2, %xmm6                                     #638.2
        pxor      %xmm5, %xmm3                                  #639.2
        paddd     %xmm0, %xmm15                                 #638.2
        paddd     544(%rdi), %xmm14                             #638.2
        por       %xmm6, %xmm11                                 #638.2
        pxor      %xmm13, %xmm3                                 #639.2
        movdqa    %xmm14, %xmm6                                 #639.2
        paddd     1824(%rdi), %xmm15                            #638.2
        paddd     %xmm3, %xmm9                                  #639.2
        movdqa    %xmm14, %xmm3                                 #639.2
        movdqa    %xmm11, %xmm1                                 #639.2
        pslld     $5, %xmm3                                     #639.2
        psrld     $27, %xmm6                                    #639.2
        pxor      %xmm2, %xmm1                                  #639.2
        movdqa    %xmm15, %xmm4                                 #639.2
        movdqa    %xmm15, %xmm8                                 #639.2
        por       %xmm6, %xmm3                                  #639.2
        pxor      %xmm12, %xmm1                                 #639.2
        pslld     $5, %xmm4                                     #639.2
        psrld     $27, %xmm8                                    #639.2
        paddd     %xmm3, %xmm9                                  #639.2
        paddd     %xmm1, %xmm7                                  #639.2
        por       %xmm8, %xmm4                                  #639.2
        movdqa    %xmm12, %xmm3                                 #639.2
        paddd     %xmm4, %xmm7                                  #639.2
        pslld     $30, %xmm3                                    #639.2
        psrld     $2, %xmm12                                    #639.2
        paddd     %xmm0, %xmm7                                  #639.2
        por       %xmm12, %xmm3                                 #639.2
        paddd     1840(%rdi), %xmm7                             #639.2
        movdqa    %xmm13, %xmm1                                 #639.2
        movdqa    %xmm3, %xmm6                                  #640.2
        pslld     $30, %xmm1                                    #639.2
        psrld     $2, %xmm13                                    #639.2
        pxor      %xmm11, %xmm6                                 #640.2
        movdqa    %xmm7, %xmm4                                  #640.2
        movdqa    %xmm7, %xmm8                                  #640.2
        por       %xmm13, %xmm1                                 #639.2
        pxor      %xmm15, %xmm6                                 #640.2
        pslld     $5, %xmm4                                     #640.2
        psrld     $27, %xmm8                                    #640.2
        movdqa    %xmm1, %xmm13                                 #640.2
        paddd     %xmm6, %xmm2                                  #640.2
        por       %xmm8, %xmm4                                  #640.2
        pxor      %xmm10, %xmm13                                #640.2
        paddd     %xmm4, %xmm2                                  #640.2
        movdqa    %xmm14, %xmm4                                 #640.2
        pxor      %xmm14, %xmm13                                #640.2
        pslld     $30, %xmm4                                    #640.2
        psrld     $2, %xmm14                                    #640.2
        paddd     %xmm0, %xmm9                                  #639.2
        por       %xmm14, %xmm4                                 #640.2
        paddd     %xmm0, %xmm2                                  #640.2
        movdqa    %xmm4, %xmm14                                 #641.2
        movdqa    %xmm15, %xmm6                                 #640.2
        paddd     560(%rdi), %xmm9                              #639.2
        pxor      %xmm1, %xmm14                                 #641.2
        paddd     1856(%rdi), %xmm2                             #640.2
        pxor      %xmm9, %xmm14                                 #641.2
        paddd     %xmm13, %xmm5                                 #640.2
        movdqa    %xmm9, %xmm13                                 #640.2
        movdqa    %xmm9, %xmm12                                 #640.2
        pslld     $30, %xmm6                                    #640.2
        psrld     $2, %xmm15                                    #640.2
        paddd     %xmm14, %xmm10                                #641.2
        movdqa    %xmm2, %xmm14                                 #641.2
        movdqa    %xmm2, %xmm8                                  #641.2
        pslld     $5, %xmm13                                    #640.2
        psrld     $27, %xmm12                                   #640.2
        por       %xmm15, %xmm6                                 #640.2
        pslld     $5, %xmm14                                    #641.2
        psrld     $27, %xmm8                                    #641.2
        por       %xmm12, %xmm13                                #640.2
        movdqa    %xmm6, %xmm12                                 #641.2
        por       %xmm8, %xmm14                                 #641.2
        movdqa    %xmm9, %xmm8                                  #641.2
        pxor      %xmm3, %xmm12                                 #641.2
        pslld     $30, %xmm8                                    #641.2
        psrld     $2, %xmm9                                     #641.2
        paddd     %xmm13, %xmm5                                 #640.2
        pxor      %xmm7, %xmm12                                 #641.2
        por       %xmm9, %xmm8                                  #641.2
        movdqa    %xmm7, %xmm9                                  #641.2
        paddd     %xmm0, %xmm5                                  #640.2
        paddd     %xmm12, %xmm11                                #641.2
        pslld     $30, %xmm9                                    #641.2
        psrld     $2, %xmm7                                     #641.2
        paddd     576(%rdi), %xmm5                              #640.2
        paddd     %xmm14, %xmm11                                #641.2
        por       %xmm7, %xmm9                                  #641.2
        movdqa    %xmm8, %xmm7                                  #642.2
        movdqa    %xmm5, %xmm13                                 #641.2
        movdqa    %xmm5, %xmm15                                 #641.2
        paddd     %xmm0, %xmm11                                 #641.2
        pxor      %xmm4, %xmm7                                  #642.2
        paddd     1872(%rdi), %xmm11                            #641.2
        pslld     $5, %xmm13                                    #641.2
        psrld     $27, %xmm15                                   #641.2
        pxor      %xmm5, %xmm7                                  #642.2
        movdqa    %xmm9, %xmm14                                 #642.2
        por       %xmm15, %xmm13                                #641.2
        paddd     %xmm7, %xmm1                                  #642.2
        pxor      %xmm6, %xmm14                                 #642.2
        movdqa    %xmm11, %xmm7                                 #642.2
        movdqa    %xmm11, %xmm15                                #642.2
        paddd     %xmm13, %xmm10                                #641.2
        pxor      %xmm2, %xmm14                                 #642.2
        pslld     $5, %xmm7                                     #642.2
        psrld     $27, %xmm15                                   #642.2
        paddd     %xmm0, %xmm10                                 #641.2
        paddd     %xmm14, %xmm3                                 #642.2
        por       %xmm15, %xmm7                                 #642.2
        paddd     592(%rdi), %xmm10                             #641.2
        paddd     %xmm7, %xmm3                                  #642.2
        movdqa    %xmm5, %xmm7                                  #642.2
        movdqa    %xmm10, %xmm12                                #642.2
        movdqa    %xmm10, %xmm13                                #642.2
        pslld     $30, %xmm7                                    #642.2
        psrld     $2, %xmm5                                     #642.2
        pslld     $5, %xmm12                                    #642.2
        psrld     $27, %xmm13                                   #642.2
        por       %xmm5, %xmm7                                  #642.2
        movdqa    %xmm2, %xmm5                                  #642.2
        por       %xmm13, %xmm12                                #642.2
        pslld     $30, %xmm5                                    #642.2
        psrld     $2, %xmm2                                     #642.2
        paddd     %xmm12, %xmm1                                 #642.2
        por       %xmm2, %xmm5                                  #642.2
        movdqa    %xmm7, %xmm2                                  #643.2
        paddd     %xmm0, %xmm1                                  #642.2
        paddd     %xmm0, %xmm3                                  #642.2
        pxor      %xmm8, %xmm2                                  #643.2
        paddd     608(%rdi), %xmm1                              #642.2
        pxor      %xmm10, %xmm2                                 #643.2
        paddd     1888(%rdi), %xmm3                             #642.2
        movdqa    %xmm5, %xmm14                                 #643.2
        paddd     %xmm2, %xmm4                                  #643.2
        movdqa    %xmm1, %xmm12                                 #643.2
        movdqa    %xmm1, %xmm13                                 #643.2
        pxor      %xmm9, %xmm14                                 #643.2
        movdqa    %xmm3, %xmm2                                  #643.2
        movdqa    %xmm3, %xmm15                                 #643.2
        pslld     $5, %xmm12                                    #643.2
        psrld     $27, %xmm13                                   #643.2
        pxor      %xmm11, %xmm14                                #643.2
        pslld     $5, %xmm2                                     #643.2
        psrld     $27, %xmm15                                   #643.2
        por       %xmm13, %xmm12                                #643.2
        paddd     %xmm14, %xmm6                                 #643.2
        por       %xmm15, %xmm2                                 #643.2
        paddd     %xmm12, %xmm4                                 #643.2
        paddd     %xmm2, %xmm6                                  #643.2
        paddd     %xmm0, %xmm4                                  #643.2
        paddd     %xmm0, %xmm6                                  #643.2
        movdqa    %xmm10, %xmm2                                 #643.2
        movdqa    %xmm11, %xmm0                                 #643.2
        pslld     $30, %xmm2                                    #643.2
        psrld     $2, %xmm10                                    #643.2
        pslld     $30, %xmm0                                    #643.2
        psrld     $2, %xmm11                                    #643.2
        por       %xmm10, %xmm2                                 #643.2
        por       %xmm11, %xmm0                                 #643.2
        movdqa    %xmm1, %xmm11                                 #646.2
        movdqa    %xmm1, %xmm10                                 #646.2
        por       %xmm2, %xmm11                                 #646.2
        pand      %xmm2, %xmm10                                 #646.2
        paddd     624(%rdi), %xmm4                              #643.2
        pand      %xmm7, %xmm11                                 #646.2
        por       %xmm11, %xmm10                                #646.2
        movdqa    %xmm4, %xmm12                                 #646.2
        movdqa    %xmm4, %xmm11                                 #646.2
        pslld     $5, %xmm12                                    #646.2
        psrld     $27, %xmm11                                   #646.2
        movdqa    %xmm3, %xmm14                                 #646.2
        paddd     1904(%rdi), %xmm6                             #643.2
        paddd     %xmm10, %xmm8                                 #646.2
        por       %xmm11, %xmm12                                #646.2
        movdqa    %xmm3, %xmm15                                 #646.2
        por       %xmm0, %xmm14                                 #646.2
        paddd     %xmm12, %xmm8                                 #646.2
        pand      %xmm0, %xmm15                                 #646.2
        pand      %xmm5, %xmm14                                 #646.2
        movdqa    %xmm6, %xmm12                                 #646.2
        movdqa    %xmm6, %xmm11                                 #646.2
        por       %xmm14, %xmm15                                #646.2
        pslld     $5, %xmm12                                    #646.2
        psrld     $27, %xmm11                                   #646.2
        paddd     %xmm15, %xmm9                                 #646.2
        por       %xmm11, %xmm12                                #646.2
        movdqa    %xmm3, %xmm11                                 #646.2
        paddd     %xmm12, %xmm9                                 #646.2
        movdqa    %xmm1, %xmm12                                 #646.2
        pslld     $30, %xmm12                                   #646.2
        psrld     $2, %xmm1                                     #646.2
        pslld     $30, %xmm11                                   #646.2
        psrld     $2, %xmm3                                     #646.2
        movdqa    .L_2il0floatpacket.505(%rip), %xmm13          #645.8
        por       %xmm1, %xmm12                                 #646.2
        por       %xmm3, %xmm11                                 #646.2
        movdqa    %xmm4, %xmm3                                  #647.2
        paddd     %xmm13, %xmm8                                 #646.2
        movdqa    %xmm4, %xmm1                                  #647.2
        por       %xmm12, %xmm3                                 #647.2
        pand      %xmm12, %xmm1                                 #647.2
        paddd     640(%rdi), %xmm8                              #646.2
        pand      %xmm2, %xmm3                                  #647.2
        por       %xmm3, %xmm1                                  #647.2
        movdqa    %xmm8, %xmm10                                 #647.2
        movdqa    %xmm8, %xmm3                                  #647.2
        paddd     %xmm13, %xmm9                                 #646.2
        pslld     $5, %xmm10                                    #647.2
        psrld     $27, %xmm3                                    #647.2
        movdqa    %xmm6, %xmm14                                 #647.2
        paddd     %xmm1, %xmm7                                  #647.2
        paddd     1920(%rdi), %xmm9                             #646.2
        por       %xmm3, %xmm10                                 #647.2
        movdqa    %xmm6, %xmm15                                 #647.2
        por       %xmm11, %xmm14                                #647.2
        paddd     %xmm10, %xmm7                                 #647.2
        pand      %xmm11, %xmm15                                #647.2
        pand      %xmm0, %xmm14                                 #647.2
        movdqa    %xmm9, %xmm10                                 #647.2
        movdqa    %xmm9, %xmm3                                  #647.2
        por       %xmm14, %xmm15                                #647.2
        pslld     $5, %xmm10                                    #647.2
        psrld     $27, %xmm3                                    #647.2
        paddd     %xmm15, %xmm5                                 #647.2
        por       %xmm3, %xmm10                                 #647.2
        paddd     %xmm10, %xmm5                                 #647.2
        movdqa    %xmm4, %xmm10                                 #647.2
        movdqa    %xmm6, %xmm3                                  #647.2
        pslld     $30, %xmm10                                   #647.2
        psrld     $2, %xmm4                                     #647.2
        pslld     $30, %xmm3                                    #647.2
        psrld     $2, %xmm6                                     #647.2
        por       %xmm4, %xmm10                                 #647.2
        por       %xmm6, %xmm3                                  #647.2
        movdqa    %xmm8, %xmm6                                  #648.2
        paddd     %xmm13, %xmm7                                 #647.2
        movdqa    %xmm8, %xmm4                                  #648.2
        por       %xmm10, %xmm6                                 #648.2
        pand      %xmm10, %xmm4                                 #648.2
        paddd     656(%rdi), %xmm7                              #647.2
        pand      %xmm12, %xmm6                                 #648.2
        por       %xmm6, %xmm4                                  #648.2
        movdqa    %xmm7, %xmm6                                  #648.2
        movdqa    %xmm7, %xmm1                                  #648.2
        paddd     %xmm13, %xmm5                                 #647.2
        pslld     $5, %xmm6                                     #648.2
        psrld     $27, %xmm1                                    #648.2
        movdqa    %xmm9, %xmm14                                 #648.2
        paddd     %xmm4, %xmm2                                  #648.2
        paddd     1936(%rdi), %xmm5                             #647.2
        por       %xmm1, %xmm6                                  #648.2
        movdqa    %xmm9, %xmm15                                 #648.2
        por       %xmm3, %xmm14                                 #648.2
        paddd     %xmm6, %xmm2                                  #648.2
        pand      %xmm3, %xmm15                                 #648.2
        pand      %xmm11, %xmm14                                #648.2
        movdqa    %xmm5, %xmm6                                  #648.2
        movdqa    %xmm5, %xmm1                                  #648.2
        por       %xmm14, %xmm15                                #648.2
        pslld     $5, %xmm6                                     #648.2
        psrld     $27, %xmm1                                    #648.2
        paddd     %xmm15, %xmm0                                 #648.2
        por       %xmm1, %xmm6                                  #648.2
        paddd     %xmm6, %xmm0                                  #648.2
        movdqa    %xmm8, %xmm1                                  #648.2
        movdqa    %xmm9, %xmm6                                  #648.2
        pslld     $30, %xmm1                                    #648.2
        psrld     $2, %xmm8                                     #648.2
        pslld     $30, %xmm6                                    #648.2
        psrld     $2, %xmm9                                     #648.2
        paddd     %xmm13, %xmm2                                 #648.2
        por       %xmm8, %xmm1                                  #648.2
        por       %xmm9, %xmm6                                  #648.2
        movdqa    %xmm7, %xmm9                                  #649.2
        movdqa    %xmm7, %xmm4                                  #649.2
        paddd     672(%rdi), %xmm2                              #648.2
        por       %xmm1, %xmm9                                  #649.2
        pand      %xmm1, %xmm4                                  #649.2
        pand      %xmm10, %xmm9                                 #649.2
        movdqa    %xmm2, %xmm14                                 #649.2
        movdqa    %xmm2, %xmm8                                  #649.2
        por       %xmm9, %xmm4                                  #649.2
        pslld     $5, %xmm14                                    #649.2
        psrld     $27, %xmm8                                    #649.2
        paddd     %xmm4, %xmm12                                 #649.2
        por       %xmm8, %xmm14                                 #649.2
        movdqa    %xmm5, %xmm15                                 #649.2
        paddd     %xmm14, %xmm12                                #649.2
        movdqa    %xmm5, %xmm4                                  #649.2
        por       %xmm6, %xmm15                                 #649.2
        paddd     %xmm13, %xmm0                                 #648.2
        paddd     %xmm13, %xmm12                                #649.2
        pand      %xmm6, %xmm4                                  #649.2
        pand      %xmm3, %xmm15                                 #649.2
        paddd     688(%rdi), %xmm12                             #649.2
        por       %xmm15, %xmm4                                 #649.2
        paddd     1952(%rdi), %xmm0                             #648.2
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm10 xmm11 xmm12 xmm13
..B9.17:                        # Preds ..B9.18
        paddd     %xmm4, %xmm11                                 #649.2
        movdqa    %xmm0, %xmm8                                  #649.2
        movdqa    %xmm0, %xmm4                                  #649.2
        pslld     $5, %xmm8                                     #649.2
        psrld     $27, %xmm4                                    #649.2
        movdqa    %xmm2, %xmm9                                  #650.2
        por       %xmm4, %xmm8                                  #649.2
        movdqa    %xmm7, %xmm4                                  #649.2
        pslld     $30, %xmm4                                    #649.2
        psrld     $2, %xmm7                                     #649.2
        por       %xmm7, %xmm4                                  #649.2
        movdqa    %xmm5, %xmm7                                  #649.2
        pslld     $30, %xmm7                                    #649.2
        psrld     $2, %xmm5                                     #649.2
        movdqa    %xmm2, %xmm14                                 #650.2
        por       %xmm4, %xmm9                                  #650.2
        paddd     %xmm8, %xmm11                                 #649.2
        por       %xmm5, %xmm7                                  #649.2
        pand      %xmm4, %xmm14                                 #650.2
        pand      %xmm1, %xmm9                                  #650.2
        movdqa    %xmm12, %xmm5                                 #650.2
        movdqa    %xmm12, %xmm8                                 #650.2
        paddd     %xmm13, %xmm11                                #649.2
        por       %xmm9, %xmm14                                 #650.2
        pslld     $5, %xmm5                                     #650.2
        psrld     $27, %xmm8                                    #650.2
        movdqa    %xmm0, %xmm15                                 #650.2
        paddd     %xmm14, %xmm10                                #650.2
        paddd     1968(%rdi), %xmm11                            #649.2
        por       %xmm8, %xmm5                                  #650.2
        movdqa    %xmm0, %xmm9                                  #650.2
        por       %xmm7, %xmm15                                 #650.2
        paddd     %xmm5, %xmm10                                 #650.2
        pand      %xmm7, %xmm9                                  #650.2
        pand      %xmm6, %xmm15                                 #650.2
        movdqa    %xmm11, %xmm5                                 #650.2
        movdqa    %xmm11, %xmm8                                 #650.2
        por       %xmm15, %xmm9                                 #650.2
        pslld     $5, %xmm5                                     #650.2
        psrld     $27, %xmm8                                    #650.2
        paddd     %xmm9, %xmm3                                  #650.2
        por       %xmm8, %xmm5                                  #650.2
        paddd     %xmm5, %xmm3                                  #650.2
        movdqa    %xmm2, %xmm5                                  #650.2
        pslld     $30, %xmm5                                    #650.2
        psrld     $2, %xmm2                                     #650.2
        por       %xmm2, %xmm5                                  #650.2
        movdqa    %xmm0, %xmm2                                  #650.2
        pslld     $30, %xmm2                                    #650.2
        psrld     $2, %xmm0                                     #650.2
        por       %xmm0, %xmm2                                  #650.2
        movdqa    %xmm12, %xmm0                                 #651.2
        movdqa    %xmm12, %xmm8                                 #651.2
        por       %xmm5, %xmm0                                  #651.2
        pand      %xmm5, %xmm8                                  #651.2
        pand      %xmm4, %xmm0                                  #651.2
        movdqa    %xmm11, %xmm14                                #651.2
        por       %xmm0, %xmm8                                  #651.2
        movdqa    %xmm11, %xmm0                                 #651.2
        por       %xmm2, %xmm14                                 #651.2
        pand      %xmm2, %xmm0                                  #651.2
        pand      %xmm7, %xmm14                                 #651.2
        paddd     %xmm13, %xmm10                                #650.2
        por       %xmm14, %xmm0                                 #651.2
        paddd     704(%rdi), %xmm10                             #650.2
        paddd     %xmm0, %xmm6                                  #651.2
        movdqa    %xmm12, %xmm0                                 #651.2
        paddd     %xmm13, %xmm3                                 #650.2
        movdqa    %xmm10, %xmm9                                 #651.2
        movdqa    %xmm10, %xmm15                                #651.2
        pslld     $30, %xmm0                                    #651.2
        psrld     $2, %xmm12                                    #651.2
        paddd     1984(%rdi), %xmm3                             #650.2
        pslld     $5, %xmm9                                     #651.2
        psrld     $27, %xmm15                                   #651.2
        por       %xmm12, %xmm0                                 #651.2
        movdqa    %xmm11, %xmm12                                #651.2
        paddd     %xmm8, %xmm1                                  #651.2
        por       %xmm15, %xmm9                                 #651.2
        movdqa    %xmm3, %xmm15                                 #651.2
        movdqa    %xmm3, %xmm8                                  #651.2
        pslld     $30, %xmm12                                   #651.2
        psrld     $2, %xmm11                                    #651.2
        pslld     $5, %xmm15                                    #651.2
        psrld     $27, %xmm8                                    #651.2
        por       %xmm11, %xmm12                                #651.2
        movdqa    %xmm10, %xmm11                                #652.2
        por       %xmm8, %xmm15                                 #651.2
        movdqa    %xmm10, %xmm8                                 #652.2
        por       %xmm0, %xmm11                                 #652.2
        pand      %xmm0, %xmm8                                  #652.2
        pand      %xmm5, %xmm11                                 #652.2
        movdqa    %xmm3, %xmm14                                 #652.2
        por       %xmm11, %xmm8                                 #652.2
        movdqa    %xmm3, %xmm11                                 #652.2
        por       %xmm12, %xmm14                                #652.2
        paddd     %xmm9, %xmm1                                  #651.2
        pand      %xmm12, %xmm11                                #652.2
        pand      %xmm2, %xmm14                                 #652.2
        paddd     %xmm13, %xmm1                                 #651.2
        por       %xmm14, %xmm11                                #652.2
        paddd     %xmm15, %xmm6                                 #651.2
        paddd     720(%rdi), %xmm1                              #651.2
        paddd     %xmm11, %xmm7                                 #652.2
        movdqa    %xmm10, %xmm11                                #652.2
        paddd     %xmm13, %xmm6                                 #651.2
        movdqa    %xmm1, %xmm9                                  #652.2
        movdqa    %xmm1, %xmm15                                 #652.2
        pslld     $30, %xmm11                                   #652.2
        psrld     $2, %xmm10                                    #652.2
        paddd     2000(%rdi), %xmm6                             #651.2
        pslld     $5, %xmm9                                     #652.2
        psrld     $27, %xmm15                                   #652.2
        por       %xmm10, %xmm11                                #652.2
        movdqa    %xmm3, %xmm10                                 #652.2
        paddd     %xmm8, %xmm4                                  #652.2
        por       %xmm15, %xmm9                                 #652.2
        movdqa    %xmm6, %xmm15                                 #652.2
        movdqa    %xmm6, %xmm8                                  #652.2
        pslld     $30, %xmm10                                   #652.2
        psrld     $2, %xmm3                                     #652.2
        pslld     $5, %xmm15                                    #652.2
        psrld     $27, %xmm8                                    #652.2
        por       %xmm3, %xmm10                                 #652.2
        movdqa    %xmm1, %xmm3                                  #653.2
        por       %xmm8, %xmm15                                 #652.2
        movdqa    %xmm1, %xmm8                                  #653.2
        por       %xmm11, %xmm3                                 #653.2
        paddd     %xmm9, %xmm4                                  #652.2
        pand      %xmm11, %xmm8                                 #653.2
        pand      %xmm0, %xmm3                                  #653.2
        movdqa    %xmm6, %xmm14                                 #653.2
        paddd     %xmm13, %xmm4                                 #652.2
        por       %xmm3, %xmm8                                  #653.2
        movdqa    %xmm6, %xmm3                                  #653.2
        por       %xmm10, %xmm14                                #653.2
        paddd     736(%rdi), %xmm4                              #652.2
        paddd     %xmm15, %xmm7                                 #652.2
        pand      %xmm10, %xmm3                                 #653.2
        pand      %xmm12, %xmm14                                #653.2
        paddd     %xmm13, %xmm7                                 #652.2
        movdqa    %xmm4, %xmm9                                  #653.2
        movdqa    %xmm4, %xmm15                                 #653.2
        por       %xmm14, %xmm3                                 #653.2
        paddd     2016(%rdi), %xmm7                             #652.2
        pslld     $5, %xmm9                                     #653.2
        psrld     $27, %xmm15                                   #653.2
        paddd     %xmm3, %xmm2                                  #653.2
        movdqa    %xmm1, %xmm3                                  #653.2
        paddd     %xmm8, %xmm5                                  #653.2
        por       %xmm15, %xmm9                                 #653.2
        movdqa    %xmm7, %xmm15                                 #653.2
        movdqa    %xmm7, %xmm8                                  #653.2
        pslld     $30, %xmm3                                    #653.2
        psrld     $2, %xmm1                                     #653.2
        movdqa    %xmm6, %xmm14                                 #653.2
        paddd     %xmm9, %xmm5                                  #653.2
        pslld     $5, %xmm15                                    #653.2
        psrld     $27, %xmm8                                    #653.2
        por       %xmm1, %xmm3                                  #653.2
        pslld     $30, %xmm14                                   #653.2
        psrld     $2, %xmm6                                     #653.2
        movdqa    %xmm4, %xmm1                                  #654.2
        paddd     %xmm13, %xmm5                                 #653.2
        por       %xmm8, %xmm15                                 #653.2
        por       %xmm6, %xmm14                                 #653.2
        movdqa    %xmm4, %xmm6                                  #654.2
        por       %xmm3, %xmm1                                  #654.2
        paddd     752(%rdi), %xmm5                              #653.2
        paddd     %xmm15, %xmm2                                 #653.2
        pand      %xmm3, %xmm6                                  #654.2
        pand      %xmm11, %xmm1                                 #654.2
        movdqa    %xmm7, %xmm15                                 #654.2
        por       %xmm1, %xmm6                                  #654.2
        movdqa    %xmm5, %xmm8                                  #654.2
        movdqa    %xmm5, %xmm1                                  #654.2
        movdqa    %xmm7, %xmm9                                  #654.2
        por       %xmm14, %xmm15                                #654.2
        pslld     $5, %xmm8                                     #654.2
        psrld     $27, %xmm1                                    #654.2
        pand      %xmm14, %xmm9                                 #654.2
        pand      %xmm10, %xmm15                                #654.2
        paddd     %xmm13, %xmm2                                 #653.2
        paddd     %xmm6, %xmm0                                  #654.2
        por       %xmm1, %xmm8                                  #654.2
        por       %xmm15, %xmm9                                 #654.2
        paddd     2032(%rdi), %xmm2                             #653.2
        paddd     %xmm8, %xmm0                                  #654.2
        paddd     %xmm9, %xmm12                                 #654.2
        movdqa    %xmm4, %xmm9                                  #654.2
        movdqa    %xmm7, %xmm8                                  #654.2
        movdqa    %xmm2, %xmm6                                  #654.2
        movdqa    %xmm2, %xmm1                                  #654.2
        pslld     $30, %xmm9                                    #654.2
        psrld     $2, %xmm4                                     #654.2
        pslld     $30, %xmm8                                    #654.2
        psrld     $2, %xmm7                                     #654.2
        pslld     $5, %xmm6                                     #654.2
        psrld     $27, %xmm1                                    #654.2
        por       %xmm4, %xmm9                                  #654.2
        por       %xmm7, %xmm8                                  #654.2
        movdqa    %xmm5, %xmm7                                  #655.2
        por       %xmm1, %xmm6                                  #654.2
        movdqa    %xmm5, %xmm1                                  #655.2
        por       %xmm9, %xmm7                                  #655.2
        paddd     %xmm13, %xmm0                                 #654.2
        pand      %xmm9, %xmm1                                  #655.2
        pand      %xmm3, %xmm7                                  #655.2
        paddd     768(%rdi), %xmm0                              #654.2
        por       %xmm7, %xmm1                                  #655.2
        movdqa    %xmm2, %xmm15                                 #655.2
        paddd     %xmm6, %xmm12                                 #654.2
        paddd     %xmm1, %xmm11                                 #655.2
        movdqa    %xmm0, %xmm6                                  #655.2
        movdqa    %xmm0, %xmm4                                  #655.2
        movdqa    %xmm2, %xmm1                                  #655.2
        por       %xmm8, %xmm15                                 #655.2
        pslld     $5, %xmm6                                     #655.2
        psrld     $27, %xmm4                                    #655.2
        pand      %xmm8, %xmm1                                  #655.2
        pand      %xmm14, %xmm15                                #655.2
        paddd     %xmm13, %xmm12                                #654.2
        por       %xmm4, %xmm6                                  #655.2
        por       %xmm15, %xmm1                                 #655.2
        paddd     2048(%rdi), %xmm12                            #654.2
        paddd     %xmm6, %xmm11                                 #655.2
        paddd     %xmm1, %xmm10                                 #655.2
        movdqa    %xmm5, %xmm1                                  #655.2
        movdqa    %xmm2, %xmm6                                  #655.2
        movdqa    %xmm12, %xmm7                                 #655.2
        movdqa    %xmm12, %xmm4                                 #655.2
        pslld     $30, %xmm1                                    #655.2
        psrld     $2, %xmm5                                     #655.2
        pslld     $30, %xmm6                                    #655.2
        psrld     $2, %xmm2                                     #655.2
        paddd     %xmm13, %xmm11                                #655.2
        pslld     $5, %xmm7                                     #655.2
        psrld     $27, %xmm4                                    #655.2
        por       %xmm5, %xmm1                                  #655.2
        por       %xmm2, %xmm6                                  #655.2
        movdqa    %xmm0, %xmm2                                  #656.2
        por       %xmm4, %xmm7                                  #655.2
        paddd     784(%rdi), %xmm11                             #655.2
        movdqa    %xmm0, %xmm4                                  #656.2
        por       %xmm1, %xmm2                                  #656.2
        paddd     %xmm7, %xmm10                                 #655.2
        pand      %xmm1, %xmm4                                  #656.2
        pand      %xmm9, %xmm2                                  #656.2
        movdqa    %xmm11, %xmm5                                 #656.2
        movdqa    %xmm11, %xmm7                                 #656.2
        movdqa    %xmm12, %xmm15                                #656.2
        por       %xmm2, %xmm4                                  #656.2
        pslld     $5, %xmm5                                     #656.2
        psrld     $27, %xmm7                                    #656.2
        movdqa    %xmm12, %xmm2                                 #656.2
        por       %xmm6, %xmm15                                 #656.2
        paddd     %xmm13, %xmm10                                #655.2
        paddd     %xmm4, %xmm3                                  #656.2
        por       %xmm7, %xmm5                                  #656.2
        pand      %xmm6, %xmm2                                  #656.2
        pand      %xmm8, %xmm15                                 #656.2
        paddd     %xmm5, %xmm3                                  #656.2
        paddd     2064(%rdi), %xmm10                            #655.2
        por       %xmm15, %xmm2                                 #656.2
        movdqa    %xmm0, %xmm5                                  #656.2
        movdqa    %xmm12, %xmm15                                #656.2
        movdqa    %xmm10, %xmm7                                 #656.2
        movdqa    %xmm10, %xmm4                                 #656.2
        pslld     $30, %xmm5                                    #656.2
        psrld     $2, %xmm0                                     #656.2
        pslld     $30, %xmm15                                   #656.2
        psrld     $2, %xmm12                                    #656.2
        paddd     %xmm13, %xmm3                                 #656.2
        pslld     $5, %xmm7                                     #656.2
        psrld     $27, %xmm4                                    #656.2
        por       %xmm0, %xmm5                                  #656.2
        por       %xmm12, %xmm15                                #656.2
        movdqa    %xmm11, %xmm12                                #657.2
        paddd     800(%rdi), %xmm3                              #656.2
        paddd     %xmm2, %xmm14                                 #656.2
        por       %xmm4, %xmm7                                  #656.2
        movdqa    %xmm11, %xmm2                                 #657.2
        por       %xmm5, %xmm12                                 #657.2
        paddd     %xmm7, %xmm14                                 #656.2
        pand      %xmm5, %xmm2                                  #657.2
        pand      %xmm1, %xmm12                                 #657.2
        movdqa    %xmm3, %xmm0                                  #657.2
        movdqa    %xmm3, %xmm4                                  #657.2
        paddd     %xmm13, %xmm14                                #656.2
        por       %xmm12, %xmm2                                 #657.2
        pslld     $5, %xmm0                                     #657.2
        psrld     $27, %xmm4                                    #657.2
        movdqa    %xmm10, %xmm7                                 #657.2
        paddd     %xmm2, %xmm9                                  #657.2
        paddd     2080(%rdi), %xmm14                            #656.2
        por       %xmm4, %xmm0                                  #657.2
        movdqa    %xmm10, %xmm2                                 #657.2
        por       %xmm15, %xmm7                                 #657.2
        paddd     %xmm0, %xmm9                                  #657.2
        pand      %xmm15, %xmm2                                 #657.2
        pand      %xmm6, %xmm7                                  #657.2
        movdqa    %xmm14, %xmm0                                 #657.2
        movdqa    %xmm14, %xmm4                                 #657.2
        por       %xmm7, %xmm2                                  #657.2
        pslld     $5, %xmm0                                     #657.2
        psrld     $27, %xmm4                                    #657.2
        paddd     %xmm2, %xmm8                                  #657.2
        por       %xmm4, %xmm0                                  #657.2
        movdqa    %xmm11, %xmm4                                 #657.2
        movdqa    %xmm10, %xmm2                                 #657.2
        pslld     $30, %xmm4                                    #657.2
        psrld     $2, %xmm11                                    #657.2
        pslld     $30, %xmm2                                    #657.2
        psrld     $2, %xmm10                                    #657.2
        por       %xmm11, %xmm4                                 #657.2
        por       %xmm10, %xmm2                                 #657.2
        movdqa    %xmm3, %xmm10                                 #658.2
        paddd     %xmm13, %xmm9                                 #657.2
        paddd     %xmm0, %xmm8                                  #657.2
        movdqa    %xmm3, %xmm0                                  #658.2
        por       %xmm4, %xmm10                                 #658.2
        pand      %xmm4, %xmm0                                  #658.2
        paddd     816(%rdi), %xmm9                              #657.2
        pand      %xmm5, %xmm10                                 #658.2
        por       %xmm10, %xmm0                                 #658.2
        movdqa    %xmm9, %xmm7                                  #658.2
        movdqa    %xmm9, %xmm11                                 #658.2
        movdqa    %xmm14, %xmm12                                #658.2
        paddd     %xmm13, %xmm8                                 #657.2
        paddd     %xmm0, %xmm1                                  #658.2
        pslld     $5, %xmm7                                     #658.2
        psrld     $27, %xmm11                                   #658.2
        movdqa    %xmm14, %xmm0                                 #658.2
        por       %xmm2, %xmm12                                 #658.2
        paddd     2096(%rdi), %xmm8                             #657.2
        por       %xmm11, %xmm7                                 #658.2
        pand      %xmm2, %xmm0                                  #658.2
        pand      %xmm15, %xmm12                                #658.2
        paddd     %xmm7, %xmm1                                  #658.2
        por       %xmm12, %xmm0                                 #658.2
        movdqa    %xmm8, %xmm7                                  #658.2
        movdqa    %xmm8, %xmm11                                 #658.2
        paddd     %xmm0, %xmm6                                  #658.2
        pslld     $5, %xmm7                                     #658.2
        psrld     $27, %xmm11                                   #658.2
        movdqa    %xmm3, %xmm0                                  #658.2
        por       %xmm11, %xmm7                                 #658.2
        pslld     $30, %xmm0                                    #658.2
        psrld     $2, %xmm3                                     #658.2
        movdqa    %xmm14, %xmm11                                #658.2
        paddd     %xmm13, %xmm1                                 #658.2
        por       %xmm3, %xmm0                                  #658.2
        pslld     $30, %xmm11                                   #658.2
        psrld     $2, %xmm14                                    #658.2
        movdqa    %xmm9, %xmm3                                  #659.2
        por       %xmm14, %xmm11                                #658.2
        paddd     832(%rdi), %xmm1                              #658.2
        movdqa    %xmm9, %xmm14                                 #659.2
        por       %xmm0, %xmm3                                  #659.2
        paddd     %xmm7, %xmm6                                  #658.2
        pand      %xmm0, %xmm14                                 #659.2
        pand      %xmm4, %xmm3                                  #659.2
        movdqa    %xmm1, %xmm10                                 #659.2
        movdqa    %xmm1, %xmm7                                  #659.2
        paddd     %xmm13, %xmm6                                 #658.2
        por       %xmm3, %xmm14                                 #659.2
        pslld     $5, %xmm10                                    #659.2
        psrld     $27, %xmm7                                    #659.2
        movdqa    %xmm8, %xmm3                                  #659.2
        paddd     %xmm14, %xmm5                                 #659.2
        paddd     2112(%rdi), %xmm6                             #658.2
        por       %xmm7, %xmm10                                 #659.2
        movdqa    %xmm8, %xmm12                                 #659.2
        por       %xmm11, %xmm3                                 #659.2
        paddd     %xmm10, %xmm5                                 #659.2
        pand      %xmm11, %xmm12                                #659.2
        pand      %xmm2, %xmm3                                  #659.2
        movdqa    %xmm6, %xmm10                                 #659.2
        movdqa    %xmm6, %xmm7                                  #659.2
        por       %xmm3, %xmm12                                 #659.2
        pslld     $5, %xmm10                                    #659.2
        psrld     $27, %xmm7                                    #659.2
        paddd     %xmm12, %xmm15                                #659.2
        por       %xmm7, %xmm10                                 #659.2
        paddd     %xmm10, %xmm15                                #659.2
        movdqa    %xmm9, %xmm10                                 #659.2
        movdqa    %xmm8, %xmm7                                  #659.2
        pslld     $30, %xmm10                                   #659.2
        psrld     $2, %xmm9                                     #659.2
        pslld     $30, %xmm7                                    #659.2
        psrld     $2, %xmm8                                     #659.2
        por       %xmm9, %xmm10                                 #659.2
        por       %xmm8, %xmm7                                  #659.2
        movdqa    %xmm1, %xmm8                                  #660.2
        paddd     %xmm13, %xmm5                                 #659.2
        movdqa    %xmm1, %xmm9                                  #660.2
        por       %xmm10, %xmm8                                 #660.2
        pand      %xmm10, %xmm9                                 #660.2
        paddd     848(%rdi), %xmm5                              #659.2
        pand      %xmm0, %xmm8                                  #660.2
        por       %xmm8, %xmm9                                  #660.2
        movdqa    %xmm5, %xmm8                                  #660.2
        movdqa    %xmm5, %xmm3                                  #660.2
        paddd     %xmm13, %xmm15                                #659.2
        pslld     $5, %xmm8                                     #660.2
        psrld     $27, %xmm3                                    #660.2
        paddd     2128(%rdi), %xmm15                            #659.2
        paddd     %xmm9, %xmm4                                  #660.2
        por       %xmm3, %xmm8                                  #660.2
        movdqa    %xmm15, %xmm3                                 #660.2
        paddd     %xmm8, %xmm4                                  #660.2
        movdqa    %xmm15, %xmm8                                 #660.2
        pslld     $5, %xmm8                                     #660.2
        psrld     $27, %xmm3                                    #660.2
        movdqa    %xmm6, %xmm12                                 #660.2
        por       %xmm3, %xmm8                                  #660.2
        movdqa    %xmm1, %xmm3                                  #660.2
        movdqa    %xmm6, %xmm14                                 #660.2
        por       %xmm7, %xmm12                                 #660.2
        pslld     $30, %xmm3                                    #660.2
        psrld     $2, %xmm1                                     #660.2
        pand      %xmm7, %xmm14                                 #660.2
        pand      %xmm11, %xmm12                                #660.2
        por       %xmm1, %xmm3                                  #660.2
        movdqa    %xmm6, %xmm1                                  #660.2
        por       %xmm12, %xmm14                                #660.2
        pslld     $30, %xmm1                                    #660.2
        psrld     $2, %xmm6                                     #660.2
        paddd     %xmm13, %xmm4                                 #660.2
        paddd     %xmm14, %xmm2                                 #660.2
        por       %xmm6, %xmm1                                  #660.2
        movdqa    %xmm5, %xmm6                                  #661.2
        paddd     864(%rdi), %xmm4                              #660.2
        paddd     %xmm8, %xmm2                                  #660.2
        movdqa    %xmm5, %xmm8                                  #661.2
        por       %xmm3, %xmm6                                  #661.2
        paddd     %xmm13, %xmm2                                 #660.2
        pand      %xmm3, %xmm8                                  #661.2
        pand      %xmm10, %xmm6                                 #661.2
        movdqa    %xmm4, %xmm12                                 #661.2
        movdqa    %xmm4, %xmm9                                  #661.2
        por       %xmm6, %xmm8                                  #661.2
        paddd     2144(%rdi), %xmm2                             #660.2
        pslld     $5, %xmm12                                    #661.2
        psrld     $27, %xmm9                                    #661.2
        movdqa    %xmm15, %xmm14                                #661.2
        paddd     %xmm8, %xmm0                                  #661.2
        por       %xmm9, %xmm12                                 #661.2
        movdqa    %xmm15, %xmm6                                 #661.2
        por       %xmm1, %xmm14                                 #661.2
        movdqa    %xmm2, %xmm9                                  #661.2
        movdqa    %xmm2, %xmm8                                  #661.2
        pand      %xmm1, %xmm6                                  #661.2
        pand      %xmm7, %xmm14                                 #661.2
        pslld     $5, %xmm9                                     #661.2
        psrld     $27, %xmm8                                    #661.2
        por       %xmm14, %xmm6                                 #661.2
        por       %xmm8, %xmm9                                  #661.2
        movdqa    %xmm5, %xmm8                                  #661.2
        paddd     %xmm6, %xmm11                                 #661.2
        pslld     $30, %xmm8                                    #661.2
        psrld     $2, %xmm5                                     #661.2
        movdqa    %xmm15, %xmm6                                 #661.2
        paddd     %xmm12, %xmm0                                 #661.2
        por       %xmm5, %xmm8                                  #661.2
        pslld     $30, %xmm6                                    #661.2
        psrld     $2, %xmm15                                    #661.2
        movdqa    %xmm4, %xmm5                                  #662.2
        paddd     %xmm13, %xmm0                                 #661.2
        por       %xmm15, %xmm6                                 #661.2
        movdqa    %xmm4, %xmm15                                 #662.2
        por       %xmm8, %xmm5                                  #662.2
        paddd     880(%rdi), %xmm0                              #661.2
        pand      %xmm8, %xmm15                                 #662.2
        pand      %xmm3, %xmm5                                  #662.2
        paddd     %xmm9, %xmm11                                 #661.2
        por       %xmm5, %xmm15                                 #662.2
        movdqa    %xmm0, %xmm9                                  #662.2
        movdqa    %xmm0, %xmm5                                  #662.2
        paddd     %xmm13, %xmm11                                #661.2
        pslld     $5, %xmm9                                     #662.2
        psrld     $27, %xmm5                                    #662.2
        movdqa    %xmm2, %xmm12                                 #662.2
        paddd     %xmm15, %xmm10                                #662.2
        paddd     2160(%rdi), %xmm11                            #661.2
        por       %xmm5, %xmm9                                  #662.2
        movdqa    %xmm2, %xmm14                                 #662.2
        por       %xmm6, %xmm12                                 #662.2
        paddd     %xmm9, %xmm10                                 #662.2
        pand      %xmm6, %xmm14                                 #662.2
        pand      %xmm1, %xmm12                                 #662.2
        movdqa    %xmm11, %xmm9                                 #662.2
        movdqa    %xmm11, %xmm5                                 #662.2
        por       %xmm12, %xmm14                                #662.2
        pslld     $5, %xmm9                                     #662.2
        psrld     $27, %xmm5                                    #662.2
        paddd     %xmm14, %xmm7                                 #662.2
        por       %xmm5, %xmm9                                  #662.2
        paddd     %xmm9, %xmm7                                  #662.2
        paddd     %xmm13, %xmm10                                #662.2
        paddd     %xmm13, %xmm7                                 #662.2
        movdqa    %xmm4, %xmm5                                  #662.2
        paddd     2176(%rdi), %xmm7                             #662.2
        pslld     $30, %xmm5                                    #662.2
        paddd     896(%rdi), %xmm10                             #662.2
        psrld     $2, %xmm4                                     #662.2
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm10 xmm11 xmm13
..B9.16:                        # Preds ..B9.17
        por       %xmm4, %xmm5                                  #662.2
        movdqa    %xmm2, %xmm4                                  #662.2
        pslld     $30, %xmm4                                    #662.2
        psrld     $2, %xmm2                                     #662.2
        movdqa    %xmm0, %xmm9                                  #663.2
        por       %xmm2, %xmm4                                  #662.2
        movdqa    %xmm0, %xmm2                                  #663.2
        por       %xmm5, %xmm9                                  #663.2
        pand      %xmm5, %xmm2                                  #663.2
        pand      %xmm8, %xmm9                                  #663.2
        movdqa    %xmm10, %xmm14                                #663.2
        movdqa    %xmm10, %xmm12                                #663.2
        por       %xmm9, %xmm2                                  #663.2
        pslld     $5, %xmm14                                    #663.2
        psrld     $27, %xmm12                                   #663.2
        paddd     %xmm2, %xmm3                                  #663.2
        por       %xmm12, %xmm14                                #663.2
        movdqa    %xmm7, %xmm12                                 #663.2
        movdqa    %xmm7, %xmm2                                  #663.2
        movdqa    %xmm11, %xmm15                                #663.2
        pslld     $5, %xmm12                                    #663.2
        psrld     $27, %xmm2                                    #663.2
        movdqa    %xmm11, %xmm9                                 #663.2
        por       %xmm4, %xmm15                                 #663.2
        por       %xmm2, %xmm12                                 #663.2
        movdqa    %xmm0, %xmm2                                  #663.2
        pand      %xmm4, %xmm9                                  #663.2
        pand      %xmm6, %xmm15                                 #663.2
        pslld     $30, %xmm2                                    #663.2
        psrld     $2, %xmm0                                     #663.2
        paddd     %xmm14, %xmm3                                 #663.2
        por       %xmm15, %xmm9                                 #663.2
        por       %xmm0, %xmm2                                  #663.2
        movdqa    %xmm11, %xmm0                                 #663.2
        paddd     %xmm13, %xmm3                                 #663.2
        paddd     %xmm9, %xmm1                                  #663.2
        pslld     $30, %xmm0                                    #663.2
        psrld     $2, %xmm11                                    #663.2
        paddd     912(%rdi), %xmm3                              #663.2
        paddd     %xmm12, %xmm1                                 #663.2
        por       %xmm11, %xmm0                                 #663.2
        movdqa    %xmm10, %xmm11                                #664.2
        paddd     %xmm13, %xmm1                                 #663.2
        movdqa    %xmm10, %xmm9                                 #664.2
        por       %xmm2, %xmm11                                 #664.2
        movdqa    %xmm3, %xmm14                                 #664.2
        movdqa    %xmm3, %xmm12                                 #664.2
        pand      %xmm2, %xmm9                                  #664.2
        paddd     2192(%rdi), %xmm1                             #663.2
        pand      %xmm5, %xmm11                                 #664.2
        pslld     $5, %xmm14                                    #664.2
        psrld     $27, %xmm12                                   #664.2
        por       %xmm11, %xmm9                                 #664.2
        por       %xmm12, %xmm14                                #664.2
        movdqa    %xmm1, %xmm12                                 #664.2
        movdqa    %xmm1, %xmm11                                 #664.2
        pslld     $5, %xmm12                                    #664.2
        psrld     $27, %xmm11                                   #664.2
        por       %xmm11, %xmm12                                #664.2
        movdqa    %xmm10, %xmm11                                #664.2
        movdqa    %xmm7, %xmm15                                 #664.2
        pslld     $30, %xmm11                                   #664.2
        psrld     $2, %xmm10                                    #664.2
        paddd     %xmm9, %xmm8                                  #664.2
        movdqa    %xmm7, %xmm9                                  #664.2
        por       %xmm0, %xmm15                                 #664.2
        por       %xmm10, %xmm11                                #664.2
        movdqa    %xmm7, %xmm10                                 #664.2
        pand      %xmm0, %xmm9                                  #664.2
        pand      %xmm4, %xmm15                                 #664.2
        pslld     $30, %xmm10                                   #664.2
        psrld     $2, %xmm7                                     #664.2
        paddd     %xmm14, %xmm8                                 #664.2
        por       %xmm15, %xmm9                                 #664.2
        por       %xmm7, %xmm10                                 #664.2
        movdqa    %xmm3, %xmm7                                  #665.2
        paddd     %xmm13, %xmm8                                 #664.2
        paddd     %xmm9, %xmm6                                  #664.2
        movdqa    %xmm3, %xmm9                                  #665.2
        por       %xmm11, %xmm7                                 #665.2
        paddd     928(%rdi), %xmm8                              #664.2
        paddd     %xmm12, %xmm6                                 #664.2
        pand      %xmm11, %xmm9                                 #665.2
        pand      %xmm2, %xmm7                                  #665.2
        paddd     %xmm13, %xmm6                                 #664.2
        por       %xmm7, %xmm9                                  #665.2
        movdqa    %xmm8, %xmm14                                 #665.2
        movdqa    %xmm8, %xmm12                                 #665.2
        movdqa    %xmm1, %xmm15                                 #665.2
        paddd     %xmm9, %xmm5                                  #665.2
        paddd     2208(%rdi), %xmm6                             #664.2
        pslld     $5, %xmm14                                    #665.2
        psrld     $27, %xmm12                                   #665.2
        movdqa    %xmm1, %xmm9                                  #665.2
        por       %xmm10, %xmm15                                #665.2
        por       %xmm12, %xmm14                                #665.2
        pand      %xmm10, %xmm9                                 #665.2
        pand      %xmm0, %xmm15                                 #665.2
        movdqa    %xmm6, %xmm12                                 #665.2
        movdqa    %xmm6, %xmm7                                  #665.2
        por       %xmm15, %xmm9                                 #665.2
        pslld     $5, %xmm12                                    #665.2
        psrld     $27, %xmm7                                    #665.2
        paddd     %xmm9, %xmm4                                  #665.2
        por       %xmm7, %xmm12                                 #665.2
        paddd     %xmm14, %xmm5                                 #665.2
        paddd     %xmm12, %xmm4                                 #665.2
        paddd     %xmm13, %xmm5                                 #665.2
        paddd     %xmm13, %xmm4                                 #665.2
        movdqa    %xmm3, %xmm13                                 #665.2
        pslld     $30, %xmm13                                   #665.2
        psrld     $2, %xmm3                                     #665.2
        por       %xmm3, %xmm13                                 #665.2
        movdqa    %xmm1, %xmm3                                  #665.2
        paddd     944(%rdi), %xmm5                              #665.2
        pslld     $30, %xmm3                                    #665.2
        psrld     $2, %xmm1                                     #665.2
        movdqa    %xmm5, %xmm12                                 #668.2
        por       %xmm1, %xmm3                                  #665.2
        movdqa    %xmm13, %xmm1                                 #668.2
        movdqa    %xmm5, %xmm7                                  #668.2
        pxor      %xmm11, %xmm1                                 #668.2
        pslld     $5, %xmm12                                    #668.2
        psrld     $27, %xmm7                                    #668.2
        paddd     2224(%rdi), %xmm4                             #665.2
        pxor      %xmm8, %xmm1                                  #668.2
        por       %xmm7, %xmm12                                 #668.2
        movdqa    %xmm3, %xmm14                                 #668.2
        movdqa    %xmm8, %xmm7                                  #668.2
        paddd     %xmm1, %xmm2                                  #668.2
        pxor      %xmm10, %xmm14                                #668.2
        movdqa    %xmm4, %xmm1                                  #668.2
        movdqa    %xmm4, %xmm15                                 #668.2
        pslld     $30, %xmm7                                    #668.2
        psrld     $2, %xmm8                                     #668.2
        pxor      %xmm6, %xmm14                                 #668.2
        pslld     $5, %xmm1                                     #668.2
        psrld     $27, %xmm15                                   #668.2
        por       %xmm8, %xmm7                                  #668.2
        paddd     %xmm12, %xmm2                                 #668.2
        movdqa    .L_2il0floatpacket.506(%rip), %xmm9           #667.8
        paddd     %xmm14, %xmm0                                 #668.2
        por       %xmm15, %xmm1                                 #668.2
        movdqa    %xmm7, %xmm8                                  #669.2
        paddd     %xmm9, %xmm2                                  #668.2
        paddd     %xmm1, %xmm0                                  #668.2
        movdqa    %xmm6, %xmm1                                  #668.2
        pxor      %xmm13, %xmm8                                 #669.2
        paddd     960(%rdi), %xmm2                              #668.2
        pslld     $30, %xmm1                                    #668.2
        psrld     $2, %xmm6                                     #668.2
        pxor      %xmm5, %xmm8                                  #669.2
        por       %xmm6, %xmm1                                  #668.2
        paddd     %xmm8, %xmm11                                 #669.2
        movdqa    %xmm2, %xmm8                                  #669.2
        movdqa    %xmm2, %xmm6                                  #669.2
        pslld     $5, %xmm8                                     #669.2
        psrld     $27, %xmm6                                    #669.2
        por       %xmm6, %xmm8                                  #669.2
        movdqa    %xmm1, %xmm12                                 #669.2
        paddd     %xmm8, %xmm11                                 #669.2
        movdqa    %xmm5, %xmm8                                  #669.2
        paddd     %xmm9, %xmm0                                  #668.2
        pxor      %xmm3, %xmm12                                 #669.2
        pslld     $30, %xmm8                                    #669.2
        psrld     $2, %xmm5                                     #669.2
        movdqa    %xmm4, %xmm6                                  #669.2
        pxor      %xmm4, %xmm12                                 #669.2
        paddd     2240(%rdi), %xmm0                             #668.2
        por       %xmm5, %xmm8                                  #669.2
        pslld     $30, %xmm6                                    #669.2
        psrld     $2, %xmm4                                     #669.2
        movdqa    %xmm0, %xmm15                                 #669.2
        movdqa    %xmm0, %xmm14                                 #669.2
        por       %xmm4, %xmm6                                  #669.2
        movdqa    %xmm8, %xmm4                                  #670.2
        paddd     %xmm9, %xmm11                                 #669.2
        pslld     $5, %xmm15                                    #669.2
        psrld     $27, %xmm14                                   #669.2
        pxor      %xmm7, %xmm4                                  #670.2
        paddd     976(%rdi), %xmm11                             #669.2
        paddd     %xmm12, %xmm10                                #669.2
        por       %xmm14, %xmm15                                #669.2
        pxor      %xmm2, %xmm4                                  #670.2
        paddd     %xmm15, %xmm10                                #669.2
        paddd     %xmm4, %xmm13                                 #670.2
        movdqa    %xmm11, %xmm4                                 #670.2
        movdqa    %xmm11, %xmm5                                 #670.2
        paddd     %xmm9, %xmm10                                 #669.2
        pslld     $5, %xmm4                                     #670.2
        psrld     $27, %xmm5                                    #670.2
        movdqa    %xmm6, %xmm12                                 #670.2
        paddd     2256(%rdi), %xmm10                            #669.2
        por       %xmm5, %xmm4                                  #670.2
        movdqa    %xmm2, %xmm5                                  #670.2
        pxor      %xmm1, %xmm12                                 #670.2
        movdqa    %xmm10, %xmm15                                #670.2
        movdqa    %xmm10, %xmm14                                #670.2
        pslld     $30, %xmm5                                    #670.2
        psrld     $2, %xmm2                                     #670.2
        paddd     %xmm4, %xmm13                                 #670.2
        pxor      %xmm0, %xmm12                                 #670.2
        pslld     $5, %xmm15                                    #670.2
        psrld     $27, %xmm14                                   #670.2
        por       %xmm2, %xmm5                                  #670.2
        movdqa    %xmm0, %xmm2                                  #670.2
        paddd     %xmm9, %xmm13                                 #670.2
        paddd     %xmm12, %xmm3                                 #670.2
        por       %xmm14, %xmm15                                #670.2
        pslld     $30, %xmm2                                    #670.2
        psrld     $2, %xmm0                                     #670.2
        paddd     %xmm15, %xmm3                                 #670.2
        paddd     992(%rdi), %xmm13                             #670.2
        por       %xmm0, %xmm2                                  #670.2
        movdqa    %xmm5, %xmm0                                  #671.2
        paddd     %xmm9, %xmm3                                  #670.2
        pxor      %xmm8, %xmm0                                  #671.2
        movdqa    %xmm13, %xmm12                                #671.2
        movdqa    %xmm13, %xmm4                                 #671.2
        pxor      %xmm11, %xmm0                                 #671.2
        paddd     2272(%rdi), %xmm3                             #670.2
        pslld     $5, %xmm12                                    #671.2
        psrld     $27, %xmm4                                    #671.2
        movdqa    %xmm2, %xmm14                                 #671.2
        paddd     %xmm0, %xmm7                                  #671.2
        por       %xmm4, %xmm12                                 #671.2
        pxor      %xmm6, %xmm14                                 #671.2
        movdqa    %xmm3, %xmm4                                  #671.2
        movdqa    %xmm3, %xmm15                                 #671.2
        paddd     %xmm12, %xmm7                                 #671.2
        pxor      %xmm10, %xmm14                                #671.2
        pslld     $5, %xmm4                                     #671.2
        psrld     $27, %xmm15                                   #671.2
        paddd     %xmm9, %xmm7                                  #671.2
        paddd     %xmm14, %xmm1                                 #671.2
        por       %xmm15, %xmm4                                 #671.2
        movdqa    %xmm11, %xmm0                                 #671.2
        paddd     %xmm4, %xmm1                                  #671.2
        paddd     1008(%rdi), %xmm7                             #671.2
        pslld     $30, %xmm0                                    #671.2
        psrld     $2, %xmm11                                    #671.2
        movdqa    %xmm10, %xmm15                                #671.2
        paddd     %xmm9, %xmm1                                  #671.2
        por       %xmm11, %xmm0                                 #671.2
        pslld     $30, %xmm15                                   #671.2
        psrld     $2, %xmm10                                    #671.2
        movdqa    %xmm7, %xmm11                                 #672.2
        movdqa    %xmm7, %xmm4                                  #672.2
        paddd     2288(%rdi), %xmm1                             #671.2
        por       %xmm10, %xmm15                                #671.2
        pslld     $5, %xmm11                                    #672.2
        psrld     $27, %xmm4                                    #672.2
        por       %xmm4, %xmm11                                 #672.2
        movdqa    %xmm15, %xmm12                                #672.2
        movdqa    %xmm1, %xmm4                                  #672.2
        movdqa    %xmm1, %xmm14                                 #672.2
        movdqa    %xmm0, %xmm10                                 #672.2
        pxor      %xmm2, %xmm12                                 #672.2
        pslld     $5, %xmm4                                     #672.2
        psrld     $27, %xmm14                                   #672.2
        pxor      %xmm5, %xmm10                                 #672.2
        pxor      %xmm3, %xmm12                                 #672.2
        por       %xmm14, %xmm4                                 #672.2
        movdqa    %xmm13, %xmm14                                #672.2
        pxor      %xmm13, %xmm10                                #672.2
        paddd     %xmm12, %xmm6                                 #672.2
        pslld     $30, %xmm14                                   #672.2
        psrld     $2, %xmm13                                    #672.2
        movdqa    %xmm3, %xmm12                                 #672.2
        por       %xmm13, %xmm14                                #672.2
        pslld     $30, %xmm12                                   #672.2
        psrld     $2, %xmm3                                     #672.2
        paddd     %xmm10, %xmm8                                 #672.2
        paddd     %xmm4, %xmm6                                  #672.2
        por       %xmm3, %xmm12                                 #672.2
        movdqa    %xmm14, %xmm3                                 #673.2
        paddd     %xmm11, %xmm8                                 #672.2
        paddd     %xmm9, %xmm6                                  #672.2
        pxor      %xmm0, %xmm3                                  #673.2
        paddd     %xmm9, %xmm8                                  #672.2
        paddd     2304(%rdi), %xmm6                             #672.2
        pxor      %xmm7, %xmm3                                  #673.2
        paddd     1024(%rdi), %xmm8                             #672.2
        paddd     %xmm3, %xmm5                                  #673.2
        movdqa    %xmm6, %xmm3                                  #673.2
        movdqa    %xmm6, %xmm13                                 #673.2
        movdqa    %xmm8, %xmm10                                 #673.2
        movdqa    %xmm8, %xmm4                                  #673.2
        pslld     $5, %xmm3                                     #673.2
        psrld     $27, %xmm13                                   #673.2
        pslld     $5, %xmm10                                    #673.2
        psrld     $27, %xmm4                                    #673.2
        por       %xmm13, %xmm3                                 #673.2
        movdqa    %xmm7, %xmm13                                 #673.2
        por       %xmm4, %xmm10                                 #673.2
        movdqa    %xmm12, %xmm11                                #673.2
        pslld     $30, %xmm13                                   #673.2
        psrld     $2, %xmm7                                     #673.2
        paddd     %xmm10, %xmm5                                 #673.2
        pxor      %xmm15, %xmm11                                #673.2
        por       %xmm7, %xmm13                                 #673.2
        movdqa    %xmm1, %xmm7                                  #673.2
        paddd     %xmm9, %xmm5                                  #673.2
        pxor      %xmm1, %xmm11                                 #673.2
        pslld     $30, %xmm7                                    #673.2
        psrld     $2, %xmm1                                     #673.2
        paddd     1040(%rdi), %xmm5                             #673.2
        paddd     %xmm11, %xmm2                                 #673.2
        por       %xmm1, %xmm7                                  #673.2
        movdqa    %xmm13, %xmm1                                 #674.2
        paddd     %xmm3, %xmm2                                  #673.2
        pxor      %xmm14, %xmm1                                 #674.2
        movdqa    %xmm5, %xmm4                                  #674.2
        movdqa    %xmm5, %xmm3                                  #674.2
        paddd     %xmm9, %xmm2                                  #673.2
        pxor      %xmm8, %xmm1                                  #674.2
        pslld     $5, %xmm4                                     #674.2
        psrld     $27, %xmm3                                    #674.2
        paddd     2320(%rdi), %xmm2                             #673.2
        paddd     %xmm1, %xmm0                                  #674.2
        por       %xmm3, %xmm4                                  #674.2
        movdqa    %xmm7, %xmm10                                 #674.2
        paddd     %xmm4, %xmm0                                  #674.2
        pxor      %xmm12, %xmm10                                #674.2
        movdqa    %xmm2, %xmm3                                  #674.2
        movdqa    %xmm2, %xmm11                                 #674.2
        movdqa    %xmm8, %xmm4                                  #674.2
        pxor      %xmm6, %xmm10                                 #674.2
        pslld     $5, %xmm3                                     #674.2
        psrld     $27, %xmm11                                   #674.2
        pslld     $30, %xmm4                                    #674.2
        psrld     $2, %xmm8                                     #674.2
        paddd     %xmm10, %xmm15                                #674.2
        por       %xmm11, %xmm3                                 #674.2
        por       %xmm8, %xmm4                                  #674.2
        paddd     %xmm3, %xmm15                                 #674.2
        movdqa    %xmm6, %xmm3                                  #674.2
        movdqa    %xmm4, %xmm8                                  #675.2
        paddd     %xmm9, %xmm0                                  #674.2
        pslld     $30, %xmm3                                    #674.2
        psrld     $2, %xmm6                                     #674.2
        pxor      %xmm13, %xmm8                                 #675.2
        paddd     1056(%rdi), %xmm0                             #674.2
        por       %xmm6, %xmm3                                  #674.2
        pxor      %xmm5, %xmm8                                  #675.2
        movdqa    %xmm0, %xmm1                                  #675.2
        paddd     %xmm8, %xmm14                                 #675.2
        movdqa    %xmm0, %xmm6                                  #675.2
        movdqa    %xmm3, %xmm8                                  #675.2
        pslld     $5, %xmm1                                     #675.2
        psrld     $27, %xmm6                                    #675.2
        pxor      %xmm7, %xmm8                                  #675.2
        por       %xmm6, %xmm1                                  #675.2
        pxor      %xmm2, %xmm8                                  #675.2
        paddd     %xmm1, %xmm14                                 #675.2
        paddd     %xmm8, %xmm12                                 #675.2
        movdqa    %xmm5, %xmm1                                  #675.2
        movdqa    %xmm2, %xmm8                                  #675.2
        paddd     %xmm9, %xmm15                                 #674.2
        pslld     $30, %xmm1                                    #675.2
        psrld     $2, %xmm5                                     #675.2
        pslld     $30, %xmm8                                    #675.2
        psrld     $2, %xmm2                                     #675.2
        por       %xmm5, %xmm1                                  #675.2
        paddd     2336(%rdi), %xmm15                            #674.2
        por       %xmm2, %xmm8                                  #675.2
        movdqa    %xmm15, %xmm11                                #675.2
        movdqa    %xmm15, %xmm10                                #675.2
        movdqa    %xmm1, %xmm5                                  #676.2
        movdqa    %xmm8, %xmm6                                  #676.2
        paddd     %xmm9, %xmm14                                 #675.2
        pslld     $5, %xmm11                                    #675.2
        psrld     $27, %xmm10                                   #675.2
        pxor      %xmm4, %xmm5                                  #676.2
        pxor      %xmm3, %xmm6                                  #676.2
        por       %xmm10, %xmm11                                #675.2
        paddd     1072(%rdi), %xmm14                            #675.2
        pxor      %xmm0, %xmm5                                  #676.2
        pxor      %xmm15, %xmm6                                 #676.2
        paddd     %xmm11, %xmm12                                #675.2
        paddd     %xmm5, %xmm13                                 #676.2
        movdqa    %xmm14, %xmm5                                 #676.2
        movdqa    %xmm14, %xmm2                                 #676.2
        paddd     %xmm6, %xmm7                                  #676.2
        movdqa    %xmm0, %xmm6                                  #676.2
        paddd     %xmm9, %xmm12                                 #675.2
        pslld     $5, %xmm5                                     #676.2
        psrld     $27, %xmm2                                    #676.2
        pslld     $30, %xmm6                                    #676.2
        psrld     $2, %xmm0                                     #676.2
        paddd     2352(%rdi), %xmm12                            #675.2
        por       %xmm2, %xmm5                                  #676.2
        por       %xmm0, %xmm6                                  #676.2
        paddd     %xmm5, %xmm13                                 #676.2
        movdqa    %xmm12, %xmm11                                #676.2
        movdqa    %xmm12, %xmm10                                #676.2
        movdqa    %xmm15, %xmm5                                 #676.2
        movdqa    %xmm6, %xmm0                                  #677.2
        paddd     %xmm9, %xmm13                                 #676.2
        pslld     $5, %xmm11                                    #676.2
        psrld     $27, %xmm10                                   #676.2
        pslld     $30, %xmm5                                    #676.2
        psrld     $2, %xmm15                                    #676.2
        pxor      %xmm1, %xmm0                                  #677.2
        paddd     1088(%rdi), %xmm13                            #676.2
        por       %xmm10, %xmm11                                #676.2
        por       %xmm15, %xmm5                                 #676.2
        pxor      %xmm14, %xmm0                                 #677.2
        paddd     %xmm11, %xmm7                                 #676.2
        paddd     %xmm0, %xmm4                                  #677.2
        movdqa    %xmm13, %xmm0                                 #677.2
        movdqa    %xmm13, %xmm15                                #677.2
        movdqa    %xmm5, %xmm2                                  #677.2
        paddd     %xmm9, %xmm7                                  #676.2
        pslld     $5, %xmm0                                     #677.2
        psrld     $27, %xmm15                                   #677.2
        pxor      %xmm8, %xmm2                                  #677.2
        por       %xmm15, %xmm0                                 #677.2
        paddd     2368(%rdi), %xmm7                             #676.2
        pxor      %xmm12, %xmm2                                 #677.2
        paddd     %xmm0, %xmm4                                  #677.2
        paddd     %xmm2, %xmm3                                  #677.2
        movdqa    %xmm7, %xmm11                                 #677.2
        movdqa    %xmm7, %xmm10                                 #677.2
        movdqa    %xmm14, %xmm2                                 #677.2
        movdqa    %xmm12, %xmm0                                 #677.2
        pslld     $5, %xmm11                                    #677.2
        psrld     $27, %xmm10                                   #677.2
        pslld     $30, %xmm2                                    #677.2
        psrld     $2, %xmm14                                    #677.2
        pslld     $30, %xmm0                                    #677.2
        psrld     $2, %xmm12                                    #677.2
        paddd     %xmm9, %xmm4                                  #677.2
        por       %xmm10, %xmm11                                #677.2
        por       %xmm14, %xmm2                                 #677.2
        por       %xmm12, %xmm0                                 #677.2
        paddd     1104(%rdi), %xmm4                             #677.2
        paddd     %xmm11, %xmm3                                 #677.2
        movdqa    %xmm2, %xmm12                                 #678.2
        movdqa    %xmm0, %xmm11                                 #678.2
        paddd     %xmm9, %xmm3                                  #677.2
        pxor      %xmm6, %xmm12                                 #678.2
        movdqa    %xmm4, %xmm10                                 #678.2
        movdqa    %xmm4, %xmm14                                 #678.2
        pxor      %xmm5, %xmm11                                 #678.2
        pxor      %xmm13, %xmm12                                #678.2
        paddd     2384(%rdi), %xmm3                             #677.2
        pslld     $5, %xmm10                                    #678.2
        psrld     $27, %xmm14                                   #678.2
        pxor      %xmm7, %xmm11                                 #678.2
        paddd     %xmm12, %xmm1                                 #678.2
        por       %xmm14, %xmm10                                #678.2
        paddd     %xmm11, %xmm8                                 #678.2
        movdqa    %xmm3, %xmm15                                 #678.2
        movdqa    %xmm3, %xmm12                                 #678.2
        movdqa    %xmm13, %xmm11                                #678.2
        paddd     %xmm10, %xmm1                                 #678.2
        pslld     $5, %xmm15                                    #678.2
        psrld     $27, %xmm12                                   #678.2
        pslld     $30, %xmm11                                   #678.2
        psrld     $2, %xmm13                                    #678.2
        movdqa    %xmm7, %xmm10                                 #678.2
        por       %xmm12, %xmm15                                #678.2
        por       %xmm13, %xmm11                                #678.2
        pslld     $30, %xmm10                                   #678.2
        psrld     $2, %xmm7                                     #678.2
        paddd     %xmm9, %xmm1                                  #678.2
        paddd     %xmm15, %xmm8                                 #678.2
        por       %xmm7, %xmm10                                 #678.2
        movdqa    %xmm11, %xmm7                                 #679.2
        paddd     1120(%rdi), %xmm1                             #678.2
        paddd     %xmm9, %xmm8                                  #678.2
        pxor      %xmm2, %xmm7                                  #679.2
        movdqa    %xmm1, %xmm13                                 #679.2
        paddd     2400(%rdi), %xmm8                             #678.2
        pxor      %xmm4, %xmm7                                  #679.2
        movdqa    %xmm1, %xmm12                                 #679.2
        movdqa    %xmm10, %xmm14                                #679.2
        paddd     %xmm7, %xmm6                                  #679.2
        pslld     $5, %xmm13                                    #679.2
        psrld     $27, %xmm12                                   #679.2
        pxor      %xmm0, %xmm14                                 #679.2
        movdqa    %xmm8, %xmm7                                  #679.2
        movdqa    %xmm8, %xmm15                                 #679.2
        por       %xmm12, %xmm13                                #679.2
        pxor      %xmm3, %xmm14                                 #679.2
        pslld     $5, %xmm7                                     #679.2
        psrld     $27, %xmm15                                   #679.2
        paddd     %xmm13, %xmm6                                 #679.2
        paddd     %xmm14, %xmm5                                 #679.2
        por       %xmm15, %xmm7                                 #679.2
        paddd     %xmm9, %xmm6                                  #679.2
        paddd     %xmm7, %xmm5                                  #679.2
        movdqa    2416(%rdi), %xmm7                             #561.6
        paddd     %xmm9, %xmm5                                  #679.2
        paddd     1136(%rdi), %xmm6                             #679.2
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm11
..B9.15:                        # Preds ..B9.16
        paddd     %xmm7, %xmm5                                  #679.2
        movdqa    %xmm4, %xmm7                                  #679.2
        pslld     $30, %xmm7                                    #679.2
        psrld     $2, %xmm4                                     #679.2
        por       %xmm4, %xmm7                                  #679.2
        movdqa    %xmm11, %xmm12                                #680.2
        movdqa    %xmm3, %xmm4                                  #679.2
        pxor      %xmm7, %xmm12                                 #680.2
        movdqa    %xmm6, %xmm13                                 #680.2
        movdqa    %xmm6, %xmm14                                 #680.2
        pslld     $30, %xmm4                                    #679.2
        psrld     $2, %xmm3                                     #679.2
        pxor      %xmm1, %xmm12                                 #680.2
        pslld     $5, %xmm13                                    #680.2
        psrld     $27, %xmm14                                   #680.2
        por       %xmm3, %xmm4                                  #679.2
        paddd     %xmm12, %xmm2                                 #680.2
        por       %xmm14, %xmm13                                #680.2
        movdqa    %xmm10, %xmm15                                #680.2
        movdqa    %xmm1, %xmm3                                  #680.2
        paddd     %xmm13, %xmm2                                 #680.2
        pxor      %xmm4, %xmm15                                 #680.2
        movdqa    %xmm5, %xmm14                                 #680.2
        movdqa    %xmm5, %xmm12                                 #680.2
        pslld     $30, %xmm3                                    #680.2
        psrld     $2, %xmm1                                     #680.2
        paddd     %xmm9, %xmm2                                  #680.2
        pxor      %xmm8, %xmm15                                 #680.2
        pslld     $5, %xmm14                                    #680.2
        psrld     $27, %xmm12                                   #680.2
        por       %xmm1, %xmm3                                  #680.2
        movdqa    %xmm8, %xmm1                                  #680.2
        paddd     1152(%rdi), %xmm2                             #680.2
        paddd     %xmm15, %xmm0                                 #680.2
        por       %xmm12, %xmm14                                #680.2
        pslld     $30, %xmm1                                    #680.2
        psrld     $2, %xmm8                                     #680.2
        paddd     %xmm14, %xmm0                                 #680.2
        por       %xmm8, %xmm1                                  #680.2
        movdqa    %xmm3, %xmm13                                 #681.2
        movdqa    %xmm2, %xmm12                                 #681.2
        movdqa    %xmm2, %xmm8                                  #681.2
        paddd     %xmm9, %xmm0                                  #680.2
        pxor      %xmm7, %xmm13                                 #681.2
        pslld     $5, %xmm12                                    #681.2
        psrld     $27, %xmm8                                    #681.2
        paddd     2432(%rdi), %xmm0                             #680.2
        pxor      %xmm6, %xmm13                                 #681.2
        por       %xmm8, %xmm12                                 #681.2
        movdqa    %xmm1, %xmm14                                 #681.2
        movdqa    %xmm6, %xmm8                                  #681.2
        paddd     %xmm13, %xmm11                                #681.2
        pxor      %xmm4, %xmm14                                 #681.2
        movdqa    %xmm0, %xmm15                                 #681.2
        movdqa    %xmm0, %xmm13                                 #681.2
        pslld     $30, %xmm8                                    #681.2
        psrld     $2, %xmm6                                     #681.2
        pxor      %xmm5, %xmm14                                 #681.2
        pslld     $5, %xmm15                                    #681.2
        psrld     $27, %xmm13                                   #681.2
        por       %xmm6, %xmm8                                  #681.2
        movdqa    %xmm5, %xmm6                                  #681.2
        paddd     %xmm14, %xmm10                                #681.2
        por       %xmm13, %xmm15                                #681.2
        pslld     $30, %xmm6                                    #681.2
        psrld     $2, %xmm5                                     #681.2
        paddd     %xmm15, %xmm10                                #681.2
        por       %xmm5, %xmm6                                  #681.2
        movdqa    %xmm8, %xmm5                                  #682.2
        paddd     %xmm12, %xmm11                                #681.2
        paddd     %xmm9, %xmm10                                 #681.2
        pxor      %xmm3, %xmm5                                  #682.2
        paddd     2448(%rdi), %xmm10                            #681.2
        paddd     %xmm9, %xmm11                                 #681.2
        pxor      %xmm2, %xmm5                                  #682.2
        movdqa    %xmm6, %xmm13                                 #682.2
        paddd     1168(%rdi), %xmm11                            #681.2
        paddd     %xmm5, %xmm7                                  #682.2
        pxor      %xmm1, %xmm13                                 #682.2
        movdqa    %xmm10, %xmm5                                 #682.2
        movdqa    %xmm10, %xmm15                                #682.2
        movdqa    %xmm11, %xmm14                                #682.2
        movdqa    %xmm11, %xmm12                                #682.2
        pxor      %xmm0, %xmm13                                 #682.2
        pslld     $5, %xmm5                                     #682.2
        psrld     $27, %xmm15                                   #682.2
        pslld     $5, %xmm14                                    #682.2
        psrld     $27, %xmm12                                   #682.2
        paddd     %xmm13, %xmm4                                 #682.2
        por       %xmm15, %xmm5                                 #682.2
        por       %xmm12, %xmm14                                #682.2
        paddd     %xmm5, %xmm4                                  #682.2
        movdqa    %xmm2, %xmm5                                  #682.2
        paddd     %xmm14, %xmm7                                 #682.2
        pslld     $30, %xmm5                                    #682.2
        psrld     $2, %xmm2                                     #682.2
        paddd     %xmm9, %xmm7                                  #682.2
        por       %xmm2, %xmm5                                  #682.2
        movdqa    %xmm0, %xmm2                                  #682.2
        psrld     $2, %xmm0                                     #682.2
        paddd     1184(%rdi), %xmm7                             #682.2
        pslld     $30, %xmm2                                    #682.2
        paddd     %xmm9, %xmm4                                  #682.2
        por       %xmm0, %xmm2                                  #682.2
        movdqa    %xmm7, %xmm14                                 #683.2
        movdqa    %xmm7, %xmm12                                 #683.2
        paddd     2464(%rdi), %xmm4                             #682.2
        pslld     $5, %xmm14                                    #683.2
        psrld     $27, %xmm12                                   #683.2
        movdqa    %xmm2, %xmm13                                 #683.2
        por       %xmm12, %xmm14                                #683.2
        pxor      %xmm6, %xmm13                                 #683.2
        movdqa    %xmm4, %xmm12                                 #683.2
        movdqa    %xmm4, %xmm15                                 #683.2
        pxor      %xmm10, %xmm13                                #683.2
        pslld     $5, %xmm12                                    #683.2
        psrld     $27, %xmm15                                   #683.2
        movdqa    %xmm5, %xmm0                                  #683.2
        paddd     %xmm13, %xmm1                                 #683.2
        por       %xmm15, %xmm12                                #683.2
        pxor      %xmm8, %xmm0                                  #683.2
        paddd     %xmm12, %xmm1                                 #683.2
        movdqa    %xmm11, %xmm12                                #683.2
        pxor      %xmm11, %xmm0                                 #683.2
        pslld     $30, %xmm12                                   #683.2
        psrld     $2, %xmm11                                    #683.2
        por       %xmm11, %xmm12                                #683.2
        movdqa    %xmm10, %xmm11                                #683.2
        pslld     $30, %xmm11                                   #683.2
        psrld     $2, %xmm10                                    #683.2
        paddd     %xmm0, %xmm3                                  #683.2
        por       %xmm10, %xmm11                                #683.2
        movdqa    %xmm12, %xmm10                                #684.2
        paddd     %xmm14, %xmm3                                 #683.2
        paddd     %xmm9, %xmm1                                  #683.2
        pxor      %xmm5, %xmm10                                 #684.2
        paddd     2480(%rdi), %xmm1                             #683.2
        paddd     %xmm9, %xmm3                                  #683.2
        pxor      %xmm7, %xmm10                                 #684.2
        movdqa    %xmm11, %xmm13                                #684.2
        paddd     1200(%rdi), %xmm3                             #683.2
        paddd     %xmm10, %xmm8                                 #684.2
        pxor      %xmm2, %xmm13                                 #684.2
        movdqa    %xmm1, %xmm10                                 #684.2
        movdqa    %xmm1, %xmm15                                 #684.2
        movdqa    %xmm3, %xmm14                                 #684.2
        movdqa    %xmm3, %xmm0                                  #684.2
        pxor      %xmm4, %xmm13                                 #684.2
        pslld     $5, %xmm10                                    #684.2
        psrld     $27, %xmm15                                   #684.2
        pslld     $5, %xmm14                                    #684.2
        psrld     $27, %xmm0                                    #684.2
        paddd     %xmm13, %xmm6                                 #684.2
        por       %xmm15, %xmm10                                #684.2
        por       %xmm0, %xmm14                                 #684.2
        paddd     %xmm10, %xmm6                                 #684.2
        movdqa    %xmm7, %xmm10                                 #684.2
        paddd     %xmm14, %xmm8                                 #684.2
        pslld     $30, %xmm10                                   #684.2
        psrld     $2, %xmm7                                     #684.2
        paddd     %xmm9, %xmm8                                  #684.2
        por       %xmm7, %xmm10                                 #684.2
        movdqa    %xmm4, %xmm7                                  #684.2
        psrld     $2, %xmm4                                     #684.2
        paddd     1216(%rdi), %xmm8                             #684.2
        pslld     $30, %xmm7                                    #684.2
        paddd     %xmm9, %xmm6                                  #684.2
        por       %xmm4, %xmm7                                  #684.2
        movdqa    %xmm8, %xmm14                                 #685.2
        movdqa    %xmm8, %xmm0                                  #685.2
        paddd     2496(%rdi), %xmm6                             #684.2
        pslld     $5, %xmm14                                    #685.2
        psrld     $27, %xmm0                                    #685.2
        movdqa    %xmm7, %xmm13                                 #685.2
        movdqa    %xmm10, %xmm4                                 #685.2
        por       %xmm0, %xmm14                                 #685.2
        pxor      %xmm11, %xmm13                                #685.2
        movdqa    %xmm6, %xmm0                                  #685.2
        movdqa    %xmm6, %xmm15                                 #685.2
        pxor      %xmm12, %xmm4                                 #685.2
        pxor      %xmm1, %xmm13                                 #685.2
        pslld     $5, %xmm0                                     #685.2
        psrld     $27, %xmm15                                   #685.2
        pxor      %xmm3, %xmm4                                  #685.2
        paddd     %xmm13, %xmm2                                 #685.2
        por       %xmm15, %xmm0                                 #685.2
        paddd     %xmm4, %xmm5                                  #685.2
        paddd     %xmm0, %xmm2                                  #685.2
        movdqa    %xmm3, %xmm0                                  #685.2
        paddd     %xmm14, %xmm5                                 #685.2
        pslld     $30, %xmm0                                    #685.2
        psrld     $2, %xmm3                                     #685.2
        movdqa    %xmm1, %xmm14                                 #685.2
        paddd     %xmm9, %xmm5                                  #685.2
        por       %xmm3, %xmm0                                  #685.2
        pslld     $30, %xmm14                                   #685.2
        psrld     $2, %xmm1                                     #685.2
        paddd     %xmm9, %xmm2                                  #685.2
        paddd     1232(%rdi), %xmm5                             #685.2
        por       %xmm1, %xmm14                                 #685.2
        movdqa    %xmm0, %xmm1                                  #686.2
        movdqa    %xmm5, %xmm4                                  #686.2
        pxor      %xmm10, %xmm1                                 #686.2
        movdqa    %xmm5, %xmm3                                  #686.2
        paddd     2512(%rdi), %xmm2                             #685.2
        pxor      %xmm8, %xmm1                                  #686.2
        pslld     $5, %xmm4                                     #686.2
        psrld     $27, %xmm3                                    #686.2
        movdqa    %xmm14, %xmm13                                #686.2
        paddd     %xmm1, %xmm12                                 #686.2
        por       %xmm3, %xmm4                                  #686.2
        pxor      %xmm7, %xmm13                                 #686.2
        movdqa    %xmm2, %xmm15                                 #686.2
        movdqa    %xmm2, %xmm1                                  #686.2
        paddd     %xmm4, %xmm12                                 #686.2
        pxor      %xmm6, %xmm13                                 #686.2
        pslld     $5, %xmm15                                    #686.2
        psrld     $27, %xmm1                                    #686.2
        paddd     %xmm9, %xmm12                                 #686.2
        paddd     %xmm13, %xmm11                                #686.2
        por       %xmm1, %xmm15                                 #686.2
        movdqa    %xmm8, %xmm13                                 #686.2
        movdqa    %xmm6, %xmm4                                  #686.2
        paddd     %xmm15, %xmm11                                #686.2
        paddd     1248(%rdi), %xmm12                            #686.2
        pslld     $30, %xmm13                                   #686.2
        psrld     $2, %xmm8                                     #686.2
        pslld     $30, %xmm4                                    #686.2
        psrld     $2, %xmm6                                     #686.2
        paddd     %xmm9, %xmm11                                 #686.2
        por       %xmm8, %xmm13                                 #686.2
        por       %xmm6, %xmm4                                  #686.2
        movdqa    %xmm12, %xmm3                                 #687.2
        movdqa    %xmm12, %xmm1                                 #687.2
        paddd     2528(%rdi), %xmm11                            #686.2
        movdqa    %xmm13, %xmm6                                 #687.2
        pslld     $5, %xmm3                                     #687.2
        psrld     $27, %xmm1                                    #687.2
        movdqa    %xmm4, %xmm8                                  #687.2
        pxor      %xmm0, %xmm6                                  #687.2
        por       %xmm1, %xmm3                                  #687.2
        pxor      %xmm14, %xmm8                                 #687.2
        movdqa    %xmm11, %xmm1                                 #687.2
        movdqa    %xmm11, %xmm15                                #687.2
        pxor      %xmm5, %xmm6                                  #687.2
        pxor      %xmm2, %xmm8                                  #687.2
        pslld     $5, %xmm1                                     #687.2
        psrld     $27, %xmm15                                   #687.2
        paddd     %xmm6, %xmm10                                 #687.2
        paddd     %xmm8, %xmm7                                  #687.2
        por       %xmm15, %xmm1                                 #687.2
        paddd     %xmm3, %xmm10                                 #687.2
        paddd     %xmm1, %xmm7                                  #687.2
        movdqa    %xmm5, %xmm3                                  #687.2
        movdqa    %xmm2, %xmm1                                  #687.2
        paddd     %xmm9, %xmm10                                 #687.2
        paddd     %xmm9, %xmm7                                  #687.2
        pslld     $30, %xmm3                                    #687.2
        psrld     $2, %xmm5                                     #687.2
        pslld     $30, %xmm1                                    #687.2
        psrld     $2, %xmm2                                     #687.2
        por       %xmm5, %xmm3                                  #687.2
        paddd     2544(%rdi), %xmm7                             #687.2
        por       %xmm2, %xmm1                                  #687.2
        paddd     1264(%rdi), %xmm10                            #687.2
        je        ..B9.11       # Prob 12%                      #689.6
                                # LOE rdx rbx rbp rsi r12 r13 r14 r15 ecx xmm0 xmm1 xmm3 xmm4 xmm7 xmm10 xmm11 xmm12 xmm13 xmm14
..B9.6:                         # Preds ..B9.15
        movdqa    (%rdx), %xmm2                                 #561.6
        movdqa    16(%rdx), %xmm5                               #561.6
        paddd     %xmm2, %xmm10                                 #704.11
        movdqa    32(%rdx), %xmm6                               #561.6
        paddd     %xmm5, %xmm12                                 #705.11
        movdqa    48(%rdx), %xmm8                               #561.6
        paddd     %xmm6, %xmm3                                  #706.11
        movdqa    64(%rdx), %xmm9                               #561.6
        paddd     %xmm8, %xmm13                                 #707.11
        movdqa    80(%rdx), %xmm15                              #561.6
        paddd     %xmm9, %xmm0                                  #708.11
        movdqa    96(%rdx), %xmm2                               #561.6
        paddd     %xmm15, %xmm7                                 #704.11
        movdqa    112(%rdx), %xmm5                              #561.6
        paddd     %xmm2, %xmm11                                 #705.11
        movdqa    128(%rdx), %xmm6                              #561.6
        paddd     %xmm5, %xmm1                                  #706.11
        movdqa    144(%rdx), %xmm8                              #561.6
        paddd     %xmm6, %xmm4                                  #707.11
        paddd     %xmm8, %xmm14                                 #708.11
                                # LOE rbx rbp rsi r12 r13 r14 r15 ecx xmm0 xmm1 xmm3 xmm4 xmm7 xmm10 xmm11 xmm12 xmm13 xmm14
..B9.7:                         # Preds ..B9.11 ..B9.6
        movdqa    %xmm10, (%rsi)                                #561.6
        testl     %ecx, %ecx                                    #711.6
        movdqa    %xmm12, 16(%rsi)                              #561.6
        movdqa    %xmm3, 32(%rsi)                               #561.6
        movdqa    %xmm13, 48(%rsi)                              #561.6
        movdqa    %xmm0, 64(%rsi)                               #561.6
        je        ..B9.9        # Prob 50%                      #711.6
                                # LOE rbx rbp rsi r12 r13 r14 r15 xmm1 xmm4 xmm7 xmm11 xmm14
..B9.8:                         # Preds ..B9.7
        movdqa    %xmm7, 1280(%rsi)                             #561.6
        movdqa    %xmm11, 1296(%rsi)                            #561.6
        movdqa    %xmm1, 1312(%rsi)                             #561.6
        movdqa    %xmm4, 1328(%rsi)                             #561.6
        movdqa    %xmm14, 1344(%rsi)                            #561.6
        ret                                                     #561.6
                                # LOE rbx rbp r12 r13 r14 r15
..B9.9:                         # Preds ..B9.7
        movdqa    %xmm7, 80(%rsi)                               #561.6
        movdqa    %xmm11, 96(%rsi)                              #561.6
        movdqa    %xmm1, 112(%rsi)                              #561.6
        movdqa    %xmm4, 128(%rsi)                              #561.6
        movdqa    %xmm14, 144(%rsi)                             #561.6
                                # LOE rbx rbp r12 r13 r14 r15
..B9.10:                        # Preds ..B9.9
        ret                                                     #733.1
                                # LOE
..B9.11:                        # Preds ..B9.15                 # Infreq
        movdqa    .L_2il0floatpacket.498(%rip), %xmm2           #693.11
        movdqa    .L_2il0floatpacket.499(%rip), %xmm5           #694.11
        paddd     %xmm2, %xmm10                                 #693.11
        movdqa    .L_2il0floatpacket.500(%rip), %xmm6           #695.11
        paddd     %xmm5, %xmm12                                 #694.11
        movdqa    .L_2il0floatpacket.501(%rip), %xmm8           #696.11
        paddd     %xmm6, %xmm3                                  #695.11
        movdqa    .L_2il0floatpacket.502(%rip), %xmm9           #697.11
        paddd     %xmm8, %xmm13                                 #696.11
        paddd     %xmm9, %xmm0                                  #697.11
        paddd     %xmm2, %xmm7                                  #693.11
        paddd     %xmm5, %xmm11                                 #694.11
        paddd     %xmm6, %xmm1                                  #695.11
        paddd     %xmm8, %xmm4                                  #696.11
        paddd     %xmm9, %xmm14                                 #697.11
        jmp       ..B9.7        # Prob 100%                     #697.11
                                # LOE rbx rbp rsi r12 r13 r14 r15 ecx xmm0 xmm1 xmm3 xmm4 xmm7 xmm10 xmm11 xmm12 xmm13 xmm14
..B9.12:                        # Preds ..B9.3                  # Infreq
        movdqa    .L_2il0floatpacket.498(%rip), %xmm7           #582.11
        movdqa    .L_2il0floatpacket.499(%rip), %xmm1           #583.11
        movdqa    %xmm7, %xmm10                                 #582.11
        movdqa    .L_2il0floatpacket.500(%rip), %xmm6           #584.11
        movdqa    %xmm1, %xmm5                                  #583.11
        movdqa    .L_2il0floatpacket.501(%rip), %xmm2           #585.11
        movdqa    %xmm6, %xmm9                                  #584.11
        movdqa    .L_2il0floatpacket.502(%rip), %xmm11          #586.11
        movdqa    %xmm2, %xmm3                                  #585.11
        movdqa    %xmm11, %xmm0                                 #586.11
        jmp       ..B9.5        # Prob 100%                     #586.11
        .align    16,0x90
..___tag_value_SSESHA1body.146:                                 #
                                # LOE rdx rbx rbp rsi rdi r12 r13 r14 r15 ecx xmm0 xmm1 xmm2 xmm3 xmm5 xmm6 xmm7 xmm9 xmm10 xmm11
# mark_end;
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
	.space 8	# pad
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
.L_2il0floatpacket.474:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.474,@object
	.size	.L_2il0floatpacket.474,16
	.align 16
.L_2il0floatpacket.475:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.475,@object
	.size	.L_2il0floatpacket.475,16
	.align 16
.L_2il0floatpacket.476:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.476,@object
	.size	.L_2il0floatpacket.476,16
	.align 16
.L_2il0floatpacket.477:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.477,@object
	.size	.L_2il0floatpacket.477,16
	.align 16
.L_2il0floatpacket.478:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.478,@object
	.size	.L_2il0floatpacket.478,16
	.align 16
.L_2il0floatpacket.479:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.479,@object
	.size	.L_2il0floatpacket.479,16
	.align 16
.L_2il0floatpacket.498:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.498,@object
	.size	.L_2il0floatpacket.498,16
	.align 16
.L_2il0floatpacket.499:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.499,@object
	.size	.L_2il0floatpacket.499,16
	.align 16
.L_2il0floatpacket.500:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.500,@object
	.size	.L_2il0floatpacket.500,16
	.align 16
.L_2il0floatpacket.501:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.501,@object
	.size	.L_2il0floatpacket.501,16
	.align 16
.L_2il0floatpacket.502:
	.long	0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0
	.type	.L_2il0floatpacket.502,@object
	.size	.L_2il0floatpacket.502,16
	.align 16
.L_2il0floatpacket.503:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.503,@object
	.size	.L_2il0floatpacket.503,16
	.align 16
.L_2il0floatpacket.504:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.504,@object
	.size	.L_2il0floatpacket.504,16
	.align 16
.L_2il0floatpacket.505:
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
	.type	.L_2il0floatpacket.505,@object
	.size	.L_2il0floatpacket.505,16
	.align 16
.L_2il0floatpacket.506:
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
	.type	.L_2il0floatpacket.506,@object
	.size	.L_2il0floatpacket.506,16
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
	.byte	49
	.byte	36
	.byte	0
	.type	.L_2__STRING.2,@object
	.size	.L_2__STRING.2,4
	.align 4
.L_2__STRING.1:
	.byte	36
	.byte	97
	.byte	112
	.byte	114
	.byte	49
	.byte	36
	.byte	0
	.type	.L_2__STRING.1,@object
	.size	.L_2__STRING.1,7
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
	.4byte 0x00000054
	.4byte 0x00000034
	.8byte ..___tag_value_mmxput.4
	.8byte ..___tag_value_mmxput.18-..___tag_value_mmxput.4
	.byte 0x04
	.4byte ..___tag_value_mmxput.6-..___tag_value_mmxput.4
	.4byte 0x0f09048f
	.2byte 0x040f
	.4byte ..___tag_value_mmxput.8-..___tag_value_mmxput.6
	.4byte 0x03090383
	.2byte 0x0403
	.4byte ..___tag_value_mmxput.10-..___tag_value_mmxput.8
	.8byte 0x8603830606090286
	.4byte 0x04048f02
	.4byte ..___tag_value_mmxput.15-..___tag_value_mmxput.10
	.4byte 0x040f0f09
	.4byte ..___tag_value_mmxput.16-..___tag_value_mmxput.15
	.4byte 0x04030309
	.4byte ..___tag_value_mmxput.17-..___tag_value_mmxput.16
	.4byte 0x00060609
	.2byte 0x0000
	.byte 0x00
	.4byte 0x00000084
	.4byte 0x0000008c
	.8byte ..___tag_value_mmxput2.19
	.8byte ..___tag_value_mmxput2.41-..___tag_value_mmxput2.19
	.byte 0x04
	.4byte ..___tag_value_mmxput2.21-..___tag_value_mmxput2.19
	.4byte 0x070c028c
	.2byte 0x0410
	.4byte ..___tag_value_mmxput2.23-..___tag_value_mmxput2.21
	.4byte 0x070c038d
	.2byte 0x0418
	.4byte ..___tag_value_mmxput2.25-..___tag_value_mmxput2.23
	.4byte 0x070c048e
	.2byte 0x0420
	.4byte ..___tag_value_mmxput2.27-..___tag_value_mmxput2.25
	.4byte 0x070c058f
	.2byte 0x0428
	.4byte ..___tag_value_mmxput2.29-..___tag_value_mmxput2.27
	.4byte 0x070c0683
	.2byte 0x0430
	.4byte ..___tag_value_mmxput2.31-..___tag_value_mmxput2.29
	.4byte 0x04030309
	.4byte ..___tag_value_mmxput2.32-..___tag_value_mmxput2.31
	.4byte 0x0928070c
	.2byte 0x0f0f
	.byte 0x04
	.4byte ..___tag_value_mmxput2.34-..___tag_value_mmxput2.32
	.4byte 0x0920070c
	.2byte 0x0e0e
	.byte 0x04
	.4byte ..___tag_value_mmxput2.36-..___tag_value_mmxput2.34
	.4byte 0x0918070c
	.2byte 0x0d0d
	.byte 0x04
	.4byte ..___tag_value_mmxput2.38-..___tag_value_mmxput2.36
	.4byte 0x0910070c
	.2byte 0x0c0c
	.byte 0x04
	.4byte ..___tag_value_mmxput2.40-..___tag_value_mmxput2.38
	.4byte 0x0008070c
	.byte 0x00
	.4byte 0x000000a4
	.4byte 0x00000114
	.8byte ..___tag_value_dispatch.42
	.8byte ..___tag_value_dispatch.70-..___tag_value_dispatch.42
	.byte 0x04
	.4byte ..___tag_value_dispatch.44-..___tag_value_dispatch.42
	.4byte 0x070c028c
	.2byte 0x0410
	.4byte ..___tag_value_dispatch.46-..___tag_value_dispatch.44
	.4byte 0x070c038d
	.2byte 0x0418
	.4byte ..___tag_value_dispatch.48-..___tag_value_dispatch.46
	.4byte 0x070c048e
	.2byte 0x0420
	.4byte ..___tag_value_dispatch.50-..___tag_value_dispatch.48
	.4byte 0x070c058f
	.2byte 0x0428
	.4byte ..___tag_value_dispatch.52-..___tag_value_dispatch.50
	.4byte 0x070c0683
	.2byte 0x0430
	.4byte ..___tag_value_dispatch.54-..___tag_value_dispatch.52
	.4byte 0x070c0786
	.2byte 0x0438
	.4byte ..___tag_value_dispatch.56-..___tag_value_dispatch.54
	.4byte 0x0450070c
	.4byte ..___tag_value_dispatch.57-..___tag_value_dispatch.56
	.4byte 0x0938070c
	.2byte 0x0606
	.byte 0x04
	.4byte ..___tag_value_dispatch.59-..___tag_value_dispatch.57
	.4byte 0x0930070c
	.2byte 0x0303
	.byte 0x04
	.4byte ..___tag_value_dispatch.61-..___tag_value_dispatch.59
	.4byte 0x0928070c
	.2byte 0x0f0f
	.byte 0x04
	.4byte ..___tag_value_dispatch.63-..___tag_value_dispatch.61
	.4byte 0x0920070c
	.2byte 0x0e0e
	.byte 0x04
	.4byte ..___tag_value_dispatch.65-..___tag_value_dispatch.63
	.4byte 0x0918070c
	.2byte 0x0d0d
	.byte 0x04
	.4byte ..___tag_value_dispatch.67-..___tag_value_dispatch.65
	.4byte 0x0910070c
	.2byte 0x0c0c
	.byte 0x04
	.4byte ..___tag_value_dispatch.69-..___tag_value_dispatch.67
	.4byte 0x0008070c
	.byte 0x00
	.4byte 0x0000009c
	.4byte 0x000001bc
	.8byte ..___tag_value_mmxput3.71
	.8byte ..___tag_value_mmxput3.97-..___tag_value_mmxput3.71
	.byte 0x04
	.4byte ..___tag_value_mmxput3.73-..___tag_value_mmxput3.71
	.4byte 0x070c028c
	.2byte 0x0410
	.4byte ..___tag_value_mmxput3.75-..___tag_value_mmxput3.73
	.4byte 0x070c038d
	.2byte 0x0418
	.4byte ..___tag_value_mmxput3.77-..___tag_value_mmxput3.75
	.4byte 0x070c048e
	.2byte 0x0420
	.4byte ..___tag_value_mmxput3.79-..___tag_value_mmxput3.77
	.4byte 0x070c058f
	.2byte 0x0428
	.4byte ..___tag_value_mmxput3.81-..___tag_value_mmxput3.79
	.4byte 0x070c0683
	.2byte 0x0430
	.4byte ..___tag_value_mmxput3.83-..___tag_value_mmxput3.81
	.4byte 0x070c0786
	.2byte 0x0438
	.4byte ..___tag_value_mmxput3.85-..___tag_value_mmxput3.83
	.4byte 0x04060609
	.4byte ..___tag_value_mmxput3.86-..___tag_value_mmxput3.85
	.4byte 0x0930070c
	.2byte 0x0303
	.byte 0x04
	.4byte ..___tag_value_mmxput3.88-..___tag_value_mmxput3.86
	.4byte 0x0928070c
	.2byte 0x0f0f
	.byte 0x04
	.4byte ..___tag_value_mmxput3.90-..___tag_value_mmxput3.88
	.4byte 0x0920070c
	.2byte 0x0e0e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.92-..___tag_value_mmxput3.90
	.4byte 0x0918070c
	.2byte 0x0d0d
	.byte 0x04
	.4byte ..___tag_value_mmxput3.94-..___tag_value_mmxput3.92
	.4byte 0x0910070c
	.2byte 0x0c0c
	.byte 0x04
	.4byte ..___tag_value_mmxput3.96-..___tag_value_mmxput3.94
	.8byte 0x000000000008070c
	.4byte 0x0000002c
	.4byte 0x0000025c
	.8byte ..___tag_value_SSEmd5body.98
	.8byte ..___tag_value_SSEmd5body.102-..___tag_value_SSEmd5body.98
	.byte 0x04
	.4byte ..___tag_value_SSEmd5body.100-..___tag_value_SSEmd5body.98
	.4byte 0x0690070c
	.byte 0x04
	.4byte ..___tag_value_SSEmd5body.101-..___tag_value_SSEmd5body.100
	.8byte 0x000000000008070c
	.2byte 0x0000
	.4byte 0x000000bc
	.4byte 0x0000028c
	.8byte ..___tag_value_md5cryptsse.103
	.8byte ..___tag_value_md5cryptsse.138-..___tag_value_md5cryptsse.103
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.105-..___tag_value_md5cryptsse.103
	.4byte 0x070c028c
	.2byte 0x0410
	.4byte ..___tag_value_md5cryptsse.107-..___tag_value_md5cryptsse.105
	.4byte 0x070c038d
	.2byte 0x0418
	.4byte ..___tag_value_md5cryptsse.109-..___tag_value_md5cryptsse.107
	.4byte 0x070c048e
	.2byte 0x0420
	.4byte ..___tag_value_md5cryptsse.111-..___tag_value_md5cryptsse.109
	.4byte 0x070c058f
	.2byte 0x0428
	.4byte ..___tag_value_md5cryptsse.113-..___tag_value_md5cryptsse.111
	.4byte 0x070c0683
	.2byte 0x0430
	.4byte ..___tag_value_md5cryptsse.115-..___tag_value_md5cryptsse.113
	.4byte 0x070c0786
	.2byte 0x0438
	.4byte ..___tag_value_md5cryptsse.117-..___tag_value_md5cryptsse.115
	.4byte 0x35e0070c
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.118-..___tag_value_md5cryptsse.117
	.4byte 0x0938070c
	.2byte 0x0606
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.120-..___tag_value_md5cryptsse.118
	.4byte 0x0930070c
	.2byte 0x0303
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.122-..___tag_value_md5cryptsse.120
	.4byte 0x0928070c
	.2byte 0x0f0f
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.124-..___tag_value_md5cryptsse.122
	.4byte 0x0920070c
	.2byte 0x0e0e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.126-..___tag_value_md5cryptsse.124
	.4byte 0x0918070c
	.2byte 0x0d0d
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.128-..___tag_value_md5cryptsse.126
	.4byte 0x0910070c
	.2byte 0x0c0c
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.130-..___tag_value_md5cryptsse.128
	.4byte 0x0408070c
	.4byte ..___tag_value_md5cryptsse.131-..___tag_value_md5cryptsse.130
	.8byte 0x0786068335e0070c
	.8byte 0x058f048e038d028c
	.4byte 0x00000000
	.4byte 0x0000002c
	.4byte 0x0000034c
	.8byte ..___tag_value_SSEmd4body.139
	.8byte ..___tag_value_SSEmd4body.143-..___tag_value_SSEmd4body.139
	.byte 0x04
	.4byte ..___tag_value_SSEmd4body.141-..___tag_value_SSEmd4body.139
	.4byte 0x0690070c
	.byte 0x04
	.4byte ..___tag_value_SSEmd4body.142-..___tag_value_SSEmd4body.141
	.8byte 0x000000000008070c
	.2byte 0x0000
	.4byte 0x00000014
	.4byte 0x0000037c
	.8byte ..___tag_value_SSESHA1body.144
	.8byte ..___tag_value_SSESHA1body.146-..___tag_value_SSESHA1body.144
# End
