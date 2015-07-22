	.file "simd-intrinsics.c"
	.text
..TXTST0:
# -- Begin  SIMDmd5body
       .align    16,0x90
	.globl SIMDmd5body
SIMDmd5body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B1.1:
..___tag_value_SIMDmd5body.1:
        subq      $1544, %rsp
..___tag_value_SIMDmd5body.3:
        movl      %ecx, %r8d
        movq      %rdx, %rcx
        testl     $1, %r8d
        pcmpeqd   %xmm0, %xmm0
        je        ..B1.18
..B1.2:
        movl      (%rdi), %eax
        xorl      %edx, %edx
        movl      %eax, (%rsp)
        lea       4(%rsp), %rax
        testl     $256, %r8d
        jne       ..B1.13
..B1.3:
        testl     $64, %r8d
        jne       ..B1.9
        jmp       ..B1.5
..B1.6:
        movl      (%rdi), %r9d
        movl      %r9d, 252(%rax)
        addq      $256, %rax
..B1.5:
        movl      64(%rdi), %r9d
        incl      %edx
        movl      128(%rdi), %r10d
        movl      192(%rdi), %r11d
        movl      %r9d, (%rax)
        movl      %r10d, 4(%rax)
        movl      %r11d, 8(%rax)
        movl      4(%rdi), %r9d
        movl      68(%rdi), %r10d
        movl      132(%rdi), %r11d
        movl      %r9d, 12(%rax)
        movl      %r10d, 16(%rax)
        movl      %r11d, 20(%rax)
        movl      196(%rdi), %r9d
        movl      8(%rdi), %r10d
        movl      72(%rdi), %r11d
        movl      %r9d, 24(%rax)
        movl      %r10d, 28(%rax)
        movl      %r11d, 32(%rax)
        movl      136(%rdi), %r9d
        movl      200(%rdi), %r10d
        movl      12(%rdi), %r11d
        movl      %r9d, 36(%rax)
        movl      %r10d, 40(%rax)
        movl      %r11d, 44(%rax)
        movl      76(%rdi), %r9d
        movl      140(%rdi), %r10d
        movl      204(%rdi), %r11d
        movl      %r9d, 48(%rax)
        movl      %r10d, 52(%rax)
        movl      %r11d, 56(%rax)
        movl      16(%rdi), %r9d
        movl      80(%rdi), %r10d
        movl      144(%rdi), %r11d
        movl      %r9d, 60(%rax)
        movl      %r10d, 64(%rax)
        movl      %r11d, 68(%rax)
        movl      208(%rdi), %r9d
        movl      20(%rdi), %r10d
        movl      84(%rdi), %r11d
        movl      %r9d, 72(%rax)
        movl      %r10d, 76(%rax)
        movl      %r11d, 80(%rax)
        movl      148(%rdi), %r9d
        movl      212(%rdi), %r10d
        movl      24(%rdi), %r11d
        movl      %r9d, 84(%rax)
        movl      %r10d, 88(%rax)
        movl      %r11d, 92(%rax)
        movl      88(%rdi), %r9d
        movl      152(%rdi), %r10d
        .byte     15
        .byte     31
        .byte     64
        .byte     0
        movl      216(%rdi), %r11d
        movl      %r9d, 96(%rax)
        movl      %r10d, 100(%rax)
        movl      %r11d, 104(%rax)
        movl      28(%rdi), %r9d
        movl      92(%rdi), %r10d
        movl      156(%rdi), %r11d
        movl      %r9d, 108(%rax)
        movl      %r10d, 112(%rax)
        movl      %r11d, 116(%rax)
        movl      220(%rdi), %r9d
        movl      32(%rdi), %r10d
        movl      96(%rdi), %r11d
        movl      %r9d, 120(%rax)
        movl      %r10d, 124(%rax)
        movl      %r11d, 128(%rax)
        movl      160(%rdi), %r9d
        movl      224(%rdi), %r10d
        movl      36(%rdi), %r11d
        movl      %r9d, 132(%rax)
        movl      %r10d, 136(%rax)
        movl      %r11d, 140(%rax)
        .byte     15
        .byte     31
        .byte     0
        movl      100(%rdi), %r9d
        movl      164(%rdi), %r10d
        movl      228(%rdi), %r11d
        movl      %r9d, 144(%rax)
        movl      %r10d, 148(%rax)
        movl      %r11d, 152(%rax)
        .byte     144
        movl      40(%rdi), %r9d
        movl      104(%rdi), %r10d
        movl      168(%rdi), %r11d
        movl      %r9d, 156(%rax)
        .byte     15
        .byte     31
        .byte     0
        movl      %r10d, 160(%rax)
        movl      %r11d, 164(%rax)
        movl      232(%rdi), %r9d
        movl      44(%rdi), %r10d
        movl      108(%rdi), %r11d
        movl      %r9d, 168(%rax)
        movl      %r10d, 172(%rax)
        movl      %r11d, 176(%rax)
        .byte     144
        movl      172(%rdi), %r9d
        .byte     15
        .byte     31
        .byte     0
        movl      236(%rdi), %r10d
        movl      48(%rdi), %r11d
        .byte     15
        .byte     31
        .byte     64
        .byte     0
        movl      %r9d, 180(%rax)
        movl      %r10d, 184(%rax)
        movl      %r11d, 188(%rax)
        movl      112(%rdi), %r9d
        movl      176(%rdi), %r10d
        .byte     144
        movl      240(%rdi), %r11d
        .byte     102
        .byte     144
        movl      %r9d, 192(%rax)
        movl      %r10d, 196(%rax)
        movl      %r11d, 200(%rax)
        .byte     144
        movl      52(%rdi), %r9d
        movl      116(%rdi), %r10d
        movl      180(%rdi), %r11d
        movl      %r9d, 204(%rax)
        .byte     15
        .byte     31
        .byte     0
        movl      %r10d, 208(%rax)
        movl      %r11d, 212(%rax)
        movl      244(%rdi), %r9d
        movl      56(%rdi), %r10d
        movl      120(%rdi), %r11d
        movl      %r9d, 216(%rax)
        movl      %r10d, 220(%rax)
        movl      %r11d, 224(%rax)
        movl      184(%rdi), %r9d
        movl      248(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      %r9d, 228(%rax)
        movl      %r10d, 232(%rax)
        movl      %r11d, 236(%rax)
        movl      124(%rdi), %r9d
        movl      188(%rdi), %r10d
        movl      252(%rdi), %r11d
        addq      $256, %rdi
        movl      %r9d, 240(%rax)
        cmpl      $3, %edx
        movl      %r10d, 244(%rax)
        movl      %r11d, 248(%rax)
        jb        ..B1.6
        jmp       ..B1.16
..B1.10:
        movl      (%rdi), %r9d
        movl      %r9d, 252(%rax)
        addq      $256, %rax
..B1.9:
        movl      128(%rdi), %r9d
        incl      %edx
        movl      256(%rdi), %r10d
        movl      384(%rdi), %r11d
        movl      %r9d, (%rax)
        movl      %r10d, 4(%rax)
        movl      %r11d, 8(%rax)
        movl      4(%rdi), %r9d
        movl      132(%rdi), %r10d
        movl      260(%rdi), %r11d
        movl      %r9d, 12(%rax)
        movl      %r10d, 16(%rax)
        movl      %r11d, 20(%rax)
        movl      388(%rdi), %r9d
        movl      8(%rdi), %r10d
        movl      136(%rdi), %r11d
        movl      %r9d, 24(%rax)
        movl      %r10d, 28(%rax)
        movl      %r11d, 32(%rax)
        movl      264(%rdi), %r9d
        movl      392(%rdi), %r10d
        movl      12(%rdi), %r11d
        movl      %r9d, 36(%rax)
        movl      %r10d, 40(%rax)
        movl      %r11d, 44(%rax)
        movl      140(%rdi), %r9d
        movl      268(%rdi), %r10d
        movl      396(%rdi), %r11d
        movl      %r9d, 48(%rax)
        movl      %r10d, 52(%rax)
        movl      %r11d, 56(%rax)
        movl      16(%rdi), %r9d
        movl      144(%rdi), %r10d
        movl      272(%rdi), %r11d
        movl      %r9d, 60(%rax)
        movl      %r10d, 64(%rax)
        movl      %r11d, 68(%rax)
        movl      400(%rdi), %r9d
        movl      20(%rdi), %r10d
        movl      148(%rdi), %r11d
        movl      %r9d, 72(%rax)
        movl      %r10d, 76(%rax)
        movl      %r11d, 80(%rax)
        movl      276(%rdi), %r9d
        movl      404(%rdi), %r10d
        movl      24(%rdi), %r11d
        movl      %r9d, 84(%rax)
        movl      %r10d, 88(%rax)
        movl      %r11d, 92(%rax)
        movl      152(%rdi), %r9d
        movl      280(%rdi), %r10d
        movl      408(%rdi), %r11d
        movl      %r9d, 96(%rax)
        movl      %r10d, 100(%rax)
        movl      %r11d, 104(%rax)
        movl      28(%rdi), %r9d
        movl      156(%rdi), %r10d
        movl      284(%rdi), %r11d
        movl      %r9d, 108(%rax)
        movl      %r10d, 112(%rax)
        movl      %r11d, 116(%rax)
        movl      412(%rdi), %r9d
        movl      32(%rdi), %r10d
        movl      160(%rdi), %r11d
        movl      %r9d, 120(%rax)
        movl      %r10d, 124(%rax)
        movl      %r11d, 128(%rax)
        movl      288(%rdi), %r9d
        movl      416(%rdi), %r10d
        movl      36(%rdi), %r11d
        movl      %r9d, 132(%rax)
        movl      %r10d, 136(%rax)
        movl      %r11d, 140(%rax)
        movl      164(%rdi), %r9d
        movl      292(%rdi), %r10d
        movl      420(%rdi), %r11d
        movl      %r9d, 144(%rax)
        movl      %r10d, 148(%rax)
        movl      %r11d, 152(%rax)
        movl      40(%rdi), %r9d
        movl      168(%rdi), %r10d
        movl      296(%rdi), %r11d
        movl      %r9d, 156(%rax)
        movl      %r10d, 160(%rax)
        movl      %r11d, 164(%rax)
        movl      424(%rdi), %r9d
        movl      44(%rdi), %r10d
        movl      172(%rdi), %r11d
        movl      %r9d, 168(%rax)
        movl      %r10d, 172(%rax)
        movl      %r11d, 176(%rax)
        movl      300(%rdi), %r9d
        movl      428(%rdi), %r10d
        movl      48(%rdi), %r11d
        movl      %r9d, 180(%rax)
        movl      %r10d, 184(%rax)
        movl      %r11d, 188(%rax)
        movl      176(%rdi), %r9d
        movl      304(%rdi), %r10d
        movl      432(%rdi), %r11d
        movl      %r9d, 192(%rax)
        movl      %r10d, 196(%rax)
        movl      %r11d, 200(%rax)
        movl      52(%rdi), %r9d
        movl      180(%rdi), %r10d
        movl      308(%rdi), %r11d
        movl      %r9d, 204(%rax)
        movl      %r10d, 208(%rax)
        movl      %r11d, 212(%rax)
        movl      436(%rdi), %r9d
        movl      56(%rdi), %r10d
        movl      184(%rdi), %r11d
        movl      %r9d, 216(%rax)
        movl      %r10d, 220(%rax)
        movl      %r11d, 224(%rax)
        movl      312(%rdi), %r9d
        movl      440(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      %r9d, 228(%rax)
        movl      %r10d, 232(%rax)
        movl      %r11d, 236(%rax)
        movl      188(%rdi), %r9d
        movl      316(%rdi), %r10d
        movl      444(%rdi), %r11d
        addq      $512, %rdi
        movl      %r9d, 240(%rax)
        cmpl      $3, %edx
        movl      %r10d, 244(%rax)
        movl      %r11d, 248(%rax)
        jb        ..B1.10
        jmp       ..B1.16
..B1.14:
        movl      (%rdi), %r9d
        movl      %r9d, 252(%rax)
        addq      $256, %rax
..B1.13:
        movl      256(%rdi), %r9d
        incl      %edx
        movl      512(%rdi), %r10d
        movl      768(%rdi), %r11d
        movl      %r9d, (%rax)
        movl      %r10d, 4(%rax)
        movl      %r11d, 8(%rax)
        movl      4(%rdi), %r9d
        movl      260(%rdi), %r10d
        movl      516(%rdi), %r11d
        movl      %r9d, 12(%rax)
        movl      %r10d, 16(%rax)
        movl      %r11d, 20(%rax)
        movl      772(%rdi), %r9d
        movl      8(%rdi), %r10d
        movl      264(%rdi), %r11d
        movl      %r9d, 24(%rax)
        movl      %r10d, 28(%rax)
        movl      %r11d, 32(%rax)
        movl      520(%rdi), %r9d
        movl      776(%rdi), %r10d
        movl      12(%rdi), %r11d
        movl      %r9d, 36(%rax)
        movl      %r10d, 40(%rax)
        movl      %r11d, 44(%rax)
        movl      268(%rdi), %r9d
        movl      524(%rdi), %r10d
        movl      780(%rdi), %r11d
        movl      %r9d, 48(%rax)
        movl      %r10d, 52(%rax)
        movl      %r11d, 56(%rax)
        movl      16(%rdi), %r9d
        movl      272(%rdi), %r10d
        movl      528(%rdi), %r11d
        movl      %r9d, 60(%rax)
        movl      %r10d, 64(%rax)
        movl      %r11d, 68(%rax)
        movl      784(%rdi), %r9d
        movl      20(%rdi), %r10d
        movl      276(%rdi), %r11d
        movl      %r9d, 72(%rax)
        movl      %r10d, 76(%rax)
        movl      %r11d, 80(%rax)
        movl      532(%rdi), %r9d
        movl      788(%rdi), %r10d
        movl      24(%rdi), %r11d
        movl      %r9d, 84(%rax)
        movl      %r10d, 88(%rax)
        movl      %r11d, 92(%rax)
        movl      280(%rdi), %r9d
        movl      536(%rdi), %r10d
        movl      792(%rdi), %r11d
        movl      %r9d, 96(%rax)
        movl      %r10d, 100(%rax)
        movl      %r11d, 104(%rax)
        movl      28(%rdi), %r9d
        movl      284(%rdi), %r10d
        movl      540(%rdi), %r11d
        movl      %r9d, 108(%rax)
        movl      %r10d, 112(%rax)
        movl      %r11d, 116(%rax)
        movl      796(%rdi), %r9d
        movl      32(%rdi), %r10d
        movl      288(%rdi), %r11d
        movl      %r9d, 120(%rax)
        movl      %r10d, 124(%rax)
        movl      %r11d, 128(%rax)
        movl      544(%rdi), %r9d
        movl      800(%rdi), %r10d
        movl      36(%rdi), %r11d
        movl      %r9d, 132(%rax)
        movl      %r10d, 136(%rax)
        movl      %r11d, 140(%rax)
        movl      292(%rdi), %r9d
        movl      548(%rdi), %r10d
        movl      804(%rdi), %r11d
        movl      %r9d, 144(%rax)
        movl      %r10d, 148(%rax)
        movl      %r11d, 152(%rax)
        movl      40(%rdi), %r9d
        movl      296(%rdi), %r10d
        movl      552(%rdi), %r11d
        movl      %r9d, 156(%rax)
        movl      %r10d, 160(%rax)
        movl      %r11d, 164(%rax)
        movl      808(%rdi), %r9d
        movl      44(%rdi), %r10d
        movl      300(%rdi), %r11d
        movl      %r9d, 168(%rax)
        movl      %r10d, 172(%rax)
        movl      %r11d, 176(%rax)
        movl      556(%rdi), %r9d
        movl      812(%rdi), %r10d
        movl      48(%rdi), %r11d
        movl      %r9d, 180(%rax)
        movl      %r10d, 184(%rax)
        movl      %r11d, 188(%rax)
        movl      304(%rdi), %r9d
        movl      560(%rdi), %r10d
        movl      816(%rdi), %r11d
        movl      %r9d, 192(%rax)
        movl      %r10d, 196(%rax)
        movl      %r11d, 200(%rax)
        movl      52(%rdi), %r9d
        movl      308(%rdi), %r10d
        movl      564(%rdi), %r11d
        movl      %r9d, 204(%rax)
        movl      %r10d, 208(%rax)
        movl      %r11d, 212(%rax)
        movl      820(%rdi), %r9d
        movl      56(%rdi), %r10d
        movl      312(%rdi), %r11d
        movl      %r9d, 216(%rax)
        movl      %r10d, 220(%rax)
        movl      %r11d, 224(%rax)
        movl      568(%rdi), %r9d
        movl      824(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      %r9d, 228(%rax)
        movl      %r10d, 232(%rax)
        movl      %r11d, 236(%rax)
        movl      316(%rdi), %r9d
        movl      572(%rdi), %r10d
        movl      828(%rdi), %r11d
        addq      $1024, %rdi
        movl      %r9d, 240(%rax)
        cmpl      $3, %edx
        movl      %r10d, 244(%rax)
        movl      %r11d, 248(%rax)
        jb        ..B1.14
..B1.16:
        lea       (%rsp), %rdi
..B1.18:
        movl      %r8d, %edx
        andl      $2, %edx
        jne       ..B1.20
..B1.19:
        movdqa    .L_2il0floatpacket.21(%rip), %xmm4
        movdqa    .L_2il0floatpacket.22(%rip), %xmm5
        movdqa    %xmm4, %xmm14
        movdqa    .L_2il0floatpacket.23(%rip), %xmm7
        movdqa    %xmm5, %xmm10
        movdqa    .L_2il0floatpacket.24(%rip), %xmm11
        movdqa    %xmm7, %xmm13
        movdqa    %xmm11, %xmm12
        movdqa    %xmm4, %xmm6
        movdqa    %xmm5, %xmm2
        movdqa    %xmm7, %xmm3
        movdqa    %xmm11, %xmm1
        jmp       ..B1.23
..B1.20:
        movl      %r8d, %eax
        andl      $6, %eax
        movdqa    (%rcx), %xmm4
        cmpl      $6, %eax
        movdqa    16(%rcx), %xmm5
        movdqa    32(%rcx), %xmm7
        movdqa    48(%rcx), %xmm11
        jne       ..B1.22
..B1.21:
        movdqa    256(%rcx), %xmm14
        movdqa    272(%rcx), %xmm10
        movdqa    288(%rcx), %xmm13
        movdqa    304(%rcx), %xmm12
        movdqa    512(%rcx), %xmm6
        movdqa    528(%rcx), %xmm2
        movdqa    544(%rcx), %xmm3
        movdqa    560(%rcx), %xmm1
        jmp       ..B1.23
..B1.22:
        movdqa    64(%rcx), %xmm14
        movdqa    80(%rcx), %xmm10
        movdqa    96(%rcx), %xmm13
        movdqa    112(%rcx), %xmm12
        movdqa    128(%rcx), %xmm6
        movdqa    144(%rcx), %xmm2
        movdqa    160(%rcx), %xmm3
        movdqa    176(%rcx), %xmm1
..B1.23:
        movdqa    %xmm7, %xmm9
        movdqa    %xmm13, %xmm15
        pxor      %xmm11, %xmm9
        pxor      %xmm12, %xmm15
        movdqa    .L_2il0floatpacket.25(%rip), %xmm8
        pand      %xmm5, %xmm9
        paddd     %xmm8, %xmm4
        pxor      %xmm11, %xmm9
        paddd     %xmm9, %xmm4
        pand      %xmm10, %xmm15
        movdqa    (%rdi), %xmm9
        paddd     %xmm8, %xmm14
        movdqa    %xmm9, 1088(%rsp)
        paddd     %xmm9, %xmm4
        movdqa    %xmm3, %xmm9
        pxor      %xmm12, %xmm15
        pxor      %xmm1, %xmm9
        paddd     %xmm8, %xmm6
        pand      %xmm2, %xmm9
        paddd     %xmm15, %xmm14
        pxor      %xmm1, %xmm9
        movdqa    %xmm4, %xmm8
        movdqa    256(%rdi), %xmm15
        paddd     %xmm9, %xmm6
        paddd     512(%rdi), %xmm6
        paddd     %xmm15, %xmm14
        pslld     $7, %xmm8
        psrld     $25, %xmm4
        por       %xmm4, %xmm8
        movdqa    %xmm14, %xmm9
        movdqa    %xmm6, %xmm4
        pslld     $7, %xmm9
        psrld     $25, %xmm14
        pslld     $7, %xmm4
        psrld     $25, %xmm6
        por       %xmm14, %xmm9
        por       %xmm6, %xmm4
        movdqa    %xmm5, %xmm6
        movdqa    %xmm10, %xmm14
        paddd     %xmm5, %xmm8
        paddd     %xmm10, %xmm9
        pxor      %xmm7, %xmm6
        pxor      %xmm13, %xmm14
        pand      %xmm8, %xmm6
        movdqa    %xmm15, 1104(%rsp)
        pand      %xmm9, %xmm14
        movdqa    .L_2il0floatpacket.26(%rip), %xmm15
        pxor      %xmm7, %xmm6
        paddd     %xmm15, %xmm11
        paddd     %xmm15, %xmm12
        pxor      %xmm13, %xmm14
        paddd     %xmm6, %xmm11
        paddd     %xmm14, %xmm12
        paddd     %xmm2, %xmm4
        movdqa    16(%rdi), %xmm14
        paddd     %xmm15, %xmm1
        movdqa    %xmm14, 880(%rsp)
        paddd     %xmm14, %xmm11
        movdqa    %xmm2, %xmm14
        movdqa    %xmm11, %xmm15
        pxor      %xmm3, %xmm14
        pslld     $12, %xmm15
        pand      %xmm4, %xmm14
        psrld     $20, %xmm11
        movdqa    272(%rdi), %xmm6
        pxor      %xmm3, %xmm14
        movdqa    %xmm6, 864(%rsp)
        paddd     %xmm6, %xmm12
        movdqa    528(%rdi), %xmm6
        paddd     %xmm14, %xmm1
        paddd     %xmm6, %xmm1
        por       %xmm11, %xmm15
        movdqa    %xmm1, %xmm11
        psrld     $20, %xmm1
        pslld     $12, %xmm11
        paddd     %xmm8, %xmm15
        movdqa    %xmm6, 1024(%rsp)
        movdqa    %xmm12, %xmm6
        por       %xmm1, %xmm11
        movdqa    %xmm5, %xmm1
        pslld     $12, %xmm6
        psrld     $20, %xmm12
        pxor      %xmm8, %xmm1
        por       %xmm12, %xmm6
        movdqa    .L_2il0floatpacket.27(%rip), %xmm12
        pand      %xmm15, %xmm1
        paddd     %xmm12, %xmm7
        pxor      %xmm5, %xmm1
        movdqa    %xmm10, %xmm14
        paddd     %xmm9, %xmm6
        paddd     %xmm1, %xmm7
        pxor      %xmm9, %xmm14
        movdqa    32(%rdi), %xmm1
        pand      %xmm6, %xmm14
        movdqa    %xmm1, 768(%rsp)
        paddd     %xmm1, %xmm7
        movdqa    %xmm2, %xmm1
        paddd     %xmm4, %xmm11
        paddd     %xmm12, %xmm13
        pxor      %xmm10, %xmm14
        pxor      %xmm4, %xmm1
        paddd     %xmm14, %xmm13
        movdqa    288(%rdi), %xmm14
        pand      %xmm11, %xmm1
        paddd     %xmm14, %xmm13
        pxor      %xmm2, %xmm1
        paddd     %xmm12, %xmm3
        movdqa    %xmm7, %xmm12
        paddd     %xmm1, %xmm3
        movdqa    %xmm13, %xmm1
        movdqa    %xmm14, 784(%rsp)
        pslld     $17, %xmm12
        movdqa    544(%rdi), %xmm14
        psrld     $15, %xmm7
        pslld     $17, %xmm1
        psrld     $15, %xmm13
        paddd     %xmm14, %xmm3
        por       %xmm7, %xmm12
        por       %xmm13, %xmm1
        movdqa    %xmm15, %xmm13
        movdqa    %xmm14, 896(%rsp)
        paddd     %xmm15, %xmm12
        movdqa    %xmm3, %xmm14
        pxor      %xmm8, %xmm13
        movdqa    .L_2il0floatpacket.28(%rip), %xmm7
        pslld     $17, %xmm14
        psrld     $15, %xmm3
        pand      %xmm12, %xmm13
        por       %xmm3, %xmm14
        paddd     %xmm7, %xmm5
        pxor      %xmm8, %xmm13
        movdqa    %xmm6, %xmm3
        paddd     %xmm6, %xmm1
        paddd     %xmm13, %xmm5
        movdqa    48(%rdi), %xmm13
        pxor      %xmm9, %xmm3
        movdqa    %xmm13, 976(%rsp)
        pand      %xmm1, %xmm3
        paddd     %xmm13, %xmm5
        movdqa    %xmm11, %xmm13
        paddd     %xmm11, %xmm14
        paddd     %xmm7, %xmm10
        pxor      %xmm9, %xmm3
        pxor      %xmm4, %xmm13
        paddd     %xmm3, %xmm10
        pand      %xmm14, %xmm13
        movdqa    304(%rdi), %xmm3
        paddd     %xmm7, %xmm2
        movdqa    %xmm5, %xmm7
        paddd     %xmm3, %xmm10
        pxor      %xmm4, %xmm13
        pslld     $22, %xmm7
        psrld     $10, %xmm5
        paddd     %xmm13, %xmm2
        movdqa    %xmm3, 992(%rsp)
        por       %xmm5, %xmm7
        movdqa    560(%rdi), %xmm3
        movdqa    %xmm10, %xmm5
        paddd     %xmm3, %xmm2
        pslld     $22, %xmm5
        psrld     $10, %xmm10
        movdqa    %xmm2, %xmm13
        por       %xmm10, %xmm5
        movdqa    %xmm12, %xmm10
        paddd     %xmm12, %xmm7
        pslld     $22, %xmm13
        psrld     $10, %xmm2
        pxor      %xmm15, %xmm10
        por       %xmm2, %xmm13
        pand      %xmm7, %xmm10
        movdqa    .L_2il0floatpacket.29(%rip), %xmm2
        pxor      %xmm15, %xmm10
        movdqa    %xmm3, 1216(%rsp)
        paddd     %xmm2, %xmm8
        movdqa    %xmm1, %xmm3
        paddd     %xmm1, %xmm5
        paddd     %xmm10, %xmm8
        pxor      %xmm6, %xmm3
        movdqa    64(%rdi), %xmm10
        pand      %xmm5, %xmm3
        movdqa    %xmm10, 800(%rsp)
        paddd     %xmm10, %xmm8
        movdqa    %xmm14, %xmm10
        paddd     %xmm14, %xmm13
        paddd     %xmm2, %xmm9
        pxor      %xmm6, %xmm3
        pxor      %xmm11, %xmm10
        paddd     %xmm3, %xmm9
        movdqa    320(%rdi), %xmm3
        pand      %xmm13, %xmm10
        paddd     %xmm2, %xmm4
        movdqa    %xmm8, %xmm2
        paddd     %xmm3, %xmm9
        pxor      %xmm11, %xmm10
        pslld     $7, %xmm2
        psrld     $25, %xmm8
        movdqa    %xmm3, 816(%rsp)
        paddd     %xmm10, %xmm4
        movdqa    576(%rdi), %xmm3
        por       %xmm8, %xmm2
        movdqa    %xmm9, %xmm8
        paddd     %xmm3, %xmm4
        pslld     $7, %xmm8
        psrld     $25, %xmm9
        movdqa    %xmm3, 960(%rsp)
        por       %xmm9, %xmm8
        movdqa    %xmm4, %xmm3
        movdqa    %xmm7, %xmm9
        paddd     %xmm7, %xmm2
        pslld     $7, %xmm3
        psrld     $25, %xmm4
        pxor      %xmm12, %xmm9
        por       %xmm4, %xmm3
        pand      %xmm2, %xmm9
        movdqa    .L_2il0floatpacket.30(%rip), %xmm4
        pxor      %xmm12, %xmm9
        paddd     %xmm4, %xmm15
        movdqa    %xmm5, %xmm10
        paddd     %xmm5, %xmm8
        paddd     %xmm9, %xmm15
        movdqa    80(%rdi), %xmm9
        pxor      %xmm1, %xmm10
        movdqa    %xmm9, 1152(%rsp)
        pand      %xmm8, %xmm10
        paddd     %xmm9, %xmm15
        movdqa    %xmm13, %xmm9
        paddd     %xmm13, %xmm3
        paddd     %xmm4, %xmm6
        pxor      %xmm1, %xmm10
        pxor      %xmm14, %xmm9
        paddd     %xmm10, %xmm6
        pand      %xmm3, %xmm9
        movdqa    336(%rdi), %xmm10
        paddd     %xmm4, %xmm11
        movdqa    %xmm15, %xmm4
        paddd     %xmm10, %xmm6
        pxor      %xmm14, %xmm9
        pslld     $12, %xmm4
        psrld     $20, %xmm15
        paddd     %xmm9, %xmm11
        movdqa    %xmm10, 1232(%rsp)
        por       %xmm15, %xmm4
        movdqa    592(%rdi), %xmm10
        movdqa    %xmm6, %xmm15
        paddd     %xmm10, %xmm11
        pslld     $12, %xmm15
        psrld     $20, %xmm6
        movdqa    %xmm8, %xmm9
        movdqa    %xmm10, 1344(%rsp)
        por       %xmm6, %xmm15
        movdqa    %xmm11, %xmm10
        paddd     %xmm8, %xmm15
        pslld     $12, %xmm10
        psrld     $20, %xmm11
        pxor      %xmm5, %xmm9
        movdqa    %xmm2, %xmm6
        por       %xmm11, %xmm10
        pand      %xmm15, %xmm9
        movdqa    .L_2il0floatpacket.31(%rip), %xmm11
        paddd     %xmm2, %xmm4
        pxor      %xmm7, %xmm6
        paddd     %xmm11, %xmm1
        pxor      %xmm5, %xmm9
        pand      %xmm4, %xmm6
        paddd     %xmm9, %xmm1
        movdqa    %xmm3, %xmm9
        paddd     %xmm11, %xmm12
        pxor      %xmm7, %xmm6
        paddd     %xmm3, %xmm10
        pxor      %xmm13, %xmm9
        paddd     %xmm6, %xmm12
        pand      %xmm10, %xmm9
        movdqa    96(%rdi), %xmm6
        pxor      %xmm13, %xmm9
        movdqa    %xmm6, 912(%rsp)
        paddd     %xmm6, %xmm12
        movdqa    352(%rdi), %xmm6
        paddd     %xmm11, %xmm14
        movdqa    %xmm6, 928(%rsp)
        paddd     %xmm6, %xmm1
        movdqa    608(%rdi), %xmm6
        paddd     %xmm9, %xmm14
        movdqa    %xmm6, 1120(%rsp)
        paddd     %xmm6, %xmm14
        movdqa    %xmm12, %xmm9
        movdqa    %xmm1, %xmm6
        pslld     $17, %xmm9
        psrld     $15, %xmm12
        pslld     $17, %xmm6
        psrld     $15, %xmm1
        por       %xmm12, %xmm9
        por       %xmm1, %xmm6
        movdqa    %xmm14, %xmm1
        movdqa    %xmm4, %xmm11
        paddd     %xmm4, %xmm9
        pslld     $17, %xmm1
        psrld     $15, %xmm14
        pxor      %xmm2, %xmm11
        por       %xmm14, %xmm1
        pand      %xmm9, %xmm11
        movdqa    .L_2il0floatpacket.32(%rip), %xmm14
        pxor      %xmm2, %xmm11
        paddd     %xmm14, %xmm7
        movdqa    %xmm15, %xmm12
        paddd     %xmm15, %xmm6
        paddd     %xmm11, %xmm7
        movdqa    112(%rdi), %xmm11
        pxor      %xmm8, %xmm12
        movdqa    %xmm11, 1360(%rsp)
        pand      %xmm6, %xmm12
        paddd     %xmm11, %xmm7
        movdqa    %xmm10, %xmm11
        paddd     %xmm10, %xmm1
        paddd     %xmm14, %xmm5
        pxor      %xmm8, %xmm12
        pxor      %xmm3, %xmm11
        paddd     %xmm12, %xmm5
        pand      %xmm1, %xmm11
        movdqa    368(%rdi), %xmm12
        paddd     %xmm14, %xmm13
        movdqa    %xmm7, %xmm14
        paddd     %xmm12, %xmm5
        pxor      %xmm3, %xmm11
        pslld     $22, %xmm14
        psrld     $10, %xmm7
        paddd     %xmm11, %xmm13
        movdqa    %xmm12, 1328(%rsp)
        por       %xmm7, %xmm14
        movdqa    624(%rdi), %xmm12
        movdqa    %xmm5, %xmm7
        paddd     %xmm12, %xmm13
        pslld     $22, %xmm7
        psrld     $10, %xmm5
        movdqa    %xmm9, %xmm11
        por       %xmm5, %xmm7
        movdqa    %xmm13, %xmm5
        paddd     %xmm9, %xmm14
        pslld     $22, %xmm5
        psrld     $10, %xmm13
        pxor      %xmm4, %xmm11
        por       %xmm13, %xmm5
        pand      %xmm14, %xmm11
        movdqa    .L_2il0floatpacket.33(%rip), %xmm13
        pxor      %xmm4, %xmm11
        movdqa    %xmm12, 1440(%rsp)
        paddd     %xmm13, %xmm2
        movdqa    %xmm6, %xmm12
        paddd     %xmm6, %xmm7
        paddd     %xmm11, %xmm2
        pxor      %xmm15, %xmm12
        movdqa    128(%rdi), %xmm11
        pand      %xmm7, %xmm12
        movdqa    %xmm11, 1056(%rsp)
        paddd     %xmm11, %xmm2
        movdqa    %xmm1, %xmm11
        paddd     %xmm1, %xmm5
        paddd     %xmm13, %xmm8
        pxor      %xmm15, %xmm12
        pxor      %xmm10, %xmm11
        paddd     %xmm12, %xmm8
        movdqa    384(%rdi), %xmm12
        pand      %xmm5, %xmm11
        paddd     %xmm13, %xmm3
        movdqa    %xmm2, %xmm13
        paddd     %xmm12, %xmm8
        pxor      %xmm10, %xmm11
        pslld     $7, %xmm13
        psrld     $25, %xmm2
        movdqa    %xmm12, 1040(%rsp)
        paddd     %xmm11, %xmm3
        movdqa    640(%rdi), %xmm12
        por       %xmm2, %xmm13
        movdqa    %xmm8, %xmm2
        paddd     %xmm12, %xmm3
        pslld     $7, %xmm2
        psrld     $25, %xmm8
        por       %xmm8, %xmm2
        movdqa    %xmm3, %xmm8
        movdqa    %xmm14, %xmm11
        paddd     %xmm14, %xmm13
        pslld     $7, %xmm8
        psrld     $25, %xmm3
        pxor      %xmm9, %xmm11
        por       %xmm3, %xmm8
        movdqa    .L_2il0floatpacket.34(%rip), %xmm3
        pand      %xmm13, %xmm11
        movdqa    %xmm12, 1296(%rsp)
        paddd     %xmm3, %xmm4
        pxor      %xmm9, %xmm11
        movdqa    %xmm7, %xmm12
        paddd     %xmm7, %xmm2
        paddd     %xmm11, %xmm4
        movdqa    144(%rdi), %xmm11
        pxor      %xmm6, %xmm12
        movdqa    %xmm11, 832(%rsp)
        pand      %xmm2, %xmm12
        paddd     %xmm11, %xmm4
        movdqa    %xmm5, %xmm11
        paddd     %xmm5, %xmm8
        paddd     %xmm3, %xmm15
        pxor      %xmm6, %xmm12
        pxor      %xmm1, %xmm11
        paddd     %xmm12, %xmm15
        pand      %xmm8, %xmm11
        movdqa    400(%rdi), %xmm12
        paddd     %xmm3, %xmm10
        movdqa    %xmm4, %xmm3
        paddd     %xmm12, %xmm15
        pxor      %xmm1, %xmm11
        pslld     $12, %xmm3
        psrld     $20, %xmm4
        paddd     %xmm11, %xmm10
        movdqa    %xmm12, 848(%rsp)
        por       %xmm4, %xmm3
        movdqa    656(%rdi), %xmm12
        movdqa    %xmm15, %xmm4
        paddd     %xmm12, %xmm10
        pslld     $12, %xmm4
        psrld     $20, %xmm15
        movdqa    %xmm13, %xmm11
        por       %xmm15, %xmm4
        movdqa    %xmm10, %xmm15
        paddd     %xmm13, %xmm3
        pslld     $12, %xmm15
        psrld     $20, %xmm10
        pxor      %xmm14, %xmm11
        por       %xmm10, %xmm15
        pand      %xmm3, %xmm11
        movdqa    .L_2il0floatpacket.35(%rip), %xmm10
        pxor      %xmm14, %xmm11
        movdqa    %xmm12, 1008(%rsp)
        paddd     %xmm10, %xmm9
        movdqa    %xmm2, %xmm12
        paddd     %xmm2, %xmm4
        paddd     %xmm11, %xmm9
        pxor      %xmm7, %xmm12
        movdqa    160(%rdi), %xmm11
        pand      %xmm4, %xmm12
        movdqa    %xmm11, 1200(%rsp)
        paddd     %xmm11, %xmm9
        movdqa    %xmm8, %xmm11
        paddd     %xmm8, %xmm15
        paddd     %xmm10, %xmm6
        pxor      %xmm7, %xmm12
        pxor      %xmm5, %xmm11
        paddd     %xmm12, %xmm6
        movdqa    416(%rdi), %xmm12
        pand      %xmm15, %xmm11
        paddd     %xmm10, %xmm1
        movdqa    %xmm9, %xmm10
        paddd     %xmm12, %xmm6
        pxor      %xmm5, %xmm11
        pslld     $17, %xmm10
        psrld     $15, %xmm9
        movdqa    %xmm12, 1248(%rsp)
        paddd     %xmm11, %xmm1
        movdqa    672(%rdi), %xmm12
        por       %xmm9, %xmm10
        movdqa    %xmm6, %xmm9
        paddd     %xmm12, %xmm1
        pslld     $17, %xmm9
        psrld     $15, %xmm6
        por       %xmm6, %xmm9
        movdqa    %xmm1, %xmm6
        pslld     $17, %xmm6
        psrld     $15, %xmm1
        por       %xmm1, %xmm6
        movdqa    %xmm3, %xmm1
        movdqa    %xmm12, 1392(%rsp)
        paddd     %xmm3, %xmm10
        pxor      %xmm13, %xmm1
        movdqa    %xmm4, %xmm12
        movdqa    .L_2il0floatpacket.36(%rip), %xmm11
        paddd     %xmm4, %xmm9
        pand      %xmm10, %xmm1
        pxor      %xmm2, %xmm12
        paddd     %xmm11, %xmm14
        pxor      %xmm13, %xmm1
        pand      %xmm9, %xmm12
        paddd     %xmm11, %xmm7
        paddd     %xmm1, %xmm14
        pxor      %xmm2, %xmm12
        movdqa    176(%rdi), %xmm1
        paddd     %xmm15, %xmm6
        movdqa    %xmm1, 1168(%rsp)
        paddd     %xmm12, %xmm7
        movdqa    512(%rdi), %xmm12
..B1.37:
        movdqa    %xmm12, 1520(%rsp)
        movdqa    %xmm15, %xmm12
        movdqa    1168(%rsp), %xmm1
        pxor      %xmm8, %xmm12
        paddd     %xmm1, %xmm14
        pand      %xmm6, %xmm12
        movdqa    432(%rdi), %xmm0
        paddd     %xmm11, %xmm5
        movdqa    %xmm14, %xmm11
        paddd     %xmm0, %xmm7
        pxor      %xmm8, %xmm12
        pslld     $22, %xmm11
        psrld     $10, %xmm14
        paddd     %xmm12, %xmm5
        movdqa    %xmm0, 944(%rsp)
        por       %xmm14, %xmm11
        movdqa    688(%rdi), %xmm0
        movdqa    %xmm7, %xmm14
        paddd     %xmm0, %xmm5
        pslld     $22, %xmm14
        psrld     $10, %xmm7
        movdqa    %xmm10, %xmm12
        por       %xmm7, %xmm14
        movdqa    %xmm5, %xmm7
        paddd     %xmm10, %xmm11
        pslld     $22, %xmm7
        psrld     $10, %xmm5
        pxor      %xmm3, %xmm12
        por       %xmm5, %xmm7
        pand      %xmm11, %xmm12
        movdqa    .L_2il0floatpacket.37(%rip), %xmm5
        pxor      %xmm3, %xmm12
        movdqa    %xmm0, 1184(%rsp)
        paddd     %xmm5, %xmm13
        movdqa    %xmm9, %xmm0
        paddd     %xmm9, %xmm14
        paddd     %xmm12, %xmm13
        pxor      %xmm4, %xmm0
        movdqa    192(%rdi), %xmm12
        pand      %xmm14, %xmm0
        movdqa    %xmm12, 1408(%rsp)
        paddd     %xmm12, %xmm13
        movdqa    %xmm6, %xmm12
        paddd     %xmm6, %xmm7
        paddd     %xmm5, %xmm2
        pxor      %xmm4, %xmm0
        pxor      %xmm15, %xmm12
        paddd     %xmm0, %xmm2
        movdqa    448(%rdi), %xmm0
        pand      %xmm7, %xmm12
        paddd     %xmm5, %xmm8
        movdqa    %xmm13, %xmm5
        paddd     %xmm0, %xmm2
        pxor      %xmm15, %xmm12
        pslld     $7, %xmm5
        psrld     $25, %xmm13
        movdqa    %xmm0, 1376(%rsp)
        paddd     %xmm12, %xmm8
        movdqa    704(%rdi), %xmm0
        por       %xmm13, %xmm5
        movdqa    %xmm2, %xmm13
        paddd     %xmm0, %xmm8
        pslld     $7, %xmm13
        psrld     $25, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm8, %xmm2
        movdqa    %xmm10, %xmm12
        paddd     %xmm11, %xmm5
        pslld     $7, %xmm2
        psrld     $25, %xmm8
        pxor      %xmm11, %xmm12
        por       %xmm8, %xmm2
        movdqa    .L_2il0floatpacket.38(%rip), %xmm8
        pand      %xmm5, %xmm12
        movdqa    %xmm0, 1488(%rsp)
        paddd     %xmm8, %xmm3
        pxor      %xmm10, %xmm12
        movdqa    %xmm9, %xmm0
        paddd     %xmm14, %xmm13
        paddd     %xmm12, %xmm3
        movdqa    208(%rdi), %xmm12
        pxor      %xmm14, %xmm0
        movdqa    %xmm12, 1072(%rsp)
        pand      %xmm13, %xmm0
        paddd     %xmm12, %xmm3
        movdqa    %xmm6, %xmm12
        paddd     %xmm7, %xmm2
        paddd     %xmm8, %xmm4
        pxor      %xmm9, %xmm0
        pxor      %xmm7, %xmm12
        paddd     %xmm0, %xmm4
        pand      %xmm2, %xmm12
        movdqa    464(%rdi), %xmm0
        paddd     %xmm8, %xmm15
        movdqa    %xmm3, %xmm8
        paddd     %xmm0, %xmm4
        pxor      %xmm6, %xmm12
        pslld     $12, %xmm8
        psrld     $20, %xmm3
        paddd     %xmm12, %xmm15
        movdqa    %xmm0, 1136(%rsp)
        por       %xmm3, %xmm8
        movdqa    720(%rdi), %xmm0
        movdqa    %xmm4, %xmm3
        paddd     %xmm0, %xmm15
        pslld     $12, %xmm3
        psrld     $20, %xmm4
        paddd     %xmm5, %xmm8
        por       %xmm4, %xmm3
        movdqa    %xmm15, %xmm4
        pslld     $12, %xmm4
        psrld     $20, %xmm15
        por       %xmm15, %xmm4
        movdqa    %xmm5, %xmm15
        pxor      %xmm11, %xmm15
        paddd     %xmm13, %xmm3
        movdqa    .L_2il0floatpacket.39(%rip), %xmm12
        pand      %xmm8, %xmm15
        paddd     %xmm12, %xmm10
        pxor      %xmm11, %xmm15
        movdqa    %xmm0, 1312(%rsp)
        movdqa    %xmm13, %xmm0
        paddd     %xmm15, %xmm10
        pxor      %xmm14, %xmm0
        movdqa    224(%rdi), %xmm15
        pand      %xmm3, %xmm0
        movdqa    %xmm15, 1472(%rsp)
        paddd     %xmm15, %xmm10
        movdqa    %xmm2, %xmm15
        paddd     %xmm2, %xmm4
        pxor      %xmm7, %xmm15
        paddd     %xmm12, %xmm9
        pxor      %xmm14, %xmm0
        pand      %xmm4, %xmm15
        paddd     %xmm0, %xmm9
        pxor      %xmm7, %xmm15
        movdqa    480(%rdi), %xmm0
        paddd     %xmm12, %xmm6
        paddd     %xmm0, %xmm9
        paddd     %xmm15, %xmm6
        movdqa    %xmm0, 1456(%rsp)
        movdqa    %xmm10, %xmm12
        movdqa    736(%rdi), %xmm0
        movdqa    %xmm9, %xmm15
        paddd     %xmm0, %xmm6
        pslld     $17, %xmm12
        psrld     $15, %xmm10
        pslld     $17, %xmm15
        psrld     $15, %xmm9
        por       %xmm10, %xmm12
        movdqa    %xmm0, 1504(%rsp)
        movdqa    %xmm6, %xmm0
        por       %xmm9, %xmm15
        movdqa    %xmm3, %xmm10
        pslld     $17, %xmm0
        psrld     $15, %xmm6
        paddd     %xmm3, %xmm15
        pxor      %xmm13, %xmm10
        por       %xmm6, %xmm0
        movdqa    %xmm8, %xmm6
        movdqa    .L_2il0floatpacket.40(%rip), %xmm9
        pand      %xmm15, %xmm10
        paddd     %xmm8, %xmm12
        pxor      %xmm5, %xmm6
        paddd     %xmm9, %xmm14
        pxor      %xmm13, %xmm10
        pand      %xmm12, %xmm6
        paddd     %xmm10, %xmm14
        movdqa    %xmm4, %xmm10
        paddd     %xmm9, %xmm11
        pxor      %xmm5, %xmm6
        paddd     %xmm4, %xmm0
        pxor      %xmm2, %xmm10
        paddd     %xmm6, %xmm11
        movdqa    240(%rdi), %xmm6
        pand      %xmm0, %xmm10
        movdqa    %xmm6, 1264(%rsp)
        paddd     %xmm6, %xmm11
        movdqa    496(%rdi), %xmm6
        pxor      %xmm2, %xmm10
        paddd     %xmm9, %xmm7
        paddd     %xmm6, %xmm14
        movdqa    %xmm6, 1280(%rsp)
        paddd     %xmm10, %xmm7
        movdqa    752(%rdi), %xmm6
        movdqa    %xmm11, %xmm9
        paddd     %xmm6, %xmm7
        pslld     $22, %xmm9
        psrld     $10, %xmm11
        movdqa    %xmm7, %xmm10
        por       %xmm11, %xmm9
        pslld     $22, %xmm10
        paddd     %xmm12, %xmm9
        psrld     $10, %xmm7
        movdqa    %xmm14, %xmm11
        por       %xmm7, %xmm10
        movdqa    %xmm9, %xmm7
        pslld     $22, %xmm11
        psrld     $10, %xmm14
        pxor      %xmm12, %xmm7
        por       %xmm14, %xmm11
        pand      %xmm8, %xmm7
        movdqa    .L_2il0floatpacket.41(%rip), %xmm14
        paddd     %xmm15, %xmm11
        paddd     %xmm14, %xmm5
        pxor      %xmm12, %xmm7
        paddd     %xmm7, %xmm5
        movdqa    %xmm11, %xmm7
        pxor      %xmm15, %xmm7
        paddd     %xmm0, %xmm10
        pand      %xmm3, %xmm7
        paddd     %xmm14, %xmm13
        pxor      %xmm15, %xmm7
        paddd     %xmm14, %xmm2
        paddd     %xmm7, %xmm13
        movdqa    %xmm10, %xmm7
        paddd     880(%rsp), %xmm5
        pxor      %xmm0, %xmm7
        pand      %xmm4, %xmm7
        movdqa    %xmm5, %xmm14
        paddd     864(%rsp), %xmm13
        pxor      %xmm0, %xmm7
        pslld     $5, %xmm14
        psrld     $27, %xmm5
        paddd     %xmm7, %xmm2
        por       %xmm5, %xmm14
        movdqa    %xmm13, %xmm5
        paddd     %xmm9, %xmm14
        paddd     1024(%rsp), %xmm2
        pslld     $5, %xmm5
        psrld     $27, %xmm13
        movdqa    %xmm14, %xmm7
        por       %xmm13, %xmm5
        movdqa    %xmm2, %xmm13
        pslld     $5, %xmm13
        psrld     $27, %xmm2
        pxor      %xmm9, %xmm7
        por       %xmm2, %xmm13
        movdqa    .L_2il0floatpacket.42(%rip), %xmm2
        pand      %xmm12, %xmm7
        paddd     %xmm11, %xmm5
        paddd     %xmm2, %xmm8
        pxor      %xmm9, %xmm7
        paddd     %xmm10, %xmm13
        paddd     %xmm7, %xmm8
        movdqa    %xmm5, %xmm7
        pxor      %xmm11, %xmm7
        paddd     %xmm2, %xmm3
        pand      %xmm15, %xmm7
        paddd     %xmm2, %xmm4
        pxor      %xmm11, %xmm7
        paddd     %xmm7, %xmm3
        movdqa    %xmm13, %xmm7
        pxor      %xmm10, %xmm7
        pand      %xmm0, %xmm7
        paddd     912(%rsp), %xmm8
        pxor      %xmm10, %xmm7
        paddd     %xmm7, %xmm4
        movdqa    %xmm8, %xmm2
        paddd     1120(%rsp), %xmm4
        pslld     $9, %xmm2
        psrld     $23, %xmm8
        movdqa    %xmm4, %xmm7
        por       %xmm8, %xmm2
        pslld     $9, %xmm7
        paddd     928(%rsp), %xmm3
        paddd     %xmm14, %xmm2
        psrld     $23, %xmm4
        movdqa    %xmm3, %xmm8
        por       %xmm4, %xmm7
        movdqa    %xmm2, %xmm4
        pslld     $9, %xmm8
        psrld     $23, %xmm3
        pxor      %xmm14, %xmm4
        por       %xmm3, %xmm8
        movdqa    .L_2il0floatpacket.43(%rip), %xmm3
        pand      %xmm9, %xmm4
        paddd     %xmm3, %xmm12
        pxor      %xmm14, %xmm4
        paddd     %xmm5, %xmm8
        paddd     %xmm13, %xmm7
        paddd     %xmm4, %xmm12
        movdqa    %xmm8, %xmm4
        paddd     %xmm1, %xmm12
        movdqa    %xmm7, %xmm1
        pxor      %xmm5, %xmm4
        pxor      %xmm13, %xmm1
        pand      %xmm11, %xmm4
        pand      %xmm10, %xmm1
        paddd     %xmm3, %xmm15
        pxor      %xmm5, %xmm4
        pxor      %xmm13, %xmm1
        paddd     %xmm3, %xmm0
        paddd     %xmm4, %xmm15
        paddd     %xmm1, %xmm0
        movdqa    %xmm12, %xmm1
        psrld     $18, %xmm12
        paddd     432(%rdi), %xmm15
        pslld     $14, %xmm1
        por       %xmm12, %xmm1
        movdqa    %xmm15, %xmm3
        paddd     688(%rdi), %xmm0
        paddd     %xmm2, %xmm1
        pslld     $14, %xmm3
        psrld     $18, %xmm15
        por       %xmm15, %xmm3
        movdqa    %xmm0, %xmm4
        movdqa    %xmm1, %xmm15
        paddd     %xmm8, %xmm3
        pslld     $14, %xmm4
        psrld     $18, %xmm0
        pxor      %xmm2, %xmm15
        por       %xmm0, %xmm4
        movdqa    .L_2il0floatpacket.44(%rip), %xmm12
        pand      %xmm14, %xmm15
        movdqa    %xmm3, %xmm0
        paddd     %xmm7, %xmm4
        paddd     %xmm12, %xmm9
        pxor      %xmm2, %xmm15
        pxor      %xmm8, %xmm0
        paddd     %xmm15, %xmm9
        pand      %xmm5, %xmm0
        movdqa    %xmm4, %xmm15
        paddd     1088(%rsp), %xmm9
        paddd     %xmm12, %xmm11
        pxor      %xmm8, %xmm0
        pxor      %xmm7, %xmm15
        paddd     %xmm0, %xmm11
        pand      %xmm13, %xmm15
        movdqa    %xmm9, %xmm0
        pxor      %xmm7, %xmm15
        paddd     1104(%rsp), %xmm11
        paddd     %xmm12, %xmm10
        pslld     $20, %xmm0
        psrld     $12, %xmm9
        movdqa    1520(%rsp), %xmm12
        paddd     %xmm15, %xmm10
        por       %xmm9, %xmm0
        movdqa    %xmm11, %xmm9
        paddd     %xmm12, %xmm10
        paddd     %xmm1, %xmm0
        pslld     $20, %xmm9
        psrld     $12, %xmm11
        por       %xmm11, %xmm9
        movdqa    %xmm10, %xmm11
        movdqa    %xmm0, %xmm15
        pslld     $20, %xmm11
        psrld     $12, %xmm10
        pxor      %xmm1, %xmm15
        por       %xmm10, %xmm11
        pand      %xmm2, %xmm15
        movdqa    .L_2il0floatpacket.45(%rip), %xmm10
        paddd     %xmm3, %xmm9
        paddd     %xmm10, %xmm14
        pxor      %xmm1, %xmm15
        paddd     %xmm15, %xmm14
        movdqa    %xmm9, %xmm15
        pxor      %xmm3, %xmm15
        paddd     %xmm4, %xmm11
        pand      %xmm8, %xmm15
        paddd     %xmm10, %xmm5
        pxor      %xmm3, %xmm15
        paddd     %xmm10, %xmm13
        paddd     %xmm15, %xmm5
        movdqa    %xmm11, %xmm15
        paddd     1152(%rsp), %xmm14
        pxor      %xmm4, %xmm15
        pand      %xmm7, %xmm15
        movdqa    %xmm14, %xmm10
        paddd     1232(%rsp), %xmm5
        pxor      %xmm4, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm13
        por       %xmm14, %xmm10
        movdqa    %xmm5, %xmm14
        paddd     %xmm0, %xmm10
        paddd     1344(%rsp), %xmm13
        pslld     $5, %xmm14
        psrld     $27, %xmm5
        movdqa    %xmm10, %xmm15
        por       %xmm5, %xmm14
        movdqa    %xmm13, %xmm5
        pslld     $5, %xmm5
        psrld     $27, %xmm13
        pxor      %xmm0, %xmm15
        por       %xmm13, %xmm5
        movdqa    .L_2il0floatpacket.46(%rip), %xmm13
        pand      %xmm1, %xmm15
        paddd     %xmm9, %xmm14
        paddd     %xmm13, %xmm2
        pxor      %xmm0, %xmm15
        paddd     %xmm11, %xmm5
        paddd     %xmm15, %xmm2
        movdqa    %xmm14, %xmm15
        pxor      %xmm9, %xmm15
        paddd     %xmm13, %xmm8
        pand      %xmm3, %xmm15
        paddd     %xmm13, %xmm7
        pxor      %xmm9, %xmm15
        paddd     %xmm15, %xmm8
        movdqa    %xmm5, %xmm15
        paddd     1200(%rsp), %xmm2
        pxor      %xmm11, %xmm15
        pand      %xmm4, %xmm15
        movdqa    %xmm2, %xmm13
        paddd     1248(%rsp), %xmm8
        pxor      %xmm11, %xmm15
        pslld     $9, %xmm13
        psrld     $23, %xmm2
        paddd     %xmm15, %xmm7
        por       %xmm2, %xmm13
        movdqa    %xmm8, %xmm2
        paddd     %xmm10, %xmm13
        paddd     1392(%rsp), %xmm7
        pslld     $9, %xmm2
        psrld     $23, %xmm8
        movdqa    %xmm13, %xmm15
        por       %xmm8, %xmm2
        movdqa    %xmm7, %xmm8
        pslld     $9, %xmm8
        psrld     $23, %xmm7
        pxor      %xmm10, %xmm15
        por       %xmm7, %xmm8
        movdqa    .L_2il0floatpacket.47(%rip), %xmm7
        pand      %xmm0, %xmm15
        paddd     %xmm14, %xmm2
        paddd     %xmm7, %xmm1
        pxor      %xmm10, %xmm15
        paddd     %xmm5, %xmm8
        paddd     %xmm15, %xmm1
        movdqa    %xmm2, %xmm15
        pxor      %xmm14, %xmm15
        paddd     %xmm7, %xmm3
        pand      %xmm9, %xmm15
        paddd     %xmm7, %xmm4
        pxor      %xmm14, %xmm15
        paddd     %xmm15, %xmm3
        movdqa    %xmm8, %xmm15
        pxor      %xmm5, %xmm15
        pand      %xmm11, %xmm15
        pxor      %xmm5, %xmm15
        paddd     240(%rdi), %xmm1
        paddd     %xmm15, %xmm4
        paddd     496(%rdi), %xmm3
        paddd     %xmm6, %xmm4
        movdqa    %xmm6, 1424(%rsp)
        movdqa    %xmm1, %xmm6
        movdqa    %xmm3, %xmm7
        pslld     $14, %xmm6
        psrld     $18, %xmm1
        pslld     $14, %xmm7
        psrld     $18, %xmm3
        por       %xmm1, %xmm6
        por       %xmm3, %xmm7
        movdqa    %xmm4, %xmm3
        paddd     %xmm13, %xmm6
        pslld     $14, %xmm3
        psrld     $18, %xmm4
        paddd     %xmm2, %xmm7
        por       %xmm4, %xmm3
        movdqa    %xmm6, %xmm4
        pxor      %xmm13, %xmm4
        paddd     %xmm8, %xmm3
        movdqa    .L_2il0floatpacket.48(%rip), %xmm15
        pand      %xmm10, %xmm4
        paddd     %xmm15, %xmm0
        pxor      %xmm13, %xmm4
        paddd     %xmm4, %xmm0
        movdqa    %xmm7, %xmm1
        movdqa    %xmm3, %xmm4
        pxor      %xmm2, %xmm1
        pxor      %xmm8, %xmm4
        pand      %xmm14, %xmm1
        pand      %xmm5, %xmm4
        paddd     %xmm15, %xmm9
        paddd     800(%rsp), %xmm0
        pxor      %xmm2, %xmm1
        pxor      %xmm8, %xmm4
        paddd     %xmm15, %xmm11
        paddd     %xmm1, %xmm9
        paddd     %xmm4, %xmm11
        movdqa    %xmm0, %xmm4
        psrld     $12, %xmm0
        paddd     816(%rsp), %xmm9
        pslld     $20, %xmm4
        por       %xmm0, %xmm4
        movdqa    %xmm9, %xmm1
        paddd     960(%rsp), %xmm11
        paddd     %xmm6, %xmm4
        pslld     $20, %xmm1
        psrld     $12, %xmm9
        pcmpeqd   %xmm0, %xmm0
..B1.36:
        movdqa    %xmm12, 1520(%rsp)
        por       %xmm9, %xmm1
        movdqa    %xmm11, %xmm9
        movdqa    %xmm4, %xmm12
        pslld     $20, %xmm9
        psrld     $12, %xmm11
        pxor      %xmm6, %xmm12
        paddd     %xmm7, %xmm1
        movdqa    .L_2il0floatpacket.49(%rip), %xmm15
        por       %xmm11, %xmm9
        pand      %xmm13, %xmm12
        movdqa    %xmm7, %xmm11
        paddd     %xmm15, %xmm10
        pxor      %xmm6, %xmm12
        pxor      %xmm1, %xmm11
        paddd     %xmm3, %xmm9
        paddd     %xmm12, %xmm10
        pand      %xmm2, %xmm11
        movdqa    %xmm3, %xmm0
        paddd     %xmm15, %xmm14
        paddd     832(%rsp), %xmm10
        pxor      %xmm7, %xmm11
        pxor      %xmm9, %xmm0
        paddd     %xmm11, %xmm14
        pand      %xmm8, %xmm0
        movdqa    %xmm10, %xmm11
        paddd     848(%rsp), %xmm14
        pxor      %xmm3, %xmm0
        paddd     %xmm15, %xmm5
        pslld     $5, %xmm11
        psrld     $27, %xmm10
        paddd     %xmm0, %xmm5
        por       %xmm10, %xmm11
        movdqa    %xmm14, %xmm10
        paddd     1008(%rsp), %xmm5
        pslld     $5, %xmm10
        psrld     $27, %xmm14
        paddd     %xmm4, %xmm11
        por       %xmm14, %xmm10
        movdqa    %xmm5, %xmm14
        pslld     $5, %xmm14
        psrld     $27, %xmm5
        por       %xmm5, %xmm14
        movdqa    %xmm4, %xmm5
        paddd     %xmm1, %xmm10
        pxor      %xmm11, %xmm5
        movdqa    .L_2il0floatpacket.50(%rip), %xmm12
        pand      %xmm6, %xmm5
        movdqa    %xmm10, %xmm0
        paddd     %xmm9, %xmm14
        paddd     %xmm12, %xmm13
        pxor      %xmm4, %xmm5
        pxor      %xmm1, %xmm0
        paddd     %xmm5, %xmm13
        pand      %xmm7, %xmm0
        movdqa    %xmm14, %xmm15
        paddd     1472(%rsp), %xmm13
        paddd     %xmm12, %xmm2
        pxor      %xmm1, %xmm0
        pxor      %xmm9, %xmm15
        paddd     %xmm0, %xmm2
        pand      %xmm3, %xmm15
        movdqa    %xmm13, %xmm5
        pxor      %xmm9, %xmm15
        paddd     1456(%rsp), %xmm2
        paddd     %xmm12, %xmm8
        pslld     $9, %xmm5
        psrld     $23, %xmm13
        paddd     %xmm15, %xmm8
        por       %xmm13, %xmm5
        movdqa    %xmm2, %xmm13
        psrld     $23, %xmm2
        paddd     1504(%rsp), %xmm8
        pslld     $9, %xmm13
        por       %xmm2, %xmm13
        movdqa    %xmm8, %xmm2
        paddd     %xmm11, %xmm5
        paddd     %xmm10, %xmm13
        pslld     $9, %xmm2
        psrld     $23, %xmm8
        por       %xmm8, %xmm2
        movdqa    %xmm5, %xmm8
        movdqa    %xmm13, %xmm0
        paddd     %xmm14, %xmm2
        pxor      %xmm11, %xmm8
        pxor      %xmm10, %xmm0
        movdqa    .L_2il0floatpacket.51(%rip), %xmm12
        pand      %xmm4, %xmm8
        pand      %xmm1, %xmm0
        movdqa    %xmm2, %xmm15
        paddd     %xmm12, %xmm6
        paddd     %xmm12, %xmm7
        pxor      %xmm11, %xmm8
        pxor      %xmm10, %xmm0
        pxor      %xmm14, %xmm15
        paddd     %xmm8, %xmm6
        paddd     %xmm0, %xmm7
        pand      %xmm9, %xmm15
        paddd     976(%rsp), %xmm6
        pxor      %xmm14, %xmm15
        paddd     992(%rsp), %xmm7
        paddd     %xmm12, %xmm3
        paddd     %xmm15, %xmm3
        movdqa    %xmm6, %xmm12
        movdqa    %xmm7, %xmm8
        pslld     $14, %xmm12
        paddd     1216(%rsp), %xmm3
        psrld     $18, %xmm6
        pslld     $14, %xmm8
        psrld     $18, %xmm7
        por       %xmm6, %xmm12
        por       %xmm7, %xmm8
        movdqa    %xmm3, %xmm7
        paddd     %xmm5, %xmm12
        pslld     $14, %xmm7
        psrld     $18, %xmm3
        por       %xmm3, %xmm7
        movdqa    %xmm12, %xmm3
        pxor      %xmm5, %xmm3
        paddd     %xmm13, %xmm8
        movdqa    .L_2il0floatpacket.52(%rip), %xmm0
        pand      %xmm11, %xmm3
        paddd     %xmm2, %xmm7
        paddd     %xmm0, %xmm4
        pxor      %xmm5, %xmm3
        movdqa    %xmm8, %xmm6
        paddd     %xmm3, %xmm4
        movdqa    %xmm7, %xmm3
        pxor      %xmm13, %xmm6
        pxor      %xmm2, %xmm3
        pand      %xmm10, %xmm6
        pand      %xmm14, %xmm3
        paddd     1056(%rsp), %xmm4
        paddd     %xmm0, %xmm1
        pxor      %xmm13, %xmm6
        pxor      %xmm2, %xmm3
        paddd     %xmm0, %xmm9
        paddd     %xmm6, %xmm1
        paddd     %xmm3, %xmm9
        movdqa    %xmm4, %xmm6
        paddd     1040(%rsp), %xmm1
        pslld     $20, %xmm6
        paddd     1296(%rsp), %xmm9
        psrld     $12, %xmm4
        por       %xmm4, %xmm6
        movdqa    %xmm1, %xmm4
        movdqa    %xmm9, %xmm3
        paddd     %xmm12, %xmm6
        pslld     $20, %xmm4
        psrld     $12, %xmm1
        pslld     $20, %xmm3
        psrld     $12, %xmm9
        por       %xmm1, %xmm4
        por       %xmm9, %xmm3
        movdqa    %xmm6, %xmm1
        paddd     %xmm8, %xmm4
        paddd     %xmm7, %xmm3
        pxor      %xmm12, %xmm1
        movdqa    .L_2il0floatpacket.53(%rip), %xmm9
        pand      %xmm5, %xmm1
        movdqa    %xmm4, %xmm0
        movdqa    %xmm3, %xmm15
        paddd     %xmm9, %xmm11
        pxor      %xmm12, %xmm1
        pxor      %xmm8, %xmm0
        pxor      %xmm7, %xmm15
        paddd     %xmm1, %xmm11
        pand      %xmm13, %xmm0
        pand      %xmm2, %xmm15
        paddd     %xmm9, %xmm10
        paddd     1072(%rsp), %xmm11
        pxor      %xmm8, %xmm0
        pxor      %xmm7, %xmm15
        paddd     %xmm9, %xmm14
        paddd     %xmm0, %xmm10
        paddd     %xmm15, %xmm14
        movdqa    %xmm11, %xmm0
        psrld     $27, %xmm11
        paddd     1136(%rsp), %xmm10
        pslld     $5, %xmm0
        paddd     1312(%rsp), %xmm14
        por       %xmm11, %xmm0
        movdqa    %xmm10, %xmm11
        movdqa    %xmm14, %xmm9
        paddd     %xmm6, %xmm0
        pslld     $5, %xmm11
        psrld     $27, %xmm10
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        por       %xmm10, %xmm11
        por       %xmm14, %xmm9
        movdqa    %xmm0, %xmm10
        paddd     %xmm4, %xmm11
        paddd     %xmm3, %xmm9
        pxor      %xmm6, %xmm10
        movdqa    %xmm11, %xmm1
        movdqa    .L_2il0floatpacket.54(%rip), %xmm14
        pand      %xmm12, %xmm10
        movdqa    %xmm9, %xmm15
        paddd     %xmm14, %xmm5
        pxor      %xmm6, %xmm10
        pxor      %xmm4, %xmm1
        pxor      %xmm3, %xmm15
        paddd     %xmm10, %xmm5
        pand      %xmm8, %xmm1
        pand      %xmm7, %xmm15
        paddd     768(%rsp), %xmm5
        paddd     %xmm14, %xmm13
        pxor      %xmm4, %xmm1
        pxor      %xmm3, %xmm15
        paddd     %xmm14, %xmm2
        paddd     %xmm1, %xmm13
        paddd     %xmm15, %xmm2
        movdqa    %xmm5, %xmm10
        paddd     784(%rsp), %xmm13
        pslld     $9, %xmm10
        paddd     896(%rsp), %xmm2
        psrld     $23, %xmm5
        por       %xmm5, %xmm10
        movdqa    %xmm13, %xmm1
        movdqa    %xmm2, %xmm14
        paddd     %xmm0, %xmm10
        pslld     $9, %xmm1
        psrld     $23, %xmm13
        pslld     $9, %xmm14
        psrld     $23, %xmm2
        por       %xmm13, %xmm1
        por       %xmm2, %xmm14
        movdqa    %xmm10, %xmm2
        paddd     %xmm11, %xmm1
        pxor      %xmm0, %xmm2
        movdqa    %xmm1, %xmm13
        movdqa    .L_2il0floatpacket.55(%rip), %xmm5
        pand      %xmm6, %xmm2
        paddd     %xmm9, %xmm14
        paddd     %xmm5, %xmm12
        pxor      %xmm0, %xmm2
        pxor      %xmm11, %xmm13
        paddd     %xmm2, %xmm12
        pand      %xmm4, %xmm13
        movdqa    %xmm14, %xmm2
        paddd     %xmm5, %xmm8
        paddd     1360(%rsp), %xmm12
        pxor      %xmm11, %xmm13
        pxor      %xmm9, %xmm2
        paddd     %xmm13, %xmm8
        pand      %xmm3, %xmm2
        paddd     %xmm5, %xmm7
        movdqa    %xmm12, %xmm5
        pxor      %xmm9, %xmm2
        paddd     1328(%rsp), %xmm8
        pslld     $14, %xmm5
        psrld     $18, %xmm12
        paddd     %xmm2, %xmm7
        por       %xmm12, %xmm5
        movdqa    %xmm8, %xmm13
        paddd     1440(%rsp), %xmm7
        paddd     %xmm10, %xmm5
        pslld     $14, %xmm13
        psrld     $18, %xmm8
        por       %xmm8, %xmm13
        movdqa    %xmm7, %xmm8
        movdqa    %xmm5, %xmm15
        pslld     $14, %xmm8
        psrld     $18, %xmm7
        pxor      %xmm10, %xmm15
        movdqa    %xmm0, %xmm12
        paddd     %xmm1, %xmm13
        por       %xmm7, %xmm8
        pand      %xmm15, %xmm12
        movdqa    .L_2il0floatpacket.56(%rip), %xmm7
        pxor      %xmm10, %xmm12
        paddd     %xmm7, %xmm6
        movdqa    %xmm13, %xmm2
        paddd     %xmm12, %xmm6
        pxor      %xmm1, %xmm2
        movdqa    %xmm11, %xmm12
        paddd     %xmm14, %xmm8
        pand      %xmm2, %xmm12
        paddd     %xmm7, %xmm4
        pxor      %xmm1, %xmm12
        paddd     %xmm7, %xmm3
        paddd     %xmm12, %xmm4
        movdqa    %xmm8, %xmm12
        movdqa    %xmm1, (%rsp)
        pxor      %xmm14, %xmm12
        paddd     1408(%rsp), %xmm6
        movdqa    %xmm9, %xmm1
        pand      %xmm12, %xmm1
        movdqa    %xmm6, %xmm7
        paddd     1376(%rsp), %xmm4
        pxor      %xmm14, %xmm1
        pslld     $20, %xmm7
        psrld     $12, %xmm6
        paddd     %xmm1, %xmm3
        por       %xmm6, %xmm7
        movdqa    %xmm4, %xmm6
        psrld     $12, %xmm4
        paddd     1488(%rsp), %xmm3
        pslld     $20, %xmm6
        por       %xmm4, %xmm6
        movdqa    %xmm3, %xmm4
        pslld     $20, %xmm4
        psrld     $12, %xmm3
        paddd     %xmm5, %xmm7
        por       %xmm3, %xmm4
        movdqa    .L_2il0floatpacket.57(%rip), %xmm3
        pxor      %xmm7, %xmm15
        paddd     %xmm3, %xmm0
        paddd     %xmm13, %xmm6
        paddd     %xmm15, %xmm0
        paddd     %xmm8, %xmm4
        paddd     1152(%rsp), %xmm0
        paddd     %xmm3, %xmm11
        pxor      %xmm6, %xmm2
        paddd     %xmm3, %xmm9
        movdqa    %xmm0, %xmm3
        paddd     %xmm2, %xmm11
        pxor      %xmm4, %xmm12
        pslld     $4, %xmm3
        psrld     $28, %xmm0
        paddd     %xmm12, %xmm9
        paddd     1232(%rsp), %xmm11
        por       %xmm0, %xmm3
        movdqa    %xmm7, %xmm0
        paddd     %xmm7, %xmm3
        paddd     1344(%rsp), %xmm9
        movdqa    %xmm11, %xmm2
        movdqa    .L_2il0floatpacket.58(%rip), %xmm12
        pxor      %xmm5, %xmm0
        pslld     $4, %xmm2
        psrld     $28, %xmm11
        movdqa    %xmm9, %xmm1
        paddd     %xmm12, %xmm10
        pxor      %xmm3, %xmm0
        por       %xmm11, %xmm2
        pslld     $4, %xmm1
        psrld     $28, %xmm9
        paddd     %xmm10, %xmm0
        movdqa    %xmm6, %xmm11
        paddd     1056(%rsp), %xmm0
        paddd     %xmm6, %xmm2
        por       %xmm9, %xmm1
        pxor      %xmm13, %xmm11
        movdqa    (%rsp), %xmm9
        pxor      %xmm2, %xmm11
        paddd     %xmm12, %xmm9
        paddd     %xmm12, %xmm14
        movdqa    %xmm0, %xmm12
        paddd     %xmm9, %xmm11
        pslld     $11, %xmm12
        psrld     $21, %xmm0
        paddd     1040(%rsp), %xmm11
        por       %xmm0, %xmm12
        movdqa    %xmm3, %xmm9
        movdqa    %xmm4, %xmm10
        movdqa    .L_2il0floatpacket.59(%rip), %xmm15
        paddd     %xmm3, %xmm12
        movdqa    %xmm11, %xmm0
        pxor      %xmm7, %xmm9
        paddd     %xmm4, %xmm1
        pxor      %xmm8, %xmm10
        pslld     $11, %xmm0
        psrld     $21, %xmm11
        paddd     %xmm15, %xmm5
        pxor      %xmm12, %xmm9
        pxor      %xmm1, %xmm10
        por       %xmm11, %xmm0
        paddd     %xmm5, %xmm9
        movdqa    %xmm2, %xmm5
        paddd     %xmm10, %xmm14
        paddd     %xmm2, %xmm0
        pxor      %xmm6, %xmm5
        paddd     %xmm15, %xmm13
        paddd     1296(%rsp), %xmm14
        pxor      %xmm0, %xmm5
        movdqa    %xmm14, %xmm11
        paddd     %xmm13, %xmm5
        paddd     944(%rsp), %xmm5
        pslld     $11, %xmm11
        psrld     $21, %xmm14
        paddd     %xmm15, %xmm8
        por       %xmm14, %xmm11
        pshufhw   $177, %xmm5, %xmm14
        movdqa    %xmm1, %xmm5
        paddd     1168(%rsp), %xmm9
        paddd     %xmm1, %xmm11
        pxor      %xmm4, %xmm5
        pshufhw   $177, %xmm9, %xmm13
        pxor      %xmm11, %xmm5
        pshuflw   $177, %xmm13, %xmm10
        paddd     %xmm5, %xmm8
        movdqa    %xmm12, %xmm5
        paddd     %xmm12, %xmm10
        paddd     1184(%rsp), %xmm8
        pxor      %xmm3, %xmm5
        pshuflw   $177, %xmm14, %xmm9
        pxor      %xmm10, %xmm5
        movdqa    .L_2il0floatpacket.60(%rip), %xmm14
        movdqa    %xmm0, %xmm13
        pshufhw   $177, %xmm8, %xmm8
        paddd     %xmm14, %xmm7
        pshuflw   $177, %xmm8, %xmm8
        paddd     %xmm7, %xmm5
        movdqa    %xmm11, %xmm7
        paddd     %xmm11, %xmm8
        pxor      %xmm1, %xmm7
        paddd     %xmm14, %xmm4
        paddd     1472(%rsp), %xmm5
        pxor      %xmm8, %xmm7
        paddd     %xmm0, %xmm9
        pxor      %xmm2, %xmm13
        paddd     %xmm7, %xmm4
        movdqa    %xmm5, %xmm7
        paddd     1504(%rsp), %xmm4
        paddd     %xmm14, %xmm6
        pxor      %xmm9, %xmm13
        pslld     $23, %xmm7
        psrld     $9, %xmm5
        paddd     %xmm6, %xmm13
        por       %xmm5, %xmm7
        movdqa    %xmm4, %xmm5
        paddd     1456(%rsp), %xmm13
        pslld     $23, %xmm5
        psrld     $9, %xmm4
        movdqa    %xmm13, %xmm6
        por       %xmm4, %xmm5
        movdqa    %xmm10, %xmm4
        movdqa    .L_2il0floatpacket.61(%rip), %xmm14
        paddd     %xmm10, %xmm7
        pslld     $23, %xmm6
        psrld     $9, %xmm13
        pxor      %xmm12, %xmm4
        por       %xmm13, %xmm6
        paddd     %xmm14, %xmm3
        pxor      %xmm7, %xmm4
        movdqa    %xmm9, %xmm13
        paddd     %xmm9, %xmm6
        paddd     %xmm4, %xmm3
        pxor      %xmm0, %xmm13
        paddd     880(%rsp), %xmm3
        paddd     %xmm14, %xmm2
        pxor      %xmm6, %xmm13
        movdqa    %xmm8, %xmm15
        paddd     %xmm8, %xmm5
        paddd     %xmm13, %xmm2
        pxor      %xmm11, %xmm15
        movdqa    %xmm3, %xmm4
        paddd     864(%rsp), %xmm2
        pxor      %xmm5, %xmm15
        paddd     %xmm14, %xmm1
        pslld     $4, %xmm4
        psrld     $28, %xmm3
        paddd     %xmm15, %xmm1
        por       %xmm3, %xmm4
        movdqa    %xmm2, %xmm3
        paddd     1024(%rsp), %xmm1
        pslld     $4, %xmm3
        psrld     $28, %xmm2
        movdqa    %xmm6, %xmm14
        por       %xmm2, %xmm3
        movdqa    %xmm1, %xmm2
        pslld     $4, %xmm2
        psrld     $28, %xmm1
        por       %xmm1, %xmm2
        paddd     %xmm7, %xmm4
        movdqa    .L_2il0floatpacket.62(%rip), %xmm1
        paddd     %xmm6, %xmm3
        paddd     %xmm1, %xmm12
        paddd     %xmm1, %xmm0
        movdqa    %xmm7, %xmm1
        pxor      %xmm9, %xmm14
        pxor      %xmm10, %xmm1
        pxor      %xmm3, %xmm14
        pxor      %xmm4, %xmm1
        paddd     %xmm0, %xmm14
        paddd     %xmm12, %xmm1
        movdqa    %xmm5, %xmm13
        paddd     800(%rsp), %xmm1
        paddd     %xmm5, %xmm2
        paddd     816(%rsp), %xmm14
        pxor      %xmm8, %xmm13
        movdqa    1520(%rsp), %xmm12
        pcmpeqd   %xmm0, %xmm0
..B1.35:
        paddd     .L_2il0floatpacket.62(%rip), %xmm11
        pxor      %xmm2, %xmm13
        paddd     %xmm13, %xmm11
        movdqa    %xmm1, %xmm13
        pslld     $11, %xmm13
        psrld     $21, %xmm1
        por       %xmm1, %xmm13
        movdqa    %xmm14, %xmm1
        paddd     960(%rsp), %xmm11
        pslld     $11, %xmm1
        psrld     $21, %xmm14
        paddd     %xmm4, %xmm13
        por       %xmm14, %xmm1
        movdqa    %xmm11, %xmm14
        pslld     $11, %xmm14
        psrld     $21, %xmm11
        por       %xmm11, %xmm14
        movdqa    %xmm4, %xmm11
        movdqa    .L_2il0floatpacket.63(%rip), %xmm15
        pxor      %xmm7, %xmm11
        paddd     %xmm15, %xmm10
        pxor      %xmm13, %xmm11
        paddd     %xmm10, %xmm11
        movdqa    %xmm3, %xmm10
        paddd     %xmm3, %xmm1
        pxor      %xmm6, %xmm10
        paddd     %xmm15, %xmm9
        pxor      %xmm1, %xmm10
        paddd     %xmm9, %xmm10
        paddd     %xmm2, %xmm14
        paddd     1360(%rsp), %xmm11
        paddd     %xmm15, %xmm8
        paddd     1328(%rsp), %xmm10
        movdqa    %xmm4, %xmm15
        pshufhw   $177, %xmm11, %xmm9
        pxor      %xmm13, %xmm15
        pshufhw   $177, %xmm10, %xmm10
        pshuflw   $177, %xmm9, %xmm11
        pshuflw   $177, %xmm10, %xmm9
        movdqa    %xmm2, %xmm10
        pxor      %xmm5, %xmm10
        paddd     %xmm13, %xmm11
        pxor      %xmm14, %xmm10
        pxor      %xmm11, %xmm15
        paddd     %xmm10, %xmm8
        paddd     %xmm1, %xmm9
        paddd     1440(%rsp), %xmm8
        pshufhw   $177, %xmm8, %xmm8
        pshuflw   $177, %xmm8, %xmm10
        movdqa    .L_2il0floatpacket.64(%rip), %xmm8
        paddd     %xmm14, %xmm10
        paddd     %xmm8, %xmm7
        paddd     %xmm8, %xmm6
        paddd     %xmm7, %xmm15
        movdqa    %xmm3, %xmm7
        pxor      %xmm1, %xmm7
        paddd     %xmm8, %xmm5
        pxor      %xmm9, %xmm7
        paddd     %xmm6, %xmm7
        movdqa    %xmm2, %xmm6
        pxor      %xmm14, %xmm6
        paddd     1248(%rsp), %xmm7
        pxor      %xmm10, %xmm6
        paddd     1200(%rsp), %xmm15
        paddd     %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        movdqa    %xmm15, %xmm8
        paddd     1392(%rsp), %xmm5
        pslld     $23, %xmm6
        psrld     $9, %xmm7
        pslld     $23, %xmm8
        psrld     $9, %xmm15
        por       %xmm7, %xmm6
        movdqa    %xmm5, %xmm7
        por       %xmm15, %xmm8
        pslld     $23, %xmm7
        psrld     $9, %xmm5
        movdqa    %xmm11, %xmm15
        paddd     %xmm11, %xmm8
        por       %xmm5, %xmm7
        pxor      %xmm13, %xmm15
        movdqa    .L_2il0floatpacket.65(%rip), %xmm5
        pxor      %xmm8, %xmm15
        paddd     %xmm5, %xmm4
        paddd     %xmm9, %xmm6
        paddd     %xmm15, %xmm4
        movdqa    %xmm9, %xmm15
        pxor      %xmm1, %xmm15
        paddd     %xmm5, %xmm3
        pxor      %xmm6, %xmm15
        paddd     %xmm10, %xmm7
        paddd     1072(%rsp), %xmm4
        paddd     %xmm15, %xmm3
        movdqa    %xmm10, %xmm15
        paddd     %xmm5, %xmm2
        pxor      %xmm14, %xmm15
        movdqa    %xmm4, %xmm5
        paddd     1136(%rsp), %xmm3
        pxor      %xmm7, %xmm15
        pslld     $4, %xmm5
        psrld     $28, %xmm4
        paddd     %xmm15, %xmm2
        por       %xmm4, %xmm5
        movdqa    %xmm3, %xmm4
        psrld     $28, %xmm3
        paddd     1312(%rsp), %xmm2
        pslld     $4, %xmm4
        por       %xmm3, %xmm4
        movdqa    %xmm2, %xmm3
        pslld     $4, %xmm3
        psrld     $28, %xmm2
        movdqa    %xmm8, %xmm15
        paddd     %xmm8, %xmm5
        por       %xmm2, %xmm3
        pxor      %xmm11, %xmm15
        movdqa    .L_2il0floatpacket.66(%rip), %xmm2
        pxor      %xmm5, %xmm15
        paddd     %xmm2, %xmm13
        paddd     %xmm6, %xmm4
        paddd     %xmm13, %xmm15
        movdqa    %xmm6, %xmm13
        pxor      %xmm9, %xmm13
        paddd     %xmm2, %xmm1
        pxor      %xmm4, %xmm13
        paddd     %xmm7, %xmm3
        paddd     %xmm1, %xmm13
        movdqa    %xmm7, %xmm1
        pxor      %xmm10, %xmm1
        paddd     %xmm2, %xmm14
        paddd     1104(%rsp), %xmm13
        pxor      %xmm3, %xmm1
        paddd     %xmm1, %xmm14
        movdqa    %xmm13, %xmm2
        paddd     1088(%rsp), %xmm15
        paddd     %xmm12, %xmm14
        pslld     $11, %xmm2
        psrld     $21, %xmm13
        movdqa    %xmm15, %xmm1
        por       %xmm13, %xmm2
        movdqa    %xmm14, %xmm13
        pslld     $11, %xmm1
        psrld     $21, %xmm15
        pslld     $11, %xmm13
        psrld     $21, %xmm14
        por       %xmm15, %xmm1
        por       %xmm14, %xmm13
        movdqa    %xmm5, %xmm14
        movdqa    .L_2il0floatpacket.67(%rip), %xmm15
        paddd     %xmm5, %xmm1
        pxor      %xmm8, %xmm14
        paddd     %xmm15, %xmm11
        pxor      %xmm1, %xmm14
        paddd     %xmm4, %xmm2
        paddd     %xmm11, %xmm14
        movdqa    %xmm4, %xmm11
        pxor      %xmm6, %xmm11
        paddd     %xmm15, %xmm9
        pxor      %xmm2, %xmm11
        paddd     %xmm3, %xmm13
        paddd     %xmm9, %xmm11
        paddd     %xmm15, %xmm10
        paddd     992(%rsp), %xmm11
        movdqa    %xmm1, %xmm15
        pshufhw   $177, %xmm11, %xmm9
        movdqa    %xmm3, %xmm11
        pxor      %xmm7, %xmm11
        pxor      %xmm5, %xmm15
        pxor      %xmm13, %xmm11
        paddd     976(%rsp), %xmm14
        paddd     %xmm11, %xmm10
        paddd     1216(%rsp), %xmm10
        pshufhw   $177, %xmm14, %xmm14
        pshuflw   $177, %xmm14, %xmm14
        pshufhw   $177, %xmm10, %xmm10
        paddd     %xmm1, %xmm14
        pshuflw   $177, %xmm10, %xmm11
        pxor      %xmm14, %xmm15
        movdqa    .L_2il0floatpacket.68(%rip), %xmm10
        paddd     %xmm13, %xmm11
        paddd     %xmm10, %xmm8
        paddd     %xmm10, %xmm6
        pshuflw   $177, %xmm9, %xmm9
        paddd     %xmm8, %xmm15
        movdqa    %xmm2, %xmm8
        paddd     %xmm2, %xmm9
        pxor      %xmm4, %xmm8
        paddd     %xmm10, %xmm7
        pxor      %xmm9, %xmm8
        paddd     %xmm6, %xmm8
        movdqa    %xmm13, %xmm6
        pxor      %xmm3, %xmm6
        paddd     928(%rsp), %xmm8
        pxor      %xmm11, %xmm6
        paddd     912(%rsp), %xmm15
        paddd     %xmm6, %xmm7
        movdqa    %xmm8, %xmm6
        movdqa    %xmm15, %xmm10
        paddd     1120(%rsp), %xmm7
        pslld     $23, %xmm6
        psrld     $9, %xmm8
        pslld     $23, %xmm10
        psrld     $9, %xmm15
        por       %xmm8, %xmm6
        movdqa    %xmm7, %xmm8
        por       %xmm15, %xmm10
        pslld     $23, %xmm8
        psrld     $9, %xmm7
        movdqa    %xmm14, %xmm15
        paddd     %xmm14, %xmm10
        por       %xmm7, %xmm8
        pxor      %xmm1, %xmm15
        movdqa    .L_2il0floatpacket.69(%rip), %xmm7
        pxor      %xmm10, %xmm15
        paddd     %xmm7, %xmm5
        paddd     %xmm9, %xmm6
        paddd     %xmm15, %xmm5
        movdqa    %xmm9, %xmm15
        pxor      %xmm2, %xmm15
        paddd     %xmm7, %xmm4
        pxor      %xmm6, %xmm15
        paddd     %xmm11, %xmm8
        paddd     832(%rsp), %xmm5
        paddd     %xmm15, %xmm4
        movdqa    %xmm11, %xmm15
        paddd     %xmm7, %xmm3
        pxor      %xmm13, %xmm15
        movdqa    %xmm5, %xmm7
        paddd     848(%rsp), %xmm4
        pxor      %xmm8, %xmm15
        pslld     $4, %xmm7
        psrld     $28, %xmm5
        paddd     %xmm15, %xmm3
        por       %xmm5, %xmm7
        movdqa    %xmm4, %xmm5
        psrld     $28, %xmm4
        paddd     1008(%rsp), %xmm3
        pslld     $4, %xmm5
        por       %xmm4, %xmm5
        movdqa    %xmm3, %xmm4
        pslld     $4, %xmm4
        psrld     $28, %xmm3
        movdqa    %xmm10, %xmm15
        paddd     %xmm10, %xmm7
        por       %xmm3, %xmm4
        pxor      %xmm14, %xmm15
        movdqa    .L_2il0floatpacket.70(%rip), %xmm3
        pxor      %xmm7, %xmm15
        paddd     %xmm3, %xmm1
        paddd     %xmm6, %xmm5
        paddd     %xmm1, %xmm15
        movdqa    %xmm6, %xmm1
        pxor      %xmm9, %xmm1
        paddd     %xmm3, %xmm2
        pxor      %xmm5, %xmm1
        paddd     %xmm8, %xmm4
        paddd     %xmm2, %xmm1
        movdqa    %xmm8, %xmm2
        pxor      %xmm11, %xmm2
        paddd     %xmm3, %xmm13
        paddd     1376(%rsp), %xmm1
        pxor      %xmm4, %xmm2
        paddd     %xmm2, %xmm13
        movdqa    %xmm1, %xmm3
        paddd     1408(%rsp), %xmm15
        pslld     $11, %xmm3
        paddd     1488(%rsp), %xmm13
        psrld     $21, %xmm1
        movdqa    %xmm15, %xmm2
        por       %xmm1, %xmm3
        movdqa    %xmm13, %xmm1
        pslld     $11, %xmm2
        psrld     $21, %xmm15
        pslld     $11, %xmm1
        psrld     $21, %xmm13
        por       %xmm15, %xmm2
        por       %xmm13, %xmm1
        movdqa    %xmm7, %xmm13
        movdqa    .L_2il0floatpacket.71(%rip), %xmm15
        paddd     %xmm7, %xmm2
        pxor      %xmm10, %xmm13
        paddd     %xmm15, %xmm14
        pxor      %xmm2, %xmm13
        paddd     %xmm5, %xmm3
        paddd     %xmm14, %xmm13
        movdqa    %xmm5, %xmm14
        pxor      %xmm6, %xmm14
        paddd     %xmm15, %xmm9
        pxor      %xmm3, %xmm14
        paddd     %xmm4, %xmm1
        paddd     %xmm9, %xmm14
        paddd     %xmm15, %xmm11
        paddd     1280(%rsp), %xmm14
        movdqa    %xmm2, %xmm15
        pshufhw   $177, %xmm14, %xmm14
        pxor      %xmm7, %xmm15
        pshuflw   $177, %xmm14, %xmm9
        movdqa    %xmm4, %xmm14
        pxor      %xmm8, %xmm14
        paddd     %xmm3, %xmm9
        pxor      %xmm1, %xmm14
        paddd     1264(%rsp), %xmm13
        paddd     %xmm14, %xmm11
        paddd     1424(%rsp), %xmm11
        pshufhw   $177, %xmm13, %xmm13
        pshuflw   $177, %xmm13, %xmm13
        pshufhw   $177, %xmm11, %xmm11
        paddd     %xmm2, %xmm13
        pshuflw   $177, %xmm11, %xmm14
        pxor      %xmm13, %xmm15
        movdqa    .L_2il0floatpacket.72(%rip), %xmm11
        paddd     %xmm1, %xmm14
        paddd     %xmm11, %xmm10
        paddd     %xmm11, %xmm6
        paddd     %xmm10, %xmm15
        movdqa    %xmm3, %xmm10
        pxor      %xmm5, %xmm10
        paddd     %xmm11, %xmm8
        pxor      %xmm9, %xmm10
        paddd     %xmm6, %xmm10
        movdqa    %xmm1, %xmm6
        pxor      %xmm4, %xmm6
        paddd     768(%rsp), %xmm15
        pxor      %xmm14, %xmm6
        paddd     784(%rsp), %xmm10
        paddd     %xmm6, %xmm8
        movdqa    %xmm15, %xmm6
        psrld     $9, %xmm15
        pslld     $23, %xmm6
        movdqa    %xmm10, %xmm11
        paddd     896(%rsp), %xmm8
        por       %xmm15, %xmm6
        pslld     $23, %xmm11
        psrld     $9, %xmm10
        movdqa    %xmm2, %xmm15
        paddd     %xmm13, %xmm6
        por       %xmm10, %xmm11
        movdqa    %xmm8, %xmm10
        pandn     %xmm0, %xmm15
        pslld     $23, %xmm10
        psrld     $9, %xmm8
        por       %xmm6, %xmm15
        movdqa    %xmm13, (%rsp)
        por       %xmm8, %xmm10
        movdqa    .L_2il0floatpacket.73(%rip), %xmm8
        pxor      %xmm13, %xmm15
        movdqa    %xmm3, %xmm13
        paddd     %xmm9, %xmm11
        paddd     %xmm8, %xmm7
        pandn     %xmm0, %xmm13
        por       %xmm11, %xmm13
        paddd     %xmm15, %xmm7
        movdqa    %xmm1, %xmm15
        paddd     %xmm14, %xmm10
        paddd     1088(%rsp), %xmm7
        paddd     %xmm8, %xmm5
        pxor      %xmm9, %xmm13
        pandn     %xmm0, %xmm15
        paddd     %xmm13, %xmm5
        por       %xmm10, %xmm15
        paddd     %xmm8, %xmm4
        movdqa    %xmm7, %xmm8
        paddd     1104(%rsp), %xmm5
        pxor      %xmm14, %xmm15
        pslld     $6, %xmm8
        psrld     $26, %xmm7
        paddd     %xmm15, %xmm4
        por       %xmm7, %xmm8
        movdqa    %xmm5, %xmm7
        paddd     %xmm12, %xmm4
        movdqa    (%rsp), %xmm15
        pslld     $6, %xmm7
        psrld     $26, %xmm5
        movdqa    %xmm15, %xmm12
        por       %xmm5, %xmm7
        movdqa    %xmm4, %xmm5
        movdqa    %xmm9, %xmm13
        paddd     %xmm6, %xmm8
        paddd     %xmm11, %xmm7
        pslld     $6, %xmm5
        psrld     $26, %xmm4
        pandn     %xmm0, %xmm12
        pandn     %xmm0, %xmm13
        por       %xmm4, %xmm5
        movdqa    .L_2il0floatpacket.74(%rip), %xmm4
        por       %xmm8, %xmm12
        por       %xmm7, %xmm13
        paddd     %xmm4, %xmm2
        paddd     %xmm4, %xmm3
        pxor      %xmm6, %xmm12
        pxor      %xmm11, %xmm13
        paddd     %xmm2, %xmm12
        paddd     %xmm3, %xmm13
        movdqa    %xmm14, %xmm3
        paddd     1360(%rsp), %xmm12
        paddd     %xmm10, %xmm5
        pandn     %xmm0, %xmm3
        paddd     %xmm4, %xmm1
        por       %xmm5, %xmm3
        movdqa    %xmm12, %xmm4
        paddd     1328(%rsp), %xmm13
        pxor      %xmm10, %xmm3
        pslld     $10, %xmm4
        psrld     $22, %xmm12
        paddd     %xmm3, %xmm1
        por       %xmm12, %xmm4
        movdqa    %xmm13, %xmm12
        psrld     $22, %xmm13
        paddd     1440(%rsp), %xmm1
        pslld     $10, %xmm12
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm13
        movdqa    %xmm6, %xmm2
        movdqa    %xmm11, %xmm3
        paddd     %xmm8, %xmm4
        paddd     %xmm7, %xmm12
        pslld     $10, %xmm13
        psrld     $22, %xmm1
        pandn     %xmm0, %xmm2
        pandn     %xmm0, %xmm3
        por       %xmm1, %xmm13
        por       %xmm4, %xmm2
        movdqa    .L_2il0floatpacket.75(%rip), %xmm1
        por       %xmm12, %xmm3
        paddd     %xmm1, %xmm15
        paddd     %xmm1, %xmm9
        pxor      %xmm8, %xmm2
        pxor      %xmm7, %xmm3
        paddd     %xmm15, %xmm2
        paddd     %xmm9, %xmm3
        movdqa    %xmm10, %xmm9
        paddd     %xmm5, %xmm13
        paddd     1472(%rsp), %xmm2
        pandn     %xmm0, %xmm9
        por       %xmm13, %xmm9
        paddd     %xmm1, %xmm14
        movdqa    %xmm2, %xmm1
        pxor      %xmm5, %xmm9
        paddd     1456(%rsp), %xmm3
        pslld     $15, %xmm1
        psrld     $17, %xmm2
        paddd     %xmm9, %xmm14
        por       %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        paddd     1504(%rsp), %xmm14
        pslld     $15, %xmm2
        psrld     $17, %xmm3
        movdqa    %xmm8, %xmm9
        por       %xmm3, %xmm2
        movdqa    %xmm14, %xmm3
        pslld     $15, %xmm3
        psrld     $17, %xmm14
        por       %xmm14, %xmm3
        movdqa    %xmm7, %xmm14
        paddd     %xmm12, %xmm2
        pandn     %xmm0, %xmm14
        movdqa    .L_2il0floatpacket.76(%rip), %xmm15
        por       %xmm2, %xmm14
        paddd     %xmm4, %xmm1
        paddd     %xmm15, %xmm11
        pandn     %xmm0, %xmm9
        pxor      %xmm12, %xmm14
        por       %xmm1, %xmm9
        paddd     %xmm11, %xmm14
        movdqa    %xmm5, %xmm11
        paddd     %xmm13, %xmm3
        paddd     %xmm15, %xmm6
        pxor      %xmm4, %xmm9
        pandn     %xmm0, %xmm11
        paddd     %xmm6, %xmm9
        por       %xmm3, %xmm11
        paddd     %xmm15, %xmm10
        paddd     1152(%rsp), %xmm9
        pxor      %xmm13, %xmm11
        paddd     %xmm11, %xmm10
        movdqa    %xmm9, %xmm6
        paddd     1232(%rsp), %xmm14
        pslld     $21, %xmm6
        paddd     1344(%rsp), %xmm10
..B1.34:
        psrld     $11, %xmm9
        movdqa    %xmm10, %xmm11
        por       %xmm9, %xmm6
        movdqa    %xmm14, %xmm9
        movdqa    %xmm4, %xmm15
        paddd     %xmm1, %xmm6
        pslld     $21, %xmm9
        psrld     $11, %xmm14
        pslld     $21, %xmm11
        psrld     $11, %xmm10
        pandn     %xmm0, %xmm15
        por       %xmm14, %xmm9
        por       %xmm10, %xmm11
        por       %xmm6, %xmm15
        movdqa    .L_2il0floatpacket.77(%rip), %xmm10
        movdqa    %xmm12, %xmm14
        paddd     %xmm2, %xmm9
        paddd     %xmm10, %xmm8
        pxor      %xmm1, %xmm15
        pandn     %xmm0, %xmm14
        por       %xmm9, %xmm14
        paddd     %xmm15, %xmm8
        movdqa    %xmm13, %xmm15
        paddd     %xmm3, %xmm11
        paddd     1408(%rsp), %xmm8
        paddd     %xmm10, %xmm7
        pxor      %xmm2, %xmm14
        pandn     %xmm0, %xmm15
        paddd     %xmm14, %xmm7
        por       %xmm11, %xmm15
        paddd     %xmm10, %xmm5
        movdqa    %xmm8, %xmm10
        paddd     1376(%rsp), %xmm7
        pxor      %xmm3, %xmm15
        pslld     $6, %xmm10
        psrld     $26, %xmm8
        paddd     %xmm15, %xmm5
        por       %xmm8, %xmm10
        movdqa    %xmm7, %xmm8
        psrld     $26, %xmm7
        paddd     1488(%rsp), %xmm5
        pslld     $6, %xmm8
        por       %xmm7, %xmm8
        movdqa    %xmm5, %xmm7
        movdqa    %xmm1, %xmm15
        paddd     %xmm6, %xmm10
        pslld     $6, %xmm7
        psrld     $26, %xmm5
        pandn     %xmm0, %xmm15
        por       %xmm5, %xmm7
        movdqa    .L_2il0floatpacket.78(%rip), %xmm14
        por       %xmm10, %xmm15
        movdqa    %xmm2, %xmm5
        paddd     %xmm9, %xmm8
        paddd     %xmm14, %xmm4
        pxor      %xmm6, %xmm15
        pandn     %xmm0, %xmm5
        paddd     %xmm4, %xmm15
        por       %xmm8, %xmm5
        movdqa    %xmm3, %xmm4
        paddd     %xmm11, %xmm7
        paddd     %xmm14, %xmm12
        pxor      %xmm9, %xmm5
        pandn     %xmm0, %xmm4
        paddd     %xmm12, %xmm5
        por       %xmm7, %xmm4
        paddd     976(%rsp), %xmm15
        pxor      %xmm11, %xmm4
        paddd     992(%rsp), %xmm5
        paddd     %xmm14, %xmm13
        paddd     %xmm4, %xmm13
        movdqa    %xmm15, %xmm4
        movdqa    %xmm5, %xmm12
        pslld     $10, %xmm4
        paddd     1216(%rsp), %xmm13
        psrld     $22, %xmm15
        pslld     $10, %xmm12
        psrld     $22, %xmm5
        por       %xmm15, %xmm4
        por       %xmm5, %xmm12
        movdqa    %xmm13, %xmm5
        movdqa    %xmm6, %xmm14
        paddd     %xmm10, %xmm4
        pslld     $10, %xmm5
        psrld     $22, %xmm13
        pandn     %xmm0, %xmm14
        movdqa    .L_2il0floatpacket.79(%rip), %xmm15
        por       %xmm13, %xmm5
        por       %xmm4, %xmm14
        movdqa    %xmm9, %xmm13
        paddd     %xmm8, %xmm12
        paddd     %xmm15, %xmm1
        pxor      %xmm10, %xmm14
        pandn     %xmm0, %xmm13
        por       %xmm12, %xmm13
        paddd     %xmm1, %xmm14
        movdqa    %xmm11, %xmm1
        paddd     %xmm7, %xmm5
        paddd     %xmm15, %xmm2
        pxor      %xmm8, %xmm13
        pandn     %xmm0, %xmm1
        paddd     %xmm2, %xmm13
        por       %xmm5, %xmm1
        paddd     %xmm15, %xmm3
        paddd     1248(%rsp), %xmm13
        pxor      %xmm7, %xmm1
        paddd     %xmm1, %xmm3
        movdqa    %xmm13, %xmm2
        paddd     1200(%rsp), %xmm14
        pslld     $15, %xmm2
        paddd     1392(%rsp), %xmm3
        psrld     $17, %xmm13
        movdqa    %xmm14, %xmm1
        por       %xmm13, %xmm2
        movdqa    %xmm3, %xmm13
        pslld     $15, %xmm1
        psrld     $17, %xmm14
        pslld     $15, %xmm13
        psrld     $17, %xmm3
        por       %xmm14, %xmm1
        por       %xmm3, %xmm13
        movdqa    %xmm10, %xmm3
        paddd     %xmm4, %xmm1
        pandn     %xmm0, %xmm3
        movdqa    .L_2il0floatpacket.80(%rip), %xmm15
        por       %xmm1, %xmm3
        paddd     %xmm15, %xmm6
        pxor      %xmm4, %xmm3
        movdqa    %xmm8, %xmm14
        paddd     %xmm6, %xmm3
        movdqa    %xmm7, %xmm6
        paddd     %xmm12, %xmm2
        paddd     %xmm5, %xmm13
        pandn     %xmm0, %xmm14
        pandn     %xmm0, %xmm6
        por       %xmm2, %xmm14
        por       %xmm13, %xmm6
        paddd     %xmm15, %xmm9
        paddd     880(%rsp), %xmm3
        pxor      %xmm12, %xmm14
        pxor      %xmm5, %xmm6
        paddd     %xmm15, %xmm11
        paddd     %xmm9, %xmm14
        paddd     %xmm6, %xmm11
        movdqa    %xmm3, %xmm6
        psrld     $11, %xmm3
        paddd     864(%rsp), %xmm14
        pslld     $21, %xmm6
        por       %xmm3, %xmm6
        movdqa    %xmm14, %xmm3
        paddd     1024(%rsp), %xmm11
        pslld     $21, %xmm3
        psrld     $11, %xmm14
        movdqa    %xmm4, %xmm9
        por       %xmm14, %xmm3
        movdqa    %xmm11, %xmm14
        paddd     %xmm1, %xmm6
        pslld     $21, %xmm14
        psrld     $11, %xmm11
        pandn     %xmm0, %xmm9
        por       %xmm11, %xmm14
        por       %xmm6, %xmm9
        movdqa    .L_2il0floatpacket.81(%rip), %xmm11
        movdqa    %xmm12, %xmm15
        paddd     %xmm2, %xmm3
        paddd     %xmm11, %xmm10
        pxor      %xmm1, %xmm9
        pandn     %xmm0, %xmm15
        por       %xmm3, %xmm15
        paddd     %xmm9, %xmm10
        movdqa    %xmm5, %xmm9
        paddd     %xmm13, %xmm14
        paddd     1056(%rsp), %xmm10
        paddd     %xmm11, %xmm8
        pxor      %xmm2, %xmm15
        pandn     %xmm0, %xmm9
        paddd     %xmm15, %xmm8
        por       %xmm14, %xmm9
        paddd     %xmm11, %xmm7
        movdqa    %xmm10, %xmm11
        paddd     1040(%rsp), %xmm8
        pxor      %xmm13, %xmm9
        pslld     $6, %xmm11
        psrld     $26, %xmm10
        paddd     %xmm9, %xmm7
        por       %xmm10, %xmm11
        movdqa    %xmm8, %xmm10
        psrld     $26, %xmm8
        paddd     1296(%rsp), %xmm7
        pslld     $6, %xmm10
        por       %xmm8, %xmm10
        movdqa    %xmm7, %xmm15
        movdqa    %xmm2, %xmm8
        paddd     %xmm3, %xmm10
        pslld     $6, %xmm15
        psrld     $26, %xmm7
        pandn     %xmm0, %xmm8
        por       %xmm7, %xmm15
        movdqa    .L_2il0floatpacket.82(%rip), %xmm9
        movdqa    %xmm1, %xmm7
        por       %xmm10, %xmm8
        paddd     %xmm6, %xmm11
        paddd     %xmm9, %xmm12
        pandn     %xmm0, %xmm7
        pxor      %xmm3, %xmm8
        por       %xmm11, %xmm7
        paddd     %xmm12, %xmm8
        movdqa    %xmm13, %xmm12
        paddd     %xmm14, %xmm15
        paddd     %xmm9, %xmm4
        pxor      %xmm6, %xmm7
        pandn     %xmm0, %xmm12
        paddd     %xmm4, %xmm7
        por       %xmm15, %xmm12
        paddd     1264(%rsp), %xmm7
        pxor      %xmm14, %xmm12
        paddd     1280(%rsp), %xmm8
        paddd     %xmm9, %xmm5
        paddd     %xmm12, %xmm5
        movdqa    %xmm7, %xmm4
        movdqa    %xmm8, %xmm12
        pslld     $10, %xmm4
        paddd     1424(%rsp), %xmm5
        psrld     $22, %xmm7
        pslld     $10, %xmm12
        psrld     $22, %xmm8
        por       %xmm7, %xmm4
        por       %xmm8, %xmm12
        movdqa    %xmm5, %xmm7
        movdqa    %xmm3, %xmm9
        paddd     %xmm10, %xmm12
        pslld     $10, %xmm7
        psrld     $22, %xmm5
        pandn     %xmm0, %xmm9
        por       %xmm5, %xmm7
        movdqa    %xmm6, %xmm8
        movdqa    .L_2il0floatpacket.83(%rip), %xmm5
        por       %xmm12, %xmm9
        paddd     %xmm11, %xmm4
        paddd     %xmm5, %xmm2
        pandn     %xmm0, %xmm8
        pxor      %xmm10, %xmm9
        por       %xmm4, %xmm8
        paddd     %xmm2, %xmm9
        movdqa    %xmm14, %xmm2
        paddd     %xmm15, %xmm7
        paddd     %xmm5, %xmm1
        pxor      %xmm11, %xmm8
        pandn     %xmm0, %xmm2
        paddd     %xmm1, %xmm8
        por       %xmm7, %xmm2
        paddd     %xmm5, %xmm13
        paddd     912(%rsp), %xmm8
        pxor      %xmm15, %xmm2
        paddd     928(%rsp), %xmm9
        paddd     %xmm2, %xmm13
        movdqa    %xmm8, %xmm1
        movdqa    %xmm9, %xmm2
        paddd     1120(%rsp), %xmm13
        pslld     $15, %xmm1
        psrld     $17, %xmm8
        pslld     $15, %xmm2
        psrld     $17, %xmm9
        por       %xmm8, %xmm1
        por       %xmm9, %xmm2
        movdqa    %xmm13, %xmm5
        movdqa    %xmm10, %xmm8
        paddd     %xmm12, %xmm2
        pslld     $15, %xmm5
        psrld     $17, %xmm13
        pandn     %xmm0, %xmm8
        por       %xmm13, %xmm5
        movdqa    .L_2il0floatpacket.84(%rip), %xmm13
        por       %xmm2, %xmm8
        paddd     %xmm13, %xmm3
        pxor      %xmm12, %xmm8
        movdqa    %xmm11, %xmm9
        paddd     %xmm3, %xmm8
        movdqa    %xmm15, %xmm3
        paddd     %xmm4, %xmm1
        paddd     %xmm7, %xmm5
        pandn     %xmm0, %xmm9
        pandn     %xmm0, %xmm3
        por       %xmm1, %xmm9
        por       %xmm5, %xmm3
        paddd     %xmm13, %xmm6
        pxor      %xmm4, %xmm9
        pxor      %xmm7, %xmm3
        paddd     %xmm13, %xmm14
        paddd     %xmm6, %xmm9
        paddd     %xmm3, %xmm14
        testl     %edx, %edx
        paddd     1072(%rsp), %xmm9
        paddd     1312(%rsp), %xmm14
        movdqa    %xmm9, %xmm6
        movdqa    %xmm14, %xmm13
        pslld     $21, %xmm6
        paddd     1136(%rsp), %xmm8
        psrld     $11, %xmm9
        pslld     $21, %xmm13
        psrld     $11, %xmm14
        por       %xmm9, %xmm6
        movdqa    %xmm8, %xmm3
        por       %xmm14, %xmm13
        movdqa    %xmm4, %xmm14
        paddd     %xmm1, %xmm6
        pslld     $21, %xmm3
        psrld     $11, %xmm8
        pandn     %xmm0, %xmm14
        por       %xmm8, %xmm3
        por       %xmm6, %xmm14
        movdqa    .L_2il0floatpacket.85(%rip), %xmm8
        movdqa    %xmm12, %xmm9
        paddd     %xmm2, %xmm3
        paddd     %xmm8, %xmm11
        pxor      %xmm1, %xmm14
        pandn     %xmm0, %xmm9
        por       %xmm3, %xmm9
        paddd     %xmm14, %xmm11
        movdqa    %xmm7, %xmm14
        paddd     %xmm5, %xmm13
        paddd     %xmm8, %xmm10
        pxor      %xmm2, %xmm9
        pandn     %xmm0, %xmm14
        paddd     %xmm9, %xmm10
        por       %xmm13, %xmm14
        paddd     %xmm8, %xmm15
        paddd     800(%rsp), %xmm11
        pxor      %xmm5, %xmm14
        paddd     816(%rsp), %xmm10
        paddd     %xmm14, %xmm15
        movdqa    %xmm11, %xmm14
        movdqa    %xmm10, %xmm9
        pslld     $6, %xmm14
        psrld     $26, %xmm11
        pslld     $6, %xmm9
        psrld     $26, %xmm10
        por       %xmm11, %xmm14
        por       %xmm10, %xmm9
        movdqa    %xmm1, %xmm10
        paddd     %xmm6, %xmm14
        paddd     960(%rsp), %xmm15
        pandn     %xmm0, %xmm10
        movdqa    .L_2il0floatpacket.86(%rip), %xmm11
        movdqa    %xmm15, %xmm8
        por       %xmm14, %xmm10
        pslld     $6, %xmm8
        psrld     $26, %xmm15
        paddd     %xmm11, %xmm4
        pxor      %xmm6, %xmm10
        por       %xmm15, %xmm8
        movdqa    %xmm2, %xmm15
        paddd     %xmm4, %xmm10
        movdqa    %xmm5, %xmm4
        paddd     %xmm3, %xmm9
        paddd     %xmm13, %xmm8
        pandn     %xmm0, %xmm15
        pandn     %xmm0, %xmm4
        por       %xmm9, %xmm15
        por       %xmm8, %xmm4
        paddd     %xmm11, %xmm12
        paddd     1168(%rsp), %xmm10
        pxor      %xmm3, %xmm15
        pxor      %xmm13, %xmm4
        paddd     %xmm11, %xmm7
        paddd     %xmm12, %xmm15
        paddd     %xmm4, %xmm7
        movdqa    %xmm10, %xmm11
        psrld     $22, %xmm10
        paddd     944(%rsp), %xmm15
        pslld     $10, %xmm11
        paddd     1184(%rsp), %xmm7
        por       %xmm10, %xmm11
        movdqa    %xmm15, %xmm10
        movdqa    %xmm7, %xmm4
        movdqa    %xmm6, %xmm12
        paddd     %xmm14, %xmm11
        pslld     $10, %xmm10
        psrld     $22, %xmm15
        pslld     $10, %xmm4
        psrld     $22, %xmm7
        pandn     %xmm0, %xmm12
        por       %xmm15, %xmm10
        movdqa    .L_2il0floatpacket.87(%rip), %xmm15
        por       %xmm7, %xmm4
        por       %xmm11, %xmm12
        movdqa    %xmm3, %xmm7
        paddd     %xmm9, %xmm10
        paddd     %xmm15, %xmm1
        pxor      %xmm14, %xmm12
        pandn     %xmm0, %xmm7
        por       %xmm10, %xmm7
        paddd     %xmm1, %xmm12
        movdqa    %xmm13, %xmm1
        paddd     %xmm8, %xmm4
        paddd     %xmm15, %xmm2
        pxor      %xmm9, %xmm7
        pandn     %xmm0, %xmm1
        paddd     %xmm2, %xmm7
        por       %xmm4, %xmm1
        paddd     %xmm15, %xmm5
        paddd     768(%rsp), %xmm12
        pxor      %xmm8, %xmm1
        paddd     784(%rsp), %xmm7
        paddd     %xmm1, %xmm5
        movdqa    %xmm12, %xmm2
        movdqa    %xmm7, %xmm1
        pslld     $15, %xmm2
        psrld     $17, %xmm12
        pslld     $15, %xmm1
        psrld     $17, %xmm7
        por       %xmm12, %xmm2
        por       %xmm7, %xmm1
        movdqa    %xmm14, %xmm7
        paddd     %xmm11, %xmm2
        paddd     896(%rsp), %xmm5
        pandn     %xmm0, %xmm7
        movdqa    .L_2il0floatpacket.88(%rip), %xmm15
        movdqa    %xmm5, %xmm12
        por       %xmm2, %xmm7
        pslld     $15, %xmm12
        psrld     $17, %xmm5
        paddd     %xmm15, %xmm6
        pxor      %xmm11, %xmm7
        por       %xmm5, %xmm12
        movdqa    %xmm9, %xmm5
        paddd     %xmm6, %xmm7
        movdqa    %xmm8, %xmm6
        paddd     %xmm10, %xmm1
        paddd     %xmm4, %xmm12
        pandn     %xmm0, %xmm5
        pandn     %xmm0, %xmm6
        por       %xmm1, %xmm5
        por       %xmm12, %xmm6
        paddd     %xmm15, %xmm3
        pxor      %xmm10, %xmm5
        pxor      %xmm4, %xmm6
        paddd     %xmm15, %xmm13
        paddd     %xmm3, %xmm5
        paddd     %xmm6, %xmm13
        paddd     832(%rsp), %xmm7
        paddd     848(%rsp), %xmm5
        movdqa    %xmm7, %xmm6
        paddd     1008(%rsp), %xmm13
        movdqa    %xmm5, %xmm3
        movdqa    %xmm13, %xmm0
        pslld     $21, %xmm6
        psrld     $11, %xmm7
        pslld     $21, %xmm3
        psrld     $11, %xmm5
        pslld     $21, %xmm0
        psrld     $11, %xmm13
        por       %xmm7, %xmm6
        por       %xmm5, %xmm3
        por       %xmm13, %xmm0
        paddd     %xmm2, %xmm6
        paddd     %xmm1, %xmm3
        paddd     %xmm12, %xmm0
        jne       ..B1.25
..B1.24:
        movdqa    .L_2il0floatpacket.89(%rip), %xmm5
        movdqa    .L_2il0floatpacket.22(%rip), %xmm7
        paddd     %xmm5, %xmm14
        movdqa    .L_2il0floatpacket.23(%rip), %xmm13
        paddd     %xmm7, %xmm6
        movdqa    .L_2il0floatpacket.24(%rip), %xmm15
        paddd     %xmm13, %xmm2
        paddd     %xmm15, %xmm11
        paddd     %xmm5, %xmm9
        paddd     %xmm7, %xmm3
        paddd     %xmm13, %xmm1
        paddd     %xmm15, %xmm10
        paddd     %xmm5, %xmm8
        paddd     %xmm7, %xmm0
        paddd     %xmm13, %xmm12
        paddd     %xmm15, %xmm4
        jmp       ..B1.28
..B1.25:
        movl      %r8d, %eax
        andl      $6, %eax
        movdqa    (%rcx), %xmm5
        cmpl      $6, %eax
        movdqa    16(%rcx), %xmm7
        paddd     %xmm5, %xmm14
        movdqa    32(%rcx), %xmm13
        paddd     %xmm7, %xmm6
        movdqa    48(%rcx), %xmm15
        paddd     %xmm13, %xmm2
        paddd     %xmm15, %xmm11
        jne       ..B1.27
..B1.26:
        movdqa    256(%rcx), %xmm5
        movdqa    272(%rcx), %xmm7
        paddd     %xmm5, %xmm9
        movdqa    288(%rcx), %xmm13
        paddd     %xmm7, %xmm3
        movdqa    304(%rcx), %xmm15
        paddd     %xmm13, %xmm1
        movdqa    512(%rcx), %xmm5
        paddd     %xmm15, %xmm10
        movdqa    528(%rcx), %xmm7
        paddd     %xmm5, %xmm8
        movdqa    544(%rcx), %xmm13
        paddd     %xmm7, %xmm0
        movdqa    560(%rcx), %xmm15
        paddd     %xmm13, %xmm12
        paddd     %xmm15, %xmm4
        jmp       ..B1.28
..B1.27:
        movdqa    64(%rcx), %xmm5
        movdqa    80(%rcx), %xmm7
        paddd     %xmm5, %xmm9
        movdqa    96(%rcx), %xmm13
        paddd     %xmm7, %xmm3
        movdqa    112(%rcx), %xmm15
        paddd     %xmm13, %xmm1
        movdqa    128(%rcx), %xmm5
        paddd     %xmm15, %xmm10
        movdqa    144(%rcx), %xmm7
        paddd     %xmm5, %xmm8
        movdqa    160(%rcx), %xmm13
        paddd     %xmm7, %xmm0
        movdqa    176(%rcx), %xmm15
        paddd     %xmm13, %xmm12
        paddd     %xmm15, %xmm4
..B1.28:
        movdqa    %xmm14, (%rsi)
        testl     $8, %r8d
        movdqa    %xmm6, 16(%rsi)
        movdqa    %xmm2, 32(%rsi)
        movdqa    %xmm11, 48(%rsi)
        je        ..B1.30
..B1.29:
        movdqa    %xmm9, 256(%rsi)
        movdqa    %xmm3, 272(%rsi)
        movdqa    %xmm1, 288(%rsi)
        movdqa    %xmm10, 304(%rsi)
        movdqa    %xmm8, 512(%rsi)
        movdqa    %xmm0, 528(%rsi)
        movdqa    %xmm12, 544(%rsi)
        movdqa    %xmm4, 560(%rsi)
        addq      $1544, %rsp
..___tag_value_SIMDmd5body.4:
        ret       
..___tag_value_SIMDmd5body.5:
..B1.30:
        movdqa    %xmm9, 64(%rsi)
        movdqa    %xmm3, 80(%rsi)
        movdqa    %xmm1, 96(%rsi)
        movdqa    %xmm10, 112(%rsi)
        movdqa    %xmm8, 128(%rsi)
        movdqa    %xmm0, 144(%rsi)
        movdqa    %xmm12, 160(%rsi)
        movdqa    %xmm4, 176(%rsi)
..B1.31:
        addq      $1544, %rsp
..___tag_value_SIMDmd5body.6:
        ret       
        .align    16,0x90
..___tag_value_SIMDmd5body.7:
	.type	SIMDmd5body,@function
	.size	SIMDmd5body,.-SIMDmd5body
	.data
# -- End  SIMDmd5body
	.text
# -- Begin  SIMDmd5body..0
       .align    16,0x90
SIMDmd5body..0:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B2.1:
..___tag_value_SIMDmd5body..0.8:
        subq      $792, %rsp
..___tag_value_SIMDmd5body..0.10:
        movdqa    .L_2il0floatpacket.23(%rip), %xmm14
        pcmpeqd   %xmm13, %xmm13
        movdqa    .L_2il0floatpacket.24(%rip), %xmm10
        movdqa    %xmm14, %xmm0
        movdqa    .L_2il0floatpacket.22(%rip), %xmm11
        pxor      %xmm10, %xmm0
        movdqa    .L_2il0floatpacket.25(%rip), %xmm5
        pand      %xmm11, %xmm0
        paddd     .L_2il0floatpacket.89(%rip), %xmm5
        pxor      %xmm10, %xmm0
        movdqa    (%rdi), %xmm9
        paddd     %xmm0, %xmm5
        movdqa    %xmm9, 464(%rsp)
        paddd     %xmm5, %xmm9
        movdqa    256(%rdi), %xmm1
        movdqa    %xmm9, %xmm0
        movdqa    %xmm1, 432(%rsp)
        paddd     %xmm5, %xmm1
        pslld     $7, %xmm0
        psrld     $25, %xmm9
        por       %xmm9, %xmm0
        movdqa    %xmm1, %xmm8
        movdqa    512(%rdi), %xmm3
        paddd     %xmm11, %xmm0
        pslld     $7, %xmm8
        psrld     $25, %xmm1
        movdqa    %xmm11, %xmm6
        paddd     %xmm3, %xmm5
        movdqa    %xmm3, 416(%rsp)
        por       %xmm1, %xmm8
        pxor      %xmm14, %xmm6
        movdqa    %xmm0, %xmm3
        movdqa    .L_2il0floatpacket.26(%rip), %xmm7
        paddd     %xmm11, %xmm8
        movdqa    %xmm5, %xmm9
        pand      %xmm6, %xmm3
        pslld     $7, %xmm9
        psrld     $25, %xmm5
        paddd     %xmm10, %xmm7
        pxor      %xmm14, %xmm3
        movdqa    %xmm8, %xmm12
        por       %xmm5, %xmm9
        movdqa    16(%rdi), %xmm15
        paddd     %xmm7, %xmm3
        pand      %xmm6, %xmm12
        paddd     %xmm11, %xmm9
        paddd     %xmm15, %xmm3
        pxor      %xmm14, %xmm12
        movdqa    272(%rdi), %xmm2
        paddd     %xmm7, %xmm12
        pand      %xmm9, %xmm6
        movdqa    %xmm3, %xmm1
        paddd     %xmm2, %xmm12
        pxor      %xmm14, %xmm6
        pslld     $12, %xmm1
        psrld     $20, %xmm3
        movdqa    %xmm15, 192(%rsp)
        paddd     %xmm6, %xmm7
        movdqa    528(%rdi), %xmm4
        por       %xmm3, %xmm1
        movdqa    %xmm12, %xmm6
        movdqa    %xmm11, %xmm15
        paddd     %xmm4, %xmm7
        paddd     %xmm0, %xmm1
        pslld     $12, %xmm6
        psrld     $20, %xmm12
        pxor      %xmm0, %xmm15
        por       %xmm12, %xmm6
        movdqa    .L_2il0floatpacket.27(%rip), %xmm12
        movdqa    %xmm7, %xmm3
        pand      %xmm1, %xmm15
        pslld     $12, %xmm3
        movdqa    %xmm2, 144(%rsp)
        psrld     $20, %xmm7
        paddd     %xmm14, %xmm12
        pxor      %xmm11, %xmm15
        movdqa    %xmm11, %xmm2
        paddd     %xmm8, %xmm6
        por       %xmm7, %xmm3
        paddd     %xmm12, %xmm15
        movdqa    32(%rdi), %xmm7
        pxor      %xmm8, %xmm2
        movdqa    %xmm7, (%rsp)
        paddd     %xmm7, %xmm15
        pand      %xmm6, %xmm2
        movdqa    %xmm11, %xmm7
        paddd     %xmm9, %xmm3
        pxor      %xmm11, %xmm2
        pxor      %xmm9, %xmm7
        paddd     %xmm12, %xmm2
        movdqa    288(%rdi), %xmm14
        pand      %xmm3, %xmm7
        paddd     %xmm14, %xmm2
        pxor      %xmm11, %xmm7
        movdqa    544(%rdi), %xmm10
        paddd     %xmm7, %xmm12
        movdqa    %xmm15, %xmm7
        movdqa    %xmm2, %xmm5
        paddd     %xmm10, %xmm12
        pslld     $17, %xmm7
        psrld     $15, %xmm15
        pslld     $17, %xmm5
        psrld     $15, %xmm2
        por       %xmm15, %xmm7
        movdqa    %xmm4, 320(%rsp)
        por       %xmm2, %xmm5
        movdqa    %xmm10, 96(%rsp)
        movdqa    %xmm12, %xmm10
        movdqa    %xmm1, %xmm2
        movdqa    %xmm6, %xmm4
        paddd     %xmm1, %xmm7
        paddd     %xmm6, %xmm5
        pslld     $17, %xmm10
        psrld     $15, %xmm12
        pxor      %xmm0, %xmm2
        pxor      %xmm8, %xmm4
        movdqa    %xmm14, 16(%rsp)
        por       %xmm12, %xmm10
        movdqa    .L_2il0floatpacket.28(%rip), %xmm15
        pand      %xmm7, %xmm2
        pand      %xmm5, %xmm4
        movdqa    %xmm3, %xmm14
        paddd     %xmm3, %xmm10
        paddd     %xmm11, %xmm15
        pxor      %xmm0, %xmm2
        pxor      %xmm8, %xmm4
        pxor      %xmm9, %xmm14
        paddd     %xmm15, %xmm2
        movdqa    48(%rdi), %xmm11
        paddd     %xmm15, %xmm4
        movdqa    304(%rdi), %xmm12
        pand      %xmm10, %xmm14
        paddd     %xmm11, %xmm2
        paddd     %xmm12, %xmm4
        pxor      %xmm9, %xmm14
        movdqa    %xmm11, 288(%rsp)
        paddd     %xmm14, %xmm15
        movdqa    %xmm12, 272(%rsp)
        movdqa    %xmm2, %xmm12
        movdqa    560(%rdi), %xmm11
        movdqa    %xmm4, %xmm14
        paddd     %xmm11, %xmm15
        pslld     $22, %xmm12
        psrld     $10, %xmm2
        pslld     $22, %xmm14
        psrld     $10, %xmm4
        por       %xmm2, %xmm12
        movdqa    %xmm11, 544(%rsp)
        por       %xmm4, %xmm14
        movdqa    %xmm15, %xmm11
        movdqa    %xmm7, %xmm4
        paddd     %xmm7, %xmm12
        pslld     $22, %xmm11
        psrld     $10, %xmm15
        pxor      %xmm1, %xmm4
        por       %xmm15, %xmm11
        pand      %xmm12, %xmm4
        movdqa    .L_2il0floatpacket.29(%rip), %xmm15
        pxor      %xmm1, %xmm4
        paddd     %xmm15, %xmm0
        movdqa    %xmm5, %xmm2
        paddd     %xmm5, %xmm14
        paddd     %xmm4, %xmm0
        movdqa    64(%rdi), %xmm4
        pxor      %xmm6, %xmm2
        movdqa    %xmm4, 32(%rsp)
        pand      %xmm14, %xmm2
        paddd     %xmm4, %xmm0
        movdqa    %xmm10, %xmm4
        paddd     %xmm10, %xmm11
        paddd     %xmm15, %xmm8
        pxor      %xmm6, %xmm2
        pxor      %xmm3, %xmm4
        paddd     %xmm2, %xmm8
        pand      %xmm11, %xmm4
        movdqa    320(%rdi), %xmm2
        paddd     %xmm15, %xmm9
        movdqa    %xmm0, %xmm15
        paddd     %xmm2, %xmm8
        pxor      %xmm3, %xmm4
        pslld     $7, %xmm15
        psrld     $25, %xmm0
        paddd     %xmm4, %xmm9
        movdqa    %xmm2, 48(%rsp)
        por       %xmm0, %xmm15
        movdqa    576(%rdi), %xmm2
        movdqa    %xmm8, %xmm0
        paddd     %xmm2, %xmm9
        pslld     $7, %xmm0
        psrld     $25, %xmm8
        movdqa    %xmm12, %xmm4
        por       %xmm8, %xmm0
        movdqa    %xmm9, %xmm8
        paddd     %xmm12, %xmm15
        pslld     $7, %xmm8
        psrld     $25, %xmm9
        pxor      %xmm7, %xmm4
        por       %xmm9, %xmm8
        pand      %xmm15, %xmm4
        movdqa    .L_2il0floatpacket.30(%rip), %xmm9
        pxor      %xmm7, %xmm4
        movdqa    %xmm2, 256(%rsp)
        paddd     %xmm9, %xmm1
        movdqa    %xmm14, %xmm2
        paddd     %xmm14, %xmm0
        paddd     %xmm4, %xmm1
        pxor      %xmm5, %xmm2
        movdqa    80(%rdi), %xmm4
        pand      %xmm0, %xmm2
        movdqa    %xmm4, 384(%rsp)
        paddd     %xmm4, %xmm1
        movdqa    %xmm11, %xmm4
        paddd     %xmm11, %xmm8
        paddd     %xmm9, %xmm6
        pxor      %xmm5, %xmm2
        pxor      %xmm10, %xmm4
        paddd     %xmm2, %xmm6
        movdqa    336(%rdi), %xmm2
        pand      %xmm8, %xmm4
        paddd     %xmm9, %xmm3
        movdqa    %xmm1, %xmm9
        paddd     %xmm2, %xmm6
        pxor      %xmm10, %xmm4
        pslld     $12, %xmm9
        psrld     $20, %xmm1
        movdqa    %xmm2, 368(%rsp)
        paddd     %xmm4, %xmm3
        movdqa    592(%rdi), %xmm2
        por       %xmm1, %xmm9
        movdqa    %xmm6, %xmm1
        paddd     %xmm2, %xmm3
        pslld     $12, %xmm1
        psrld     $20, %xmm6
        movdqa    %xmm2, 656(%rsp)
        por       %xmm6, %xmm1
        movdqa    %xmm3, %xmm2
        movdqa    %xmm15, %xmm6
        paddd     %xmm15, %xmm9
        pslld     $12, %xmm2
        psrld     $20, %xmm3
        pxor      %xmm12, %xmm6
        por       %xmm3, %xmm2
        pand      %xmm9, %xmm6
        movdqa    .L_2il0floatpacket.31(%rip), %xmm3
        pxor      %xmm12, %xmm6
        paddd     %xmm3, %xmm7
        movdqa    %xmm0, %xmm4
        paddd     %xmm0, %xmm1
        paddd     %xmm6, %xmm7
        movdqa    96(%rdi), %xmm6
        pxor      %xmm14, %xmm4
        movdqa    %xmm6, 128(%rsp)
        pand      %xmm1, %xmm4
        paddd     %xmm6, %xmm7
        movdqa    %xmm8, %xmm6
        paddd     %xmm8, %xmm2
        paddd     %xmm3, %xmm5
        pxor      %xmm14, %xmm4
        pxor      %xmm11, %xmm6
        paddd     %xmm4, %xmm5
        pand      %xmm2, %xmm6
        movdqa    352(%rdi), %xmm4
        paddd     %xmm3, %xmm10
        movdqa    %xmm7, %xmm3
        paddd     %xmm4, %xmm5
        pxor      %xmm11, %xmm6
        pslld     $17, %xmm3
        psrld     $15, %xmm7
        paddd     %xmm6, %xmm10
        movdqa    %xmm4, 112(%rsp)
        por       %xmm7, %xmm3
        movdqa    608(%rdi), %xmm4
        movdqa    %xmm5, %xmm7
        paddd     %xmm4, %xmm10
        pslld     $17, %xmm7
        psrld     $15, %xmm5
        movdqa    %xmm1, %xmm6
        movdqa    %xmm4, 304(%rsp)
        por       %xmm5, %xmm7
        movdqa    %xmm10, %xmm4
        paddd     %xmm1, %xmm7
        pslld     $17, %xmm4
        psrld     $15, %xmm10
        pxor      %xmm0, %xmm6
        movdqa    %xmm9, %xmm5
        por       %xmm10, %xmm4
        pand      %xmm7, %xmm6
        movdqa    .L_2il0floatpacket.32(%rip), %xmm10
        paddd     %xmm9, %xmm3
        pxor      %xmm15, %xmm5
        paddd     %xmm10, %xmm14
        pxor      %xmm0, %xmm6
        pand      %xmm3, %xmm5
        paddd     %xmm6, %xmm14
        movdqa    %xmm2, %xmm6
        paddd     %xmm10, %xmm12
        pxor      %xmm15, %xmm5
        paddd     %xmm2, %xmm4
        pxor      %xmm8, %xmm6
        paddd     %xmm5, %xmm12
        pand      %xmm4, %xmm6
        movdqa    112(%rdi), %xmm5
        pxor      %xmm8, %xmm6
        movdqa    %xmm5, 576(%rsp)
        paddd     %xmm5, %xmm12
        movdqa    368(%rdi), %xmm5
        paddd     %xmm10, %xmm11
        movdqa    %xmm5, 592(%rsp)
        paddd     %xmm5, %xmm14
        movdqa    624(%rdi), %xmm5
        paddd     %xmm6, %xmm11
        movdqa    %xmm5, 736(%rsp)
        paddd     %xmm5, %xmm11
        movdqa    %xmm12, %xmm5
        psrld     $10, %xmm12
        pslld     $22, %xmm5
        movdqa    %xmm11, %xmm10
        por       %xmm12, %xmm5
        movdqa    %xmm3, %xmm12
        paddd     %xmm3, %xmm5
        movdqa    %xmm14, %xmm6
        pslld     $22, %xmm10
        psrld     $10, %xmm11
        pxor      %xmm9, %xmm12
        pslld     $22, %xmm6
        psrld     $10, %xmm14
        por       %xmm11, %xmm10
        movdqa    .L_2il0floatpacket.33(%rip), %xmm11
        pand      %xmm5, %xmm12
        por       %xmm14, %xmm6
        paddd     %xmm11, %xmm15
        pxor      %xmm9, %xmm12
        movdqa    %xmm7, %xmm14
        paddd     %xmm7, %xmm6
        paddd     %xmm12, %xmm15
        movdqa    128(%rdi), %xmm12
        pxor      %xmm1, %xmm14
        movdqa    %xmm12, 240(%rsp)
        pand      %xmm6, %xmm14
        paddd     %xmm12, %xmm15
        movdqa    %xmm4, %xmm12
        paddd     %xmm4, %xmm10
        paddd     %xmm11, %xmm0
        pxor      %xmm1, %xmm14
        pxor      %xmm2, %xmm12
        paddd     %xmm14, %xmm0
        pand      %xmm10, %xmm12
        movdqa    384(%rdi), %xmm14
        paddd     %xmm11, %xmm8
        movdqa    %xmm15, %xmm11
        paddd     %xmm14, %xmm0
        pxor      %xmm2, %xmm12
        pslld     $7, %xmm11
        psrld     $25, %xmm15
        paddd     %xmm12, %xmm8
        movdqa    %xmm14, 224(%rsp)
        por       %xmm15, %xmm11
        movdqa    640(%rdi), %xmm14
        movdqa    %xmm0, %xmm15
        paddd     %xmm14, %xmm8
        pslld     $7, %xmm15
        psrld     $25, %xmm0
        paddd     %xmm5, %xmm11
        por       %xmm0, %xmm15
        movdqa    %xmm8, %xmm0
        movdqa    %xmm14, 480(%rsp)
        movdqa    %xmm6, %xmm14
        pslld     $7, %xmm0
        psrld     $25, %xmm8
        paddd     %xmm6, %xmm15
        pxor      %xmm7, %xmm14
        por       %xmm8, %xmm0
        movdqa    %xmm5, %xmm8
        movdqa    .L_2il0floatpacket.34(%rip), %xmm12
        pand      %xmm15, %xmm14
        pxor      %xmm3, %xmm8
        paddd     %xmm12, %xmm1
        pxor      %xmm7, %xmm14
        pand      %xmm11, %xmm8
        paddd     %xmm14, %xmm1
        movdqa    %xmm10, %xmm14
        paddd     %xmm12, %xmm9
        pxor      %xmm3, %xmm8
        paddd     %xmm10, %xmm0
        pxor      %xmm4, %xmm14
        paddd     %xmm8, %xmm9
        pand      %xmm0, %xmm14
        movdqa    144(%rdi), %xmm8
        pxor      %xmm4, %xmm14
        movdqa    %xmm8, 64(%rsp)
        paddd     %xmm8, %xmm9
        movdqa    400(%rdi), %xmm8
        paddd     %xmm12, %xmm2
        movdqa    %xmm8, 80(%rsp)
        paddd     %xmm8, %xmm1
        movdqa    656(%rdi), %xmm8
        paddd     %xmm14, %xmm2
        movdqa    %xmm8, 208(%rsp)
        paddd     %xmm8, %xmm2
        movdqa    %xmm9, %xmm8
        psrld     $20, %xmm9
        pslld     $12, %xmm8
        movdqa    %xmm11, %xmm12
        por       %xmm9, %xmm8
        movdqa    %xmm1, %xmm9
        pslld     $12, %xmm9
        psrld     $20, %xmm1
        por       %xmm1, %xmm9
        movdqa    %xmm2, %xmm1
        movdqa    %xmm15, %xmm14
        paddd     %xmm11, %xmm8
        paddd     %xmm15, %xmm9
        pslld     $12, %xmm1
        psrld     $20, %xmm2
        pxor      %xmm5, %xmm12
        pxor      %xmm6, %xmm14
        por       %xmm2, %xmm1
        movdqa    .L_2il0floatpacket.35(%rip), %xmm2
        pand      %xmm8, %xmm12
        pand      %xmm9, %xmm14
        paddd     %xmm2, %xmm3
        paddd     %xmm2, %xmm7
        pxor      %xmm5, %xmm12
        pxor      %xmm6, %xmm14
        paddd     %xmm12, %xmm3
        movdqa    160(%rdi), %xmm12
        paddd     %xmm14, %xmm7
        movdqa    %xmm0, %xmm14
        paddd     %xmm0, %xmm1
        paddd     %xmm12, %xmm3
        pxor      %xmm10, %xmm14
        movdqa    %xmm12, 496(%rsp)
        pand      %xmm1, %xmm14
        movdqa    416(%rdi), %xmm12
        paddd     %xmm2, %xmm4
        movdqa    %xmm3, %xmm2
        paddd     %xmm12, %xmm7
        pxor      %xmm10, %xmm14
        pslld     $17, %xmm2
        psrld     $15, %xmm3
        paddd     %xmm14, %xmm4
        movdqa    %xmm12, 448(%rsp)
        por       %xmm3, %xmm2
        movdqa    672(%rdi), %xmm12
        movdqa    %xmm7, %xmm3
        paddd     %xmm12, %xmm4
        pslld     $17, %xmm3
        psrld     $15, %xmm7
        movdqa    %xmm8, %xmm14
        por       %xmm7, %xmm3
        movdqa    %xmm4, %xmm7
        paddd     %xmm8, %xmm2
        pslld     $17, %xmm7
        psrld     $15, %xmm4
        pxor      %xmm11, %xmm14
        por       %xmm4, %xmm7
        pand      %xmm2, %xmm14
        movdqa    .L_2il0floatpacket.36(%rip), %xmm4
        pxor      %xmm11, %xmm14
        movdqa    %xmm12, 640(%rsp)
        paddd     %xmm4, %xmm5
        movdqa    %xmm9, %xmm12
        paddd     %xmm9, %xmm3
        paddd     %xmm14, %xmm5
        pxor      %xmm15, %xmm12
        movdqa    176(%rdi), %xmm14
        pand      %xmm3, %xmm12
        movdqa    %xmm14, 160(%rsp)
        paddd     %xmm14, %xmm5
        movdqa    %xmm1, %xmm14
        paddd     %xmm1, %xmm7
        paddd     %xmm4, %xmm6
        pxor      %xmm15, %xmm12
        pxor      %xmm0, %xmm14
        paddd     %xmm12, %xmm6
        movdqa    432(%rdi), %xmm12
        pand      %xmm7, %xmm14
        paddd     %xmm4, %xmm10
        movdqa    %xmm5, %xmm4
        paddd     %xmm12, %xmm6
        pxor      %xmm0, %xmm14
        pslld     $22, %xmm4
        psrld     $10, %xmm5
        movdqa    %xmm12, 176(%rsp)
        paddd     %xmm14, %xmm10
        movdqa    688(%rdi), %xmm12
        por       %xmm5, %xmm4
        movdqa    %xmm6, %xmm5
        paddd     %xmm12, %xmm10
        pslld     $22, %xmm5
        psrld     $10, %xmm6
        por       %xmm6, %xmm5
        movdqa    %xmm10, %xmm6
        movdqa    %xmm12, 400(%rsp)
        paddd     %xmm2, %xmm4
        paddd     %xmm3, %xmm5
        pslld     $22, %xmm6
        psrld     $10, %xmm10
..B2.7:
        movdqa    %xmm2, %xmm13
        por       %xmm10, %xmm6
        pxor      %xmm8, %xmm13
        movdqa    %xmm3, %xmm10
        movdqa    .L_2il0floatpacket.37(%rip), %xmm14
        pand      %xmm4, %xmm13
        paddd     %xmm14, %xmm11
        pxor      %xmm8, %xmm13
        movdqa    192(%rdi), %xmm12
        paddd     %xmm13, %xmm11
        pxor      %xmm9, %xmm10
        paddd     %xmm12, %xmm11
        movdqa    %xmm12, 608(%rsp)
        pand      %xmm5, %xmm10
        movdqa    %xmm7, %xmm12
        paddd     %xmm7, %xmm6
        paddd     %xmm14, %xmm15
        pxor      %xmm9, %xmm10
        pxor      %xmm1, %xmm12
        paddd     %xmm10, %xmm15
        movdqa    448(%rdi), %xmm13
        pand      %xmm6, %xmm12
        paddd     %xmm13, %xmm15
        pxor      %xmm1, %xmm12
        paddd     %xmm14, %xmm0
        movdqa    %xmm11, %xmm14
        paddd     %xmm12, %xmm0
        movdqa    %xmm15, %xmm12
        paddd     704(%rdi), %xmm0
        pslld     $7, %xmm14
        psrld     $25, %xmm11
        pslld     $7, %xmm12
        psrld     $25, %xmm15
        por       %xmm11, %xmm14
        por       %xmm15, %xmm12
        movdqa    %xmm0, %xmm10
        movdqa    %xmm4, %xmm15
        movdqa    %xmm5, %xmm11
        paddd     %xmm4, %xmm14
        paddd     %xmm5, %xmm12
        pslld     $7, %xmm10
        psrld     $25, %xmm0
        pxor      %xmm2, %xmm15
        pxor      %xmm3, %xmm11
        por       %xmm0, %xmm10
        pand      %xmm14, %xmm15
        movdqa    .L_2il0floatpacket.38(%rip), %xmm0
        pand      %xmm12, %xmm11
        paddd     %xmm0, %xmm8
        paddd     %xmm0, %xmm9
        pxor      %xmm2, %xmm15
        pxor      %xmm3, %xmm11
        paddd     %xmm15, %xmm8
        paddd     %xmm11, %xmm9
        movdqa    208(%rdi), %xmm11
        paddd     %xmm6, %xmm10
        movdqa    %xmm11, 352(%rsp)
        paddd     %xmm11, %xmm8
        movdqa    %xmm7, %xmm11
        paddd     %xmm0, %xmm1
        pxor      %xmm6, %xmm11
        movdqa    %xmm8, %xmm0
        pand      %xmm10, %xmm11
        pslld     $12, %xmm0
        movdqa    %xmm13, 624(%rsp)
        pxor      %xmm7, %xmm11
        movdqa    464(%rdi), %xmm13
        paddd     %xmm11, %xmm1
        movdqa    720(%rdi), %xmm15
        paddd     %xmm13, %xmm9
        movdqa    %xmm13, 336(%rsp)
        paddd     %xmm15, %xmm1
        psrld     $20, %xmm8
        movdqa    %xmm9, %xmm13
        por       %xmm8, %xmm0
        pslld     $12, %xmm13
        psrld     $20, %xmm9
        movdqa    %xmm1, %xmm8
        por       %xmm9, %xmm13
        pslld     $12, %xmm8
        psrld     $20, %xmm1
        movdqa    %xmm4, %xmm9
        paddd     %xmm14, %xmm0
        por       %xmm1, %xmm8
        pxor      %xmm14, %xmm9
        movdqa    %xmm5, %xmm1
        movdqa    .L_2il0floatpacket.39(%rip), %xmm11
        paddd     %xmm12, %xmm13
        pand      %xmm0, %xmm9
        pxor      %xmm12, %xmm1
        paddd     %xmm11, %xmm2
        pxor      %xmm4, %xmm9
        pand      %xmm13, %xmm1
        paddd     %xmm11, %xmm3
        movdqa    %xmm15, 560(%rsp)
        paddd     %xmm9, %xmm2
        movdqa    224(%rdi), %xmm9
        pxor      %xmm5, %xmm1
        movdqa    %xmm10, %xmm15
        paddd     %xmm10, %xmm8
        paddd     %xmm1, %xmm3
        paddd     %xmm9, %xmm2
        movdqa    480(%rdi), %xmm1
        pxor      %xmm6, %xmm15
        movdqa    %xmm1, 688(%rsp)
        paddd     %xmm1, %xmm3
        pand      %xmm8, %xmm15
        movdqa    %xmm2, %xmm1
        pxor      %xmm6, %xmm15
        paddd     %xmm11, %xmm7
        pslld     $17, %xmm1
        psrld     $15, %xmm2
        movdqa    %xmm9, 704(%rsp)
        paddd     %xmm15, %xmm7
        movdqa    736(%rdi), %xmm9
        por       %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        paddd     %xmm9, %xmm7
        pslld     $17, %xmm2
        psrld     $15, %xmm3
        por       %xmm3, %xmm2
        movdqa    %xmm7, %xmm3
        pslld     $17, %xmm3
        psrld     $15, %xmm7
        por       %xmm7, %xmm3
        movdqa    %xmm0, %xmm7
        paddd     %xmm0, %xmm1
        pxor      %xmm14, %xmm7
        movdqa    %xmm9, 720(%rsp)
        pand      %xmm1, %xmm7
        movdqa    .L_2il0floatpacket.40(%rip), %xmm9
        movdqa    %xmm13, %xmm11
        movdqa    %xmm8, %xmm15
        paddd     %xmm13, %xmm2
        paddd     %xmm8, %xmm3
        paddd     %xmm9, %xmm4
        pxor      %xmm14, %xmm7
        pxor      %xmm12, %xmm11
        pxor      %xmm10, %xmm15
        paddd     %xmm7, %xmm4
        movdqa    240(%rdi), %xmm7
        pand      %xmm2, %xmm11
        pand      %xmm3, %xmm15
        paddd     %xmm9, %xmm5
        pxor      %xmm12, %xmm11
        paddd     %xmm7, %xmm4
        pxor      %xmm10, %xmm15
        paddd     %xmm9, %xmm6
        paddd     %xmm11, %xmm5
        paddd     %xmm15, %xmm6
        movdqa    496(%rdi), %xmm11
        movdqa    %xmm4, %xmm15
        paddd     %xmm11, %xmm5
        pslld     $22, %xmm15
        psrld     $10, %xmm4
        movdqa    %xmm11, 512(%rsp)
        por       %xmm4, %xmm15
        movdqa    752(%rdi), %xmm11
        movdqa    %xmm5, %xmm4
        paddd     %xmm11, %xmm6
        pslld     $22, %xmm4
        psrld     $10, %xmm5
        paddd     %xmm1, %xmm15
        por       %xmm5, %xmm4
        movdqa    %xmm6, %xmm5
        pslld     $22, %xmm5
        psrld     $10, %xmm6
        por       %xmm6, %xmm5
        movdqa    %xmm15, %xmm6
        pxor      %xmm1, %xmm6
        paddd     %xmm2, %xmm4
        movdqa    .L_2il0floatpacket.41(%rip), %xmm9
        pand      %xmm0, %xmm6
        paddd     %xmm9, %xmm14
        pxor      %xmm1, %xmm6
        paddd     %xmm6, %xmm14
        movdqa    %xmm4, %xmm6
        pxor      %xmm2, %xmm6
        paddd     %xmm3, %xmm5
        pand      %xmm13, %xmm6
        paddd     %xmm9, %xmm12
        pxor      %xmm2, %xmm6
        paddd     %xmm9, %xmm10
        paddd     %xmm6, %xmm12
        movdqa    %xmm5, %xmm6
        pxor      %xmm3, %xmm6
        pand      %xmm8, %xmm6
        paddd     192(%rsp), %xmm14
        pxor      %xmm3, %xmm6
        paddd     %xmm6, %xmm10
        movdqa    %xmm14, %xmm9
        paddd     320(%rsp), %xmm10
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        movdqa    %xmm10, %xmm6
        por       %xmm14, %xmm9
        pslld     $5, %xmm6
        paddd     144(%rsp), %xmm12
        paddd     %xmm15, %xmm9
        psrld     $27, %xmm10
        movdqa    %xmm12, %xmm14
        por       %xmm10, %xmm6
        movdqa    %xmm9, %xmm10
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        pxor      %xmm15, %xmm10
        por       %xmm12, %xmm14
        movdqa    .L_2il0floatpacket.42(%rip), %xmm12
        pand      %xmm1, %xmm10
        paddd     %xmm4, %xmm14
        paddd     %xmm12, %xmm0
        pxor      %xmm15, %xmm10
        paddd     %xmm5, %xmm6
        paddd     %xmm10, %xmm0
        movdqa    %xmm14, %xmm10
        pxor      %xmm4, %xmm10
        paddd     %xmm12, %xmm13
        pand      %xmm2, %xmm10
        paddd     %xmm12, %xmm8
        pxor      %xmm4, %xmm10
        paddd     %xmm10, %xmm13
        movdqa    %xmm6, %xmm10
        paddd     128(%rsp), %xmm0
        pxor      %xmm5, %xmm10
        pand      %xmm3, %xmm10
        movdqa    %xmm0, %xmm12
        paddd     112(%rsp), %xmm13
        pxor      %xmm5, %xmm10
        pslld     $9, %xmm12
        psrld     $23, %xmm0
        paddd     %xmm10, %xmm8
        por       %xmm0, %xmm12
        movdqa    %xmm13, %xmm0
        paddd     %xmm9, %xmm12
        paddd     304(%rsp), %xmm8
        pslld     $9, %xmm0
        psrld     $23, %xmm13
        movdqa    %xmm8, %xmm10
        por       %xmm13, %xmm0
        movdqa    %xmm12, %xmm13
        pslld     $9, %xmm10
        psrld     $23, %xmm8
        pxor      %xmm9, %xmm13
        por       %xmm8, %xmm10
        movdqa    .L_2il0floatpacket.43(%rip), %xmm8
        pand      %xmm15, %xmm13
        paddd     %xmm14, %xmm0
        paddd     %xmm8, %xmm1
        pxor      %xmm9, %xmm13
        paddd     %xmm6, %xmm10
        paddd     %xmm13, %xmm1
        movdqa    %xmm0, %xmm13
        pxor      %xmm14, %xmm13
        paddd     %xmm8, %xmm2
        pand      %xmm4, %xmm13
        paddd     %xmm8, %xmm3
        pxor      %xmm14, %xmm13
        paddd     %xmm13, %xmm2
        movdqa    %xmm10, %xmm13
        pxor      %xmm6, %xmm13
        pand      %xmm5, %xmm13
        paddd     160(%rsp), %xmm1
        pxor      %xmm6, %xmm13
        paddd     %xmm13, %xmm3
        movdqa    %xmm1, %xmm13
        paddd     400(%rsp), %xmm3
        pslld     $14, %xmm13
        psrld     $18, %xmm1
        por       %xmm1, %xmm13
        movdqa    %xmm3, %xmm1
        paddd     176(%rsp), %xmm2
        paddd     %xmm12, %xmm13
        pslld     $14, %xmm1
        psrld     $18, %xmm3
        movdqa    %xmm2, %xmm8
        por       %xmm3, %xmm1
        movdqa    %xmm13, %xmm3
        pslld     $14, %xmm8
        psrld     $18, %xmm2
        pxor      %xmm12, %xmm3
        por       %xmm2, %xmm8
        pand      %xmm9, %xmm3
        movdqa    .L_2il0floatpacket.44(%rip), %xmm2
        paddd     %xmm0, %xmm8
        paddd     %xmm2, %xmm15
        pxor      %xmm12, %xmm3
        paddd     %xmm3, %xmm15
        movdqa    %xmm8, %xmm3
        pxor      %xmm0, %xmm3
        paddd     %xmm10, %xmm1
        pand      %xmm14, %xmm3
        paddd     %xmm2, %xmm4
        pxor      %xmm0, %xmm3
        paddd     %xmm2, %xmm5
        paddd     %xmm3, %xmm4
        movdqa    %xmm1, %xmm3
        pxor      %xmm10, %xmm3
        pand      %xmm6, %xmm3
        paddd     464(%rsp), %xmm15
        pxor      %xmm10, %xmm3
        paddd     %xmm3, %xmm5
        movdqa    %xmm15, %xmm3
        paddd     432(%rsp), %xmm4
        pslld     $20, %xmm3
        psrld     $12, %xmm15
        movdqa    %xmm4, %xmm2
        por       %xmm15, %xmm3
        pslld     $20, %xmm2
        paddd     416(%rsp), %xmm5
        paddd     %xmm13, %xmm3
        psrld     $12, %xmm4
        movdqa    %xmm3, %xmm15
        por       %xmm4, %xmm2
        movdqa    %xmm5, %xmm4
        pslld     $20, %xmm4
        psrld     $12, %xmm5
        pxor      %xmm13, %xmm15
        por       %xmm5, %xmm4
        movdqa    .L_2il0floatpacket.45(%rip), %xmm5
        pand      %xmm12, %xmm15
        paddd     %xmm8, %xmm2
        paddd     %xmm5, %xmm9
        pxor      %xmm13, %xmm15
        paddd     %xmm1, %xmm4
        paddd     %xmm15, %xmm9
        movdqa    %xmm2, %xmm15
        pxor      %xmm8, %xmm15
        paddd     %xmm5, %xmm14
        pand      %xmm0, %xmm15
        paddd     %xmm5, %xmm6
        pxor      %xmm8, %xmm15
        paddd     %xmm15, %xmm14
        movdqa    %xmm4, %xmm15
        paddd     384(%rsp), %xmm9
        pxor      %xmm1, %xmm15
        pand      %xmm10, %xmm15
        movdqa    %xmm9, %xmm5
        paddd     368(%rsp), %xmm14
        pxor      %xmm1, %xmm15
        pslld     $5, %xmm5
        psrld     $27, %xmm9
        paddd     %xmm15, %xmm6
        por       %xmm9, %xmm5
        movdqa    %xmm14, %xmm9
        paddd     %xmm3, %xmm5
        paddd     656(%rsp), %xmm6
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        movdqa    %xmm5, %xmm15
        por       %xmm14, %xmm9
        movdqa    %xmm6, %xmm14
        pslld     $5, %xmm14
        psrld     $27, %xmm6
        pxor      %xmm3, %xmm15
        por       %xmm6, %xmm14
        movdqa    .L_2il0floatpacket.46(%rip), %xmm6
        pand      %xmm13, %xmm15
        paddd     %xmm2, %xmm9
        paddd     %xmm6, %xmm12
        pxor      %xmm3, %xmm15
        paddd     %xmm4, %xmm14
        paddd     %xmm15, %xmm12
        movdqa    %xmm9, %xmm15
        pxor      %xmm2, %xmm15
        paddd     %xmm6, %xmm0
        pand      %xmm8, %xmm15
        paddd     %xmm6, %xmm10
        pxor      %xmm2, %xmm15
        paddd     %xmm15, %xmm0
        movdqa    %xmm14, %xmm15
        paddd     496(%rsp), %xmm12
        pxor      %xmm4, %xmm15
        pand      %xmm1, %xmm15
        movdqa    %xmm12, %xmm6
        paddd     448(%rsp), %xmm0
        pxor      %xmm4, %xmm15
        pslld     $9, %xmm6
        psrld     $23, %xmm12
        paddd     %xmm15, %xmm10
        por       %xmm12, %xmm6
        movdqa    %xmm0, %xmm12
        psrld     $23, %xmm0
        paddd     640(%rsp), %xmm10
        pslld     $9, %xmm12
        por       %xmm0, %xmm12
        movdqa    %xmm10, %xmm0
        paddd     %xmm5, %xmm6
        pslld     $9, %xmm0
        psrld     $23, %xmm10
        paddd     %xmm9, %xmm12
        por       %xmm10, %xmm0
        movdqa    %xmm6, %xmm10
        pxor      %xmm5, %xmm10
        paddd     %xmm14, %xmm0
        movdqa    .L_2il0floatpacket.47(%rip), %xmm15
        pand      %xmm3, %xmm10
        paddd     %xmm15, %xmm13
        pxor      %xmm5, %xmm10
        paddd     %xmm10, %xmm13
        movdqa    %xmm12, %xmm10
        movdqa    %xmm7, 528(%rsp)
        pxor      %xmm9, %xmm10
        paddd     %xmm7, %xmm13
        movdqa    %xmm0, %xmm7
        pand      %xmm2, %xmm10
        pxor      %xmm14, %xmm7
        paddd     %xmm15, %xmm8
        pxor      %xmm9, %xmm10
        pand      %xmm4, %xmm7
        paddd     %xmm10, %xmm8
        pxor      %xmm14, %xmm7
        paddd     %xmm15, %xmm1
        paddd     496(%rdi), %xmm8
        paddd     %xmm7, %xmm1
        movdqa    %xmm11, 672(%rsp)
        paddd     %xmm11, %xmm1
        movdqa    %xmm13, %xmm11
        movdqa    %xmm8, %xmm7
        pslld     $14, %xmm11
        psrld     $18, %xmm13
        pslld     $14, %xmm7
        psrld     $18, %xmm8
        por       %xmm13, %xmm11
        por       %xmm8, %xmm7
        movdqa    %xmm1, %xmm8
        paddd     %xmm6, %xmm11
        pslld     $14, %xmm8
        psrld     $18, %xmm1
        por       %xmm1, %xmm8
        movdqa    %xmm11, %xmm1
        paddd     %xmm12, %xmm7
        pxor      %xmm6, %xmm1
        movdqa    .L_2il0floatpacket.48(%rip), %xmm13
        pand      %xmm5, %xmm1
        movdqa    %xmm7, %xmm10
        paddd     %xmm13, %xmm3
        pxor      %xmm6, %xmm1
        pxor      %xmm12, %xmm10
        paddd     %xmm1, %xmm3
        pand      %xmm9, %xmm10
        paddd     32(%rsp), %xmm3
        paddd     %xmm0, %xmm8
        paddd     %xmm13, %xmm2
        pxor      %xmm12, %xmm10
        paddd     %xmm10, %xmm2
        movdqa    %xmm8, %xmm15
        movdqa    %xmm3, %xmm1
        pxor      %xmm0, %xmm15
        paddd     48(%rsp), %xmm2
        pslld     $20, %xmm1
        psrld     $12, %xmm3
        pand      %xmm14, %xmm15
        por       %xmm3, %xmm1
        movdqa    %xmm2, %xmm3
        pxor      %xmm0, %xmm15
        paddd     %xmm13, %xmm4
        pslld     $20, %xmm3
        psrld     $12, %xmm2
        paddd     %xmm15, %xmm4
        por       %xmm2, %xmm3
        paddd     256(%rsp), %xmm4
        paddd     %xmm11, %xmm1
        paddd     %xmm7, %xmm3
        movdqa    %xmm4, %xmm2
        movdqa    %xmm1, %xmm10
        movdqa    %xmm3, %xmm13
        pslld     $20, %xmm2
        psrld     $12, %xmm4
        pxor      %xmm11, %xmm10
        pxor      %xmm7, %xmm13
        por       %xmm4, %xmm2
        pand      %xmm6, %xmm10
        movdqa    .L_2il0floatpacket.49(%rip), %xmm4
        pand      %xmm12, %xmm13
        paddd     %xmm8, %xmm2
        paddd     %xmm4, %xmm5
        paddd     %xmm4, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm7, %xmm13
        paddd     %xmm10, %xmm5
        paddd     %xmm13, %xmm9
        movdqa    %xmm2, %xmm15
        paddd     64(%rsp), %xmm5
        pxor      %xmm8, %xmm15
        paddd     80(%rsp), %xmm9
        pcmpeqd   %xmm13, %xmm13
        movdqa    704(%rdi), %xmm10
..B2.6:
        pand      %xmm0, %xmm15
        paddd     %xmm4, %xmm14
        movdqa    %xmm5, %xmm4
        pxor      %xmm8, %xmm15
        pslld     $5, %xmm4
        psrld     $27, %xmm5
        paddd     %xmm15, %xmm14
        por       %xmm5, %xmm4
        movdqa    %xmm9, %xmm5
        psrld     $27, %xmm9
        paddd     208(%rsp), %xmm14
        pslld     $5, %xmm5
        paddd     %xmm1, %xmm4
        por       %xmm9, %xmm5
        movdqa    %xmm14, %xmm9
        movdqa    %xmm1, %xmm13
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        pxor      %xmm4, %xmm13
        por       %xmm14, %xmm9
        movdqa    .L_2il0floatpacket.50(%rip), %xmm14
        pand      %xmm11, %xmm13
        paddd     %xmm14, %xmm6
        pxor      %xmm1, %xmm13
        paddd     %xmm2, %xmm9
        paddd     %xmm13, %xmm6
        movdqa    %xmm2, %xmm13
        paddd     %xmm3, %xmm5
        pxor      %xmm9, %xmm13
        movdqa    %xmm3, %xmm15
        pand      %xmm8, %xmm13
        pxor      %xmm5, %xmm15
        paddd     704(%rsp), %xmm6
        pxor      %xmm2, %xmm13
        paddd     %xmm14, %xmm0
        paddd     %xmm14, %xmm12
        pand      %xmm7, %xmm15
        paddd     %xmm13, %xmm0
        movdqa    %xmm6, %xmm14
        pxor      %xmm3, %xmm15
        paddd     720(%rsp), %xmm0
        pslld     $9, %xmm14
        psrld     $23, %xmm6
        paddd     %xmm15, %xmm12
        por       %xmm6, %xmm14
        movdqa    %xmm0, %xmm6
        paddd     688(%rsp), %xmm12
        paddd     %xmm4, %xmm14
        pslld     $9, %xmm6
        psrld     $23, %xmm0
        movdqa    %xmm12, %xmm15
        por       %xmm0, %xmm6
        movdqa    %xmm14, %xmm0
        pslld     $9, %xmm15
        psrld     $23, %xmm12
        pxor      %xmm4, %xmm0
        por       %xmm12, %xmm15
        pand      %xmm1, %xmm0
        movdqa    .L_2il0floatpacket.51(%rip), %xmm12
        paddd     %xmm9, %xmm6
        paddd     %xmm12, %xmm11
        pxor      %xmm4, %xmm0
        paddd     %xmm0, %xmm11
        movdqa    %xmm6, %xmm0
        paddd     %xmm5, %xmm15
        pxor      %xmm9, %xmm0
        movdqa    %xmm15, %xmm13
        pand      %xmm2, %xmm0
        paddd     288(%rsp), %xmm11
        pxor      %xmm5, %xmm13
        pxor      %xmm9, %xmm0
        paddd     %xmm12, %xmm8
        pand      %xmm3, %xmm13
        paddd     %xmm0, %xmm8
        movdqa    %xmm11, %xmm0
        paddd     %xmm12, %xmm7
        pxor      %xmm5, %xmm13
        pslld     $14, %xmm0
        psrld     $18, %xmm11
        paddd     %xmm13, %xmm7
        por       %xmm11, %xmm0
        paddd     272(%rsp), %xmm7
        paddd     %xmm14, %xmm0
        paddd     544(%rsp), %xmm8
        movdqa    %xmm7, %xmm13
        movdqa    %xmm8, %xmm12
        movdqa    %xmm0, %xmm11
        pslld     $14, %xmm13
        psrld     $18, %xmm7
        pslld     $14, %xmm12
        psrld     $18, %xmm8
        pxor      %xmm14, %xmm11
        por       %xmm7, %xmm13
        por       %xmm8, %xmm12
        pand      %xmm4, %xmm11
        movdqa    .L_2il0floatpacket.52(%rip), %xmm8
        paddd     %xmm15, %xmm13
        paddd     %xmm6, %xmm12
        paddd     %xmm8, %xmm1
        pxor      %xmm14, %xmm11
        movdqa    %xmm13, %xmm7
        paddd     %xmm11, %xmm1
        movdqa    %xmm12, %xmm11
        pxor      %xmm15, %xmm7
        pxor      %xmm6, %xmm11
        pand      %xmm5, %xmm7
        pand      %xmm9, %xmm11
        paddd     240(%rsp), %xmm1
        paddd     %xmm8, %xmm3
        pxor      %xmm15, %xmm7
        pxor      %xmm6, %xmm11
        paddd     %xmm8, %xmm2
        paddd     %xmm7, %xmm3
        paddd     %xmm11, %xmm2
        movdqa    %xmm1, %xmm8
        paddd     224(%rsp), %xmm3
        pslld     $20, %xmm8
        paddd     480(%rsp), %xmm2
        psrld     $12, %xmm1
        por       %xmm1, %xmm8
        movdqa    %xmm3, %xmm11
        movdqa    %xmm2, %xmm1
        paddd     %xmm0, %xmm8
        pslld     $20, %xmm11
        psrld     $12, %xmm3
        pslld     $20, %xmm1
        psrld     $12, %xmm2
        por       %xmm3, %xmm11
        por       %xmm2, %xmm1
        movdqa    %xmm8, %xmm2
        paddd     %xmm13, %xmm11
        pxor      %xmm0, %xmm2
        movdqa    %xmm11, %xmm3
        movdqa    .L_2il0floatpacket.53(%rip), %xmm7
        pand      %xmm14, %xmm2
        paddd     %xmm12, %xmm1
        paddd     %xmm7, %xmm4
        pxor      %xmm0, %xmm2
        pxor      %xmm13, %xmm3
        paddd     %xmm2, %xmm4
        pand      %xmm15, %xmm3
        movdqa    %xmm1, %xmm2
        paddd     %xmm7, %xmm5
        paddd     352(%rsp), %xmm4
        pxor      %xmm13, %xmm3
        pxor      %xmm12, %xmm2
        paddd     %xmm3, %xmm5
        pand      %xmm6, %xmm2
        movdqa    %xmm4, %xmm3
        paddd     336(%rsp), %xmm5
        pxor      %xmm12, %xmm2
        paddd     %xmm7, %xmm9
        pslld     $5, %xmm3
        psrld     $27, %xmm4
        paddd     %xmm2, %xmm9
        por       %xmm4, %xmm3
        movdqa    %xmm5, %xmm4
        paddd     560(%rsp), %xmm9
        pslld     $5, %xmm4
        psrld     $27, %xmm5
        paddd     %xmm8, %xmm3
        por       %xmm5, %xmm4
        movdqa    %xmm9, %xmm5
        pslld     $5, %xmm5
        psrld     $27, %xmm9
        por       %xmm9, %xmm5
        movdqa    %xmm3, %xmm9
        paddd     %xmm11, %xmm4
        pxor      %xmm8, %xmm9
        movdqa    .L_2il0floatpacket.54(%rip), %xmm7
        pand      %xmm0, %xmm9
        movdqa    %xmm4, %xmm2
        paddd     %xmm1, %xmm5
        paddd     %xmm7, %xmm14
        pxor      %xmm8, %xmm9
        pxor      %xmm11, %xmm2
        paddd     %xmm9, %xmm14
        pand      %xmm13, %xmm2
        movdqa    %xmm5, %xmm9
        paddd     (%rsp), %xmm14
        paddd     %xmm7, %xmm15
        pxor      %xmm11, %xmm2
        pxor      %xmm1, %xmm9
        paddd     %xmm2, %xmm15
        pand      %xmm12, %xmm9
        movdqa    %xmm14, %xmm2
        pxor      %xmm1, %xmm9
        paddd     16(%rsp), %xmm15
        paddd     %xmm7, %xmm6
        pslld     $9, %xmm2
        psrld     $23, %xmm14
        paddd     %xmm9, %xmm6
        por       %xmm14, %xmm2
        movdqa    %xmm15, %xmm7
        paddd     %xmm3, %xmm2
        paddd     96(%rsp), %xmm6
        pslld     $9, %xmm7
        psrld     $23, %xmm15
        movdqa    %xmm6, %xmm14
        por       %xmm15, %xmm7
        movdqa    %xmm2, %xmm15
        pslld     $9, %xmm14
        psrld     $23, %xmm6
        pxor      %xmm3, %xmm15
        por       %xmm6, %xmm14
        movdqa    .L_2il0floatpacket.55(%rip), %xmm6
        pand      %xmm8, %xmm15
        paddd     %xmm4, %xmm7
        paddd     %xmm5, %xmm14
        paddd     %xmm6, %xmm0
        pxor      %xmm3, %xmm15
        paddd     %xmm15, %xmm0
        movdqa    %xmm7, %xmm9
        movdqa    %xmm14, %xmm15
        pxor      %xmm4, %xmm9
        pxor      %xmm5, %xmm15
        pand      %xmm11, %xmm9
        pand      %xmm1, %xmm15
        paddd     %xmm6, %xmm13
        paddd     576(%rsp), %xmm0
        pxor      %xmm4, %xmm9
        pxor      %xmm5, %xmm15
        paddd     %xmm6, %xmm12
        paddd     %xmm9, %xmm13
        paddd     %xmm15, %xmm12
        movdqa    %xmm0, %xmm9
        psrld     $18, %xmm0
        paddd     736(%rsp), %xmm12
        pslld     $14, %xmm9
        por       %xmm0, %xmm9
        movdqa    %xmm12, %xmm6
        paddd     592(%rsp), %xmm13
        paddd     %xmm2, %xmm9
        pslld     $14, %xmm6
        psrld     $18, %xmm12
        movdqa    %xmm13, %xmm15
        por       %xmm12, %xmm6
        movdqa    %xmm9, %xmm12
        pslld     $14, %xmm15
        psrld     $18, %xmm13
        pxor      %xmm2, %xmm12
        movdqa    %xmm3, %xmm0
        por       %xmm13, %xmm15
        movdqa    .L_2il0floatpacket.56(%rip), %xmm13
        pand      %xmm12, %xmm0
        paddd     %xmm7, %xmm15
        paddd     %xmm13, %xmm8
        pxor      %xmm2, %xmm0
        paddd     %xmm14, %xmm6
        paddd     %xmm0, %xmm8
        movdqa    %xmm15, %xmm0
        movdqa    %xmm2, 752(%rsp)
        pxor      %xmm7, %xmm0
        movdqa    %xmm4, %xmm2
        paddd     %xmm13, %xmm11
        pand      %xmm0, %xmm2
        paddd     %xmm13, %xmm1
        pxor      %xmm7, %xmm2
        paddd     %xmm2, %xmm11
        movdqa    %xmm6, %xmm2
        movdqa    %xmm7, 768(%rsp)
        pxor      %xmm14, %xmm2
        movdqa    %xmm5, %xmm7
        pand      %xmm2, %xmm7
        paddd     608(%rsp), %xmm8
        pxor      %xmm14, %xmm7
        paddd     %xmm7, %xmm1
        movdqa    %xmm8, %xmm7
        paddd     624(%rsp), %xmm11
        pslld     $20, %xmm7
        psrld     $12, %xmm8
        paddd     %xmm10, %xmm1
        por       %xmm8, %xmm7
        movdqa    %xmm11, %xmm8
        pslld     $20, %xmm8
        psrld     $12, %xmm11
        por       %xmm11, %xmm8
        movdqa    %xmm1, %xmm11
        pslld     $20, %xmm11
        psrld     $12, %xmm1
        paddd     %xmm9, %xmm7
        por       %xmm1, %xmm11
        movdqa    .L_2il0floatpacket.57(%rip), %xmm1
        paddd     %xmm15, %xmm8
        paddd     %xmm6, %xmm11
        paddd     %xmm1, %xmm3
        pxor      %xmm7, %xmm12
        paddd     %xmm1, %xmm4
        paddd     %xmm12, %xmm3
        pxor      %xmm8, %xmm0
        pxor      %xmm11, %xmm2
        paddd     %xmm1, %xmm5
        paddd     384(%rsp), %xmm3
        paddd     %xmm0, %xmm4
        paddd     %xmm2, %xmm5
        movdqa    %xmm3, %xmm12
        paddd     368(%rsp), %xmm4
        pslld     $4, %xmm12
        paddd     656(%rsp), %xmm5
        psrld     $28, %xmm3
        movdqa    %xmm4, %xmm13
        movdqa    %xmm5, %xmm0
        por       %xmm3, %xmm12
        pslld     $4, %xmm13
        psrld     $28, %xmm4
        pslld     $4, %xmm0
        psrld     $28, %xmm5
        movdqa    %xmm7, %xmm2
        paddd     %xmm7, %xmm12
        por       %xmm4, %xmm13
        movdqa    .L_2il0floatpacket.58(%rip), %xmm4
        por       %xmm5, %xmm0
        movdqa    752(%rsp), %xmm5
        pxor      %xmm9, %xmm2
        paddd     %xmm4, %xmm5
        pxor      %xmm12, %xmm2
        movdqa    %xmm8, %xmm3
        paddd     %xmm8, %xmm13
        movdqa    768(%rsp), %xmm1
        paddd     %xmm5, %xmm2
        pxor      %xmm15, %xmm3
        paddd     %xmm4, %xmm1
        paddd     240(%rsp), %xmm2
        pxor      %xmm13, %xmm3
        movdqa    %xmm11, %xmm5
        paddd     %xmm11, %xmm0
        paddd     %xmm1, %xmm3
        pxor      %xmm6, %xmm5
        movdqa    %xmm2, %xmm1
        pxor      %xmm0, %xmm5
        paddd     224(%rsp), %xmm3
        paddd     %xmm4, %xmm14
        pslld     $11, %xmm1
        psrld     $21, %xmm2
        paddd     %xmm5, %xmm14
        por       %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        psrld     $21, %xmm3
        paddd     480(%rsp), %xmm14
        pslld     $11, %xmm2
        por       %xmm3, %xmm2
        movdqa    %xmm14, %xmm3
        pslld     $11, %xmm3
        psrld     $21, %xmm14
        movdqa    %xmm13, %xmm5
        paddd     %xmm13, %xmm2
        por       %xmm14, %xmm3
        movdqa    %xmm12, %xmm4
        movdqa    .L_2il0floatpacket.59(%rip), %xmm14
        pxor      %xmm8, %xmm5
        paddd     %xmm12, %xmm1
        paddd     %xmm14, %xmm15
        pxor      %xmm7, %xmm4
        pxor      %xmm2, %xmm5
        paddd     %xmm14, %xmm9
        pxor      %xmm1, %xmm4
        paddd     %xmm15, %xmm5
        movdqa    %xmm0, %xmm15
        paddd     176(%rsp), %xmm5
        paddd     %xmm0, %xmm3
        paddd     %xmm9, %xmm4
        pxor      %xmm11, %xmm15
        paddd     160(%rsp), %xmm4
        pxor      %xmm3, %xmm15
        pshufhw   $177, %xmm5, %xmm9
        paddd     %xmm14, %xmm6
        pshufhw   $177, %xmm4, %xmm4
        paddd     %xmm15, %xmm6
        pshuflw   $177, %xmm9, %xmm5
        movdqa    %xmm2, %xmm14
        paddd     400(%rsp), %xmm6
        paddd     %xmm2, %xmm5
        pshuflw   $177, %xmm4, %xmm4
        movdqa    %xmm1, %xmm9
        movdqa    .L_2il0floatpacket.60(%rip), %xmm15
        pxor      %xmm13, %xmm14
        pshufhw   $177, %xmm6, %xmm6
        paddd     %xmm1, %xmm4
        paddd     %xmm15, %xmm8
        pxor      %xmm12, %xmm9
        pxor      %xmm5, %xmm14
        paddd     %xmm15, %xmm7
        pshuflw   $177, %xmm6, %xmm6
        pxor      %xmm4, %xmm9
        paddd     %xmm8, %xmm14
        movdqa    %xmm3, %xmm8
        paddd     %xmm3, %xmm6
        paddd     %xmm7, %xmm9
        pxor      %xmm0, %xmm8
        paddd     %xmm15, %xmm11
        paddd     704(%rsp), %xmm9
        pxor      %xmm6, %xmm8
        paddd     688(%rsp), %xmm14
        paddd     %xmm8, %xmm11
        movdqa    %xmm9, %xmm7
        psrld     $9, %xmm9
        paddd     720(%rsp), %xmm11
        pslld     $23, %xmm7
        movdqa    %xmm14, %xmm8
        por       %xmm9, %xmm7
        pslld     $23, %xmm8
        psrld     $9, %xmm14
        movdqa    %xmm11, %xmm9
        por       %xmm14, %xmm8
        pslld     $23, %xmm9
        psrld     $9, %xmm11
        movdqa    %xmm4, %xmm14
        paddd     %xmm4, %xmm7
        por       %xmm11, %xmm9
        pxor      %xmm1, %xmm14
        movdqa    .L_2il0floatpacket.61(%rip), %xmm11
        pxor      %xmm7, %xmm14
        paddd     %xmm11, %xmm12
        movdqa    %xmm5, %xmm15
        paddd     %xmm14, %xmm12
        movdqa    %xmm6, %xmm14
        paddd     %xmm5, %xmm8
        paddd     %xmm6, %xmm9
        pxor      %xmm2, %xmm15
        pxor      %xmm3, %xmm14
        paddd     192(%rsp), %xmm12
        paddd     %xmm11, %xmm13
        pxor      %xmm8, %xmm15
        pxor      %xmm9, %xmm14
        paddd     %xmm11, %xmm0
        paddd     %xmm15, %xmm13
        paddd     %xmm14, %xmm0
        movdqa    %xmm12, %xmm14
        paddd     144(%rsp), %xmm13
        pslld     $4, %xmm14
        psrld     $28, %xmm12
        movdqa    %xmm8, %xmm15
        paddd     320(%rsp), %xmm0
        por       %xmm12, %xmm14
        movdqa    %xmm13, %xmm12
        psrld     $28, %xmm13
        pslld     $4, %xmm12
        movdqa    %xmm0, %xmm11
        por       %xmm13, %xmm12
        pslld     $4, %xmm11
        psrld     $28, %xmm0
        paddd     %xmm8, %xmm12
        por       %xmm0, %xmm11
        pxor      %xmm5, %xmm15
        movdqa    .L_2il0floatpacket.62(%rip), %xmm0
        pxor      %xmm12, %xmm15
        paddd     %xmm0, %xmm2
        paddd     %xmm9, %xmm11
        paddd     %xmm2, %xmm15
        movdqa    %xmm9, %xmm2
        movdqa    %xmm7, %xmm13
        pxor      %xmm6, %xmm2
        paddd     %xmm7, %xmm14
        pxor      %xmm4, %xmm13
        pxor      %xmm11, %xmm2
        paddd     %xmm0, %xmm3
        paddd     %xmm0, %xmm1
        pxor      %xmm14, %xmm13
        paddd     %xmm2, %xmm3
        paddd     %xmm1, %xmm13
        paddd     256(%rsp), %xmm3
        paddd     32(%rsp), %xmm13
        movdqa    %xmm3, %xmm2
        paddd     48(%rsp), %xmm15
        movdqa    %xmm13, %xmm0
        movdqa    %xmm15, %xmm1
        pslld     $11, %xmm2
        psrld     $21, %xmm3
        pslld     $11, %xmm0
        psrld     $21, %xmm13
        pslld     $11, %xmm1
        psrld     $21, %xmm15
        por       %xmm3, %xmm2
        movdqa    .L_2il0floatpacket.63(%rip), %xmm3
        por       %xmm13, %xmm0
        por       %xmm15, %xmm1
        paddd     %xmm3, %xmm4
        paddd     %xmm3, %xmm5
        movdqa    %xmm14, %xmm3
        paddd     %xmm14, %xmm0
        paddd     %xmm12, %xmm1
        paddd     %xmm11, %xmm2
        pxor      %xmm7, %xmm3
        pcmpeqd   %xmm13, %xmm13
..B2.5:
        pxor      %xmm0, %xmm3
        movdqa    %xmm11, %xmm15
        paddd     %xmm4, %xmm3
        movdqa    %xmm12, %xmm4
        pxor      %xmm8, %xmm4
        pxor      %xmm9, %xmm15
        pxor      %xmm1, %xmm4
        pxor      %xmm2, %xmm15
        paddd     .L_2il0floatpacket.63(%rip), %xmm6
        paddd     %xmm5, %xmm4
        paddd     576(%rsp), %xmm3
        paddd     %xmm15, %xmm6
        paddd     592(%rsp), %xmm4
        paddd     736(%rsp), %xmm6
        pshufhw   $177, %xmm3, %xmm3
        pshufhw   $177, %xmm4, %xmm4
        pshuflw   $177, %xmm3, %xmm5
        pshuflw   $177, %xmm4, %xmm3
        movdqa    %xmm0, %xmm4
        pshufhw   $177, %xmm6, %xmm6
        paddd     %xmm0, %xmm5
        pshuflw   $177, %xmm6, %xmm15
        pxor      %xmm14, %xmm4
        movdqa    .L_2il0floatpacket.64(%rip), %xmm6
        pxor      %xmm5, %xmm4
        paddd     %xmm6, %xmm7
        paddd     %xmm1, %xmm3
        paddd     %xmm7, %xmm4
        movdqa    %xmm1, %xmm7
        pxor      %xmm12, %xmm7
        paddd     %xmm6, %xmm8
        pxor      %xmm3, %xmm7
        paddd     %xmm2, %xmm15
        paddd     %xmm8, %xmm7
        movdqa    %xmm2, %xmm8
        pxor      %xmm11, %xmm8
        paddd     %xmm6, %xmm9
        paddd     448(%rsp), %xmm7
        pxor      %xmm15, %xmm8
        paddd     496(%rsp), %xmm4
        paddd     %xmm8, %xmm9
        movdqa    %xmm7, %xmm8
        movdqa    %xmm4, %xmm6
        paddd     640(%rsp), %xmm9
        pslld     $23, %xmm8
        psrld     $9, %xmm7
        pslld     $23, %xmm6
        psrld     $9, %xmm4
        por       %xmm7, %xmm8
        movdqa    %xmm9, %xmm7
        por       %xmm4, %xmm6
        pslld     $23, %xmm7
        psrld     $9, %xmm9
        movdqa    %xmm0, %xmm4
        paddd     %xmm5, %xmm6
        por       %xmm9, %xmm7
        pxor      %xmm5, %xmm4
        movdqa    .L_2il0floatpacket.65(%rip), %xmm9
        pxor      %xmm6, %xmm4
        paddd     %xmm9, %xmm14
        paddd     %xmm3, %xmm8
        paddd     %xmm4, %xmm14
        movdqa    %xmm1, %xmm4
        pxor      %xmm3, %xmm4
        paddd     %xmm9, %xmm12
        pxor      %xmm8, %xmm4
        paddd     %xmm15, %xmm7
        paddd     352(%rsp), %xmm14
        paddd     %xmm4, %xmm12
        movdqa    %xmm2, %xmm4
        paddd     %xmm9, %xmm11
        pxor      %xmm15, %xmm4
        movdqa    %xmm14, %xmm9
        paddd     336(%rsp), %xmm12
        pxor      %xmm7, %xmm4
        pslld     $4, %xmm9
        psrld     $28, %xmm14
        paddd     %xmm4, %xmm11
        por       %xmm14, %xmm9
        movdqa    %xmm12, %xmm14
        psrld     $28, %xmm12
        paddd     560(%rsp), %xmm11
        pslld     $4, %xmm14
        por       %xmm12, %xmm14
        movdqa    %xmm11, %xmm12
        pslld     $4, %xmm12
        psrld     $28, %xmm11
        movdqa    %xmm6, %xmm4
        paddd     %xmm6, %xmm9
        por       %xmm11, %xmm12
        pxor      %xmm5, %xmm4
        movdqa    .L_2il0floatpacket.66(%rip), %xmm11
        pxor      %xmm9, %xmm4
        paddd     %xmm11, %xmm0
        paddd     %xmm8, %xmm14
        paddd     %xmm0, %xmm4
        movdqa    %xmm8, %xmm0
        pxor      %xmm3, %xmm0
        paddd     %xmm11, %xmm1
        pxor      %xmm14, %xmm0
        paddd     %xmm7, %xmm12
        paddd     %xmm1, %xmm0
        movdqa    %xmm7, %xmm1
        pxor      %xmm15, %xmm1
        paddd     %xmm11, %xmm2
        paddd     432(%rsp), %xmm0
        pxor      %xmm12, %xmm1
        paddd     %xmm1, %xmm2
        movdqa    %xmm0, %xmm11
        paddd     464(%rsp), %xmm4
        pslld     $11, %xmm11
        paddd     416(%rsp), %xmm2
        psrld     $21, %xmm0
        movdqa    %xmm4, %xmm1
        por       %xmm0, %xmm11
        movdqa    %xmm2, %xmm0
        pslld     $11, %xmm1
        psrld     $21, %xmm4
        pslld     $11, %xmm0
        psrld     $21, %xmm2
        por       %xmm4, %xmm1
        por       %xmm2, %xmm0
        movdqa    %xmm9, %xmm2
        movdqa    .L_2il0floatpacket.67(%rip), %xmm4
        paddd     %xmm9, %xmm1
        pxor      %xmm6, %xmm2
        paddd     %xmm4, %xmm5
        pxor      %xmm1, %xmm2
        paddd     %xmm14, %xmm11
        paddd     %xmm5, %xmm2
        movdqa    %xmm14, %xmm5
        pxor      %xmm8, %xmm5
        paddd     %xmm4, %xmm3
        pxor      %xmm11, %xmm5
        paddd     %xmm12, %xmm0
        paddd     %xmm3, %xmm5
        paddd     %xmm4, %xmm15
        paddd     288(%rsp), %xmm2
        movdqa    %xmm1, %xmm4
        paddd     272(%rsp), %xmm5
        pxor      %xmm9, %xmm4
        pshufhw   $177, %xmm2, %xmm3
        pshufhw   $177, %xmm5, %xmm5
        pshuflw   $177, %xmm3, %xmm2
        pshuflw   $177, %xmm5, %xmm3
        movdqa    %xmm12, %xmm5
        pxor      %xmm7, %xmm5
        paddd     %xmm1, %xmm2
        pxor      %xmm0, %xmm5
        pxor      %xmm2, %xmm4
        paddd     %xmm5, %xmm15
        paddd     %xmm11, %xmm3
        paddd     544(%rsp), %xmm15
        pshufhw   $177, %xmm15, %xmm15
        pshuflw   $177, %xmm15, %xmm5
        movdqa    .L_2il0floatpacket.68(%rip), %xmm15
        paddd     %xmm0, %xmm5
        paddd     %xmm15, %xmm6
        paddd     %xmm15, %xmm8
        paddd     %xmm6, %xmm4
        movdqa    %xmm11, %xmm6
        pxor      %xmm14, %xmm6
        paddd     %xmm15, %xmm7
        pxor      %xmm3, %xmm6
        paddd     %xmm8, %xmm6
        movdqa    %xmm0, %xmm8
        pxor      %xmm12, %xmm8
        paddd     112(%rsp), %xmm6
        pxor      %xmm5, %xmm8
        paddd     128(%rsp), %xmm4
        paddd     %xmm8, %xmm7
        movdqa    %xmm6, %xmm8
        movdqa    %xmm4, %xmm15
        paddd     304(%rsp), %xmm7
        pslld     $23, %xmm8
        psrld     $9, %xmm6
        pslld     $23, %xmm15
        psrld     $9, %xmm4
        por       %xmm6, %xmm8
        movdqa    %xmm7, %xmm6
        por       %xmm4, %xmm15
        pslld     $23, %xmm6
        psrld     $9, %xmm7
        movdqa    %xmm2, %xmm4
        paddd     %xmm2, %xmm15
        por       %xmm7, %xmm6
        pxor      %xmm1, %xmm4
        movdqa    .L_2il0floatpacket.69(%rip), %xmm7
        pxor      %xmm15, %xmm4
        paddd     %xmm7, %xmm9
        paddd     %xmm3, %xmm8
        paddd     %xmm4, %xmm9
        movdqa    %xmm3, %xmm4
        pxor      %xmm11, %xmm4
        paddd     %xmm7, %xmm14
        pxor      %xmm8, %xmm4
        paddd     %xmm5, %xmm6
        paddd     64(%rsp), %xmm9
        paddd     %xmm4, %xmm14
        movdqa    %xmm5, %xmm4
        paddd     %xmm7, %xmm12
        pxor      %xmm0, %xmm4
        movdqa    %xmm9, %xmm7
        paddd     80(%rsp), %xmm14
        pxor      %xmm6, %xmm4
        pslld     $4, %xmm7
        psrld     $28, %xmm9
        paddd     %xmm4, %xmm12
        por       %xmm9, %xmm7
        movdqa    %xmm14, %xmm9
        psrld     $28, %xmm14
        paddd     208(%rsp), %xmm12
        pslld     $4, %xmm9
        por       %xmm14, %xmm9
        movdqa    %xmm12, %xmm14
        pslld     $4, %xmm14
        psrld     $28, %xmm12
        movdqa    %xmm15, %xmm4
        paddd     %xmm15, %xmm7
        por       %xmm12, %xmm14
        pxor      %xmm2, %xmm4
        movdqa    .L_2il0floatpacket.70(%rip), %xmm12
        pxor      %xmm7, %xmm4
        paddd     %xmm12, %xmm1
        paddd     %xmm8, %xmm9
        paddd     %xmm1, %xmm4
        movdqa    %xmm8, %xmm1
        pxor      %xmm3, %xmm1
        paddd     %xmm12, %xmm11
        pxor      %xmm9, %xmm1
        paddd     %xmm6, %xmm14
        paddd     %xmm11, %xmm1
        movdqa    %xmm6, %xmm11
        pxor      %xmm5, %xmm11
        paddd     %xmm12, %xmm0
        pxor      %xmm14, %xmm11
        paddd     608(%rsp), %xmm4
        paddd     %xmm11, %xmm0
        paddd     %xmm10, %xmm0
        movdqa    %xmm4, %xmm12
        paddd     624(%rsp), %xmm1
        pslld     $11, %xmm12
        movdqa    %xmm10, 752(%rsp)
        psrld     $21, %xmm4
        movdqa    %xmm0, %xmm10
        por       %xmm4, %xmm12
        movdqa    %xmm1, %xmm4
        pslld     $11, %xmm10
        psrld     $21, %xmm0
        pslld     $11, %xmm4
        psrld     $21, %xmm1
        por       %xmm0, %xmm10
        movdqa    %xmm7, %xmm0
        paddd     %xmm7, %xmm12
        por       %xmm1, %xmm4
        pxor      %xmm15, %xmm0
        movdqa    .L_2il0floatpacket.109(%rip), %xmm1
        pxor      %xmm12, %xmm0
        paddd     %xmm1, %xmm2
        paddd     %xmm9, %xmm4
        paddd     %xmm2, %xmm0
        movdqa    %xmm9, %xmm2
        paddd     528(%rsp), %xmm0
        pxor      %xmm8, %xmm2
        pshufhw   $177, %xmm0, %xmm11
        paddd     %xmm1, %xmm3
        pxor      %xmm4, %xmm2
        movdqa    %xmm14, %xmm0
        paddd     %xmm14, %xmm10
        paddd     %xmm3, %xmm2
        pxor      %xmm6, %xmm0
        paddd     %xmm1, %xmm5
        paddd     512(%rsp), %xmm2
        pxor      %xmm10, %xmm0
        pshuflw   $177, %xmm11, %xmm3
        paddd     %xmm0, %xmm5
        pshufhw   $177, %xmm2, %xmm2
        movdqa    %xmm12, %xmm11
        paddd     672(%rsp), %xmm5
        paddd     %xmm12, %xmm3
        pshuflw   $177, %xmm2, %xmm2
        pxor      %xmm7, %xmm11
        movdqa    .L_2il0floatpacket.110(%rip), %xmm1
        movdqa    %xmm4, %xmm0
        pshufhw   $177, %xmm5, %xmm5
        paddd     %xmm4, %xmm2
        paddd     %xmm1, %xmm15
        pxor      %xmm3, %xmm11
        pxor      %xmm9, %xmm0
        paddd     %xmm1, %xmm8
        pshuflw   $177, %xmm5, %xmm5
        paddd     %xmm15, %xmm11
        pxor      %xmm2, %xmm0
        movdqa    %xmm10, %xmm15
        paddd     %xmm10, %xmm5
        paddd     %xmm8, %xmm0
        pxor      %xmm14, %xmm15
        paddd     %xmm1, %xmm6
        paddd     (%rsp), %xmm11
        pxor      %xmm5, %xmm15
        paddd     16(%rsp), %xmm0
        paddd     %xmm15, %xmm6
        movdqa    %xmm11, %xmm8
        movdqa    %xmm0, %xmm15
        paddd     96(%rsp), %xmm6
        pslld     $23, %xmm8
        psrld     $9, %xmm11
        pslld     $23, %xmm15
        psrld     $9, %xmm0
        por       %xmm11, %xmm8
        por       %xmm0, %xmm15
        movdqa    %xmm6, %xmm0
        movdqa    %xmm12, %xmm1
        paddd     %xmm3, %xmm8
        pslld     $23, %xmm0
        psrld     $9, %xmm6
        pandn     %xmm13, %xmm1
        por       %xmm6, %xmm0
        movdqa    .L_2il0floatpacket.111(%rip), %xmm6
        por       %xmm8, %xmm1
        paddd     %xmm6, %xmm7
        pxor      %xmm3, %xmm1
        movdqa    %xmm4, %xmm11
        paddd     %xmm1, %xmm7
        movdqa    %xmm10, %xmm1
        paddd     %xmm2, %xmm15
        paddd     %xmm5, %xmm0
        pandn     %xmm13, %xmm11
        pandn     %xmm13, %xmm1
        por       %xmm15, %xmm11
        por       %xmm0, %xmm1
        paddd     %xmm6, %xmm9
        paddd     464(%rsp), %xmm7
        pxor      %xmm2, %xmm11
        pxor      %xmm5, %xmm1
        paddd     %xmm6, %xmm14
        paddd     %xmm11, %xmm9
        paddd     %xmm1, %xmm14
        movdqa    %xmm7, %xmm1
        psrld     $26, %xmm7
        paddd     432(%rsp), %xmm9
        pslld     $6, %xmm1
        por       %xmm7, %xmm1
        movdqa    %xmm9, %xmm7
        paddd     416(%rsp), %xmm14
        pslld     $6, %xmm7
        psrld     $26, %xmm9
        movdqa    %xmm14, %xmm6
        por       %xmm9, %xmm7
        movdqa    %xmm3, %xmm9
        paddd     %xmm8, %xmm1
        pslld     $6, %xmm6
        psrld     $26, %xmm14
        pandn     %xmm13, %xmm9
        por       %xmm14, %xmm6
        por       %xmm1, %xmm9
        movdqa    .L_2il0floatpacket.112(%rip), %xmm14
        movdqa    %xmm2, %xmm11
        paddd     %xmm15, %xmm7
        paddd     %xmm14, %xmm12
        pxor      %xmm8, %xmm9
        pandn     %xmm13, %xmm11
        por       %xmm7, %xmm11
        paddd     %xmm12, %xmm9
        movdqa    %xmm5, %xmm12
        paddd     %xmm0, %xmm6
        paddd     576(%rsp), %xmm9
        paddd     %xmm14, %xmm4
        pxor      %xmm15, %xmm11
        pandn     %xmm13, %xmm12
        paddd     %xmm4, %xmm11
        por       %xmm6, %xmm12
        movdqa    %xmm9, %xmm4
        pxor      %xmm0, %xmm12
        paddd     592(%rsp), %xmm11
        paddd     %xmm14, %xmm10
        pslld     $10, %xmm4
        psrld     $22, %xmm9
        paddd     %xmm12, %xmm10
        por       %xmm9, %xmm4
        movdqa    %xmm11, %xmm9
        psrld     $22, %xmm11
        paddd     736(%rsp), %xmm10
        pslld     $10, %xmm9
        por       %xmm11, %xmm9
        movdqa    %xmm10, %xmm11
        pslld     $10, %xmm11
        psrld     $22, %xmm10
        por       %xmm10, %xmm11
        movdqa    %xmm8, %xmm10
        paddd     %xmm1, %xmm4
        pandn     %xmm13, %xmm10
        movdqa    .L_2il0floatpacket.113(%rip), %xmm14
        por       %xmm4, %xmm10
        movdqa    %xmm15, %xmm12
        paddd     %xmm7, %xmm9
        paddd     %xmm14, %xmm3
        pxor      %xmm1, %xmm10
        pandn     %xmm13, %xmm12
        paddd     %xmm3, %xmm10
        por       %xmm9, %xmm12
        movdqa    %xmm0, %xmm3
        paddd     %xmm6, %xmm11
        paddd     %xmm14, %xmm2
        pxor      %xmm7, %xmm12
        pandn     %xmm13, %xmm3
        paddd     %xmm2, %xmm12
        por       %xmm11, %xmm3
        paddd     704(%rsp), %xmm10
        pxor      %xmm6, %xmm3
        paddd     688(%rsp), %xmm12
        paddd     %xmm14, %xmm5
        paddd     %xmm3, %xmm5
        movdqa    %xmm10, %xmm2
        movdqa    %xmm12, %xmm3
        pslld     $15, %xmm2
        paddd     720(%rsp), %xmm5
        psrld     $17, %xmm10
        pslld     $15, %xmm3
        psrld     $17, %xmm12
        por       %xmm10, %xmm2
        por       %xmm12, %xmm3
        movdqa    %xmm5, %xmm12
        movdqa    %xmm1, %xmm10
        paddd     %xmm4, %xmm2
        pslld     $15, %xmm12
        psrld     $17, %xmm5
        pandn     %xmm13, %xmm10
        por       %xmm5, %xmm12
        por       %xmm2, %xmm10
        movdqa    .L_2il0floatpacket.114(%rip), %xmm5
        movdqa    %xmm7, %xmm14
        paddd     %xmm9, %xmm3
        paddd     %xmm5, %xmm8
        pxor      %xmm4, %xmm10
        pandn     %xmm13, %xmm14
        por       %xmm3, %xmm14
        paddd     %xmm8, %xmm10
        movdqa    %xmm6, %xmm8
        paddd     %xmm11, %xmm12
        paddd     %xmm5, %xmm15
        pxor      %xmm9, %xmm14
        pandn     %xmm13, %xmm8
        paddd     %xmm15, %xmm14
        por       %xmm12, %xmm8
        paddd     %xmm5, %xmm0
        paddd     368(%rsp), %xmm14
        pxor      %xmm11, %xmm8
        paddd     %xmm8, %xmm0
        movdqa    %xmm14, %xmm8
        paddd     384(%rsp), %xmm10
        pslld     $21, %xmm8
        paddd     656(%rsp), %xmm0
        psrld     $11, %xmm14
        movdqa    %xmm10, %xmm5
        por       %xmm14, %xmm8
        movdqa    %xmm0, %xmm14
        pslld     $21, %xmm5
        psrld     $11, %xmm10
        pslld     $21, %xmm14
        psrld     $11, %xmm0
        por       %xmm10, %xmm5
        por       %xmm0, %xmm14
        movdqa    %xmm4, %xmm0
        movdqa    %xmm9, %xmm15
        paddd     %xmm2, %xmm5
        paddd     %xmm3, %xmm8
        pandn     %xmm13, %xmm0
        pandn     %xmm13, %xmm15
        por       %xmm5, %xmm0
        movdqa    .L_2il0floatpacket.115(%rip), %xmm10
        por       %xmm8, %xmm15
        paddd     %xmm12, %xmm14
        paddd     %xmm10, %xmm1
        paddd     %xmm10, %xmm7
        pxor      %xmm2, %xmm0
        movdqa    752(%rsp), %xmm10
        pxor      %xmm3, %xmm15
..B2.4:
        paddd     %xmm15, %xmm7
        movdqa    %xmm11, %xmm15
        pandn     %xmm13, %xmm15
        paddd     %xmm0, %xmm1
        por       %xmm14, %xmm15
        movdqa    %xmm2, %xmm0
        paddd     .L_2il0floatpacket.115(%rip), %xmm6
        pxor      %xmm12, %xmm15
        paddd     608(%rsp), %xmm1
        paddd     %xmm15, %xmm6
        paddd     %xmm10, %xmm6
        movdqa    %xmm1, %xmm10
        paddd     624(%rsp), %xmm7
        pslld     $6, %xmm10
        psrld     $26, %xmm1
        pandn     %xmm13, %xmm0
        por       %xmm1, %xmm10
        movdqa    %xmm7, %xmm1
        pslld     $6, %xmm1
        psrld     $26, %xmm7
        por       %xmm7, %xmm1
        movdqa    %xmm6, %xmm7
        paddd     %xmm5, %xmm10
        pslld     $6, %xmm7
        psrld     $26, %xmm6
        por       %xmm10, %xmm0
        por       %xmm6, %xmm7
        movdqa    %xmm3, %xmm15
        movdqa    .L_2il0floatpacket.116(%rip), %xmm6
        paddd     %xmm8, %xmm1
        paddd     %xmm6, %xmm4
        pxor      %xmm5, %xmm0
        pandn     %xmm13, %xmm15
        paddd     %xmm4, %xmm0
        por       %xmm1, %xmm15
        movdqa    %xmm12, %xmm4
        paddd     %xmm14, %xmm7
        paddd     %xmm6, %xmm9
        pxor      %xmm8, %xmm15
        pandn     %xmm13, %xmm4
        paddd     %xmm9, %xmm15
        por       %xmm7, %xmm4
        paddd     288(%rsp), %xmm0
        pxor      %xmm14, %xmm4
        paddd     272(%rsp), %xmm15
        paddd     %xmm6, %xmm11
        paddd     %xmm4, %xmm11
        movdqa    %xmm0, %xmm4
        movdqa    %xmm15, %xmm9
        pslld     $10, %xmm4
        paddd     544(%rsp), %xmm11
        psrld     $22, %xmm0
        pslld     $10, %xmm9
        psrld     $22, %xmm15
        por       %xmm0, %xmm4
        por       %xmm15, %xmm9
        movdqa    %xmm11, %xmm6
        movdqa    %xmm5, %xmm15
        paddd     %xmm10, %xmm4
        pslld     $10, %xmm6
        psrld     $22, %xmm11
        pandn     %xmm13, %xmm15
        movdqa    .L_2il0floatpacket.117(%rip), %xmm0
        por       %xmm11, %xmm6
        por       %xmm4, %xmm15
        movdqa    %xmm8, %xmm11
        paddd     %xmm1, %xmm9
        paddd     %xmm0, %xmm2
        pxor      %xmm10, %xmm15
        pandn     %xmm13, %xmm11
        por       %xmm9, %xmm11
        paddd     %xmm2, %xmm15
        movdqa    %xmm14, %xmm2
        paddd     %xmm7, %xmm6
        paddd     %xmm0, %xmm3
        pxor      %xmm1, %xmm11
        pandn     %xmm13, %xmm2
        paddd     %xmm3, %xmm11
        por       %xmm6, %xmm2
        paddd     %xmm0, %xmm12
        paddd     448(%rsp), %xmm11
        pxor      %xmm7, %xmm2
        paddd     %xmm2, %xmm12
        movdqa    %xmm11, %xmm3
        paddd     496(%rsp), %xmm15
        pslld     $15, %xmm3
        paddd     640(%rsp), %xmm12
        psrld     $17, %xmm11
        movdqa    %xmm15, %xmm2
        por       %xmm11, %xmm3
        movdqa    %xmm12, %xmm11
        movdqa    %xmm1, %xmm0
        pslld     $15, %xmm2
        psrld     $17, %xmm15
        paddd     %xmm9, %xmm3
        pslld     $15, %xmm11
        psrld     $17, %xmm12
        pandn     %xmm13, %xmm0
        por       %xmm15, %xmm2
        por       %xmm12, %xmm11
        movdqa    .L_2il0floatpacket.118(%rip), %xmm15
        movdqa    %xmm10, %xmm12
        por       %xmm3, %xmm0
        paddd     %xmm4, %xmm2
        paddd     %xmm15, %xmm8
        pandn     %xmm13, %xmm12
        pxor      %xmm9, %xmm0
        por       %xmm2, %xmm12
        paddd     %xmm8, %xmm0
        movdqa    %xmm7, %xmm8
        paddd     %xmm6, %xmm11
        paddd     %xmm15, %xmm5
        pxor      %xmm4, %xmm12
        pandn     %xmm13, %xmm8
        paddd     %xmm5, %xmm12
        por       %xmm11, %xmm8
        paddd     192(%rsp), %xmm12
        pxor      %xmm6, %xmm8
        paddd     144(%rsp), %xmm0
        paddd     %xmm15, %xmm14
        paddd     %xmm8, %xmm14
        movdqa    %xmm12, %xmm5
        movdqa    %xmm0, %xmm8
        pslld     $21, %xmm5
        paddd     320(%rsp), %xmm14
        psrld     $11, %xmm12
        pslld     $21, %xmm8
        psrld     $11, %xmm0
        por       %xmm12, %xmm5
        por       %xmm0, %xmm8
        movdqa    %xmm14, %xmm12
        movdqa    %xmm4, %xmm0
        paddd     %xmm2, %xmm5
        pslld     $21, %xmm12
        psrld     $11, %xmm14
        pandn     %xmm13, %xmm0
        por       %xmm14, %xmm12
        por       %xmm5, %xmm0
        movdqa    .L_2il0floatpacket.119(%rip), %xmm14
        movdqa    %xmm9, %xmm15
        paddd     %xmm3, %xmm8
        paddd     %xmm14, %xmm10
        pxor      %xmm2, %xmm0
        pandn     %xmm13, %xmm15
        por       %xmm8, %xmm15
        paddd     %xmm0, %xmm10
        movdqa    %xmm6, %xmm0
        paddd     %xmm11, %xmm12
        paddd     %xmm14, %xmm1
        pxor      %xmm3, %xmm15
        pandn     %xmm13, %xmm0
        paddd     %xmm15, %xmm1
        por       %xmm12, %xmm0
        paddd     %xmm14, %xmm7
        paddd     240(%rsp), %xmm10
        pxor      %xmm11, %xmm0
        paddd     224(%rsp), %xmm1
        paddd     %xmm0, %xmm7
        movdqa    %xmm10, %xmm15
        movdqa    %xmm1, %xmm0
        paddd     480(%rsp), %xmm7
        pslld     $6, %xmm15
        psrld     $26, %xmm10
        pslld     $6, %xmm0
        psrld     $26, %xmm1
        por       %xmm10, %xmm15
        por       %xmm1, %xmm0
        movdqa    %xmm7, %xmm14
        movdqa    %xmm3, %xmm10
        paddd     %xmm8, %xmm0
        pslld     $6, %xmm14
        psrld     $26, %xmm7
        pandn     %xmm13, %xmm10
        por       %xmm7, %xmm14
        movdqa    .L_2il0floatpacket.120(%rip), %xmm7
        movdqa    %xmm2, %xmm1
        por       %xmm0, %xmm10
        paddd     %xmm5, %xmm15
        paddd     %xmm7, %xmm9
        pandn     %xmm13, %xmm1
        pxor      %xmm8, %xmm10
        por       %xmm15, %xmm1
        paddd     %xmm9, %xmm10
        movdqa    %xmm11, %xmm9
        paddd     %xmm12, %xmm14
        paddd     %xmm7, %xmm4
        pxor      %xmm5, %xmm1
        pandn     %xmm13, %xmm9
        paddd     %xmm4, %xmm1
        por       %xmm14, %xmm9
        paddd     528(%rsp), %xmm1
        pxor      %xmm12, %xmm9
        paddd     %xmm7, %xmm6
        movdqa    %xmm1, %xmm4
        paddd     %xmm9, %xmm6
        pslld     $10, %xmm4
        paddd     512(%rsp), %xmm10
        psrld     $22, %xmm1
        paddd     672(%rsp), %xmm6
        por       %xmm1, %xmm4
        movdqa    %xmm10, %xmm9
        movdqa    %xmm6, %xmm1
        pslld     $10, %xmm9
        psrld     $22, %xmm10
        pslld     $10, %xmm1
        psrld     $22, %xmm6
        por       %xmm10, %xmm9
        por       %xmm6, %xmm1
        movdqa    %xmm8, %xmm6
        paddd     %xmm0, %xmm9
        pandn     %xmm13, %xmm6
        movdqa    %xmm5, %xmm7
        movdqa    .L_2il0floatpacket.121(%rip), %xmm10
        por       %xmm9, %xmm6
        paddd     %xmm15, %xmm4
        paddd     %xmm10, %xmm3
        pandn     %xmm13, %xmm7
        pxor      %xmm0, %xmm6
        por       %xmm4, %xmm7
        paddd     %xmm3, %xmm6
        movdqa    %xmm12, %xmm3
        paddd     %xmm14, %xmm1
        paddd     %xmm10, %xmm2
        pxor      %xmm15, %xmm7
        pandn     %xmm13, %xmm3
        paddd     %xmm2, %xmm7
        por       %xmm1, %xmm3
        paddd     %xmm10, %xmm11
        paddd     128(%rsp), %xmm7
        pxor      %xmm14, %xmm3
        paddd     112(%rsp), %xmm6
        paddd     %xmm3, %xmm11
        movdqa    %xmm7, %xmm2
        movdqa    %xmm6, %xmm3
        paddd     304(%rsp), %xmm11
        pslld     $15, %xmm2
        psrld     $17, %xmm7
        pslld     $15, %xmm3
        psrld     $17, %xmm6
        por       %xmm7, %xmm2
        por       %xmm6, %xmm3
        movdqa    %xmm11, %xmm6
        movdqa    %xmm15, %xmm10
        paddd     %xmm4, %xmm2
        pslld     $15, %xmm6
        psrld     $17, %xmm11
        pandn     %xmm13, %xmm10
        por       %xmm11, %xmm6
        movdqa    .L_2il0floatpacket.122(%rip), %xmm11
        por       %xmm2, %xmm10
        paddd     %xmm11, %xmm5
        pxor      %xmm4, %xmm10
        movdqa    %xmm0, %xmm7
        paddd     %xmm5, %xmm10
        movdqa    %xmm14, %xmm5
        paddd     %xmm9, %xmm3
        paddd     %xmm1, %xmm6
        pandn     %xmm13, %xmm7
        pandn     %xmm13, %xmm5
        por       %xmm3, %xmm7
        por       %xmm6, %xmm5
        paddd     %xmm11, %xmm8
        paddd     352(%rsp), %xmm10
        pxor      %xmm9, %xmm7
        pxor      %xmm1, %xmm5
        paddd     %xmm11, %xmm12
        paddd     %xmm8, %xmm7
        paddd     %xmm5, %xmm12
        movdqa    %xmm10, %xmm5
        psrld     $11, %xmm10
        paddd     336(%rsp), %xmm7
        pslld     $21, %xmm5
        paddd     560(%rsp), %xmm12
        por       %xmm10, %xmm5
        movdqa    %xmm7, %xmm8
        movdqa    %xmm12, %xmm11
        movdqa    %xmm4, %xmm10
        paddd     %xmm2, %xmm5
        pslld     $21, %xmm8
        psrld     $11, %xmm7
        pslld     $21, %xmm11
        psrld     $11, %xmm12
        pandn     %xmm13, %xmm10
        por       %xmm7, %xmm8
        por       %xmm12, %xmm11
        por       %xmm5, %xmm10
        movdqa    .L_2il0floatpacket.123(%rip), %xmm12
        movdqa    %xmm9, %xmm7
        paddd     %xmm3, %xmm8
        paddd     %xmm12, %xmm15
        pxor      %xmm2, %xmm10
        pandn     %xmm13, %xmm7
        por       %xmm8, %xmm7
        paddd     %xmm10, %xmm15
        movdqa    %xmm1, %xmm10
        paddd     %xmm6, %xmm11
        paddd     %xmm12, %xmm0
        pxor      %xmm3, %xmm7
        pandn     %xmm13, %xmm10
        paddd     %xmm7, %xmm0
        por       %xmm11, %xmm10
        paddd     %xmm12, %xmm14
        paddd     48(%rsp), %xmm0
        pxor      %xmm6, %xmm10
        paddd     %xmm10, %xmm14
        movdqa    %xmm0, %xmm12
        paddd     32(%rsp), %xmm15
        pslld     $6, %xmm12
        paddd     256(%rsp), %xmm14
        psrld     $26, %xmm0
        movdqa    %xmm15, %xmm7
        por       %xmm0, %xmm12
        movdqa    %xmm14, %xmm0
        pslld     $6, %xmm7
        psrld     $26, %xmm15
        pslld     $6, %xmm0
        psrld     $26, %xmm14
        por       %xmm15, %xmm7
        por       %xmm14, %xmm0
        movdqa    %xmm2, %xmm14
        paddd     %xmm5, %xmm7
        pandn     %xmm13, %xmm14
        movdqa    .L_2il0floatpacket.124(%rip), %xmm10
        por       %xmm7, %xmm14
        paddd     %xmm10, %xmm4
        pxor      %xmm5, %xmm14
        movdqa    %xmm3, %xmm15
        paddd     %xmm4, %xmm14
        movdqa    %xmm6, %xmm4
        paddd     %xmm8, %xmm12
        paddd     %xmm11, %xmm0
        pandn     %xmm13, %xmm15
        pandn     %xmm13, %xmm4
        por       %xmm12, %xmm15
        por       %xmm0, %xmm4
        paddd     %xmm10, %xmm9
        paddd     160(%rsp), %xmm14
        pxor      %xmm8, %xmm15
        pxor      %xmm11, %xmm4
        paddd     %xmm10, %xmm1
        paddd     %xmm9, %xmm15
        paddd     %xmm4, %xmm1
        movdqa    %xmm14, %xmm4
        psrld     $22, %xmm14
        paddd     176(%rsp), %xmm15
        pslld     $10, %xmm4
        paddd     400(%rsp), %xmm1
        por       %xmm14, %xmm4
        movdqa    %xmm15, %xmm14
        movdqa    %xmm1, %xmm10
        movdqa    %xmm5, %xmm9
        paddd     %xmm7, %xmm4
        pslld     $10, %xmm14
        psrld     $22, %xmm15
        pslld     $10, %xmm10
        psrld     $22, %xmm1
        pandn     %xmm13, %xmm9
        por       %xmm15, %xmm14
        movdqa    .L_2il0floatpacket.125(%rip), %xmm15
        por       %xmm1, %xmm10
        por       %xmm4, %xmm9
        movdqa    %xmm8, %xmm1
        paddd     %xmm12, %xmm14
        paddd     %xmm15, %xmm2
        pxor      %xmm7, %xmm9
        pandn     %xmm13, %xmm1
        por       %xmm14, %xmm1
        paddd     %xmm2, %xmm9
        movdqa    %xmm11, %xmm2
        paddd     %xmm0, %xmm10
        paddd     %xmm15, %xmm3
        pxor      %xmm12, %xmm1
        pandn     %xmm13, %xmm2
        paddd     %xmm3, %xmm1
        por       %xmm10, %xmm2
        paddd     %xmm15, %xmm6
        paddd     16(%rsp), %xmm1
        pxor      %xmm0, %xmm2
        paddd     %xmm2, %xmm6
        movdqa    %xmm1, %xmm2
        paddd     (%rsp), %xmm9
        pslld     $15, %xmm2
        psrld     $17, %xmm1
        movdqa    %xmm9, %xmm3
        por       %xmm1, %xmm2
        movdqa    %xmm12, %xmm1
        paddd     96(%rsp), %xmm6
        pslld     $15, %xmm3
        psrld     $17, %xmm9
        paddd     %xmm14, %xmm2
        pandn     %xmm13, %xmm1
        por       %xmm9, %xmm3
        movdqa    .L_2il0floatpacket.126(%rip), %xmm9
        movdqa    %xmm6, %xmm15
        por       %xmm2, %xmm1
        pslld     $15, %xmm15
        psrld     $17, %xmm6
        paddd     %xmm9, %xmm8
        pxor      %xmm14, %xmm1
        por       %xmm6, %xmm15
        paddd     %xmm8, %xmm1
        movdqa    %xmm0, %xmm8
        paddd     %xmm10, %xmm15
        pandn     %xmm13, %xmm8
        movdqa    %xmm7, %xmm6
        por       %xmm15, %xmm8
        paddd     %xmm4, %xmm3
        pandn     %xmm13, %xmm6
        pxor      %xmm10, %xmm8
        paddd     %xmm9, %xmm11
        por       %xmm3, %xmm6
        paddd     %xmm8, %xmm11
        paddd     208(%rsp), %xmm11
        paddd     %xmm9, %xmm5
        pxor      %xmm4, %xmm6
        paddd     %xmm5, %xmm6
        movdqa    %xmm11, %xmm5
        paddd     64(%rsp), %xmm6
        pslld     $21, %xmm5
        paddd     80(%rsp), %xmm1
        psrld     $11, %xmm11
        por       %xmm11, %xmm5
        movdqa    %xmm6, %xmm11
        movdqa    %xmm1, %xmm13
        pslld     $21, %xmm11
        psrld     $11, %xmm6
        pslld     $21, %xmm13
        psrld     $11, %xmm1
        por       %xmm6, %xmm11
        por       %xmm1, %xmm13
        paddd     %xmm3, %xmm11
        movdqa    .L_2il0floatpacket.89(%rip), %xmm1
        paddd     %xmm2, %xmm13
        movdqa    .L_2il0floatpacket.22(%rip), %xmm6
        paddd     %xmm15, %xmm5
        movdqa    .L_2il0floatpacket.23(%rip), %xmm8
        paddd     %xmm1, %xmm7
        movdqa    .L_2il0floatpacket.24(%rip), %xmm9
        paddd     %xmm6, %xmm11
        paddd     %xmm8, %xmm3
        paddd     %xmm9, %xmm4
        paddd     %xmm1, %xmm12
        paddd     %xmm6, %xmm13
        paddd     %xmm8, %xmm2
        paddd     %xmm9, %xmm14
        paddd     %xmm1, %xmm0
        paddd     %xmm6, %xmm5
        paddd     %xmm8, %xmm15
        paddd     %xmm9, %xmm10
        movdqa    %xmm7, (%rsi)
        movdqa    %xmm11, 16(%rsi)
        movdqa    %xmm3, 32(%rsi)
        movdqa    %xmm4, 48(%rsi)
        movdqa    %xmm12, 64(%rsi)
        movdqa    %xmm13, 80(%rsi)
        movdqa    %xmm2, 96(%rsi)
        movdqa    %xmm14, 112(%rsi)
        movdqa    %xmm0, 128(%rsi)
        movdqa    %xmm5, 144(%rsi)
        movdqa    %xmm15, 160(%rsi)
        movdqa    %xmm10, 176(%rsi)
        addq      $792, %rsp
..___tag_value_SIMDmd5body..0.11:
        ret       
        .align    16,0x90
..___tag_value_SIMDmd5body..0.12:
	.type	SIMDmd5body..0,@function
	.size	SIMDmd5body..0,.-SIMDmd5body..0
	.data
# -- End  SIMDmd5body..0
	.text
# -- Begin  md5cryptsse
       .align    16,0x90
	.globl md5cryptsse
md5cryptsse:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B3.1:
..___tag_value_md5cryptsse.13:
        pushq     %r12
..___tag_value_md5cryptsse.15:
        pushq     %r13
..___tag_value_md5cryptsse.17:
        pushq     %r14
..___tag_value_md5cryptsse.19:
        pushq     %r15
..___tag_value_md5cryptsse.21:
        pushq     %rbx
..___tag_value_md5cryptsse.23:
        pushq     %rbp
..___tag_value_md5cryptsse.25:
        subq      $6824, %rsp
..___tag_value_md5cryptsse.27:
        movq      %rdx, %r15
        movq      %rsi, %rbp
        movq      %rdi, %rbx
        xorl      %esi, %esi
        lea       6304(%rsp), %rdi
        movl      $192, %edx
        movl      %ecx, 6744(%rsp)
..___tag_value_md5cryptsse.28:
        call      memset
..___tag_value_md5cryptsse.29:
..B3.2:
        xorl      %esi, %esi
        lea       (%rsp), %rdi
        movl      $6144, %edx
..___tag_value_md5cryptsse.30:
        call      memset
..___tag_value_md5cryptsse.31:
..B3.3:
        movq      %rbp, %rdi
..___tag_value_md5cryptsse.32:
        call      strlen
..___tag_value_md5cryptsse.33:
..B3.263:
        movq      %rax, %rcx
..B3.4:
        movl      %ecx, %eax
        xorl      %edx, %edx
        movl      %ecx, %esi
        movl      %eax, %ecx
        shrl      $1, %ecx
        movl      %ecx, 6752(%rsp)
        movl      %eax, %r12d
        movq      %rsi, 6760(%rsp)
        lea       (,%rax,8), %r8d
        movl      %r8d, 6768(%rsp)
        movl      %edx, %r14d
        movq      %rbp, 6776(%rsp)
        movq      %r15, 6296(%rsp)
..B3.5:
        movl      %r14d, %edx
        shlq      $4, %rdx
        movq      %rdx, 6784(%rsp)
        lea       (%rbx,%rdx), %rdi
        movq      %rdi, 6800(%rsp)
..___tag_value_md5cryptsse.34:
        call      strlen
..___tag_value_md5cryptsse.35:
..B3.264:
        movq      6784(%rsp), %rdx
        movq      %rax, 6792(%rsp)
..B3.6:
        movl      %r14d, %r13d
        shrl      $2, %r13d
        movl      %r13d, %ecx
        shll      $8, %ecx
        movq      6792(%rsp), %r15
        testl     %r15d, %r15d
        lea       (%rsp,%rcx), %r8
        jbe       ..B3.13
..B3.7:
        movl      %r15d, %eax
        movl      %r14d, %ebp
        shrl      $1, %eax
        xorl      %edi, %edi
        andl      $3, %ebp
        movl      $1, %esi
        testl     %eax, %eax
        jbe       ..B3.11
..B3.8:
        movq      6800(%rsp), %rsi
..B3.9:
        lea       16(%rdi,%rdi), %r9d
        movl      %r9d, %r10d
        lea       (%rdi,%rdi), %r11d
        andl      $-4, %r10d
        andl      $3, %r9d
        shll      $2, %r10d
        lea       (%r10,%rbp,4), %r10d
        addl      %r9d, %r10d
        movb      (%r11,%rsi), %r9b
        movb      %r9b, (%r10,%r8)
        lea       17(%rdi,%rdi), %r10d
        movl      %r10d, %r11d
        lea       1(%rdi,%rdi), %r9d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        incl      %edi
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        cmpl      %eax, %edi
        movb      (%r9,%rsi), %r9b
        movb      %r9b, (%r11,%r8)
        jb        ..B3.9
..B3.10:
        lea       1(%rdi,%rdi), %esi
..B3.11:
        lea       -1(%rsi), %edi
        cmpl      %r15d, %edi
        jae       ..B3.14
..B3.12:
        addl      $15, %esi
        movl      %esi, %r9d
        andl      $3, %esi
        andl      $-4, %r9d
        addl      %ebp, %r9d
        addq      %rbx, %rdi
        lea       (%rsi,%r9,4), %esi
        movb      (%rdi,%rdx), %r10b
        movb      %r10b, (%rsi,%r8)
        jmp       ..B3.14
..B3.13:
        movl      %r14d, %ebp
        andl      $3, %ebp
..B3.14:
        lea       16(%r15), %esi
        movl      %esi, %edi
        andl      $3, %esi
        andl      $-4, %edi
        addl      %ebp, %edi
        testl     %r15d, %r15d
        lea       (%rsi,%rdi,4), %edi
        movb      $128, (%rdi,%r8)
        jbe       ..B3.21
..B3.15:
        movl      %r15d, %r9d
        xorl      %esi, %esi
        shrl      $1, %r9d
        movl      $1, %eax
        testl     %r9d, %r9d
        jbe       ..B3.19
..B3.16:
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %rax
..B3.17:
        lea       (%rsi,%rsi), %ebx
        movl      %ebx, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %ebx, %r11d
        andl      $3, %ebx
        lea       (%r10,%rbp,4), %r10d
        addl      %ebx, %r10d
        movb      (%r11,%rax), %r11b
        movb      %r11b, 768(%r10,%r8)
        lea       1(%rsi,%rsi), %r10d
        movl      %r10d, %r11d
        incl      %esi
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %r10d, %ebx
        andl      $3, %r10d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        cmpl      %r9d, %esi
        movb      (%rbx,%rax), %bl
        movb      %bl, 768(%r11,%r8)
        jb        ..B3.17
..B3.18:
        movq      6648(%rsp), %rbx
        lea       1(%rsi,%rsi), %eax
..B3.19:
        decl      %eax
        cmpl      %r15d, %eax
        jae       ..B3.272
..B3.20:
        movl      %eax, %esi
        andl      $-4, %esi
        movl      %eax, %r10d
        addl      %ebp, %esi
        andl      $3, %eax
        addq      %rbx, %r10
        movb      (%r10,%rdx), %r11b
        lea       (%rax,%rsi,4), %r9d
        movb      %r11b, 768(%r9,%r8)
        lea       1536(%rsp,%rcx), %r9
        movb      $128, 768(%rdi,%r8)
        jmp       ..B3.22
..B3.21:
        movb      $128, 768(%rdi,%r8)
        lea       1536(%rsp,%rcx), %r9
        jbe       ..B3.34
..B3.22:
        movl      %r15d, %edi
        xorl      %esi, %esi
        shrl      $1, %edi
        movl      $1, %eax
        testl     %edi, %edi
        jbe       ..B3.26
..B3.23:
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %rax
..B3.24:
        lea       (%rsi,%rsi), %ebx
        movl      %ebx, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %ebx, %r11d
        andl      $3, %ebx
        lea       (%r10,%rbp,4), %r10d
        addl      %ebx, %r10d
        movb      (%r11,%rax), %r11b
        movb      %r11b, (%r10,%r9)
        lea       1(%rsi,%rsi), %r10d
        movl      %r10d, %r11d
        incl      %esi
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %r10d, %ebx
        andl      $3, %r10d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        cmpl      %edi, %esi
        movb      (%rbx,%rax), %bl
        movb      %bl, (%r11,%r9)
        jb        ..B3.24
..B3.25:
        movq      6648(%rsp), %rbx
        lea       1(%rsi,%rsi), %eax
..B3.26:
        decl      %eax
        cmpl      %r15d, %eax
        jae       ..B3.28
..B3.27:
        movl      %eax, %esi
        andl      $-4, %esi
        movl      %eax, %r10d
        addl      %ebp, %esi
        andl      $3, %eax
        addq      %rbx, %r10
        movb      (%r10,%rdx), %r11b
        lea       (%rax,%rsi,4), %edi
        movb      %r11b, (%rdi,%r9)
..B3.28:
        movl      %r15d, %esi
        xorl      %eax, %eax
        shrl      $1, %esi
        movl      $1, %edi
        testl     %esi, %esi
        jbe       ..B3.32
..B3.29:
        movl      %r12d, 6728(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %r10
..B3.30:
        lea       (%r15,%rax,2), %r11d
        movl      %r11d, %r12d
        movl      %r11d, %ebx
        andl      $-4, %r12d
        lea       (%rax,%rax), %edi
        shll      $2, %r12d
        andl      $3, %ebx
        incl      %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %ebx, %r12d
        lea       1(%rax,%rax), %ebx
        incl      %eax
        movb      (%rdi,%r10), %dil
        movb      %dil, (%r12,%r9)
        movl      %r11d, %edi
        andl      $-4, %edi
        andl      $3, %r11d
        shll      $2, %edi
        lea       (%rdi,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %esi, %eax
        movb      (%rbx,%r10), %r11b
        movb      %r11b, (%r12,%r9)
        jb        ..B3.30
..B3.31:
        movl      6728(%rsp), %r12d
        lea       1(%rax,%rax), %edi
        movq      6648(%rsp), %rbx
..B3.32:
        lea       -1(%rdi), %esi
        cmpl      %r15d, %esi
        jae       ..B3.34
..B3.33:
        lea       -1(%r15,%rdi), %edi
        movl      %edi, %r10d
        addq      %rbx, %rsi
        andl      $-4, %r10d
        andl      $3, %edi
        addl      %ebp, %r10d
        movb      (%rsi,%rdx), %sil
        lea       (%rdi,%r10,4), %r11d
        movb      %sil, (%r11,%r9)
..B3.34:
        lea       16(%r15,%r15), %esi
        movl      %esi, %r9d
        andl      $3, %esi
        andl      $-4, %r9d
        lea       (%r15,%r15), %edi
        addl      %ebp, %r9d
        testl     %r15d, %r15d
        lea       (%rsi,%r9,4), %eax
        movb      $128, 1536(%rax,%r8)
        jbe       ..B3.47
..B3.35:
        movl      %r15d, %esi
        xorl      %r9d, %r9d
        shrl      $1, %esi
        movl      $1, %r10d
        testl     %esi, %esi
        jbe       ..B3.39
..B3.36:
        movq      %rbx, 6648(%rsp)
        movl      %r12d, 6728(%rsp)
        movq      6800(%rsp), %rbx
..B3.37:
        lea       16(%r9,%r9), %r10d
        movl      %r10d, %r11d
        lea       (%r9,%r9), %r12d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        movb      (%r12,%rbx), %r10b
        movb      %r10b, 2304(%r11,%r8)
        lea       17(%r9,%r9), %r11d
        movl      %r11d, %r12d
        lea       1(%r9,%r9), %r10d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        incl      %r9d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %esi, %r9d
        movb      (%r10,%rbx), %r10b
        movb      %r10b, 2304(%r12,%r8)
        jb        ..B3.37
..B3.38:
        movl      6728(%rsp), %r12d
        lea       1(%r9,%r9), %r10d
        movq      6648(%rsp), %rbx
..B3.39:
        lea       -1(%r10), %esi
        cmpl      %r15d, %esi
        jae       ..B3.41
..B3.40:
        addl      $15, %r10d
        movl      %r10d, %r9d
        andl      $3, %r10d
        andl      $-4, %r9d
        addl      %ebp, %r9d
        addq      %rbx, %rsi
        lea       (%r10,%r9,4), %r10d
        movb      (%rsi,%rdx), %r11b
        movb      %r11b, 2304(%r10,%r8)
..B3.41:
        movl      %r15d, %r9d
        xorl      %esi, %esi
        shrl      $1, %r9d
        movl      $1, %r10d
        testl     %r9d, %r9d
        jbe       ..B3.45
..B3.42:
        movl      %r12d, 6728(%rsp)
        movl      %r14d, 6720(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %r12
..B3.43:
        lea       (%r15,%rsi,2), %r14d
        lea       16(%r14), %r11d
        addl      $17, %r14d
        movl      %r11d, %ebx
        lea       (%rsi,%rsi), %r10d
        andl      $-4, %ebx
        andl      $3, %r11d
        shll      $2, %ebx
        lea       (%rbx,%rbp,4), %ebx
        addl      %r11d, %ebx
        movb      (%r10,%r12), %r11b
        movl      %r14d, %r10d
        andl      $-4, %r10d
        andl      $3, %r14d
        shll      $2, %r10d
        movb      %r11b, 2304(%rbx,%r8)
        lea       1(%rsi,%rsi), %ebx
        lea       (%r10,%rbp,4), %r11d
        addl      %r14d, %r11d
        incl      %esi
        cmpl      %r9d, %esi
        movb      (%rbx,%r12), %r14b
        movb      %r14b, 2304(%r11,%r8)
        jb        ..B3.43
..B3.44:
        movl      6720(%rsp), %r14d
        lea       1(%rsi,%rsi), %r10d
        movl      6728(%rsp), %r12d
        movq      6648(%rsp), %rbx
..B3.45:
        lea       -1(%r10), %esi
        cmpl      %r15d, %esi
        jae       ..B3.271
..B3.46:
        lea       15(%r15,%r10), %r9d
        movl      %r9d, %r10d
        addq      %rbx, %rsi
        andl      $-4, %r10d
        andl      $3, %r9d
        addl      %ebp, %r10d
        movb      (%rsi,%rdx), %sil
        lea       (%r9,%r10,4), %r11d
        lea       3072(%rsp,%rcx), %r10
        movb      %sil, 2304(%r11,%r8)
        movb      $128, 2304(%rax,%r8)
        jmp       ..B3.48
..B3.47:
        movb      $128, 2304(%rax,%r8)
        lea       3072(%rsp,%rcx), %r10
        jbe       ..B3.54
..B3.48:
        movl      %r15d, %esi
        xorl      %r9d, %r9d
        shrl      $1, %esi
        movl      $1, %r11d
        testl     %esi, %esi
        jbe       ..B3.52
..B3.49:
        movl      %r12d, 6728(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %rax
..B3.50:
        lea       (%r9,%r9), %ebx
        movl      %ebx, %r11d
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %ebx, %r12d
        andl      $3, %ebx
        lea       (%r11,%rbp,4), %r11d
        addl      %ebx, %r11d
        movb      (%r12,%rax), %r12b
        movb      %r12b, (%r11,%r10)
        lea       1(%r9,%r9), %r11d
        movl      %r11d, %r12d
        incl      %r9d
        andl      $-4, %r12d
        shll      $2, %r12d
        movl      %r11d, %ebx
        andl      $3, %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %esi, %r9d
        movb      (%rbx,%rax), %bl
        movb      %bl, (%r12,%r10)
        jb        ..B3.50
..B3.51:
        movl      6728(%rsp), %r12d
        lea       1(%r9,%r9), %r11d
        movq      6648(%rsp), %rbx
..B3.52:
        decl      %r11d
        cmpl      %r15d, %r11d
        jae       ..B3.54
..B3.53:
        movl      %r11d, %esi
        andl      $-4, %esi
        movl      %r11d, %eax
        andl      $3, %r11d
        addl      %ebp, %esi
        addq      %rbx, %rax
        lea       (%r11,%rsi,4), %r9d
        movb      (%rax,%rdx), %r11b
        movb      %r11b, (%r9,%r10)
..B3.54:
        testl     %r12d, %r12d
        jbe       ..B3.61
..B3.55:
        xorl      %eax, %eax
        movl      $1, %esi
        cmpl      $0, 6752(%rsp)
        jbe       ..B3.59
..B3.56:
        movl      %r14d, 6720(%rsp)
        movl      %r12d, 6728(%rsp)
        movq      %rbx, 6648(%rsp)
        movl      6752(%rsp), %r9d
        movq      6776(%rsp), %r11
..B3.57:
        lea       (%r15,%rax,2), %r12d
        movl      %r12d, %r14d
        movl      %r12d, %ebx
        andl      $-4, %r14d
        lea       (%rax,%rax), %esi
        shll      $2, %r14d
        andl      $3, %ebx
        incl      %r12d
        lea       (%r14,%rbp,4), %r14d
        addl      %ebx, %r14d
        lea       1(%rax,%rax), %ebx
        incl      %eax
        movb      (%rsi,%r11), %sil
        movb      %sil, (%r14,%r10)
        movl      %r12d, %esi
        andl      $-4, %esi
        andl      $3, %r12d
        shll      $2, %esi
        lea       (%rsi,%rbp,4), %r14d
        addl      %r12d, %r14d
        cmpl      %r9d, %eax
        movb      (%rbx,%r11), %r12b
        movb      %r12b, (%r14,%r10)
        jb        ..B3.57
..B3.58:
        movl      6720(%rsp), %r14d
        lea       1(%rax,%rax), %esi
        movl      6728(%rsp), %r12d
        movq      6648(%rsp), %rbx
..B3.59:
        lea       -1(%rsi), %eax
        cmpl      %r12d, %eax
        jae       ..B3.61
..B3.60:
        lea       -1(%r15,%rsi), %esi
        movl      %esi, %r9d
        andl      $3, %esi
        andl      $-4, %r9d
        addl      %ebp, %r9d
        lea       (%rsi,%r9,4), %r11d
        movq      6776(%rsp), %rsi
        movb      (%rax,%rsi), %r9b
        movb      %r9b, (%r11,%r10)
..B3.61:
        lea       16(%r15,%r12), %r9d
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        lea       (%r15,%r12), %esi
        addl      %ebp, %r10d
        testl     %r12d, %r12d
        lea       (%r9,%r10,4), %eax
        movb      $128, 3072(%rax,%r8)
        jbe       ..B3.69
..B3.62:
        xorl      %r10d, %r10d
        movl      $1, %r9d
        cmpl      $0, 6752(%rsp)
        jbe       ..B3.66
..B3.63:
        movq      %rbx, 6648(%rsp)
        movl      %r14d, 6720(%rsp)
        movl      %r12d, 6728(%rsp)
        movl      6752(%rsp), %ebx
        movq      6776(%rsp), %r9
..B3.64:
        lea       16(%r10,%r10), %r11d
        movl      %r11d, %r12d
        lea       (%r10,%r10), %r14d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        movb      (%r14,%r9), %r11b
        movb      %r11b, 3840(%r12,%r8)
        lea       17(%r10,%r10), %r12d
        movl      %r12d, %r14d
        lea       1(%r10,%r10), %r11d
        andl      $-4, %r14d
        andl      $3, %r12d
        shll      $2, %r14d
        incl      %r10d
        lea       (%r14,%rbp,4), %r14d
        addl      %r12d, %r14d
        cmpl      %ebx, %r10d
        movb      (%r11,%r9), %r11b
        movb      %r11b, 3840(%r14,%r8)
        jb        ..B3.64
..B3.65:
        movl      6720(%rsp), %r14d
        lea       1(%r10,%r10), %r9d
        movl      6728(%rsp), %r12d
        movq      6648(%rsp), %rbx
..B3.66:
        lea       -1(%r9), %r10d
        cmpl      %r12d, %r10d
        jae       ..B3.256
..B3.67:
        addl      $15, %r9d
        movl      %r9d, %r11d
        andl      $3, %r9d
        andl      $-4, %r11d
        addl      %ebp, %r11d
        testl     %r15d, %r15d
        lea       (%r9,%r11,4), %r9d
        movq      6776(%rsp), %r11
        movb      (%r10,%r11), %r10b
        movb      %r10b, 3840(%r9,%r8)
        ja        ..B3.70
..B3.68:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rcx), %rax
        jmp       ..B3.77
..B3.69:
        testl     %r15d, %r15d
        jbe       ..B3.83
..B3.70:
        movl      %r15d, %r9d
        xorl      %r10d, %r10d
        shrl      $1, %r9d
        movl      $1, %r11d
        testl     %r9d, %r9d
        jbe       ..B3.74
..B3.71:
        movl      %r14d, 6720(%rsp)
        movl      %r15d, 6736(%rsp)
        movq      %rdx, 6784(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %r14
..B3.72:
        lea       (%r12,%r10,2), %r15d
        lea       16(%r15), %r11d
        addl      $17, %r15d
        movl      %r11d, %edx
        lea       (%r10,%r10), %ebx
        andl      $-4, %edx
        andl      $3, %r11d
        shll      $2, %edx
        lea       (%rdx,%rbp,4), %edx
        addl      %r11d, %edx
        movb      (%rbx,%r14), %r11b
        movl      %r15d, %ebx
        andl      $-4, %ebx
        andl      $3, %r15d
        shll      $2, %ebx
        movb      %r11b, 3840(%rdx,%r8)
        lea       1(%r10,%r10), %edx
        lea       (%rbx,%rbp,4), %r11d
        addl      %r15d, %r11d
        incl      %r10d
        cmpl      %r9d, %r10d
        movb      (%rdx,%r14), %r15b
        movb      %r15b, 3840(%r11,%r8)
        jb        ..B3.72
..B3.73:
        movl      6736(%rsp), %r15d
        lea       1(%r10,%r10), %r11d
        movq      6784(%rsp), %rdx
        movl      6720(%rsp), %r14d
        movq      6648(%rsp), %rbx
..B3.74:
        lea       -1(%r11), %r9d
        cmpl      %r15d, %r9d
        jae       ..B3.76
..B3.75:
        lea       15(%r12,%r11), %r10d
        movl      %r10d, %r11d
        andl      $3, %r10d
        andl      $-4, %r11d
        addq      %rbx, %r9
        addl      %ebp, %r11d
        movb      (%r9,%rdx), %r9b
        lea       (%r10,%r11,4), %r10d
        movb      %r9b, 3840(%r10,%r8)
..B3.76:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rcx), %rax
        testl     %r12d, %r12d
        jbe       ..B3.269
..B3.77:
        xorl      %r9d, %r9d
        movl      $1, %r10d
        cmpl      $0, 6752(%rsp)
        jbe       ..B3.81
..B3.78:
        movq      %rbx, 6648(%rsp)
        movl      %r12d, 6728(%rsp)
        movl      6752(%rsp), %ecx
        movq      6776(%rsp), %rbx
..B3.79:
        lea       16(%r9,%r9), %r10d
        movl      %r10d, %r11d
        lea       (%r9,%r9), %r12d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        movb      (%r12,%rbx), %r10b
        movb      %r10b, (%r11,%rax)
        lea       17(%r9,%r9), %r11d
        movl      %r11d, %r12d
        lea       1(%r9,%r9), %r10d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        incl      %r9d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %ecx, %r9d
        movb      (%r10,%rbx), %r10b
        movb      %r10b, (%r12,%rax)
        jb        ..B3.79
..B3.80:
        movl      6728(%rsp), %r12d
        lea       1(%r9,%r9), %r10d
        movq      6648(%rsp), %rbx
..B3.81:
        lea       -1(%r10), %ecx
        cmpl      %r12d, %ecx
        jae       ..B3.269
..B3.82:
        addl      $15, %r10d
        movl      %r10d, %r9d
        andl      $3, %r10d
        andl      $-4, %r9d
        addl      %ebp, %r9d
        testl     %r15d, %r15d
        movq      6776(%rsp), %r11
        lea       (%r10,%r9,4), %r10d
        movb      (%rcx,%r11), %cl
        movb      %cl, (%r10,%rax)
        ja        ..B3.85
        jmp       ..B3.97
..B3.83:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rcx), %rax
..B3.84:
        jbe       ..B3.97
..B3.85:
        movl      %r15d, %r9d
        xorl      %ecx, %ecx
        shrl      $1, %r9d
        movl      $1, %r10d
        testl     %r9d, %r9d
        jbe       ..B3.89
..B3.86:
        movq      %rdx, 6784(%rsp)
        movl      %r14d, 6720(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %r11
..B3.87:
        lea       (%r12,%rcx,2), %r14d
        lea       16(%r14), %r10d
        addl      $17, %r14d
        movl      %r10d, %edx
        lea       (%rcx,%rcx), %ebx
        andl      $-4, %edx
        andl      $3, %r10d
        shll      $2, %edx
        lea       (%rdx,%rbp,4), %edx
        addl      %r10d, %edx
        movb      (%rbx,%r11), %r10b
        movl      %r14d, %ebx
        andl      $-4, %ebx
        andl      $3, %r14d
        shll      $2, %ebx
        movb      %r10b, (%rdx,%rax)
        lea       1(%rcx,%rcx), %edx
        lea       (%rbx,%rbp,4), %r10d
        addl      %r14d, %r10d
        incl      %ecx
        cmpl      %r9d, %ecx
        movb      (%rdx,%r11), %r14b
        movb      %r14b, (%r10,%rax)
        jb        ..B3.87
..B3.88:
        movq      6784(%rsp), %rdx
        lea       1(%rcx,%rcx), %r10d
        movl      6720(%rsp), %r14d
        movq      6648(%rsp), %rbx
..B3.89:
        lea       -1(%r10), %ecx
        cmpl      %r15d, %ecx
        jae       ..B3.91
..B3.90:
        lea       15(%r12,%r10), %r9d
        movl      %r9d, %r10d
        addq      %rbx, %rcx
        andl      $-4, %r10d
        andl      $3, %r9d
        addl      %ebp, %r10d
        movb      (%rcx,%rdx), %cl
        lea       (%r9,%r10,4), %r11d
        movb      %cl, (%r11,%rax)
..B3.91:
        movl      %r15d, %ecx
        xorl      %r9d, %r9d
        shrl      $1, %ecx
        movl      $1, %r10d
        testl     %ecx, %ecx
        jbe       ..B3.95
..B3.92:
        movl      %r12d, 6728(%rsp)
        movl      %r14d, 6720(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %r12
..B3.93:
        lea       (%rsi,%r9,2), %r14d
        lea       16(%r14), %r11d
        addl      $17, %r14d
        movl      %r11d, %ebx
        lea       (%r9,%r9), %r10d
        andl      $-4, %ebx
        andl      $3, %r11d
        shll      $2, %ebx
        lea       (%rbx,%rbp,4), %ebx
        addl      %r11d, %ebx
        movb      (%r10,%r12), %r11b
        movl      %r14d, %r10d
        andl      $-4, %r10d
        andl      $3, %r14d
        shll      $2, %r10d
        movb      %r11b, (%rbx,%rax)
        lea       1(%r9,%r9), %ebx
        lea       (%r10,%rbp,4), %r11d
        addl      %r14d, %r11d
        incl      %r9d
        cmpl      %ecx, %r9d
        movb      (%rbx,%r12), %r14b
        movb      %r14b, (%r11,%rax)
        jb        ..B3.93
..B3.94:
        movl      6720(%rsp), %r14d
        lea       1(%r9,%r9), %r10d
        movl      6728(%rsp), %r12d
        movq      6648(%rsp), %rbx
..B3.95:
        lea       -1(%r10), %ecx
        cmpl      %r15d, %ecx
        jae       ..B3.97
..B3.96:
        lea       15(%rsi,%r10), %r9d
        movl      %r9d, %r10d
        addq      %rbx, %rcx
        andl      $-4, %r10d
        andl      $3, %r9d
        addl      %ebp, %r10d
        movb      (%rcx,%rdx), %cl
        lea       (%r9,%r10,4), %r11d
        movb      %cl, (%r11,%rax)
..B3.97:
        lea       16(%r12,%r15,2), %ecx
        movl      %ecx, %r9d
        andl      $3, %ecx
        andl      $-4, %r9d
        addl      %ebp, %r9d
        testl     %r15d, %r15d
        lea       (%rcx,%r9,4), %eax
        movb      $128, 4608(%rax,%r8)
        jbe       ..B3.104
..B3.98:
        movl      %r15d, %r9d
        xorl      %r10d, %r10d
        shrl      $1, %r9d
        movl      $1, %r11d
        testl     %r9d, %r9d
        jbe       ..B3.102
..B3.99:
        movl      %r12d, 6728(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %rcx
..B3.100:
        lea       (%r10,%r10), %ebx
        movl      %ebx, %r11d
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %ebx, %r12d
        andl      $3, %ebx
        lea       (%r11,%rbp,4), %r11d
        addl      %ebx, %r11d
        movb      (%r12,%rcx), %r12b
        movb      %r12b, 5376(%r11,%r8)
        lea       1(%r10,%r10), %r11d
        movl      %r11d, %r12d
        incl      %r10d
        andl      $-4, %r12d
        shll      $2, %r12d
        movl      %r11d, %ebx
        andl      $3, %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %r9d, %r10d
        movb      (%rbx,%rcx), %bl
        movb      %bl, 5376(%r12,%r8)
        jb        ..B3.100
..B3.101:
        movl      6728(%rsp), %r12d
        lea       1(%r10,%r10), %r11d
        movq      6648(%rsp), %rbx
..B3.102:
        decl      %r11d
        cmpl      %r15d, %r11d
        jae       ..B3.258
..B3.103:
        movl      %r11d, %r9d
        andl      $-4, %r9d
        movl      %r11d, %ecx
        addl      %ebp, %r9d
        andl      $3, %r11d
        addq      %rbx, %rcx
        testl     %r12d, %r12d
        lea       (%r11,%r9,4), %r10d
        movb      (%rcx,%rdx), %r11b
        movb      %r11b, 5376(%r10,%r8)
        ja        ..B3.105
        jmp       ..B3.112
..B3.104:
        testl     %r12d, %r12d
        jbe       ..B3.118
..B3.105:
        xorl      %ecx, %ecx
        movl      $1, %r9d
        cmpl      $0, 6752(%rsp)
        jbe       ..B3.109
..B3.106:
        movl      %r14d, 6720(%rsp)
        movl      %r12d, 6728(%rsp)
        movq      %rbx, 6648(%rsp)
        movl      6752(%rsp), %r10d
        movq      6776(%rsp), %r11
..B3.107:
        lea       (%r15,%rcx,2), %r12d
        movl      %r12d, %r14d
        movl      %r12d, %ebx
        andl      $-4, %r14d
        lea       (%rcx,%rcx), %r9d
        shll      $2, %r14d
        andl      $3, %ebx
        incl      %r12d
        lea       (%r14,%rbp,4), %r14d
        addl      %ebx, %r14d
        lea       1(%rcx,%rcx), %ebx
        incl      %ecx
        movb      (%r9,%r11), %r9b
        movb      %r9b, 5376(%r14,%r8)
        movl      %r12d, %r9d
        andl      $-4, %r9d
        andl      $3, %r12d
        shll      $2, %r9d
        lea       (%r9,%rbp,4), %r14d
        addl      %r12d, %r14d
        cmpl      %r10d, %ecx
        movb      (%rbx,%r11), %r12b
        movb      %r12b, 5376(%r14,%r8)
        jb        ..B3.107
..B3.108:
        movl      6720(%rsp), %r14d
        lea       1(%rcx,%rcx), %r9d
        movl      6728(%rsp), %r12d
        movq      6648(%rsp), %rbx
..B3.109:
        lea       -1(%r9), %ecx
        cmpl      %r12d, %ecx
        jae       ..B3.111
..B3.110:
        lea       -1(%r15,%r9), %r9d
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %ebp, %r10d
        lea       (%r9,%r10,4), %r11d
        movq      6776(%rsp), %r9
        movb      (%rcx,%r9), %cl
        movb      %cl, 5376(%r11,%r8)
..B3.111:
        testl     %r15d, %r15d
        jbe       ..B3.118
..B3.112:
        movl      %r15d, %ecx
        xorl      %r9d, %r9d
        shrl      $1, %ecx
        movl      $1, %r10d
        testl     %ecx, %ecx
        jbe       ..B3.116
..B3.113:
        movl      %r14d, 6720(%rsp)
        movl      %r12d, 6728(%rsp)
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %r11
..B3.114:
        lea       (%rsi,%r9,2), %r12d
        movl      %r12d, %r14d
        movl      %r12d, %ebx
        andl      $-4, %r14d
        lea       (%r9,%r9), %r10d
        shll      $2, %r14d
        andl      $3, %ebx
        incl      %r12d
        lea       (%r14,%rbp,4), %r14d
        addl      %ebx, %r14d
        lea       1(%r9,%r9), %ebx
        incl      %r9d
        movb      (%r10,%r11), %r10b
        movb      %r10b, 5376(%r14,%r8)
        movl      %r12d, %r10d
        andl      $-4, %r10d
        andl      $3, %r12d
        shll      $2, %r10d
        lea       (%r10,%rbp,4), %r14d
        addl      %r12d, %r14d
        cmpl      %ecx, %r9d
        movb      (%rbx,%r11), %r12b
        movb      %r12b, 5376(%r14,%r8)
        jb        ..B3.114
..B3.115:
        movl      6720(%rsp), %r14d
        lea       1(%r9,%r9), %r10d
        movl      6728(%rsp), %r12d
        movq      6648(%rsp), %rbx
..B3.116:
        lea       -1(%r10), %ecx
        cmpl      %r15d, %ecx
        jae       ..B3.118
..B3.117:
        lea       -1(%rsi,%r10), %esi
        movl      %esi, %r9d
        andl      $3, %esi
        andl      $-4, %r9d
        addq      %rbx, %rcx
        addl      %ebp, %r9d
        movb      (%rcx,%rdx), %r11b
        lea       (%rsi,%r9,4), %r10d
        movb      %r11b, 5376(%r10,%r8)
..B3.118:
        movl      %r13d, %ecx
        lea       128(,%rdi,8), %r9d
        shll      $6, %ecx
        movl      6768(%rsp), %r11d
        movb      $128, 5376(%rax,%r8)
        lea       128(,%r15,8), %r8d
        lea       56(%rbp,%rcx), %esi
        lea       128(%r11,%rdi,8), %edi
        lea       128(%r11,%r15,8), %r10d
        movl      %edi, 4608(%rsp,%rsi,4)
        movl      %edi, 5376(%rsp,%rsi,4)
        lea       6496(%rsp), %rdi
        movl      %r8d, (%rsp,%rsi,4)
        movl      %r8d, 768(%rsp,%rsi,4)
        movl      %r9d, 1536(%rsp,%rsi,4)
        movl      %r9d, 2304(%rsp,%rsi,4)
        movl      %r10d, 3072(%rsp,%rsi,4)
        movl      %r10d, 3840(%rsp,%rsi,4)
..___tag_value_md5cryptsse.36:
        call      MD5_Init
..___tag_value_md5cryptsse.37:
..B3.119:
        movl      6792(%rsp), %edx
        lea       6496(%rsp), %rdi
        movq      6800(%rsp), %rsi
        movq      %rdx, 6808(%rsp)
..___tag_value_md5cryptsse.38:
        call      MD5_Update
..___tag_value_md5cryptsse.39:
..B3.120:
        cmpl      $2, 6744(%rsp)
        jne       ..B3.122
..B3.121:
        movl      $.L_2__STRING.1, %esi
        lea       6496(%rsp), %rdi
        movl      $3, %edx
..___tag_value_md5cryptsse.40:
        call      MD5_Update
..___tag_value_md5cryptsse.41:
        jmp       ..B3.124
..B3.122:
        cmpl      $1, 6744(%rsp)
        jne       ..B3.124
..B3.123:
        movl      $.L_2__STRING.2, %esi
        lea       6496(%rsp), %rdi
        movl      $6, %edx
..___tag_value_md5cryptsse.42:
        call      MD5_Update
..___tag_value_md5cryptsse.43:
..B3.124:
        movq      6776(%rsp), %rsi
        lea       6496(%rsp), %rdi
        movq      6760(%rsp), %rdx
..___tag_value_md5cryptsse.44:
        call      MD5_Update
..___tag_value_md5cryptsse.45:
..B3.125:
        lea       6144(%rsp), %rdi
..___tag_value_md5cryptsse.46:
        call      MD5_Init
..___tag_value_md5cryptsse.47:
..B3.126:
        movq      6800(%rsp), %rsi
        lea       6144(%rsp), %rdi
        movq      6808(%rsp), %rdx
..___tag_value_md5cryptsse.48:
        call      MD5_Update
..___tag_value_md5cryptsse.49:
..B3.127:
        movq      6776(%rsp), %rsi
        lea       6144(%rsp), %rdi
        movq      6760(%rsp), %rdx
..___tag_value_md5cryptsse.50:
        call      MD5_Update
..___tag_value_md5cryptsse.51:
..B3.128:
        movq      6800(%rsp), %rsi
        lea       6144(%rsp), %rdi
        movq      6808(%rsp), %rdx
..___tag_value_md5cryptsse.52:
        call      MD5_Update
..___tag_value_md5cryptsse.53:
..B3.129:
        lea       6704(%rsp), %rdi
        lea       6144(%rsp), %rsi
..___tag_value_md5cryptsse.54:
        call      MD5_Final
..___tag_value_md5cryptsse.55:
..B3.130:
        movq      6808(%rsp), %rdx
        lea       6496(%rsp), %rdi
        lea       6704(%rsp), %rsi
..___tag_value_md5cryptsse.56:
        call      MD5_Update
..___tag_value_md5cryptsse.57:
..B3.131:
        testl     %r15d, %r15d
        movl      %r15d, 6656(%rsp,%r14,4)
        je        ..B3.138
..B3.132:
        movq      %rbx, 6648(%rsp)
        movq      6800(%rsp), %rbx
..B3.133:
        testl     $1, %r15d
        je        ..B3.135
..B3.134:
        movl      $.L_2__STRING.3, %esi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.58:
        call      MD5_Update
..___tag_value_md5cryptsse.59:
        jmp       ..B3.136
..B3.135:
        movq      %rbx, %rsi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.60:
        call      MD5_Update
..___tag_value_md5cryptsse.61:
..B3.136:
        shrl      $1, %r15d
        testl     %r15d, %r15d
        jne       ..B3.133
..B3.137:
        movq      6648(%rsp), %rbx
..B3.138:
        lea       6704(%rsp), %rdi
        lea       6496(%rsp), %rsi
..___tag_value_md5cryptsse.62:
        call      MD5_Final
..___tag_value_md5cryptsse.63:
..B3.139:
        shll      $4, %r13d
        incl      %r14d
        movl      6704(%rsp), %esi
        cmpl      $12, %r14d
        movl      6708(%rsp), %r8d
        movl      6712(%rsp), %r10d
        movl      6716(%rsp), %r11d
        lea       (%rbp,%r13), %ecx
        lea       4(%r13,%rbp), %edi
        lea       8(%r13,%rbp), %r9d
        lea       12(%r13,%rbp), %ebp
        movl      %esi, 6304(%rsp,%rcx,4)
        movl      %r8d, 6304(%rsp,%rdi,4)
        movl      %r10d, 6304(%rsp,%r9,4)
        movl      %r11d, 6304(%rsp,%rbp,4)
        jb        ..B3.5
..B3.140:
        xorl      %r10d, %r10d
        movl      %r12d, %eax
        movl      $23, %ecx
        movl      %r10d, %edx
        movl      %eax, %r12d
        movl      %edx, %r13d
        movl      %ecx, %r14d
        movl      %r10d, %ebx
        lea       (%rsp), %r15
        lea       6304(%rsp), %rbp
..B3.141:
        cmpl      $40, %r13d
        ja        ..B3.235
..B3.142:
        jmp       *..1..TPKT.4_0.0.4.43(,%r13,8)
..1.4_0.TAG.015.0.4.43:
..B3.158:
        movl      %ebx, %r8d
        movl      $1, %eax
        movl      %r8d, %r9d
        movl      %r12d, 6728(%rsp)
        movl      %r9d, %edi
..B3.159:
        lea       (,%r8,4), %ecx
        movl      %r9d, %edx
        addq      %r15, %rdx
        movl      6304(%rsp,%rdi,4), %r10d
        movl      6656(%rsp,%rcx,4), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        testl     %ebx, %ebx
        je        ..B3.161
..B3.160:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      768(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       4(%rdi), %r11d
        movl      %r12d, 768(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       8(%rdi), %r10d
        movl      %r11d, 784(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 800(%rsi,%rdx)
        lea       12(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      832(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 816(%rsi,%rdx)
        movl      %r11d, 832(%rsi,%rdx)
        jmp       ..B3.162
..B3.161:
        shll      $2, %esi
        lea       4(%rdi), %ecx
        lea       12(%rdi), %r12d
        movl      %r10d, 768(%rsi,%rdx)
        lea       8(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r12,4), %ecx
        movl      %ebp, 784(%rsi,%rdx)
        movl      %ecx, 816(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 800(%rsi,%rdx)
..B3.162:
        lea       1(,%r8,4), %ecx
        lea       1(%rdi), %ebp
        movl      6656(%rsp,%rcx,4), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%rbp,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.164
..B3.163:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      772(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       5(%rdi), %r11d
        movl      %r12d, 772(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       9(%rdi), %r10d
        movl      %r11d, 788(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 804(%rsi,%rdx)
        lea       13(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      836(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 820(%rsi,%rdx)
        movl      %r11d, 836(%rsi,%rdx)
        jmp       ..B3.165
..B3.164:
        shll      $2, %esi
        lea       5(%rdi), %ecx
        lea       13(%rdi), %r12d
        movl      %r10d, 772(%rsi,%rdx)
        lea       9(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r12,4), %ecx
        movl      %ebp, 788(%rsi,%rdx)
        movl      %ecx, 820(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 804(%rsi,%rdx)
..B3.165:
        lea       2(,%r8,4), %ecx
        lea       2(%rdi), %ebp
        movl      6656(%rsp,%rcx,4), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%rbp,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.167
..B3.166:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      776(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       6(%rdi), %r11d
        movl      %r12d, 776(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       10(%rdi), %r10d
        movl      %r11d, 792(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 808(%rsi,%rdx)
        lea       14(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      840(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 824(%rsi,%rdx)
        movl      %r11d, 840(%rsi,%rdx)
        jmp       ..B3.168
..B3.167:
        shll      $2, %esi
        lea       6(%rdi), %ecx
        lea       14(%rdi), %r12d
        movl      %r10d, 776(%rsi,%rdx)
        lea       10(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r12,4), %ecx
        movl      %ebp, 792(%rsi,%rdx)
        movl      %ecx, 824(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 808(%rsi,%rdx)
..B3.168:
        lea       3(,%r8,4), %ecx
        lea       3(%rdi), %ebp
        movl      6656(%rsp,%rcx,4), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%rbp,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.170
..B3.169:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      780(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       7(%rdi), %r11d
        movl      %r12d, 780(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       11(%rdi), %r10d
        movl      %r11d, 796(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 812(%rsi,%rdx)
        lea       15(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      844(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 828(%rsi,%rdx)
        movl      %r11d, 844(%rsi,%rdx)
        jmp       ..B3.171
..B3.170:
        shll      $2, %esi
        lea       7(%rdi), %ecx
        lea       15(%rdi), %r12d
        movl      %r10d, 780(%rsi,%rdx)
        lea       11(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r12,4), %ecx
        movl      %ebp, 796(%rsi,%rdx)
        movl      %ecx, 828(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 812(%rsi,%rdx)
..B3.171:
        incl      %r8d
        addl      $256, %r9d
        addl      $16, %edi
        cmpl      $3, %r8d
        jb        ..B3.159
..B3.172:
        movl      6728(%rsp), %r12d
        xorl      %ebx, %ebx
        lea       6304(%rsp), %rbp
        jmp       ..B3.250
..1.4_0.TAG.01c.0.4.43:
..1.4_0.TAG.0e.0.4.43:
..B3.178:
        movl      %ebx, %r8d
        movl      $5, %eax
        xorb      %r9b, %r9b
        movl      %r8d, %ecx
        movl      %r13d, 6648(%rsp)
        movq      %rax, %r13
        movl      %r14d, 6720(%rsp)
        movl      %ecx, %ebx
        movl      %r12d, 6728(%rsp)
        movl      %r8d, %r15d
        movb      %r9b, %r14b
        lea       3840(%rsp), %r12
..B3.179:
        movl      %r15d, %edi
        movl      $64, %edx
        movl      %ebx, %esi
        addq      %r12, %rdi
        addq      %rbp, %rsi
..___tag_value_md5cryptsse.64:
        call      memcpy
..___tag_value_md5cryptsse.65:
..B3.180:
        incb      %r14b
        addl      $256, %r15d
        addl      $64, %ebx
        cmpb      $3, %r14b
        jb        ..B3.179
..B3.181:
        movl      6720(%rsp), %r14d
        movq      %r13, %rax
        movl      6648(%rsp), %r13d
        xorl      %ebx, %ebx
        movl      6728(%rsp), %r12d
        lea       (%rsp), %r15
        jmp       ..B3.250
..1.4_0.TAG.023.0.4.43:
..1.4_0.TAG.07.0.4.43:
..B3.187:
        movl      %ebx, %r8d
        movl      $4, %eax
        movl      %r8d, %r9d
        movl      %r14d, 6720(%rsp)
        movl      %r9d, %edi
..B3.188:
        lea       (,%r8,4), %ecx
        movl      %r9d, %edx
        addq      %r15, %rdx
        movl      6304(%rsp,%rdi,4), %r10d
        movl      6656(%rsp,%rcx,4), %esi
        addl      %r12d, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        testl     %ebx, %ebx
        je        ..B3.190
..B3.189:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      3072(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       4(%rdi), %r11d
        movl      %r14d, 3072(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       8(%rdi), %r10d
        movl      %r11d, 3088(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 3104(%rsi,%rdx)
        lea       12(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      3136(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 3120(%rsi,%rdx)
        movl      %r11d, 3136(%rsi,%rdx)
        jmp       ..B3.191
..B3.190:
        shll      $2, %esi
        lea       4(%rdi), %ecx
        lea       12(%rdi), %r14d
        movl      %r10d, 3072(%rsi,%rdx)
        lea       8(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 3088(%rsi,%rdx)
        movl      %ecx, 3120(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 3104(%rsi,%rdx)
..B3.191:
        lea       1(,%r8,4), %ecx
        lea       1(%rdi), %ebp
        movl      6656(%rsp,%rcx,4), %esi
        addl      %r12d, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%rbp,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.193
..B3.192:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      3076(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       5(%rdi), %r11d
        movl      %r14d, 3076(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       9(%rdi), %r10d
        movl      %r11d, 3092(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 3108(%rsi,%rdx)
        lea       13(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      3140(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 3124(%rsi,%rdx)
        movl      %r11d, 3140(%rsi,%rdx)
        jmp       ..B3.194
..B3.193:
        shll      $2, %esi
        lea       5(%rdi), %ecx
        lea       13(%rdi), %r14d
        movl      %r10d, 3076(%rsi,%rdx)
        lea       9(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 3092(%rsi,%rdx)
        movl      %ecx, 3124(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 3108(%rsi,%rdx)
..B3.194:
        lea       2(,%r8,4), %ecx
        lea       2(%rdi), %ebp
        movl      6656(%rsp,%rcx,4), %esi
        addl      %r12d, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%rbp,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.196
..B3.195:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      3080(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       6(%rdi), %r11d
        movl      %r14d, 3080(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       10(%rdi), %r10d
        movl      %r11d, 3096(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 3112(%rsi,%rdx)
        lea       14(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      3144(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 3128(%rsi,%rdx)
        movl      %r11d, 3144(%rsi,%rdx)
        jmp       ..B3.197
..B3.196:
        shll      $2, %esi
        lea       6(%rdi), %ecx
        lea       14(%rdi), %r14d
        movl      %r10d, 3080(%rsi,%rdx)
        lea       10(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 3096(%rsi,%rdx)
        movl      %ecx, 3128(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 3112(%rsi,%rdx)
..B3.197:
        lea       3(,%r8,4), %ecx
        lea       3(%rdi), %ebp
        movl      6656(%rsp,%rcx,4), %esi
        addl      %r12d, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%rbp,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.199
..B3.198:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      3084(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       7(%rdi), %r11d
        movl      %r14d, 3084(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       11(%rdi), %r10d
        movl      %r11d, 3100(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 3116(%rsi,%rdx)
        lea       15(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      3148(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 3132(%rsi,%rdx)
        movl      %r11d, 3148(%rsi,%rdx)
        jmp       ..B3.200
..B3.199:
        shll      $2, %esi
        lea       7(%rdi), %ecx
        lea       15(%rdi), %r14d
        movl      %r10d, 3084(%rsi,%rdx)
        lea       11(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 3100(%rsi,%rdx)
        movl      %ecx, 3132(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 3116(%rsi,%rdx)
..B3.200:
        incl      %r8d
        addl      $256, %r9d
        addl      $16, %edi
        cmpl      $3, %r8d
        jb        ..B3.188
        jmp       ..B3.249
..1.4_0.TAG.024.0.4.43:
..1.4_0.TAG.01e.0.4.43:
..1.4_0.TAG.018.0.4.43:
..1.4_0.TAG.012.0.4.43:
..1.4_0.TAG.0c.0.4.43:
..1.4_0.TAG.06.0.4.43:
..B3.203:
        movl      %ebx, %r9d
        movl      $3, %eax
        xorb      %r11b, %r11b
        movl      %r9d, %r8d
        movl      %r13d, 6648(%rsp)
        movq      %rax, %rbx
        movl      %r14d, 6720(%rsp)
        movq      %rbp, %r13
        movl      %r12d, 6728(%rsp)
        movl      %r8d, %ebp
        movl      %r9d, %r15d
        movb      %r11b, %r14b
        lea       2304(%rsp), %r12
..B3.204:
        movl      %r15d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %r12, %rdi
        addq      %r13, %rsi
..___tag_value_md5cryptsse.66:
        call      memcpy
..___tag_value_md5cryptsse.67:
..B3.205:
        incb      %r14b
        addl      $256, %r15d
        addl      $64, %ebp
        cmpb      $3, %r14b
        jb        ..B3.204
..B3.206:
        movl      6720(%rsp), %r14d
        movq      %rbx, %rax
        movl      6728(%rsp), %r12d
        movq      %r13, %rbp
        movl      6648(%rsp), %r13d
        xorl      %ebx, %ebx
        lea       (%rsp), %r15
        jmp       ..B3.250
..1.4_0.TAG.027.0.4.43:
..1.4_0.TAG.021.0.4.43:
..1.4_0.TAG.01b.0.4.43:
..1.4_0.TAG.0f.0.4.43:
..1.4_0.TAG.09.0.4.43:
..1.4_0.TAG.03.0.4.43:
..B3.209:
        movl      %ebx, %r8d
        movl      $2, %eax
        movl      %r8d, %r9d
        movl      %r12d, 6728(%rsp)
        movl      %r9d, %edi
..B3.210:
        lea       (,%r8,4), %ebp
        movl      %r9d, %edx
        addq      %r15, %rdx
        movl      6304(%rsp,%rdi,4), %r10d
        movl      6656(%rsp,%rbp,4), %esi
        addl      %esi, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        testl     %ebx, %ebx
        je        ..B3.212
..B3.211:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      1536(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       4(%rdi), %r11d
        movl      %r12d, 1536(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       8(%rdi), %r10d
        movl      %r11d, 1552(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 1568(%rsi,%rdx)
        lea       12(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      1600(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 1584(%rsi,%rdx)
        movl      %r11d, 1600(%rsi,%rdx)
        jmp       ..B3.213
..B3.212:
        shll      $2, %esi
        lea       4(%rdi), %ebp
        lea       8(%rdi), %r11d
        movl      %r10d, 1536(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %r10d
        lea       12(%rdi), %ebp
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r10d, 1552(%rsi,%rdx)
        movl      %r12d, 1568(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %ebp
        movl      %ebp, 1584(%rsi,%rdx)
..B3.213:
        lea       1(,%r8,4), %ebp
        lea       1(%rdi), %r10d
        movl      6656(%rsp,%rbp,4), %esi
        addl      %esi, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%r10,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.215
..B3.214:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      1540(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       5(%rdi), %r11d
        movl      %r12d, 1540(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       9(%rdi), %r10d
        movl      %r11d, 1556(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 1572(%rsi,%rdx)
        lea       13(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      1604(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 1588(%rsi,%rdx)
        movl      %r11d, 1604(%rsi,%rdx)
        jmp       ..B3.216
..B3.215:
        shll      $2, %esi
        lea       5(%rdi), %ebp
        lea       9(%rdi), %r11d
        movl      %r10d, 1540(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %r10d
        lea       13(%rdi), %ebp
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r10d, 1556(%rsi,%rdx)
        movl      %r12d, 1572(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %ebp
        movl      %ebp, 1588(%rsi,%rdx)
..B3.216:
        lea       2(,%r8,4), %ebp
        lea       2(%rdi), %r10d
        movl      6656(%rsp,%rbp,4), %esi
        addl      %esi, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%r10,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.218
..B3.217:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      1544(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       6(%rdi), %r11d
        movl      %r12d, 1544(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       10(%rdi), %r10d
        movl      %r11d, 1560(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 1576(%rsi,%rdx)
        lea       14(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      1608(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 1592(%rsi,%rdx)
        movl      %r11d, 1608(%rsi,%rdx)
        jmp       ..B3.219
..B3.218:
        shll      $2, %esi
        lea       6(%rdi), %ebp
        lea       10(%rdi), %r11d
        movl      %r10d, 1544(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %r10d
        lea       14(%rdi), %ebp
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r10d, 1560(%rsi,%rdx)
        movl      %r12d, 1576(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %ebp
        movl      %ebp, 1592(%rsi,%rdx)
..B3.219:
        lea       3(,%r8,4), %ebp
        lea       3(%rdi), %r10d
        movl      6656(%rsp,%rbp,4), %esi
        addl      %esi, %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        movl      6304(%rsp,%r10,4), %r10d
        testl     %ebx, %ebx
        je        ..B3.221
..B3.220:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r12d
        movl      %r10d, %r11d
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      1548(%rsi,%rdx), %r12d
        orl       %r11d, %r12d
        lea       7(%rdi), %r11d
        movl      %r12d, 1548(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r12d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       11(%rdi), %r10d
        movl      %r11d, 1564(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r12d
        movl      %ebx, %ecx
        orl       %r12d, %r10d
        movl      %r10d, 1580(%rsi,%rdx)
        lea       15(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r12d
        shll      %cl, %r12d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r12d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      1612(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r12d, 1596(%rsi,%rdx)
        movl      %r11d, 1612(%rsi,%rdx)
        jmp       ..B3.222
..B3.221:
        shll      $2, %esi
        lea       7(%rdi), %ebp
        lea       11(%rdi), %r11d
        movl      %r10d, 1548(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %r10d
        lea       15(%rdi), %ebp
        movl      6304(%rsp,%r11,4), %r12d
        movl      %r10d, 1564(%rsi,%rdx)
        movl      %r12d, 1580(%rsi,%rdx)
        movl      6304(%rsp,%rbp,4), %ebp
        movl      %ebp, 1596(%rsi,%rdx)
..B3.222:
        incl      %r8d
        addl      $256, %r9d
        addl      $16, %edi
        cmpl      $3, %r8d
        jb        ..B3.210
..B3.223:
        movl      6728(%rsp), %r12d
        xorl      %ebx, %ebx
        lea       6304(%rsp), %rbp
        jmp       ..B3.250
..1.4_0.TAG.028.0.4.43:
..1.4_0.TAG.026.0.4.43:
..1.4_0.TAG.022.0.4.43:
..1.4_0.TAG.020.0.4.43:
..1.4_0.TAG.01a.0.4.43:
..1.4_0.TAG.016.0.4.43:
..1.4_0.TAG.014.0.4.43:
..1.4_0.TAG.010.0.4.43:
..1.4_0.TAG.0a.0.4.43:
..1.4_0.TAG.08.0.4.43:
..1.4_0.TAG.04.0.4.43:
..1.4_0.TAG.02.0.4.43:
..B3.225:
        movl      %ebx, %r9d
        movl      $6, %eax
        xorb      %r11b, %r11b
        movl      %r9d, %r8d
        movl      %r13d, 6648(%rsp)
        movq      %rax, %rbx
        movl      %r14d, 6720(%rsp)
        movq      %rbp, %r13
        movl      %r12d, 6728(%rsp)
        movl      %r8d, %ebp
        movl      %r9d, %r15d
        movb      %r11b, %r14b
        lea       4608(%rsp), %r12
..B3.226:
        movl      %r15d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %r12, %rdi
        addq      %r13, %rsi
..___tag_value_md5cryptsse.68:
        call      memcpy
..___tag_value_md5cryptsse.69:
..B3.227:
        incb      %r14b
        addl      $256, %r15d
        addl      $64, %ebp
        cmpb      $3, %r14b
        jb        ..B3.226
..B3.228:
        movl      6720(%rsp), %r14d
        movq      %rbx, %rax
        movl      6728(%rsp), %r12d
        movq      %r13, %rbp
        movl      6648(%rsp), %r13d
        xorl      %ebx, %ebx
        lea       (%rsp), %r15
        jmp       ..B3.250
..1.4_0.TAG.00.0.4.43:
..B3.231:
        movl      %ebx, %r8d
        xorl      %eax, %eax
        xorb      %r9b, %r9b
        movl      %r8d, %ecx
        movl      %r13d, 6648(%rsp)
        movq      %rax, %r13
        movl      %r14d, 6720(%rsp)
        movl      %ecx, %ebx
        movl      %r12d, 6728(%rsp)
        movq      %rbp, %r14
        movl      %r8d, %ebp
        movb      %r9b, %r12b
..B3.232:
        movl      %ebp, %edi
        movl      $64, %edx
        movl      %ebx, %esi
        addq      %r15, %rdi
        addq      %r14, %rsi
..___tag_value_md5cryptsse.70:
        call      memcpy
..___tag_value_md5cryptsse.71:
..B3.233:
        incb      %r12b
        addl      $256, %ebp
        addl      $64, %ebx
        cmpb      $3, %r12b
        jb        ..B3.232
..B3.234:
        movl      6728(%rsp), %r12d
        movq      %r13, %rax
        movl      6648(%rsp), %r13d
        movq      %r14, %rbp
        movl      6720(%rsp), %r14d
        xorl      %ebx, %ebx
        jmp       ..B3.250
..1.4_0.TAG.DEFAULT.0.4.43:
..B3.235:
        movl      %ebx, %r8d
        movl      $7, %eax
        movl      %r8d, %r9d
        movl      %r14d, 6720(%rsp)
        movl      %r9d, %edi
..B3.236:
        lea       (,%r8,4), %ecx
        movl      %r9d, %edx
        addq      %r15, %rdx
        movl      6304(%rsp,%rdi,4), %r10d
        movl      6656(%rsp,%rcx,4), %ebp
        lea       (%r12,%rbp,2), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        testl     %ebx, %ebx
        je        ..B3.238
..B3.237:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      5376(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       4(%rdi), %r11d
        movl      %r14d, 5376(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       8(%rdi), %r10d
        movl      %r11d, 5392(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 5408(%rsi,%rdx)
        lea       12(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      5440(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 5424(%rsi,%rdx)
        movl      %r11d, 5440(%rsi,%rdx)
        jmp       ..B3.239
..B3.238:
        shll      $2, %esi
        lea       4(%rdi), %ecx
        lea       12(%rdi), %r14d
        movl      %r10d, 5376(%rsi,%rdx)
        lea       8(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 5392(%rsi,%rdx)
        movl      %ecx, 5424(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 5408(%rsi,%rdx)
..B3.239:
        lea       1(,%r8,4), %ecx
        lea       1(%rdi), %r10d
        movl      6656(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r10,4), %r10d
        lea       (%r12,%rbp,2), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        testl     %ebx, %ebx
        je        ..B3.241
..B3.240:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      5380(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       5(%rdi), %r11d
        movl      %r14d, 5380(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       9(%rdi), %r10d
        movl      %r11d, 5396(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 5412(%rsi,%rdx)
        lea       13(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      5444(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 5428(%rsi,%rdx)
        movl      %r11d, 5444(%rsi,%rdx)
        jmp       ..B3.242
..B3.241:
        shll      $2, %esi
        lea       5(%rdi), %ecx
        lea       13(%rdi), %r14d
        movl      %r10d, 5380(%rsi,%rdx)
        lea       9(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 5396(%rsi,%rdx)
        movl      %ecx, 5428(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 5412(%rsi,%rdx)
..B3.242:
        lea       2(,%r8,4), %ecx
        lea       2(%rdi), %r10d
        movl      6656(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r10,4), %r10d
        lea       (%r12,%rbp,2), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        testl     %ebx, %ebx
        je        ..B3.244
..B3.243:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      5384(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       6(%rdi), %r11d
        movl      %r14d, 5384(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       10(%rdi), %r10d
        movl      %r11d, 5400(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 5416(%rsi,%rdx)
        lea       14(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      5448(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 5432(%rsi,%rdx)
        movl      %r11d, 5448(%rsi,%rdx)
        jmp       ..B3.245
..B3.244:
        shll      $2, %esi
        lea       6(%rdi), %ecx
        lea       14(%rdi), %r14d
        movl      %r10d, 5384(%rsi,%rdx)
        lea       10(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 5400(%rsi,%rdx)
        movl      %ecx, 5432(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 5416(%rsi,%rdx)
..B3.245:
        lea       3(,%r8,4), %ecx
        lea       3(%rdi), %r10d
        movl      6656(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r10,4), %r10d
        lea       (%r12,%rbp,2), %esi
        movl      %esi, %ebx
        andl      $3, %ebx
        shll      $3, %ebx
        testl     %ebx, %ebx
        je        ..B3.247
..B3.246:
        andl      $-4, %esi
        movl      %ebx, %ebp
        shll      $2, %esi
        negl      %ebp
        movl      %ebp, %ecx
        movl      $-1, %r14d
        movl      %r10d, %r11d
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        shll      %cl, %r11d
        movl      %ebx, %ecx
        andl      5388(%rsi,%rdx), %r14d
        orl       %r11d, %r14d
        lea       7(%rdi), %r11d
        movl      %r14d, 5388(%rsi,%rdx)
        movl      6304(%rsp,%r11,4), %r14d
        movl      %r14d, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        shrl      %cl, %r10d
        movl      %ebx, %ecx
        orl       %r10d, %r11d
        lea       11(%rdi), %r10d
        movl      %r11d, 5404(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, %r10d
        shll      %cl, %r10d
        movl      %ebp, %ecx
        shrl      %cl, %r14d
        movl      %ebx, %ecx
        orl       %r14d, %r10d
        movl      %r10d, 5420(%rsi,%rdx)
        lea       15(%rdi), %r10d
        movl      6304(%rsp,%r10,4), %r10d
        movl      %r10d, %r14d
        shll      %cl, %r14d
        movl      %ebp, %ecx
        shrl      %cl, %r11d
        movl      %ebx, %ecx
        orl       %r11d, %r14d
        movl      $-1, %r11d
        shll      %cl, %r11d
        movl      %ebp, %ecx
        andl      5452(%rsi,%rdx), %r11d
        shrl      %cl, %r10d
        orl       %r10d, %r11d
        movl      %r14d, 5436(%rsi,%rdx)
        movl      %r11d, 5452(%rsi,%rdx)
        jmp       ..B3.248
..B3.247:
        shll      $2, %esi
        lea       7(%rdi), %ecx
        lea       15(%rdi), %r14d
        movl      %r10d, 5388(%rsi,%rdx)
        lea       11(%rdi), %r10d
        movl      6304(%rsp,%rcx,4), %ebp
        movl      6304(%rsp,%r14,4), %ecx
        movl      %ebp, 5404(%rsi,%rdx)
        movl      %ecx, 5436(%rsi,%rdx)
        movl      6304(%rsp,%r10,4), %r11d
        movl      %r11d, 5420(%rsi,%rdx)
..B3.248:
        incl      %r8d
        addl      $256, %r9d
        addl      $16, %edi
        cmpl      $3, %r8d
        jb        ..B3.236
..B3.249:
        movl      6720(%rsp), %r14d
        xorl      %ebx, %ebx
        lea       6304(%rsp), %rbp
..B3.250:
        movq      %rbp, %rsi
        lea       (%rax,%rax,2), %rdi
        shlq      $8, %rdi
        xorl      %edx, %edx
        addq      %r15, %rdi
        xorl      %ecx, %ecx
..___tag_value_md5cryptsse.72:
        call      SIMDmd5body..0
..___tag_value_md5cryptsse.73:
..B3.251:
        incl      %r13d
        lea       -1(%r13), %edi
        cmpl      $33, %edi
        jb        ..B3.141
..B3.252:
        cmpl      $34, %r13d
        jne       ..B3.255
..B3.253:
        testl     %r14d, %r14d
        je        ..B3.259
..B3.254:
        decl      %r14d
        jmp       ..B3.141
..B3.255:
        cmpl      $42, %r13d
        cmovae    %ebx, %r13d
        jmp       ..B3.141
..B3.256:
        testl     %r15d, %r15d
        ja        ..B3.70
..B3.257:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rcx), %rax
        jmp       ..B3.77
..B3.258:
        testl     %r12d, %r12d
        ja        ..B3.105
        jmp       ..B3.112
..B3.259:
        movq      6296(%rsp), %r15
        movq      %r15, %rdi
        movl      $192, %edx
        lea       6304(%rsp), %rsi
..___tag_value_md5cryptsse.74:
        call      memcpy
..___tag_value_md5cryptsse.75:
..B3.260:
        addq      $6824, %rsp
..___tag_value_md5cryptsse.76:
        popq      %rbp
..___tag_value_md5cryptsse.78:
        popq      %rbx
..___tag_value_md5cryptsse.80:
        popq      %r15
..___tag_value_md5cryptsse.82:
        popq      %r14
..___tag_value_md5cryptsse.84:
        popq      %r13
..___tag_value_md5cryptsse.86:
        popq      %r12
..___tag_value_md5cryptsse.88:
        ret       
..___tag_value_md5cryptsse.89:
..B3.269:
        testl     %r15d, %r15d
        ja        ..B3.85
        jmp       ..B3.97
..B3.271:
        testl     %r15d, %r15d
        jmp       ..B3.47
..B3.272:
        testl     %r15d, %r15d
        jmp       ..B3.21
        .align    16,0x90
..___tag_value_md5cryptsse.96:
	.type	md5cryptsse,@function
	.size	md5cryptsse,.-md5cryptsse
	.section .rodata, "a"
	.align 32
	.align 32
..1..TPKT.4_0.0.4.43:
	.quad	..1.4_0.TAG.00.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.02.0.4.43
	.quad	..1.4_0.TAG.03.0.4.43
	.quad	..1.4_0.TAG.04.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.06.0.4.43
	.quad	..1.4_0.TAG.07.0.4.43
	.quad	..1.4_0.TAG.08.0.4.43
	.quad	..1.4_0.TAG.09.0.4.43
	.quad	..1.4_0.TAG.0a.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.0c.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.0e.0.4.43
	.quad	..1.4_0.TAG.0f.0.4.43
	.quad	..1.4_0.TAG.010.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.012.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.014.0.4.43
	.quad	..1.4_0.TAG.015.0.4.43
	.quad	..1.4_0.TAG.016.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.018.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.01a.0.4.43
	.quad	..1.4_0.TAG.01b.0.4.43
	.quad	..1.4_0.TAG.01c.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.01e.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.020.0.4.43
	.quad	..1.4_0.TAG.021.0.4.43
	.quad	..1.4_0.TAG.022.0.4.43
	.quad	..1.4_0.TAG.023.0.4.43
	.quad	..1.4_0.TAG.024.0.4.43
	.quad	..1.4_0.TAG.DEFAULT.0.4.43
	.quad	..1.4_0.TAG.026.0.4.43
	.quad	..1.4_0.TAG.027.0.4.43
	.quad	..1.4_0.TAG.028.0.4.43
	.data
# -- End  md5cryptsse
	.text
# -- Begin  SIMDmd4body
       .align    16,0x90
	.globl SIMDmd4body
SIMDmd4body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B4.1:
..___tag_value_SIMDmd4body.97:
        subq      $1544, %rsp
..___tag_value_SIMDmd4body.99:
        movl      %ecx, %r8d
        movq      %rdx, %rcx
        testl     $1, %r8d
        je        ..B4.18
..B4.2:
        movl      (%rdi), %eax
        xorl      %edx, %edx
        movl      %eax, (%rsp)
        lea       4(%rsp), %rax
        testl     $256, %r8d
        jne       ..B4.13
..B4.3:
        testl     $64, %r8d
        jne       ..B4.9
        jmp       ..B4.5
..B4.6:
        movl      (%rdi), %r9d
        movl      %r9d, 252(%rax)
        addq      $256, %rax
..B4.5:
        movl      64(%rdi), %r9d
        incl      %edx
        movl      128(%rdi), %r10d
        movl      192(%rdi), %r11d
        movl      %r9d, (%rax)
        movl      %r10d, 4(%rax)
        movl      %r11d, 8(%rax)
        movl      4(%rdi), %r9d
        movl      68(%rdi), %r10d
        movl      132(%rdi), %r11d
        movl      %r9d, 12(%rax)
        movl      %r10d, 16(%rax)
        movl      %r11d, 20(%rax)
        movl      196(%rdi), %r9d
        movl      8(%rdi), %r10d
        movl      72(%rdi), %r11d
        movl      %r9d, 24(%rax)
        movl      %r10d, 28(%rax)
        movl      %r11d, 32(%rax)
        movl      136(%rdi), %r9d
        movl      200(%rdi), %r10d
        movl      12(%rdi), %r11d
        movl      %r9d, 36(%rax)
        movl      %r10d, 40(%rax)
        movl      %r11d, 44(%rax)
        movl      76(%rdi), %r9d
        movl      140(%rdi), %r10d
        movl      204(%rdi), %r11d
        movl      %r9d, 48(%rax)
        movl      %r10d, 52(%rax)
        movl      %r11d, 56(%rax)
        movl      16(%rdi), %r9d
        movl      80(%rdi), %r10d
        movl      144(%rdi), %r11d
        movl      %r9d, 60(%rax)
        movl      %r10d, 64(%rax)
        movl      %r11d, 68(%rax)
        movl      208(%rdi), %r9d
        movl      20(%rdi), %r10d
        movl      84(%rdi), %r11d
        movl      %r9d, 72(%rax)
        movl      %r10d, 76(%rax)
        movl      %r11d, 80(%rax)
        movl      148(%rdi), %r9d
        movl      212(%rdi), %r10d
        movl      24(%rdi), %r11d
        movl      %r9d, 84(%rax)
        movl      %r10d, 88(%rax)
        movl      %r11d, 92(%rax)
        movl      88(%rdi), %r9d
        movl      152(%rdi), %r10d
        .byte     15
        .byte     31
        .byte     64
        .byte     0
        movl      216(%rdi), %r11d
        movl      %r9d, 96(%rax)
        movl      %r10d, 100(%rax)
        movl      %r11d, 104(%rax)
        movl      28(%rdi), %r9d
        movl      92(%rdi), %r10d
        movl      156(%rdi), %r11d
        movl      %r9d, 108(%rax)
        movl      %r10d, 112(%rax)
        movl      %r11d, 116(%rax)
        movl      220(%rdi), %r9d
        movl      32(%rdi), %r10d
        movl      96(%rdi), %r11d
        movl      %r9d, 120(%rax)
        movl      %r10d, 124(%rax)
        movl      %r11d, 128(%rax)
        movl      160(%rdi), %r9d
        movl      224(%rdi), %r10d
        movl      36(%rdi), %r11d
        movl      %r9d, 132(%rax)
        movl      %r10d, 136(%rax)
        movl      %r11d, 140(%rax)
        .byte     15
        .byte     31
        .byte     0
        movl      100(%rdi), %r9d
        movl      164(%rdi), %r10d
        movl      228(%rdi), %r11d
        movl      %r9d, 144(%rax)
        movl      %r10d, 148(%rax)
        movl      %r11d, 152(%rax)
        .byte     144
        movl      40(%rdi), %r9d
        movl      104(%rdi), %r10d
        movl      168(%rdi), %r11d
        movl      %r9d, 156(%rax)
        .byte     15
        .byte     31
        .byte     0
        movl      %r10d, 160(%rax)
        movl      %r11d, 164(%rax)
        movl      232(%rdi), %r9d
        movl      44(%rdi), %r10d
        movl      108(%rdi), %r11d
        movl      %r9d, 168(%rax)
        movl      %r10d, 172(%rax)
        movl      %r11d, 176(%rax)
        .byte     144
        movl      172(%rdi), %r9d
        .byte     15
        .byte     31
        .byte     0
        movl      236(%rdi), %r10d
        movl      48(%rdi), %r11d
        .byte     15
        .byte     31
        .byte     64
        .byte     0
        movl      %r9d, 180(%rax)
        movl      %r10d, 184(%rax)
        movl      %r11d, 188(%rax)
        movl      112(%rdi), %r9d
        movl      176(%rdi), %r10d
        .byte     144
        movl      240(%rdi), %r11d
        .byte     102
        .byte     144
        movl      %r9d, 192(%rax)
        movl      %r10d, 196(%rax)
        movl      %r11d, 200(%rax)
        .byte     144
        movl      52(%rdi), %r9d
        movl      116(%rdi), %r10d
        movl      180(%rdi), %r11d
        movl      %r9d, 204(%rax)
        .byte     15
        .byte     31
        .byte     0
        movl      %r10d, 208(%rax)
        movl      %r11d, 212(%rax)
        movl      244(%rdi), %r9d
        movl      56(%rdi), %r10d
        movl      120(%rdi), %r11d
        movl      %r9d, 216(%rax)
        movl      %r10d, 220(%rax)
        movl      %r11d, 224(%rax)
        movl      184(%rdi), %r9d
        movl      248(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      %r9d, 228(%rax)
        movl      %r10d, 232(%rax)
        movl      %r11d, 236(%rax)
        movl      124(%rdi), %r9d
        movl      188(%rdi), %r10d
        movl      252(%rdi), %r11d
        addq      $256, %rdi
        movl      %r9d, 240(%rax)
        cmpl      $3, %edx
        movl      %r10d, 244(%rax)
        movl      %r11d, 248(%rax)
        jb        ..B4.6
        jmp       ..B4.16
..B4.10:
        movl      (%rdi), %r9d
        movl      %r9d, 252(%rax)
        addq      $256, %rax
..B4.9:
        movl      128(%rdi), %r9d
        incl      %edx
        movl      256(%rdi), %r10d
        movl      384(%rdi), %r11d
        movl      %r9d, (%rax)
        movl      %r10d, 4(%rax)
        movl      %r11d, 8(%rax)
        movl      4(%rdi), %r9d
        movl      132(%rdi), %r10d
        movl      260(%rdi), %r11d
        movl      %r9d, 12(%rax)
        movl      %r10d, 16(%rax)
        movl      %r11d, 20(%rax)
        movl      388(%rdi), %r9d
        movl      8(%rdi), %r10d
        movl      136(%rdi), %r11d
        movl      %r9d, 24(%rax)
        movl      %r10d, 28(%rax)
        movl      %r11d, 32(%rax)
        movl      264(%rdi), %r9d
        movl      392(%rdi), %r10d
        movl      12(%rdi), %r11d
        movl      %r9d, 36(%rax)
        movl      %r10d, 40(%rax)
        movl      %r11d, 44(%rax)
        movl      140(%rdi), %r9d
        movl      268(%rdi), %r10d
        movl      396(%rdi), %r11d
        movl      %r9d, 48(%rax)
        movl      %r10d, 52(%rax)
        movl      %r11d, 56(%rax)
        movl      16(%rdi), %r9d
        movl      144(%rdi), %r10d
        movl      272(%rdi), %r11d
        movl      %r9d, 60(%rax)
        movl      %r10d, 64(%rax)
        movl      %r11d, 68(%rax)
        movl      400(%rdi), %r9d
        movl      20(%rdi), %r10d
        movl      148(%rdi), %r11d
        movl      %r9d, 72(%rax)
        movl      %r10d, 76(%rax)
        movl      %r11d, 80(%rax)
        movl      276(%rdi), %r9d
        movl      404(%rdi), %r10d
        movl      24(%rdi), %r11d
        movl      %r9d, 84(%rax)
        movl      %r10d, 88(%rax)
        movl      %r11d, 92(%rax)
        movl      152(%rdi), %r9d
        movl      280(%rdi), %r10d
        movl      408(%rdi), %r11d
        movl      %r9d, 96(%rax)
        movl      %r10d, 100(%rax)
        movl      %r11d, 104(%rax)
        movl      28(%rdi), %r9d
        movl      156(%rdi), %r10d
        movl      284(%rdi), %r11d
        movl      %r9d, 108(%rax)
        movl      %r10d, 112(%rax)
        movl      %r11d, 116(%rax)
        movl      412(%rdi), %r9d
        movl      32(%rdi), %r10d
        movl      160(%rdi), %r11d
        movl      %r9d, 120(%rax)
        movl      %r10d, 124(%rax)
        movl      %r11d, 128(%rax)
        movl      288(%rdi), %r9d
        movl      416(%rdi), %r10d
        movl      36(%rdi), %r11d
        movl      %r9d, 132(%rax)
        movl      %r10d, 136(%rax)
        movl      %r11d, 140(%rax)
        movl      164(%rdi), %r9d
        movl      292(%rdi), %r10d
        movl      420(%rdi), %r11d
        movl      %r9d, 144(%rax)
        movl      %r10d, 148(%rax)
        movl      %r11d, 152(%rax)
        movl      40(%rdi), %r9d
        movl      168(%rdi), %r10d
        movl      296(%rdi), %r11d
        movl      %r9d, 156(%rax)
        movl      %r10d, 160(%rax)
        movl      %r11d, 164(%rax)
        movl      424(%rdi), %r9d
        movl      44(%rdi), %r10d
        movl      172(%rdi), %r11d
        movl      %r9d, 168(%rax)
        movl      %r10d, 172(%rax)
        movl      %r11d, 176(%rax)
        movl      300(%rdi), %r9d
        movl      428(%rdi), %r10d
        movl      48(%rdi), %r11d
        movl      %r9d, 180(%rax)
        movl      %r10d, 184(%rax)
        movl      %r11d, 188(%rax)
        movl      176(%rdi), %r9d
        movl      304(%rdi), %r10d
        movl      432(%rdi), %r11d
        movl      %r9d, 192(%rax)
        movl      %r10d, 196(%rax)
        movl      %r11d, 200(%rax)
        movl      52(%rdi), %r9d
        movl      180(%rdi), %r10d
        movl      308(%rdi), %r11d
        movl      %r9d, 204(%rax)
        movl      %r10d, 208(%rax)
        movl      %r11d, 212(%rax)
        movl      436(%rdi), %r9d
        movl      56(%rdi), %r10d
        movl      184(%rdi), %r11d
        movl      %r9d, 216(%rax)
        movl      %r10d, 220(%rax)
        movl      %r11d, 224(%rax)
        movl      312(%rdi), %r9d
        movl      440(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      %r9d, 228(%rax)
        movl      %r10d, 232(%rax)
        movl      %r11d, 236(%rax)
        movl      188(%rdi), %r9d
        movl      316(%rdi), %r10d
        movl      444(%rdi), %r11d
        addq      $512, %rdi
        movl      %r9d, 240(%rax)
        cmpl      $3, %edx
        movl      %r10d, 244(%rax)
        movl      %r11d, 248(%rax)
        jb        ..B4.10
        jmp       ..B4.16
..B4.14:
        movl      (%rdi), %r9d
        movl      %r9d, 252(%rax)
        addq      $256, %rax
..B4.13:
        movl      256(%rdi), %r9d
        incl      %edx
        movl      512(%rdi), %r10d
        movl      768(%rdi), %r11d
        movl      %r9d, (%rax)
        movl      %r10d, 4(%rax)
        movl      %r11d, 8(%rax)
        movl      4(%rdi), %r9d
        movl      260(%rdi), %r10d
        movl      516(%rdi), %r11d
        movl      %r9d, 12(%rax)
        movl      %r10d, 16(%rax)
        movl      %r11d, 20(%rax)
        movl      772(%rdi), %r9d
        movl      8(%rdi), %r10d
        movl      264(%rdi), %r11d
        movl      %r9d, 24(%rax)
        movl      %r10d, 28(%rax)
        movl      %r11d, 32(%rax)
        movl      520(%rdi), %r9d
        movl      776(%rdi), %r10d
        movl      12(%rdi), %r11d
        movl      %r9d, 36(%rax)
        movl      %r10d, 40(%rax)
        movl      %r11d, 44(%rax)
        movl      268(%rdi), %r9d
        movl      524(%rdi), %r10d
        movl      780(%rdi), %r11d
        movl      %r9d, 48(%rax)
        movl      %r10d, 52(%rax)
        movl      %r11d, 56(%rax)
        movl      16(%rdi), %r9d
        movl      272(%rdi), %r10d
        movl      528(%rdi), %r11d
        movl      %r9d, 60(%rax)
        movl      %r10d, 64(%rax)
        movl      %r11d, 68(%rax)
        movl      784(%rdi), %r9d
        movl      20(%rdi), %r10d
        movl      276(%rdi), %r11d
        movl      %r9d, 72(%rax)
        movl      %r10d, 76(%rax)
        movl      %r11d, 80(%rax)
        movl      532(%rdi), %r9d
        movl      788(%rdi), %r10d
        movl      24(%rdi), %r11d
        movl      %r9d, 84(%rax)
        movl      %r10d, 88(%rax)
        movl      %r11d, 92(%rax)
        movl      280(%rdi), %r9d
        movl      536(%rdi), %r10d
        movl      792(%rdi), %r11d
        movl      %r9d, 96(%rax)
        movl      %r10d, 100(%rax)
        movl      %r11d, 104(%rax)
        movl      28(%rdi), %r9d
        movl      284(%rdi), %r10d
        movl      540(%rdi), %r11d
        movl      %r9d, 108(%rax)
        movl      %r10d, 112(%rax)
        movl      %r11d, 116(%rax)
        movl      796(%rdi), %r9d
        movl      32(%rdi), %r10d
        movl      288(%rdi), %r11d
        movl      %r9d, 120(%rax)
        movl      %r10d, 124(%rax)
        movl      %r11d, 128(%rax)
        movl      544(%rdi), %r9d
        movl      800(%rdi), %r10d
        movl      36(%rdi), %r11d
        movl      %r9d, 132(%rax)
        movl      %r10d, 136(%rax)
        movl      %r11d, 140(%rax)
        movl      292(%rdi), %r9d
        movl      548(%rdi), %r10d
        movl      804(%rdi), %r11d
        movl      %r9d, 144(%rax)
        movl      %r10d, 148(%rax)
        movl      %r11d, 152(%rax)
        movl      40(%rdi), %r9d
        movl      296(%rdi), %r10d
        movl      552(%rdi), %r11d
        movl      %r9d, 156(%rax)
        movl      %r10d, 160(%rax)
        movl      %r11d, 164(%rax)
        movl      808(%rdi), %r9d
        movl      44(%rdi), %r10d
        movl      300(%rdi), %r11d
        movl      %r9d, 168(%rax)
        movl      %r10d, 172(%rax)
        movl      %r11d, 176(%rax)
        movl      556(%rdi), %r9d
        movl      812(%rdi), %r10d
        movl      48(%rdi), %r11d
        movl      %r9d, 180(%rax)
        movl      %r10d, 184(%rax)
        movl      %r11d, 188(%rax)
        movl      304(%rdi), %r9d
        movl      560(%rdi), %r10d
        movl      816(%rdi), %r11d
        movl      %r9d, 192(%rax)
        movl      %r10d, 196(%rax)
        movl      %r11d, 200(%rax)
        movl      52(%rdi), %r9d
        movl      308(%rdi), %r10d
        movl      564(%rdi), %r11d
        movl      %r9d, 204(%rax)
        movl      %r10d, 208(%rax)
        movl      %r11d, 212(%rax)
        movl      820(%rdi), %r9d
        movl      56(%rdi), %r10d
        movl      312(%rdi), %r11d
        movl      %r9d, 216(%rax)
        movl      %r10d, 220(%rax)
        movl      %r11d, 224(%rax)
        movl      568(%rdi), %r9d
        movl      824(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      %r9d, 228(%rax)
        movl      %r10d, 232(%rax)
        movl      %r11d, 236(%rax)
        movl      316(%rdi), %r9d
        movl      572(%rdi), %r10d
        movl      828(%rdi), %r11d
        addq      $1024, %rdi
        movl      %r9d, 240(%rax)
        cmpl      $3, %edx
        movl      %r10d, 244(%rax)
        movl      %r11d, 248(%rax)
        jb        ..B4.14
..B4.16:
        lea       (%rsp), %rdi
..B4.18:
        movl      %r8d, %edx
        andl      $2, %edx
        jne       ..B4.20
..B4.19:
        movdqa    .L_2il0floatpacket.521(%rip), %xmm4
        movdqa    .L_2il0floatpacket.22(%rip), %xmm1
        movdqa    %xmm4, %xmm9
        movdqa    .L_2il0floatpacket.23(%rip), %xmm2
        movdqa    %xmm1, %xmm3
        movdqa    .L_2il0floatpacket.24(%rip), %xmm0
        movdqa    %xmm2, %xmm7
        movdqa    %xmm0, %xmm12
        movdqa    %xmm4, %xmm10
        movdqa    %xmm1, %xmm5
        movdqa    %xmm2, %xmm11
        movdqa    %xmm0, %xmm13
        jmp       ..B4.23
..B4.20:
        movl      %r8d, %eax
        andl      $6, %eax
        movdqa    (%rcx), %xmm4
        cmpl      $6, %eax
        movdqa    16(%rcx), %xmm1
        movdqa    32(%rcx), %xmm2
        movdqa    48(%rcx), %xmm0
        jne       ..B4.22
..B4.21:
        movdqa    256(%rcx), %xmm9
        movdqa    272(%rcx), %xmm3
        movdqa    288(%rcx), %xmm7
        movdqa    304(%rcx), %xmm12
        movdqa    512(%rcx), %xmm10
        movdqa    528(%rcx), %xmm5
        movdqa    544(%rcx), %xmm11
        movdqa    560(%rcx), %xmm13
        jmp       ..B4.23
..B4.22:
        movdqa    64(%rcx), %xmm9
        movdqa    80(%rcx), %xmm3
        movdqa    96(%rcx), %xmm7
        movdqa    112(%rcx), %xmm12
        movdqa    128(%rcx), %xmm10
        movdqa    144(%rcx), %xmm5
        movdqa    160(%rcx), %xmm11
        movdqa    176(%rcx), %xmm13
..B4.23:
        movdqa    %xmm7, %xmm8
        movdqa    %xmm2, %xmm6
        pxor      %xmm12, %xmm8
        pxor      %xmm15, %xmm15
        pand      %xmm3, %xmm8
        paddd     %xmm15, %xmm9
        pxor      %xmm0, %xmm6
        pxor      %xmm12, %xmm8
        pand      %xmm1, %xmm6
        paddd     %xmm8, %xmm9
        movdqa    %xmm11, %xmm8
        paddd     %xmm15, %xmm4
        pxor      %xmm0, %xmm6
        pxor      %xmm13, %xmm8
        paddd     %xmm6, %xmm4
        pand      %xmm5, %xmm8
        movdqa    256(%rdi), %xmm6
        pxor      %xmm13, %xmm8
        movdqa    (%rdi), %xmm14
        paddd     %xmm6, %xmm9
        paddd     %xmm15, %xmm10
        paddd     %xmm14, %xmm4
        movdqa    %xmm14, 1072(%rsp)
        paddd     %xmm8, %xmm10
        movdqa    %xmm9, %xmm8
        psrld     $29, %xmm9
        movdqa    %xmm6, 1136(%rsp)
        movdqa    %xmm4, %xmm6
        movdqa    512(%rdi), %xmm14
        pslld     $3, %xmm8
        paddd     %xmm14, %xmm10
        pslld     $3, %xmm6
        psrld     $29, %xmm4
        por       %xmm9, %xmm8
        movdqa    %xmm1, %xmm9
        por       %xmm4, %xmm6
        movdqa    %xmm10, %xmm4
        pxor      %xmm2, %xmm9
        movdqa    %xmm14, 1520(%rsp)
        pslld     $3, %xmm4
        psrld     $29, %xmm10
        movdqa    %xmm5, %xmm14
        pand      %xmm6, %xmm9
        por       %xmm10, %xmm4
        pxor      %xmm11, %xmm14
        paddd     %xmm15, %xmm0
        pxor      %xmm2, %xmm9
        pand      %xmm4, %xmm14
        paddd     %xmm9, %xmm0
        pxor      %xmm11, %xmm14
        movdqa    16(%rdi), %xmm9
        paddd     %xmm15, %xmm13
        movdqa    %xmm3, %xmm10
        paddd     %xmm9, %xmm0
        movdqa    %xmm9, 800(%rsp)
        paddd     %xmm14, %xmm13
        movdqa    528(%rdi), %xmm9
        pxor      %xmm7, %xmm10
        movdqa    %xmm9, 992(%rsp)
        paddd     %xmm9, %xmm13
        movdqa    %xmm0, %xmm9
        pand      %xmm8, %xmm10
        pslld     $7, %xmm9
        psrld     $25, %xmm0
        paddd     %xmm15, %xmm12
        pxor      %xmm7, %xmm10
        por       %xmm0, %xmm9
        movdqa    %xmm13, %xmm0
        paddd     %xmm10, %xmm12
        pslld     $7, %xmm0
        movdqa    272(%rdi), %xmm10
        psrld     $25, %xmm13
        paddd     %xmm10, %xmm12
        por       %xmm13, %xmm0
        movdqa    %xmm1, %xmm13
        movdqa    %xmm5, %xmm14
        movdqa    %xmm10, 816(%rsp)
        movdqa    %xmm12, %xmm10
        pxor      %xmm6, %xmm13
        pslld     $7, %xmm10
        psrld     $25, %xmm12
        pand      %xmm9, %xmm13
        por       %xmm12, %xmm10
        movdqa    %xmm3, %xmm12
        pxor      %xmm4, %xmm14
        paddd     %xmm15, %xmm2
        pxor      %xmm1, %xmm13
        pxor      %xmm8, %xmm12
        pand      %xmm0, %xmm14
        paddd     %xmm13, %xmm2
        movdqa    32(%rdi), %xmm13
        pand      %xmm10, %xmm12
        pxor      %xmm5, %xmm14
        paddd     %xmm15, %xmm11
        movdqa    %xmm13, 896(%rsp)
        paddd     %xmm15, %xmm7
        pxor      %xmm3, %xmm12
        paddd     %xmm13, %xmm2
        movdqa    544(%rdi), %xmm13
        paddd     %xmm14, %xmm11
        movdqa    %xmm13, 1296(%rsp)
        paddd     %xmm12, %xmm7
        movdqa    288(%rdi), %xmm12
        paddd     %xmm13, %xmm11
        movdqa    %xmm2, %xmm13
        paddd     %xmm12, %xmm7
        pslld     $11, %xmm13
        psrld     $21, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm7, %xmm2
        movdqa    %xmm12, 912(%rsp)
        pslld     $11, %xmm2
        psrld     $21, %xmm7
        movdqa    %xmm11, %xmm12
        por       %xmm7, %xmm2
        pslld     $11, %xmm12
        psrld     $21, %xmm11
        movdqa    %xmm9, %xmm7
        por       %xmm11, %xmm12
        pxor      %xmm6, %xmm7
        movdqa    %xmm10, %xmm11
        pand      %xmm13, %xmm7
        pxor      %xmm8, %xmm11
        movdqa    %xmm0, %xmm14
        paddd     %xmm15, %xmm1
        pxor      %xmm6, %xmm7
        pand      %xmm2, %xmm11
        pxor      %xmm4, %xmm14
        paddd     %xmm15, %xmm3
        paddd     %xmm7, %xmm1
        movdqa    48(%rdi), %xmm7
        pxor      %xmm8, %xmm11
        pand      %xmm12, %xmm14
        paddd     %xmm11, %xmm3
        movdqa    304(%rdi), %xmm11
        paddd     %xmm7, %xmm1
        pxor      %xmm4, %xmm14
        paddd     %xmm15, %xmm5
        movdqa    %xmm7, 784(%rsp)
        paddd     %xmm11, %xmm3
        movdqa    %xmm11, 768(%rsp)
        paddd     %xmm14, %xmm5
        movdqa    560(%rdi), %xmm7
        movdqa    %xmm1, %xmm11
        paddd     %xmm7, %xmm5
        pslld     $19, %xmm11
        psrld     $13, %xmm1
        movdqa    %xmm3, %xmm14
        por       %xmm1, %xmm11
        movdqa    %xmm5, %xmm1
        pslld     $19, %xmm1
        psrld     $13, %xmm5
        por       %xmm5, %xmm1
        movdqa    %xmm13, %xmm5
        pxor      %xmm9, %xmm5
        paddd     %xmm15, %xmm6
        pand      %xmm11, %xmm5
        pslld     $19, %xmm14
        pxor      %xmm9, %xmm5
        psrld     $13, %xmm3
        paddd     %xmm5, %xmm6
        por       %xmm3, %xmm14
        movdqa    64(%rdi), %xmm5
        movdqa    %xmm2, %xmm3
        movdqa    %xmm5, 1104(%rsp)
        paddd     %xmm5, %xmm6
        movdqa    %xmm12, %xmm5
        pxor      %xmm10, %xmm3
        pxor      %xmm0, %xmm5
        pand      %xmm14, %xmm3
        pand      %xmm1, %xmm5
        paddd     %xmm15, %xmm8
        pxor      %xmm10, %xmm3
        pxor      %xmm0, %xmm5
        paddd     %xmm15, %xmm4
        paddd     %xmm3, %xmm8
        movdqa    %xmm7, 1008(%rsp)
        paddd     %xmm5, %xmm4
        movdqa    320(%rdi), %xmm7
        movdqa    %xmm6, %xmm5
        paddd     %xmm7, %xmm8
        pslld     $3, %xmm5
        psrld     $29, %xmm6
        paddd     %xmm15, %xmm9
        por       %xmm6, %xmm5
        movdqa    %xmm8, %xmm6
        movdqa    576(%rdi), %xmm3
        pslld     $3, %xmm6
        psrld     $29, %xmm8
        paddd     %xmm3, %xmm4
        por       %xmm8, %xmm6
        movdqa    %xmm11, %xmm8
        movdqa    %xmm7, 1120(%rsp)
        movdqa    %xmm4, %xmm7
        pxor      %xmm13, %xmm8
        pslld     $3, %xmm7
        movdqa    %xmm3, 1424(%rsp)
        psrld     $29, %xmm4
        movdqa    %xmm1, %xmm3
        pand      %xmm5, %xmm8
        por       %xmm4, %xmm7
        movdqa    %xmm14, %xmm4
        pxor      %xmm12, %xmm3
        pxor      %xmm13, %xmm8
        pxor      %xmm2, %xmm4
        pand      %xmm7, %xmm3
        paddd     %xmm8, %xmm9
        pand      %xmm6, %xmm4
        movdqa    80(%rdi), %xmm8
        pxor      %xmm12, %xmm3
        paddd     %xmm15, %xmm0
        paddd     %xmm15, %xmm10
        movdqa    %xmm8, 864(%rsp)
        pxor      %xmm2, %xmm4
        paddd     %xmm8, %xmm9
        paddd     %xmm3, %xmm0
        movdqa    592(%rdi), %xmm8
        paddd     %xmm4, %xmm10
        movdqa    336(%rdi), %xmm4
        paddd     %xmm8, %xmm0
        movdqa    %xmm8, 1184(%rsp)
        movdqa    %xmm9, %xmm8
        paddd     %xmm4, %xmm10
        pslld     $7, %xmm8
        psrld     $25, %xmm9
        movdqa    %xmm7, %xmm3
        por       %xmm9, %xmm8
        movdqa    %xmm10, %xmm9
        pslld     $7, %xmm9
        psrld     $25, %xmm10
        por       %xmm10, %xmm9
        movdqa    %xmm5, %xmm10
        movdqa    %xmm4, 880(%rsp)
        movdqa    %xmm0, %xmm4
        pxor      %xmm11, %xmm10
        pslld     $7, %xmm4
        psrld     $25, %xmm0
        pand      %xmm8, %xmm10
        por       %xmm0, %xmm4
        movdqa    %xmm6, %xmm0
        pxor      %xmm1, %xmm3
        paddd     %xmm15, %xmm13
        pxor      %xmm11, %xmm10
        pxor      %xmm14, %xmm0
        pand      %xmm4, %xmm3
        paddd     %xmm10, %xmm13
        movdqa    96(%rdi), %xmm10
        pand      %xmm9, %xmm0
        pxor      %xmm1, %xmm3
        paddd     %xmm15, %xmm12
        movdqa    %xmm10, 1024(%rsp)
        paddd     %xmm15, %xmm2
        pxor      %xmm14, %xmm0
        paddd     %xmm10, %xmm13
        movdqa    608(%rdi), %xmm10
        paddd     %xmm3, %xmm12
        movdqa    %xmm10, 1248(%rsp)
        paddd     %xmm0, %xmm2
        movdqa    352(%rdi), %xmm0
        paddd     %xmm10, %xmm12
        movdqa    %xmm13, %xmm10
        paddd     %xmm0, %xmm2
        pslld     $11, %xmm10
        psrld     $21, %xmm13
        por       %xmm13, %xmm10
        movdqa    %xmm2, %xmm13
        pslld     $11, %xmm13
        psrld     $21, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm8, %xmm2
        movdqa    %xmm0, 1040(%rsp)
        movdqa    %xmm12, %xmm0
        pxor      %xmm5, %xmm2
        pslld     $11, %xmm0
        psrld     $21, %xmm12
        movdqa    %xmm4, %xmm3
        pand      %xmm10, %xmm2
        por       %xmm12, %xmm0
        pxor      %xmm7, %xmm3
        paddd     %xmm15, %xmm11
        pxor      %xmm5, %xmm2
        pand      %xmm0, %xmm3
        paddd     %xmm2, %xmm11
        pxor      %xmm7, %xmm3
        movdqa    112(%rdi), %xmm2
        paddd     %xmm15, %xmm1
        movdqa    %xmm2, 832(%rsp)
        paddd     %xmm2, %xmm11
        movdqa    624(%rdi), %xmm2
        paddd     %xmm3, %xmm1
        paddd     %xmm2, %xmm1
        movdqa    %xmm9, %xmm12
        movdqa    %xmm1, %xmm3
        pxor      %xmm6, %xmm12
        movdqa    %xmm2, 1056(%rsp)
        movdqa    %xmm11, %xmm2
        pslld     $19, %xmm3
        psrld     $13, %xmm1
        pand      %xmm13, %xmm12
        pslld     $19, %xmm2
        psrld     $13, %xmm11
        por       %xmm1, %xmm3
        movdqa    %xmm10, %xmm1
        paddd     %xmm15, %xmm14
        pxor      %xmm6, %xmm12
        por       %xmm11, %xmm2
        pxor      %xmm8, %xmm1
        paddd     %xmm12, %xmm14
        movdqa    368(%rdi), %xmm12
        pand      %xmm2, %xmm1
        paddd     %xmm12, %xmm14
        paddd     %xmm15, %xmm5
        pxor      %xmm8, %xmm1
        movdqa    %xmm13, %xmm11
        movdqa    %xmm12, 848(%rsp)
        movdqa    %xmm14, %xmm12
        paddd     %xmm1, %xmm5
        pslld     $19, %xmm12
        movdqa    128(%rdi), %xmm1
        psrld     $13, %xmm14
        movdqa    %xmm1, 1264(%rsp)
        paddd     %xmm1, %xmm5
        movdqa    %xmm0, %xmm1
        por       %xmm14, %xmm12
        pxor      %xmm9, %xmm11
        pxor      %xmm4, %xmm1
        pand      %xmm12, %xmm11
        pand      %xmm3, %xmm1
        paddd     %xmm15, %xmm6
        pxor      %xmm9, %xmm11
        pxor      %xmm4, %xmm1
        paddd     %xmm15, %xmm7
        movdqa    384(%rdi), %xmm14
        paddd     %xmm11, %xmm6
        paddd     %xmm1, %xmm7
        movdqa    %xmm5, %xmm1
        paddd     %xmm14, %xmm6
        pslld     $3, %xmm1
        psrld     $29, %xmm5
        paddd     %xmm15, %xmm8
        movdqa    640(%rdi), %xmm11
        por       %xmm5, %xmm1
        movdqa    %xmm6, %xmm5
        paddd     %xmm11, %xmm7
        pslld     $3, %xmm5
        psrld     $29, %xmm6
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        pslld     $3, %xmm6
        psrld     $29, %xmm7
        movdqa    %xmm11, 1504(%rsp)
        por       %xmm7, %xmm6
        movdqa    %xmm2, %xmm7
        movdqa    %xmm12, %xmm11
        pxor      %xmm10, %xmm7
        pxor      %xmm13, %xmm11
        pand      %xmm1, %xmm7
        pand      %xmm5, %xmm11
        paddd     %xmm15, %xmm9
        pxor      %xmm10, %xmm7
        pxor      %xmm13, %xmm11
        paddd     %xmm7, %xmm8
        movdqa    %xmm14, 1280(%rsp)
        paddd     %xmm11, %xmm9
        movdqa    144(%rdi), %xmm14
        movdqa    %xmm3, %xmm11
        movdqa    400(%rdi), %xmm7
        paddd     %xmm14, %xmm8
        pxor      %xmm0, %xmm11
        paddd     %xmm7, %xmm9
        movdqa    %xmm7, 976(%rsp)
        pand      %xmm6, %xmm11
        movdqa    %xmm8, %xmm7
        pxor      %xmm0, %xmm11
        paddd     %xmm15, %xmm4
        pslld     $7, %xmm7
        psrld     $25, %xmm8
        paddd     %xmm11, %xmm4
        movdqa    %xmm14, 960(%rsp)
        por       %xmm8, %xmm7
        movdqa    656(%rdi), %xmm14
        movdqa    %xmm9, %xmm8
        paddd     %xmm14, %xmm4
        pslld     $7, %xmm8
        psrld     $25, %xmm9
        paddd     %xmm15, %xmm10
        por       %xmm9, %xmm8
        movdqa    %xmm4, %xmm9
        pslld     $7, %xmm9
        psrld     $25, %xmm4
        por       %xmm4, %xmm9
        movdqa    %xmm1, %xmm4
        pxor      %xmm2, %xmm4
        movdqa    %xmm5, %xmm11
        pand      %xmm7, %xmm4
        pxor      %xmm12, %xmm11
        pxor      %xmm2, %xmm4
        pand      %xmm8, %xmm11
        paddd     %xmm4, %xmm10
        paddd     %xmm15, %xmm13
        movdqa    160(%rdi), %xmm4
        pxor      %xmm12, %xmm11
        movdqa    %xmm4, 1216(%rsp)
        paddd     %xmm4, %xmm10
        movdqa    %xmm6, %xmm4
        paddd     %xmm15, %xmm0
        pxor      %xmm3, %xmm4
        paddd     %xmm11, %xmm13
        pand      %xmm9, %xmm4
        paddd     %xmm15, %xmm2
        pxor      %xmm3, %xmm4
        paddd     %xmm15, %xmm12
        movdqa    %xmm14, 1312(%rsp)
        paddd     %xmm4, %xmm0
        movdqa    416(%rdi), %xmm14
        movdqa    %xmm10, %xmm4
        paddd     %xmm14, %xmm13
        pslld     $11, %xmm4
        psrld     $21, %xmm10
        paddd     %xmm15, %xmm3
        movdqa    672(%rdi), %xmm11
        por       %xmm10, %xmm4
        movdqa    %xmm13, %xmm10
        paddd     %xmm11, %xmm0
        pslld     $11, %xmm10
        psrld     $21, %xmm13
        por       %xmm13, %xmm10
        movdqa    %xmm0, %xmm13
        pslld     $11, %xmm13
        psrld     $21, %xmm0
        por       %xmm0, %xmm13
        movdqa    %xmm7, %xmm0
        pxor      %xmm1, %xmm0
        pand      %xmm4, %xmm0
        pxor      %xmm1, %xmm0
        paddd     %xmm15, %xmm1
        paddd     %xmm0, %xmm2
        movdqa    176(%rdi), %xmm0
        movdqa    %xmm11, 1408(%rsp)
        movdqa    %xmm8, %xmm11
        movdqa    %xmm0, 928(%rsp)
        paddd     %xmm0, %xmm2
        movdqa    %xmm9, %xmm0
        pxor      %xmm5, %xmm11
        pxor      %xmm6, %xmm0
        pand      %xmm10, %xmm11
        pand      %xmm13, %xmm0
        pxor      %xmm5, %xmm11
        pxor      %xmm6, %xmm0
        paddd     %xmm11, %xmm12
        movdqa    %xmm14, 1232(%rsp)
        paddd     %xmm0, %xmm3
        movdqa    432(%rdi), %xmm14
        movdqa    %xmm2, %xmm0
        paddd     %xmm14, %xmm12
        pslld     $19, %xmm0
        psrld     $13, %xmm2
        paddd     %xmm15, %xmm5
        movdqa    688(%rdi), %xmm11
        por       %xmm2, %xmm0
        movdqa    %xmm12, %xmm2
        paddd     %xmm11, %xmm3
        pslld     $19, %xmm2
        psrld     $13, %xmm12
        por       %xmm12, %xmm2
        movdqa    %xmm3, %xmm12
        pslld     $19, %xmm12
        psrld     $13, %xmm3
        por       %xmm3, %xmm12
        movdqa    %xmm4, %xmm3
        pxor      %xmm7, %xmm3
        paddd     %xmm15, %xmm6
        pand      %xmm0, %xmm3
        pxor      %xmm7, %xmm3
        paddd     %xmm3, %xmm1
        movdqa    192(%rdi), %xmm3
        movdqa    %xmm11, 1328(%rsp)
        movdqa    %xmm10, %xmm11
        movdqa    %xmm3, 1376(%rsp)
        paddd     %xmm3, %xmm1
        movdqa    %xmm13, %xmm3
        pxor      %xmm8, %xmm11
        pxor      %xmm9, %xmm3
        pand      %xmm2, %xmm11
        pand      %xmm12, %xmm3
        pxor      %xmm8, %xmm11
        pxor      %xmm9, %xmm3
        paddd     %xmm11, %xmm5
        movdqa    %xmm14, 944(%rsp)
        paddd     %xmm3, %xmm6
        movdqa    448(%rdi), %xmm14
        movdqa    %xmm1, %xmm3
        paddd     %xmm14, %xmm5
        pslld     $3, %xmm3
        psrld     $29, %xmm1
        movdqa    704(%rdi), %xmm11
        por       %xmm1, %xmm3
        movdqa    %xmm5, %xmm1
        paddd     %xmm11, %xmm6
        movdqa    %xmm14, 1392(%rsp)
        pslld     $3, %xmm1
        movdqa    %xmm11, 1456(%rsp)
..B4.36:
        psrld     $29, %xmm5
        paddd     %xmm15, %xmm7
        por       %xmm5, %xmm1
        movdqa    %xmm6, %xmm5
        pslld     $3, %xmm5
        psrld     $29, %xmm6
        por       %xmm6, %xmm5
        movdqa    %xmm0, %xmm6
        pxor      %xmm4, %xmm6
        movdqa    %xmm2, %xmm14
        pand      %xmm3, %xmm6
        pxor      %xmm10, %xmm14
        pxor      %xmm4, %xmm6
        pand      %xmm1, %xmm14
        paddd     %xmm6, %xmm7
        paddd     %xmm15, %xmm8
        movdqa    208(%rdi), %xmm6
        pxor      %xmm10, %xmm14
        movdqa    %xmm6, 1152(%rsp)
        paddd     %xmm6, %xmm7
        movdqa    %xmm12, %xmm6
        paddd     %xmm15, %xmm9
        pxor      %xmm13, %xmm6
        paddd     %xmm14, %xmm8
        pand      %xmm5, %xmm6
        paddd     %xmm15, %xmm10
        pxor      %xmm13, %xmm6
        paddd     %xmm15, %xmm4
        movdqa    720(%rdi), %xmm14
        paddd     %xmm6, %xmm9
        movdqa    464(%rdi), %xmm11
        paddd     %xmm14, %xmm9
        movdqa    %xmm7, %xmm6
        paddd     %xmm11, %xmm8
        movdqa    %xmm14, 1440(%rsp)
        pslld     $7, %xmm6
        psrld     $25, %xmm7
        movdqa    %xmm9, %xmm14
        por       %xmm7, %xmm6
        movdqa    %xmm8, %xmm7
        pslld     $7, %xmm14
        psrld     $25, %xmm9
        pslld     $7, %xmm7
        psrld     $25, %xmm8
        por       %xmm9, %xmm14
        movdqa    %xmm2, %xmm9
        por       %xmm8, %xmm7
        pxor      %xmm1, %xmm9
        pand      %xmm7, %xmm9
        movdqa    %xmm3, %xmm8
        pxor      %xmm2, %xmm9
        pxor      %xmm0, %xmm8
        paddd     %xmm9, %xmm10
        movdqa    %xmm12, %xmm9
        pand      %xmm6, %xmm8
        pxor      %xmm5, %xmm9
        movdqa    %xmm11, 1168(%rsp)
        pxor      %xmm0, %xmm8
        movdqa    480(%rdi), %xmm11
        pand      %xmm14, %xmm9
        paddd     %xmm8, %xmm4
        paddd     %xmm11, %xmm10
        movdqa    224(%rdi), %xmm8
        pxor      %xmm12, %xmm9
        paddd     %xmm15, %xmm13
        paddd     %xmm8, %xmm4
        movdqa    %xmm8, 1344(%rsp)
        paddd     %xmm9, %xmm13
        movdqa    736(%rdi), %xmm8
        movdqa    %xmm10, %xmm9
        movdqa    %xmm8, 1472(%rsp)
        paddd     %xmm8, %xmm13
        movdqa    %xmm4, %xmm8
        pslld     $11, %xmm9
        psrld     $21, %xmm10
        pslld     $11, %xmm8
        psrld     $21, %xmm4
        por       %xmm10, %xmm9
        movdqa    %xmm3, %xmm10
        por       %xmm4, %xmm8
        pxor      %xmm6, %xmm10
        paddd     %xmm15, %xmm0
        movdqa    %xmm11, 1360(%rsp)
        movdqa    %xmm13, %xmm11
        pand      %xmm8, %xmm10
        pslld     $11, %xmm11
        psrld     $21, %xmm13
        pxor      %xmm3, %xmm10
        por       %xmm13, %xmm11
        paddd     %xmm10, %xmm0
        movdqa    240(%rdi), %xmm10
        movdqa    %xmm7, %xmm13
        movdqa    %xmm10, 1088(%rsp)
        pxor      %xmm1, %xmm13
        paddd     %xmm10, %xmm0
        movdqa    %xmm14, %xmm10
        pand      %xmm9, %xmm13
        pxor      %xmm5, %xmm10
        paddd     %xmm15, %xmm2
        pxor      %xmm1, %xmm13
        pand      %xmm11, %xmm10
        paddd     %xmm13, %xmm2
        movdqa    496(%rdi), %xmm4
        pxor      %xmm5, %xmm10
        paddd     %xmm12, %xmm15
        paddd     %xmm4, %xmm2
        movdqa    752(%rdi), %xmm13
        paddd     %xmm10, %xmm15
        movdqa    %xmm0, %xmm12
        paddd     %xmm13, %xmm15
        movdqa    %xmm13, 1488(%rsp)
        pslld     $19, %xmm12
        psrld     $13, %xmm0
        movdqa    %xmm2, %xmm13
        por       %xmm0, %xmm12
        pslld     $19, %xmm13
        psrld     $13, %xmm2
        movdqa    %xmm8, %xmm0
        por       %xmm2, %xmm13
        por       %xmm6, %xmm0
        movdqa    %xmm8, %xmm2
        pand      %xmm12, %xmm0
        movdqa    %xmm4, 1200(%rsp)
        movdqa    %xmm15, %xmm4
        pand      %xmm6, %xmm2
        pslld     $19, %xmm4
        psrld     $13, %xmm15
        por       %xmm2, %xmm0
        movdqa    %xmm9, %xmm2
        por       %xmm15, %xmm4
        por       %xmm7, %xmm2
        movdqa    %xmm9, %xmm15
        movdqa    .L_2il0floatpacket.522(%rip), %xmm10
        pand      %xmm13, %xmm2
        pand      %xmm7, %xmm15
        paddd     %xmm10, %xmm1
        por       %xmm15, %xmm2
        paddd     %xmm10, %xmm3
        paddd     %xmm2, %xmm1
        movdqa    %xmm11, %xmm2
        paddd     %xmm0, %xmm3
        por       %xmm14, %xmm2
        movdqa    %xmm11, %xmm0
        pand      %xmm4, %xmm2
        pand      %xmm14, %xmm0
        paddd     %xmm10, %xmm5
        por       %xmm0, %xmm2
        paddd     %xmm10, %xmm7
        paddd     1072(%rsp), %xmm3
        paddd     %xmm2, %xmm5
        paddd     1520(%rsp), %xmm5
        movdqa    %xmm3, %xmm0
        pslld     $3, %xmm0
        psrld     $29, %xmm3
        movdqa    %xmm5, %xmm2
        por       %xmm3, %xmm0
        pslld     $3, %xmm2
        psrld     $29, %xmm5
        movdqa    %xmm12, %xmm3
        por       %xmm5, %xmm2
        paddd     1136(%rsp), %xmm1
        por       %xmm8, %xmm3
        movdqa    %xmm12, %xmm5
        movdqa    %xmm1, %xmm15
        pand      %xmm0, %xmm3
        pand      %xmm8, %xmm5
        pslld     $3, %xmm15
        psrld     $29, %xmm1
        por       %xmm5, %xmm3
        movdqa    %xmm13, %xmm5
        por       %xmm1, %xmm15
        por       %xmm9, %xmm5
        movdqa    %xmm13, %xmm1
        pand      %xmm15, %xmm5
        pand      %xmm9, %xmm1
        paddd     %xmm10, %xmm6
        por       %xmm1, %xmm5
        paddd     %xmm3, %xmm6
        paddd     %xmm5, %xmm7
        movdqa    %xmm4, %xmm5
        por       %xmm11, %xmm5
        movdqa    %xmm4, %xmm3
        pand      %xmm2, %xmm5
        pand      %xmm11, %xmm3
        paddd     1104(%rsp), %xmm6
        por       %xmm3, %xmm5
        paddd     %xmm10, %xmm14
        movdqa    %xmm6, %xmm3
        paddd     1120(%rsp), %xmm7
        paddd     %xmm5, %xmm14
        paddd     1424(%rsp), %xmm14
        pslld     $5, %xmm3
        psrld     $27, %xmm6
        movdqa    %xmm7, %xmm5
        por       %xmm6, %xmm3
        pslld     $5, %xmm5
        psrld     $27, %xmm7
        movdqa    %xmm14, %xmm6
        por       %xmm7, %xmm5
        pslld     $5, %xmm6
        psrld     $27, %xmm14
        movdqa    %xmm0, %xmm7
        por       %xmm14, %xmm6
        por       %xmm12, %xmm7
        movdqa    %xmm0, %xmm14
        pand      %xmm3, %xmm7
        pand      %xmm12, %xmm14
        movdqa    %xmm15, %xmm1
        por       %xmm14, %xmm7
        movdqa    %xmm15, %xmm14
        por       %xmm13, %xmm14
        pand      %xmm13, %xmm1
        pand      %xmm5, %xmm14
        paddd     %xmm10, %xmm9
        por       %xmm1, %xmm14
        paddd     %xmm10, %xmm8
        paddd     %xmm14, %xmm9
        movdqa    %xmm2, %xmm14
        paddd     %xmm7, %xmm8
        por       %xmm4, %xmm14
        movdqa    %xmm2, %xmm7
        pand      %xmm6, %xmm14
        pand      %xmm4, %xmm7
        paddd     %xmm10, %xmm11
        paddd     1264(%rsp), %xmm8
        por       %xmm7, %xmm14
        paddd     1280(%rsp), %xmm9
        paddd     %xmm14, %xmm11
        movdqa    %xmm8, %xmm14
        psrld     $23, %xmm8
        paddd     1504(%rsp), %xmm11
        pslld     $9, %xmm14
        movdqa    %xmm9, %xmm7
        por       %xmm8, %xmm14
        pslld     $9, %xmm7
        psrld     $23, %xmm9
        movdqa    %xmm11, %xmm8
        por       %xmm9, %xmm7
        pslld     $9, %xmm8
        psrld     $23, %xmm11
        movdqa    %xmm3, %xmm9
        por       %xmm11, %xmm8
        por       %xmm0, %xmm9
        movdqa    %xmm3, %xmm11
        pand      %xmm14, %xmm9
        pand      %xmm0, %xmm11
        por       %xmm11, %xmm9
        movdqa    %xmm5, %xmm11
        por       %xmm15, %xmm11
        movdqa    %xmm5, %xmm1
        pand      %xmm7, %xmm11
        pand      %xmm15, %xmm1
        paddd     %xmm10, %xmm13
        por       %xmm1, %xmm11
        paddd     %xmm10, %xmm12
        paddd     %xmm11, %xmm13
        movdqa    %xmm6, %xmm11
        paddd     %xmm9, %xmm12
        por       %xmm2, %xmm11
        movdqa    %xmm6, %xmm9
        pand      %xmm8, %xmm11
        pand      %xmm2, %xmm9
        paddd     1376(%rsp), %xmm12
        por       %xmm9, %xmm11
        paddd     %xmm10, %xmm4
        movdqa    %xmm12, %xmm9
        paddd     1392(%rsp), %xmm13
        paddd     %xmm11, %xmm4
        paddd     1456(%rsp), %xmm4
        pslld     $13, %xmm9
        psrld     $19, %xmm12
        movdqa    %xmm13, %xmm11
        por       %xmm12, %xmm9
        pslld     $13, %xmm11
        psrld     $19, %xmm13
        movdqa    %xmm4, %xmm12
        por       %xmm13, %xmm11
        pslld     $13, %xmm12
        psrld     $19, %xmm4
        movdqa    %xmm14, %xmm13
        por       %xmm4, %xmm12
        por       %xmm3, %xmm13
        movdqa    %xmm14, %xmm4
        pand      %xmm9, %xmm13
        pand      %xmm3, %xmm4
        movdqa    %xmm7, %xmm1
        por       %xmm4, %xmm13
        movdqa    %xmm7, %xmm4
        por       %xmm5, %xmm4
        pand      %xmm5, %xmm1
        pand      %xmm11, %xmm4
        paddd     %xmm10, %xmm15
        por       %xmm1, %xmm4
        paddd     %xmm10, %xmm0
        paddd     %xmm4, %xmm15
        movdqa    %xmm8, %xmm4
        paddd     %xmm13, %xmm0
        por       %xmm6, %xmm4
        movdqa    %xmm8, %xmm13
        pand      %xmm12, %xmm4
        pand      %xmm6, %xmm13
        paddd     %xmm10, %xmm2
        por       %xmm13, %xmm4
        paddd     %xmm10, %xmm3
        paddd     800(%rsp), %xmm0
        paddd     %xmm4, %xmm2
        paddd     992(%rsp), %xmm2
        movdqa    %xmm0, %xmm13
        paddd     816(%rsp), %xmm15
        pslld     $3, %xmm13
        psrld     $29, %xmm0
        movdqa    %xmm2, %xmm1
        por       %xmm0, %xmm13
        movdqa    %xmm15, %xmm0
        pslld     $3, %xmm1
        psrld     $29, %xmm2
        pslld     $3, %xmm0
        psrld     $29, %xmm15
        por       %xmm2, %xmm1
        movdqa    %xmm9, %xmm2
        por       %xmm15, %xmm0
        por       %xmm14, %xmm2
        movdqa    %xmm9, %xmm15
        pand      %xmm13, %xmm2
        pand      %xmm14, %xmm15
        movdqa    %xmm11, %xmm4
        por       %xmm15, %xmm2
        movdqa    %xmm11, %xmm15
        por       %xmm7, %xmm15
        pand      %xmm7, %xmm4
        pand      %xmm0, %xmm15
        paddd     %xmm2, %xmm3
        por       %xmm4, %xmm15
        movdqa    %xmm12, %xmm4
        por       %xmm8, %xmm4
        movdqa    %xmm12, %xmm2
        paddd     864(%rsp), %xmm3
        paddd     %xmm10, %xmm5
        pand      %xmm1, %xmm4
        pand      %xmm8, %xmm2
        paddd     %xmm15, %xmm5
        por       %xmm2, %xmm4
        paddd     %xmm10, %xmm6
        movdqa    %xmm3, %xmm2
        paddd     880(%rsp), %xmm5
        paddd     %xmm4, %xmm6
        pslld     $5, %xmm2
        psrld     $27, %xmm3
        paddd     1184(%rsp), %xmm6
        por       %xmm3, %xmm2
        movdqa    %xmm5, %xmm3
        psrld     $27, %xmm5
        pslld     $5, %xmm3
        movdqa    %xmm6, %xmm4
        por       %xmm5, %xmm3
        pslld     $5, %xmm4
        psrld     $27, %xmm6
        movdqa    %xmm13, %xmm5
        por       %xmm6, %xmm4
        por       %xmm9, %xmm5
        movdqa    %xmm13, %xmm6
        pand      %xmm2, %xmm5
        pand      %xmm9, %xmm6
        movdqa    %xmm0, %xmm15
        por       %xmm6, %xmm5
        movdqa    %xmm0, %xmm6
        por       %xmm11, %xmm6
        pand      %xmm11, %xmm15
        pand      %xmm3, %xmm6
        paddd     %xmm10, %xmm7
        por       %xmm15, %xmm6
        paddd     %xmm10, %xmm14
        paddd     %xmm6, %xmm7
        movdqa    %xmm1, %xmm6
        paddd     %xmm5, %xmm14
        por       %xmm12, %xmm6
        movdqa    %xmm1, %xmm5
        pand      %xmm4, %xmm6
        pand      %xmm12, %xmm5
        paddd     %xmm10, %xmm8
        paddd     976(%rsp), %xmm7
        por       %xmm5, %xmm6
        paddd     960(%rsp), %xmm14
        paddd     %xmm6, %xmm8
        movdqa    %xmm7, %xmm6
        movdqa    %xmm14, %xmm5
        paddd     1312(%rsp), %xmm8
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        pslld     $9, %xmm5
        psrld     $23, %xmm14
        por       %xmm7, %xmm6
        movdqa    %xmm8, %xmm7
        por       %xmm14, %xmm5
        pslld     $9, %xmm7
        psrld     $23, %xmm8
        movdqa    %xmm2, %xmm14
        por       %xmm8, %xmm7
        por       %xmm13, %xmm14
        movdqa    %xmm2, %xmm8
        pand      %xmm5, %xmm14
        pand      %xmm13, %xmm8
        por       %xmm8, %xmm14
        movdqa    %xmm3, %xmm8
        por       %xmm0, %xmm8
        movdqa    %xmm3, %xmm15
        pand      %xmm6, %xmm8
        pand      %xmm0, %xmm15
        paddd     %xmm10, %xmm11
        por       %xmm15, %xmm8
        paddd     %xmm10, %xmm9
        paddd     %xmm8, %xmm11
        movdqa    %xmm4, %xmm8
        paddd     %xmm14, %xmm9
        por       %xmm1, %xmm8
        movdqa    %xmm4, %xmm14
        pand      %xmm7, %xmm8
        pand      %xmm1, %xmm14
        paddd     208(%rdi), %xmm9
        por       %xmm14, %xmm8
        paddd     %xmm10, %xmm12
        movdqa    %xmm6, %xmm15
        paddd     %xmm8, %xmm12
        movdqa    %xmm9, %xmm8
        paddd     464(%rdi), %xmm11
        pslld     $13, %xmm8
        psrld     $19, %xmm9
        pand      %xmm3, %xmm15
        paddd     720(%rdi), %xmm12
        por       %xmm9, %xmm8
        movdqa    %xmm11, %xmm9
        psrld     $19, %xmm11
        pslld     $13, %xmm9
        movdqa    %xmm12, %xmm14
        por       %xmm11, %xmm9
        pslld     $13, %xmm14
        psrld     $19, %xmm12
        movdqa    %xmm5, %xmm11
        por       %xmm12, %xmm14
        por       %xmm2, %xmm11
        movdqa    %xmm5, %xmm12
        pand      %xmm8, %xmm11
        pand      %xmm2, %xmm12
        paddd     %xmm10, %xmm0
        por       %xmm12, %xmm11
        movdqa    %xmm6, %xmm12
        por       %xmm3, %xmm12
        paddd     %xmm10, %xmm13
        pand      %xmm9, %xmm12
        paddd     %xmm11, %xmm13
        por       %xmm15, %xmm12
        movdqa    %xmm7, %xmm11
        paddd     %xmm12, %xmm0
        movdqa    %xmm7, %xmm12
        por       %xmm4, %xmm12
        pand      %xmm4, %xmm11
        pand      %xmm14, %xmm12
        paddd     %xmm10, %xmm1
        paddd     896(%rsp), %xmm13
        por       %xmm11, %xmm12
        paddd     %xmm12, %xmm1
        movdqa    %xmm13, %xmm12
        paddd     1296(%rsp), %xmm1
        pslld     $3, %xmm12
        psrld     $29, %xmm13
        movdqa    %xmm9, %xmm15
        paddd     912(%rsp), %xmm0
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm13
        movdqa    %xmm0, %xmm11
        pslld     $3, %xmm13
        psrld     $29, %xmm1
        pslld     $3, %xmm11
        psrld     $29, %xmm0
        por       %xmm1, %xmm13
        movdqa    %xmm8, %xmm1
        por       %xmm0, %xmm11
        por       %xmm5, %xmm1
        movdqa    %xmm8, %xmm0
        pand      %xmm12, %xmm1
        pand      %xmm5, %xmm0
        pand      %xmm6, %xmm15
        por       %xmm0, %xmm1
        movdqa    %xmm9, %xmm0
        por       %xmm6, %xmm0
        paddd     %xmm10, %xmm3
        pand      %xmm11, %xmm0
        paddd     %xmm10, %xmm2
        por       %xmm15, %xmm0
        paddd     %xmm1, %xmm2
        paddd     %xmm0, %xmm3
        movdqa    %xmm14, %xmm0
        por       %xmm7, %xmm0
        movdqa    %xmm14, %xmm1
        pand      %xmm13, %xmm0
        pand      %xmm7, %xmm1
        paddd     1024(%rsp), %xmm2
        por       %xmm1, %xmm0
        paddd     1040(%rsp), %xmm3
        paddd     %xmm10, %xmm4
        paddd     %xmm0, %xmm4
        movdqa    %xmm2, %xmm1
        movdqa    %xmm3, %xmm0
        pslld     $5, %xmm1
        paddd     1248(%rsp), %xmm4
        psrld     $27, %xmm2
        pslld     $5, %xmm0
        psrld     $27, %xmm3
        por       %xmm2, %xmm1
        por       %xmm3, %xmm0
        movdqa    %xmm4, %xmm3
        movdqa    %xmm12, %xmm2
        pslld     $5, %xmm3
        psrld     $27, %xmm4
        por       %xmm8, %xmm2
        por       %xmm4, %xmm3
        paddd     %xmm10, %xmm5
        paddd     %xmm10, %xmm6
        pand      %xmm1, %xmm2
..B4.35:
        movdqa    %xmm12, %xmm4
        movdqa    %xmm11, %xmm15
        pand      %xmm8, %xmm4
        pand      %xmm9, %xmm15
        por       %xmm4, %xmm2
        movdqa    %xmm11, %xmm4
        por       %xmm9, %xmm4
        paddd     %xmm2, %xmm5
        pand      %xmm0, %xmm4
        movdqa    %xmm13, %xmm2
        por       %xmm15, %xmm4
        pand      %xmm14, %xmm2
        paddd     %xmm4, %xmm6
        movdqa    %xmm13, %xmm4
        por       %xmm14, %xmm4
        paddd     %xmm10, %xmm7
        paddd     1216(%rsp), %xmm5
        pand      %xmm3, %xmm4
        por       %xmm2, %xmm4
        movdqa    %xmm5, %xmm2
        paddd     1232(%rsp), %xmm6
        pslld     $9, %xmm2
        psrld     $23, %xmm5
        paddd     %xmm4, %xmm7
        por       %xmm5, %xmm2
        movdqa    %xmm6, %xmm5
        paddd     1408(%rsp), %xmm7
        pslld     $9, %xmm5
        psrld     $23, %xmm6
        movdqa    %xmm1, %xmm15
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        por       %xmm7, %xmm6
        movdqa    %xmm1, %xmm7
        por       %xmm12, %xmm7
        pand      %xmm12, %xmm15
        pand      %xmm2, %xmm7
        movdqa    %xmm0, %xmm4
        por       %xmm15, %xmm7
        movdqa    %xmm0, %xmm15
        por       %xmm11, %xmm15
        pand      %xmm11, %xmm4
        pand      %xmm5, %xmm15
        paddd     %xmm10, %xmm8
        por       %xmm4, %xmm15
        movdqa    %xmm3, %xmm4
        paddd     %xmm7, %xmm8
        por       %xmm13, %xmm4
        movdqa    %xmm3, %xmm7
        paddd     %xmm10, %xmm9
        paddd     1344(%rsp), %xmm8
        pand      %xmm6, %xmm4
        pand      %xmm13, %xmm7
        paddd     %xmm15, %xmm9
        por       %xmm7, %xmm4
        movdqa    %xmm8, %xmm7
        paddd     1360(%rsp), %xmm9
        paddd     %xmm10, %xmm14
        pslld     $13, %xmm7
        psrld     $19, %xmm8
        paddd     %xmm4, %xmm14
        por       %xmm8, %xmm7
        movdqa    %xmm9, %xmm8
        psrld     $19, %xmm9
        paddd     1472(%rsp), %xmm14
        pslld     $13, %xmm8
        por       %xmm9, %xmm8
        movdqa    %xmm14, %xmm9
        pslld     $13, %xmm9
        psrld     $19, %xmm14
        por       %xmm14, %xmm9
        movdqa    %xmm1, %xmm14
        por       %xmm2, %xmm14
        movdqa    %xmm1, %xmm15
        pand      %xmm7, %xmm14
        pand      %xmm2, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm0, %xmm15
        por       %xmm5, %xmm15
        movdqa    %xmm0, %xmm4
        pand      %xmm8, %xmm15
        pand      %xmm5, %xmm4
        paddd     %xmm10, %xmm12
        por       %xmm4, %xmm15
        movdqa    %xmm3, %xmm4
        paddd     %xmm14, %xmm12
        por       %xmm6, %xmm4
        movdqa    %xmm3, %xmm14
        paddd     784(%rsp), %xmm12
        paddd     %xmm10, %xmm11
        pand      %xmm9, %xmm4
        pand      %xmm6, %xmm14
        paddd     %xmm15, %xmm11
        por       %xmm14, %xmm4
        movdqa    %xmm12, %xmm14
        paddd     %xmm10, %xmm13
        paddd     768(%rsp), %xmm11
        pslld     $3, %xmm14
        psrld     $29, %xmm12
        paddd     %xmm4, %xmm13
        por       %xmm12, %xmm14
        movdqa    %xmm11, %xmm12
        paddd     1008(%rsp), %xmm13
        pslld     $3, %xmm12
        psrld     $29, %xmm11
        movdqa    %xmm7, %xmm15
        por       %xmm11, %xmm12
        movdqa    %xmm13, %xmm11
        pslld     $3, %xmm11
        psrld     $29, %xmm13
        por       %xmm13, %xmm11
        movdqa    %xmm7, %xmm13
        por       %xmm2, %xmm13
        pand      %xmm2, %xmm15
        pand      %xmm14, %xmm13
        movdqa    %xmm8, %xmm4
        por       %xmm15, %xmm13
        movdqa    %xmm8, %xmm15
        por       %xmm5, %xmm15
        pand      %xmm5, %xmm4
        pand      %xmm12, %xmm15
        paddd     %xmm10, %xmm1
        por       %xmm4, %xmm15
        movdqa    %xmm9, %xmm4
        paddd     %xmm13, %xmm1
        por       %xmm6, %xmm4
        movdqa    %xmm9, %xmm13
        pand      %xmm11, %xmm4
        pand      %xmm6, %xmm13
        paddd     %xmm10, %xmm3
        por       %xmm13, %xmm4
        paddd     %xmm10, %xmm0
        paddd     832(%rsp), %xmm1
        paddd     %xmm4, %xmm3
        paddd     1056(%rsp), %xmm3
        paddd     %xmm15, %xmm0
        movdqa    %xmm1, %xmm13
        psrld     $27, %xmm1
        paddd     848(%rsp), %xmm0
        pslld     $5, %xmm13
        movdqa    %xmm3, %xmm4
        por       %xmm1, %xmm13
        movdqa    %xmm0, %xmm1
        pslld     $5, %xmm4
        psrld     $27, %xmm3
        pslld     $5, %xmm1
        psrld     $27, %xmm0
        por       %xmm3, %xmm4
        movdqa    %xmm14, %xmm3
        por       %xmm0, %xmm1
        por       %xmm7, %xmm3
        movdqa    %xmm14, %xmm0
        pand      %xmm13, %xmm3
        pand      %xmm7, %xmm0
        por       %xmm0, %xmm3
        movdqa    %xmm12, %xmm0
        por       %xmm8, %xmm0
        movdqa    %xmm12, %xmm15
        pand      %xmm1, %xmm0
        pand      %xmm8, %xmm15
        paddd     %xmm10, %xmm5
        por       %xmm15, %xmm0
        paddd     %xmm10, %xmm2
        paddd     %xmm0, %xmm5
        movdqa    %xmm11, %xmm0
        paddd     %xmm3, %xmm2
        por       %xmm9, %xmm0
        movdqa    %xmm11, %xmm3
        pand      %xmm4, %xmm0
        pand      %xmm9, %xmm3
        paddd     944(%rsp), %xmm5
        por       %xmm3, %xmm0
        paddd     %xmm10, %xmm6
        movdqa    %xmm5, %xmm3
        paddd     928(%rsp), %xmm2
        paddd     %xmm0, %xmm6
        paddd     1328(%rsp), %xmm6
        movdqa    %xmm2, %xmm0
        pslld     $9, %xmm3
        psrld     $23, %xmm5
        pslld     $9, %xmm0
        psrld     $23, %xmm2
        por       %xmm5, %xmm3
        movdqa    %xmm6, %xmm5
        por       %xmm2, %xmm0
        pslld     $9, %xmm5
        psrld     $23, %xmm6
        movdqa    %xmm13, %xmm2
        por       %xmm6, %xmm5
        por       %xmm14, %xmm2
        movdqa    %xmm13, %xmm6
        pand      %xmm0, %xmm2
        pand      %xmm14, %xmm6
        movdqa    %xmm1, %xmm15
        por       %xmm6, %xmm2
        movdqa    %xmm1, %xmm6
        por       %xmm12, %xmm6
        pand      %xmm12, %xmm15
        pand      %xmm3, %xmm6
        paddd     %xmm10, %xmm8
        por       %xmm15, %xmm6
        paddd     %xmm10, %xmm7
        paddd     %xmm6, %xmm8
        movdqa    %xmm4, %xmm6
        paddd     %xmm2, %xmm7
        por       %xmm11, %xmm6
        movdqa    %xmm4, %xmm2
        pand      %xmm5, %xmm6
        pand      %xmm11, %xmm2
        paddd     %xmm9, %xmm10
        paddd     1200(%rsp), %xmm8
        por       %xmm2, %xmm6
        paddd     %xmm6, %xmm10
        movdqa    %xmm8, %xmm15
        paddd     1488(%rsp), %xmm10
        pslld     $13, %xmm15
        psrld     $19, %xmm8
        movdqa    %xmm5, %xmm6
        paddd     1088(%rsp), %xmm7
        por       %xmm8, %xmm15
        movdqa    %xmm10, %xmm8
        movdqa    %xmm7, %xmm9
        pslld     $13, %xmm8
        psrld     $19, %xmm10
        movdqa    .L_2il0floatpacket.523(%rip), %xmm2
        pslld     $13, %xmm9
        psrld     $19, %xmm7
        por       %xmm10, %xmm8
        movdqa    %xmm0, %xmm10
        pxor      %xmm4, %xmm6
        por       %xmm7, %xmm9
        pxor      %xmm13, %xmm10
        pxor      %xmm8, %xmm6
        paddd     %xmm2, %xmm11
        paddd     %xmm2, %xmm14
        pxor      %xmm9, %xmm10
        movdqa    %xmm3, %xmm7
        paddd     %xmm6, %xmm11
        paddd     1520(%rsp), %xmm11
        paddd     %xmm10, %xmm14
        pxor      %xmm1, %xmm7
        paddd     %xmm2, %xmm12
        paddd     1072(%rsp), %xmm14
        pxor      %xmm15, %xmm7
        movdqa    %xmm11, %xmm10
        paddd     %xmm7, %xmm12
        movdqa    %xmm14, %xmm7
        pslld     $3, %xmm10
        psrld     $29, %xmm11
        pslld     $3, %xmm7
        paddd     1136(%rsp), %xmm12
        psrld     $29, %xmm14
        por       %xmm11, %xmm10
        movdqa    %xmm9, %xmm11
        por       %xmm14, %xmm7
        movdqa    %xmm12, %xmm14
        pxor      %xmm0, %xmm11
        pslld     $3, %xmm14
        psrld     $29, %xmm12
        paddd     %xmm2, %xmm13
        pxor      %xmm7, %xmm11
        por       %xmm12, %xmm14
        paddd     %xmm11, %xmm13
        movdqa    %xmm15, %xmm12
        movdqa    %xmm8, %xmm11
        pxor      %xmm3, %xmm12
        pxor      %xmm5, %xmm11
        paddd     %xmm2, %xmm1
        paddd     1264(%rsp), %xmm13
        pxor      %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        paddd     %xmm2, %xmm4
        paddd     %xmm12, %xmm1
        paddd     %xmm11, %xmm4
        movdqa    %xmm13, %xmm11
        psrld     $23, %xmm13
        paddd     1280(%rsp), %xmm1
        pslld     $9, %xmm11
        por       %xmm13, %xmm11
        movdqa    %xmm1, %xmm13
        paddd     1504(%rsp), %xmm4
        pslld     $9, %xmm13
        psrld     $23, %xmm1
        paddd     %xmm2, %xmm0
        por       %xmm1, %xmm13
        movdqa    %xmm4, %xmm1
        pslld     $9, %xmm1
        psrld     $23, %xmm4
        por       %xmm4, %xmm1
        movdqa    %xmm7, %xmm4
        pxor      %xmm9, %xmm4
        movdqa    %xmm14, %xmm6
        pxor      %xmm11, %xmm4
        pxor      %xmm15, %xmm6
        paddd     %xmm4, %xmm0
        movdqa    %xmm10, %xmm4
        pxor      %xmm8, %xmm4
        paddd     %xmm2, %xmm3
        paddd     1104(%rsp), %xmm0
        pxor      %xmm13, %xmm6
        pxor      %xmm1, %xmm4
        paddd     %xmm2, %xmm5
        paddd     %xmm6, %xmm3
        paddd     %xmm4, %xmm5
        movdqa    %xmm0, %xmm4
        psrld     $21, %xmm0
        paddd     1120(%rsp), %xmm3
        pslld     $11, %xmm4
        por       %xmm0, %xmm4
        movdqa    %xmm3, %xmm0
        paddd     1424(%rsp), %xmm5
        pslld     $11, %xmm0
        psrld     $21, %xmm3
        paddd     %xmm2, %xmm9
        por       %xmm3, %xmm0
        movdqa    %xmm5, %xmm3
        pslld     $11, %xmm3
        psrld     $21, %xmm5
        por       %xmm5, %xmm3
        movdqa    %xmm11, %xmm5
        pxor      %xmm7, %xmm5
        movdqa    %xmm13, %xmm6
        pxor      %xmm4, %xmm5
        pxor      %xmm14, %xmm6
        paddd     %xmm5, %xmm9
        paddd     %xmm2, %xmm15
        paddd     1376(%rsp), %xmm9
        pxor      %xmm0, %xmm6
        movdqa    %xmm1, %xmm12
        paddd     %xmm6, %xmm15
        pxor      %xmm10, %xmm12
        movdqa    %xmm9, %xmm5
        paddd     1392(%rsp), %xmm15
        pxor      %xmm3, %xmm12
        paddd     %xmm2, %xmm8
        pslld     $15, %xmm5
        psrld     $17, %xmm9
        paddd     %xmm12, %xmm8
        por       %xmm9, %xmm5
        movdqa    %xmm15, %xmm9
        paddd     1456(%rsp), %xmm8
        pslld     $15, %xmm9
        psrld     $17, %xmm15
        movdqa    %xmm0, %xmm6
        por       %xmm15, %xmm9
        movdqa    %xmm8, %xmm15
        pslld     $15, %xmm15
        psrld     $17, %xmm8
        por       %xmm8, %xmm15
        movdqa    %xmm4, %xmm8
        pxor      %xmm13, %xmm6
        movdqa    %xmm3, %xmm12
        paddd     %xmm2, %xmm14
        pxor      %xmm11, %xmm8
        pxor      %xmm9, %xmm6
        pxor      %xmm1, %xmm12
        paddd     %xmm2, %xmm7
        pxor      %xmm5, %xmm8
        paddd     %xmm6, %xmm14
        pxor      %xmm15, %xmm12
        paddd     %xmm2, %xmm10
        paddd     %xmm8, %xmm7
        paddd     912(%rsp), %xmm14
        paddd     %xmm12, %xmm10
        paddd     896(%rsp), %xmm7
        movdqa    %xmm14, %xmm6
        paddd     1296(%rsp), %xmm10
        movdqa    %xmm7, %xmm8
        pslld     $3, %xmm6
        psrld     $29, %xmm14
        movdqa    %xmm10, %xmm12
        pslld     $3, %xmm8
        psrld     $29, %xmm7
        por       %xmm14, %xmm6
        pslld     $3, %xmm12
        psrld     $29, %xmm10
        movdqa    %xmm5, %xmm14
        por       %xmm7, %xmm8
        por       %xmm10, %xmm12
        pxor      %xmm4, %xmm14
        movdqa    %xmm9, %xmm7
        movdqa    %xmm15, %xmm10
        paddd     %xmm2, %xmm11
        pxor      %xmm8, %xmm14
        pxor      %xmm0, %xmm7
        pxor      %xmm3, %xmm10
        paddd     %xmm2, %xmm13
        paddd     %xmm14, %xmm11
        pxor      %xmm6, %xmm7
        pxor      %xmm12, %xmm10
        paddd     %xmm2, %xmm1
        paddd     %xmm7, %xmm13
        paddd     1216(%rsp), %xmm11
        paddd     %xmm10, %xmm1
        paddd     1232(%rsp), %xmm13
        movdqa    %xmm11, %xmm14
        paddd     1408(%rsp), %xmm1
        pslld     $9, %xmm14
        psrld     $23, %xmm11
        movdqa    %xmm13, %xmm10
        movdqa    %xmm1, %xmm7
        por       %xmm11, %xmm14
        pslld     $9, %xmm10
        psrld     $23, %xmm13
        pslld     $9, %xmm7
        psrld     $23, %xmm1
        movdqa    %xmm6, %xmm11
        por       %xmm13, %xmm10
        por       %xmm1, %xmm7
        movdqa    %xmm8, %xmm1
        pxor      %xmm9, %xmm11
        paddd     %xmm2, %xmm0
        pxor      %xmm5, %xmm1
        pxor      %xmm10, %xmm11
        movdqa    %xmm12, %xmm13
        paddd     %xmm2, %xmm4
        pxor      %xmm14, %xmm1
        paddd     %xmm11, %xmm0
        pxor      %xmm15, %xmm13
        paddd     %xmm1, %xmm4
        paddd     1040(%rsp), %xmm0
        pxor      %xmm7, %xmm13
        paddd     %xmm2, %xmm3
        movdqa    %xmm0, %xmm1
        paddd     1024(%rsp), %xmm4
        paddd     %xmm13, %xmm3
        paddd     1248(%rsp), %xmm3
        movdqa    %xmm4, %xmm11
        pslld     $11, %xmm1
        psrld     $21, %xmm0
        pslld     $11, %xmm11
        psrld     $21, %xmm4
        por       %xmm0, %xmm1
        movdqa    %xmm3, %xmm0
        por       %xmm4, %xmm11
        pslld     $11, %xmm0
        psrld     $21, %xmm3
        movdqa    %xmm10, %xmm4
        por       %xmm3, %xmm0
        movdqa    %xmm14, %xmm3
        pxor      %xmm6, %xmm4
        paddd     %xmm2, %xmm9
        pxor      %xmm8, %xmm3
        pxor      %xmm1, %xmm4
        paddd     %xmm2, %xmm5
        pxor      %xmm11, %xmm3
        paddd     %xmm4, %xmm9
        paddd     %xmm3, %xmm5
        paddd     1360(%rsp), %xmm9
        movdqa    %xmm7, %xmm3
        paddd     1344(%rsp), %xmm5
        movdqa    %xmm9, %xmm4
        movdqa    %xmm5, %xmm13
        pslld     $15, %xmm4
        psrld     $17, %xmm9
        pslld     $15, %xmm13
        psrld     $17, %xmm5
        por       %xmm9, %xmm4
        movdqa    %xmm11, %xmm9
        pxor      %xmm12, %xmm3
        por       %xmm5, %xmm13
        pxor      %xmm14, %xmm9
        pxor      %xmm0, %xmm3
        paddd     %xmm2, %xmm15
        paddd     %xmm2, %xmm8
        pxor      %xmm13, %xmm9
        movdqa    %xmm1, %xmm5
        paddd     %xmm3, %xmm15
        paddd     %xmm9, %xmm8
        pxor      %xmm10, %xmm5
        paddd     1472(%rsp), %xmm15
        paddd     %xmm2, %xmm6
        paddd     800(%rsp), %xmm8
        pxor      %xmm4, %xmm5
        movdqa    %xmm15, %xmm3
        paddd     %xmm5, %xmm6
        movdqa    %xmm8, %xmm9
        pslld     $15, %xmm3
        paddd     816(%rsp), %xmm6
        psrld     $17, %xmm15
        pslld     $3, %xmm9
        psrld     $29, %xmm8
        por       %xmm15, %xmm3
        movdqa    %xmm0, %xmm15
        por       %xmm8, %xmm9
        movdqa    %xmm6, %xmm8
        pxor      %xmm7, %xmm15
        pslld     $3, %xmm8
        psrld     $29, %xmm6
        pxor      %xmm3, %xmm15
        paddd     %xmm2, %xmm12
        por       %xmm6, %xmm8
        movdqa    %xmm13, %xmm6
        paddd     %xmm15, %xmm12
        pxor      %xmm11, %xmm6
        paddd     %xmm2, %xmm14
        paddd     992(%rsp), %xmm12
        pxor      %xmm9, %xmm6
        movdqa    %xmm12, %xmm5
        paddd     %xmm6, %xmm14
        movdqa    %xmm4, %xmm6
        pslld     $3, %xmm5
        psrld     $29, %xmm12
        pxor      %xmm1, %xmm6
        por       %xmm12, %xmm5
        paddd     %xmm2, %xmm10
        pxor      %xmm8, %xmm6
..B4.34:
        paddd     960(%rsp), %xmm14
        movdqa    %xmm3, %xmm12
        paddd     %xmm6, %xmm10
        pxor      %xmm0, %xmm12
        movdqa    %xmm14, %xmm6
        pxor      %xmm5, %xmm12
        paddd     976(%rsp), %xmm10
        paddd     %xmm2, %xmm7
        pslld     $9, %xmm6
        psrld     $23, %xmm14
        paddd     %xmm12, %xmm7
        por       %xmm14, %xmm6
        movdqa    %xmm10, %xmm14
        psrld     $23, %xmm10
        paddd     1312(%rsp), %xmm7
        pslld     $9, %xmm14
        por       %xmm10, %xmm14
        movdqa    %xmm7, %xmm10
        movdqa    %xmm9, %xmm15
        pslld     $9, %xmm10
        psrld     $23, %xmm7
        pxor      %xmm13, %xmm15
        por       %xmm7, %xmm10
        paddd     %xmm2, %xmm11
        pxor      %xmm6, %xmm15
        movdqa    %xmm8, %xmm7
        paddd     %xmm15, %xmm11
        pxor      %xmm4, %xmm7
        paddd     864(%rsp), %xmm11
        paddd     %xmm2, %xmm1
        pxor      %xmm14, %xmm7
        movdqa    %xmm5, %xmm12
        paddd     %xmm7, %xmm1
        pxor      %xmm3, %xmm12
        movdqa    %xmm11, %xmm7
        pxor      %xmm10, %xmm12
        paddd     880(%rsp), %xmm1
        paddd     %xmm2, %xmm0
        pslld     $11, %xmm7
        psrld     $21, %xmm11
        paddd     %xmm12, %xmm0
        por       %xmm11, %xmm7
        movdqa    %xmm1, %xmm11
        psrld     $21, %xmm1
        paddd     1184(%rsp), %xmm0
        pslld     $11, %xmm11
        por       %xmm1, %xmm11
        movdqa    %xmm0, %xmm1
        pslld     $11, %xmm1
        psrld     $21, %xmm0
        por       %xmm0, %xmm1
        movdqa    %xmm9, %xmm0
        pxor      %xmm6, %xmm0
        paddd     %xmm2, %xmm13
        pxor      %xmm7, %xmm0
        movdqa    %xmm8, %xmm12
        paddd     %xmm0, %xmm13
        pxor      %xmm14, %xmm12
        paddd     1152(%rsp), %xmm13
        paddd     %xmm2, %xmm4
        pxor      %xmm11, %xmm12
        movdqa    %xmm5, %xmm15
        paddd     %xmm12, %xmm4
        pxor      %xmm10, %xmm15
        movdqa    %xmm13, %xmm0
        pxor      %xmm1, %xmm15
        paddd     1168(%rsp), %xmm4
        paddd     %xmm2, %xmm3
        pslld     $15, %xmm0
        psrld     $17, %xmm13
        paddd     %xmm15, %xmm3
        por       %xmm13, %xmm0
        movdqa    %xmm4, %xmm13
        psrld     $17, %xmm4
        paddd     1440(%rsp), %xmm3
        pslld     $15, %xmm13
        por       %xmm4, %xmm13
        movdqa    %xmm3, %xmm4
        pslld     $15, %xmm4
        psrld     $17, %xmm3
        movdqa    %xmm1, %xmm15
        por       %xmm3, %xmm4
        movdqa    %xmm7, %xmm3
        pxor      %xmm10, %xmm15
        pxor      %xmm6, %xmm3
        pxor      %xmm4, %xmm15
        paddd     %xmm2, %xmm5
        paddd     %xmm2, %xmm9
        pxor      %xmm0, %xmm3
        movdqa    %xmm11, %xmm12
        paddd     %xmm15, %xmm5
        paddd     %xmm3, %xmm9
        paddd     1008(%rsp), %xmm5
        pxor      %xmm14, %xmm12
        paddd     784(%rsp), %xmm9
        paddd     %xmm2, %xmm8
        pxor      %xmm13, %xmm12
        movdqa    %xmm5, %xmm3
        paddd     %xmm12, %xmm8
        movdqa    %xmm9, %xmm12
        pslld     $3, %xmm3
        psrld     $29, %xmm5
        pslld     $3, %xmm12
        psrld     $29, %xmm9
        por       %xmm5, %xmm3
        movdqa    %xmm0, %xmm5
        por       %xmm9, %xmm12
        pxor      %xmm7, %xmm5
        paddd     %xmm2, %xmm6
        pxor      %xmm12, %xmm5
        paddd     768(%rsp), %xmm8
        paddd     %xmm5, %xmm6
        movdqa    %xmm4, %xmm5
        movdqa    %xmm8, %xmm9
        pxor      %xmm1, %xmm5
        pslld     $3, %xmm9
        psrld     $29, %xmm8
        pxor      %xmm3, %xmm5
        paddd     %xmm2, %xmm10
        por       %xmm8, %xmm9
        movdqa    %xmm13, %xmm8
        paddd     %xmm5, %xmm10
        paddd     1328(%rsp), %xmm10
        pxor      %xmm11, %xmm8
        paddd     928(%rsp), %xmm6
        paddd     %xmm2, %xmm14
        pxor      %xmm9, %xmm8
        movdqa    %xmm10, %xmm5
        paddd     %xmm8, %xmm14
        movdqa    %xmm6, %xmm8
        pslld     $9, %xmm5
        psrld     $23, %xmm10
        paddd     944(%rsp), %xmm14
        pslld     $9, %xmm8
        psrld     $23, %xmm6
        por       %xmm10, %xmm5
        movdqa    %xmm12, %xmm10
        por       %xmm6, %xmm8
        movdqa    %xmm14, %xmm6
        pxor      %xmm0, %xmm10
        pslld     $9, %xmm6
        psrld     $23, %xmm14
        paddd     %xmm2, %xmm7
        pxor      %xmm8, %xmm10
        por       %xmm14, %xmm6
        paddd     %xmm10, %xmm7
        movdqa    %xmm9, %xmm14
        movdqa    %xmm3, %xmm10
        pxor      %xmm13, %xmm14
        pxor      %xmm4, %xmm10
        paddd     832(%rsp), %xmm7
        paddd     %xmm2, %xmm11
        pxor      %xmm6, %xmm14
        pxor      %xmm5, %xmm10
        paddd     %xmm2, %xmm1
        paddd     %xmm14, %xmm11
        paddd     %xmm10, %xmm1
        movdqa    %xmm7, %xmm14
        paddd     1056(%rsp), %xmm1
        pslld     $11, %xmm14
        psrld     $21, %xmm7
        paddd     %xmm2, %xmm0
        por       %xmm7, %xmm14
        movdqa    %xmm1, %xmm7
        pslld     $11, %xmm7
        psrld     $21, %xmm1
        paddd     848(%rsp), %xmm11
        por       %xmm1, %xmm7
        movdqa    %xmm8, %xmm1
        movdqa    %xmm11, %xmm10
        pxor      %xmm12, %xmm1
        pslld     $11, %xmm10
        psrld     $21, %xmm11
        pxor      %xmm14, %xmm1
        por       %xmm11, %xmm10
        paddd     %xmm1, %xmm0
        movdqa    %xmm6, %xmm11
        movdqa    %xmm5, %xmm1
        pxor      %xmm9, %xmm11
        pxor      %xmm3, %xmm1
        paddd     1088(%rsp), %xmm0
        paddd     %xmm2, %xmm13
        pxor      %xmm10, %xmm11
        pxor      %xmm7, %xmm1
        paddd     %xmm4, %xmm2
        paddd     %xmm11, %xmm13
        paddd     %xmm1, %xmm2
        movdqa    %xmm0, %xmm4
        paddd     1200(%rsp), %xmm13
        pslld     $15, %xmm4
        paddd     1488(%rsp), %xmm2
        psrld     $17, %xmm0
        por       %xmm0, %xmm4
        movdqa    %xmm13, %xmm1
        movdqa    %xmm2, %xmm0
        pslld     $15, %xmm1
        psrld     $17, %xmm13
        pslld     $15, %xmm0
        psrld     $17, %xmm2
        por       %xmm13, %xmm1
        por       %xmm2, %xmm0
        testl     %edx, %edx
        jne       ..B4.25
..B4.24:
        movdqa    .L_2il0floatpacket.524(%rip), %xmm2
        movdqa    .L_2il0floatpacket.22(%rip), %xmm11
        paddd     %xmm2, %xmm12
        movdqa    .L_2il0floatpacket.23(%rip), %xmm13
        paddd     %xmm11, %xmm4
        movdqa    .L_2il0floatpacket.24(%rip), %xmm15
        paddd     %xmm13, %xmm14
        paddd     %xmm15, %xmm8
        paddd     %xmm2, %xmm9
        paddd     %xmm11, %xmm1
        paddd     %xmm13, %xmm10
        paddd     %xmm15, %xmm6
        paddd     %xmm2, %xmm3
        paddd     %xmm11, %xmm0
        paddd     %xmm13, %xmm7
        paddd     %xmm15, %xmm5
        jmp       ..B4.28
..B4.25:
        movl      %r8d, %eax
        andl      $6, %eax
        movdqa    (%rcx), %xmm2
        cmpl      $6, %eax
        movdqa    16(%rcx), %xmm11
        paddd     %xmm2, %xmm12
        movdqa    32(%rcx), %xmm13
        paddd     %xmm11, %xmm4
        movdqa    48(%rcx), %xmm15
        paddd     %xmm13, %xmm14
        paddd     %xmm15, %xmm8
        jne       ..B4.27
..B4.26:
        movdqa    256(%rcx), %xmm2
        movdqa    272(%rcx), %xmm11
        paddd     %xmm2, %xmm9
        movdqa    288(%rcx), %xmm13
        paddd     %xmm11, %xmm1
        movdqa    304(%rcx), %xmm15
        paddd     %xmm13, %xmm10
        movdqa    512(%rcx), %xmm2
        paddd     %xmm15, %xmm6
        movdqa    528(%rcx), %xmm11
        paddd     %xmm2, %xmm3
        movdqa    544(%rcx), %xmm13
        paddd     %xmm11, %xmm0
        movdqa    560(%rcx), %xmm15
        paddd     %xmm13, %xmm7
        paddd     %xmm15, %xmm5
        jmp       ..B4.28
..B4.27:
        movdqa    64(%rcx), %xmm2
        movdqa    80(%rcx), %xmm11
        paddd     %xmm2, %xmm9
        movdqa    96(%rcx), %xmm13
        paddd     %xmm11, %xmm1
        movdqa    112(%rcx), %xmm15
        paddd     %xmm13, %xmm10
        movdqa    128(%rcx), %xmm2
        paddd     %xmm15, %xmm6
        movdqa    144(%rcx), %xmm11
        paddd     %xmm2, %xmm3
        movdqa    160(%rcx), %xmm13
        paddd     %xmm11, %xmm0
        movdqa    176(%rcx), %xmm15
        paddd     %xmm13, %xmm7
        paddd     %xmm15, %xmm5
..B4.28:
        movdqa    %xmm12, (%rsi)
        testl     $8, %r8d
        movdqa    %xmm4, 16(%rsi)
        movdqa    %xmm14, 32(%rsi)
        movdqa    %xmm8, 48(%rsi)
        je        ..B4.30
..B4.29:
        movdqa    %xmm9, 256(%rsi)
        movdqa    %xmm1, 272(%rsi)
        movdqa    %xmm10, 288(%rsi)
        movdqa    %xmm6, 304(%rsi)
        movdqa    %xmm3, 512(%rsi)
        movdqa    %xmm0, 528(%rsi)
        movdqa    %xmm7, 544(%rsi)
        movdqa    %xmm5, 560(%rsi)
        addq      $1544, %rsp
..___tag_value_SIMDmd4body.100:
        ret       
..___tag_value_SIMDmd4body.101:
..B4.30:
        movdqa    %xmm9, 64(%rsi)
        movdqa    %xmm1, 80(%rsi)
        movdqa    %xmm10, 96(%rsi)
        movdqa    %xmm6, 112(%rsi)
        movdqa    %xmm3, 128(%rsi)
        movdqa    %xmm0, 144(%rsi)
        movdqa    %xmm7, 160(%rsi)
        movdqa    %xmm5, 176(%rsi)
..B4.31:
        addq      $1544, %rsp
..___tag_value_SIMDmd4body.102:
        ret       
        .align    16,0x90
..___tag_value_SIMDmd4body.103:
	.type	SIMDmd4body,@function
	.size	SIMDmd4body,.-SIMDmd4body
	.data
# -- End  SIMDmd4body
	.text
# -- Begin  SIMDSHA1body
       .align    16,0x90
	.globl SIMDSHA1body
SIMDSHA1body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B5.1:
..___tag_value_SIMDSHA1body.104:
        subq      $584, %rsp
..___tag_value_SIMDSHA1body.106:
        testb     $1, %cl
        je        ..B5.15
..B5.2:
        movl      (%rdi), %eax
        testl     $256, %ecx
        je        ..B5.4
..B5.3:
        movl      %eax, (%rsp)
        movl      256(%rdi), %eax
        movl      512(%rdi), %r8d
        movl      %eax, 4(%rsp)
        movl      %r8d, 8(%rsp)
        movl      768(%rdi), %r9d
        movl      772(%rdi), %r8d
        movl      4(%rdi), %r10d
        movl      260(%rdi), %r11d
        movl      516(%rdi), %eax
        movl      %r9d, 12(%rsp)
        movl      %r10d, 16(%rsp)
        movl      %r11d, 20(%rsp)
        movl      %eax, 24(%rsp)
        movl      %r8d, 28(%rsp)
        movl      8(%rdi), %r9d
        movl      12(%rdi), %r8d
        movl      264(%rdi), %r10d
        movl      520(%rdi), %r11d
        movl      776(%rdi), %eax
        movl      %r9d, 32(%rsp)
        movl      %r10d, 36(%rsp)
        movl      %r11d, 40(%rsp)
        movl      %eax, 44(%rsp)
        movl      %r8d, 48(%rsp)
        movl      268(%rdi), %r9d
        movl      272(%rdi), %r8d
        movl      524(%rdi), %r10d
        movl      780(%rdi), %r11d
        movl      16(%rdi), %eax
        movl      %r9d, 52(%rsp)
        movl      %r10d, 56(%rsp)
        movl      %r11d, 60(%rsp)
        movl      %eax, 64(%rsp)
        movl      %r8d, 68(%rsp)
        movl      528(%rdi), %r9d
        movl      532(%rdi), %r8d
        movl      784(%rdi), %r10d
        movl      20(%rdi), %r11d
        movl      276(%rdi), %eax
        movl      %r9d, 72(%rsp)
        movl      %r10d, 76(%rsp)
        movl      %r11d, 80(%rsp)
        movl      %eax, 84(%rsp)
        movl      %r8d, 88(%rsp)
        movl      788(%rdi), %r9d
        movl      792(%rdi), %r8d
        movl      24(%rdi), %r10d
        movl      280(%rdi), %r11d
        movl      536(%rdi), %eax
        movl      %r9d, 92(%rsp)
        movl      %r10d, 96(%rsp)
        movl      %r11d, 100(%rsp)
        movl      %eax, 104(%rsp)
        movl      %r8d, 108(%rsp)
        movl      28(%rdi), %r9d
        movl      32(%rdi), %r8d
        movl      284(%rdi), %r10d
        movl      540(%rdi), %r11d
        movl      796(%rdi), %eax
        movl      %r9d, 112(%rsp)
        movl      %r10d, 116(%rsp)
        movl      %r11d, 120(%rsp)
        movl      %eax, 124(%rsp)
        movl      %r8d, 128(%rsp)
        movl      288(%rdi), %r9d
        movl      292(%rdi), %r8d
        movl      544(%rdi), %r10d
        movl      800(%rdi), %r11d
        movl      36(%rdi), %eax
        movl      %r9d, 132(%rsp)
        movl      %r10d, 136(%rsp)
        movl      %r11d, 140(%rsp)
        movl      %eax, 144(%rsp)
        movl      %r8d, 148(%rsp)
        movl      548(%rdi), %r9d
        movl      552(%rdi), %r8d
        movl      804(%rdi), %r10d
        movl      40(%rdi), %r11d
        movl      296(%rdi), %eax
        movl      %r9d, 152(%rsp)
        movl      %r10d, 156(%rsp)
        movl      %r11d, 160(%rsp)
        movl      %eax, 164(%rsp)
        movl      %r8d, 168(%rsp)
        movl      808(%rdi), %r9d
        movl      812(%rdi), %r8d
        movl      44(%rdi), %r10d
        movl      300(%rdi), %r11d
        movl      556(%rdi), %eax
        movl      %r9d, 172(%rsp)
        movl      %r10d, 176(%rsp)
        movl      %r11d, 180(%rsp)
        movl      %eax, 184(%rsp)
        movl      %r8d, 188(%rsp)
        movl      48(%rdi), %r9d
        movl      52(%rdi), %r8d
        movl      304(%rdi), %r10d
        movl      560(%rdi), %r11d
        movl      816(%rdi), %eax
        movl      %r9d, 192(%rsp)
        movl      %r10d, 196(%rsp)
        movl      %r11d, 200(%rsp)
        movl      %eax, 204(%rsp)
        movl      %r8d, 208(%rsp)
        movl      308(%rdi), %r9d
        movl      312(%rdi), %r8d
        movl      564(%rdi), %r10d
        movl      820(%rdi), %r11d
        movl      56(%rdi), %eax
        movl      %r9d, 212(%rsp)
        movl      %r10d, 216(%rsp)
        movl      %r11d, 220(%rsp)
        movl      %eax, 224(%rsp)
        movl      %r8d, 228(%rsp)
        movl      568(%rdi), %r9d
        movl      572(%rdi), %r8d
        movl      824(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      316(%rdi), %eax
        movl      828(%rdi), %edi
        movl      %r9d, 232(%rsp)
        movl      %r10d, 236(%rsp)
        movl      %r11d, 240(%rsp)
        movl      %eax, 244(%rsp)
        movl      %r8d, 248(%rsp)
        movl      %edi, 252(%rsp)
        jmp       ..B5.7
..B5.4:
        testb     $64, %cl
        je        ..B5.6
..B5.5:
        movl      %eax, (%rsp)
        movl      128(%rdi), %eax
        movl      256(%rdi), %r8d
        movl      %eax, 4(%rsp)
        movl      %r8d, 8(%rsp)
        movl      384(%rdi), %r9d
        movl      388(%rdi), %r8d
        movl      4(%rdi), %r10d
        movl      132(%rdi), %r11d
        movl      260(%rdi), %eax
        movl      %r9d, 12(%rsp)
        movl      %r10d, 16(%rsp)
        movl      %r11d, 20(%rsp)
        movl      %eax, 24(%rsp)
        movl      %r8d, 28(%rsp)
        movl      8(%rdi), %r9d
        movl      12(%rdi), %r8d
        movl      136(%rdi), %r10d
        movl      264(%rdi), %r11d
        movl      392(%rdi), %eax
        movl      %r9d, 32(%rsp)
        movl      %r10d, 36(%rsp)
        movl      %r11d, 40(%rsp)
        movl      %eax, 44(%rsp)
        movl      %r8d, 48(%rsp)
        movl      140(%rdi), %r9d
        movl      144(%rdi), %r8d
        movl      268(%rdi), %r10d
        movl      396(%rdi), %r11d
        movl      16(%rdi), %eax
        movl      %r9d, 52(%rsp)
        movl      %r10d, 56(%rsp)
        movl      %r11d, 60(%rsp)
        movl      %eax, 64(%rsp)
        movl      %r8d, 68(%rsp)
        movl      272(%rdi), %r9d
        movl      276(%rdi), %r8d
        movl      400(%rdi), %r10d
        movl      20(%rdi), %r11d
        movl      148(%rdi), %eax
        movl      %r9d, 72(%rsp)
        movl      %r10d, 76(%rsp)
        movl      %r11d, 80(%rsp)
        movl      %eax, 84(%rsp)
        movl      %r8d, 88(%rsp)
        movl      404(%rdi), %r9d
        movl      408(%rdi), %r8d
        movl      24(%rdi), %r10d
        movl      152(%rdi), %r11d
        movl      280(%rdi), %eax
        movl      %r9d, 92(%rsp)
        movl      %r10d, 96(%rsp)
        movl      %r11d, 100(%rsp)
        movl      %eax, 104(%rsp)
        movl      %r8d, 108(%rsp)
        movl      28(%rdi), %r9d
        movl      32(%rdi), %r8d
        movl      156(%rdi), %r10d
        movl      284(%rdi), %r11d
        movl      412(%rdi), %eax
        movl      %r9d, 112(%rsp)
        movl      %r10d, 116(%rsp)
        movl      %r11d, 120(%rsp)
        movl      %eax, 124(%rsp)
        movl      %r8d, 128(%rsp)
        movl      160(%rdi), %r9d
        movl      164(%rdi), %r8d
        movl      288(%rdi), %r10d
        movl      416(%rdi), %r11d
        movl      36(%rdi), %eax
        movl      %r9d, 132(%rsp)
        movl      %r10d, 136(%rsp)
        movl      %r11d, 140(%rsp)
        movl      %eax, 144(%rsp)
        movl      %r8d, 148(%rsp)
        movl      292(%rdi), %r9d
        movl      296(%rdi), %r8d
        movl      420(%rdi), %r10d
        movl      40(%rdi), %r11d
        movl      168(%rdi), %eax
        movl      %r9d, 152(%rsp)
        movl      %r10d, 156(%rsp)
        movl      %r11d, 160(%rsp)
        movl      %eax, 164(%rsp)
        movl      %r8d, 168(%rsp)
        movl      424(%rdi), %r9d
        movl      428(%rdi), %r8d
        movl      44(%rdi), %r10d
        movl      172(%rdi), %r11d
        movl      300(%rdi), %eax
        movl      %r9d, 172(%rsp)
        movl      %r10d, 176(%rsp)
        movl      %r11d, 180(%rsp)
        movl      %eax, 184(%rsp)
        movl      %r8d, 188(%rsp)
        movl      48(%rdi), %r9d
        movl      52(%rdi), %r8d
        movl      176(%rdi), %r10d
        movl      304(%rdi), %r11d
        movl      432(%rdi), %eax
        movl      %r9d, 192(%rsp)
        movl      %r10d, 196(%rsp)
        movl      %r11d, 200(%rsp)
        movl      %eax, 204(%rsp)
        movl      %r8d, 208(%rsp)
        movl      180(%rdi), %r9d
        movl      184(%rdi), %r8d
        movl      308(%rdi), %r10d
        movl      436(%rdi), %r11d
        movl      56(%rdi), %eax
        movl      %r9d, 212(%rsp)
        movl      %r10d, 216(%rsp)
        movl      %r11d, 220(%rsp)
        movl      %eax, 224(%rsp)
        movl      %r8d, 228(%rsp)
        movl      312(%rdi), %r9d
        movl      316(%rdi), %r8d
        movl      440(%rdi), %r10d
        movl      60(%rdi), %r11d
        movl      188(%rdi), %eax
        movl      444(%rdi), %edi
        movl      %r9d, 232(%rsp)
        movl      %r10d, 236(%rsp)
        movl      %r11d, 240(%rsp)
        movl      %eax, 244(%rsp)
        movl      %r8d, 248(%rsp)
        movl      %edi, 252(%rsp)
        jmp       ..B5.7
..B5.6:
        movl      %eax, (%rsp)
        movl      64(%rdi), %eax
        movl      128(%rdi), %r8d
        movl      %eax, 4(%rsp)
        movl      %r8d, 8(%rsp)
        movl      192(%rdi), %r9d
        movl      132(%rdi), %eax
        movl      68(%rdi), %r11d
        movl      4(%rdi), %r10d
        movl      196(%rdi), %r8d
        movl      %r9d, 12(%rsp)
        movl      %r10d, 16(%rsp)
        movl      %r11d, 20(%rsp)
        movl      %eax, 24(%rsp)
        movl      %r8d, 28(%rsp)
        movl      8(%rdi), %r9d
        movl      72(%rdi), %r10d
        movl      136(%rdi), %r11d
        movl      200(%rdi), %eax
        movl      12(%rdi), %r8d
        movl      %r9d, 32(%rsp)
        movl      %r10d, 36(%rsp)
        movl      %r11d, 40(%rsp)
        movl      %eax, 44(%rsp)
        movl      %r8d, 48(%rsp)
        movl      76(%rdi), %r9d
        movl      140(%rdi), %r10d
        movl      204(%rdi), %r11d
        movl      16(%rdi), %eax
        movl      80(%rdi), %r8d
        movl      %r9d, 52(%rsp)
        movl      %r10d, 56(%rsp)
        movl      %r11d, 60(%rsp)
        movl      %eax, 64(%rsp)
        movl      %r8d, 68(%rsp)
        movl      144(%rdi), %r9d
        movl      208(%rdi), %r10d
        movl      148(%rdi), %r8d
        movl      84(%rdi), %eax
        movl      20(%rdi), %r11d
        movl      %r9d, 72(%rsp)
        movl      %r10d, 76(%rsp)
        movl      %r11d, 80(%rsp)
        movl      %eax, 84(%rsp)
        movl      %r8d, 88(%rsp)
        movl      212(%rdi), %r9d
        movl      152(%rdi), %eax
        movl      88(%rdi), %r11d
        movl      24(%rdi), %r10d
        movl      216(%rdi), %r8d
        movl      %r9d, 92(%rsp)
        movl      %r10d, 96(%rsp)
        movl      %r11d, 100(%rsp)
        movl      %eax, 104(%rsp)
        movl      %r8d, 108(%rsp)
        movl      28(%rdi), %r9d
        movl      92(%rdi), %r10d
        movl      156(%rdi), %r11d
        movl      220(%rdi), %eax
        movl      32(%rdi), %r8d
        movl      %r9d, 112(%rsp)
        movl      %r10d, 116(%rsp)
        movl      %r11d, 120(%rsp)
        movl      %eax, 124(%rsp)
        movl      %r8d, 128(%rsp)
        movl      96(%rdi), %r9d
        movl      160(%rdi), %r10d
        movl      224(%rdi), %r11d
        movl      36(%rdi), %eax
        movl      100(%rdi), %r8d
        movl      %r9d, 132(%rsp)
        movl      %r10d, 136(%rsp)
        movl      %r11d, 140(%rsp)
        movl      %eax, 144(%rsp)
        movl      %r8d, 148(%rsp)
        movl      164(%rdi), %r9d
        movl      228(%rdi), %r10d
        movl      168(%rdi), %r8d
        movl      104(%rdi), %eax
        movl      40(%rdi), %r11d
        movl      %r9d, 152(%rsp)
        movl      %r10d, 156(%rsp)
        movl      %r11d, 160(%rsp)
        movl      %eax, 164(%rsp)
        movl      %r8d, 168(%rsp)
        movl      232(%rdi), %r9d
        movl      172(%rdi), %eax
        movl      108(%rdi), %r11d
        movl      44(%rdi), %r10d
        movl      236(%rdi), %r8d
        movl      %r9d, 172(%rsp)
        movl      %r10d, 176(%rsp)
        movl      %r11d, 180(%rsp)
        movl      %eax, 184(%rsp)
        movl      %r8d, 188(%rsp)
        movl      48(%rdi), %r9d
        movl      112(%rdi), %r10d
        movl      176(%rdi), %r11d
        movl      240(%rdi), %eax
        movl      52(%rdi), %r8d
        movl      %r9d, 192(%rsp)
        movl      %r10d, 196(%rsp)
        movl      %r11d, 200(%rsp)
        movl      %eax, 204(%rsp)
        movl      %r8d, 208(%rsp)
        movl      116(%rdi), %r9d
        movl      180(%rdi), %r10d
        movl      244(%rdi), %r11d
        movl      56(%rdi), %eax
        movl      120(%rdi), %r8d
        movl      %r9d, 212(%rsp)
        movl      %r10d, 216(%rsp)
        movl      %r11d, 220(%rsp)
        movl      %eax, 224(%rsp)
        movl      %r8d, 228(%rsp)
        movl      184(%rdi), %r9d
        movl      248(%rdi), %r10d
        movl      188(%rdi), %r8d
        movl      124(%rdi), %eax
        movl      60(%rdi), %r11d
        movl      252(%rdi), %edi
        movl      %r9d, 232(%rsp)
        movl      %r10d, 236(%rsp)
        movl      %r11d, 240(%rsp)
        movl      %eax, 244(%rsp)
        movl      %r8d, 248(%rsp)
        movl      %edi, 252(%rsp)
..B5.7:
        xorl      %edi, %edi
        xorl      %eax, %eax
..B5.8:
        shlq      $4, %rdi
        incl      %eax
        cmpl      $14, %eax
        pshufhw   $177, (%rsp,%rdi), %xmm0
        pshuflw   $177, %xmm0, %xmm1
        movdqa    %xmm1, %xmm2
        psllw     $8, %xmm1
        psrlw     $8, %xmm2
        pxor      %xmm1, %xmm2
        movdqa    %xmm2, (%rsp,%rdi)
        movl      %eax, %edi
        jb        ..B5.8
..B5.9:
        movl      %ecx, %eax
        andl      $192, %eax
        cmpl      $192, %eax
        je        ..B5.12
..B5.10:
        movl      %ecx, %eax
        andl      $768, %eax
        cmpl      $768, %eax
        je        ..B5.12
..B5.11:
        testl     $1024, %ecx
        je        ..B5.13
..B5.12:
        pshufhw   $177, 224(%rsp), %xmm0
        pshufhw   $177, 240(%rsp), %xmm3
        pshuflw   $177, %xmm0, %xmm1
        pshuflw   $177, %xmm3, %xmm4
        movdqa    %xmm1, %xmm2
        movdqa    %xmm4, %xmm5
        psrlw     $8, %xmm2
        psllw     $8, %xmm1
        psrlw     $8, %xmm5
        psllw     $8, %xmm4
        pxor      %xmm1, %xmm2
        pxor      %xmm4, %xmm5
        movdqa    %xmm2, 224(%rsp)
        movdqa    %xmm5, 240(%rsp)
..B5.13:
        lea       (%rsp), %rdi
..B5.15:
        andl      $2, %ecx
        jne       ..B5.17
..B5.16:
        movdqa    .L_2il0floatpacket.524(%rip), %xmm0
        movdqa    .L_2il0floatpacket.22(%rip), %xmm3
        movdqa    .L_2il0floatpacket.23(%rip), %xmm10
        movdqa    .L_2il0floatpacket.24(%rip), %xmm1
        movdqa    .L_2il0floatpacket.553(%rip), %xmm4
        jmp       ..B5.18
..B5.17:
        movdqa    (%rdx), %xmm0
        movdqa    16(%rdx), %xmm3
        movdqa    32(%rdx), %xmm10
        movdqa    48(%rdx), %xmm1
        movdqa    64(%rdx), %xmm4
..B5.18:
        movdqa    208(%rdi), %xmm12
        movdqa    %xmm10, %xmm9
        movdqa    128(%rdi), %xmm13
        movdqa    %xmm12, %xmm11
        pxor      %xmm13, %xmm11
        pxor      %xmm1, %xmm9
        pxor      32(%rdi), %xmm11
        pand      %xmm3, %xmm9
        pxor      (%rdi), %xmm11
        movdqa    %xmm0, %xmm7
        movdqa    %xmm11, %xmm2
        paddd     %xmm11, %xmm11
        psrld     $31, %xmm2
        movdqa    %xmm0, %xmm5
        por       %xmm2, %xmm11
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        pxor      %xmm1, %xmm9
        pslld     $5, %xmm7
        psrld     $27, %xmm5
        por       %xmm3, %xmm2
        movdqa    224(%rdi), %xmm3
        por       %xmm5, %xmm7
        paddd     %xmm9, %xmm4
        movdqa    %xmm3, %xmm15
        movdqa    .L_2il0floatpacket.554(%rip), %xmm8
        paddd     %xmm7, %xmm4
        pxor      144(%rdi), %xmm15
        paddd     %xmm8, %xmm4
        pxor      48(%rdi), %xmm15
        movdqa    %xmm10, %xmm14
        paddd     (%rdi), %xmm4
        pxor      %xmm2, %xmm14
        pxor      16(%rdi), %xmm15
        pand      %xmm0, %xmm14
        movdqa    %xmm15, %xmm6
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm5
        psrld     $31, %xmm6
        paddd     %xmm15, %xmm15
        pxor      %xmm10, %xmm14
        pslld     $5, %xmm9
        psrld     $27, %xmm5
        por       %xmm6, %xmm15
        por       %xmm5, %xmm9
        movdqa    240(%rdi), %xmm6
        paddd     %xmm14, %xmm1
        paddd     %xmm9, %xmm1
        movdqa    %xmm6, %xmm9
        pxor      160(%rdi), %xmm9
        movdqa    %xmm0, %xmm14
        pxor      64(%rdi), %xmm9
        pslld     $30, %xmm14
        psrld     $2, %xmm0
        paddd     %xmm8, %xmm1
        pxor      32(%rdi), %xmm9
        por       %xmm0, %xmm14
        movdqa    %xmm9, %xmm0
        movdqa    %xmm14, %xmm7
        paddd     16(%rdi), %xmm1
        psrld     $31, %xmm0
        paddd     %xmm9, %xmm9
        pxor      %xmm2, %xmm7
        por       %xmm0, %xmm9
        pand      %xmm4, %xmm7
        movdqa    %xmm1, %xmm0
        movdqa    %xmm1, %xmm5
        pxor      %xmm2, %xmm7
        pslld     $5, %xmm0
        psrld     $27, %xmm5
        paddd     %xmm7, %xmm10
        por       %xmm5, %xmm0
        movdqa    %xmm4, %xmm5
        paddd     %xmm0, %xmm10
        pslld     $30, %xmm5
        movdqa    176(%rdi), %xmm0
        psrld     $2, %xmm4
        pxor      %xmm11, %xmm0
        por       %xmm4, %xmm5
        pxor      80(%rdi), %xmm0
        paddd     %xmm8, %xmm10
        pxor      48(%rdi), %xmm0
        pxor      %xmm9, %xmm12
        movdqa    %xmm0, %xmm4
        paddd     %xmm0, %xmm0
        psrld     $31, %xmm4
        por       %xmm4, %xmm0
        movdqa    %xmm5, %xmm4
        paddd     32(%rdi), %xmm10
        pxor      %xmm14, %xmm4
        movdqa    %xmm11, 480(%rsp)
        pand      %xmm1, %xmm4
        movdqa    %xmm10, %xmm7
        movdqa    %xmm10, %xmm11
        pxor      %xmm14, %xmm4
        pslld     $5, %xmm7
        psrld     $27, %xmm11
        paddd     %xmm4, %xmm2
        movdqa    192(%rdi), %xmm4
        por       %xmm11, %xmm7
        paddd     %xmm7, %xmm2
        movdqa    %xmm1, %xmm7
        pxor      %xmm15, %xmm4
        pslld     $30, %xmm7
        pxor      96(%rdi), %xmm4
        psrld     $2, %xmm1
        pxor      64(%rdi), %xmm4
        por       %xmm1, %xmm7
        paddd     %xmm8, %xmm2
        movdqa    %xmm4, %xmm1
        movdqa    %xmm7, %xmm11
        psrld     $31, %xmm1
        paddd     48(%rdi), %xmm2
        paddd     %xmm4, %xmm4
        pxor      %xmm5, %xmm11
        por       %xmm1, %xmm4
        movdqa    %xmm15, 496(%rsp)
        pand      %xmm10, %xmm11
        movdqa    %xmm2, %xmm1
        movdqa    %xmm2, %xmm15
        pxor      %xmm5, %xmm11
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        paddd     %xmm11, %xmm14
        por       %xmm15, %xmm1
        pxor      %xmm0, %xmm3
        paddd     %xmm1, %xmm14
        movdqa    %xmm10, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm10
        pxor      112(%rdi), %xmm12
        por       %xmm10, %xmm1
        pxor      80(%rdi), %xmm12
        movdqa    %xmm1, %xmm11
        paddd     %xmm8, %xmm14
        movdqa    %xmm12, %xmm10
        pxor      %xmm7, %xmm11
        psrld     $31, %xmm10
        paddd     64(%rdi), %xmm14
        paddd     %xmm12, %xmm12
        pand      %xmm2, %xmm11
        por       %xmm10, %xmm12
        pxor      %xmm7, %xmm11
        movdqa    %xmm14, %xmm10
        movdqa    %xmm14, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm11, %xmm5
        movdqa    %xmm2, %xmm11
        por       %xmm15, %xmm10
        pslld     $30, %xmm11
        psrld     $2, %xmm2
        paddd     %xmm10, %xmm5
        por       %xmm2, %xmm11
        pxor      %xmm13, %xmm3
        paddd     %xmm8, %xmm5
        pxor      96(%rdi), %xmm3
        pxor      %xmm4, %xmm6
        movdqa    %xmm0, 528(%rsp)
        movdqa    %xmm11, %xmm0
        paddd     80(%rdi), %xmm5
        movdqa    %xmm3, %xmm2
        pxor      %xmm1, %xmm0
        psrld     $31, %xmm2
        paddd     %xmm3, %xmm3
        pand      %xmm14, %xmm0
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm10
        por       %xmm2, %xmm3
        pxor      %xmm1, %xmm0
        pslld     $5, %xmm15
        psrld     $27, %xmm10
        movdqa    %xmm14, %xmm2
        por       %xmm10, %xmm15
        paddd     %xmm0, %xmm7
        pslld     $30, %xmm2
        psrld     $2, %xmm14
        paddd     %xmm15, %xmm7
        por       %xmm14, %xmm2
        paddd     %xmm8, %xmm7
        movdqa    %xmm4, 448(%rsp)
        movdqa    %xmm2, %xmm4
        paddd     96(%rdi), %xmm7
        pxor      %xmm11, %xmm4
        movdqa    144(%rdi), %xmm15
        pand      %xmm5, %xmm4
        movdqa    %xmm7, %xmm0
        movdqa    %xmm7, %xmm10
        pxor      %xmm15, %xmm6
        pxor      %xmm11, %xmm4
        pslld     $5, %xmm0
        psrld     $27, %xmm10
        movdqa    %xmm12, 544(%rsp)
        por       %xmm10, %xmm0
        pxor      112(%rdi), %xmm6
        paddd     %xmm4, %xmm1
        movdqa    160(%rdi), %xmm10
        movdqa    %xmm5, %xmm4
        pxor      480(%rsp), %xmm12
        movdqa    %xmm6, %xmm14
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        pxor      %xmm10, %xmm12
        psrld     $31, %xmm14
        paddd     %xmm6, %xmm6
        paddd     %xmm0, %xmm1
        por       %xmm5, %xmm4
        pxor      %xmm13, %xmm12
        por       %xmm14, %xmm6
        paddd     %xmm8, %xmm1
        movdqa    %xmm12, %xmm5
        movdqa    %xmm4, %xmm14
        paddd     112(%rdi), %xmm1
        psrld     $31, %xmm5
        paddd     %xmm12, %xmm12
        pxor      %xmm2, %xmm14
        por       %xmm5, %xmm12
        pand      %xmm7, %xmm14
        movdqa    %xmm1, %xmm5
        movdqa    %xmm1, %xmm0
        pxor      %xmm2, %xmm14
        pslld     $5, %xmm5
        psrld     $27, %xmm0
        paddd     %xmm14, %xmm11
        por       %xmm0, %xmm5
        movdqa    %xmm3, 400(%rsp)
        paddd     %xmm5, %xmm11
        pxor      496(%rsp), %xmm3
        movdqa    %xmm7, %xmm5
        movdqa    176(%rdi), %xmm0
        pslld     $30, %xmm5
        psrld     $2, %xmm7
        pxor      %xmm0, %xmm3
        paddd     %xmm8, %xmm11
        por       %xmm7, %xmm5
        pxor      %xmm15, %xmm3
        paddd     %xmm13, %xmm11
        movdqa    %xmm3, %xmm13
        movdqa    %xmm5, %xmm7
        psrld     $31, %xmm13
        paddd     %xmm3, %xmm3
        pxor      %xmm4, %xmm7
        por       %xmm13, %xmm3
        pand      %xmm1, %xmm7
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm14
        pxor      %xmm4, %xmm7
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        por       %xmm14, %xmm13
        paddd     %xmm7, %xmm2
        movdqa    %xmm1, %xmm7
        paddd     %xmm13, %xmm2
        pslld     $30, %xmm7
        psrld     $2, %xmm1
        movdqa    %xmm6, %xmm13
        por       %xmm1, %xmm7
        movdqa    192(%rdi), %xmm1
        pxor      %xmm9, %xmm13
        pxor      %xmm1, %xmm13
        paddd     %xmm8, %xmm2
        pxor      %xmm10, %xmm13
        paddd     %xmm15, %xmm2
        movdqa    %xmm9, 512(%rsp)
        movdqa    %xmm13, %xmm9
        movdqa    %xmm7, %xmm15
        psrld     $31, %xmm9
        paddd     %xmm13, %xmm13
        pxor      %xmm5, %xmm15
        por       %xmm9, %xmm13
        pand      %xmm11, %xmm15
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm14
        pxor      %xmm5, %xmm15
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm4
        por       %xmm14, %xmm9
        paddd     %xmm9, %xmm4
        movdqa    %xmm12, 256(%rsp)
        paddd     %xmm8, %xmm4
        pxor      528(%rsp), %xmm12
        paddd     %xmm10, %xmm4
        movdqa    208(%rdi), %xmm14
        movdqa    %xmm11, %xmm10
        pxor      %xmm14, %xmm12
        pslld     $30, %xmm10
        psrld     $2, %xmm11
        pxor      %xmm0, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm12, %xmm11
        psrld     $31, %xmm11
        paddd     %xmm12, %xmm12
        por       %xmm11, %xmm12
        movdqa    %xmm10, %xmm9
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm15
        pxor      %xmm7, %xmm9
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        pand      %xmm2, %xmm9
        por       %xmm15, %xmm11
        movdqa    %xmm2, %xmm15
        pxor      %xmm7, %xmm9
        pslld     $30, %xmm15
        psrld     $2, %xmm2
        paddd     %xmm9, %xmm5
        movdqa    %xmm3, 272(%rsp)
        por       %xmm2, %xmm15
        pxor      448(%rsp), %xmm3
        paddd     %xmm11, %xmm5
        movdqa    224(%rdi), %xmm2
        paddd     %xmm8, %xmm5
        pxor      %xmm2, %xmm3
        paddd     %xmm0, %xmm5
        pxor      %xmm1, %xmm3
        movdqa    %xmm15, %xmm11
        movdqa    %xmm3, %xmm0
        paddd     %xmm3, %xmm3
        psrld     $31, %xmm0
        pxor      %xmm10, %xmm11
        por       %xmm0, %xmm3
        pand      %xmm4, %xmm11
        movdqa    %xmm5, %xmm0
        movdqa    %xmm5, %xmm9
        pxor      %xmm10, %xmm11
        pslld     $5, %xmm0
        psrld     $27, %xmm9
        paddd     %xmm11, %xmm7
        movdqa    %xmm13, 352(%rsp)
        por       %xmm9, %xmm0
        pxor      544(%rsp), %xmm13
        paddd     %xmm0, %xmm7
        movdqa    240(%rdi), %xmm11
        paddd     %xmm8, %xmm7
        pxor      %xmm11, %xmm13
        movdqa    %xmm4, %xmm0
        pxor      %xmm14, %xmm13
        paddd     %xmm1, %xmm7
        pslld     $30, %xmm0
        psrld     $2, %xmm4
        movdqa    %xmm13, %xmm1
        por       %xmm4, %xmm0
        psrld     $31, %xmm1
        paddd     %xmm13, %xmm13
        por       %xmm1, %xmm13
        movdqa    %xmm0, %xmm1
        pxor      %xmm15, %xmm1
        movdqa    %xmm7, %xmm9
        pand      %xmm5, %xmm1
        movdqa    %xmm7, %xmm4
        pxor      %xmm15, %xmm1
        pslld     $5, %xmm9
        psrld     $27, %xmm4
        paddd     %xmm1, %xmm10
        por       %xmm4, %xmm9
        paddd     %xmm9, %xmm10
        paddd     %xmm8, %xmm10
        movdqa    %xmm12, 336(%rsp)
        paddd     %xmm14, %xmm10
        pxor      400(%rsp), %xmm12
        movdqa    %xmm5, %xmm14
        movdqa    480(%rsp), %xmm9
        pslld     $30, %xmm14
        psrld     $2, %xmm5
        pxor      %xmm9, %xmm12
        por       %xmm5, %xmm14
        pxor      %xmm2, %xmm12
        movdqa    %xmm12, %xmm5
        movdqa    %xmm14, %xmm4
        psrld     $31, %xmm5
        paddd     %xmm12, %xmm12
        pxor      %xmm0, %xmm4
        por       %xmm5, %xmm12
        pand      %xmm7, %xmm4
        movdqa    %xmm10, %xmm5
        movdqa    %xmm10, %xmm1
        pxor      %xmm0, %xmm4
        pslld     $5, %xmm5
        psrld     $27, %xmm1
        movdqa    %xmm3, 288(%rsp)
        por       %xmm1, %xmm5
        paddd     %xmm4, %xmm15
        movdqa    %xmm7, %xmm1
        movdqa    496(%rsp), %xmm4
        pxor      %xmm6, %xmm3
        pslld     $30, %xmm1
        psrld     $2, %xmm7
        pxor      %xmm4, %xmm3
        paddd     %xmm5, %xmm15
        por       %xmm7, %xmm1
        pxor      %xmm11, %xmm3
        movdqa    %xmm6, 384(%rsp)
        paddd     %xmm8, %xmm15
        movdqa    %xmm3, %xmm6
        movdqa    %xmm1, %xmm5
        paddd     %xmm2, %xmm15
        psrld     $31, %xmm6
        paddd     %xmm3, %xmm3
        pxor      %xmm14, %xmm5
        por       %xmm6, %xmm3
        pand      %xmm10, %xmm5
        movdqa    %xmm15, %xmm7
        movdqa    %xmm15, %xmm2
        movdqa    %xmm10, %xmm6
        pxor      %xmm14, %xmm5
        pslld     $5, %xmm7
        psrld     $27, %xmm2
        pslld     $30, %xmm6
        psrld     $2, %xmm10
        movdqa    %xmm13, 304(%rsp)
        por       %xmm2, %xmm7
        pxor      256(%rsp), %xmm13
        paddd     %xmm5, %xmm0
        por       %xmm10, %xmm6
        paddd     %xmm7, %xmm0
        movdqa    512(%rsp), %xmm10
        paddd     %xmm8, %xmm0
        pxor      %xmm10, %xmm13
        paddd     %xmm11, %xmm0
        pxor      %xmm9, %xmm13
        movdqa    %xmm6, %xmm11
        movdqa    %xmm13, %xmm2
        paddd     %xmm13, %xmm13
        psrld     $31, %xmm2
        pxor      %xmm1, %xmm11
        por       %xmm2, %xmm13
        pand      %xmm15, %xmm11
        movdqa    %xmm0, %xmm2
        movdqa    %xmm0, %xmm5
        pxor      %xmm1, %xmm11
        pslld     $5, %xmm2
        psrld     $27, %xmm5
        paddd     %xmm11, %xmm14
        por       %xmm5, %xmm2
        movdqa    %xmm12, 320(%rsp)
        paddd     %xmm2, %xmm14
        pxor      272(%rsp), %xmm12
        movdqa    %xmm15, %xmm2
        movdqa    528(%rsp), %xmm5
        pslld     $30, %xmm2
        psrld     $2, %xmm15
        pxor      %xmm5, %xmm12
        paddd     %xmm8, %xmm14
        por       %xmm15, %xmm2
        pxor      %xmm4, %xmm12
        paddd     %xmm9, %xmm14
        movdqa    %xmm12, %xmm7
        movdqa    %xmm2, %xmm9
        psrld     $31, %xmm7
        paddd     %xmm12, %xmm12
        pxor      %xmm6, %xmm9
        por       %xmm7, %xmm12
        pand      %xmm0, %xmm9
        movdqa    %xmm14, %xmm11
        movdqa    %xmm14, %xmm7
        pxor      %xmm6, %xmm9
        pslld     $5, %xmm11
        psrld     $27, %xmm7
        por       %xmm7, %xmm11
        paddd     %xmm9, %xmm1
        paddd     %xmm11, %xmm1
        movdqa    %xmm3, 368(%rsp)
        paddd     %xmm8, %xmm1
        pxor      352(%rsp), %xmm3
        paddd     %xmm4, %xmm1
        pxor      448(%rsp), %xmm3
        movdqa    %xmm0, %xmm4
        pslld     $30, %xmm4
        psrld     $2, %xmm0
        pxor      %xmm10, %xmm3
        por       %xmm0, %xmm4
        movdqa    %xmm3, %xmm0
        paddd     %xmm3, %xmm3
        psrld     $31, %xmm0
        movdqa    %xmm4, %xmm7
        por       %xmm0, %xmm3
        pxor      %xmm2, %xmm7
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm0
        pand      %xmm14, %xmm7
        pslld     $5, %xmm9
        psrld     $27, %xmm0
        pxor      %xmm2, %xmm7
        por       %xmm0, %xmm9
        movdqa    %xmm14, %xmm0
        paddd     %xmm7, %xmm6
        pslld     $30, %xmm0
        psrld     $2, %xmm14
        paddd     %xmm9, %xmm6
        por       %xmm14, %xmm0
        paddd     %xmm8, %xmm6
        movdqa    %xmm0, %xmm14
        paddd     %xmm10, %xmm6
        movdqa    %xmm13, 464(%rsp)
        pxor      %xmm4, %xmm14
        pxor      336(%rsp), %xmm13
        pand      %xmm1, %xmm14
        movdqa    544(%rsp), %xmm10
        movdqa    %xmm6, %xmm15
        movdqa    %xmm12, 432(%rsp)
        pxor      %xmm10, %xmm13
        movdqa    %xmm6, %xmm12
        pxor      %xmm5, %xmm13
        pxor      %xmm4, %xmm14
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        movdqa    %xmm13, %xmm11
        por       %xmm12, %xmm15
        paddd     %xmm14, %xmm2
        psrld     $31, %xmm11
        paddd     %xmm13, %xmm13
        paddd     %xmm15, %xmm2
        por       %xmm11, %xmm13
        movdqa    %xmm3, 416(%rsp)
        paddd     %xmm8, %xmm2
..B5.26:
        paddd     %xmm5, %xmm2
        movdqa    %xmm1, %xmm5
        pslld     $30, %xmm5
        psrld     $2, %xmm1
        por       %xmm1, %xmm5
        movdqa    %xmm0, %xmm14
        movdqa    432(%rsp), %xmm1
        pxor      %xmm5, %xmm14
        movdqa    %xmm1, %xmm7
        movdqa    %xmm2, %xmm11
        pxor      288(%rsp), %xmm7
        pxor      %xmm6, %xmm14
        movdqa    400(%rsp), %xmm3
        psrld     $27, %xmm11
        movdqa    448(%rsp), %xmm15
        pxor      %xmm3, %xmm7
        pxor      %xmm15, %xmm7
        paddd     %xmm14, %xmm4
        movdqa    %xmm7, %xmm8
        paddd     %xmm7, %xmm7
        psrld     $31, %xmm8
        por       %xmm8, %xmm7
        movdqa    %xmm2, %xmm8
        pslld     $5, %xmm8
        por       %xmm11, %xmm8
        paddd     %xmm8, %xmm4
        movdqa    %xmm6, %xmm8
        pslld     $30, %xmm8
        psrld     $2, %xmm6
        por       %xmm6, %xmm8
        movdqa    416(%rsp), %xmm6
        movdqa    %xmm8, %xmm14
        pxor      304(%rsp), %xmm6
        pxor      %xmm5, %xmm14
        movdqa    384(%rsp), %xmm11
        pxor      %xmm2, %xmm14
        pxor      %xmm11, %xmm6
        paddd     %xmm14, %xmm0
        movdqa    .L_2il0floatpacket.555(%rip), %xmm9
        pxor      %xmm10, %xmm6
        paddd     %xmm9, %xmm4
        movdqa    %xmm6, %xmm12
        paddd     %xmm15, %xmm4
        psrld     $31, %xmm12
        paddd     %xmm6, %xmm6
        movdqa    %xmm4, %xmm15
        por       %xmm12, %xmm6
        movdqa    %xmm4, %xmm12
        pslld     $5, %xmm12
        psrld     $27, %xmm15
        por       %xmm15, %xmm12
        paddd     %xmm12, %xmm0
        movdqa    %xmm13, 208(%rsp)
        paddd     %xmm9, %xmm0
        pxor      320(%rsp), %xmm13
        paddd     %xmm10, %xmm0
        movdqa    256(%rsp), %xmm14
        movdqa    %xmm2, %xmm10
        pxor      %xmm14, %xmm13
        pslld     $30, %xmm10
        psrld     $2, %xmm2
        pxor      %xmm3, %xmm13
        por       %xmm2, %xmm10
        movdqa    %xmm13, %xmm2
        psrld     $31, %xmm2
        paddd     %xmm13, %xmm13
        movdqa    %xmm10, %xmm12
        por       %xmm2, %xmm13
        pxor      %xmm8, %xmm12
        movdqa    %xmm0, %xmm2
        movdqa    %xmm0, %xmm15
        pxor      %xmm4, %xmm12
        pslld     $5, %xmm2
        psrld     $27, %xmm15
        por       %xmm15, %xmm2
        paddd     %xmm12, %xmm5
        movdqa    368(%rsp), %xmm12
        paddd     %xmm2, %xmm5
        movdqa    272(%rsp), %xmm15
        paddd     %xmm9, %xmm5
        pxor      %xmm7, %xmm12
        paddd     %xmm3, %xmm5
        movdqa    %xmm4, %xmm3
        pxor      %xmm15, %xmm12
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        pxor      %xmm11, %xmm12
        por       %xmm4, %xmm3
        movdqa    %xmm12, %xmm4
        paddd     %xmm12, %xmm12
        movdqa    %xmm7, 224(%rsp)
        psrld     $31, %xmm4
        movdqa    %xmm3, %xmm7
        por       %xmm4, %xmm12
        pxor      %xmm10, %xmm7
        movdqa    %xmm5, %xmm4
        movdqa    %xmm5, %xmm2
        pxor      %xmm0, %xmm7
        pslld     $5, %xmm4
        psrld     $27, %xmm2
        por       %xmm2, %xmm4
        paddd     %xmm7, %xmm8
        paddd     %xmm4, %xmm8
        movdqa    %xmm0, %xmm4
        movdqa    464(%rsp), %xmm7
        paddd     %xmm9, %xmm8
        paddd     %xmm11, %xmm8
        pxor      %xmm6, %xmm7
        movdqa    352(%rsp), %xmm11
        pslld     $30, %xmm4
        pxor      %xmm11, %xmm7
        psrld     $2, %xmm0
        pxor      %xmm14, %xmm7
        por       %xmm0, %xmm4
        movdqa    %xmm7, %xmm0
        paddd     %xmm7, %xmm7
        movdqa    %xmm6, 240(%rsp)
        psrld     $31, %xmm0
        movdqa    %xmm4, %xmm6
        por       %xmm0, %xmm7
        pxor      %xmm3, %xmm6
        movdqa    %xmm8, %xmm0
        movdqa    %xmm8, %xmm2
        pxor      %xmm5, %xmm6
        pslld     $5, %xmm0
        psrld     $27, %xmm2
        por       %xmm2, %xmm0
        paddd     %xmm6, %xmm10
        movdqa    336(%rsp), %xmm6
        pxor      %xmm13, %xmm1
        paddd     %xmm0, %xmm10
        movdqa    %xmm5, %xmm0
        pxor      %xmm6, %xmm1
        pslld     $30, %xmm0
        psrld     $2, %xmm5
        pxor      %xmm15, %xmm1
        paddd     %xmm9, %xmm10
        por       %xmm5, %xmm0
        movdqa    %xmm1, %xmm5
        paddd     %xmm14, %xmm10
        psrld     $31, %xmm5
        paddd     %xmm1, %xmm1
        movdqa    %xmm0, %xmm2
        por       %xmm5, %xmm1
        pxor      %xmm4, %xmm2
        movdqa    %xmm10, %xmm5
        movdqa    %xmm10, %xmm14
        pxor      %xmm8, %xmm2
        pslld     $5, %xmm5
        psrld     $27, %xmm14
        por       %xmm14, %xmm5
        paddd     %xmm2, %xmm3
        paddd     %xmm5, %xmm3
        movdqa    %xmm8, %xmm5
        movdqa    416(%rsp), %xmm2
        paddd     %xmm9, %xmm3
        paddd     %xmm15, %xmm3
        pxor      %xmm12, %xmm2
        movdqa    288(%rsp), %xmm15
        pslld     $30, %xmm5
        pxor      %xmm15, %xmm2
        psrld     $2, %xmm8
        pxor      %xmm11, %xmm2
        por       %xmm8, %xmm5
        movdqa    %xmm2, %xmm8
        paddd     %xmm2, %xmm2
        psrld     $31, %xmm8
        movdqa    %xmm5, %xmm14
        movdqa    %xmm12, 496(%rsp)
        por       %xmm8, %xmm2
        pxor      %xmm0, %xmm14
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm12
        pxor      %xmm10, %xmm14
        pslld     $5, %xmm8
        psrld     $27, %xmm12
        por       %xmm12, %xmm8
        paddd     %xmm14, %xmm4
        paddd     %xmm8, %xmm4
        paddd     %xmm9, %xmm4
        paddd     %xmm11, %xmm4
        movdqa    %xmm10, %xmm11
        movdqa    208(%rsp), %xmm8
        pslld     $30, %xmm11
        psrld     $2, %xmm10
        pxor      %xmm7, %xmm8
        por       %xmm10, %xmm11
        movdqa    %xmm4, %xmm12
        movdqa    304(%rsp), %xmm10
        movdqa    %xmm11, %xmm14
        pxor      %xmm10, %xmm8
        pxor      %xmm5, %xmm14
        pxor      %xmm6, %xmm8
        pxor      %xmm3, %xmm14
        movdqa    %xmm7, 512(%rsp)
        movdqa    %xmm8, %xmm7
        psrld     $31, %xmm7
        paddd     %xmm8, %xmm8
        por       %xmm7, %xmm8
        movdqa    %xmm4, %xmm7
        pslld     $5, %xmm7
        psrld     $27, %xmm12
        movdqa    %xmm1, 160(%rsp)
        por       %xmm12, %xmm7
        pxor      224(%rsp), %xmm1
        paddd     %xmm14, %xmm0
        movdqa    320(%rsp), %xmm14
        paddd     %xmm7, %xmm0
        movdqa    %xmm3, %xmm7
        pxor      %xmm14, %xmm1
        pslld     $30, %xmm7
        psrld     $2, %xmm3
        pxor      %xmm15, %xmm1
        paddd     %xmm9, %xmm0
        por       %xmm3, %xmm7
        movdqa    %xmm1, %xmm3
        paddd     %xmm6, %xmm0
        psrld     $31, %xmm3
        paddd     %xmm1, %xmm1
        movdqa    %xmm7, %xmm12
        por       %xmm3, %xmm1
        pxor      %xmm11, %xmm12
        movdqa    %xmm0, %xmm3
        movdqa    %xmm0, %xmm6
        pxor      %xmm4, %xmm12
        pslld     $5, %xmm3
        psrld     $27, %xmm6
        paddd     %xmm12, %xmm5
        movdqa    %xmm2, 528(%rsp)
        por       %xmm6, %xmm3
        pxor      240(%rsp), %xmm2
        paddd     %xmm3, %xmm5
        movdqa    368(%rsp), %xmm6
        paddd     %xmm9, %xmm5
        pxor      %xmm6, %xmm2
        movdqa    %xmm4, %xmm3
        pxor      %xmm10, %xmm2
        paddd     %xmm15, %xmm5
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        movdqa    %xmm2, %xmm15
        por       %xmm4, %xmm3
        psrld     $31, %xmm15
        paddd     %xmm2, %xmm2
        por       %xmm15, %xmm2
        movdqa    %xmm3, %xmm12
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm4
        pxor      %xmm7, %xmm12
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        pxor      %xmm0, %xmm12
        por       %xmm4, %xmm15
        movdqa    %xmm8, %xmm4
        paddd     %xmm12, %xmm11
        pxor      %xmm13, %xmm4
        movdqa    464(%rsp), %xmm12
        paddd     %xmm15, %xmm11
        movdqa    %xmm0, %xmm15
        pxor      %xmm12, %xmm4
        paddd     %xmm9, %xmm11
        pslld     $30, %xmm15
        psrld     $2, %xmm0
        pxor      %xmm14, %xmm4
        paddd     %xmm10, %xmm11
        por       %xmm0, %xmm15
        movdqa    %xmm4, %xmm10
        paddd     %xmm4, %xmm4
        psrld     $31, %xmm10
        movdqa    %xmm15, %xmm0
        movdqa    %xmm13, 480(%rsp)
        por       %xmm10, %xmm4
        pxor      %xmm3, %xmm0
        movdqa    %xmm11, %xmm10
        movdqa    %xmm11, %xmm13
        pxor      %xmm5, %xmm0
        pslld     $5, %xmm10
        psrld     $27, %xmm13
        por       %xmm13, %xmm10
        paddd     %xmm0, %xmm7
        movdqa    %xmm1, 544(%rsp)
        paddd     %xmm10, %xmm7
        pxor      496(%rsp), %xmm1
        movdqa    %xmm5, %xmm0
        movdqa    432(%rsp), %xmm10
        pslld     $30, %xmm0
        pxor      %xmm10, %xmm1
        psrld     $2, %xmm5
        pxor      %xmm6, %xmm1
        por       %xmm5, %xmm0
        movdqa    %xmm1, %xmm5
        paddd     %xmm9, %xmm7
        psrld     $31, %xmm5
        paddd     %xmm1, %xmm1
        paddd     %xmm14, %xmm7
        por       %xmm5, %xmm1
        movdqa    %xmm0, %xmm5
        movdqa    %xmm7, %xmm13
        pxor      %xmm15, %xmm5
        movdqa    %xmm7, %xmm14
        pxor      %xmm11, %xmm5
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        paddd     %xmm5, %xmm3
        movdqa    %xmm2, 560(%rsp)
        por       %xmm14, %xmm13
        pxor      512(%rsp), %xmm2
        paddd     %xmm13, %xmm3
        movdqa    416(%rsp), %xmm14
        movdqa    %xmm11, %xmm13
        pxor      %xmm14, %xmm2
        pslld     $30, %xmm13
        psrld     $2, %xmm11
        pxor      %xmm12, %xmm2
        paddd     %xmm9, %xmm3
        por       %xmm11, %xmm13
        movdqa    %xmm2, %xmm11
        paddd     %xmm6, %xmm3
        psrld     $31, %xmm11
        paddd     %xmm2, %xmm2
        por       %xmm11, %xmm2
        movdqa    %xmm13, %xmm6
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm5
        pxor      %xmm0, %xmm6
        pslld     $5, %xmm11
        psrld     $27, %xmm5
        pxor      %xmm7, %xmm6
        movdqa    %xmm4, 128(%rsp)
        por       %xmm5, %xmm11
        pxor      160(%rsp), %xmm4
        paddd     %xmm6, %xmm15
        movdqa    208(%rsp), %xmm5
        movdqa    %xmm7, %xmm6
        pxor      %xmm5, %xmm4
        pslld     $30, %xmm6
        psrld     $2, %xmm7
        pxor      %xmm10, %xmm4
        paddd     %xmm11, %xmm15
        por       %xmm7, %xmm6
        movdqa    %xmm4, %xmm7
        paddd     %xmm9, %xmm15
        psrld     $31, %xmm7
        paddd     %xmm4, %xmm4
        paddd     %xmm12, %xmm15
        por       %xmm7, %xmm4
        movdqa    %xmm6, %xmm7
        movdqa    %xmm15, %xmm11
        pxor      %xmm13, %xmm7
        movdqa    %xmm15, %xmm12
        pxor      %xmm3, %xmm7
        pslld     $5, %xmm11
        psrld     $27, %xmm12
        paddd     %xmm7, %xmm0
        por       %xmm12, %xmm11
        paddd     %xmm11, %xmm0
        movdqa    %xmm1, 16(%rsp)
        paddd     %xmm9, %xmm0
        pxor      528(%rsp), %xmm1
        paddd     %xmm10, %xmm0
        movdqa    224(%rsp), %xmm12
        movdqa    %xmm3, %xmm10
        pxor      %xmm12, %xmm1
        pslld     $30, %xmm10
        psrld     $2, %xmm3
        pxor      %xmm14, %xmm1
        por       %xmm3, %xmm10
        movdqa    %xmm1, %xmm3
        psrld     $31, %xmm3
        paddd     %xmm1, %xmm1
        por       %xmm3, %xmm1
        movdqa    %xmm0, %xmm3
        movdqa    %xmm0, %xmm7
        movdqa    %xmm10, %xmm11
        pslld     $5, %xmm3
        psrld     $27, %xmm7
        pxor      %xmm6, %xmm11
        por       %xmm7, %xmm3
        movdqa    %xmm2, %xmm7
        pxor      %xmm15, %xmm11
        movdqa    %xmm8, 144(%rsp)
        pxor      %xmm8, %xmm7
        movdqa    240(%rsp), %xmm8
        paddd     %xmm11, %xmm13
        movdqa    %xmm15, %xmm11
        pxor      %xmm8, %xmm7
        paddd     %xmm3, %xmm13
        pslld     $30, %xmm11
        psrld     $2, %xmm15
        pxor      %xmm5, %xmm7
        paddd     %xmm9, %xmm13
        por       %xmm15, %xmm11
        movdqa    %xmm7, %xmm15
        paddd     %xmm14, %xmm13
        psrld     $31, %xmm15
        paddd     %xmm7, %xmm7
        movdqa    %xmm11, %xmm14
        por       %xmm15, %xmm7
        pxor      %xmm10, %xmm14
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm3
        pxor      %xmm0, %xmm14
        pslld     $5, %xmm15
        psrld     $27, %xmm3
        por       %xmm3, %xmm15
        paddd     %xmm14, %xmm6
        paddd     %xmm15, %xmm6
        movdqa    %xmm0, %xmm3
        paddd     %xmm9, %xmm6
        pslld     $30, %xmm3
        movdqa    %xmm4, 48(%rsp)
        paddd     %xmm5, %xmm6
        pxor      544(%rsp), %xmm4
        psrld     $2, %xmm0
        movdqa    480(%rsp), %xmm5
        por       %xmm0, %xmm3
        pxor      %xmm5, %xmm4
        movdqa    %xmm3, %xmm14
        pxor      %xmm12, %xmm4
        pxor      %xmm11, %xmm14
        movdqa    %xmm4, %xmm0
        paddd     %xmm4, %xmm4
        psrld     $31, %xmm0
        movdqa    %xmm6, %xmm15
        por       %xmm0, %xmm4
        movdqa    %xmm6, %xmm0
        pxor      %xmm13, %xmm14
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm10
        por       %xmm15, %xmm0
        paddd     %xmm0, %xmm10
        movdqa    %xmm13, %xmm0
        pslld     $30, %xmm0
        psrld     $2, %xmm13
        movdqa    %xmm1, 64(%rsp)
        por       %xmm13, %xmm0
        pxor      560(%rsp), %xmm1
        paddd     %xmm9, %xmm10
        movdqa    496(%rsp), %xmm13
        paddd     %xmm12, %xmm10
        pxor      %xmm13, %xmm1
        movdqa    %xmm0, %xmm14
        pxor      %xmm8, %xmm1
        pxor      %xmm3, %xmm14
        movdqa    %xmm1, %xmm12
        paddd     %xmm1, %xmm1
        psrld     $31, %xmm12
        movdqa    %xmm10, %xmm15
        por       %xmm12, %xmm1
        movdqa    %xmm10, %xmm12
        pxor      %xmm6, %xmm14
        pslld     $5, %xmm12
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm11
        por       %xmm15, %xmm12
        paddd     %xmm12, %xmm11
        movdqa    %xmm7, 80(%rsp)
        paddd     %xmm9, %xmm11
        pxor      128(%rsp), %xmm7
        paddd     %xmm8, %xmm11
        movdqa    512(%rsp), %xmm12
        movdqa    %xmm6, %xmm8
        pxor      %xmm12, %xmm7
        pslld     $30, %xmm8
        psrld     $2, %xmm6
        pxor      %xmm5, %xmm7
        por       %xmm6, %xmm8
        movdqa    %xmm7, %xmm6
        psrld     $31, %xmm6
        paddd     %xmm7, %xmm7
        movdqa    %xmm8, %xmm14
        por       %xmm6, %xmm7
        pxor      %xmm0, %xmm14
        movdqa    %xmm11, %xmm6
        movdqa    %xmm11, %xmm15
        pxor      %xmm10, %xmm14
        pslld     $5, %xmm6
        psrld     $27, %xmm15
        por       %xmm15, %xmm6
        paddd     %xmm14, %xmm3
        paddd     %xmm6, %xmm3
        movdqa    %xmm4, 96(%rsp)
        paddd     %xmm9, %xmm3
        pxor      16(%rsp), %xmm4
        paddd     %xmm5, %xmm3
        movdqa    160(%rsp), %xmm15
        movdqa    %xmm10, %xmm5
        pxor      %xmm15, %xmm4
        pslld     $30, %xmm5
        psrld     $2, %xmm10
        pxor      %xmm13, %xmm4
        por       %xmm10, %xmm5
        movdqa    %xmm4, %xmm6
        psrld     $31, %xmm6
        paddd     %xmm4, %xmm4
        movdqa    %xmm5, %xmm10
        por       %xmm6, %xmm4
        pxor      %xmm8, %xmm10
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm6
        pxor      %xmm11, %xmm10
        pslld     $5, %xmm14
        psrld     $27, %xmm6
        por       %xmm6, %xmm14
        paddd     %xmm10, %xmm0
        movdqa    %xmm11, %xmm6
        paddd     %xmm14, %xmm0
        pslld     $30, %xmm6
        psrld     $2, %xmm11
        paddd     %xmm9, %xmm0
        por       %xmm11, %xmm6
        movdqa    %xmm3, %xmm10
        paddd     %xmm13, %xmm0
        movdqa    %xmm3, %xmm13
        por       %xmm6, %xmm10
        pand      %xmm6, %xmm13
        pand      %xmm5, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm3, %xmm10
        pslld     $30, %xmm10
        psrld     $2, %xmm3
        por       %xmm3, %xmm10
        movdqa    %xmm7, %xmm3
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm11
        pxor      48(%rsp), %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm11
        paddd     %xmm13, %xmm8
        movdqa    %xmm2, 32(%rsp)
        por       %xmm11, %xmm14
        movdqa    %xmm1, 112(%rsp)
        pxor      %xmm2, %xmm1
        movdqa    528(%rsp), %xmm2
        paddd     %xmm14, %xmm8
        pxor      144(%rsp), %xmm3
        pxor      %xmm2, %xmm1
        movdqa    %xmm4, (%rsp)
        pxor      %xmm15, %xmm3
        movdqa    .L_2il0floatpacket.556(%rip), %xmm4
        pxor      %xmm12, %xmm1
        movdqa    %xmm3, %xmm15
        paddd     %xmm4, %xmm8
        movdqa    %xmm1, %xmm9
        psrld     $31, %xmm15
        paddd     %xmm3, %xmm3
        paddd     %xmm12, %xmm8
        movdqa    %xmm0, %xmm12
        psrld     $31, %xmm9
        paddd     %xmm1, %xmm1
        por       %xmm15, %xmm3
        movdqa    %xmm3, 192(%rsp)
        movdqa    %xmm0, %xmm3
        por       %xmm10, %xmm12
        por       %xmm9, %xmm1
        movdqa    %xmm1, 176(%rsp)
        pand      %xmm10, %xmm3
        pand      %xmm6, %xmm12
        movdqa    %xmm8, %xmm9
        movdqa    %xmm8, %xmm1
        por       %xmm12, %xmm3
        pslld     $5, %xmm9
        psrld     $27, %xmm1
        movdqa    544(%rsp), %xmm12
        por       %xmm1, %xmm9
        movdqa    560(%rsp), %xmm1
        paddd     %xmm3, %xmm5
..B5.25:
        movdqa    (%rsp), %xmm15
        movdqa    %xmm0, %xmm11
        pxor      64(%rsp), %xmm15
        paddd     %xmm9, %xmm5
        pxor      %xmm12, %xmm15
        pslld     $30, %xmm11
        pxor      %xmm2, %xmm15
        psrld     $2, %xmm0
        movdqa    %xmm15, %xmm9
        por       %xmm0, %xmm11
        psrld     $31, %xmm9
        paddd     %xmm15, %xmm15
        movdqa    %xmm8, %xmm3
        paddd     %xmm4, %xmm5
        por       %xmm9, %xmm15
        movdqa    %xmm8, %xmm9
        por       %xmm11, %xmm3
        pand      %xmm11, %xmm9
        paddd     160(%rsp), %xmm5
        pand      %xmm10, %xmm3
        por       %xmm3, %xmm9
        movdqa    %xmm5, %xmm0
        movdqa    %xmm5, %xmm13
        pslld     $5, %xmm0
        psrld     $27, %xmm13
        paddd     %xmm9, %xmm6
        movdqa    %xmm8, %xmm9
        por       %xmm13, %xmm0
        movdqa    176(%rsp), %xmm3
        pslld     $30, %xmm9
        psrld     $2, %xmm8
        paddd     %xmm0, %xmm6
        pxor      80(%rsp), %xmm3
        por       %xmm8, %xmm9
        movdqa    %xmm5, %xmm0
        paddd     %xmm4, %xmm6
        movdqa    144(%rsp), %xmm8
        pxor      %xmm1, %xmm3
        movdqa    %xmm5, %xmm14
        por       %xmm9, %xmm0
        paddd     %xmm2, %xmm6
        pxor      %xmm8, %xmm3
        pand      %xmm9, %xmm14
        pand      %xmm11, %xmm0
        movdqa    %xmm3, %xmm2
        por       %xmm0, %xmm14
        movdqa    %xmm6, %xmm0
        movdqa    %xmm6, %xmm13
        psrld     $31, %xmm2
        paddd     %xmm3, %xmm3
        pslld     $5, %xmm0
        psrld     $27, %xmm13
        por       %xmm2, %xmm3
        por       %xmm13, %xmm0
        paddd     %xmm14, %xmm10
        movdqa    %xmm5, %xmm2
        paddd     %xmm0, %xmm10
        pslld     $30, %xmm2
        psrld     $2, %xmm5
        paddd     %xmm4, %xmm10
        por       %xmm5, %xmm2
        paddd     %xmm8, %xmm10
        movdqa    192(%rsp), %xmm5
        movdqa    %xmm6, %xmm14
        pxor      96(%rsp), %xmm5
        movdqa    %xmm6, %xmm0
        movdqa    128(%rsp), %xmm8
        por       %xmm2, %xmm14
        pxor      %xmm8, %xmm5
        pand      %xmm2, %xmm0
        pxor      %xmm12, %xmm5
        pand      %xmm9, %xmm14
        movdqa    %xmm5, %xmm13
        paddd     %xmm5, %xmm5
        psrld     $31, %xmm13
        por       %xmm14, %xmm0
        por       %xmm13, %xmm5
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm13
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm0, %xmm11
        por       %xmm13, %xmm14
        movdqa    %xmm6, %xmm0
        paddd     %xmm14, %xmm11
        pslld     $30, %xmm0
        paddd     %xmm4, %xmm11
        psrld     $2, %xmm6
        paddd     %xmm12, %xmm11
        por       %xmm6, %xmm0
        movdqa    112(%rsp), %xmm12
        movdqa    %xmm10, %xmm13
        movdqa    16(%rsp), %xmm6
        pxor      %xmm15, %xmm12
        pxor      %xmm6, %xmm12
        movdqa    %xmm10, %xmm14
        pxor      %xmm1, %xmm12
        por       %xmm0, %xmm13
        movdqa    %xmm15, 432(%rsp)
        movdqa    %xmm12, %xmm15
        psrld     $31, %xmm15
        paddd     %xmm12, %xmm12
        pand      %xmm0, %xmm14
        pand      %xmm2, %xmm13
        por       %xmm15, %xmm12
        por       %xmm13, %xmm14
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        por       %xmm15, %xmm13
        paddd     %xmm14, %xmm9
        paddd     %xmm13, %xmm9
        movdqa    %xmm11, %xmm15
        paddd     %xmm4, %xmm9
        movdqa    %xmm11, %xmm13
        paddd     %xmm1, %xmm9
        movdqa    %xmm10, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm10
        movdqa    %xmm7, 416(%rsp)
        por       %xmm10, %xmm1
        movdqa    32(%rsp), %xmm10
        pxor      %xmm3, %xmm7
        pxor      %xmm10, %xmm7
        por       %xmm1, %xmm15
        pxor      %xmm8, %xmm7
        pand      %xmm1, %xmm13
        movdqa    %xmm7, %xmm14
        paddd     %xmm7, %xmm7
        psrld     $31, %xmm14
        pand      %xmm0, %xmm15
        por       %xmm14, %xmm7
        por       %xmm15, %xmm13
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm14
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        por       %xmm14, %xmm15
        paddd     %xmm13, %xmm2
        paddd     %xmm15, %xmm2
        movdqa    %xmm9, %xmm13
        movdqa    (%rsp), %xmm15
        paddd     %xmm4, %xmm2
        movdqa    48(%rsp), %xmm14
        paddd     %xmm8, %xmm2
        movdqa    %xmm11, %xmm8
        pxor      %xmm5, %xmm15
        pslld     $30, %xmm8
        psrld     $2, %xmm11
        pxor      %xmm14, %xmm15
        por       %xmm11, %xmm8
        pxor      %xmm6, %xmm15
        movdqa    %xmm9, %xmm11
        movdqa    %xmm5, 464(%rsp)
        movdqa    %xmm15, %xmm5
        por       %xmm8, %xmm13
        psrld     $31, %xmm5
        paddd     %xmm15, %xmm15
        pand      %xmm8, %xmm11
        pand      %xmm1, %xmm13
        por       %xmm5, %xmm15
        por       %xmm13, %xmm11
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm5
        pslld     $5, %xmm13
        psrld     $27, %xmm5
        paddd     %xmm11, %xmm0
        por       %xmm5, %xmm13
        movdqa    %xmm2, %xmm11
        paddd     %xmm13, %xmm0
        movdqa    %xmm9, %xmm13
        paddd     %xmm4, %xmm0
        pslld     $30, %xmm13
        paddd     %xmm6, %xmm0
        psrld     $2, %xmm9
        movdqa    176(%rsp), %xmm6
        por       %xmm9, %xmm13
        movdqa    %xmm12, 480(%rsp)
        pxor      %xmm12, %xmm6
        movdqa    64(%rsp), %xmm12
        por       %xmm13, %xmm11
        pxor      %xmm12, %xmm6
        pand      %xmm8, %xmm11
        pxor      %xmm10, %xmm6
        movdqa    %xmm0, %xmm5
        movdqa    %xmm6, %xmm9
        paddd     %xmm6, %xmm6
        psrld     $31, %xmm9
        psrld     $27, %xmm5
        por       %xmm9, %xmm6
        movdqa    %xmm2, %xmm9
        pand      %xmm13, %xmm9
        por       %xmm11, %xmm9
        movdqa    %xmm0, %xmm11
        pslld     $5, %xmm11
        paddd     %xmm9, %xmm1
        por       %xmm5, %xmm11
        movdqa    %xmm0, %xmm5
        paddd     %xmm11, %xmm1
        movdqa    %xmm0, %xmm11
        paddd     %xmm4, %xmm1
        paddd     %xmm10, %xmm1
        movdqa    %xmm2, %xmm10
        pslld     $30, %xmm10
        psrld     $2, %xmm2
        por       %xmm2, %xmm10
        movdqa    192(%rsp), %xmm2
        por       %xmm10, %xmm11
        movdqa    %xmm7, 368(%rsp)
        pxor      %xmm7, %xmm2
        movdqa    80(%rsp), %xmm7
        pand      %xmm10, %xmm5
        pxor      %xmm7, %xmm2
        pand      %xmm13, %xmm11
        pxor      %xmm14, %xmm2
        por       %xmm11, %xmm5
        movdqa    %xmm2, %xmm9
        paddd     %xmm2, %xmm2
        psrld     $31, %xmm9
        movdqa    %xmm1, %xmm11
        por       %xmm9, %xmm2
        movdqa    %xmm1, %xmm9
        pslld     $5, %xmm11
        psrld     $27, %xmm9
        por       %xmm9, %xmm11
        paddd     %xmm5, %xmm8
        paddd     %xmm11, %xmm8
        movdqa    %xmm1, %xmm11
        paddd     %xmm4, %xmm8
        movdqa    %xmm1, %xmm9
        paddd     %xmm14, %xmm8
        movdqa    %xmm0, %xmm14
        pslld     $30, %xmm14
        psrld     $2, %xmm0
        movdqa    %xmm15, 352(%rsp)
        por       %xmm0, %xmm14
        pxor      432(%rsp), %xmm15
        por       %xmm14, %xmm11
        movdqa    96(%rsp), %xmm0
        pand      %xmm14, %xmm9
        pxor      %xmm0, %xmm15
        pand      %xmm10, %xmm11
        pxor      %xmm12, %xmm15
        por       %xmm11, %xmm9
        movdqa    %xmm15, %xmm5
        paddd     %xmm15, %xmm15
        psrld     $31, %xmm5
        movdqa    %xmm8, %xmm11
        por       %xmm5, %xmm15
        movdqa    %xmm8, %xmm5
        pslld     $5, %xmm11
        psrld     $27, %xmm5
        por       %xmm5, %xmm11
        movdqa    %xmm1, %xmm5
        paddd     %xmm9, %xmm13
        pslld     $30, %xmm5
        psrld     $2, %xmm1
        movdqa    %xmm6, %xmm9
        por       %xmm1, %xmm5
        pxor      %xmm3, %xmm9
        movdqa    112(%rsp), %xmm1
        paddd     %xmm11, %xmm13
        pxor      %xmm1, %xmm9
        paddd     %xmm4, %xmm13
        pxor      %xmm7, %xmm9
        movdqa    %xmm8, %xmm11
        movdqa    %xmm3, 448(%rsp)
        paddd     %xmm12, %xmm13
        movdqa    %xmm9, %xmm12
        movdqa    %xmm8, %xmm3
        por       %xmm5, %xmm11
        psrld     $31, %xmm12
        paddd     %xmm9, %xmm9
        pand      %xmm5, %xmm3
        pand      %xmm14, %xmm11
        por       %xmm12, %xmm9
        por       %xmm11, %xmm3
        movdqa    %xmm13, %xmm11
        movdqa    %xmm13, %xmm12
        pslld     $5, %xmm11
        psrld     $27, %xmm12
        paddd     %xmm3, %xmm10
        por       %xmm12, %xmm11
        movdqa    %xmm8, %xmm3
        movdqa    %xmm2, 304(%rsp)
        paddd     %xmm11, %xmm10
        pxor      464(%rsp), %xmm2
        pslld     $30, %xmm3
        movdqa    416(%rsp), %xmm11
        psrld     $2, %xmm8
        pxor      %xmm11, %xmm2
        paddd     %xmm4, %xmm10
        pxor      %xmm0, %xmm2
        por       %xmm8, %xmm3
        movdqa    %xmm2, %xmm8
        paddd     %xmm7, %xmm10
        psrld     $31, %xmm8
        paddd     %xmm2, %xmm2
        movdqa    %xmm13, %xmm7
        por       %xmm8, %xmm2
        movdqa    %xmm13, %xmm8
        por       %xmm3, %xmm7
        pand      %xmm3, %xmm8
        pand      %xmm5, %xmm7
        por       %xmm7, %xmm8
        movdqa    %xmm10, %xmm7
        movdqa    %xmm10, %xmm12
        pslld     $5, %xmm7
        psrld     $27, %xmm12
        paddd     %xmm8, %xmm14
        por       %xmm12, %xmm7
        movdqa    %xmm10, %xmm12
        paddd     %xmm7, %xmm14
        movdqa    %xmm10, %xmm7
        paddd     %xmm4, %xmm14
        paddd     %xmm0, %xmm14
        movdqa    %xmm13, %xmm0
        pslld     $30, %xmm0
        psrld     $2, %xmm13
        movdqa    %xmm15, 208(%rsp)
        por       %xmm13, %xmm0
        pxor      480(%rsp), %xmm15
        por       %xmm0, %xmm12
        movdqa    (%rsp), %xmm13
        pand      %xmm0, %xmm7
        pxor      %xmm13, %xmm15
        pand      %xmm3, %xmm12
        pxor      %xmm1, %xmm15
        por       %xmm12, %xmm7
        movdqa    %xmm15, %xmm8
        paddd     %xmm15, %xmm15
        psrld     $31, %xmm8
        movdqa    %xmm14, %xmm12
        por       %xmm8, %xmm15
        movdqa    %xmm14, %xmm8
        pslld     $5, %xmm12
        psrld     $27, %xmm8
        por       %xmm8, %xmm12
        paddd     %xmm7, %xmm5
        paddd     %xmm12, %xmm5
        movdqa    %xmm10, %xmm7
        paddd     %xmm4, %xmm5
        pslld     $30, %xmm7
        movdqa    %xmm9, 240(%rsp)
        paddd     %xmm1, %xmm5
        pxor      368(%rsp), %xmm9
        psrld     $2, %xmm10
        movdqa    176(%rsp), %xmm1
        por       %xmm10, %xmm7
        pxor      %xmm1, %xmm9
        movdqa    %xmm14, %xmm8
        pxor      %xmm11, %xmm9
        por       %xmm7, %xmm8
        movdqa    %xmm9, %xmm10
        paddd     %xmm9, %xmm9
        psrld     $31, %xmm10
        pand      %xmm0, %xmm8
        por       %xmm10, %xmm9
        movdqa    %xmm14, %xmm10
        pand      %xmm7, %xmm10
        movdqa    %xmm5, %xmm12
        por       %xmm8, %xmm10
        movdqa    %xmm5, %xmm8
        paddd     %xmm10, %xmm3
        movdqa    %xmm14, %xmm10
        pslld     $5, %xmm8
        psrld     $27, %xmm12
        pslld     $30, %xmm10
        psrld     $2, %xmm14
        movdqa    %xmm2, 256(%rsp)
        por       %xmm12, %xmm8
        pxor      352(%rsp), %xmm2
        por       %xmm14, %xmm10
        movdqa    192(%rsp), %xmm14
        paddd     %xmm8, %xmm3
        pxor      %xmm14, %xmm2
        paddd     %xmm4, %xmm3
        pxor      %xmm13, %xmm2
        paddd     %xmm11, %xmm3
        movdqa    %xmm2, %xmm11
        paddd     %xmm2, %xmm2
        psrld     $31, %xmm11
        movdqa    %xmm5, %xmm12
        por       %xmm11, %xmm2
        movdqa    %xmm5, %xmm11
        por       %xmm10, %xmm12
        pand      %xmm10, %xmm11
        pand      %xmm7, %xmm12
        movdqa    %xmm3, %xmm8
        por       %xmm12, %xmm11
        movdqa    %xmm3, %xmm12
        pslld     $5, %xmm12
        psrld     $27, %xmm8
        por       %xmm8, %xmm12
        paddd     %xmm11, %xmm0
        paddd     %xmm12, %xmm0
        movdqa    %xmm3, %xmm12
        paddd     %xmm4, %xmm0
        movdqa    %xmm3, %xmm8
        paddd     %xmm13, %xmm0
        movdqa    %xmm5, %xmm13
        pslld     $30, %xmm13
        psrld     $2, %xmm5
        por       %xmm5, %xmm13
        movdqa    %xmm15, %xmm5
        movdqa    %xmm6, 272(%rsp)
        pxor      %xmm6, %xmm5
        movdqa    432(%rsp), %xmm6
        por       %xmm13, %xmm12
        pxor      %xmm6, %xmm5
        pand      %xmm13, %xmm8
        pxor      %xmm1, %xmm5
        pand      %xmm10, %xmm12
        movdqa    %xmm5, %xmm11
        paddd     %xmm5, %xmm5
        psrld     $31, %xmm11
        por       %xmm12, %xmm8
        por       %xmm11, %xmm5
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        paddd     %xmm8, %xmm7
        movdqa    %xmm3, %xmm8
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        pslld     $30, %xmm8
        psrld     $2, %xmm3
        por       %xmm11, %xmm12
        movdqa    %xmm9, 320(%rsp)
        por       %xmm3, %xmm8
        pxor      304(%rsp), %xmm9
        paddd     %xmm12, %xmm7
        movdqa    448(%rsp), %xmm3
        paddd     %xmm4, %xmm7
        pxor      %xmm3, %xmm9
        paddd     %xmm1, %xmm7
        pxor      %xmm14, %xmm9
        movdqa    %xmm0, %xmm11
        movdqa    %xmm9, %xmm1
        paddd     %xmm9, %xmm9
        psrld     $31, %xmm1
        por       %xmm8, %xmm11
        por       %xmm1, %xmm9
        movdqa    %xmm0, %xmm1
        pand      %xmm8, %xmm1
        pand      %xmm13, %xmm11
        por       %xmm11, %xmm1
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm12
        pslld     $5, %xmm11
        psrld     $27, %xmm12
        paddd     %xmm1, %xmm10
        movdqa    %xmm2, 384(%rsp)
        por       %xmm12, %xmm11
        pxor      208(%rsp), %xmm2
        movdqa    %xmm0, %xmm1
        movdqa    464(%rsp), %xmm12
        paddd     %xmm11, %xmm10
        pxor      %xmm12, %xmm2
        pslld     $30, %xmm1
        psrld     $2, %xmm0
        pxor      %xmm6, %xmm2
        paddd     %xmm4, %xmm10
        por       %xmm0, %xmm1
        movdqa    %xmm2, %xmm0
        paddd     %xmm14, %xmm10
        psrld     $31, %xmm0
        paddd     %xmm2, %xmm2
        movdqa    %xmm7, %xmm14
        por       %xmm0, %xmm2
        movdqa    %xmm7, %xmm0
        por       %xmm1, %xmm14
        pand      %xmm1, %xmm0
        pand      %xmm8, %xmm14
        por       %xmm14, %xmm0
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm11
        pslld     $5, %xmm14
        psrld     $27, %xmm11
        paddd     %xmm0, %xmm13
        movdqa    %xmm5, 224(%rsp)
        por       %xmm11, %xmm14
        pxor      240(%rsp), %xmm5
        paddd     %xmm14, %xmm13
        movdqa    480(%rsp), %xmm11
        paddd     %xmm4, %xmm13
        pxor      %xmm11, %xmm5
        movdqa    %xmm7, %xmm0
        pxor      %xmm3, %xmm5
        paddd     %xmm6, %xmm13
        pslld     $30, %xmm0
        psrld     $2, %xmm7
        movdqa    %xmm5, %xmm6
        por       %xmm7, %xmm0
        psrld     $31, %xmm6
        paddd     %xmm5, %xmm5
        movdqa    %xmm10, %xmm7
        por       %xmm6, %xmm5
        movdqa    %xmm10, %xmm6
        por       %xmm0, %xmm7
        pand      %xmm0, %xmm6
        pand      %xmm1, %xmm7
        por       %xmm7, %xmm6
        movdqa    %xmm13, %xmm7
        movdqa    %xmm13, %xmm14
        pslld     $5, %xmm7
        psrld     $27, %xmm14
        paddd     %xmm6, %xmm8
        por       %xmm14, %xmm7
        movdqa    %xmm10, %xmm6
        movdqa    %xmm9, 336(%rsp)
        paddd     %xmm7, %xmm8
        pxor      256(%rsp), %xmm9
        pslld     $30, %xmm6
        psrld     $2, %xmm10
        paddd     %xmm4, %xmm8
        pxor      368(%rsp), %xmm9
        por       %xmm10, %xmm6
        paddd     %xmm3, %xmm8
        pxor      %xmm12, %xmm9
        movdqa    %xmm6, %xmm10
        movdqa    %xmm9, %xmm3
        pxor      %xmm0, %xmm10
        movdqa    %xmm8, %xmm14
        movdqa    %xmm8, %xmm7
        psrld     $31, %xmm3
        paddd     %xmm9, %xmm9
        pxor      %xmm13, %xmm10
        pslld     $5, %xmm14
        psrld     $27, %xmm7
        por       %xmm3, %xmm9
        por       %xmm7, %xmm14
        paddd     %xmm10, %xmm1
        movdqa    %xmm13, %xmm3
        movdqa    .L_2il0floatpacket.557(%rip), %xmm4
        paddd     %xmm14, %xmm1
        pslld     $30, %xmm3
        psrld     $2, %xmm13
        paddd     %xmm4, %xmm1
        por       %xmm13, %xmm3
        movdqa    %xmm15, 288(%rsp)
        paddd     %xmm12, %xmm1
        movdqa    %xmm2, 400(%rsp)
        pxor      %xmm15, %xmm2
        movdqa    %xmm3, %xmm15
        movdqa    %xmm1, %xmm7
        pxor      %xmm6, %xmm15
        movdqa    %xmm1, %xmm13
        pxor      %xmm8, %xmm15
        pslld     $5, %xmm7
        psrld     $27, %xmm13
        paddd     %xmm15, %xmm0
        por       %xmm13, %xmm7
        paddd     %xmm7, %xmm0
        movdqa    %xmm8, %xmm7
        pxor      352(%rsp), %xmm2
        paddd     %xmm4, %xmm0
        pslld     $30, %xmm7
        psrld     $2, %xmm8
        pxor      %xmm11, %xmm2
        paddd     %xmm11, %xmm0
        por       %xmm8, %xmm7
..B5.24:
        movdqa    %xmm2, (%rsp)
        movdqa    %xmm5, %xmm2
        movdqa    320(%rsp), %xmm8
        movdqa    %xmm7, %xmm10
        movdqa    272(%rsp), %xmm13
        pxor      %xmm8, %xmm2
        movdqa    368(%rsp), %xmm15
        pxor      %xmm13, %xmm2
        pxor      %xmm15, %xmm2
        pxor      %xmm3, %xmm10
        movdqa    %xmm2, 16(%rsp)
        movdqa    %xmm0, %xmm2
        movdqa    %xmm0, %xmm14
        pxor      %xmm1, %xmm10
        pslld     $5, %xmm2
        psrld     $27, %xmm14
        por       %xmm14, %xmm2
        paddd     %xmm10, %xmm6
        movdqa    384(%rsp), %xmm10
        paddd     %xmm2, %xmm6
        movdqa    %xmm1, %xmm2
        movdqa    %xmm9, %xmm11
        movdqa    304(%rsp), %xmm12
        pslld     $30, %xmm2
        psrld     $2, %xmm1
        pxor      %xmm10, %xmm11
        paddd     %xmm4, %xmm6
        por       %xmm1, %xmm2
        movdqa    352(%rsp), %xmm1
        pxor      %xmm12, %xmm11
        paddd     %xmm15, %xmm6
        movdqa    %xmm7, %xmm15
        pxor      %xmm1, %xmm11
        pxor      %xmm2, %xmm15
        movdqa    %xmm11, 32(%rsp)
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm14
        pxor      %xmm0, %xmm15
        pslld     $5, %xmm11
        psrld     $27, %xmm14
        por       %xmm14, %xmm11
        paddd     %xmm15, %xmm3
        paddd     %xmm11, %xmm3
        paddd     %xmm4, %xmm3
        paddd     %xmm1, %xmm3
        movdqa    %xmm0, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm0
        por       %xmm0, %xmm1
        movdqa    %xmm3, %xmm14
        movdqa    %xmm1, %xmm11
        movdqa    %xmm3, %xmm0
        pxor      %xmm2, %xmm11
        pslld     $5, %xmm14
        pxor      %xmm6, %xmm11
        psrld     $27, %xmm0
        por       %xmm0, %xmm14
        paddd     %xmm11, %xmm7
        movdqa    %xmm6, %xmm0
        paddd     %xmm14, %xmm7
        pslld     $30, %xmm0
        psrld     $2, %xmm6
        paddd     %xmm4, %xmm7
        por       %xmm6, %xmm0
        paddd     %xmm13, %xmm7
        movdqa    %xmm0, %xmm13
        pxor      %xmm1, %xmm13
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm6
        pxor      %xmm3, %xmm13
        pslld     $5, %xmm11
        psrld     $27, %xmm6
        por       %xmm6, %xmm11
        paddd     %xmm13, %xmm2
        paddd     %xmm11, %xmm2
        movdqa    %xmm3, %xmm11
        pslld     $30, %xmm11
        psrld     $2, %xmm3
        paddd     %xmm4, %xmm2
        por       %xmm3, %xmm11
        paddd     %xmm12, %xmm2
        movdqa    %xmm11, %xmm6
        pxor      %xmm0, %xmm6
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm3
        pxor      %xmm7, %xmm6
        pslld     $5, %xmm12
        psrld     $27, %xmm3
        por       %xmm3, %xmm12
        paddd     %xmm6, %xmm1
        movdqa    %xmm7, %xmm6
        paddd     %xmm12, %xmm1
        pslld     $30, %xmm6
        psrld     $2, %xmm7
        paddd     %xmm4, %xmm1
        por       %xmm7, %xmm6
        paddd     208(%rsp), %xmm1
        movdqa    %xmm6, %xmm3
        pxor      %xmm11, %xmm3
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm7
        pxor      %xmm2, %xmm3
        pslld     $5, %xmm12
        psrld     $27, %xmm7
        por       %xmm7, %xmm12
        paddd     %xmm3, %xmm0
        movdqa    %xmm2, %xmm15
        paddd     %xmm12, %xmm0
        pslld     $30, %xmm15
        psrld     $2, %xmm2
        paddd     %xmm4, %xmm0
        por       %xmm2, %xmm15
        paddd     240(%rsp), %xmm0
        movdqa    %xmm15, %xmm13
        pxor      %xmm6, %xmm13
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm2
        pxor      %xmm1, %xmm13
        pslld     $5, %xmm14
        psrld     $27, %xmm2
        por       %xmm2, %xmm14
        paddd     %xmm13, %xmm11
        paddd     %xmm14, %xmm11
        movdqa    %xmm1, %xmm14
        pslld     $30, %xmm14
        psrld     $2, %xmm1
        paddd     %xmm4, %xmm11
        por       %xmm1, %xmm14
        paddd     256(%rsp), %xmm11
        movdqa    %xmm14, %xmm7
        pxor      %xmm15, %xmm7
        movdqa    %xmm11, %xmm3
        movdqa    %xmm11, %xmm1
        pxor      %xmm0, %xmm7
        pslld     $5, %xmm3
        psrld     $27, %xmm1
        por       %xmm1, %xmm3
        paddd     %xmm7, %xmm6
        paddd     %xmm3, %xmm6
        movdqa    %xmm0, %xmm3
        pslld     $30, %xmm3
        psrld     $2, %xmm0
        paddd     %xmm4, %xmm6
        por       %xmm0, %xmm3
        paddd     288(%rsp), %xmm6
        movdqa    %xmm3, %xmm7
        pxor      %xmm14, %xmm7
        movdqa    %xmm6, %xmm2
        movdqa    %xmm6, %xmm0
        pxor      %xmm11, %xmm7
        pslld     $5, %xmm2
        psrld     $27, %xmm0
        por       %xmm0, %xmm2
        paddd     %xmm7, %xmm15
        movdqa    %xmm11, %xmm13
        paddd     %xmm2, %xmm15
        pslld     $30, %xmm13
        psrld     $2, %xmm11
        paddd     %xmm4, %xmm15
        por       %xmm11, %xmm13
        paddd     %xmm8, %xmm15
        movdqa    %xmm13, %xmm7
        pxor      %xmm3, %xmm7
        movdqa    %xmm15, %xmm2
        movdqa    %xmm15, %xmm8
        pxor      %xmm6, %xmm7
        pslld     $5, %xmm2
        psrld     $27, %xmm8
        por       %xmm8, %xmm2
        paddd     %xmm7, %xmm14
        movdqa    %xmm6, %xmm12
        paddd     %xmm2, %xmm14
        pslld     $30, %xmm12
        psrld     $2, %xmm6
        paddd     %xmm4, %xmm14
        por       %xmm6, %xmm12
        paddd     %xmm10, %xmm14
        movdqa    %xmm12, %xmm0
        pxor      %xmm13, %xmm0
        movdqa    %xmm14, %xmm6
        movdqa    %xmm14, %xmm1
        pxor      %xmm15, %xmm0
        pslld     $5, %xmm6
        psrld     $27, %xmm1
        por       %xmm1, %xmm6
        paddd     %xmm0, %xmm3
        movdqa    %xmm15, %xmm11
        paddd     %xmm6, %xmm3
        pslld     $30, %xmm11
        psrld     $2, %xmm15
        paddd     %xmm4, %xmm3
        por       %xmm15, %xmm11
        paddd     224(%rsp), %xmm3
        movdqa    %xmm11, %xmm15
        pxor      %xmm12, %xmm15
        movdqa    %xmm3, %xmm7
        movdqa    %xmm3, %xmm10
        pxor      %xmm14, %xmm15
        pslld     $5, %xmm7
        psrld     $27, %xmm10
        por       %xmm10, %xmm7
        paddd     %xmm15, %xmm13
        movdqa    %xmm14, %xmm6
        paddd     %xmm7, %xmm13
        pslld     $30, %xmm6
        psrld     $2, %xmm14
        paddd     %xmm4, %xmm13
        por       %xmm14, %xmm6
        paddd     336(%rsp), %xmm13
        movdqa    %xmm6, %xmm7
        pxor      %xmm11, %xmm7
        movdqa    %xmm13, %xmm2
        movdqa    %xmm13, %xmm14
        pxor      %xmm3, %xmm7
        pslld     $5, %xmm2
        psrld     $27, %xmm14
        por       %xmm14, %xmm2
        paddd     %xmm7, %xmm12
        movdqa    %xmm3, %xmm7
        paddd     %xmm2, %xmm12
        pslld     $30, %xmm7
        psrld     $2, %xmm3
        paddd     %xmm4, %xmm12
        por       %xmm3, %xmm7
        paddd     400(%rsp), %xmm12
        movdqa    %xmm7, %xmm2
        pxor      %xmm6, %xmm2
        movdqa    %xmm12, %xmm1
        movdqa    %xmm12, %xmm3
        pxor      %xmm13, %xmm2
        pslld     $5, %xmm1
        psrld     $27, %xmm3
        por       %xmm3, %xmm1
        paddd     %xmm2, %xmm11
        movdqa    %xmm13, %xmm3
        paddd     %xmm1, %xmm11
        pslld     $30, %xmm3
        psrld     $2, %xmm13
        paddd     %xmm4, %xmm11
        por       %xmm13, %xmm3
        paddd     %xmm5, %xmm11
        movdqa    %xmm3, %xmm2
        pxor      %xmm7, %xmm2
        movdqa    %xmm11, %xmm1
        movdqa    %xmm11, %xmm5
        pxor      %xmm12, %xmm2
        pslld     $5, %xmm1
        psrld     $27, %xmm5
        por       %xmm5, %xmm1
        paddd     %xmm2, %xmm6
        movdqa    %xmm12, %xmm2
        paddd     %xmm1, %xmm6
        pslld     $30, %xmm2
        psrld     $2, %xmm12
        paddd     %xmm4, %xmm6
        por       %xmm12, %xmm2
        movdqa    (%rsp), %xmm8
        paddd     %xmm9, %xmm6
        movdqa    %xmm2, %xmm0
        movdqa    %xmm6, %xmm5
        pxor      %xmm3, %xmm0
        movdqa    %xmm6, %xmm9
        movdqa    %xmm8, %xmm1
        pxor      %xmm11, %xmm0
        pslld     $5, %xmm5
        psrld     $27, %xmm9
        psrld     $31, %xmm1
        paddd     %xmm8, %xmm8
        por       %xmm9, %xmm5
        por       %xmm1, %xmm8
        paddd     %xmm0, %xmm7
        movdqa    %xmm11, %xmm1
        paddd     %xmm5, %xmm7
        pslld     $30, %xmm1
        psrld     $2, %xmm11
        paddd     %xmm4, %xmm7
        por       %xmm11, %xmm1
        paddd     %xmm8, %xmm7
        movdqa    %xmm1, %xmm12
        movdqa    %xmm7, %xmm13
        pxor      %xmm2, %xmm12
        movdqa    %xmm7, %xmm10
        movdqa    16(%rsp), %xmm14
        pxor      %xmm6, %xmm12
        pslld     $5, %xmm13
        psrld     $27, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm14, %xmm11
        paddd     %xmm12, %xmm3
        psrld     $31, %xmm11
        paddd     %xmm14, %xmm14
        paddd     %xmm13, %xmm3
        movdqa    %xmm6, %xmm0
        por       %xmm11, %xmm14
        paddd     %xmm4, %xmm3
        pslld     $30, %xmm0
        psrld     $2, %xmm6
        paddd     %xmm14, %xmm3
        por       %xmm6, %xmm0
        movdqa    %xmm3, %xmm8
        movdqa    %xmm0, %xmm5
        movdqa    %xmm3, %xmm6
        pxor      %xmm1, %xmm5
        pslld     $5, %xmm8
        psrld     $27, %xmm6
        pxor      %xmm7, %xmm5
        por       %xmm6, %xmm8
        paddd     %xmm5, %xmm2
        movdqa    32(%rsp), %xmm6
        paddd     %xmm8, %xmm2
        movdqa    %xmm6, %xmm15
        paddd     %xmm6, %xmm6
        psrld     $31, %xmm15
        movdqa    %xmm7, %xmm9
        por       %xmm15, %xmm6
        paddd     %xmm4, %xmm2
        pslld     $30, %xmm9
        psrld     $2, %xmm7
        paddd     %xmm6, %xmm2
        por       %xmm7, %xmm9
        jne       ..B5.20
..B5.19:
        movdqa    .L_2il0floatpacket.558(%rip), %xmm4
        movdqa    .L_2il0floatpacket.22(%rip), %xmm5
        paddd     %xmm4, %xmm2
        movdqa    .L_2il0floatpacket.23(%rip), %xmm6
        paddd     %xmm5, %xmm3
        movdqa    .L_2il0floatpacket.24(%rip), %xmm7
        paddd     %xmm6, %xmm9
        movdqa    .L_2il0floatpacket.559(%rip), %xmm8
        paddd     %xmm7, %xmm0
        paddd     %xmm8, %xmm1
        jmp       ..B5.21
..B5.20:
        movdqa    (%rdx), %xmm4
        movdqa    16(%rdx), %xmm5
        paddd     %xmm4, %xmm2
        movdqa    32(%rdx), %xmm6
        paddd     %xmm5, %xmm3
        movdqa    48(%rdx), %xmm7
        paddd     %xmm6, %xmm9
        movdqa    64(%rdx), %xmm8
        paddd     %xmm7, %xmm0
        paddd     %xmm8, %xmm1
..B5.21:
        movdqa    %xmm2, (%rsi)
        movdqa    %xmm3, 16(%rsi)
        movdqa    %xmm9, 32(%rsi)
        movdqa    %xmm0, 48(%rsi)
        movdqa    %xmm1, 64(%rsi)
        addq      $584, %rsp
..___tag_value_SIMDSHA1body.107:
        ret       
        .align    16,0x90
..___tag_value_SIMDSHA1body.108:
	.type	SIMDSHA1body,@function
	.size	SIMDSHA1body,.-SIMDSHA1body
	.data
# -- End  SIMDSHA1body
	.text
# -- Begin  SIMDSHA256body
       .align    16,0x90
	.globl SIMDSHA256body
SIMDSHA256body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B6.1:
..___tag_value_SIMDSHA256body.109:
        pushq     %r12
..___tag_value_SIMDSHA256body.111:
        pushq     %r13
..___tag_value_SIMDSHA256body.113:
        pushq     %rbp
..___tag_value_SIMDSHA256body.115:
        subq      $624, %rsp
..___tag_value_SIMDSHA256body.117:
        movl      %ecx, %r12d
        movq      %rdx, %r13
        movq      %rsi, %rbp
        movq      %rdi, %rsi
        testl     $1, %r12d
        je        ..B6.14
..B6.2:
        testl     $256, %r12d
        je        ..B6.4
..B6.3:
        movl      (%rsi), %eax
        movl      %eax, (%rsp)
        movl      256(%rsi), %edx
        movl      %edx, 4(%rsp)
        movl      512(%rsi), %ecx
        movl      %ecx, 8(%rsp)
        movl      768(%rsi), %edi
        movl      %edi, 12(%rsp)
        movl      4(%rsi), %r8d
        movl      %r8d, 16(%rsp)
        movl      260(%rsi), %r9d
        movl      %r9d, 20(%rsp)
        movl      516(%rsi), %r10d
        movl      %r10d, 24(%rsp)
        movl      772(%rsi), %r11d
        movl      %r11d, 28(%rsp)
        movl      8(%rsi), %eax
        movl      %eax, 32(%rsp)
        movl      264(%rsi), %edx
        movl      %edx, 36(%rsp)
        movl      520(%rsi), %ecx
        movl      %ecx, 40(%rsp)
        movl      776(%rsi), %edi
        movl      %edi, 44(%rsp)
        movl      12(%rsi), %r8d
        movl      %r8d, 48(%rsp)
        movl      268(%rsi), %r9d
        movl      %r9d, 52(%rsp)
        movl      524(%rsi), %r10d
        movl      %r10d, 56(%rsp)
        movl      780(%rsi), %r11d
        movl      %r11d, 60(%rsp)
        movl      16(%rsi), %eax
        movl      %eax, 64(%rsp)
        movl      272(%rsi), %edx
        movl      %edx, 68(%rsp)
        movl      528(%rsi), %ecx
        movl      %ecx, 72(%rsp)
        movl      784(%rsi), %edi
        movl      %edi, 76(%rsp)
        movl      20(%rsi), %r8d
        movl      %r8d, 80(%rsp)
        movl      276(%rsi), %r9d
        movl      %r9d, 84(%rsp)
        movl      532(%rsi), %r10d
        movl      %r10d, 88(%rsp)
        movl      788(%rsi), %r11d
        movl      %r11d, 92(%rsp)
        movl      24(%rsi), %eax
        movl      %eax, 96(%rsp)
        movl      280(%rsi), %edx
        movl      %edx, 100(%rsp)
        movl      536(%rsi), %ecx
        movl      %ecx, 104(%rsp)
        movl      792(%rsi), %edi
        movl      %edi, 108(%rsp)
        movl      28(%rsi), %r8d
        movl      %r8d, 112(%rsp)
        movl      284(%rsi), %r9d
        movl      %r9d, 116(%rsp)
        movl      540(%rsi), %r10d
        movl      %r10d, 120(%rsp)
        movl      796(%rsi), %r11d
        movl      %r11d, 124(%rsp)
        movl      32(%rsi), %eax
        movl      %eax, 128(%rsp)
        movl      288(%rsi), %edx
        movl      %edx, 132(%rsp)
        movl      544(%rsi), %ecx
        movl      %ecx, 136(%rsp)
        movl      800(%rsi), %edi
        movl      %edi, 140(%rsp)
        movl      36(%rsi), %r8d
        movl      %r8d, 144(%rsp)
        movl      292(%rsi), %r9d
        movl      %r9d, 148(%rsp)
        movl      548(%rsi), %r10d
        movl      %r10d, 152(%rsp)
        movl      804(%rsi), %r11d
        movl      %r11d, 156(%rsp)
        movl      40(%rsi), %eax
        movl      %eax, 160(%rsp)
        movl      296(%rsi), %edx
        movl      %edx, 164(%rsp)
        movl      552(%rsi), %ecx
        movl      %ecx, 168(%rsp)
        movl      808(%rsi), %edi
        movl      %edi, 172(%rsp)
        movl      44(%rsi), %r8d
        movl      %r8d, 176(%rsp)
        movl      300(%rsi), %r9d
        movl      %r9d, 180(%rsp)
        movl      556(%rsi), %r10d
        movl      %r10d, 184(%rsp)
        movl      812(%rsi), %r11d
        movl      %r11d, 188(%rsp)
        movl      48(%rsi), %eax
        movl      %eax, 192(%rsp)
        movl      304(%rsi), %edx
        movl      %edx, 196(%rsp)
        movl      560(%rsi), %ecx
        movl      %ecx, 200(%rsp)
        movl      816(%rsi), %edi
        movl      %edi, 204(%rsp)
        movl      52(%rsi), %r8d
        movl      %r8d, 208(%rsp)
        movl      308(%rsi), %r9d
        movl      %r9d, 212(%rsp)
        movl      564(%rsi), %r10d
        movl      %r10d, 216(%rsp)
        movl      820(%rsi), %r11d
        movl      %r11d, 220(%rsp)
        movl      56(%rsi), %eax
        movl      %eax, 224(%rsp)
        movl      312(%rsi), %edx
        movl      %edx, 228(%rsp)
        movl      568(%rsi), %ecx
        movl      %ecx, 232(%rsp)
        movl      824(%rsi), %edi
        movl      %edi, 236(%rsp)
        movl      60(%rsi), %r8d
        movl      %r8d, 240(%rsp)
        movl      316(%rsi), %r9d
        movl      %r9d, 244(%rsp)
        movl      572(%rsi), %r10d
        movl      %r10d, 248(%rsp)
        movl      828(%rsi), %esi
        movl      %esi, 252(%rsp)
        jmp       ..B6.7
..B6.4:
        testl     $64, %r12d
        je        ..B6.6
..B6.5:
        movl      (%rsi), %eax
        movl      %eax, (%rsp)
        movl      128(%rsi), %edx
        movl      %edx, 4(%rsp)
        movl      256(%rsi), %ecx
        movl      %ecx, 8(%rsp)
        movl      384(%rsi), %edi
        movl      %edi, 12(%rsp)
        movl      4(%rsi), %r8d
        movl      %r8d, 16(%rsp)
        movl      132(%rsi), %r9d
        movl      %r9d, 20(%rsp)
        movl      260(%rsi), %r10d
        movl      %r10d, 24(%rsp)
        movl      388(%rsi), %r11d
        movl      %r11d, 28(%rsp)
        movl      8(%rsi), %eax
        movl      %eax, 32(%rsp)
        movl      136(%rsi), %edx
        movl      %edx, 36(%rsp)
        movl      264(%rsi), %ecx
        movl      %ecx, 40(%rsp)
        movl      392(%rsi), %edi
        movl      %edi, 44(%rsp)
        movl      12(%rsi), %r8d
        movl      %r8d, 48(%rsp)
        movl      140(%rsi), %r9d
        movl      %r9d, 52(%rsp)
        movl      268(%rsi), %r10d
        movl      %r10d, 56(%rsp)
        movl      396(%rsi), %r11d
        movl      %r11d, 60(%rsp)
        movl      16(%rsi), %eax
        movl      %eax, 64(%rsp)
        movl      144(%rsi), %edx
        movl      %edx, 68(%rsp)
        movl      272(%rsi), %ecx
        movl      %ecx, 72(%rsp)
        movl      400(%rsi), %edi
        movl      %edi, 76(%rsp)
        movl      20(%rsi), %r8d
        movl      %r8d, 80(%rsp)
        movl      148(%rsi), %r9d
        movl      %r9d, 84(%rsp)
        movl      276(%rsi), %r10d
        movl      %r10d, 88(%rsp)
        movl      404(%rsi), %r11d
        movl      %r11d, 92(%rsp)
        movl      24(%rsi), %eax
        movl      %eax, 96(%rsp)
        movl      152(%rsi), %edx
        movl      %edx, 100(%rsp)
        movl      280(%rsi), %ecx
        movl      %ecx, 104(%rsp)
        movl      408(%rsi), %edi
        movl      %edi, 108(%rsp)
        movl      28(%rsi), %r8d
        movl      %r8d, 112(%rsp)
        movl      156(%rsi), %r9d
        movl      %r9d, 116(%rsp)
        movl      284(%rsi), %r10d
        movl      %r10d, 120(%rsp)
        movl      412(%rsi), %r11d
        movl      %r11d, 124(%rsp)
        movl      32(%rsi), %eax
        movl      %eax, 128(%rsp)
        movl      160(%rsi), %edx
        movl      %edx, 132(%rsp)
        movl      288(%rsi), %ecx
        movl      %ecx, 136(%rsp)
        movl      416(%rsi), %edi
        movl      %edi, 140(%rsp)
        movl      36(%rsi), %r8d
        movl      %r8d, 144(%rsp)
        movl      164(%rsi), %r9d
        movl      %r9d, 148(%rsp)
        movl      292(%rsi), %r10d
        movl      %r10d, 152(%rsp)
        movl      420(%rsi), %r11d
        movl      %r11d, 156(%rsp)
        movl      40(%rsi), %eax
        movl      %eax, 160(%rsp)
        movl      168(%rsi), %edx
        movl      %edx, 164(%rsp)
        movl      296(%rsi), %ecx
        movl      %ecx, 168(%rsp)
        movl      424(%rsi), %edi
        movl      %edi, 172(%rsp)
        movl      44(%rsi), %r8d
        movl      %r8d, 176(%rsp)
        movl      172(%rsi), %r9d
        movl      %r9d, 180(%rsp)
        movl      300(%rsi), %r10d
        movl      %r10d, 184(%rsp)
        movl      428(%rsi), %r11d
        movl      %r11d, 188(%rsp)
        movl      48(%rsi), %eax
        movl      %eax, 192(%rsp)
        movl      176(%rsi), %edx
        movl      %edx, 196(%rsp)
        movl      304(%rsi), %ecx
        movl      %ecx, 200(%rsp)
        movl      432(%rsi), %edi
        movl      %edi, 204(%rsp)
        movl      52(%rsi), %r8d
        movl      %r8d, 208(%rsp)
        movl      180(%rsi), %r9d
        movl      %r9d, 212(%rsp)
        movl      308(%rsi), %r10d
        movl      %r10d, 216(%rsp)
        movl      436(%rsi), %r11d
        movl      %r11d, 220(%rsp)
        movl      56(%rsi), %eax
        movl      %eax, 224(%rsp)
        movl      184(%rsi), %edx
        movl      %edx, 228(%rsp)
        movl      312(%rsi), %ecx
        movl      %ecx, 232(%rsp)
        movl      440(%rsi), %edi
        movl      %edi, 236(%rsp)
        movl      60(%rsi), %r8d
        movl      %r8d, 240(%rsp)
        movl      188(%rsi), %r9d
        movl      %r9d, 244(%rsp)
        movl      316(%rsi), %r10d
        movl      %r10d, 248(%rsp)
        movl      444(%rsi), %esi
        movl      %esi, 252(%rsp)
        jmp       ..B6.7
..B6.6:
        movl      (%rsi), %eax
        movl      %eax, (%rsp)
        movl      64(%rsi), %edx
        movl      %edx, 4(%rsp)
        movl      128(%rsi), %ecx
        movl      %ecx, 8(%rsp)
        movl      192(%rsi), %edi
        movl      %edi, 12(%rsp)
        movl      4(%rsi), %r8d
        movl      %r8d, 16(%rsp)
        movl      68(%rsi), %r9d
        movl      %r9d, 20(%rsp)
        movl      132(%rsi), %r10d
        movl      %r10d, 24(%rsp)
        movl      196(%rsi), %r11d
        movl      %r11d, 28(%rsp)
        movl      8(%rsi), %eax
        movl      %eax, 32(%rsp)
        movl      72(%rsi), %edx
        movl      %edx, 36(%rsp)
        movl      136(%rsi), %ecx
        movl      %ecx, 40(%rsp)
        movl      200(%rsi), %edi
        movl      %edi, 44(%rsp)
        movl      12(%rsi), %r8d
        movl      %r8d, 48(%rsp)
        movl      76(%rsi), %r9d
        movl      %r9d, 52(%rsp)
        movl      140(%rsi), %r10d
        movl      %r10d, 56(%rsp)
        movl      204(%rsi), %r11d
        movl      %r11d, 60(%rsp)
        movl      16(%rsi), %eax
        movl      %eax, 64(%rsp)
        movl      80(%rsi), %edx
        movl      %edx, 68(%rsp)
        movl      144(%rsi), %ecx
        movl      %ecx, 72(%rsp)
        movl      208(%rsi), %edi
        movl      %edi, 76(%rsp)
        movl      20(%rsi), %r8d
        movl      %r8d, 80(%rsp)
        movl      84(%rsi), %r9d
        movl      %r9d, 84(%rsp)
        movl      148(%rsi), %r10d
        movl      %r10d, 88(%rsp)
        movl      212(%rsi), %r11d
        movl      %r11d, 92(%rsp)
        movl      24(%rsi), %eax
        movl      %eax, 96(%rsp)
        movl      88(%rsi), %edx
        movl      %edx, 100(%rsp)
        movl      152(%rsi), %ecx
        movl      %ecx, 104(%rsp)
        movl      216(%rsi), %edi
        movl      %edi, 108(%rsp)
        movl      28(%rsi), %r8d
        movl      %r8d, 112(%rsp)
        movl      92(%rsi), %r9d
        movl      %r9d, 116(%rsp)
        movl      156(%rsi), %r10d
        movl      %r10d, 120(%rsp)
        movl      220(%rsi), %r11d
        movl      %r11d, 124(%rsp)
        movl      32(%rsi), %eax
        movl      %eax, 128(%rsp)
        movl      96(%rsi), %edx
        movl      %edx, 132(%rsp)
        movl      160(%rsi), %ecx
        movl      %ecx, 136(%rsp)
        movl      224(%rsi), %edi
        movl      %edi, 140(%rsp)
        movl      36(%rsi), %r8d
        movl      %r8d, 144(%rsp)
        movl      100(%rsi), %r9d
        movl      %r9d, 148(%rsp)
        movl      164(%rsi), %r10d
        movl      %r10d, 152(%rsp)
        movl      228(%rsi), %r11d
        movl      %r11d, 156(%rsp)
        movl      40(%rsi), %eax
        movl      %eax, 160(%rsp)
        movl      104(%rsi), %edx
        movl      %edx, 164(%rsp)
        movl      168(%rsi), %ecx
        movl      %ecx, 168(%rsp)
        movl      232(%rsi), %edi
        movl      %edi, 172(%rsp)
        movl      44(%rsi), %r8d
        movl      %r8d, 176(%rsp)
        movl      108(%rsi), %r9d
        movl      %r9d, 180(%rsp)
        movl      172(%rsi), %r10d
        movl      %r10d, 184(%rsp)
        movl      236(%rsi), %r11d
        movl      %r11d, 188(%rsp)
        movl      48(%rsi), %eax
        movl      %eax, 192(%rsp)
        movl      112(%rsi), %edx
        movl      %edx, 196(%rsp)
        movl      176(%rsi), %ecx
        movl      %ecx, 200(%rsp)
        movl      240(%rsi), %edi
        movl      %edi, 204(%rsp)
        movl      52(%rsi), %r8d
        movl      %r8d, 208(%rsp)
        movl      116(%rsi), %r9d
        movl      %r9d, 212(%rsp)
        movl      180(%rsi), %r10d
        movl      %r10d, 216(%rsp)
        movl      244(%rsi), %r11d
        movl      %r11d, 220(%rsp)
        movl      56(%rsi), %eax
        movl      %eax, 224(%rsp)
        movl      120(%rsi), %edx
        movl      %edx, 228(%rsp)
        movl      184(%rsi), %ecx
        movl      %ecx, 232(%rsp)
        movl      248(%rsi), %edi
        movl      %edi, 236(%rsp)
        movl      60(%rsi), %r8d
        movl      %r8d, 240(%rsp)
        movl      124(%rsi), %r9d
        movl      %r9d, 244(%rsp)
        movl      188(%rsi), %r10d
        movl      %r10d, 248(%rsp)
        movl      252(%rsi), %esi
        movl      %esi, 252(%rsp)
..B6.7:
        xorb      %dl, %dl
        xorl      %eax, %eax
..B6.8:
        pshufhw   $177, (%rsp,%rax), %xmm0
        incb      %dl
        pshuflw   $177, %xmm0, %xmm1
        movdqa    %xmm1, %xmm2
        psllw     $8, %xmm1
        psrlw     $8, %xmm2
        pxor      %xmm1, %xmm2
        movdqa    %xmm2, (%rsp,%rax)
        addq      $16, %rax
        cmpb      $14, %dl
        jl        ..B6.8
..B6.9:
        movl      %r12d, %eax
        andl      $192, %eax
        cmpl      $192, %eax
        je        ..B6.12
..B6.10:
        movl      %r12d, %eax
        andl      $768, %eax
        cmpl      $768, %eax
        je        ..B6.12
..B6.11:
        testl     $1024, %r12d
        je        ..B6.15
..B6.12:
        pshufhw   $177, 224(%rsp), %xmm0
        pshufhw   $177, 240(%rsp), %xmm3
        pshuflw   $177, %xmm0, %xmm1
        pshuflw   $177, %xmm3, %xmm4
        movdqa    %xmm1, %xmm2
        movdqa    %xmm4, %xmm5
        psrlw     $8, %xmm2
        psllw     $8, %xmm1
        psrlw     $8, %xmm5
        psllw     $8, %xmm4
        pxor      %xmm1, %xmm2
        pxor      %xmm4, %xmm5
        movdqa    %xmm2, 432(%rsp)
        movdqa    %xmm2, 224(%rsp)
        movdqa    %xmm5, 336(%rsp)
        movdqa    %xmm5, 240(%rsp)
        jmp       ..B6.16
..B6.14:
        movl      $256, %edx
        lea       (%rsp), %rdi
..___tag_value_SIMDSHA256body.118:
        call      memcpy
..___tag_value_SIMDSHA256body.119:
..B6.15:
        movdqa    224(%rsp), %xmm0
        movdqa    240(%rsp), %xmm1
        movdqa    %xmm0, 432(%rsp)
        movdqa    %xmm1, 336(%rsp)
..B6.16:
        movl      %r12d, %eax
        andl      $2, %eax
        je        ..B6.18
..B6.17:
        movdqa    (%r13), %xmm6
        movdqa    16(%r13), %xmm2
        movdqa    32(%r13), %xmm4
        movdqa    48(%r13), %xmm1
        movdqa    64(%r13), %xmm7
        movdqa    80(%r13), %xmm5
        movdqa    96(%r13), %xmm3
        movdqa    112(%r13), %xmm0
        jmp       ..B6.21
..B6.18:
        testl     $4096, %r12d
        je        ..B6.20
..B6.19:
        movdqa    .L_2il0floatpacket.628(%rip), %xmm6
        movdqa    .L_2il0floatpacket.629(%rip), %xmm2
        movdqa    .L_2il0floatpacket.630(%rip), %xmm4
        movdqa    .L_2il0floatpacket.631(%rip), %xmm1
        movdqa    .L_2il0floatpacket.632(%rip), %xmm7
        movdqa    .L_2il0floatpacket.633(%rip), %xmm5
        movdqa    .L_2il0floatpacket.634(%rip), %xmm3
        movdqa    .L_2il0floatpacket.635(%rip), %xmm0
        jmp       ..B6.21
..B6.20:
        movdqa    .L_2il0floatpacket.636(%rip), %xmm6
        movdqa    .L_2il0floatpacket.637(%rip), %xmm2
        movdqa    .L_2il0floatpacket.638(%rip), %xmm4
        movdqa    .L_2il0floatpacket.639(%rip), %xmm1
        movdqa    .L_2il0floatpacket.640(%rip), %xmm7
        movdqa    .L_2il0floatpacket.641(%rip), %xmm5
        movdqa    .L_2il0floatpacket.642(%rip), %xmm3
        movdqa    .L_2il0floatpacket.643(%rip), %xmm0
..B6.21:
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm13
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm9
        psrld     $6, %xmm11
        pslld     $26, %xmm12
        psrld     $11, %xmm8
        pslld     $21, %xmm13
        psrld     $25, %xmm14
        pslld     $7, %xmm9
        por       %xmm12, %xmm11
        por       %xmm13, %xmm8
        movdqa    %xmm5, %xmm10
        por       %xmm9, %xmm14
        pxor      %xmm8, %xmm11
        pxor      %xmm3, %xmm10
        pxor      %xmm11, %xmm14
        pand      %xmm7, %xmm10
        pxor      %xmm3, %xmm10
        paddd     %xmm14, %xmm0
        paddd     %xmm10, %xmm0
        movdqa    %xmm6, %xmm11
        movdqa    (%rsp), %xmm15
        movdqa    %xmm6, %xmm12
        paddd     .L_2il0floatpacket.564(%rip), %xmm0
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm13
        paddd     %xmm15, %xmm0
        movdqa    %xmm15, 288(%rsp)
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm9
        psrld     $2, %xmm11
        pslld     $30, %xmm12
        psrld     $13, %xmm8
        pslld     $19, %xmm13
        movdqa    %xmm4, %xmm10
        movdqa    %xmm6, %xmm14
        psrld     $22, %xmm15
        pslld     $10, %xmm9
        por       %xmm12, %xmm11
        por       %xmm13, %xmm8
        pxor      %xmm2, %xmm10
        pxor      %xmm2, %xmm14
        por       %xmm9, %xmm15
        pxor      %xmm8, %xmm11
        pand      %xmm14, %xmm10
        paddd     %xmm0, %xmm1
        pxor      %xmm11, %xmm15
        pxor      %xmm2, %xmm10
        movdqa    %xmm1, %xmm12
        paddd     %xmm10, %xmm15
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm8
        psrld     $25, %xmm10
        pslld     $7, %xmm12
        psrld     $6, %xmm14
        pslld     $26, %xmm13
        psrld     $11, %xmm11
        pslld     $21, %xmm8
        por       %xmm12, %xmm10
        por       %xmm13, %xmm14
        por       %xmm8, %xmm11
        movdqa    %xmm7, %xmm12
        pxor      %xmm11, %xmm14
        pxor      %xmm5, %xmm12
        pxor      %xmm14, %xmm10
        pand      %xmm1, %xmm12
        paddd     %xmm15, %xmm0
        pxor      %xmm5, %xmm12
        paddd     %xmm10, %xmm3
        movdqa    %xmm0, %xmm13
        paddd     %xmm12, %xmm3
        movdqa    %xmm0, %xmm12
        psrld     $22, %xmm12
        pslld     $10, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm11
        psrld     $2, %xmm13
        movdqa    16(%rsp), %xmm9
        pslld     $30, %xmm8
        paddd     .L_2il0floatpacket.565(%rip), %xmm3
        psrld     $13, %xmm15
        pslld     $19, %xmm11
        paddd     %xmm9, %xmm3
        por       %xmm8, %xmm13
        por       %xmm11, %xmm15
        movdqa    %xmm2, %xmm11
        movdqa    %xmm6, %xmm8
        paddd     %xmm3, %xmm4
        pxor      %xmm6, %xmm11
        pxor      %xmm0, %xmm8
        pxor      %xmm15, %xmm13
        pand      %xmm8, %xmm11
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm14
        pxor      %xmm13, %xmm12
        pxor      %xmm6, %xmm11
        psrld     $25, %xmm8
        pslld     $7, %xmm14
        paddd     %xmm11, %xmm12
        por       %xmm14, %xmm8
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm13
        psrld     $6, %xmm14
        pslld     $26, %xmm10
        psrld     $11, %xmm11
        pslld     $21, %xmm13
        por       %xmm10, %xmm14
        por       %xmm13, %xmm11
        movdqa    %xmm7, %xmm15
        pxor      %xmm11, %xmm14
        pxor      %xmm1, %xmm15
        pxor      %xmm14, %xmm8
        pand      %xmm4, %xmm15
        paddd     %xmm12, %xmm3
        pxor      %xmm7, %xmm15
        paddd     %xmm8, %xmm5
        movdqa    %xmm3, %xmm13
        paddd     %xmm15, %xmm5
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm11
        movdqa    32(%rsp), %xmm12
        psrld     $22, %xmm13
        paddd     .L_2il0floatpacket.566(%rip), %xmm5
        pslld     $10, %xmm8
        psrld     $2, %xmm15
        pslld     $30, %xmm11
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm14
        paddd     %xmm12, %xmm5
        por       %xmm8, %xmm13
        por       %xmm11, %xmm15
        psrld     $13, %xmm10
        pslld     $19, %xmm14
        movdqa    %xmm6, %xmm11
        movdqa    %xmm3, %xmm8
        paddd     %xmm5, %xmm2
        por       %xmm14, %xmm10
        pxor      %xmm0, %xmm11
        pxor      %xmm0, %xmm8
        pxor      %xmm10, %xmm15
        pand      %xmm8, %xmm11
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm14
        pxor      %xmm15, %xmm13
        pxor      %xmm0, %xmm11
        psrld     $25, %xmm8
        pslld     $7, %xmm14
        paddd     %xmm11, %xmm13
        por       %xmm14, %xmm8
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm10
        psrld     $6, %xmm14
        pslld     $26, %xmm11
        psrld     $11, %xmm15
        pslld     $21, %xmm10
        por       %xmm11, %xmm14
        por       %xmm10, %xmm15
        movdqa    %xmm4, %xmm11
        pxor      %xmm15, %xmm14
        paddd     %xmm13, %xmm5
        pxor      %xmm14, %xmm8
        pxor      %xmm1, %xmm11
        pand      %xmm2, %xmm11
        paddd     %xmm8, %xmm7
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm8
        pxor      %xmm1, %xmm11
        psrld     $22, %xmm14
        pslld     $10, %xmm8
        paddd     %xmm11, %xmm7
        por       %xmm8, %xmm14
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm10
        psrld     $2, %xmm8
        pslld     $30, %xmm11
        psrld     $13, %xmm15
        pslld     $19, %xmm10
        por       %xmm11, %xmm8
        por       %xmm10, %xmm15
        movdqa    %xmm0, %xmm10
        movdqa    %xmm5, %xmm11
        pxor      %xmm3, %xmm10
        pxor      %xmm3, %xmm11
        pxor      %xmm15, %xmm8
        movdqa    48(%rsp), %xmm13
        pand      %xmm11, %xmm10
        paddd     .L_2il0floatpacket.567(%rip), %xmm7
        pxor      %xmm8, %xmm14
        paddd     %xmm13, %xmm7
        pxor      %xmm3, %xmm10
        paddd     %xmm7, %xmm6
        paddd     %xmm10, %xmm14
        paddd     %xmm14, %xmm7
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm10
        psrld     $25, %xmm11
        pslld     $7, %xmm14
        psrld     $6, %xmm8
        pslld     $26, %xmm10
        por       %xmm14, %xmm11
        por       %xmm10, %xmm8
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm14
        psrld     $11, %xmm10
        pslld     $21, %xmm14
        por       %xmm14, %xmm10
        movdqa    %xmm7, %xmm14
        pxor      %xmm10, %xmm8
        movdqa    %xmm7, %xmm10
        pxor      %xmm8, %xmm11
        movdqa    %xmm2, %xmm8
        pxor      %xmm4, %xmm8
        paddd     %xmm11, %xmm1
        pand      %xmm6, %xmm8
        movdqa    %xmm7, %xmm11
        pxor      %xmm4, %xmm8
        psrld     $22, %xmm10
        paddd     %xmm8, %xmm1
        pslld     $10, %xmm11
        movdqa    64(%rsp), %xmm15
        por       %xmm11, %xmm10
        paddd     .L_2il0floatpacket.568(%rip), %xmm1
        movdqa    %xmm7, %xmm11
        movdqa    %xmm15, 512(%rsp)
        paddd     %xmm15, %xmm1
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm8
        psrld     $2, %xmm14
        pslld     $30, %xmm15
        psrld     $13, %xmm11
        pslld     $19, %xmm8
        por       %xmm15, %xmm14
        por       %xmm8, %xmm11
        pxor      %xmm11, %xmm14
        movdqa    %xmm3, %xmm11
        movdqa    %xmm7, %xmm8
        pxor      %xmm5, %xmm11
        pxor      %xmm5, %xmm8
        pxor      %xmm14, %xmm10
        pand      %xmm8, %xmm11
        paddd     %xmm1, %xmm0
        pxor      %xmm5, %xmm11
        movdqa    %xmm0, %xmm8
        paddd     %xmm11, %xmm10
        movdqa    %xmm0, %xmm11
        paddd     %xmm10, %xmm1
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm15
        psrld     $25, %xmm11
        pslld     $7, %xmm10
        psrld     $6, %xmm8
        pslld     $26, %xmm15
        por       %xmm10, %xmm11
        por       %xmm15, %xmm8
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm10
        psrld     $11, %xmm15
        pslld     $21, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm1, %xmm10
        pxor      %xmm15, %xmm8
        movdqa    %xmm1, %xmm15
        pxor      %xmm8, %xmm11
        movdqa    %xmm6, %xmm8
        pxor      %xmm2, %xmm8
        paddd     %xmm11, %xmm4
        pand      %xmm0, %xmm8
        movdqa    %xmm1, %xmm11
        pxor      %xmm2, %xmm8
        psrld     $22, %xmm15
        paddd     %xmm8, %xmm4
        pslld     $10, %xmm11
        movdqa    80(%rsp), %xmm14
        por       %xmm11, %xmm15
        paddd     .L_2il0floatpacket.569(%rip), %xmm4
        movdqa    %xmm1, %xmm11
        movdqa    %xmm14, 496(%rsp)
        paddd     %xmm14, %xmm4
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm8
        psrld     $2, %xmm10
        pslld     $30, %xmm14
        psrld     $13, %xmm11
        pslld     $19, %xmm8
        por       %xmm14, %xmm10
        por       %xmm8, %xmm11
        pxor      %xmm11, %xmm10
        movdqa    %xmm5, %xmm11
        movdqa    %xmm1, %xmm8
        pxor      %xmm7, %xmm11
        pxor      %xmm7, %xmm8
        pxor      %xmm10, %xmm15
        pand      %xmm8, %xmm11
        paddd     %xmm4, %xmm3
        pxor      %xmm7, %xmm11
        movdqa    %xmm3, %xmm8
        paddd     %xmm11, %xmm15
        movdqa    %xmm3, %xmm11
        paddd     %xmm15, %xmm4
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm14
        psrld     $25, %xmm11
        pslld     $7, %xmm15
        psrld     $6, %xmm8
        pslld     $26, %xmm14
        por       %xmm15, %xmm11
        por       %xmm14, %xmm8
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm15
        psrld     $11, %xmm14
        pslld     $21, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm4, %xmm15
        pxor      %xmm14, %xmm8
        movdqa    %xmm4, %xmm14
        pxor      %xmm8, %xmm11
        movdqa    %xmm0, %xmm8
        pxor      %xmm6, %xmm8
        paddd     %xmm11, %xmm2
        pand      %xmm3, %xmm8
        movdqa    %xmm4, %xmm11
        pxor      %xmm6, %xmm8
        psrld     $22, %xmm14
        paddd     %xmm8, %xmm2
        pslld     $10, %xmm11
        movdqa    96(%rsp), %xmm10
        por       %xmm11, %xmm14
        paddd     .L_2il0floatpacket.570(%rip), %xmm2
        movdqa    %xmm4, %xmm11
        movdqa    %xmm10, 480(%rsp)
        paddd     %xmm10, %xmm2
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm8
        psrld     $2, %xmm15
        pslld     $30, %xmm10
        psrld     $13, %xmm11
        pslld     $19, %xmm8
        por       %xmm10, %xmm15
        por       %xmm8, %xmm11
        pxor      %xmm11, %xmm15
        movdqa    %xmm7, %xmm11
        movdqa    %xmm4, %xmm8
        pxor      %xmm1, %xmm11
        pxor      %xmm1, %xmm8
        pxor      %xmm15, %xmm14
        pand      %xmm8, %xmm11
        paddd     %xmm2, %xmm5
        pxor      %xmm1, %xmm11
        movdqa    %xmm5, %xmm8
        paddd     %xmm11, %xmm14
        movdqa    %xmm5, %xmm11
        paddd     %xmm14, %xmm2
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm10
        psrld     $25, %xmm11
        pslld     $7, %xmm14
        psrld     $6, %xmm8
        pslld     $26, %xmm10
        por       %xmm14, %xmm11
        por       %xmm10, %xmm8
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm14
        psrld     $11, %xmm10
        pslld     $21, %xmm14
        por       %xmm14, %xmm10
        movdqa    %xmm2, %xmm14
        pxor      %xmm10, %xmm8
        movdqa    %xmm2, %xmm10
        pxor      %xmm8, %xmm11
        movdqa    %xmm3, %xmm8
        pxor      %xmm0, %xmm8
        paddd     %xmm11, %xmm6
        pand      %xmm5, %xmm8
        movdqa    %xmm2, %xmm11
        pxor      %xmm0, %xmm8
        psrld     $22, %xmm10
        paddd     %xmm8, %xmm6
        pslld     $10, %xmm11
        movdqa    112(%rsp), %xmm15
        por       %xmm11, %xmm10
        paddd     .L_2il0floatpacket.571(%rip), %xmm6
        movdqa    %xmm2, %xmm11
        movdqa    %xmm15, 272(%rsp)
        paddd     %xmm15, %xmm6
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm8
        psrld     $2, %xmm14
        pslld     $30, %xmm15
        psrld     $13, %xmm11
        pslld     $19, %xmm8
        por       %xmm15, %xmm14
        por       %xmm8, %xmm11
        pxor      %xmm11, %xmm14
        movdqa    %xmm1, %xmm11
        movdqa    %xmm2, %xmm8
        pxor      %xmm4, %xmm11
        pxor      %xmm4, %xmm8
        pxor      %xmm14, %xmm10
        pand      %xmm8, %xmm11
        paddd     %xmm6, %xmm7
        pxor      %xmm4, %xmm11
        movdqa    %xmm7, %xmm8
        paddd     %xmm11, %xmm10
        movdqa    %xmm7, %xmm11
        paddd     %xmm10, %xmm6
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm15
        psrld     $25, %xmm11
        pslld     $7, %xmm10
        psrld     $6, %xmm8
        pslld     $26, %xmm15
        por       %xmm10, %xmm11
        por       %xmm15, %xmm8
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm10
        psrld     $11, %xmm15
        pslld     $21, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm6, %xmm10
        pxor      %xmm15, %xmm8
        movdqa    %xmm6, %xmm15
        pxor      %xmm8, %xmm11
        movdqa    %xmm5, %xmm8
        pxor      %xmm3, %xmm8
        paddd     %xmm11, %xmm0
        pand      %xmm7, %xmm8
        movdqa    %xmm6, %xmm11
        pxor      %xmm3, %xmm8
        psrld     $22, %xmm15
        paddd     %xmm8, %xmm0
        pslld     $10, %xmm11
        movdqa    128(%rsp), %xmm14
        por       %xmm11, %xmm15
        paddd     .L_2il0floatpacket.572(%rip), %xmm0
        movdqa    %xmm6, %xmm11
        movdqa    %xmm14, 256(%rsp)
        paddd     %xmm14, %xmm0
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm8
        psrld     $2, %xmm10
        pslld     $30, %xmm14
        psrld     $13, %xmm11
        pslld     $19, %xmm8
        por       %xmm14, %xmm10
        por       %xmm8, %xmm11
        pxor      %xmm11, %xmm10
        movdqa    %xmm4, %xmm11
        movdqa    %xmm6, %xmm8
        pxor      %xmm2, %xmm11
        pxor      %xmm2, %xmm8
        pxor      %xmm10, %xmm15
        pand      %xmm8, %xmm11
        paddd     %xmm0, %xmm1
        pxor      %xmm2, %xmm11
        movdqa    %xmm1, %xmm10
        paddd     %xmm11, %xmm15
        movdqa    %xmm1, %xmm11
        paddd     %xmm15, %xmm0
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm8
        psrld     $25, %xmm11
        pslld     $7, %xmm15
        psrld     $6, %xmm10
        pslld     $26, %xmm8
        por       %xmm15, %xmm11
        por       %xmm8, %xmm10
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm15
        psrld     $11, %xmm8
        pslld     $21, %xmm15
        por       %xmm15, %xmm8
        movdqa    %xmm0, %xmm15
        pxor      %xmm8, %xmm10
        movdqa    %xmm0, %xmm8
        pxor      %xmm10, %xmm11
        movdqa    %xmm7, %xmm10
        pxor      %xmm5, %xmm10
        paddd     %xmm11, %xmm3
        pand      %xmm1, %xmm10
        movdqa    %xmm0, %xmm11
        pxor      %xmm5, %xmm10
        psrld     $22, %xmm8
        paddd     %xmm10, %xmm3
        pslld     $10, %xmm11
        movdqa    144(%rsp), %xmm14
        por       %xmm11, %xmm8
        paddd     .L_2il0floatpacket.573(%rip), %xmm3
        movdqa    %xmm0, %xmm11
        movdqa    %xmm14, 464(%rsp)
        paddd     %xmm14, %xmm3
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm10
        psrld     $2, %xmm15
        pslld     $30, %xmm14
        psrld     $13, %xmm11
        pslld     $19, %xmm10
        por       %xmm14, %xmm15
        por       %xmm10, %xmm11
        pxor      %xmm11, %xmm15
        movdqa    %xmm2, %xmm11
        movdqa    %xmm0, %xmm10
        pxor      %xmm6, %xmm11
        pxor      %xmm6, %xmm10
        pxor      %xmm15, %xmm8
        pand      %xmm10, %xmm11
        paddd     %xmm3, %xmm4
        pxor      %xmm6, %xmm11
        movdqa    %xmm4, %xmm14
        paddd     %xmm11, %xmm8
        pslld     $7, %xmm14
        paddd     %xmm8, %xmm3
        movdqa    %xmm4, %xmm10
        movdqa    160(%rsp), %xmm8
        pslld     $26, %xmm10
        movdqa    %xmm8, 560(%rsp)
        movdqa    %xmm4, %xmm8
        psrld     $25, %xmm8
        movdqa    %xmm4, %xmm11
        por       %xmm14, %xmm8
        movdqa    %xmm4, %xmm14
        psrld     $6, %xmm14
        psrld     $11, %xmm11
        por       %xmm10, %xmm14
        movdqa    %xmm4, %xmm10
        pslld     $21, %xmm10
..B6.39:
        por       %xmm10, %xmm11
        movdqa    %xmm3, %xmm10
        pxor      %xmm11, %xmm14
        movdqa    %xmm1, %xmm11
        pxor      %xmm7, %xmm11
        pxor      %xmm14, %xmm8
        pand      %xmm4, %xmm11
        paddd     %xmm8, %xmm5
        pxor      %xmm7, %xmm11
        movdqa    %xmm3, %xmm8
        movdqa    %xmm13, 304(%rsp)
        paddd     %xmm11, %xmm5
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm13
        psrld     $22, %xmm10
        pslld     $10, %xmm8
        psrld     $2, %xmm11
        pslld     $30, %xmm13
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm15
        por       %xmm8, %xmm10
        por       %xmm13, %xmm11
        psrld     $13, %xmm14
        pslld     $19, %xmm15
        movdqa    %xmm6, %xmm8
        movdqa    %xmm3, %xmm13
        por       %xmm15, %xmm14
        pxor      %xmm0, %xmm8
        pxor      %xmm0, %xmm13
        pxor      %xmm14, %xmm11
        paddd     .L_2il0floatpacket.574(%rip), %xmm5
        pand      %xmm13, %xmm8
        paddd     560(%rsp), %xmm5
        pxor      %xmm11, %xmm10
        pxor      %xmm0, %xmm8
        paddd     %xmm5, %xmm2
        paddd     %xmm8, %xmm10
        movdqa    %xmm2, %xmm13
        paddd     %xmm10, %xmm5
        movdqa    %xmm2, %xmm10
        psrld     $25, %xmm13
        pslld     $7, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm15
        psrld     $6, %xmm10
        pslld     $26, %xmm8
        psrld     $11, %xmm11
        pslld     $21, %xmm15
        por       %xmm8, %xmm10
        por       %xmm15, %xmm11
        movdqa    %xmm4, %xmm8
        pxor      %xmm11, %xmm10
        pxor      %xmm1, %xmm8
        pxor      %xmm10, %xmm13
        pand      %xmm2, %xmm8
        pxor      %xmm1, %xmm8
        paddd     %xmm13, %xmm7
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm13
        paddd     %xmm8, %xmm7
        psrld     $22, %xmm15
        pslld     $10, %xmm13
        movdqa    %xmm5, %xmm10
        movdqa    176(%rsp), %xmm14
        por       %xmm13, %xmm15
        paddd     .L_2il0floatpacket.575(%rip), %xmm7
        movdqa    %xmm5, %xmm13
        movdqa    %xmm14, 544(%rsp)
        paddd     %xmm14, %xmm7
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm14
        psrld     $13, %xmm10
        pslld     $19, %xmm13
        psrld     $2, %xmm8
        pslld     $30, %xmm14
        por       %xmm13, %xmm10
        movdqa    %xmm0, %xmm13
        movdqa    %xmm3, %xmm11
        por       %xmm14, %xmm8
        pxor      %xmm3, %xmm13
        pxor      %xmm5, %xmm11
        pxor      %xmm10, %xmm8
        pand      %xmm11, %xmm13
        pxor      %xmm8, %xmm15
        pxor      %xmm3, %xmm13
        paddd     %xmm7, %xmm6
        paddd     %xmm13, %xmm15
        paddd     %xmm15, %xmm7
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm15
        psrld     $25, %xmm10
        pslld     $7, %xmm15
        movdqa    %xmm6, %xmm13
        por       %xmm15, %xmm10
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm14
        psrld     $6, %xmm15
        pslld     $26, %xmm13
        psrld     $11, %xmm11
        pslld     $21, %xmm14
        por       %xmm13, %xmm15
        por       %xmm14, %xmm11
        movdqa    %xmm4, %xmm13
        pxor      %xmm11, %xmm15
        pxor      %xmm2, %xmm13
        pxor      %xmm15, %xmm10
        pand      %xmm6, %xmm13
        paddd     %xmm10, %xmm1
        pxor      %xmm4, %xmm13
        movdqa    %xmm7, %xmm10
        paddd     %xmm13, %xmm1
        movdqa    %xmm7, %xmm13
        psrld     $22, %xmm13
        pslld     $10, %xmm10
        movdqa    192(%rsp), %xmm8
        por       %xmm10, %xmm13
        paddd     .L_2il0floatpacket.576(%rip), %xmm1
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm10
        paddd     %xmm8, %xmm1
        movdqa    %xmm8, 528(%rsp)
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm8
        psrld     $13, %xmm15
        pslld     $19, %xmm10
        psrld     $2, %xmm14
        pslld     $30, %xmm8
        por       %xmm10, %xmm15
        movdqa    %xmm3, %xmm10
        movdqa    %xmm7, %xmm11
        por       %xmm8, %xmm14
        pxor      %xmm5, %xmm10
        pxor      %xmm5, %xmm11
        pxor      %xmm15, %xmm14
        pand      %xmm11, %xmm10
        pxor      %xmm14, %xmm13
        pxor      %xmm5, %xmm10
        paddd     %xmm1, %xmm0
        paddd     %xmm10, %xmm13
        movdqa    %xmm0, %xmm14
        paddd     %xmm13, %xmm1
        movdqa    %xmm0, %xmm13
        psrld     $25, %xmm14
        pslld     $7, %xmm13
        por       %xmm13, %xmm14
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm8
        psrld     $6, %xmm13
        pslld     $26, %xmm10
        psrld     $11, %xmm15
        pslld     $21, %xmm8
        por       %xmm10, %xmm13
        por       %xmm8, %xmm15
        movdqa    %xmm6, %xmm10
        pxor      %xmm15, %xmm13
        pxor      %xmm2, %xmm10
        pxor      %xmm13, %xmm14
        pand      %xmm0, %xmm10
        pxor      %xmm2, %xmm10
        paddd     %xmm14, %xmm4
        paddd     %xmm10, %xmm4
        movdqa    %xmm1, %xmm15
        movdqa    208(%rsp), %xmm11
        movdqa    %xmm1, %xmm14
        paddd     .L_2il0floatpacket.577(%rip), %xmm4
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm13
        paddd     %xmm11, %xmm4
        movdqa    %xmm11, 448(%rsp)
        psrld     $22, %xmm15
        pslld     $10, %xmm14
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm11
        psrld     $13, %xmm10
        pslld     $19, %xmm13
        por       %xmm14, %xmm15
        psrld     $2, %xmm8
        pslld     $30, %xmm11
        por       %xmm13, %xmm10
        movdqa    %xmm5, %xmm13
        movdqa    %xmm1, %xmm14
        por       %xmm11, %xmm8
        pxor      %xmm7, %xmm13
        pxor      %xmm7, %xmm14
        pxor      %xmm10, %xmm8
        pand      %xmm14, %xmm13
        paddd     %xmm4, %xmm3
        pxor      %xmm8, %xmm15
        pxor      %xmm7, %xmm13
        movdqa    %xmm3, %xmm11
        paddd     %xmm13, %xmm15
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm8
        paddd     %xmm15, %xmm4
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm15
        psrld     $6, %xmm11
        pslld     $26, %xmm13
        psrld     $11, %xmm14
        pslld     $21, %xmm8
        psrld     $25, %xmm10
        pslld     $7, %xmm15
        por       %xmm13, %xmm11
        por       %xmm8, %xmm14
        movdqa    %xmm0, %xmm13
        por       %xmm15, %xmm10
        pxor      %xmm14, %xmm11
        pxor      %xmm6, %xmm13
        pxor      %xmm11, %xmm10
        pand      %xmm3, %xmm13
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm15
        pxor      %xmm6, %xmm13
        paddd     %xmm10, %xmm2
        psrld     $22, %xmm8
        pslld     $10, %xmm15
        paddd     %xmm13, %xmm2
        por       %xmm15, %xmm8
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm13
        psrld     $2, %xmm11
        pslld     $30, %xmm14
        psrld     $13, %xmm15
        pslld     $19, %xmm13
        por       %xmm14, %xmm11
        por       %xmm13, %xmm15
        movdqa    %xmm4, %xmm13
        pxor      %xmm15, %xmm11
        movdqa    %xmm7, %xmm15
        pxor      %xmm1, %xmm15
        pxor      %xmm1, %xmm13
        paddd     .L_2il0floatpacket.578(%rip), %xmm2
        pand      %xmm13, %xmm15
        movdqa    432(%rsp), %xmm10
        pxor      %xmm11, %xmm8
        paddd     %xmm10, %xmm2
        pxor      %xmm1, %xmm15
        paddd     %xmm2, %xmm5
        paddd     %xmm15, %xmm8
        paddd     %xmm8, %xmm2
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm8
        psrld     $25, %xmm13
        pslld     $7, %xmm8
        movdqa    %xmm5, %xmm15
        por       %xmm8, %xmm13
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm14
        psrld     $6, %xmm8
        pslld     $26, %xmm15
        psrld     $11, %xmm11
        pslld     $21, %xmm14
        por       %xmm15, %xmm8
        por       %xmm14, %xmm11
        pxor      %xmm11, %xmm8
        movdqa    %xmm3, %xmm15
        pxor      %xmm8, %xmm13
        pxor      %xmm0, %xmm15
        pand      %xmm5, %xmm15
        paddd     %xmm13, %xmm6
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm13
        pxor      %xmm0, %xmm15
        psrld     $22, %xmm11
        pslld     $10, %xmm13
        paddd     %xmm15, %xmm6
        por       %xmm13, %xmm11
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm15
        psrld     $2, %xmm13
        pslld     $30, %xmm8
        psrld     $13, %xmm14
        pslld     $19, %xmm15
        por       %xmm8, %xmm13
        por       %xmm15, %xmm14
        movdqa    %xmm1, %xmm15
        movdqa    %xmm2, %xmm8
        pxor      %xmm4, %xmm15
        pxor      %xmm4, %xmm8
        pxor      %xmm14, %xmm13
        pand      %xmm8, %xmm15
        pxor      %xmm13, %xmm11
        pxor      %xmm4, %xmm15
        movdqa    %xmm9, %xmm13
        paddd     .L_2il0floatpacket.579(%rip), %xmm6
        paddd     %xmm15, %xmm11
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm8
        psrld     $7, %xmm15
        paddd     336(%rsp), %xmm6
        pslld     $25, %xmm13
        psrld     $18, %xmm14
        pslld     $14, %xmm8
        paddd     %xmm6, %xmm7
        paddd     %xmm11, %xmm6
        movdqa    %xmm9, %xmm11
        por       %xmm13, %xmm15
        por       %xmm8, %xmm14
        psrld     $3, %xmm11
        pxor      %xmm14, %xmm15
        movdqa    %xmm10, %xmm13
        pxor      %xmm15, %xmm11
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm8
        movdqa    %xmm10, %xmm14
        psrld     $17, %xmm15
        pslld     $15, %xmm13
        psrld     $19, %xmm8
        pslld     $13, %xmm10
        por       %xmm13, %xmm15
        por       %xmm10, %xmm8
        psrld     $10, %xmm14
        pxor      %xmm8, %xmm15
        pxor      %xmm15, %xmm14
        movdqa    %xmm7, %xmm15
        paddd     464(%rsp), %xmm14
        pslld     $7, %xmm15
        movdqa    288(%rsp), %xmm13
        movdqa    %xmm7, %xmm8
        paddd     %xmm14, %xmm13
        movdqa    %xmm7, %xmm14
        paddd     %xmm13, %xmm11
        movdqa    %xmm7, %xmm13
        psrld     $25, %xmm13
        movdqa    %xmm7, %xmm10
        por       %xmm15, %xmm13
        movdqa    %xmm7, %xmm15
        psrld     $6, %xmm15
        pslld     $26, %xmm14
        psrld     $11, %xmm8
        pslld     $21, %xmm10
        por       %xmm14, %xmm15
        por       %xmm10, %xmm8
        pxor      %xmm8, %xmm15
        movdqa    %xmm5, %xmm10
        pxor      %xmm15, %xmm13
        pxor      %xmm3, %xmm10
        pand      %xmm7, %xmm10
        paddd     %xmm13, %xmm0
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm13
        pxor      %xmm3, %xmm10
        psrld     $22, %xmm8
        pslld     $10, %xmm13
        paddd     %xmm10, %xmm0
        por       %xmm13, %xmm8
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm15
        psrld     $2, %xmm13
        pslld     $30, %xmm10
        psrld     $13, %xmm14
        pslld     $19, %xmm15
        por       %xmm10, %xmm13
        por       %xmm15, %xmm14
        movdqa    %xmm4, %xmm15
        movdqa    %xmm6, %xmm10
        pxor      %xmm2, %xmm15
        pxor      %xmm2, %xmm10
        pxor      %xmm14, %xmm13
        pand      %xmm10, %xmm15
        pxor      %xmm13, %xmm8
        pxor      %xmm2, %xmm15
        movdqa    %xmm12, %xmm13
        paddd     .L_2il0floatpacket.580(%rip), %xmm0
        paddd     %xmm15, %xmm8
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm14
        movdqa    %xmm12, %xmm10
        paddd     %xmm11, %xmm0
        psrld     $7, %xmm15
        pslld     $25, %xmm13
        psrld     $18, %xmm14
        pslld     $14, %xmm10
        paddd     %xmm0, %xmm1
        paddd     %xmm8, %xmm0
        movdqa    %xmm12, %xmm8
        por       %xmm13, %xmm15
        por       %xmm10, %xmm14
        psrld     $3, %xmm8
        movdqa    336(%rsp), %xmm13
        pxor      %xmm14, %xmm15
        pxor      %xmm15, %xmm8
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm14
        psrld     $17, %xmm15
        pslld     $15, %xmm14
        movdqa    %xmm13, %xmm10
        por       %xmm14, %xmm15
        movdqa    %xmm13, %xmm14
        psrld     $19, %xmm14
        pslld     $13, %xmm13
        por       %xmm13, %xmm14
        psrld     $10, %xmm10
        pxor      %xmm14, %xmm15
        movdqa    %xmm1, %xmm13
        pxor      %xmm15, %xmm10
        movdqa    %xmm1, %xmm15
        paddd     560(%rsp), %xmm10
        movdqa    %xmm1, %xmm14
        paddd     %xmm10, %xmm9
        movdqa    %xmm1, %xmm10
        paddd     %xmm9, %xmm8
        movdqa    %xmm1, %xmm9
        psrld     $25, %xmm10
        pslld     $7, %xmm9
        por       %xmm9, %xmm10
        movdqa    %xmm1, %xmm9
        psrld     $6, %xmm9
        pslld     $26, %xmm13
        psrld     $11, %xmm15
        pslld     $21, %xmm14
        por       %xmm13, %xmm9
        por       %xmm14, %xmm15
        movdqa    %xmm7, %xmm13
        pxor      %xmm15, %xmm9
        pxor      %xmm5, %xmm13
        pxor      %xmm9, %xmm10
        pand      %xmm1, %xmm13
        paddd     %xmm10, %xmm3
        pxor      %xmm5, %xmm13
        movdqa    %xmm0, %xmm10
        paddd     %xmm13, %xmm3
        movdqa    %xmm0, %xmm13
        psrld     $22, %xmm13
        pslld     $10, %xmm10
        paddd     .L_2il0floatpacket.581(%rip), %xmm3
        por       %xmm10, %xmm13
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm10
        movdqa    %xmm8, 352(%rsp)
        paddd     %xmm8, %xmm3
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm8
        psrld     $13, %xmm9
        pslld     $19, %xmm10
        psrld     $2, %xmm14
        pslld     $30, %xmm8
        por       %xmm10, %xmm9
        movdqa    %xmm2, %xmm10
        movdqa    %xmm0, %xmm15
        por       %xmm8, %xmm14
        pxor      %xmm6, %xmm10
        pxor      %xmm6, %xmm15
        pxor      %xmm9, %xmm14
        pand      %xmm15, %xmm10
        pxor      %xmm14, %xmm13
        pxor      %xmm6, %xmm10
        paddd     %xmm10, %xmm13
        paddd     %xmm3, %xmm4
        paddd     %xmm13, %xmm3
        movdqa    304(%rsp), %xmm13
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm8
        movdqa    %xmm13, %xmm14
        movdqa    %xmm13, %xmm9
        psrld     $7, %xmm15
        pslld     $25, %xmm8
        psrld     $18, %xmm14
        pslld     $14, %xmm9
        movdqa    %xmm13, %xmm10
        por       %xmm8, %xmm15
        por       %xmm9, %xmm14
        psrld     $3, %xmm10
        pxor      %xmm14, %xmm15
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, %xmm8
        movdqa    %xmm11, %xmm9
        movdqa    %xmm11, 576(%rsp)
        pxor      %xmm15, %xmm10
        movdqa    %xmm11, %xmm15
        psrld     $17, %xmm14
        pslld     $15, %xmm8
        psrld     $19, %xmm9
        pslld     $13, %xmm11
        por       %xmm8, %xmm14
        por       %xmm11, %xmm9
        psrld     $10, %xmm15
        pxor      %xmm9, %xmm14
        movdqa    %xmm4, %xmm8
        pxor      %xmm14, %xmm15
        movdqa    %xmm4, %xmm14
        paddd     176(%rsp), %xmm15
        movdqa    %xmm4, %xmm11
        paddd     %xmm15, %xmm12
        movdqa    %xmm4, %xmm15
        paddd     %xmm12, %xmm10
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm12
        psrld     $6, %xmm15
        pslld     $26, %xmm8
        psrld     $11, %xmm14
        pslld     $21, %xmm11
        psrld     $25, %xmm9
        pslld     $7, %xmm12
        por       %xmm8, %xmm15
        por       %xmm11, %xmm14
        por       %xmm12, %xmm9
        pxor      %xmm14, %xmm15
        movdqa    %xmm1, %xmm8
        pxor      %xmm15, %xmm9
        pxor      %xmm7, %xmm8
        paddd     %xmm9, %xmm5
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm9
        pand      %xmm4, %xmm8
        psrld     $22, %xmm12
        pslld     $10, %xmm9
        pxor      %xmm7, %xmm8
        por       %xmm9, %xmm12
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm11
        paddd     %xmm8, %xmm5
        psrld     $2, %xmm9
        pslld     $30, %xmm11
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm14
        por       %xmm11, %xmm9
        psrld     $13, %xmm8
        pslld     $19, %xmm14
        movdqa    %xmm6, %xmm15
        movdqa    %xmm3, %xmm11
        por       %xmm14, %xmm8
        pxor      %xmm0, %xmm15
        pxor      %xmm0, %xmm11
        pxor      %xmm8, %xmm9
        pand      %xmm11, %xmm15
        pxor      %xmm9, %xmm12
        paddd     .L_2il0floatpacket.582(%rip), %xmm5
        pxor      %xmm0, %xmm15
        movdqa    512(%rsp), %xmm9
        paddd     %xmm10, %xmm5
        paddd     %xmm15, %xmm12
        paddd     %xmm5, %xmm2
        paddd     %xmm12, %xmm5
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm12
        movdqa    %xmm9, %xmm11
        movdqa    %xmm9, %xmm8
        psrld     $7, %xmm14
        pslld     $25, %xmm12
        psrld     $18, %xmm11
        pslld     $14, %xmm9
        por       %xmm12, %xmm14
        por       %xmm9, %xmm11
        psrld     $3, %xmm8
        pxor      %xmm11, %xmm14
        pxor      %xmm14, %xmm8
..B6.38:
        movdqa    352(%rsp), %xmm11
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, %xmm15
        movdqa    %xmm11, %xmm12
        movdqa    %xmm11, %xmm9
        psrld     $17, %xmm14
        pslld     $15, %xmm15
        psrld     $19, %xmm12
        pslld     $13, %xmm11
        por       %xmm15, %xmm14
        por       %xmm11, %xmm12
        psrld     $10, %xmm9
        pxor      %xmm12, %xmm14
        pxor      %xmm14, %xmm9
        movdqa    %xmm2, %xmm15
        paddd     528(%rsp), %xmm9
        movdqa    %xmm2, %xmm14
        paddd     %xmm9, %xmm13
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm11
        paddd     %xmm13, %xmm8
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm13
        psrld     $6, %xmm15
        pslld     $26, %xmm14
        psrld     $11, %xmm9
        pslld     $21, %xmm11
        psrld     $25, %xmm12
        pslld     $7, %xmm13
        por       %xmm14, %xmm15
        por       %xmm11, %xmm9
        movdqa    %xmm4, %xmm14
        por       %xmm13, %xmm12
        pxor      %xmm9, %xmm15
        pxor      %xmm1, %xmm14
        pxor      %xmm15, %xmm12
        pand      %xmm2, %xmm14
        pxor      %xmm1, %xmm14
        paddd     %xmm12, %xmm7
        paddd     %xmm14, %xmm7
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm14
        psrld     $22, %xmm11
        pslld     $10, %xmm12
        psrld     $2, %xmm15
        pslld     $30, %xmm14
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm9
        por       %xmm12, %xmm11
        por       %xmm14, %xmm15
        psrld     $13, %xmm13
        pslld     $19, %xmm9
        movdqa    %xmm0, %xmm14
        movdqa    %xmm5, %xmm12
        por       %xmm9, %xmm13
        pxor      %xmm3, %xmm14
        pxor      %xmm3, %xmm12
        pxor      %xmm13, %xmm15
        pand      %xmm12, %xmm14
        movdqa    496(%rsp), %xmm13
        pxor      %xmm15, %xmm11
        pxor      %xmm3, %xmm14
        movdqa    %xmm13, %xmm15
        paddd     .L_2il0floatpacket.583(%rip), %xmm7
        paddd     %xmm14, %xmm11
        movdqa    %xmm13, %xmm9
        movdqa    %xmm13, %xmm14
        movdqa    %xmm13, %xmm12
        paddd     %xmm8, %xmm7
        psrld     $7, %xmm15
        pslld     $25, %xmm9
        psrld     $18, %xmm14
        pslld     $14, %xmm12
        paddd     %xmm7, %xmm6
        paddd     %xmm11, %xmm7
        movdqa    %xmm13, %xmm11
        por       %xmm9, %xmm15
        por       %xmm12, %xmm14
        psrld     $3, %xmm11
        pxor      %xmm14, %xmm15
        movdqa    %xmm10, %xmm12
        pxor      %xmm15, %xmm11
        movdqa    %xmm10, %xmm9
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, 592(%rsp)
        psrld     $17, %xmm12
        pslld     $15, %xmm9
        psrld     $19, %xmm15
        pslld     $13, %xmm10
        por       %xmm9, %xmm12
        por       %xmm10, %xmm15
        psrld     $10, %xmm14
        pxor      %xmm15, %xmm12
        movdqa    %xmm6, %xmm9
        pxor      %xmm12, %xmm14
        psrld     $25, %xmm9
        paddd     448(%rsp), %xmm14
        movdqa    %xmm6, %xmm10
        movdqa    512(%rsp), %xmm12
        movdqa    %xmm6, %xmm15
        paddd     %xmm14, %xmm12
        movdqa    %xmm6, %xmm14
        pslld     $7, %xmm14
        paddd     %xmm12, %xmm11
        por       %xmm14, %xmm9
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm12
        psrld     $6, %xmm14
        pslld     $26, %xmm10
        psrld     $11, %xmm15
        pslld     $21, %xmm12
        por       %xmm10, %xmm14
        por       %xmm12, %xmm15
        movdqa    %xmm2, %xmm10
        pxor      %xmm15, %xmm14
        pxor      %xmm4, %xmm10
        pxor      %xmm14, %xmm9
        pand      %xmm6, %xmm10
        pxor      %xmm4, %xmm10
        paddd     %xmm9, %xmm1
        paddd     %xmm10, %xmm1
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm9
        psrld     $22, %xmm10
        pslld     $10, %xmm9
        movdqa    %xmm7, %xmm12
        por       %xmm9, %xmm10
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm14
        psrld     $2, %xmm9
        pslld     $30, %xmm12
        psrld     $13, %xmm15
        pslld     $19, %xmm14
        por       %xmm12, %xmm9
        por       %xmm14, %xmm15
        movdqa    %xmm3, %xmm14
        movdqa    %xmm5, %xmm12
        pxor      %xmm5, %xmm14
        pxor      %xmm7, %xmm12
        pxor      %xmm15, %xmm9
        pand      %xmm12, %xmm14
        paddd     .L_2il0floatpacket.584(%rip), %xmm1
        pxor      %xmm9, %xmm10
        pxor      %xmm5, %xmm14
        paddd     %xmm11, %xmm1
        paddd     %xmm14, %xmm10
        paddd     %xmm1, %xmm0
        paddd     %xmm10, %xmm1
        movdqa    480(%rsp), %xmm10
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm15
        psrld     $7, %xmm14
        pslld     $25, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm12
        psrld     $18, %xmm15
        pslld     $14, %xmm12
        movdqa    %xmm10, %xmm9
        por       %xmm12, %xmm15
        psrld     $3, %xmm9
        pxor      %xmm15, %xmm14
        movdqa    %xmm8, %xmm15
        pxor      %xmm14, %xmm9
        movdqa    %xmm8, %xmm14
        psrld     $17, %xmm15
        pslld     $15, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm8, %xmm14
        movdqa    %xmm8, 416(%rsp)
        movdqa    %xmm8, %xmm12
        psrld     $19, %xmm14
        pslld     $13, %xmm8
        por       %xmm8, %xmm14
        psrld     $10, %xmm12
        pxor      %xmm14, %xmm15
        movdqa    %xmm0, %xmm14
        pxor      %xmm15, %xmm12
        pslld     $7, %xmm14
        paddd     432(%rsp), %xmm12
        movdqa    %xmm0, %xmm8
        paddd     %xmm12, %xmm13
        movdqa    %xmm0, %xmm12
        psrld     $25, %xmm12
        paddd     %xmm13, %xmm9
        por       %xmm14, %xmm12
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm15
        psrld     $6, %xmm8
        pslld     $26, %xmm13
        psrld     $11, %xmm14
        pslld     $21, %xmm15
        por       %xmm13, %xmm8
        por       %xmm15, %xmm14
        pxor      %xmm14, %xmm8
        movdqa    %xmm2, %xmm13
        pxor      %xmm8, %xmm12
        pxor      %xmm6, %xmm13
        pand      %xmm0, %xmm13
        paddd     %xmm12, %xmm4
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm12
        pxor      %xmm2, %xmm13
        psrld     $22, %xmm8
        pslld     $10, %xmm12
        paddd     %xmm13, %xmm4
        por       %xmm12, %xmm8
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm13
        psrld     $2, %xmm12
        pslld     $30, %xmm14
        psrld     $13, %xmm15
        pslld     $19, %xmm13
        por       %xmm14, %xmm12
        por       %xmm13, %xmm15
        movdqa    %xmm5, %xmm13
        pxor      %xmm15, %xmm12
        movdqa    %xmm1, %xmm14
        pxor      %xmm12, %xmm8
        pxor      %xmm7, %xmm13
        movdqa    272(%rsp), %xmm12
        pxor      %xmm7, %xmm14
        pand      %xmm14, %xmm13
        movdqa    %xmm12, %xmm14
        movdqa    %xmm12, %xmm15
        pxor      %xmm7, %xmm13
        psrld     $7, %xmm14
        pslld     $25, %xmm15
        paddd     .L_2il0floatpacket.585(%rip), %xmm4
        paddd     %xmm13, %xmm8
        por       %xmm15, %xmm14
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm13
        paddd     %xmm9, %xmm4
        psrld     $18, %xmm15
        pslld     $14, %xmm13
        paddd     %xmm4, %xmm3
        paddd     %xmm8, %xmm4
        movdqa    %xmm12, %xmm8
        por       %xmm13, %xmm15
        psrld     $3, %xmm8
        pxor      %xmm15, %xmm14
        pxor      %xmm14, %xmm8
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm14
        psrld     $17, %xmm13
        pslld     $15, %xmm14
        movdqa    %xmm11, %xmm15
        por       %xmm14, %xmm13
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, 608(%rsp)
        psrld     $19, %xmm14
        pslld     $13, %xmm11
        psrld     $10, %xmm15
        por       %xmm11, %xmm14
        movdqa    %xmm3, %xmm11
        pxor      %xmm14, %xmm13
        movdqa    %xmm3, %xmm14
        pxor      %xmm13, %xmm15
        movdqa    %xmm3, %xmm13
        paddd     336(%rsp), %xmm15
        psrld     $6, %xmm11
        paddd     %xmm15, %xmm10
        movdqa    %xmm3, %xmm15
        paddd     %xmm10, %xmm8
        movdqa    %xmm3, %xmm10
        psrld     $25, %xmm15
        pslld     $7, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm3, %xmm10
        pslld     $26, %xmm14
        psrld     $11, %xmm10
        pslld     $21, %xmm13
        por       %xmm14, %xmm11
        por       %xmm13, %xmm10
        movdqa    %xmm0, %xmm14
        pxor      %xmm10, %xmm11
        pxor      %xmm6, %xmm14
        pxor      %xmm11, %xmm15
        pand      %xmm3, %xmm14
        paddd     %xmm15, %xmm2
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm15
        pxor      %xmm6, %xmm14
        psrld     $22, %xmm10
        pslld     $10, %xmm15
        paddd     %xmm14, %xmm2
        por       %xmm15, %xmm10
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm11
        psrld     $2, %xmm15
        pslld     $30, %xmm14
        psrld     $13, %xmm13
        pslld     $19, %xmm11
        por       %xmm14, %xmm15
        por       %xmm11, %xmm13
        movdqa    %xmm7, %xmm11
        movdqa    %xmm4, %xmm14
        pxor      %xmm1, %xmm11
        pxor      %xmm1, %xmm14
        pxor      %xmm13, %xmm15
        pand      %xmm14, %xmm11
        pxor      %xmm15, %xmm10
        pxor      %xmm1, %xmm11
        movdqa    256(%rsp), %xmm15
        paddd     %xmm11, %xmm10
        movdqa    %xmm15, %xmm11
        movdqa    %xmm15, %xmm13
        psrld     $7, %xmm11
        pslld     $25, %xmm13
        paddd     .L_2il0floatpacket.586(%rip), %xmm2
        por       %xmm13, %xmm11
        movdqa    %xmm15, %xmm13
        movdqa    %xmm15, %xmm14
        paddd     %xmm8, %xmm2
        psrld     $18, %xmm13
        pslld     $14, %xmm14
        paddd     %xmm2, %xmm5
        paddd     %xmm10, %xmm2
        movdqa    %xmm15, %xmm10
        por       %xmm14, %xmm13
        psrld     $3, %xmm10
        pxor      %xmm13, %xmm11
        movdqa    %xmm9, %xmm13
        pxor      %xmm11, %xmm10
        movdqa    %xmm9, %xmm11
        psrld     $17, %xmm13
        pslld     $15, %xmm11
        por       %xmm11, %xmm13
        movdqa    %xmm9, %xmm11
        movdqa    %xmm9, 400(%rsp)
        movdqa    %xmm9, %xmm14
        psrld     $19, %xmm11
        pslld     $13, %xmm9
        por       %xmm9, %xmm11
        psrld     $10, %xmm14
        pxor      %xmm11, %xmm13
        movdqa    %xmm5, %xmm11
        pxor      %xmm13, %xmm14
        movdqa    %xmm5, %xmm13
        paddd     576(%rsp), %xmm14
        movdqa    %xmm5, %xmm9
        paddd     %xmm14, %xmm12
        movdqa    %xmm5, %xmm14
        paddd     %xmm12, %xmm10
        movdqa    %xmm5, %xmm12
        psrld     $25, %xmm14
        pslld     $7, %xmm12
        por       %xmm12, %xmm14
        movdqa    %xmm5, %xmm12
        psrld     $6, %xmm12
        pslld     $26, %xmm11
        psrld     $11, %xmm13
        pslld     $21, %xmm9
        por       %xmm11, %xmm12
        por       %xmm9, %xmm13
        pxor      %xmm13, %xmm12
        movdqa    %xmm3, %xmm11
        pxor      %xmm12, %xmm14
        pxor      %xmm0, %xmm11
        pand      %xmm5, %xmm11
        paddd     %xmm14, %xmm6
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm14
        pxor      %xmm0, %xmm11
        psrld     $22, %xmm12
        pslld     $10, %xmm14
        paddd     %xmm11, %xmm6
        por       %xmm14, %xmm12
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm9
        psrld     $2, %xmm14
        pslld     $30, %xmm11
        psrld     $13, %xmm13
        pslld     $19, %xmm9
        por       %xmm11, %xmm14
        por       %xmm9, %xmm13
        movdqa    %xmm1, %xmm9
        movdqa    %xmm2, %xmm11
        pxor      %xmm4, %xmm9
        pxor      %xmm4, %xmm11
        pxor      %xmm13, %xmm14
        pand      %xmm11, %xmm9
        pxor      %xmm14, %xmm12
        paddd     .L_2il0floatpacket.587(%rip), %xmm6
        pxor      %xmm4, %xmm9
        paddd     %xmm10, %xmm6
        paddd     %xmm9, %xmm12
        paddd     %xmm6, %xmm7
        paddd     %xmm12, %xmm6
        movdqa    464(%rsp), %xmm12
        movdqa    %xmm12, %xmm11
        movdqa    %xmm12, %xmm13
        psrld     $7, %xmm11
        pslld     $25, %xmm13
        por       %xmm13, %xmm11
        movdqa    %xmm12, %xmm13
        movdqa    %xmm12, %xmm9
        psrld     $18, %xmm13
        pslld     $14, %xmm9
        movdqa    %xmm12, %xmm14
        por       %xmm9, %xmm13
        psrld     $3, %xmm14
        pxor      %xmm13, %xmm11
        movdqa    %xmm8, %xmm9
        pxor      %xmm11, %xmm14
        movdqa    %xmm8, %xmm11
        psrld     $17, %xmm11
        pslld     $15, %xmm9
        por       %xmm9, %xmm11
        movdqa    %xmm8, %xmm9
        movdqa    %xmm8, 384(%rsp)
        movdqa    %xmm8, %xmm13
        psrld     $19, %xmm9
        pslld     $13, %xmm8
        por       %xmm8, %xmm9
        psrld     $10, %xmm13
        pxor      %xmm9, %xmm11
        movdqa    %xmm7, %xmm8
        pxor      %xmm11, %xmm13
        movdqa    %xmm7, %xmm11
        paddd     352(%rsp), %xmm13
        psrld     $25, %xmm11
        paddd     %xmm13, %xmm15
        movdqa    %xmm7, %xmm13
        paddd     %xmm15, %xmm14
        movdqa    %xmm7, %xmm15
        pslld     $7, %xmm15
        movdqa    %xmm7, %xmm9
        por       %xmm15, %xmm11
        movdqa    %xmm7, %xmm15
        psrld     $6, %xmm15
        pslld     $26, %xmm8
        psrld     $11, %xmm13
        pslld     $21, %xmm9
        por       %xmm8, %xmm15
        por       %xmm9, %xmm13
        movdqa    %xmm5, %xmm8
        pxor      %xmm13, %xmm15
        pxor      %xmm3, %xmm8
        pxor      %xmm15, %xmm11
        pand      %xmm7, %xmm8
        paddd     %xmm11, %xmm0
        pxor      %xmm3, %xmm8
        movdqa    %xmm6, %xmm13
        paddd     %xmm8, %xmm0
        psrld     $22, %xmm13
        paddd     .L_2il0floatpacket.588(%rip), %xmm0
        movdqa    %xmm6, %xmm8
        movdqa    %xmm14, 320(%rsp)
        paddd     %xmm14, %xmm0
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm9
        pslld     $10, %xmm14
        movdqa    %xmm6, %xmm11
        por       %xmm14, %xmm13
        movdqa    %xmm6, %xmm14
        psrld     $13, %xmm8
        pslld     $19, %xmm14
        psrld     $2, %xmm9
        pslld     $30, %xmm11
        por       %xmm14, %xmm8
        movdqa    %xmm4, %xmm14
        movdqa    %xmm6, %xmm15
        por       %xmm11, %xmm9
        pxor      %xmm2, %xmm14
        pxor      %xmm2, %xmm15
        pxor      %xmm8, %xmm9
        pand      %xmm15, %xmm14
        pxor      %xmm9, %xmm13
        pxor      %xmm2, %xmm14
        paddd     %xmm14, %xmm13
        paddd     %xmm0, %xmm1
        movdqa    560(%rsp), %xmm14
        paddd     %xmm13, %xmm0
        movdqa    %xmm14, %xmm9
        movdqa    %xmm14, %xmm13
        movdqa    %xmm14, %xmm8
        movdqa    %xmm14, %xmm11
        psrld     $7, %xmm9
        pslld     $25, %xmm13
        psrld     $18, %xmm8
        pslld     $14, %xmm14
        por       %xmm13, %xmm9
        por       %xmm14, %xmm8
        psrld     $3, %xmm11
        pxor      %xmm8, %xmm9
        movdqa    %xmm10, %xmm8
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm14
        pxor      %xmm9, %xmm11
        movdqa    %xmm10, 368(%rsp)
        movdqa    %xmm10, %xmm9
        psrld     $17, %xmm8
        pslld     $15, %xmm15
        psrld     $19, %xmm14
        pslld     $13, %xmm10
        por       %xmm15, %xmm8
        por       %xmm10, %xmm14
        psrld     $10, %xmm9
        pxor      %xmm14, %xmm8
        movdqa    592(%rsp), %xmm10
        pxor      %xmm8, %xmm9
        paddd     %xmm10, %xmm9
        movdqa    %xmm1, %xmm8
        paddd     %xmm9, %xmm12
        movdqa    %xmm1, %xmm15
        paddd     %xmm12, %xmm11
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm9
        psrld     $25, %xmm8
        pslld     $7, %xmm12
        psrld     $6, %xmm15
        pslld     $26, %xmm14
        psrld     $11, %xmm13
        pslld     $21, %xmm9
        por       %xmm12, %xmm8
        por       %xmm14, %xmm15
        por       %xmm9, %xmm13
        movdqa    %xmm7, %xmm12
        pxor      %xmm13, %xmm15
        pxor      %xmm5, %xmm12
        pxor      %xmm15, %xmm8
        pand      %xmm1, %xmm12
        paddd     %xmm8, %xmm3
        pxor      %xmm5, %xmm12
        movdqa    %xmm0, %xmm14
        paddd     %xmm12, %xmm3
        movdqa    %xmm0, %xmm8
        paddd     .L_2il0floatpacket.589(%rip), %xmm3
        psrld     $22, %xmm14
        pslld     $10, %xmm8
        paddd     %xmm11, %xmm3
        movdqa    %xmm11, 288(%rsp)
        por       %xmm8, %xmm14
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm12
        psrld     $2, %xmm9
        pslld     $30, %xmm11
        psrld     $13, %xmm8
        pslld     $19, %xmm12
        movdqa    %xmm2, %xmm15
        movdqa    %xmm0, %xmm13
        por       %xmm11, %xmm9
        por       %xmm12, %xmm8
        pxor      %xmm6, %xmm15
        pxor      %xmm6, %xmm13
        pxor      %xmm8, %xmm9
        pand      %xmm13, %xmm15
        pxor      %xmm9, %xmm14
        pxor      %xmm6, %xmm15
        movdqa    544(%rsp), %xmm11
        paddd     %xmm15, %xmm14
        paddd     %xmm3, %xmm4
        paddd     %xmm14, %xmm3
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, %xmm12
        psrld     $3, %xmm14
        psrld     $7, %xmm12
        movdqa    416(%rsp), %xmm8
        pslld     $25, %xmm11
        movdqa    608(%rsp), %xmm9
        movdqa    %xmm14, 304(%rsp)
..B6.37:
        movdqa    %xmm10, 592(%rsp)
        por       %xmm11, %xmm12
        movdqa    544(%rsp), %xmm10
        movdqa    %xmm10, %xmm11
        movdqa    %xmm10, %xmm13
        pslld     $14, %xmm11
        psrld     $18, %xmm13
        por       %xmm11, %xmm13
        movdqa    304(%rsp), %xmm11
        pxor      %xmm13, %xmm12
        pxor      %xmm12, %xmm11
        movdqa    320(%rsp), %xmm12
        movdqa    %xmm12, %xmm14
        movdqa    %xmm12, %xmm15
        psrld     $17, %xmm14
        pslld     $15, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm13
        psrld     $19, %xmm15
        pslld     $13, %xmm12
        psrld     $10, %xmm13
        por       %xmm12, %xmm15
        movdqa    %xmm4, %xmm12
        pxor      %xmm15, %xmm14
        pslld     $7, %xmm12
        pxor      %xmm14, %xmm13
        movdqa    %xmm4, %xmm15
        movdqa    %xmm8, 416(%rsp)
        paddd     %xmm8, %xmm13
        movdqa    560(%rsp), %xmm8
        movdqa    %xmm4, %xmm14
        paddd     %xmm13, %xmm8
        movdqa    %xmm4, %xmm13
        psrld     $25, %xmm13
        paddd     %xmm8, %xmm11
        por       %xmm12, %xmm13
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm12
        psrld     $6, %xmm8
        pslld     $26, %xmm15
        psrld     $11, %xmm12
        pslld     $21, %xmm14
        por       %xmm15, %xmm8
        por       %xmm14, %xmm12
        movdqa    %xmm1, %xmm15
        pxor      %xmm12, %xmm8
        pxor      %xmm7, %xmm15
        pxor      %xmm8, %xmm13
        pand      %xmm4, %xmm15
        paddd     %xmm13, %xmm5
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm13
        pxor      %xmm7, %xmm15
        psrld     $22, %xmm12
        pslld     $10, %xmm13
        paddd     %xmm15, %xmm5
        por       %xmm13, %xmm12
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm14
        psrld     $2, %xmm13
        pslld     $30, %xmm15
        psrld     $13, %xmm8
        pslld     $19, %xmm14
        por       %xmm15, %xmm13
        por       %xmm14, %xmm8
        movdqa    %xmm6, %xmm14
        movdqa    %xmm3, %xmm15
        pxor      %xmm0, %xmm14
        pxor      %xmm0, %xmm15
        pxor      %xmm8, %xmm13
        pand      %xmm15, %xmm14
        pxor      %xmm13, %xmm12
        pxor      %xmm0, %xmm14
        paddd     .L_2il0floatpacket.590(%rip), %xmm5
        paddd     %xmm14, %xmm12
        movdqa    528(%rsp), %xmm14
        paddd     %xmm11, %xmm5
        movdqa    %xmm14, %xmm13
        movdqa    %xmm14, %xmm15
        movdqa    %xmm14, %xmm8
        paddd     %xmm5, %xmm2
        paddd     %xmm12, %xmm5
        movdqa    %xmm14, %xmm12
        psrld     $7, %xmm13
        pslld     $25, %xmm15
        psrld     $18, %xmm8
        pslld     $14, %xmm14
        por       %xmm15, %xmm13
        por       %xmm14, %xmm8
        movdqa    288(%rsp), %xmm14
        psrld     $3, %xmm12
        pxor      %xmm8, %xmm13
        movdqa    %xmm14, %xmm15
        pxor      %xmm13, %xmm12
        movdqa    %xmm14, %xmm13
        psrld     $17, %xmm15
        pslld     $15, %xmm13
        por       %xmm13, %xmm15
        movdqa    %xmm14, %xmm13
        movdqa    %xmm14, %xmm8
        psrld     $19, %xmm13
        pslld     $13, %xmm14
        psrld     $10, %xmm8
        por       %xmm14, %xmm13
        movdqa    %xmm2, %xmm14
        pxor      %xmm13, %xmm15
        movdqa    %xmm2, %xmm13
        pxor      %xmm15, %xmm8
        movdqa    %xmm2, %xmm15
        paddd     %xmm9, %xmm8
        psrld     $6, %xmm14
        movdqa    %xmm9, 608(%rsp)
        paddd     %xmm8, %xmm10
        movdqa    %xmm2, %xmm9
        paddd     %xmm10, %xmm12
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm10
        pslld     $26, %xmm13
        psrld     $11, %xmm15
        pslld     $21, %xmm9
        psrld     $25, %xmm8
        pslld     $7, %xmm10
        por       %xmm13, %xmm14
        por       %xmm9, %xmm15
        movdqa    %xmm4, %xmm13
        por       %xmm10, %xmm8
        pxor      %xmm15, %xmm14
        pxor      %xmm1, %xmm13
        pxor      %xmm14, %xmm8
        pand      %xmm2, %xmm13
        paddd     %xmm8, %xmm7
        pxor      %xmm1, %xmm13
        movdqa    %xmm5, %xmm10
        paddd     %xmm13, %xmm7
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm9
        psrld     $2, %xmm10
        pslld     $30, %xmm13
        psrld     $13, %xmm15
        pslld     $19, %xmm9
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm8
        por       %xmm13, %xmm10
        por       %xmm9, %xmm15
        movdqa    %xmm0, %xmm9
        movdqa    %xmm3, %xmm13
        psrld     $22, %xmm14
        pslld     $10, %xmm8
        pxor      %xmm3, %xmm9
        pxor      %xmm5, %xmm13
        por       %xmm8, %xmm14
        pxor      %xmm15, %xmm10
        pand      %xmm13, %xmm9
        pxor      %xmm10, %xmm14
        movdqa    448(%rsp), %xmm8
        pxor      %xmm3, %xmm9
        paddd     .L_2il0floatpacket.591(%rip), %xmm7
        paddd     %xmm9, %xmm14
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, %xmm9
        movdqa    %xmm8, %xmm13
        paddd     %xmm12, %xmm7
        psrld     $7, %xmm10
        pslld     $25, %xmm15
        psrld     $18, %xmm9
        pslld     $14, %xmm13
        paddd     %xmm7, %xmm6
        paddd     %xmm14, %xmm7
        movdqa    %xmm8, %xmm14
        por       %xmm15, %xmm10
        por       %xmm13, %xmm9
        psrld     $3, %xmm14
        pxor      %xmm9, %xmm10
        pxor      %xmm10, %xmm14
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm9
        movdqa    %xmm11, %xmm10
        movdqa    %xmm11, 304(%rsp)
        movdqa    %xmm11, %xmm15
        psrld     $17, %xmm13
        pslld     $15, %xmm9
        psrld     $19, %xmm10
        pslld     $13, %xmm11
        por       %xmm9, %xmm13
        por       %xmm11, %xmm10
        psrld     $10, %xmm15
        pxor      %xmm10, %xmm13
        pxor      %xmm13, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     400(%rsp), %xmm15
        psrld     $25, %xmm11
        movdqa    528(%rsp), %xmm13
        movdqa    %xmm6, %xmm10
        paddd     %xmm15, %xmm13
        movdqa    %xmm6, %xmm15
        pslld     $7, %xmm15
        paddd     %xmm13, %xmm14
        por       %xmm15, %xmm11
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm9
        psrld     $6, %xmm15
        pslld     $26, %xmm13
        psrld     $11, %xmm10
        pslld     $21, %xmm9
        por       %xmm13, %xmm15
        por       %xmm9, %xmm10
        pxor      %xmm10, %xmm15
        movdqa    %xmm4, %xmm13
        pxor      %xmm15, %xmm11
        pxor      %xmm2, %xmm13
        pand      %xmm6, %xmm13
        paddd     %xmm11, %xmm1
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm11
        pxor      %xmm4, %xmm13
        psrld     $22, %xmm9
        pslld     $10, %xmm11
        paddd     %xmm13, %xmm1
        por       %xmm11, %xmm9
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm13
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm15
        psrld     $2, %xmm11
        pslld     $30, %xmm13
        psrld     $13, %xmm10
        pslld     $19, %xmm15
        por       %xmm13, %xmm11
        por       %xmm15, %xmm10
        movdqa    %xmm3, %xmm15
        movdqa    %xmm7, %xmm13
        pxor      %xmm5, %xmm15
        pxor      %xmm5, %xmm13
        pxor      %xmm10, %xmm11
        pand      %xmm13, %xmm15
        pxor      %xmm11, %xmm9
        movdqa    432(%rsp), %xmm13
        pxor      %xmm5, %xmm15
        paddd     %xmm15, %xmm9
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm10
        psrld     $7, %xmm15
        pslld     $25, %xmm10
        movdqa    %xmm13, %xmm11
        paddd     .L_2il0floatpacket.592(%rip), %xmm1
        por       %xmm10, %xmm15
        movdqa    %xmm13, %xmm10
        paddd     %xmm14, %xmm1
        psrld     $18, %xmm10
        pslld     $14, %xmm11
        paddd     %xmm1, %xmm0
        paddd     %xmm9, %xmm1
        movdqa    %xmm13, %xmm9
        por       %xmm11, %xmm10
        psrld     $3, %xmm9
        pxor      %xmm10, %xmm15
        pxor      %xmm15, %xmm9
        movdqa    %xmm12, %xmm10
        movdqa    %xmm12, %xmm15
        psrld     $17, %xmm10
        pslld     $15, %xmm15
        movdqa    %xmm12, %xmm11
        por       %xmm15, %xmm10
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, 480(%rsp)
        psrld     $19, %xmm15
        pslld     $13, %xmm12
        psrld     $10, %xmm11
        por       %xmm12, %xmm15
        movdqa    %xmm0, %xmm12
        pxor      %xmm15, %xmm10
        movdqa    %xmm0, %xmm15
        pxor      %xmm10, %xmm11
        movdqa    %xmm0, %xmm10
        paddd     384(%rsp), %xmm11
        psrld     $6, %xmm12
        paddd     %xmm11, %xmm8
        movdqa    %xmm0, %xmm11
        paddd     %xmm8, %xmm9
        movdqa    %xmm0, %xmm8
        psrld     $25, %xmm8
        pslld     $7, %xmm11
        por       %xmm11, %xmm8
        movdqa    %xmm0, %xmm11
        pslld     $26, %xmm15
        psrld     $11, %xmm11
        pslld     $21, %xmm10
        por       %xmm15, %xmm12
        por       %xmm10, %xmm11
        movdqa    %xmm6, %xmm15
        pxor      %xmm11, %xmm12
        pxor      %xmm2, %xmm15
        pxor      %xmm12, %xmm8
        pand      %xmm0, %xmm15
        paddd     %xmm8, %xmm4
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm8
        pxor      %xmm2, %xmm15
        psrld     $22, %xmm12
        pslld     $10, %xmm8
        paddd     %xmm15, %xmm4
        por       %xmm8, %xmm12
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm15
        psrld     $2, %xmm8
        pslld     $30, %xmm11
        psrld     $13, %xmm10
        pslld     $19, %xmm15
        por       %xmm11, %xmm8
        por       %xmm15, %xmm10
        pxor      %xmm10, %xmm8
        movdqa    %xmm5, %xmm15
        movdqa    %xmm1, %xmm11
        pxor      %xmm8, %xmm12
        movdqa    336(%rsp), %xmm8
        pxor      %xmm7, %xmm15
        pxor      %xmm7, %xmm11
        movdqa    %xmm8, %xmm10
        pand      %xmm11, %xmm15
        movdqa    %xmm8, %xmm11
        pxor      %xmm7, %xmm15
        psrld     $7, %xmm11
        pslld     $25, %xmm10
        paddd     %xmm15, %xmm12
        paddd     .L_2il0floatpacket.593(%rip), %xmm4
        por       %xmm10, %xmm11
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, %xmm15
        paddd     %xmm9, %xmm4
        psrld     $18, %xmm10
        pslld     $14, %xmm15
        paddd     %xmm4, %xmm3
        paddd     %xmm12, %xmm4
        movdqa    %xmm8, %xmm12
        por       %xmm15, %xmm10
        psrld     $3, %xmm12
        pxor      %xmm10, %xmm11
        movdqa    %xmm14, %xmm10
        pxor      %xmm11, %xmm12
        movdqa    %xmm14, %xmm11
        psrld     $17, %xmm10
        pslld     $15, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm14, %xmm11
        movdqa    %xmm14, 496(%rsp)
        movdqa    %xmm14, %xmm15
        psrld     $19, %xmm11
        pslld     $13, %xmm14
        por       %xmm14, %xmm11
        psrld     $10, %xmm15
        pxor      %xmm11, %xmm10
        movdqa    %xmm3, %xmm11
        pxor      %xmm10, %xmm15
        pslld     $7, %xmm11
        paddd     368(%rsp), %xmm15
        movdqa    %xmm3, %xmm14
        paddd     %xmm15, %xmm13
        movdqa    %xmm3, %xmm15
        psrld     $25, %xmm15
        paddd     %xmm13, %xmm12
        por       %xmm11, %xmm15
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm10
        psrld     $6, %xmm14
        pslld     $26, %xmm13
        psrld     $11, %xmm11
        pslld     $21, %xmm10
        por       %xmm13, %xmm14
        por       %xmm10, %xmm11
        movdqa    %xmm0, %xmm13
        pxor      %xmm11, %xmm14
        pxor      %xmm6, %xmm13
        pxor      %xmm14, %xmm15
        pand      %xmm3, %xmm13
        paddd     %xmm15, %xmm2
        pxor      %xmm6, %xmm13
        movdqa    %xmm4, %xmm15
        paddd     %xmm13, %xmm2
        movdqa    %xmm4, %xmm13
        psrld     $22, %xmm13
        pslld     $10, %xmm15
        por       %xmm15, %xmm13
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm14
        psrld     $2, %xmm15
        pslld     $30, %xmm11
        psrld     $13, %xmm10
        pslld     $19, %xmm14
        por       %xmm11, %xmm15
        por       %xmm14, %xmm10
        movdqa    %xmm7, %xmm14
        movdqa    %xmm4, %xmm11
        pxor      %xmm1, %xmm14
        pxor      %xmm1, %xmm11
        pxor      %xmm10, %xmm15
        pand      %xmm11, %xmm14
        pxor      %xmm15, %xmm13
        paddd     .L_2il0floatpacket.594(%rip), %xmm2
        pxor      %xmm1, %xmm14
        paddd     %xmm12, %xmm2
        paddd     %xmm14, %xmm13
        paddd     %xmm2, %xmm5
        paddd     %xmm13, %xmm2
        movdqa    576(%rsp), %xmm13
        movdqa    %xmm13, %xmm11
        movdqa    %xmm13, %xmm10
        psrld     $7, %xmm11
        pslld     $25, %xmm10
        por       %xmm10, %xmm11
        movdqa    %xmm13, %xmm10
        movdqa    %xmm13, %xmm14
        psrld     $18, %xmm10
        pslld     $14, %xmm14
        movdqa    %xmm13, %xmm15
        por       %xmm14, %xmm10
        psrld     $3, %xmm15
        pxor      %xmm10, %xmm11
        movdqa    %xmm9, %xmm10
        pxor      %xmm11, %xmm15
        movdqa    %xmm9, %xmm11
        psrld     $17, %xmm11
        pslld     $15, %xmm10
        por       %xmm10, %xmm11
        movdqa    %xmm9, %xmm10
        movdqa    %xmm9, 512(%rsp)
        movdqa    %xmm9, %xmm14
        psrld     $19, %xmm10
        pslld     $13, %xmm9
        por       %xmm9, %xmm10
        psrld     $10, %xmm14
        pxor      %xmm10, %xmm11
        movdqa    %xmm5, %xmm9
        pxor      %xmm11, %xmm14
        movdqa    %xmm5, %xmm11
        paddd     320(%rsp), %xmm14
        pslld     $7, %xmm11
        paddd     %xmm14, %xmm8
        movdqa    %xmm5, %xmm14
        psrld     $25, %xmm14
        paddd     %xmm8, %xmm15
        por       %xmm11, %xmm14
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm10
        psrld     $6, %xmm9
        pslld     $26, %xmm8
        psrld     $11, %xmm11
        pslld     $21, %xmm10
        por       %xmm8, %xmm9
        por       %xmm10, %xmm11
        movdqa    %xmm3, %xmm8
        pxor      %xmm11, %xmm9
        pxor      %xmm0, %xmm8
        pxor      %xmm9, %xmm14
        pand      %xmm5, %xmm8
        paddd     %xmm14, %xmm6
        pxor      %xmm0, %xmm8
        movdqa    %xmm2, %xmm9
        paddd     %xmm8, %xmm6
        movdqa    %xmm2, %xmm14
        paddd     .L_2il0floatpacket.595(%rip), %xmm6
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm11
        paddd     %xmm15, %xmm6
        movdqa    %xmm15, 256(%rsp)
        psrld     $22, %xmm9
        pslld     $10, %xmm14
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm15
        psrld     $13, %xmm8
        pslld     $19, %xmm11
        por       %xmm14, %xmm9
        psrld     $2, %xmm10
        pslld     $30, %xmm15
        por       %xmm11, %xmm8
        movdqa    %xmm1, %xmm11
        movdqa    %xmm2, %xmm14
        por       %xmm15, %xmm10
        pxor      %xmm4, %xmm11
        pxor      %xmm4, %xmm14
        pxor      %xmm8, %xmm10
        pand      %xmm14, %xmm11
        pxor      %xmm10, %xmm9
        pxor      %xmm4, %xmm11
        movdqa    352(%rsp), %xmm15
        paddd     %xmm11, %xmm9
        paddd     %xmm6, %xmm7
        paddd     %xmm9, %xmm6
        movdqa    %xmm15, %xmm10
        movdqa    %xmm15, %xmm9
        movdqa    %xmm15, %xmm8
        movdqa    %xmm15, %xmm11
        psrld     $7, %xmm10
        pslld     $25, %xmm9
        psrld     $18, %xmm8
        pslld     $14, %xmm15
        por       %xmm9, %xmm10
        por       %xmm15, %xmm8
        psrld     $3, %xmm11
        pxor      %xmm8, %xmm10
        movdqa    %xmm12, %xmm9
        movdqa    %xmm12, %xmm14
        movdqa    %xmm12, %xmm8
        pxor      %xmm10, %xmm11
        movdqa    %xmm12, 464(%rsp)
        movdqa    %xmm12, %xmm10
        psrld     $17, %xmm9
        pslld     $15, %xmm14
        psrld     $19, %xmm8
        pslld     $13, %xmm12
        por       %xmm14, %xmm9
        por       %xmm12, %xmm8
        psrld     $10, %xmm10
        pxor      %xmm8, %xmm9
        pxor      %xmm9, %xmm10
        movdqa    %xmm7, %xmm12
        paddd     288(%rsp), %xmm10
        movdqa    %xmm7, %xmm8
        paddd     %xmm10, %xmm13
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm9
        paddd     %xmm13, %xmm11
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm13
        psrld     $6, %xmm12
        pslld     $26, %xmm8
        psrld     $11, %xmm10
        pslld     $21, %xmm9
        psrld     $25, %xmm14
        pslld     $7, %xmm13
        por       %xmm8, %xmm12
        por       %xmm9, %xmm10
        movdqa    %xmm5, %xmm15
        por       %xmm13, %xmm14
        pxor      %xmm10, %xmm12
        pxor      %xmm3, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm7, %xmm15
        pxor      %xmm3, %xmm15
        paddd     %xmm14, %xmm0
        paddd     %xmm15, %xmm0
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm10
        psrld     $2, %xmm13
        paddd     .L_2il0floatpacket.596(%rip), %xmm0
        pslld     $30, %xmm9
        psrld     $13, %xmm12
        pslld     $19, %xmm10
        movdqa    %xmm11, 272(%rsp)
        paddd     %xmm11, %xmm0
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm8
        por       %xmm9, %xmm13
        por       %xmm10, %xmm12
        psrld     $22, %xmm11
        pslld     $10, %xmm8
        pxor      %xmm12, %xmm13
        movdqa    %xmm4, %xmm12
        movdqa    %xmm6, %xmm14
        por       %xmm8, %xmm11
        pxor      %xmm2, %xmm12
        pxor      %xmm2, %xmm14
        movdqa    592(%rsp), %xmm10
        paddd     %xmm0, %xmm1
        movdqa    416(%rsp), %xmm8
        pxor      %xmm13, %xmm11
        movdqa    608(%rsp), %xmm9
        pand      %xmm14, %xmm12
..B6.36:
        pxor      %xmm2, %xmm12
        movdqa    %xmm10, %xmm15
        paddd     %xmm12, %xmm11
        movdqa    %xmm10, %xmm12
        psrld     $7, %xmm15
        pslld     $25, %xmm12
        por       %xmm12, %xmm15
        movdqa    %xmm10, %xmm12
        movdqa    %xmm10, %xmm13
        psrld     $18, %xmm12
        pslld     $14, %xmm13
        paddd     %xmm11, %xmm0
        movdqa    %xmm10, %xmm11
        por       %xmm13, %xmm12
        psrld     $3, %xmm11
        pxor      %xmm12, %xmm15
        pxor      %xmm15, %xmm11
        movdqa    256(%rsp), %xmm15
        movdqa    %xmm15, %xmm13
        movdqa    %xmm15, %xmm12
        psrld     $17, %xmm13
        pslld     $15, %xmm12
        por       %xmm12, %xmm13
        movdqa    %xmm15, %xmm12
        movdqa    %xmm15, %xmm14
        psrld     $19, %xmm12
        pslld     $13, %xmm15
        psrld     $10, %xmm14
        por       %xmm15, %xmm12
        movdqa    %xmm1, %xmm15
        pxor      %xmm12, %xmm13
        movdqa    %xmm1, %xmm12
        pxor      %xmm13, %xmm14
        pslld     $7, %xmm12
        paddd     304(%rsp), %xmm14
        psrld     $6, %xmm15
        movdqa    352(%rsp), %xmm13
        paddd     %xmm14, %xmm13
        movdqa    %xmm1, %xmm14
        paddd     %xmm13, %xmm11
        movdqa    %xmm1, %xmm13
        psrld     $25, %xmm14
        pslld     $26, %xmm13
        por       %xmm12, %xmm14
        por       %xmm13, %xmm15
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm12
        psrld     $11, %xmm13
        pslld     $21, %xmm12
        por       %xmm12, %xmm13
        movdqa    %xmm0, %xmm12
        pxor      %xmm13, %xmm15
        movdqa    %xmm0, %xmm13
        pxor      %xmm15, %xmm14
        movdqa    %xmm7, %xmm15
        pxor      %xmm5, %xmm15
        paddd     %xmm14, %xmm3
        pand      %xmm1, %xmm15
        movdqa    %xmm0, %xmm14
        pxor      %xmm5, %xmm15
        psrld     $22, %xmm13
        paddd     %xmm15, %xmm3
        movdqa    %xmm0, %xmm15
        pslld     $10, %xmm14
        psrld     $2, %xmm12
        pslld     $30, %xmm15
        por       %xmm14, %xmm13
        por       %xmm15, %xmm12
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm14
        psrld     $13, %xmm15
        pslld     $19, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm8, %xmm14
        pxor      %xmm15, %xmm12
        movdqa    %xmm2, %xmm15
        pxor      %xmm12, %xmm13
        movdqa    %xmm6, %xmm12
        pxor      %xmm6, %xmm15
        pxor      %xmm0, %xmm12
        pand      %xmm12, %xmm15
        movdqa    %xmm8, %xmm12
        paddd     .L_2il0floatpacket.597(%rip), %xmm3
        pxor      %xmm6, %xmm15
        paddd     %xmm11, %xmm3
        paddd     %xmm15, %xmm13
        paddd     %xmm3, %xmm4
        paddd     %xmm13, %xmm3
        movdqa    %xmm8, %xmm13
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, 416(%rsp)
        psrld     $7, %xmm13
        pslld     $25, %xmm14
        psrld     $18, %xmm15
        pslld     $14, %xmm8
        por       %xmm14, %xmm13
        por       %xmm8, %xmm15
        psrld     $3, %xmm12
        pxor      %xmm15, %xmm13
        pxor      %xmm13, %xmm12
        movdqa    272(%rsp), %xmm13
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm8
        psrld     $17, %xmm15
        pslld     $15, %xmm8
        por       %xmm8, %xmm15
        movdqa    %xmm13, %xmm8
        movdqa    %xmm13, %xmm14
        psrld     $19, %xmm8
        pslld     $13, %xmm13
        psrld     $10, %xmm14
        por       %xmm13, %xmm8
        movdqa    %xmm4, %xmm13
        pxor      %xmm8, %xmm15
        movdqa    %xmm4, %xmm8
        pxor      %xmm15, %xmm14
        movdqa    %xmm4, %xmm15
        paddd     480(%rsp), %xmm14
        pslld     $26, %xmm8
        paddd     %xmm14, %xmm10
        movdqa    %xmm4, %xmm14
        paddd     %xmm10, %xmm12
        movdqa    %xmm4, %xmm10
        psrld     $25, %xmm10
        pslld     $7, %xmm14
        por       %xmm14, %xmm10
        movdqa    %xmm4, %xmm14
        psrld     $6, %xmm14
        psrld     $11, %xmm15
        pslld     $21, %xmm13
        por       %xmm8, %xmm14
        por       %xmm13, %xmm15
        movdqa    %xmm1, %xmm8
        pxor      %xmm15, %xmm14
        pxor      %xmm7, %xmm8
        pxor      %xmm14, %xmm10
        pand      %xmm4, %xmm8
        paddd     %xmm10, %xmm5
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm10
        pxor      %xmm7, %xmm8
        psrld     $22, %xmm13
        pslld     $10, %xmm10
        paddd     %xmm8, %xmm5
        por       %xmm10, %xmm13
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm15
        psrld     $2, %xmm10
        pslld     $30, %xmm8
        psrld     $13, %xmm14
        pslld     $19, %xmm15
        por       %xmm8, %xmm10
        por       %xmm15, %xmm14
        movdqa    %xmm6, %xmm15
        movdqa    %xmm3, %xmm8
        pxor      %xmm0, %xmm15
        pxor      %xmm0, %xmm8
        pxor      %xmm14, %xmm10
        pand      %xmm8, %xmm15
        pxor      %xmm10, %xmm13
        pxor      %xmm0, %xmm15
        paddd     .L_2il0floatpacket.598(%rip), %xmm5
        paddd     %xmm15, %xmm13
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm10
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm8
        paddd     %xmm12, %xmm5
        psrld     $7, %xmm15
        pslld     $25, %xmm10
        psrld     $18, %xmm14
        pslld     $14, %xmm8
        paddd     %xmm5, %xmm2
        paddd     %xmm13, %xmm5
        movdqa    %xmm9, %xmm13
        por       %xmm10, %xmm15
        por       %xmm8, %xmm14
        psrld     $3, %xmm13
        pxor      %xmm14, %xmm15
        movdqa    %xmm11, %xmm10
        movdqa    %xmm11, %xmm8
        movdqa    %xmm11, %xmm14
        pxor      %xmm15, %xmm13
        movdqa    %xmm11, 528(%rsp)
        movdqa    %xmm11, %xmm15
        psrld     $17, %xmm10
        pslld     $15, %xmm8
        psrld     $19, %xmm14
        pslld     $13, %xmm11
        por       %xmm8, %xmm10
        por       %xmm11, %xmm14
        psrld     $10, %xmm15
        pxor      %xmm14, %xmm10
        pxor      %xmm10, %xmm15
        movdqa    %xmm2, %xmm8
        paddd     496(%rsp), %xmm15
        psrld     $25, %xmm8
        movdqa    416(%rsp), %xmm10
        movdqa    %xmm2, %xmm11
        paddd     %xmm15, %xmm10
        movdqa    %xmm2, %xmm15
        pslld     $7, %xmm15
        paddd     %xmm10, %xmm13
        por       %xmm15, %xmm8
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm10
        psrld     $6, %xmm15
        pslld     $26, %xmm11
        psrld     $11, %xmm14
        pslld     $21, %xmm10
        por       %xmm11, %xmm15
        por       %xmm10, %xmm14
        pxor      %xmm14, %xmm15
        movdqa    %xmm1, %xmm11
        pxor      %xmm15, %xmm8
        pxor      %xmm4, %xmm11
        pand      %xmm2, %xmm11
        paddd     %xmm8, %xmm7
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm8
        pxor      %xmm1, %xmm11
        psrld     $22, %xmm10
        pslld     $10, %xmm8
        paddd     %xmm11, %xmm7
        por       %xmm8, %xmm10
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm15
        psrld     $2, %xmm8
        pslld     $30, %xmm11
        psrld     $13, %xmm14
        pslld     $19, %xmm15
        por       %xmm11, %xmm8
        por       %xmm15, %xmm14
        movdqa    %xmm0, %xmm15
        movdqa    %xmm5, %xmm11
        pxor      %xmm3, %xmm15
        pxor      %xmm3, %xmm11
        pxor      %xmm14, %xmm8
        pand      %xmm11, %xmm15
        pxor      %xmm8, %xmm10
        paddd     .L_2il0floatpacket.599(%rip), %xmm7
        pxor      %xmm3, %xmm15
        paddd     %xmm13, %xmm7
        paddd     %xmm15, %xmm10
        paddd     %xmm7, %xmm6
        paddd     %xmm10, %xmm7
        movdqa    400(%rsp), %xmm10
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm14
        psrld     $7, %xmm15
        pslld     $25, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm11
        psrld     $18, %xmm14
        pslld     $14, %xmm11
        movdqa    %xmm10, %xmm8
        por       %xmm11, %xmm14
        psrld     $3, %xmm8
        pxor      %xmm14, %xmm15
        movdqa    %xmm12, %xmm14
        pxor      %xmm15, %xmm8
        movdqa    %xmm12, %xmm15
        psrld     $17, %xmm14
        pslld     $15, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, 560(%rsp)
        movdqa    %xmm12, %xmm11
        psrld     $19, %xmm15
        pslld     $13, %xmm12
        por       %xmm12, %xmm15
        psrld     $10, %xmm11
        pxor      %xmm15, %xmm14
        movdqa    %xmm6, %xmm12
        pxor      %xmm14, %xmm11
        movdqa    %xmm6, %xmm14
        paddd     512(%rsp), %xmm11
        movdqa    %xmm6, %xmm15
        paddd     %xmm11, %xmm9
        movdqa    %xmm6, %xmm11
        paddd     %xmm9, %xmm8
        movdqa    %xmm6, %xmm9
        psrld     $25, %xmm11
        pslld     $7, %xmm9
        por       %xmm9, %xmm11
        movdqa    %xmm6, %xmm9
        psrld     $6, %xmm9
        pslld     $26, %xmm12
        psrld     $11, %xmm14
        pslld     $21, %xmm15
        por       %xmm12, %xmm9
        por       %xmm15, %xmm14
        movdqa    %xmm2, %xmm12
        pxor      %xmm14, %xmm9
        pxor      %xmm4, %xmm12
        pxor      %xmm9, %xmm11
        pand      %xmm6, %xmm12
        paddd     %xmm11, %xmm1
        pxor      %xmm4, %xmm12
        movdqa    %xmm7, %xmm11
        paddd     %xmm12, %xmm1
        movdqa    %xmm7, %xmm12
        psrld     $22, %xmm12
        pslld     $10, %xmm11
        por       %xmm11, %xmm12
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm14
        psrld     $2, %xmm11
        pslld     $30, %xmm15
        psrld     $13, %xmm9
        pslld     $19, %xmm14
        por       %xmm15, %xmm11
        por       %xmm14, %xmm9
        movdqa    %xmm3, %xmm14
        movdqa    %xmm7, %xmm15
        pxor      %xmm9, %xmm11
        movdqa    384(%rsp), %xmm9
        pxor      %xmm5, %xmm14
        pxor      %xmm5, %xmm15
        pxor      %xmm11, %xmm12
        pand      %xmm15, %xmm14
        movdqa    %xmm9, %xmm11
        movdqa    %xmm9, %xmm15
        pxor      %xmm5, %xmm14
        psrld     $7, %xmm11
        pslld     $25, %xmm15
        paddd     .L_2il0floatpacket.600(%rip), %xmm1
        paddd     %xmm14, %xmm12
        por       %xmm15, %xmm11
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm14
        paddd     %xmm8, %xmm1
        psrld     $18, %xmm15
        pslld     $14, %xmm14
        paddd     %xmm1, %xmm0
        paddd     %xmm12, %xmm1
        movdqa    %xmm9, %xmm12
        por       %xmm14, %xmm15
        psrld     $3, %xmm12
        pxor      %xmm15, %xmm11
        pxor      %xmm11, %xmm12
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm11
        psrld     $17, %xmm15
        pslld     $15, %xmm11
        movdqa    %xmm13, %xmm14
        por       %xmm11, %xmm15
        movdqa    %xmm13, %xmm11
        movdqa    %xmm13, 576(%rsp)
        psrld     $19, %xmm11
        pslld     $13, %xmm13
        psrld     $10, %xmm14
        por       %xmm13, %xmm11
        movdqa    %xmm0, %xmm13
        pxor      %xmm11, %xmm15
        movdqa    %xmm0, %xmm11
        pxor      %xmm15, %xmm14
        pslld     $7, %xmm11
        paddd     464(%rsp), %xmm14
        movdqa    %xmm0, %xmm15
        paddd     %xmm14, %xmm10
        movdqa    %xmm0, %xmm14
        psrld     $25, %xmm14
        paddd     %xmm10, %xmm12
        por       %xmm11, %xmm14
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm11
        psrld     $6, %xmm13
        pslld     $26, %xmm10
        psrld     $11, %xmm11
        pslld     $21, %xmm15
        por       %xmm10, %xmm13
        por       %xmm15, %xmm11
        movdqa    %xmm6, %xmm10
        pxor      %xmm11, %xmm13
        pxor      %xmm2, %xmm10
        pxor      %xmm13, %xmm14
        pand      %xmm0, %xmm10
        paddd     %xmm14, %xmm4
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm14
        pxor      %xmm2, %xmm10
        psrld     $22, %xmm11
        pslld     $10, %xmm14
        paddd     %xmm10, %xmm4
        por       %xmm14, %xmm11
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm13
        psrld     $2, %xmm14
        pslld     $30, %xmm10
        psrld     $13, %xmm15
        pslld     $19, %xmm13
        por       %xmm10, %xmm14
        por       %xmm13, %xmm15
        pxor      %xmm15, %xmm14
        movdqa    %xmm5, %xmm13
        movdqa    %xmm1, %xmm10
        pxor      %xmm14, %xmm11
        movdqa    368(%rsp), %xmm14
        pxor      %xmm7, %xmm13
        pxor      %xmm7, %xmm10
        movdqa    %xmm14, %xmm15
        pand      %xmm10, %xmm13
        movdqa    %xmm14, %xmm10
        pxor      %xmm7, %xmm13
        psrld     $7, %xmm10
        pslld     $25, %xmm15
        paddd     %xmm13, %xmm11
        paddd     .L_2il0floatpacket.601(%rip), %xmm4
        por       %xmm15, %xmm10
        movdqa    %xmm14, %xmm15
        movdqa    %xmm14, %xmm13
        paddd     %xmm12, %xmm4
        psrld     $18, %xmm15
        pslld     $14, %xmm13
        paddd     %xmm4, %xmm3
        paddd     %xmm11, %xmm4
        movdqa    %xmm14, %xmm11
        por       %xmm13, %xmm15
        psrld     $3, %xmm11
        pxor      %xmm15, %xmm10
        movdqa    %xmm8, %xmm15
        pxor      %xmm10, %xmm11
        movdqa    %xmm8, %xmm10
        psrld     $17, %xmm10
        pslld     $15, %xmm15
        por       %xmm15, %xmm10
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, 544(%rsp)
        movdqa    %xmm8, %xmm13
        psrld     $19, %xmm15
        pslld     $13, %xmm8
        por       %xmm8, %xmm15
        psrld     $10, %xmm13
        pxor      %xmm15, %xmm10
        movdqa    %xmm3, %xmm8
        pxor      %xmm10, %xmm13
        psrld     $25, %xmm8
        paddd     256(%rsp), %xmm13
        movdqa    %xmm3, %xmm10
        paddd     %xmm13, %xmm9
        movdqa    %xmm3, %xmm15
        paddd     %xmm9, %xmm11
        movdqa    %xmm3, %xmm9
        pslld     $7, %xmm9
        movdqa    %xmm3, %xmm13
        por       %xmm9, %xmm8
        movdqa    %xmm3, %xmm9
        psrld     $6, %xmm9
        pslld     $26, %xmm10
        psrld     $11, %xmm15
        pslld     $21, %xmm13
        por       %xmm10, %xmm9
        por       %xmm13, %xmm15
        movdqa    %xmm0, %xmm10
        pxor      %xmm15, %xmm9
        pxor      %xmm6, %xmm10
        pxor      %xmm9, %xmm8
        pand      %xmm3, %xmm10
        paddd     %xmm8, %xmm2
        pxor      %xmm6, %xmm10
        movdqa    %xmm4, %xmm8
        paddd     %xmm10, %xmm2
        movdqa    %xmm4, %xmm10
        psrld     $22, %xmm10
        pslld     $10, %xmm8
        por       %xmm8, %xmm10
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm8
        psrld     $2, %xmm9
        pslld     $30, %xmm13
        psrld     $13, %xmm15
        pslld     $19, %xmm8
        por       %xmm13, %xmm9
        por       %xmm8, %xmm15
        movdqa    %xmm7, %xmm13
        movdqa    %xmm4, %xmm8
        pxor      %xmm1, %xmm13
        pxor      %xmm1, %xmm8
        pxor      %xmm15, %xmm9
        pand      %xmm8, %xmm13
        pxor      %xmm9, %xmm10
        paddd     .L_2il0floatpacket.602(%rip), %xmm2
        pxor      %xmm1, %xmm13
        movdqa    320(%rsp), %xmm8
        paddd     %xmm11, %xmm2
        paddd     %xmm13, %xmm10
        paddd     %xmm2, %xmm5
        paddd     %xmm10, %xmm2
        movdqa    %xmm8, %xmm9
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, %xmm13
        psrld     $7, %xmm9
        pslld     $25, %xmm10
        psrld     $18, %xmm15
        pslld     $14, %xmm8
        por       %xmm10, %xmm9
        por       %xmm8, %xmm15
        psrld     $3, %xmm13
        pxor      %xmm15, %xmm9
        movdqa    %xmm12, %xmm10
        pxor      %xmm9, %xmm13
        movdqa    %xmm12, %xmm9
        psrld     $17, %xmm10
        pslld     $15, %xmm9
        por       %xmm9, %xmm10
        movdqa    %xmm12, %xmm9
        movdqa    %xmm12, %xmm15
        psrld     $19, %xmm9
        pslld     $13, %xmm15
        movdqa    %xmm12, %xmm8
        por       %xmm15, %xmm9
        psrld     $10, %xmm8
        pxor      %xmm9, %xmm10
        movdqa    %xmm5, %xmm15
        pxor      %xmm10, %xmm8
        psrld     $25, %xmm15
        paddd     272(%rsp), %xmm8
        movdqa    %xmm5, %xmm10
        paddd     %xmm8, %xmm14
        movdqa    %xmm5, %xmm9
        paddd     %xmm14, %xmm13
        movdqa    %xmm5, %xmm14
        pslld     $7, %xmm14
        movdqa    %xmm5, %xmm8
        por       %xmm14, %xmm15
        movdqa    %xmm5, %xmm14
        psrld     $6, %xmm14
        pslld     $26, %xmm10
        psrld     $11, %xmm9
        pslld     $21, %xmm8
        por       %xmm10, %xmm14
        por       %xmm8, %xmm9
        movdqa    %xmm3, %xmm10
        pxor      %xmm9, %xmm14
        pxor      %xmm0, %xmm10
        pxor      %xmm14, %xmm15
        pand      %xmm5, %xmm10
        paddd     %xmm15, %xmm6
        pxor      %xmm0, %xmm10
        movdqa    %xmm2, %xmm8
        paddd     %xmm10, %xmm6
        movdqa    %xmm2, %xmm15
        paddd     .L_2il0floatpacket.603(%rip), %xmm6
        movdqa    %xmm2, %xmm10
        movdqa    %xmm13, 336(%rsp)
        paddd     %xmm13, %xmm6
        movdqa    %xmm2, %xmm13
        psrld     $2, %xmm8
        pslld     $30, %xmm15
        psrld     $22, %xmm10
        pslld     $10, %xmm13
        por       %xmm15, %xmm8
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm14
        movdqa    576(%rsp), %xmm9
        paddd     %xmm6, %xmm7
        por       %xmm13, %xmm10
        psrld     $13, %xmm15
        pslld     $19, %xmm14
..B6.35:
        por       %xmm14, %xmm15
        movdqa    %xmm12, 608(%rsp)
        movdqa    %xmm1, %xmm13
        movdqa    %xmm2, %xmm12
        pxor      %xmm4, %xmm13
        pxor      %xmm4, %xmm12
        pxor      %xmm15, %xmm8
        pand      %xmm12, %xmm13
        pxor      %xmm8, %xmm10
        pxor      %xmm4, %xmm13
        movdqa    288(%rsp), %xmm12
        paddd     %xmm13, %xmm10
        paddd     %xmm10, %xmm6
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm8
        movdqa    %xmm12, %xmm14
        movdqa    %xmm12, %xmm10
        psrld     $7, %xmm15
        pslld     $25, %xmm8
        psrld     $18, %xmm14
        pslld     $14, %xmm10
        movdqa    %xmm12, %xmm13
        por       %xmm8, %xmm15
        por       %xmm10, %xmm14
        psrld     $3, %xmm13
        pxor      %xmm14, %xmm15
        pxor      %xmm15, %xmm13
        movdqa    %xmm11, %xmm10
        movdqa    %xmm11, %xmm8
        movdqa    %xmm11, %xmm15
        movdqa    %xmm11, 592(%rsp)
        movdqa    %xmm11, %xmm14
        psrld     $17, %xmm10
        pslld     $15, %xmm8
        psrld     $19, %xmm15
        pslld     $13, %xmm11
        por       %xmm8, %xmm10
        por       %xmm11, %xmm15
        psrld     $10, %xmm14
        pxor      %xmm15, %xmm10
        pxor      %xmm10, %xmm14
        movdqa    %xmm7, %xmm11
        paddd     528(%rsp), %xmm14
        psrld     $25, %xmm11
        movdqa    320(%rsp), %xmm10
        movdqa    %xmm7, %xmm15
        paddd     %xmm14, %xmm10
        movdqa    %xmm7, %xmm14
        pslld     $7, %xmm14
        paddd     %xmm10, %xmm13
        por       %xmm14, %xmm11
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm8
        psrld     $6, %xmm14
        pslld     $26, %xmm10
        psrld     $11, %xmm15
        pslld     $21, %xmm8
        por       %xmm10, %xmm14
        por       %xmm8, %xmm15
        pxor      %xmm15, %xmm14
        movdqa    %xmm5, %xmm10
        pxor      %xmm14, %xmm11
        pxor      %xmm3, %xmm10
        pand      %xmm7, %xmm10
        paddd     %xmm11, %xmm0
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm11
        pxor      %xmm3, %xmm10
        psrld     $22, %xmm15
        pslld     $10, %xmm11
        paddd     %xmm10, %xmm0
        por       %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm14
        psrld     $2, %xmm11
        pslld     $30, %xmm10
        psrld     $13, %xmm8
        pslld     $19, %xmm14
        por       %xmm10, %xmm11
        por       %xmm14, %xmm8
        movdqa    %xmm4, %xmm14
        movdqa    %xmm2, %xmm10
        pxor      %xmm8, %xmm11
        movdqa    304(%rsp), %xmm8
        pxor      %xmm2, %xmm14
        pxor      %xmm6, %xmm10
        pxor      %xmm11, %xmm15
        pand      %xmm10, %xmm14
        movdqa    %xmm8, %xmm11
        movdqa    %xmm8, %xmm10
        pxor      %xmm2, %xmm14
        paddd     .L_2il0floatpacket.604(%rip), %xmm0
        psrld     $7, %xmm11
        pslld     $25, %xmm10
        paddd     %xmm13, %xmm0
        paddd     %xmm14, %xmm15
        por       %xmm10, %xmm11
        movdqa    %xmm8, %xmm10
        paddd     %xmm0, %xmm1
        paddd     %xmm15, %xmm0
        movdqa    %xmm8, %xmm15
        psrld     $18, %xmm10
        pslld     $14, %xmm8
        por       %xmm8, %xmm10
        psrld     $3, %xmm15
        movdqa    336(%rsp), %xmm14
        pxor      %xmm10, %xmm11
        pxor      %xmm11, %xmm15
        movdqa    %xmm14, %xmm10
        movdqa    %xmm14, %xmm11
        psrld     $17, %xmm10
        pslld     $15, %xmm11
        movdqa    %xmm14, %xmm8
        por       %xmm11, %xmm10
        movdqa    %xmm14, %xmm11
        psrld     $19, %xmm11
        pslld     $13, %xmm14
        por       %xmm14, %xmm11
        psrld     $10, %xmm8
        pxor      %xmm11, %xmm10
        movdqa    %xmm1, %xmm11
        pxor      %xmm10, %xmm8
        movdqa    %xmm1, %xmm14
        paddd     560(%rsp), %xmm8
        movdqa    %xmm1, %xmm10
        paddd     %xmm8, %xmm12
        movdqa    %xmm1, %xmm8
        paddd     %xmm12, %xmm15
        movdqa    %xmm1, %xmm12
        psrld     $25, %xmm8
        pslld     $7, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm1, %xmm12
        psrld     $6, %xmm12
        pslld     $26, %xmm11
        psrld     $11, %xmm14
        pslld     $21, %xmm10
        por       %xmm11, %xmm12
        por       %xmm10, %xmm14
        pxor      %xmm14, %xmm12
        movdqa    %xmm7, %xmm11
        pxor      %xmm12, %xmm8
        pxor      %xmm5, %xmm11
        pand      %xmm1, %xmm11
        paddd     %xmm8, %xmm3
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm8
        pxor      %xmm5, %xmm11
        psrld     $22, %xmm14
        pslld     $10, %xmm8
        paddd     %xmm11, %xmm3
        por       %xmm8, %xmm14
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm12
        psrld     $2, %xmm8
        pslld     $30, %xmm11
        psrld     $13, %xmm10
        pslld     $19, %xmm12
        por       %xmm11, %xmm8
        por       %xmm12, %xmm10
        movdqa    %xmm2, %xmm12
        movdqa    %xmm0, %xmm11
        pxor      %xmm6, %xmm12
        pxor      %xmm6, %xmm11
        pxor      %xmm10, %xmm8
        pand      %xmm11, %xmm12
        pxor      %xmm8, %xmm14
        paddd     .L_2il0floatpacket.605(%rip), %xmm3
        pxor      %xmm6, %xmm12
        paddd     %xmm15, %xmm3
        paddd     %xmm12, %xmm14
        paddd     %xmm3, %xmm4
        paddd     %xmm14, %xmm3
        movdqa    480(%rsp), %xmm14
        movdqa    %xmm14, %xmm12
        movdqa    %xmm14, %xmm10
        psrld     $7, %xmm12
        pslld     $25, %xmm10
        por       %xmm10, %xmm12
        movdqa    %xmm14, %xmm10
        movdqa    %xmm14, %xmm11
        psrld     $18, %xmm10
        pslld     $14, %xmm11
        movdqa    %xmm14, %xmm8
        por       %xmm11, %xmm10
        psrld     $3, %xmm8
        pxor      %xmm10, %xmm12
        movdqa    %xmm13, %xmm10
        pxor      %xmm12, %xmm8
        movdqa    %xmm13, %xmm12
        psrld     $17, %xmm10
        pslld     $15, %xmm12
        por       %xmm12, %xmm10
        movdqa    %xmm13, %xmm12
        movdqa    %xmm13, 384(%rsp)
        movdqa    %xmm13, %xmm11
        psrld     $19, %xmm12
        pslld     $13, %xmm13
        por       %xmm13, %xmm12
        psrld     $10, %xmm11
        pxor      %xmm12, %xmm10
        movdqa    %xmm4, %xmm13
        pxor      %xmm10, %xmm11
        psrld     $25, %xmm13
        movdqa    %xmm9, 576(%rsp)
        paddd     %xmm9, %xmm11
        movdqa    304(%rsp), %xmm9
        movdqa    %xmm4, %xmm12
        paddd     %xmm11, %xmm9
        movdqa    %xmm4, %xmm11
        pslld     $7, %xmm11
        paddd     %xmm9, %xmm8
        por       %xmm11, %xmm13
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm10
        psrld     $6, %xmm9
        pslld     $26, %xmm12
        psrld     $11, %xmm11
        pslld     $21, %xmm10
        por       %xmm12, %xmm9
        por       %xmm10, %xmm11
        pxor      %xmm11, %xmm9
        movdqa    %xmm7, %xmm12
        pxor      %xmm9, %xmm13
        pxor      %xmm1, %xmm12
        pand      %xmm4, %xmm12
        paddd     %xmm13, %xmm5
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm13
        pxor      %xmm7, %xmm12
        psrld     $22, %xmm11
        pslld     $10, %xmm13
        paddd     %xmm12, %xmm5
        por       %xmm13, %xmm11
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm12
        psrld     $2, %xmm13
        pslld     $30, %xmm9
        psrld     $13, %xmm10
        pslld     $19, %xmm12
        por       %xmm9, %xmm13
        por       %xmm12, %xmm10
        movdqa    %xmm6, %xmm12
        pxor      %xmm10, %xmm13
        movdqa    %xmm3, %xmm9
        pxor      %xmm13, %xmm11
        pxor      %xmm0, %xmm12
        movdqa    496(%rsp), %xmm13
        pxor      %xmm0, %xmm9
        pand      %xmm9, %xmm12
        movdqa    %xmm13, %xmm9
        movdqa    %xmm13, %xmm10
        pxor      %xmm0, %xmm12
        psrld     $7, %xmm9
        pslld     $25, %xmm10
        paddd     .L_2il0floatpacket.606(%rip), %xmm5
        paddd     %xmm12, %xmm11
        por       %xmm10, %xmm9
        movdqa    %xmm13, %xmm10
        movdqa    %xmm13, %xmm12
        paddd     %xmm8, %xmm5
        psrld     $18, %xmm10
        pslld     $14, %xmm12
        paddd     %xmm5, %xmm2
        paddd     %xmm11, %xmm5
        movdqa    %xmm13, %xmm11
        por       %xmm12, %xmm10
        psrld     $3, %xmm11
        pxor      %xmm10, %xmm9
        pxor      %xmm9, %xmm11
        movdqa    %xmm15, %xmm9
        movdqa    %xmm15, %xmm10
        psrld     $17, %xmm9
        pslld     $15, %xmm10
        movdqa    %xmm15, %xmm12
        por       %xmm10, %xmm9
        movdqa    %xmm15, %xmm10
        movdqa    %xmm15, 400(%rsp)
        psrld     $19, %xmm10
        pslld     $13, %xmm15
        psrld     $10, %xmm12
        por       %xmm15, %xmm10
        movdqa    %xmm2, %xmm15
        pxor      %xmm10, %xmm9
        movdqa    %xmm2, %xmm10
        pxor      %xmm9, %xmm12
        movdqa    %xmm2, %xmm9
        paddd     544(%rsp), %xmm12
        pslld     $26, %xmm9
        paddd     %xmm12, %xmm14
        movdqa    %xmm2, %xmm12
        paddd     %xmm14, %xmm11
        movdqa    %xmm2, %xmm14
        psrld     $25, %xmm12
        pslld     $7, %xmm14
        por       %xmm14, %xmm12
        movdqa    %xmm2, %xmm14
        psrld     $6, %xmm14
        psrld     $11, %xmm15
        pslld     $21, %xmm10
        por       %xmm9, %xmm14
        por       %xmm10, %xmm15
        movdqa    %xmm4, %xmm9
        pxor      %xmm15, %xmm14
        pxor      %xmm1, %xmm9
        pxor      %xmm14, %xmm12
        pand      %xmm2, %xmm9
        pxor      %xmm1, %xmm9
        paddd     %xmm12, %xmm7
        paddd     %xmm9, %xmm7
        movdqa    %xmm5, %xmm9
        movdqa    %xmm5, %xmm12
        psrld     $22, %xmm9
        pslld     $10, %xmm12
        movdqa    %xmm5, %xmm10
        por       %xmm12, %xmm9
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm14
        psrld     $2, %xmm12
        pslld     $30, %xmm10
        psrld     $13, %xmm15
        pslld     $19, %xmm14
        por       %xmm10, %xmm12
        por       %xmm14, %xmm15
        movdqa    %xmm0, %xmm14
        movdqa    %xmm5, %xmm10
        pxor      %xmm3, %xmm14
        pxor      %xmm3, %xmm10
        pxor      %xmm15, %xmm12
        pand      %xmm10, %xmm14
        movdqa    512(%rsp), %xmm10
        pxor      %xmm12, %xmm9
        movdqa    %xmm10, %xmm12
        movdqa    %xmm10, %xmm15
        pxor      %xmm3, %xmm14
        psrld     $7, %xmm12
        pslld     $25, %xmm15
        paddd     %xmm14, %xmm9
        paddd     .L_2il0floatpacket.607(%rip), %xmm7
        por       %xmm15, %xmm12
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm14
        paddd     %xmm11, %xmm7
        psrld     $18, %xmm15
        pslld     $14, %xmm14
        paddd     %xmm7, %xmm6
        paddd     %xmm9, %xmm7
        movdqa    %xmm10, %xmm9
        por       %xmm14, %xmm15
        psrld     $3, %xmm9
        pxor      %xmm15, %xmm12
        movdqa    %xmm8, %xmm15
        pxor      %xmm12, %xmm9
        movdqa    %xmm8, %xmm12
        psrld     $17, %xmm15
        pslld     $15, %xmm12
        por       %xmm12, %xmm15
        movdqa    %xmm8, %xmm12
        movdqa    %xmm8, 416(%rsp)
        movdqa    %xmm8, %xmm14
        psrld     $19, %xmm12
        pslld     $13, %xmm8
        por       %xmm8, %xmm12
        psrld     $10, %xmm14
        pxor      %xmm12, %xmm15
        movdqa    %xmm6, %xmm8
        pxor      %xmm15, %xmm14
        movdqa    %xmm6, %xmm12
        paddd     608(%rsp), %xmm14
        movdqa    %xmm6, %xmm15
        paddd     %xmm14, %xmm13
        movdqa    %xmm6, %xmm14
        paddd     %xmm13, %xmm9
        movdqa    %xmm6, %xmm13
        psrld     $25, %xmm14
        pslld     $7, %xmm13
        por       %xmm13, %xmm14
        movdqa    %xmm6, %xmm13
        psrld     $6, %xmm8
        pslld     $26, %xmm12
        psrld     $11, %xmm13
        pslld     $21, %xmm15
        por       %xmm12, %xmm8
        por       %xmm15, %xmm13
        movdqa    %xmm2, %xmm12
        pxor      %xmm13, %xmm8
        pxor      %xmm4, %xmm12
        pxor      %xmm8, %xmm14
        pand      %xmm6, %xmm12
        paddd     %xmm14, %xmm1
        pxor      %xmm4, %xmm12
        movdqa    %xmm7, %xmm14
        paddd     %xmm12, %xmm1
        movdqa    %xmm7, %xmm12
        psrld     $22, %xmm12
        pslld     $10, %xmm14
        por       %xmm14, %xmm12
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm13
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm8
        psrld     $2, %xmm14
        pslld     $30, %xmm13
        psrld     $13, %xmm15
        pslld     $19, %xmm8
        por       %xmm13, %xmm14
        por       %xmm8, %xmm15
        movdqa    %xmm3, %xmm8
        movdqa    %xmm7, %xmm13
        pxor      %xmm5, %xmm8
        pxor      %xmm5, %xmm13
        pxor      %xmm15, %xmm14
        pand      %xmm13, %xmm8
        pxor      %xmm14, %xmm12
        paddd     .L_2il0floatpacket.608(%rip), %xmm1
        pxor      %xmm5, %xmm8
        paddd     %xmm9, %xmm1
        paddd     %xmm8, %xmm12
        paddd     %xmm1, %xmm0
        paddd     %xmm12, %xmm1
        movdqa    464(%rsp), %xmm12
        movdqa    %xmm12, %xmm8
        movdqa    %xmm12, %xmm15
        psrld     $7, %xmm8
        pslld     $25, %xmm15
        por       %xmm15, %xmm8
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm13
        psrld     $18, %xmm15
        pslld     $14, %xmm13
        movdqa    %xmm12, %xmm14
        por       %xmm13, %xmm15
        movdqa    %xmm11, %xmm13
        pxor      %xmm15, %xmm8
        movdqa    %xmm11, %xmm15
        psrld     $17, %xmm13
        pslld     $15, %xmm15
        psrld     $3, %xmm14
        por       %xmm15, %xmm13
        movdqa    %xmm11, %xmm15
        pxor      %xmm8, %xmm14
        movdqa    %xmm11, 432(%rsp)
        movdqa    %xmm11, %xmm8
        psrld     $19, %xmm15
        pslld     $13, %xmm11
        por       %xmm11, %xmm15
        psrld     $10, %xmm8
        pxor      %xmm15, %xmm13
        movdqa    %xmm0, %xmm15
        movdqa    592(%rsp), %xmm11
        pxor      %xmm13, %xmm8
        paddd     %xmm11, %xmm8
        movdqa    %xmm0, %xmm13
        paddd     %xmm8, %xmm10
        movdqa    %xmm0, %xmm8
        paddd     %xmm10, %xmm14
        movdqa    %xmm0, %xmm10
        psrld     $25, %xmm10
        pslld     $7, %xmm8
        psrld     $6, %xmm13
        pslld     $26, %xmm15
        por       %xmm8, %xmm10
        por       %xmm15, %xmm13
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm8
        psrld     $11, %xmm15
        pslld     $21, %xmm8
        por       %xmm8, %xmm15
        movdqa    %xmm1, %xmm8
        pxor      %xmm15, %xmm13
        movdqa    %xmm1, %xmm15
        pxor      %xmm13, %xmm10
        movdqa    %xmm6, %xmm13
        pxor      %xmm2, %xmm13
        paddd     %xmm10, %xmm4
        pand      %xmm0, %xmm13
        movdqa    %xmm1, %xmm10
        pxor      %xmm2, %xmm13
        psrld     $22, %xmm15
        paddd     %xmm13, %xmm4
        pslld     $10, %xmm10
        paddd     .L_2il0floatpacket.609(%rip), %xmm4
        por       %xmm10, %xmm15
        movdqa    %xmm14, 368(%rsp)
        paddd     %xmm14, %xmm4
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm14
        psrld     $2, %xmm10
        pslld     $30, %xmm13
        psrld     $13, %xmm8
        pslld     $19, %xmm14
        por       %xmm13, %xmm10
        por       %xmm14, %xmm8
        movdqa    %xmm5, %xmm14
        movdqa    %xmm1, %xmm13
        pxor      %xmm7, %xmm14
        pxor      %xmm7, %xmm13
        pxor      %xmm8, %xmm10
        pand      %xmm13, %xmm14
        pxor      %xmm10, %xmm15
        pxor      %xmm7, %xmm14
        paddd     %xmm4, %xmm3
        movdqa    256(%rsp), %xmm10
        paddd     %xmm14, %xmm15
        paddd     %xmm15, %xmm4
        movdqa    %xmm10, %xmm8
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm13
        psrld     $7, %xmm8
        pslld     $25, %xmm15
        psrld     $18, %xmm14
        pslld     $14, %xmm10
        por       %xmm15, %xmm8
        por       %xmm10, %xmm14
        psrld     $3, %xmm13
        pxor      %xmm14, %xmm8
        movdqa    %xmm9, %xmm10
        pxor      %xmm8, %xmm13
        movdqa    %xmm9, %xmm8
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, 448(%rsp)
        psrld     $17, %xmm10
        pslld     $15, %xmm8
        psrld     $19, %xmm15
        pslld     $13, %xmm9
        por       %xmm8, %xmm10
        por       %xmm9, %xmm15
        psrld     $10, %xmm14
        pxor      %xmm15, %xmm10
        movdqa    %xmm3, %xmm15
        pxor      %xmm10, %xmm14
        movdqa    %xmm3, %xmm8
        paddd     336(%rsp), %xmm14
        movdqa    %xmm3, %xmm10
        paddd     %xmm14, %xmm12
        movdqa    %xmm3, %xmm14
        paddd     %xmm12, %xmm13
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm12
        psrld     $6, %xmm15
        pslld     $26, %xmm8
        psrld     $11, %xmm14
        pslld     $21, %xmm10
        psrld     $25, %xmm9
        pslld     $7, %xmm12
        por       %xmm8, %xmm15
        por       %xmm10, %xmm14
        movdqa    %xmm0, %xmm8
        por       %xmm12, %xmm9
        pxor      %xmm14, %xmm15
        pxor      %xmm6, %xmm8
        pxor      %xmm15, %xmm9
        pand      %xmm3, %xmm8
        paddd     %xmm9, %xmm2
        pxor      %xmm6, %xmm8
        movdqa    %xmm4, %xmm10
        paddd     %xmm8, %xmm2
        movdqa    %xmm4, %xmm8
        paddd     .L_2il0floatpacket.610(%rip), %xmm2
        psrld     $22, %xmm8
        paddd     %xmm13, %xmm2
        pslld     $10, %xmm10
        movdqa    %xmm13, 352(%rsp)
        paddd     %xmm2, %xmm5
        movdqa    576(%rsp), %xmm9
        movdqa    608(%rsp), %xmm12
..B6.34:
        movdqa    %xmm11, 592(%rsp)
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm11
        por       %xmm10, %xmm8
        movdqa    %xmm12, 608(%rsp)
        psrld     $2, %xmm13
        pslld     $30, %xmm11
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm10
        por       %xmm11, %xmm13
        psrld     $13, %xmm12
        pslld     $19, %xmm10
        movdqa    %xmm7, %xmm11
        movdqa    %xmm4, %xmm15
        por       %xmm10, %xmm12
        pxor      %xmm1, %xmm11
        pxor      %xmm1, %xmm15
        pxor      %xmm12, %xmm13
        pand      %xmm15, %xmm11
        pxor      %xmm13, %xmm8
        pxor      %xmm1, %xmm11
        paddd     %xmm11, %xmm8
        movdqa    272(%rsp), %xmm11
        paddd     %xmm8, %xmm2
        movdqa    %xmm9, 576(%rsp)
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, %xmm8
        movdqa    %xmm11, %xmm12
        movdqa    %xmm11, %xmm9
        psrld     $7, %xmm14
        pslld     $25, %xmm8
        psrld     $18, %xmm12
        pslld     $14, %xmm9
        movdqa    %xmm11, %xmm10
        por       %xmm8, %xmm14
        por       %xmm9, %xmm12
        movdqa    368(%rsp), %xmm8
        psrld     $3, %xmm10
        pxor      %xmm12, %xmm14
        movdqa    %xmm8, %xmm13
        pxor      %xmm14, %xmm10
        movdqa    %xmm8, %xmm14
        movdqa    %xmm8, %xmm12
        movdqa    %xmm8, %xmm9
        psrld     $17, %xmm14
        pslld     $15, %xmm13
        psrld     $19, %xmm12
        pslld     $13, %xmm8
        por       %xmm13, %xmm14
        por       %xmm8, %xmm12
        psrld     $10, %xmm9
        pxor      %xmm12, %xmm14
        pxor      %xmm14, %xmm9
        movdqa    %xmm5, %xmm8
        paddd     384(%rsp), %xmm9
        movdqa    %xmm5, %xmm12
        movdqa    256(%rsp), %xmm15
        movdqa    %xmm5, %xmm13
        paddd     %xmm9, %xmm15
        movdqa    %xmm5, %xmm9
        paddd     %xmm15, %xmm10
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm14
        psrld     $25, %xmm8
        pslld     $7, %xmm9
        psrld     $6, %xmm15
        pslld     $26, %xmm12
        psrld     $11, %xmm13
        pslld     $21, %xmm14
        por       %xmm9, %xmm8
        por       %xmm12, %xmm15
        por       %xmm14, %xmm13
        movdqa    %xmm3, %xmm9
        pxor      %xmm13, %xmm15
        pxor      %xmm0, %xmm9
        pxor      %xmm15, %xmm8
        pand      %xmm5, %xmm9
        paddd     %xmm8, %xmm6
        pxor      %xmm0, %xmm9
        movdqa    %xmm2, %xmm14
        paddd     %xmm9, %xmm6
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm9
        psrld     $22, %xmm14
        pslld     $10, %xmm8
        psrld     $2, %xmm15
        pslld     $30, %xmm9
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm12
        por       %xmm8, %xmm14
        por       %xmm9, %xmm15
        psrld     $13, %xmm13
        pslld     $19, %xmm12
        movdqa    %xmm1, %xmm9
        movdqa    %xmm4, %xmm8
        por       %xmm12, %xmm13
        pxor      %xmm4, %xmm9
        pxor      %xmm2, %xmm8
        pxor      %xmm13, %xmm15
        pand      %xmm8, %xmm9
        pxor      %xmm15, %xmm14
        movdqa    528(%rsp), %xmm12
        pxor      %xmm4, %xmm9
        paddd     .L_2il0floatpacket.611(%rip), %xmm6
        paddd     %xmm9, %xmm14
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm13
        movdqa    %xmm12, %xmm9
        movdqa    %xmm12, %xmm8
        paddd     %xmm10, %xmm6
        psrld     $7, %xmm15
        pslld     $25, %xmm13
        psrld     $18, %xmm9
        pslld     $14, %xmm8
        paddd     %xmm6, %xmm7
        paddd     %xmm14, %xmm6
        movdqa    %xmm12, %xmm14
        por       %xmm13, %xmm15
        por       %xmm8, %xmm9
        psrld     $3, %xmm14
        pxor      %xmm9, %xmm15
        pxor      %xmm15, %xmm14
        movdqa    352(%rsp), %xmm15
        movdqa    %xmm15, %xmm13
        movdqa    %xmm15, %xmm9
        psrld     $17, %xmm13
        pslld     $15, %xmm9
        por       %xmm9, %xmm13
        movdqa    %xmm15, %xmm9
        movdqa    %xmm15, %xmm8
        psrld     $19, %xmm9
        pslld     $13, %xmm15
        psrld     $10, %xmm8
        por       %xmm15, %xmm9
        movdqa    %xmm7, %xmm15
        pxor      %xmm9, %xmm13
        movdqa    %xmm7, %xmm9
        pxor      %xmm13, %xmm8
        movdqa    %xmm7, %xmm13
        paddd     400(%rsp), %xmm8
        psrld     $6, %xmm15
        paddd     %xmm8, %xmm11
        movdqa    %xmm7, %xmm8
        paddd     %xmm11, %xmm14
        movdqa    %xmm7, %xmm11
        psrld     $25, %xmm11
        pslld     $7, %xmm8
        por       %xmm8, %xmm11
        movdqa    %xmm7, %xmm8
        pslld     $26, %xmm13
        psrld     $11, %xmm9
        pslld     $21, %xmm8
        por       %xmm13, %xmm15
        por       %xmm8, %xmm9
        movdqa    %xmm5, %xmm8
        pxor      %xmm9, %xmm15
        pxor      %xmm3, %xmm8
        pxor      %xmm15, %xmm11
        pand      %xmm7, %xmm8
        pxor      %xmm3, %xmm8
        paddd     %xmm11, %xmm0
        paddd     %xmm8, %xmm0
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm11
        psrld     $22, %xmm8
        pslld     $10, %xmm11
        movdqa    %xmm6, %xmm9
        por       %xmm11, %xmm8
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm13
        psrld     $2, %xmm11
        pslld     $30, %xmm9
        psrld     $13, %xmm15
        pslld     $19, %xmm13
        por       %xmm9, %xmm11
        por       %xmm13, %xmm15
        movdqa    %xmm4, %xmm13
        movdqa    %xmm6, %xmm9
        pxor      %xmm2, %xmm13
        pxor      %xmm2, %xmm9
        pxor      %xmm15, %xmm11
        pand      %xmm9, %xmm13
        pxor      %xmm11, %xmm8
        pxor      %xmm2, %xmm13
        paddd     %xmm13, %xmm8
        movdqa    560(%rsp), %xmm13
        movdqa    %xmm13, %xmm11
        movdqa    %xmm13, %xmm15
        psrld     $7, %xmm11
        pslld     $25, %xmm15
        paddd     .L_2il0floatpacket.612(%rip), %xmm0
        por       %xmm15, %xmm11
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm9
        paddd     %xmm14, %xmm0
        psrld     $18, %xmm15
        pslld     $14, %xmm9
        paddd     %xmm0, %xmm1
        paddd     %xmm8, %xmm0
        movdqa    %xmm13, %xmm8
        por       %xmm9, %xmm15
        psrld     $3, %xmm8
        pxor      %xmm15, %xmm11
        movdqa    %xmm10, %xmm15
        pxor      %xmm11, %xmm8
        movdqa    %xmm10, %xmm11
        psrld     $17, %xmm11
        pslld     $15, %xmm15
        por       %xmm15, %xmm11
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, 464(%rsp)
        movdqa    %xmm10, %xmm9
        psrld     $19, %xmm15
        pslld     $13, %xmm10
        por       %xmm10, %xmm15
        psrld     $10, %xmm9
        pxor      %xmm15, %xmm11
        movdqa    %xmm1, %xmm10
        pxor      %xmm11, %xmm9
        movdqa    %xmm1, %xmm11
        paddd     416(%rsp), %xmm9
        psrld     $25, %xmm11
        paddd     %xmm9, %xmm12
        movdqa    %xmm1, %xmm9
        pslld     $7, %xmm9
        paddd     %xmm12, %xmm8
        por       %xmm9, %xmm11
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm15
        psrld     $6, %xmm9
        pslld     $26, %xmm12
        psrld     $11, %xmm10
        pslld     $21, %xmm15
        por       %xmm12, %xmm9
        por       %xmm15, %xmm10
        pxor      %xmm10, %xmm9
        movdqa    %xmm5, %xmm12
        pxor      %xmm9, %xmm11
        pxor      %xmm7, %xmm12
        pand      %xmm1, %xmm12
        paddd     %xmm11, %xmm3
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm11
        pxor      %xmm5, %xmm12
        psrld     $22, %xmm9
        pslld     $10, %xmm11
        paddd     %xmm12, %xmm3
        por       %xmm11, %xmm9
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm12
        psrld     $2, %xmm11
        pslld     $30, %xmm10
        psrld     $13, %xmm15
        pslld     $19, %xmm12
        por       %xmm10, %xmm11
        por       %xmm12, %xmm15
        movdqa    %xmm2, %xmm12
        movdqa    %xmm0, %xmm10
        pxor      %xmm15, %xmm11
        movdqa    576(%rsp), %xmm15
        pxor      %xmm6, %xmm12
        pxor      %xmm6, %xmm10
        pxor      %xmm11, %xmm9
        pand      %xmm10, %xmm12
        movdqa    %xmm15, %xmm11
        movdqa    %xmm15, %xmm10
        pxor      %xmm6, %xmm12
        psrld     $7, %xmm11
        pslld     $25, %xmm10
        paddd     .L_2il0floatpacket.613(%rip), %xmm3
        paddd     %xmm12, %xmm9
        por       %xmm10, %xmm11
        movdqa    %xmm15, %xmm10
        movdqa    %xmm15, %xmm12
        paddd     %xmm8, %xmm3
        psrld     $18, %xmm10
        pslld     $14, %xmm12
        paddd     %xmm3, %xmm4
        paddd     %xmm9, %xmm3
        movdqa    %xmm15, %xmm9
        por       %xmm12, %xmm10
        psrld     $3, %xmm9
        pxor      %xmm10, %xmm11
        pxor      %xmm11, %xmm9
        movdqa    %xmm14, %xmm12
        movdqa    %xmm14, %xmm11
        psrld     $17, %xmm12
        pslld     $15, %xmm11
        movdqa    %xmm14, %xmm10
        por       %xmm11, %xmm12
        movdqa    %xmm14, %xmm11
        movdqa    %xmm14, 320(%rsp)
        psrld     $19, %xmm11
        pslld     $13, %xmm14
        psrld     $10, %xmm10
        por       %xmm14, %xmm11
        movdqa    %xmm4, %xmm14
        pxor      %xmm11, %xmm12
        movdqa    %xmm4, %xmm11
        pxor      %xmm12, %xmm10
        pslld     $7, %xmm11
        paddd     432(%rsp), %xmm10
        movdqa    %xmm4, %xmm12
        paddd     %xmm10, %xmm13
        movdqa    %xmm4, %xmm10
        paddd     %xmm13, %xmm9
        movdqa    %xmm4, %xmm13
        psrld     $25, %xmm13
        psrld     $6, %xmm14
        por       %xmm11, %xmm13
        movdqa    %xmm4, %xmm11
        pslld     $26, %xmm10
        psrld     $11, %xmm11
        pslld     $21, %xmm12
        por       %xmm10, %xmm14
        por       %xmm12, %xmm11
        movdqa    %xmm1, %xmm10
        pxor      %xmm11, %xmm14
        pxor      %xmm7, %xmm10
        pxor      %xmm14, %xmm13
        pand      %xmm4, %xmm10
        paddd     %xmm13, %xmm5
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm13
        pxor      %xmm7, %xmm10
        psrld     $22, %xmm14
        pslld     $10, %xmm13
        paddd     %xmm10, %xmm5
        por       %xmm13, %xmm14
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm10
        psrld     $2, %xmm13
        pslld     $30, %xmm11
        psrld     $13, %xmm12
        pslld     $19, %xmm10
        por       %xmm11, %xmm13
        por       %xmm10, %xmm12
        movdqa    %xmm6, %xmm10
        movdqa    %xmm3, %xmm11
        pxor      %xmm0, %xmm10
        pxor      %xmm0, %xmm11
        pxor      %xmm12, %xmm13
        pand      %xmm11, %xmm10
        pxor      %xmm13, %xmm14
        pxor      %xmm0, %xmm10
        movdqa    544(%rsp), %xmm13
        paddd     %xmm10, %xmm14
        movdqa    %xmm13, %xmm10
        movdqa    %xmm13, %xmm12
        psrld     $7, %xmm10
        pslld     $25, %xmm12
        paddd     .L_2il0floatpacket.614(%rip), %xmm5
        por       %xmm12, %xmm10
        movdqa    %xmm13, %xmm12
        movdqa    %xmm13, %xmm11
        paddd     %xmm9, %xmm5
        psrld     $18, %xmm12
        pslld     $14, %xmm11
        paddd     %xmm5, %xmm2
        paddd     %xmm14, %xmm5
        movdqa    %xmm13, %xmm14
        por       %xmm11, %xmm12
        psrld     $3, %xmm14
        pxor      %xmm12, %xmm10
        movdqa    %xmm8, %xmm12
        pxor      %xmm10, %xmm14
        movdqa    %xmm8, %xmm10
        psrld     $17, %xmm12
        pslld     $15, %xmm10
        por       %xmm10, %xmm12
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, 288(%rsp)
        movdqa    %xmm8, %xmm11
        psrld     $19, %xmm10
        pslld     $13, %xmm8
        por       %xmm8, %xmm10
        psrld     $10, %xmm11
        pxor      %xmm10, %xmm12
        movdqa    %xmm2, %xmm10
        pxor      %xmm12, %xmm11
        pslld     $7, %xmm10
        paddd     448(%rsp), %xmm11
        movdqa    %xmm2, %xmm12
        paddd     %xmm11, %xmm15
        movdqa    %xmm2, %xmm11
        psrld     $25, %xmm11
        paddd     %xmm15, %xmm14
        por       %xmm10, %xmm11
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm15
        psrld     $6, %xmm10
        pslld     $26, %xmm12
        psrld     $11, %xmm8
        pslld     $21, %xmm15
        por       %xmm12, %xmm10
        por       %xmm15, %xmm8
        pxor      %xmm8, %xmm10
        movdqa    %xmm4, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm1, %xmm12
        pand      %xmm2, %xmm12
        paddd     %xmm11, %xmm7
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm11
        pxor      %xmm1, %xmm12
        psrld     $22, %xmm8
        pslld     $10, %xmm11
        paddd     %xmm12, %xmm7
        por       %xmm11, %xmm8
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm12
        psrld     $2, %xmm11
        pslld     $30, %xmm10
        psrld     $13, %xmm15
        pslld     $19, %xmm12
        por       %xmm10, %xmm11
        por       %xmm12, %xmm15
        movdqa    %xmm0, %xmm12
        movdqa    %xmm5, %xmm10
        pxor      %xmm3, %xmm12
        pxor      %xmm3, %xmm10
        pxor      %xmm15, %xmm11
        pand      %xmm10, %xmm12
        pxor      %xmm11, %xmm8
        paddd     .L_2il0floatpacket.615(%rip), %xmm7
        pxor      %xmm3, %xmm12
        paddd     %xmm14, %xmm7
        paddd     %xmm12, %xmm8
        paddd     %xmm7, %xmm6
        paddd     %xmm8, %xmm7
        movdqa    608(%rsp), %xmm8
        movdqa    %xmm8, %xmm12
        movdqa    %xmm8, %xmm15
        psrld     $7, %xmm12
        pslld     $25, %xmm15
        por       %xmm15, %xmm12
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, %xmm10
        psrld     $18, %xmm15
        pslld     $14, %xmm10
        movdqa    %xmm8, %xmm11
        por       %xmm10, %xmm15
        psrld     $3, %xmm11
        pxor      %xmm15, %xmm12
        movdqa    %xmm9, %xmm15
        pxor      %xmm12, %xmm11
        movdqa    %xmm9, %xmm12
        psrld     $17, %xmm15
        pslld     $15, %xmm12
        por       %xmm12, %xmm15
        movdqa    %xmm9, %xmm12
        movdqa    %xmm9, 304(%rsp)
        movdqa    %xmm9, %xmm10
        psrld     $19, %xmm12
        pslld     $13, %xmm9
        por       %xmm9, %xmm12
        psrld     $10, %xmm10
        pxor      %xmm12, %xmm15
        movdqa    %xmm6, %xmm9
        pxor      %xmm15, %xmm10
        psrld     $25, %xmm9
        paddd     368(%rsp), %xmm10
        movdqa    %xmm6, %xmm15
        paddd     %xmm10, %xmm13
        movdqa    %xmm6, %xmm10
        paddd     %xmm13, %xmm11
        movdqa    %xmm6, %xmm13
        pslld     $7, %xmm13
        movdqa    %xmm6, %xmm12
        por       %xmm13, %xmm9
        movdqa    %xmm6, %xmm13
        psrld     $6, %xmm13
        pslld     $26, %xmm10
        psrld     $11, %xmm15
        pslld     $21, %xmm12
        por       %xmm10, %xmm13
        por       %xmm12, %xmm15
        movdqa    %xmm2, %xmm10
        pxor      %xmm15, %xmm13
        pxor      %xmm4, %xmm10
        pxor      %xmm13, %xmm9
        pand      %xmm6, %xmm10
        paddd     %xmm9, %xmm1
        pxor      %xmm4, %xmm10
        movdqa    %xmm7, %xmm9
        paddd     %xmm10, %xmm1
        pslld     $10, %xmm9
        paddd     .L_2il0floatpacket.616(%rip), %xmm1
        movdqa    %xmm7, %xmm10
        movdqa    %xmm11, 512(%rsp)
        paddd     %xmm11, %xmm1
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm13
        psrld     $22, %xmm11
        movdqa    %xmm7, %xmm12
        por       %xmm9, %xmm11
        movdqa    %xmm7, %xmm9
        psrld     $13, %xmm9
        pslld     $19, %xmm10
        psrld     $2, %xmm13
        pslld     $30, %xmm12
        por       %xmm10, %xmm9
        movdqa    %xmm3, %xmm10
        movdqa    %xmm7, %xmm15
        por       %xmm12, %xmm13
        pxor      %xmm5, %xmm10
        pxor      %xmm5, %xmm15
        pxor      %xmm9, %xmm13
        pand      %xmm15, %xmm10
        pxor      %xmm13, %xmm11
        pxor      %xmm5, %xmm10
        paddd     %xmm10, %xmm11
        paddd     %xmm1, %xmm0
        paddd     %xmm11, %xmm1
        movdqa    592(%rsp), %xmm11
        movdqa    %xmm11, %xmm15
        movdqa    %xmm11, %xmm9
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm12
        psrld     $7, %xmm15
        pslld     $25, %xmm9
        psrld     $18, %xmm13
        pslld     $14, %xmm12
        movdqa    %xmm11, %xmm10
        por       %xmm9, %xmm15
        por       %xmm12, %xmm13
        psrld     $3, %xmm10
        pxor      %xmm13, %xmm15
        movdqa    %xmm14, %xmm9
        pxor      %xmm15, %xmm10
        movdqa    %xmm14, %xmm13
        movdqa    %xmm14, %xmm15
        movdqa    %xmm14, %xmm12
        movdqa    %xmm14, 480(%rsp)
        psrld     $17, %xmm9
        pslld     $15, %xmm13
        psrld     $19, %xmm15
        pslld     $13, %xmm14
        por       %xmm13, %xmm9
        por       %xmm14, %xmm15
        psrld     $10, %xmm12
        pxor      %xmm15, %xmm9
        movdqa    %xmm0, %xmm14
        pxor      %xmm9, %xmm12
        movdqa    %xmm0, %xmm13
        paddd     352(%rsp), %xmm12
        movdqa    %xmm0, %xmm9
        paddd     %xmm12, %xmm8
        movdqa    %xmm0, %xmm12
        paddd     %xmm8, %xmm10
        movdqa    %xmm0, %xmm8
        movdqa    %xmm10, 496(%rsp)
        movdqa    %xmm0, %xmm10
        psrld     $25, %xmm14
        pslld     $7, %xmm8
        psrld     $6, %xmm13
        pslld     $26, %xmm9
        psrld     $11, %xmm12
        pslld     $21, %xmm10
        por       %xmm8, %xmm14
        por       %xmm9, %xmm13
        por       %xmm10, %xmm12
        movdqa    %xmm6, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm2, %xmm8
        pxor      %xmm13, %xmm14
        pand      %xmm0, %xmm8
        pxor      %xmm2, %xmm8
        paddd     %xmm14, %xmm4
        paddd     %xmm8, %xmm4
..B6.33:
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm9
        psrld     $2, %xmm15
        pslld     $30, %xmm8
        psrld     $13, %xmm10
        pslld     $19, %xmm9
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm13
        por       %xmm8, %xmm15
        por       %xmm9, %xmm10
        movdqa    %xmm5, %xmm9
        movdqa    %xmm1, %xmm8
        psrld     $22, %xmm14
        pslld     $10, %xmm13
        pxor      %xmm7, %xmm9
        pxor      %xmm7, %xmm8
        por       %xmm13, %xmm14
        pxor      %xmm10, %xmm15
        pand      %xmm8, %xmm9
        pxor      %xmm15, %xmm14
        movdqa    336(%rsp), %xmm13
        pxor      %xmm7, %xmm9
        movdqa    496(%rsp), %xmm12
        paddd     %xmm9, %xmm14
        paddd     .L_2il0floatpacket.617(%rip), %xmm4
        movdqa    %xmm13, %xmm9
        movdqa    %xmm13, %xmm8
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm10
        paddd     %xmm12, %xmm4
        psrld     $7, %xmm9
        pslld     $25, %xmm8
        psrld     $18, %xmm15
        pslld     $14, %xmm10
        paddd     %xmm4, %xmm3
        paddd     %xmm14, %xmm4
        movdqa    %xmm13, %xmm14
        por       %xmm8, %xmm9
        por       %xmm10, %xmm15
        psrld     $3, %xmm14
        movdqa    512(%rsp), %xmm10
        pxor      %xmm15, %xmm9
        pxor      %xmm9, %xmm14
        movdqa    %xmm10, %xmm9
        movdqa    %xmm10, %xmm8
        psrld     $17, %xmm9
        pslld     $15, %xmm8
        movdqa    %xmm10, %xmm15
        por       %xmm8, %xmm9
        movdqa    %xmm10, %xmm8
        psrld     $19, %xmm8
        pslld     $13, %xmm10
        por       %xmm10, %xmm8
        psrld     $10, %xmm15
        pxor      %xmm8, %xmm9
        movdqa    %xmm3, %xmm8
        pxor      %xmm9, %xmm15
        pslld     $7, %xmm8
        paddd     464(%rsp), %xmm15
        movdqa    %xmm3, %xmm10
        paddd     %xmm15, %xmm11
        movdqa    %xmm3, %xmm9
        paddd     %xmm11, %xmm14
        movdqa    %xmm3, %xmm11
        psrld     $25, %xmm11
        movdqa    %xmm3, %xmm15
        por       %xmm8, %xmm11
        movdqa    %xmm3, %xmm8
        psrld     $6, %xmm10
        pslld     $26, %xmm9
        psrld     $11, %xmm8
        pslld     $21, %xmm15
        por       %xmm9, %xmm10
        por       %xmm15, %xmm8
        pxor      %xmm8, %xmm10
        movdqa    %xmm0, %xmm9
        pxor      %xmm10, %xmm11
        pxor      %xmm6, %xmm9
        pand      %xmm3, %xmm9
        paddd     %xmm11, %xmm2
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm11
        pxor      %xmm6, %xmm9
        psrld     $22, %xmm10
        pslld     $10, %xmm11
        paddd     %xmm9, %xmm2
        por       %xmm11, %xmm10
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm9
        psrld     $2, %xmm11
        pslld     $30, %xmm8
        psrld     $13, %xmm15
        pslld     $19, %xmm9
        por       %xmm8, %xmm11
        por       %xmm9, %xmm15
        movdqa    %xmm7, %xmm9
        pxor      %xmm15, %xmm11
        movdqa    %xmm1, %xmm8
        pxor      %xmm11, %xmm10
        pxor      %xmm1, %xmm9
        movdqa    384(%rsp), %xmm11
        pxor      %xmm4, %xmm8
        pand      %xmm8, %xmm9
        movdqa    %xmm11, %xmm8
        movdqa    %xmm11, %xmm15
        pxor      %xmm1, %xmm9
        psrld     $7, %xmm8
        pslld     $25, %xmm15
        paddd     .L_2il0floatpacket.618(%rip), %xmm2
        paddd     %xmm9, %xmm10
        por       %xmm15, %xmm8
        movdqa    %xmm11, %xmm15
        movdqa    %xmm11, %xmm9
        paddd     %xmm14, %xmm2
        psrld     $18, %xmm15
        pslld     $14, %xmm9
        paddd     %xmm2, %xmm5
        paddd     %xmm10, %xmm2
        movdqa    %xmm11, %xmm10
        por       %xmm9, %xmm15
        psrld     $3, %xmm10
        pxor      %xmm15, %xmm8
        pxor      %xmm8, %xmm10
        movdqa    %xmm12, %xmm9
        movdqa    %xmm12, %xmm8
        psrld     $17, %xmm9
        pslld     $15, %xmm8
        movdqa    %xmm12, %xmm15
        por       %xmm8, %xmm9
        movdqa    %xmm12, %xmm8
        psrld     $19, %xmm8
        pslld     $13, %xmm12
        por       %xmm12, %xmm8
        psrld     $10, %xmm15
        pxor      %xmm8, %xmm9
        movdqa    %xmm5, %xmm8
        pxor      %xmm9, %xmm15
        pslld     $7, %xmm8
        paddd     320(%rsp), %xmm15
        movdqa    %xmm5, %xmm12
        paddd     %xmm15, %xmm13
        movdqa    %xmm5, %xmm15
        psrld     $25, %xmm15
        paddd     %xmm13, %xmm10
        por       %xmm8, %xmm15
        movdqa    %xmm5, %xmm9
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm13
        psrld     $6, %xmm12
        pslld     $26, %xmm9
        psrld     $11, %xmm8
        pslld     $21, %xmm13
        por       %xmm9, %xmm12
        por       %xmm13, %xmm8
        pxor      %xmm8, %xmm12
        movdqa    %xmm0, %xmm9
        pxor      %xmm12, %xmm15
        pxor      %xmm3, %xmm9
        pand      %xmm5, %xmm9
        paddd     %xmm15, %xmm6
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm15
        pxor      %xmm0, %xmm9
        psrld     $22, %xmm8
        pslld     $10, %xmm15
        paddd     %xmm9, %xmm6
        por       %xmm15, %xmm8
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm13
        psrld     $2, %xmm15
        pslld     $30, %xmm9
        psrld     $13, %xmm12
        pslld     $19, %xmm13
        por       %xmm9, %xmm15
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm13
        movdqa    %xmm2, %xmm9
        pxor      %xmm4, %xmm13
        pxor      %xmm4, %xmm9
        pxor      %xmm12, %xmm15
        pand      %xmm9, %xmm13
        pxor      %xmm15, %xmm8
        movdqa    400(%rsp), %xmm15
        pxor      %xmm4, %xmm13
        paddd     %xmm13, %xmm8
        movdqa    %xmm15, %xmm13
        movdqa    %xmm15, %xmm12
        psrld     $7, %xmm13
        pslld     $25, %xmm12
        movdqa    %xmm15, %xmm9
        paddd     .L_2il0floatpacket.619(%rip), %xmm6
        por       %xmm12, %xmm13
        movdqa    %xmm15, %xmm12
        paddd     %xmm10, %xmm6
        psrld     $18, %xmm12
        pslld     $14, %xmm9
        paddd     %xmm6, %xmm7
        paddd     %xmm8, %xmm6
        movdqa    %xmm15, %xmm8
        por       %xmm9, %xmm12
        psrld     $3, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm13, %xmm8
        movdqa    %xmm14, %xmm12
        movdqa    %xmm14, %xmm13
        psrld     $17, %xmm12
        pslld     $15, %xmm13
        movdqa    %xmm14, %xmm9
        por       %xmm13, %xmm12
        movdqa    %xmm14, %xmm13
        movdqa    %xmm14, 592(%rsp)
        psrld     $19, %xmm13
        pslld     $13, %xmm14
        psrld     $10, %xmm9
        por       %xmm14, %xmm13
        movdqa    %xmm7, %xmm14
        pxor      %xmm13, %xmm12
        movdqa    %xmm7, %xmm13
        pxor      %xmm12, %xmm9
        movdqa    %xmm7, %xmm12
        paddd     288(%rsp), %xmm9
        pslld     $26, %xmm13
        paddd     %xmm9, %xmm11
        movdqa    %xmm7, %xmm9
        paddd     %xmm11, %xmm8
        movdqa    %xmm7, %xmm11
        psrld     $25, %xmm11
        pslld     $7, %xmm9
        por       %xmm9, %xmm11
        movdqa    %xmm7, %xmm9
        psrld     $6, %xmm9
        psrld     $11, %xmm14
        pslld     $21, %xmm12
        por       %xmm13, %xmm9
        por       %xmm12, %xmm14
        movdqa    %xmm5, %xmm13
        pxor      %xmm14, %xmm9
        pxor      %xmm3, %xmm13
        pxor      %xmm9, %xmm11
        pand      %xmm7, %xmm13
        paddd     %xmm11, %xmm0
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm11
        pxor      %xmm3, %xmm13
        psrld     $22, %xmm9
        pslld     $10, %xmm11
        paddd     %xmm13, %xmm0
        por       %xmm11, %xmm9
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm13
        psrld     $2, %xmm11
        pslld     $30, %xmm14
        psrld     $13, %xmm12
        pslld     $19, %xmm13
        por       %xmm14, %xmm11
        por       %xmm13, %xmm12
        pxor      %xmm12, %xmm11
        movdqa    %xmm4, %xmm13
        movdqa    %xmm6, %xmm14
        pxor      %xmm11, %xmm9
        movdqa    416(%rsp), %xmm11
        pxor      %xmm2, %xmm13
        pxor      %xmm2, %xmm14
        movdqa    %xmm11, %xmm12
        pand      %xmm14, %xmm13
        movdqa    %xmm11, %xmm14
        pxor      %xmm2, %xmm13
        psrld     $7, %xmm14
        pslld     $25, %xmm12
        paddd     %xmm13, %xmm9
        paddd     .L_2il0floatpacket.620(%rip), %xmm0
        por       %xmm12, %xmm14
        movdqa    %xmm11, %xmm12
        movdqa    %xmm11, %xmm13
        paddd     %xmm8, %xmm0
        psrld     $18, %xmm12
        pslld     $14, %xmm13
        paddd     %xmm0, %xmm1
        paddd     %xmm9, %xmm0
        movdqa    %xmm11, %xmm9
        por       %xmm13, %xmm12
        psrld     $3, %xmm9
        pxor      %xmm12, %xmm14
        movdqa    %xmm10, %xmm12
        pxor      %xmm14, %xmm9
        movdqa    %xmm10, %xmm14
        psrld     $17, %xmm12
        pslld     $15, %xmm14
        por       %xmm14, %xmm12
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, 560(%rsp)
        movdqa    %xmm10, %xmm13
        psrld     $19, %xmm14
        pslld     $13, %xmm10
        por       %xmm10, %xmm14
        psrld     $10, %xmm13
        pxor      %xmm14, %xmm12
        movdqa    %xmm1, %xmm10
        pxor      %xmm12, %xmm13
        psrld     $25, %xmm10
        paddd     304(%rsp), %xmm13
        movdqa    %xmm1, %xmm14
        paddd     %xmm13, %xmm15
        movdqa    %xmm1, %xmm12
        paddd     %xmm15, %xmm9
        movdqa    %xmm1, %xmm15
        pslld     $7, %xmm15
        movdqa    %xmm1, %xmm13
        por       %xmm15, %xmm10
        movdqa    %xmm1, %xmm15
        psrld     $6, %xmm15
        pslld     $26, %xmm14
        psrld     $11, %xmm12
        pslld     $21, %xmm13
        por       %xmm14, %xmm15
        por       %xmm13, %xmm12
        pxor      %xmm12, %xmm15
        movdqa    %xmm7, %xmm14
        pxor      %xmm15, %xmm10
        pxor      %xmm5, %xmm14
        pand      %xmm1, %xmm14
        paddd     %xmm10, %xmm3
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm10
        pxor      %xmm5, %xmm14
        psrld     $22, %xmm13
        pslld     $10, %xmm10
        paddd     %xmm14, %xmm3
        por       %xmm10, %xmm13
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm12
        psrld     $2, %xmm10
        pslld     $30, %xmm14
        psrld     $13, %xmm15
        pslld     $19, %xmm12
        por       %xmm14, %xmm10
        por       %xmm12, %xmm15
        movdqa    %xmm2, %xmm12
        movdqa    %xmm0, %xmm14
        pxor      %xmm6, %xmm12
        pxor      %xmm6, %xmm14
        pxor      %xmm15, %xmm10
        pand      %xmm14, %xmm12
        pxor      %xmm10, %xmm13
        movdqa    432(%rsp), %xmm10
        pxor      %xmm6, %xmm12
        paddd     %xmm12, %xmm13
        movdqa    %xmm10, %xmm12
        movdqa    %xmm10, %xmm15
        psrld     $7, %xmm12
        pslld     $25, %xmm15
        movdqa    %xmm10, %xmm14
        paddd     .L_2il0floatpacket.621(%rip), %xmm3
        por       %xmm15, %xmm12
        movdqa    %xmm10, %xmm15
        paddd     %xmm9, %xmm3
        psrld     $18, %xmm15
        pslld     $14, %xmm14
        paddd     %xmm3, %xmm4
        paddd     %xmm13, %xmm3
        movdqa    %xmm10, %xmm13
        por       %xmm14, %xmm15
        psrld     $3, %xmm13
        pxor      %xmm15, %xmm12
        pxor      %xmm12, %xmm13
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, %xmm12
        psrld     $17, %xmm15
        pslld     $15, %xmm12
        movdqa    %xmm8, %xmm14
        por       %xmm12, %xmm15
        movdqa    %xmm8, %xmm12
        movdqa    %xmm8, 576(%rsp)
        psrld     $19, %xmm12
        pslld     $13, %xmm8
        psrld     $10, %xmm14
        por       %xmm8, %xmm12
        movdqa    %xmm4, %xmm8
        pxor      %xmm12, %xmm15
        movdqa    %xmm4, %xmm12
        pxor      %xmm15, %xmm14
        pslld     $7, %xmm12
        paddd     480(%rsp), %xmm14
        movdqa    %xmm4, %xmm15
        paddd     %xmm14, %xmm11
        movdqa    %xmm4, %xmm14
        psrld     $25, %xmm14
        paddd     %xmm11, %xmm13
        por       %xmm12, %xmm14
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm11
        psrld     $6, %xmm12
        pslld     $26, %xmm15
        psrld     $11, %xmm8
        pslld     $21, %xmm11
        por       %xmm15, %xmm12
        por       %xmm11, %xmm8
        movdqa    %xmm1, %xmm15
        pxor      %xmm8, %xmm12
        pxor      %xmm7, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm4, %xmm15
        paddd     %xmm14, %xmm5
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm14
        pxor      %xmm7, %xmm15
        psrld     $22, %xmm8
        pslld     $10, %xmm14
        paddd     %xmm15, %xmm5
        por       %xmm14, %xmm8
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm15
        psrld     $2, %xmm14
        pslld     $30, %xmm12
        psrld     $13, %xmm11
        pslld     $19, %xmm15
        por       %xmm12, %xmm14
        por       %xmm15, %xmm11
        pxor      %xmm11, %xmm14
        movdqa    %xmm6, %xmm15
        movdqa    %xmm3, %xmm12
        pxor      %xmm14, %xmm8
        movdqa    448(%rsp), %xmm14
        pxor      %xmm0, %xmm15
        pxor      %xmm0, %xmm12
        movdqa    %xmm14, %xmm11
        pand      %xmm12, %xmm15
        movdqa    %xmm14, %xmm12
        pxor      %xmm0, %xmm15
        psrld     $7, %xmm11
        pslld     $25, %xmm12
        paddd     %xmm15, %xmm8
        paddd     .L_2il0floatpacket.622(%rip), %xmm5
        por       %xmm12, %xmm11
        movdqa    %xmm14, %xmm12
        movdqa    %xmm14, %xmm15
        paddd     %xmm13, %xmm5
        psrld     $18, %xmm12
        pslld     $14, %xmm15
        paddd     %xmm5, %xmm2
        paddd     %xmm8, %xmm5
        movdqa    %xmm14, %xmm8
        por       %xmm15, %xmm12
        psrld     $3, %xmm8
        pxor      %xmm12, %xmm11
        movdqa    %xmm9, %xmm15
        pxor      %xmm11, %xmm8
        movdqa    %xmm9, %xmm11
        psrld     $17, %xmm15
        pslld     $15, %xmm11
        por       %xmm11, %xmm15
        movdqa    %xmm9, %xmm11
        movdqa    %xmm9, 256(%rsp)
        movdqa    %xmm9, %xmm12
        psrld     $19, %xmm11
        pslld     $13, %xmm9
        por       %xmm9, %xmm11
        psrld     $10, %xmm12
        pxor      %xmm11, %xmm15
        movdqa    %xmm2, %xmm9
        pxor      %xmm15, %xmm12
        psrld     $25, %xmm9
        paddd     512(%rsp), %xmm12
        movdqa    %xmm2, %xmm15
        paddd     %xmm12, %xmm10
        movdqa    %xmm2, %xmm12
        paddd     %xmm10, %xmm8
        movdqa    %xmm2, %xmm10
        pslld     $7, %xmm10
        movdqa    %xmm2, %xmm11
        por       %xmm10, %xmm9
        movdqa    %xmm2, %xmm10
        psrld     $6, %xmm10
        pslld     $26, %xmm12
        psrld     $11, %xmm15
        pslld     $21, %xmm11
        por       %xmm12, %xmm10
        por       %xmm11, %xmm15
        movdqa    %xmm4, %xmm12
        pxor      %xmm15, %xmm10
        pxor      %xmm1, %xmm12
        pxor      %xmm10, %xmm9
        pand      %xmm2, %xmm12
        paddd     %xmm9, %xmm7
        pxor      %xmm1, %xmm12
        movdqa    %xmm5, %xmm15
        paddd     %xmm12, %xmm7
        movdqa    %xmm5, %xmm12
        paddd     .L_2il0floatpacket.623(%rip), %xmm7
        movdqa    %xmm5, %xmm9
        movdqa    %xmm8, 528(%rsp)
        paddd     %xmm8, %xmm7
        movdqa    %xmm5, %xmm8
        psrld     $22, %xmm12
        pslld     $10, %xmm8
        psrld     $2, %xmm15
        pslld     $30, %xmm9
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm10
        por       %xmm8, %xmm12
        por       %xmm9, %xmm15
        psrld     $13, %xmm11
        pslld     $19, %xmm10
        movdqa    %xmm0, %xmm9
        movdqa    %xmm5, %xmm8
        por       %xmm10, %xmm11
        pxor      %xmm3, %xmm9
        pxor      %xmm3, %xmm8
        pxor      %xmm11, %xmm15
        pand      %xmm8, %xmm9
        pxor      %xmm15, %xmm12
        pxor      %xmm3, %xmm9
        movdqa    368(%rsp), %xmm8
        paddd     %xmm9, %xmm12
        paddd     %xmm7, %xmm6
        paddd     %xmm12, %xmm7
        movdqa    %xmm8, %xmm11
        movdqa    %xmm8, %xmm12
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, %xmm9
        psrld     $7, %xmm11
        pslld     $25, %xmm12
        psrld     $18, %xmm10
        pslld     $14, %xmm8
        por       %xmm12, %xmm11
        por       %xmm8, %xmm10
        psrld     $3, %xmm9
        pxor      %xmm10, %xmm11
        movdqa    %xmm13, %xmm10
        movdqa    %xmm13, %xmm15
        movdqa    %xmm13, %xmm8
        pxor      %xmm11, %xmm9
        movdqa    %xmm13, 272(%rsp)
        movdqa    %xmm13, %xmm11
        psrld     $17, %xmm10
        pslld     $15, %xmm15
        psrld     $19, %xmm8
        pslld     $13, %xmm13
        por       %xmm15, %xmm10
        por       %xmm13, %xmm8
        psrld     $10, %xmm11
        pxor      %xmm8, %xmm10
        pxor      %xmm10, %xmm11
        movdqa    %xmm6, %xmm8
        paddd     496(%rsp), %xmm11
        psrld     $25, %xmm8
        paddd     %xmm11, %xmm14
        movdqa    %xmm6, %xmm11
        paddd     %xmm14, %xmm9
        movdqa    %xmm6, %xmm14
        pslld     $7, %xmm14
        movdqa    %xmm6, %xmm10
        movdqa    %xmm9, 544(%rsp)
        por       %xmm14, %xmm8
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm9
        psrld     $6, %xmm14
        pslld     $26, %xmm9
        psrld     $11, %xmm11
        pslld     $21, %xmm10
        por       %xmm9, %xmm14
        por       %xmm10, %xmm11
        movdqa    592(%rsp), %xmm12
        pxor      %xmm11, %xmm14
        movdqa    560(%rsp), %xmm13
        movdqa    576(%rsp), %xmm9
..B6.32:
        movdqa    %xmm9, 576(%rsp)
        movdqa    %xmm2, %xmm9
        pxor      %xmm4, %xmm9
        pxor      %xmm14, %xmm8
        pand      %xmm6, %xmm9
        paddd     %xmm8, %xmm1
        pxor      %xmm4, %xmm9
        movdqa    %xmm7, %xmm11
        movdqa    %xmm13, 560(%rsp)
        paddd     %xmm9, %xmm1
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm13
        psrld     $22, %xmm11
        pslld     $10, %xmm14
        psrld     $2, %xmm9
        pslld     $30, %xmm13
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm15
        por       %xmm14, %xmm11
        por       %xmm13, %xmm9
        psrld     $13, %xmm10
        pslld     $19, %xmm15
        movdqa    %xmm3, %xmm13
        movdqa    %xmm7, %xmm14
        por       %xmm15, %xmm10
        pxor      %xmm5, %xmm13
        pxor      %xmm5, %xmm14
        pxor      %xmm10, %xmm9
        pand      %xmm14, %xmm13
        paddd     .L_2il0floatpacket.624(%rip), %xmm1
        pxor      %xmm9, %xmm11
        movdqa    544(%rsp), %xmm8
        pxor      %xmm5, %xmm13
        movdqa    352(%rsp), %xmm15
        paddd     %xmm8, %xmm1
        paddd     %xmm13, %xmm11
        movdqa    %xmm15, %xmm10
        movdqa    %xmm15, %xmm9
        movdqa    %xmm15, %xmm14
        paddd     %xmm1, %xmm0
        paddd     %xmm11, %xmm1
        movdqa    %xmm15, %xmm11
        psrld     $7, %xmm10
        pslld     $25, %xmm9
        psrld     $18, %xmm14
        pslld     $14, %xmm15
        por       %xmm9, %xmm10
        por       %xmm15, %xmm14
        psrld     $3, %xmm11
        movdqa    528(%rsp), %xmm15
        pxor      %xmm14, %xmm10
        movdqa    %xmm15, %xmm14
        movdqa    %xmm15, %xmm9
        psrld     $17, %xmm14
        pslld     $15, %xmm9
        por       %xmm9, %xmm14
        movdqa    %xmm15, %xmm9
        movdqa    %xmm15, %xmm13
        psrld     $19, %xmm9
        pslld     $13, %xmm15
        psrld     $10, %xmm13
        por       %xmm15, %xmm9
        pxor      %xmm10, %xmm11
        pxor      %xmm9, %xmm14
        movdqa    %xmm0, %xmm9
        pxor      %xmm14, %xmm13
        psrld     $25, %xmm9
        movdqa    368(%rsp), %xmm14
        paddd     %xmm12, %xmm13
        paddd     %xmm13, %xmm14
        movdqa    %xmm0, %xmm13
        pslld     $7, %xmm13
        paddd     %xmm14, %xmm11
        por       %xmm13, %xmm9
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm15
        psrld     $6, %xmm13
        pslld     $26, %xmm14
        psrld     $11, %xmm10
        pslld     $21, %xmm15
        por       %xmm14, %xmm13
        por       %xmm15, %xmm10
        movdqa    %xmm6, %xmm14
        pxor      %xmm10, %xmm13
        pxor      %xmm2, %xmm14
        pxor      %xmm13, %xmm9
        pand      %xmm0, %xmm14
        paddd     %xmm9, %xmm4
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm9
        pxor      %xmm2, %xmm14
        psrld     $22, %xmm10
        pslld     $10, %xmm9
        paddd     %xmm14, %xmm4
        por       %xmm9, %xmm10
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm13
        psrld     $2, %xmm9
        pslld     $30, %xmm14
        psrld     $13, %xmm15
        pslld     $19, %xmm13
        por       %xmm14, %xmm9
        por       %xmm13, %xmm15
        movdqa    %xmm5, %xmm13
        movdqa    %xmm7, %xmm14
        pxor      %xmm7, %xmm13
        pxor      %xmm1, %xmm14
        pxor      %xmm15, %xmm9
        pand      %xmm14, %xmm13
        paddd     .L_2il0floatpacket.625(%rip), %xmm4
        pxor      %xmm9, %xmm10
        pxor      %xmm7, %xmm13
        paddd     %xmm11, %xmm4
        paddd     %xmm13, %xmm10
        paddd     %xmm4, %xmm3
        paddd     %xmm10, %xmm4
        testl     %eax, %eax
        movdqa    464(%rsp), %xmm10
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm15
        psrld     $7, %xmm14
        pslld     $25, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm13
        psrld     $18, %xmm15
        pslld     $14, %xmm13
        movdqa    %xmm10, %xmm9
        por       %xmm13, %xmm15
        psrld     $3, %xmm9
        pxor      %xmm15, %xmm14
        movdqa    %xmm8, %xmm15
        pxor      %xmm14, %xmm9
        movdqa    %xmm8, %xmm14
        psrld     $17, %xmm14
        pslld     $15, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, %xmm13
        psrld     $19, %xmm15
        pslld     $13, %xmm8
        psrld     $10, %xmm13
        por       %xmm8, %xmm15
        movdqa    %xmm3, %xmm8
        pxor      %xmm15, %xmm14
        movdqa    %xmm3, %xmm15
        pxor      %xmm14, %xmm13
        pslld     $7, %xmm15
        paddd     560(%rsp), %xmm13
        pslld     $26, %xmm8
        movdqa    352(%rsp), %xmm14
        paddd     %xmm13, %xmm14
        movdqa    %xmm3, %xmm13
        paddd     %xmm14, %xmm9
        movdqa    %xmm3, %xmm14
        psrld     $25, %xmm13
        psrld     $6, %xmm14
        por       %xmm15, %xmm13
        por       %xmm8, %xmm14
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm15
        psrld     $11, %xmm8
        pslld     $21, %xmm15
        por       %xmm15, %xmm8
        movdqa    %xmm4, %xmm15
        pxor      %xmm8, %xmm14
        movdqa    %xmm4, %xmm8
        pxor      %xmm14, %xmm13
        movdqa    %xmm6, %xmm14
        pxor      %xmm0, %xmm14
        paddd     %xmm13, %xmm2
        pand      %xmm3, %xmm14
        psrld     $22, %xmm8
        pxor      %xmm6, %xmm14
        movdqa    %xmm4, %xmm13
        paddd     %xmm14, %xmm2
        movdqa    %xmm4, %xmm14
        paddd     .L_2il0floatpacket.626(%rip), %xmm2
        pslld     $30, %xmm14
        movdqa    %xmm9, 336(%rsp)
        paddd     %xmm9, %xmm2
        movdqa    %xmm4, %xmm9
        psrld     $13, %xmm15
        pslld     $10, %xmm9
        pslld     $19, %xmm13
        por       %xmm9, %xmm8
        movdqa    %xmm4, %xmm9
        psrld     $2, %xmm9
        por       %xmm13, %xmm15
        por       %xmm14, %xmm9
        movdqa    %xmm7, %xmm13
        movdqa    %xmm4, %xmm14
        pxor      %xmm1, %xmm13
        pxor      %xmm1, %xmm14
        pxor      %xmm15, %xmm9
        pand      %xmm14, %xmm13
        pxor      %xmm9, %xmm8
        movdqa    320(%rsp), %xmm14
        pxor      %xmm1, %xmm13
        paddd     %xmm13, %xmm8
        movdqa    %xmm14, %xmm9
        movdqa    %xmm14, %xmm15
        movdqa    %xmm14, %xmm13
        paddd     %xmm2, %xmm5
        paddd     %xmm8, %xmm2
        movdqa    %xmm14, %xmm8
        psrld     $7, %xmm9
        pslld     $25, %xmm15
        psrld     $18, %xmm13
        pslld     $14, %xmm14
        por       %xmm15, %xmm9
        por       %xmm14, %xmm13
        psrld     $3, %xmm8
        pxor      %xmm13, %xmm9
        movdqa    %xmm11, %xmm15
        pxor      %xmm9, %xmm8
        movdqa    %xmm11, %xmm9
        psrld     $17, %xmm9
        pslld     $15, %xmm15
        por       %xmm15, %xmm9
        movdqa    %xmm11, %xmm15
        movdqa    %xmm11, %xmm14
        psrld     $19, %xmm15
        pslld     $13, %xmm14
        movdqa    %xmm11, %xmm13
        por       %xmm14, %xmm15
        psrld     $10, %xmm13
        pxor      %xmm15, %xmm9
        movdqa    %xmm5, %xmm14
        pxor      %xmm9, %xmm13
        movdqa    %xmm5, %xmm15
        movdqa    576(%rsp), %xmm9
        psrld     $25, %xmm14
        paddd     %xmm9, %xmm13
        psrld     $6, %xmm15
        paddd     %xmm13, %xmm10
        movdqa    %xmm5, %xmm13
        paddd     %xmm10, %xmm8
        movdqa    %xmm5, %xmm10
        pslld     $7, %xmm10
        pslld     $26, %xmm13
        por       %xmm10, %xmm14
        por       %xmm13, %xmm15
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm10
        psrld     $11, %xmm13
        pslld     $21, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm2, %xmm10
        pxor      %xmm13, %xmm15
        movdqa    %xmm2, %xmm13
        pxor      %xmm15, %xmm14
        movdqa    %xmm3, %xmm15
        paddd     %xmm14, %xmm6
        movdqa    %xmm2, %xmm14
        pxor      %xmm0, %xmm15
        psrld     $22, %xmm14
        pslld     $10, %xmm13
        pand      %xmm5, %xmm15
        por       %xmm13, %xmm14
        movdqa    %xmm2, %xmm13
        pxor      %xmm0, %xmm15
        psrld     $2, %xmm13
        pslld     $30, %xmm10
        paddd     %xmm15, %xmm6
        por       %xmm10, %xmm13
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm15
        psrld     $13, %xmm10
        pslld     $19, %xmm15
        por       %xmm15, %xmm10
        pxor      %xmm10, %xmm13
        movdqa    %xmm1, %xmm10
        pxor      %xmm13, %xmm14
        movdqa    %xmm2, %xmm13
        pxor      %xmm4, %xmm10
        pxor      %xmm4, %xmm13
        pand      %xmm13, %xmm10
        paddd     .L_2il0floatpacket.627(%rip), %xmm6
        pxor      %xmm4, %xmm10
        paddd     %xmm8, %xmm6
        paddd     %xmm10, %xmm14
        movdqa    560(%rsp), %xmm13
        paddd     %xmm6, %xmm7
        movdqa    336(%rsp), %xmm10
        paddd     %xmm14, %xmm6
        je        ..B6.23
..B6.22:
        movdqa    %xmm11, 208(%rsp)
        movdqa    544(%rsp), %xmm11
        movdqa    %xmm11, 192(%rsp)
        movdqa    %xmm9, 128(%rsp)
        movdqa    %xmm12, 96(%rsp)
        movdqa    256(%rsp), %xmm11
        movdqa    496(%rsp), %xmm9
        movdqa    512(%rsp), %xmm12
        movdqa    %xmm11, 144(%rsp)
        movdqa    %xmm13, 112(%rsp)
        movdqa    %xmm9, 80(%rsp)
        movdqa    %xmm12, 64(%rsp)
        movdqa    528(%rsp), %xmm14
        movdqa    272(%rsp), %xmm15
        movdqa    480(%rsp), %xmm13
        movdqa    304(%rsp), %xmm9
        movdqa    288(%rsp), %xmm11
        movdqa    320(%rsp), %xmm12
        movdqa    %xmm14, 176(%rsp)
        movdqa    %xmm15, 160(%rsp)
        movdqa    %xmm13, 48(%rsp)
        movdqa    %xmm9, 32(%rsp)
        movdqa    %xmm11, 16(%rsp)
        movdqa    %xmm12, (%rsp)
        movdqa    %xmm8, 240(%rsp)
        movdqa    %xmm10, 224(%rsp)
        paddd     (%r13), %xmm6
        paddd     16(%r13), %xmm2
        paddd     32(%r13), %xmm4
        paddd     48(%r13), %xmm1
        paddd     64(%r13), %xmm7
        paddd     80(%r13), %xmm5
        paddd     96(%r13), %xmm3
        paddd     112(%r13), %xmm0
        jmp       ..B6.27
..B6.23:
        testl     $32, %r12d
        jne       ..B6.27
..B6.24:
        testl     $4096, %r12d
        je        ..B6.26
..B6.25:
        paddd     .L_2il0floatpacket.644(%rip), %xmm6
        paddd     .L_2il0floatpacket.645(%rip), %xmm2
        paddd     .L_2il0floatpacket.646(%rip), %xmm4
        paddd     .L_2il0floatpacket.647(%rip), %xmm1
        paddd     .L_2il0floatpacket.648(%rip), %xmm7
        paddd     .L_2il0floatpacket.649(%rip), %xmm5
        paddd     .L_2il0floatpacket.650(%rip), %xmm3
        paddd     .L_2il0floatpacket.651(%rip), %xmm0
        jmp       ..B6.27
..B6.26:
        paddd     .L_2il0floatpacket.652(%rip), %xmm6
        paddd     .L_2il0floatpacket.653(%rip), %xmm2
        paddd     .L_2il0floatpacket.654(%rip), %xmm4
        paddd     .L_2il0floatpacket.655(%rip), %xmm1
        paddd     .L_2il0floatpacket.656(%rip), %xmm7
        paddd     .L_2il0floatpacket.657(%rip), %xmm5
        paddd     .L_2il0floatpacket.658(%rip), %xmm3
        paddd     .L_2il0floatpacket.659(%rip), %xmm0
..B6.27:
        testl     $16, %r12d
        je        ..B6.29
..B6.28:
        pshufhw   $177, %xmm6, %xmm6
        pshufhw   $177, %xmm2, %xmm2
        pshufhw   $177, %xmm4, %xmm4
        pshufhw   $177, %xmm1, %xmm1
        pshufhw   $177, %xmm7, %xmm7
        pshufhw   $177, %xmm5, %xmm5
        pshufhw   $177, %xmm3, %xmm3
        pshufhw   $177, %xmm0, %xmm0
        pshuflw   $177, %xmm6, %xmm8
        pshuflw   $177, %xmm2, %xmm9
        movdqa    %xmm8, %xmm6
        pshuflw   $177, %xmm4, %xmm10
        movdqa    %xmm9, %xmm2
        pshuflw   $177, %xmm1, %xmm11
        movdqa    %xmm10, %xmm4
        pshuflw   $177, %xmm7, %xmm12
        movdqa    %xmm11, %xmm1
        pshuflw   $177, %xmm5, %xmm13
        movdqa    %xmm12, %xmm7
        pshuflw   $177, %xmm3, %xmm14
        movdqa    %xmm13, %xmm5
        pshuflw   $177, %xmm0, %xmm15
        movdqa    %xmm14, %xmm3
        movdqa    %xmm15, %xmm0
        psrlw     $8, %xmm6
        psllw     $8, %xmm8
        psrlw     $8, %xmm2
        psllw     $8, %xmm9
        psrlw     $8, %xmm4
        psllw     $8, %xmm10
        psrlw     $8, %xmm1
        psllw     $8, %xmm11
        psrlw     $8, %xmm7
        psllw     $8, %xmm12
        psrlw     $8, %xmm5
        psllw     $8, %xmm13
        psrlw     $8, %xmm3
        psllw     $8, %xmm14
        psrlw     $8, %xmm0
        psllw     $8, %xmm15
        pxor      %xmm8, %xmm6
        pxor      %xmm9, %xmm2
        pxor      %xmm10, %xmm4
        pxor      %xmm11, %xmm1
        pxor      %xmm12, %xmm7
        pxor      %xmm13, %xmm5
        pxor      %xmm14, %xmm3
        pxor      %xmm15, %xmm0
..B6.29:
        movdqa    %xmm6, (%rbp)
        movdqa    %xmm2, 16(%rbp)
        movdqa    %xmm4, 32(%rbp)
        movdqa    %xmm1, 48(%rbp)
        movdqa    %xmm7, 64(%rbp)
        movdqa    %xmm5, 80(%rbp)
        movdqa    %xmm3, 96(%rbp)
        movdqa    %xmm0, 112(%rbp)
        addq      $624, %rsp
..___tag_value_SIMDSHA256body.120:
        popq      %rbp
..___tag_value_SIMDSHA256body.122:
        popq      %r13
..___tag_value_SIMDSHA256body.124:
        popq      %r12
..___tag_value_SIMDSHA256body.126:
        ret       
        .align    16,0x90
..___tag_value_SIMDSHA256body.127:
	.type	SIMDSHA256body,@function
	.size	SIMDSHA256body,.-SIMDSHA256body
	.data
# -- End  SIMDSHA256body
	.text
# -- Begin  SIMDSHA512body
       .align    16,0x90
	.globl SIMDSHA512body
SIMDSHA512body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B7.1:
..___tag_value_SIMDSHA512body.128:
        pushq     %r12
..___tag_value_SIMDSHA512body.130:
        pushq     %rbx
..___tag_value_SIMDSHA512body.132:
        pushq     %rbp
..___tag_value_SIMDSHA512body.134:
        subq      $1280, %rsp
..___tag_value_SIMDSHA512body.136:
        movl      %ecx, %r12d
        movq      %rdx, %rbx
        movq      %rsi, %rbp
        movq      %rdi, %rsi
        testl     $1, %r12d
        je        ..B7.13
..B7.2:
        xorl      %edx, %edx
        xorl      %eax, %eax
        testl     $64, %r12d
        jne       ..B7.7
..B7.4:
        movq      (%rsi,%rdx,8), %xmm0
        movq      8(%rsi,%rdx,8), %xmm4
        movhpd    128(%rsi,%rdx,8), %xmm0
        movhpd    136(%rsi,%rdx,8), %xmm4
        addq      $2, %rdx
        pshuflw   $177, %xmm0, %xmm1
        pshuflw   $177, %xmm4, %xmm5
        pshufhw   $177, %xmm1, %xmm2
        pshufhw   $177, %xmm5, %xmm6
        movdqa    %xmm2, %xmm3
        movdqa    %xmm6, %xmm7
        psllw     $8, %xmm3
        psrlw     $8, %xmm2
        psllw     $8, %xmm7
        psrlw     $8, %xmm6
        pxor      %xmm2, %xmm3
        pxor      %xmm6, %xmm7
        pshufd    $177, %xmm3, %xmm8
        pshufd    $177, %xmm7, %xmm9
        movdqa    %xmm8, (%rsp,%rax)
        movdqa    %xmm9, 16(%rsp,%rax)
        addq      $32, %rax
        cmpq      $14, %rdx
        jl        ..B7.4
..B7.5:
        movq      112(%rsi), %xmm0
        movq      120(%rsi), %xmm3
        movhpd    240(%rsi), %xmm0
        movhpd    248(%rsi), %xmm3
        jmp       ..B7.9
..B7.7:
        movq      (%rsi,%rdx,8), %xmm0
        movq      8(%rsi,%rdx,8), %xmm4
        movhpd    256(%rsi,%rdx,8), %xmm0
        movhpd    264(%rsi,%rdx,8), %xmm4
        addq      $2, %rdx
        pshuflw   $177, %xmm0, %xmm1
        pshuflw   $177, %xmm4, %xmm5
        pshufhw   $177, %xmm1, %xmm2
        pshufhw   $177, %xmm5, %xmm6
        movdqa    %xmm2, %xmm3
        movdqa    %xmm6, %xmm7
        psllw     $8, %xmm3
        psrlw     $8, %xmm2
        psllw     $8, %xmm7
        psrlw     $8, %xmm6
        pxor      %xmm2, %xmm3
        pxor      %xmm6, %xmm7
        pshufd    $177, %xmm3, %xmm8
        pshufd    $177, %xmm7, %xmm9
        movdqa    %xmm8, (%rsp,%rax)
        movdqa    %xmm9, 16(%rsp,%rax)
        addq      $32, %rax
        cmpq      $14, %rdx
        jl        ..B7.7
..B7.8:
        movq      112(%rsi), %xmm0
        movq      120(%rsi), %xmm3
        movhpd    368(%rsi), %xmm0
        movhpd    376(%rsi), %xmm3
..B7.9:
        movl      %r12d, %eax
        andl      $192, %eax
        cmpl      $192, %eax
        je        ..B7.11
..B7.10:
        testl     $1024, %r12d
        je        ..B7.12
..B7.11:
        pshuflw   $177, %xmm0, %xmm0
        pshuflw   $177, %xmm3, %xmm3
        pshufhw   $177, %xmm0, %xmm1
        pshufhw   $177, %xmm3, %xmm4
        movdqa    %xmm1, %xmm2
        movdqa    %xmm4, %xmm5
        psllw     $8, %xmm2
        psrlw     $8, %xmm1
        psllw     $8, %xmm5
        psrlw     $8, %xmm4
        pxor      %xmm1, %xmm2
        pxor      %xmm4, %xmm5
        pshufd    $177, %xmm2, %xmm0
        pshufd    $177, %xmm5, %xmm3
..B7.12:
        movdqa    %xmm0, 224(%rsp)
        movdqa    %xmm3, 240(%rsp)
        jmp       ..B7.14
..B7.13:
        movl      $256, %edx
        lea       (%rsp), %rdi
..___tag_value_SIMDSHA512body.137:
        call      memcpy
..___tag_value_SIMDSHA512body.138:
..B7.14:
        movb      $16, %dl
        movl      $256, %eax
..B7.15:
        movdqa    -32(%rsp,%rax), %xmm1
        incb      %dl
        movdqa    -240(%rsp,%rax), %xmm5
        movdqa    %xmm1, %xmm3
        movdqa    %xmm1, %xmm0
        movdqa    %xmm1, %xmm2
        movdqa    %xmm5, %xmm7
        movdqa    %xmm5, %xmm4
        movdqa    %xmm5, %xmm6
        movdqa    %xmm1, %xmm9
        psrlq     $19, %xmm3
        psllq     $45, %xmm0
        psrlq     $61, %xmm2
        psllq     $3, %xmm1
        movdqa    %xmm5, %xmm8
        psrlq     $1, %xmm7
        psllq     $63, %xmm4
        psrlq     $8, %xmm6
        psllq     $56, %xmm5
        por       %xmm0, %xmm3
        por       %xmm1, %xmm2
        por       %xmm4, %xmm7
        por       %xmm5, %xmm6
        psrlq     $6, %xmm9
        pxor      %xmm2, %xmm3
        psrlq     $7, %xmm8
        pxor      %xmm6, %xmm7
        pxor      %xmm3, %xmm9
        pxor      %xmm7, %xmm8
        paddq     -256(%rsp,%rax), %xmm8
        paddq     -112(%rsp,%rax), %xmm9
        paddq     %xmm8, %xmm9
        movdqa    %xmm9, (%rsp,%rax)
        addq      $16, %rax
        cmpb      $80, %dl
        jl        ..B7.15
..B7.16:
        movl      %r12d, %eax
        andl      $2, %eax
        je        ..B7.18
..B7.17:
        movdqa    (%rbx), %xmm4
        movdqa    16(%rbx), %xmm5
        movdqa    32(%rbx), %xmm7
        movdqa    48(%rbx), %xmm3
        movdqa    64(%rbx), %xmm6
        movdqa    80(%rbx), %xmm2
        movdqa    96(%rbx), %xmm1
        movdqa    112(%rbx), %xmm0
        jmp       ..B7.21
..B7.18:
        testl     $4096, %r12d
        je        ..B7.20
..B7.19:
        movdqa    .L_2il0floatpacket.744(%rip), %xmm4
        movdqa    .L_2il0floatpacket.745(%rip), %xmm5
        movdqa    .L_2il0floatpacket.746(%rip), %xmm7
        movdqa    .L_2il0floatpacket.747(%rip), %xmm3
        movdqa    .L_2il0floatpacket.748(%rip), %xmm6
        movdqa    .L_2il0floatpacket.749(%rip), %xmm2
        movdqa    .L_2il0floatpacket.750(%rip), %xmm1
        movdqa    .L_2il0floatpacket.751(%rip), %xmm0
        jmp       ..B7.21
..B7.20:
        movdqa    .L_2il0floatpacket.752(%rip), %xmm4
        movdqa    .L_2il0floatpacket.753(%rip), %xmm5
        movdqa    .L_2il0floatpacket.754(%rip), %xmm7
        movdqa    .L_2il0floatpacket.755(%rip), %xmm3
        movdqa    .L_2il0floatpacket.756(%rip), %xmm6
        movdqa    .L_2il0floatpacket.757(%rip), %xmm2
        movdqa    .L_2il0floatpacket.758(%rip), %xmm1
        movdqa    .L_2il0floatpacket.759(%rip), %xmm0
..B7.21:
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        movdqa    %xmm2, %xmm8
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm1, %xmm8
        psrlq     $41, %xmm14
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pand      %xmm6, %xmm8
        por       %xmm9, %xmm14
        pxor      %xmm12, %xmm13
        pxor      %xmm1, %xmm8
        paddq     (%rsp), %xmm0
        pxor      %xmm13, %xmm14
        movdqa    %xmm4, %xmm11
        paddq     %xmm8, %xmm0
        paddq     .L_2il0floatpacket.664(%rip), %xmm14
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm15
        paddq     %xmm14, %xmm0
        movdqa    %xmm4, %xmm14
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm7, %xmm13
        movdqa    %xmm4, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm5, %xmm13
        pxor      %xmm5, %xmm12
        movdqa    %xmm6, %xmm8
        paddq     %xmm0, %xmm3
        por       %xmm15, %xmm14
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm2, %xmm8
        movdqa    16(%rsp), %xmm15
        pxor      %xmm11, %xmm14
        pxor      %xmm5, %xmm13
        pand      %xmm3, %xmm8
        paddq     %xmm15, %xmm1
        paddq     %xmm13, %xmm14
        pxor      %xmm2, %xmm8
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm9
        paddq     %xmm8, %xmm1
        paddq     %xmm14, %xmm0
        movdqa    %xmm3, %xmm8
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        movdqa    %xmm0, %xmm9
        pxor      %xmm13, %xmm8
        psllq     $25, %xmm9
        paddq     .L_2il0floatpacket.665(%rip), %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm14
        psrlq     $39, %xmm8
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm5, %xmm9
        movdqa    %xmm4, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm4, %xmm9
        pxor      %xmm0, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm4, %xmm9
        movdqa    %xmm6, %xmm11
        paddq     %xmm1, %xmm7
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm7, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm7, %xmm13
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm3, %xmm11
        por       %xmm14, %xmm13
        movdqa    32(%rsp), %xmm10
        pand      %xmm7, %xmm11
        pxor      %xmm13, %xmm12
        pxor      %xmm6, %xmm11
        paddq     %xmm10, %xmm2
        pxor      %xmm12, %xmm8
        movdqa    %xmm1, %xmm9
        paddq     %xmm11, %xmm2
        paddq     .L_2il0floatpacket.666(%rip), %xmm8
        paddq     %xmm8, %xmm2
        movdqa    %xmm1, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm1, %xmm10
        por       %xmm9, %xmm8
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm4, %xmm11
        movdqa    %xmm1, %xmm10
        pxor      %xmm0, %xmm11
        pxor      %xmm0, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm0, %xmm11
        paddq     %xmm2, %xmm5
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm2
        movdqa    48(%rsp), %xmm12
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm9
        movdqa    %xmm7, %xmm13
        paddq     %xmm12, %xmm6
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm14
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm3, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm5, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm3, %xmm13
        pxor      %xmm11, %xmm12
        paddq     %xmm13, %xmm6
        paddq     .L_2il0floatpacket.667(%rip), %xmm12
        paddq     %xmm12, %xmm6
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm0, %xmm11
        movdqa    %xmm2, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm1, %xmm11
        pxor      %xmm1, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm1, %xmm11
        movdqa    %xmm5, %xmm8
        paddq     %xmm6, %xmm4
        paddq     %xmm11, %xmm12
        paddq     %xmm12, %xmm6
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm7, %xmm8
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pand      %xmm4, %xmm8
        movdqa    64(%rsp), %xmm14
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm13
        pxor      %xmm7, %xmm8
        paddq     %xmm14, %xmm3
        pxor      %xmm13, %xmm15
        movdqa    %xmm6, %xmm12
        paddq     %xmm8, %xmm3
        paddq     .L_2il0floatpacket.668(%rip), %xmm15
        paddq     %xmm15, %xmm3
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm8
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm10
        por       %xmm8, %xmm15
        paddq     %xmm3, %xmm0
        movdqa    80(%rsp), %xmm8
        psrlq     $28, %xmm12
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        por       %xmm9, %xmm12
        paddq     %xmm8, %xmm7
        por       %xmm10, %xmm11
        movdqa    %xmm1, %xmm14
        movdqa    %xmm6, %xmm13
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm2, %xmm14
        pxor      %xmm2, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm12
        movdqa    %xmm4, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm5, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm2, %xmm14
        pand      %xmm0, %xmm9
        pxor      %xmm13, %xmm10
        paddq     %xmm14, %xmm15
        pxor      %xmm5, %xmm9
        pxor      %xmm10, %xmm8
        paddq     %xmm15, %xmm3
        paddq     %xmm9, %xmm7
        paddq     .L_2il0floatpacket.669(%rip), %xmm8
        paddq     %xmm8, %xmm7
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm2, %xmm11
        movdqa    %xmm3, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm6, %xmm11
        pxor      %xmm6, %xmm9
        pxor      %xmm14, %xmm15
        paddq     %xmm7, %xmm1
        pand      %xmm9, %xmm11
        pxor      %xmm15, %xmm8
        movdqa    96(%rsp), %xmm10
        pxor      %xmm6, %xmm11
        paddq     %xmm10, %xmm5
        paddq     %xmm11, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm13
        psrlq     $41, %xmm10
        psllq     $23, %xmm13
        paddq     %xmm8, %xmm7
        por       %xmm13, %xmm10
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm13
        movdqa    %xmm0, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm4, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm1, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm4, %xmm12
        pxor      %xmm9, %xmm10
        movdqa    %xmm7, %xmm11
        paddq     %xmm12, %xmm5
        paddq     .L_2il0floatpacket.670(%rip), %xmm10
        paddq     %xmm10, %xmm5
        movdqa    %xmm7, %xmm10
        psllq     $25, %xmm11
        psrlq     $39, %xmm10
        movdqa    %xmm7, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm7, %xmm11
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm15
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm6, %xmm9
        movdqa    %xmm7, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm3, %xmm9
        pxor      %xmm3, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm3, %xmm9
        paddq     %xmm5, %xmm2
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm5
        movdqa    112(%rsp), %xmm13
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm10
        movdqa    %xmm1, %xmm14
        paddq     %xmm13, %xmm4
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm0, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm2, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm0, %xmm14
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm4
        paddq     .L_2il0floatpacket.671(%rip), %xmm13
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm9
        paddq     %xmm13, %xmm4
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm3, %xmm13
        movdqa    %xmm5, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm7, %xmm13
        pxor      %xmm7, %xmm12
        movdqa    %xmm2, %xmm8
        por       %xmm15, %xmm14
        paddq     %xmm4, %xmm6
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm1, %xmm8
        pxor      %xmm11, %xmm14
        movdqa    128(%rsp), %xmm15
        pxor      %xmm7, %xmm13
        pand      %xmm6, %xmm8
        movdqa    %xmm6, %xmm10
        paddq     %xmm15, %xmm0
        paddq     %xmm13, %xmm14
        pxor      %xmm1, %xmm8
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        paddq     %xmm8, %xmm0
        paddq     %xmm14, %xmm4
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm13, %xmm8
        movdqa    %xmm4, %xmm9
        paddq     .L_2il0floatpacket.672(%rip), %xmm8
        paddq     %xmm8, %xmm0
        movdqa    %xmm4, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm7, %xmm9
        movdqa    %xmm4, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm5, %xmm9
        pxor      %xmm5, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm5, %xmm9
        paddq     %xmm0, %xmm3
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm0
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm3, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm3, %xmm13
        movdqa    %xmm6, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm2, %xmm11
        por       %xmm14, %xmm13
        pand      %xmm3, %xmm11
        movdqa    144(%rsp), %xmm10
        pxor      %xmm13, %xmm12
        paddq     %xmm10, %xmm1
        pxor      %xmm2, %xmm11
        pxor      %xmm12, %xmm8
        paddq     %xmm11, %xmm1
        paddq     .L_2il0floatpacket.673(%rip), %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm5, %xmm11
        movdqa    %xmm0, %xmm10
        pxor      %xmm4, %xmm11
        pxor      %xmm4, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        movdqa    %xmm3, %xmm13
        paddq     %xmm1, %xmm7
        pxor      %xmm9, %xmm8
        pxor      %xmm4, %xmm11
        pxor      %xmm6, %xmm13
        movdqa    %xmm7, %xmm14
        paddq     %xmm11, %xmm8
        movdqa    160(%rsp), %xmm12
        pand      %xmm7, %xmm13
        movdqa    %xmm7, %xmm11
        pxor      %xmm6, %xmm13
        paddq     %xmm12, %xmm2
        paddq     %xmm8, %xmm1
        paddq     %xmm13, %xmm2
        psrlq     $41, %xmm11
        psllq     $23, %xmm14
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm8
        por       %xmm14, %xmm11
        psrlq     $14, %xmm10
        psllq     $50, %xmm8
..B7.40:
        por       %xmm8, %xmm10
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm8
        psrlq     $18, %xmm9
        psllq     $46, %xmm8
        movdqa    %xmm1, %xmm14
        por       %xmm8, %xmm9
        movdqa    %xmm1, %xmm8
        pxor      %xmm9, %xmm10
        psrlq     $39, %xmm8
        pxor      %xmm10, %xmm11
        movdqa    %xmm1, %xmm10
        paddq     .L_2il0floatpacket.674(%rip), %xmm11
        paddq     %xmm11, %xmm2
        psllq     $25, %xmm10
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm12
        por       %xmm10, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm11
        psrlq     $34, %xmm13
        psllq     $30, %xmm12
        movdqa    %xmm4, %xmm10
        movdqa    %xmm1, %xmm15
        por       %xmm11, %xmm14
        por       %xmm12, %xmm13
        pxor      %xmm0, %xmm10
        pxor      %xmm0, %xmm15
        pxor      %xmm13, %xmm14
        pand      %xmm15, %xmm10
        pxor      %xmm14, %xmm8
        pxor      %xmm0, %xmm10
        movdqa    %xmm7, %xmm11
        paddq     %xmm2, %xmm5
        paddq     %xmm10, %xmm8
        paddq     %xmm8, %xmm2
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm5, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm5, %xmm13
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm3, %xmm11
        por       %xmm14, %xmm13
        movdqa    176(%rsp), %xmm9
        pand      %xmm5, %xmm11
        pxor      %xmm13, %xmm12
        pxor      %xmm3, %xmm11
        paddq     %xmm9, %xmm6
        pxor      %xmm12, %xmm8
        movdqa    %xmm2, %xmm9
        paddq     %xmm11, %xmm6
        paddq     .L_2il0floatpacket.675(%rip), %xmm8
        paddq     %xmm8, %xmm6
        movdqa    %xmm2, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm2, %xmm10
        por       %xmm9, %xmm8
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm0, %xmm11
        movdqa    %xmm1, %xmm10
        pxor      %xmm1, %xmm11
        pxor      %xmm2, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm1, %xmm11
        paddq     %xmm6, %xmm4
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm6
        movdqa    192(%rsp), %xmm12
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm9
        movdqa    %xmm7, %xmm13
        paddq     %xmm12, %xmm3
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm14
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm5, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm4, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm7, %xmm13
        pxor      %xmm11, %xmm12
        paddq     %xmm13, %xmm3
        paddq     .L_2il0floatpacket.676(%rip), %xmm12
        paddq     %xmm12, %xmm3
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm1, %xmm11
        movdqa    %xmm6, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm2, %xmm11
        pxor      %xmm2, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm2, %xmm11
        movdqa    %xmm4, %xmm8
        paddq     %xmm3, %xmm0
        paddq     %xmm11, %xmm12
        paddq     %xmm12, %xmm3
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm5, %xmm8
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pand      %xmm0, %xmm8
        movdqa    208(%rsp), %xmm14
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm13
        pxor      %xmm5, %xmm8
        paddq     %xmm14, %xmm7
        pxor      %xmm13, %xmm15
        movdqa    %xmm3, %xmm12
        paddq     %xmm8, %xmm7
        paddq     .L_2il0floatpacket.677(%rip), %xmm15
        paddq     %xmm15, %xmm7
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm8
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm10
        por       %xmm8, %xmm15
        paddq     %xmm7, %xmm1
        movdqa    224(%rsp), %xmm8
        psrlq     $28, %xmm12
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        por       %xmm9, %xmm12
        paddq     %xmm8, %xmm5
        por       %xmm10, %xmm11
        movdqa    %xmm2, %xmm14
        movdqa    %xmm3, %xmm13
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm6, %xmm14
        pxor      %xmm6, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm12
        movdqa    %xmm0, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm4, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm6, %xmm14
        pand      %xmm1, %xmm9
        pxor      %xmm13, %xmm10
        paddq     %xmm14, %xmm15
        pxor      %xmm4, %xmm9
        pxor      %xmm10, %xmm8
        paddq     %xmm15, %xmm7
        paddq     %xmm9, %xmm5
        paddq     .L_2il0floatpacket.678(%rip), %xmm8
        paddq     %xmm8, %xmm5
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm6, %xmm11
        movdqa    %xmm7, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm3, %xmm11
        pxor      %xmm3, %xmm9
        pxor      %xmm14, %xmm15
        paddq     %xmm5, %xmm2
        pand      %xmm9, %xmm11
        pxor      %xmm15, %xmm8
        movdqa    240(%rsp), %xmm10
        pxor      %xmm3, %xmm11
        paddq     %xmm10, %xmm4
        paddq     %xmm11, %xmm8
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm13
        psrlq     $41, %xmm10
        psllq     $23, %xmm13
        paddq     %xmm8, %xmm5
        por       %xmm13, %xmm10
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm13
        movdqa    %xmm1, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm0, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm2, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm0, %xmm12
        pxor      %xmm9, %xmm10
        movdqa    %xmm5, %xmm11
        paddq     %xmm12, %xmm4
        paddq     .L_2il0floatpacket.679(%rip), %xmm10
        paddq     %xmm10, %xmm4
        movdqa    %xmm5, %xmm10
        psllq     $25, %xmm11
        psrlq     $39, %xmm10
        movdqa    %xmm5, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm5, %xmm11
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm15
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm3, %xmm9
        movdqa    %xmm5, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm7, %xmm9
        pxor      %xmm7, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm7, %xmm9
        paddq     %xmm4, %xmm6
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm4
        movdqa    256(%rsp), %xmm13
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm10
        movdqa    %xmm2, %xmm14
        paddq     %xmm13, %xmm0
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm1, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm6, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm1, %xmm14
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm0
        paddq     .L_2il0floatpacket.680(%rip), %xmm13
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm9
        paddq     %xmm13, %xmm0
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm7, %xmm13
        movdqa    %xmm4, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm5, %xmm13
        pxor      %xmm5, %xmm12
        movdqa    %xmm6, %xmm8
        por       %xmm15, %xmm14
        paddq     %xmm0, %xmm3
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm2, %xmm8
        pxor      %xmm11, %xmm14
        movdqa    272(%rsp), %xmm15
        pxor      %xmm5, %xmm13
        pand      %xmm3, %xmm8
        movdqa    %xmm3, %xmm10
        paddq     %xmm15, %xmm1
        paddq     %xmm13, %xmm14
        pxor      %xmm2, %xmm8
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm11
        paddq     %xmm8, %xmm1
        paddq     %xmm14, %xmm0
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm13, %xmm8
        movdqa    %xmm0, %xmm9
        paddq     .L_2il0floatpacket.681(%rip), %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm0, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm5, %xmm9
        movdqa    %xmm0, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm4, %xmm9
        pxor      %xmm4, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm4, %xmm9
        paddq     %xmm1, %xmm7
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm7, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm7, %xmm13
        movdqa    %xmm3, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm6, %xmm11
        por       %xmm14, %xmm13
        pand      %xmm7, %xmm11
        movdqa    288(%rsp), %xmm10
        pxor      %xmm13, %xmm12
        paddq     %xmm10, %xmm2
        pxor      %xmm6, %xmm11
        pxor      %xmm12, %xmm8
        paddq     %xmm11, %xmm2
        paddq     .L_2il0floatpacket.682(%rip), %xmm8
        paddq     %xmm8, %xmm2
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm4, %xmm11
        movdqa    %xmm1, %xmm10
        pxor      %xmm0, %xmm11
        pxor      %xmm0, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm0, %xmm11
        movdqa    %xmm7, %xmm13
        paddq     %xmm2, %xmm5
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm2
        movdqa    304(%rsp), %xmm12
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm9
        movdqa    %xmm5, %xmm14
        paddq     %xmm12, %xmm6
        movdqa    %xmm5, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm3, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm5, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm3, %xmm13
        pxor      %xmm11, %xmm12
        movdqa    %xmm2, %xmm9
        paddq     %xmm13, %xmm6
        paddq     .L_2il0floatpacket.683(%rip), %xmm12
        paddq     %xmm12, %xmm6
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm0, %xmm11
        movdqa    %xmm2, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm1, %xmm11
        pxor      %xmm1, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm1, %xmm11
        paddq     %xmm6, %xmm4
        paddq     %xmm11, %xmm12
        movdqa    %xmm5, %xmm8
        movdqa    %xmm4, %xmm13
        paddq     %xmm12, %xmm6
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm11
        pxor      %xmm7, %xmm8
        movdqa    320(%rsp), %xmm14
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pand      %xmm4, %xmm8
        paddq     %xmm14, %xmm3
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pxor      %xmm7, %xmm8
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm13
        movdqa    %xmm6, %xmm12
        paddq     %xmm8, %xmm3
        movdqa    %xmm6, %xmm8
        pxor      %xmm13, %xmm15
        psrlq     $39, %xmm12
        psllq     $25, %xmm8
        paddq     .L_2il0floatpacket.684(%rip), %xmm15
        por       %xmm8, %xmm12
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm10
        psrlq     $28, %xmm8
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        por       %xmm9, %xmm8
        paddq     %xmm15, %xmm3
        por       %xmm10, %xmm11
        paddq     %xmm3, %xmm0
        pxor      %xmm11, %xmm8
..B7.39:
        pxor      %xmm8, %xmm12
        movdqa    %xmm1, %xmm9
        movdqa    %xmm6, %xmm8
        pxor      %xmm2, %xmm9
        pxor      %xmm2, %xmm8
        movdqa    %xmm0, %xmm13
        pand      %xmm8, %xmm9
        movdqa    %xmm0, %xmm8
        pxor      %xmm2, %xmm9
        psrlq     $41, %xmm8
        paddq     %xmm9, %xmm12
        paddq     %xmm12, %xmm3
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm15
        psllq     $23, %xmm12
        movdqa    %xmm0, %xmm14
        por       %xmm12, %xmm8
        movdqa    %xmm0, %xmm12
        movdqa    %xmm4, %xmm11
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        psrlq     $18, %xmm15
        psllq     $46, %xmm14
        pxor      %xmm5, %xmm11
        por       %xmm13, %xmm12
        por       %xmm14, %xmm15
        movdqa    336(%rsp), %xmm10
        pand      %xmm0, %xmm11
        pxor      %xmm15, %xmm12
        pxor      %xmm5, %xmm11
        paddq     %xmm10, %xmm7
        pxor      %xmm12, %xmm8
        movdqa    %xmm3, %xmm9
        paddq     %xmm11, %xmm7
        paddq     .L_2il0floatpacket.685(%rip), %xmm8
        paddq     %xmm8, %xmm7
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm10
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm11
        por       %xmm9, %xmm8
        por       %xmm10, %xmm14
        psrlq     $34, %xmm13
        psllq     $30, %xmm11
        movdqa    %xmm2, %xmm10
        movdqa    %xmm6, %xmm9
        por       %xmm11, %xmm13
        pxor      %xmm6, %xmm10
        pxor      %xmm3, %xmm9
        pxor      %xmm13, %xmm14
        pand      %xmm9, %xmm10
        paddq     %xmm7, %xmm1
        pxor      %xmm14, %xmm8
        pxor      %xmm6, %xmm10
        paddq     %xmm10, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm12
        psrlq     $41, %xmm10
        psllq     $23, %xmm12
        paddq     %xmm8, %xmm7
        por       %xmm12, %xmm10
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm12
        movdqa    %xmm0, %xmm11
        psrlq     $14, %xmm9
        psllq     $50, %xmm13
        psrlq     $18, %xmm8
        psllq     $46, %xmm12
        pxor      %xmm4, %xmm11
        por       %xmm13, %xmm9
        por       %xmm12, %xmm8
        pand      %xmm1, %xmm11
        movdqa    352(%rsp), %xmm15
        pxor      %xmm8, %xmm9
        paddq     %xmm15, %xmm5
        pxor      %xmm4, %xmm11
        pxor      %xmm9, %xmm10
        paddq     %xmm11, %xmm5
        paddq     .L_2il0floatpacket.686(%rip), %xmm10
        paddq     %xmm10, %xmm5
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm11
        psrlq     $39, %xmm10
        psllq     $25, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm14
        psrlq     $28, %xmm11
        psllq     $36, %xmm14
        movdqa    %xmm7, %xmm15
        por       %xmm14, %xmm11
        movdqa    %xmm7, %xmm14
        psrlq     $34, %xmm14
        psllq     $30, %xmm15
        movdqa    %xmm6, %xmm9
        movdqa    %xmm7, %xmm8
        por       %xmm15, %xmm14
        pxor      %xmm3, %xmm9
        pxor      %xmm3, %xmm8
        pxor      %xmm14, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm3, %xmm9
        movdqa    %xmm0, %xmm13
        paddq     %xmm5, %xmm2
        paddq     %xmm9, %xmm10
        movdqa    368(%rsp), %xmm12
        movdqa    %xmm2, %xmm9
        paddq     %xmm10, %xmm5
        paddq     %xmm12, %xmm4
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm1, %xmm13
        psrlq     $41, %xmm14
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm2, %xmm13
        por       %xmm8, %xmm14
        pxor      %xmm11, %xmm12
        pxor      %xmm0, %xmm13
        pxor      %xmm12, %xmm14
        movdqa    %xmm5, %xmm11
        paddq     %xmm13, %xmm4
        paddq     .L_2il0floatpacket.687(%rip), %xmm14
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm9
        movdqa    %xmm5, %xmm15
        paddq     %xmm14, %xmm4
        movdqa    %xmm5, %xmm14
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm3, %xmm13
        movdqa    %xmm5, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm7, %xmm13
        pxor      %xmm7, %xmm12
        movdqa    %xmm2, %xmm8
        paddq     %xmm4, %xmm6
        por       %xmm15, %xmm14
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm1, %xmm8
        movdqa    384(%rsp), %xmm15
        pxor      %xmm11, %xmm14
        pxor      %xmm7, %xmm13
        pand      %xmm6, %xmm8
        paddq     %xmm15, %xmm0
        paddq     %xmm13, %xmm14
        pxor      %xmm1, %xmm8
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm9
        paddq     %xmm8, %xmm0
        paddq     %xmm14, %xmm4
        movdqa    %xmm6, %xmm8
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        movdqa    %xmm4, %xmm9
        pxor      %xmm13, %xmm8
        psllq     $25, %xmm9
        paddq     .L_2il0floatpacket.688(%rip), %xmm8
        paddq     %xmm8, %xmm0
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm14
        psrlq     $39, %xmm8
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm7, %xmm9
        movdqa    %xmm4, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm5, %xmm9
        pxor      %xmm5, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm5, %xmm9
        movdqa    %xmm6, %xmm11
        paddq     %xmm0, %xmm3
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm0
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm3, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm3, %xmm13
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm2, %xmm11
        por       %xmm14, %xmm13
        movdqa    400(%rsp), %xmm10
        pand      %xmm3, %xmm11
        pxor      %xmm13, %xmm12
        pxor      %xmm2, %xmm11
        paddq     %xmm10, %xmm1
        pxor      %xmm12, %xmm8
        movdqa    %xmm0, %xmm9
        paddq     %xmm11, %xmm1
        paddq     .L_2il0floatpacket.689(%rip), %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm0, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm0, %xmm10
        por       %xmm9, %xmm8
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm5, %xmm11
        movdqa    %xmm0, %xmm10
        pxor      %xmm4, %xmm11
        pxor      %xmm4, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm4, %xmm11
        paddq     %xmm1, %xmm7
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm1
        movdqa    416(%rsp), %xmm12
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm9
        movdqa    %xmm3, %xmm13
        paddq     %xmm12, %xmm2
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm14
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm6, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm7, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm6, %xmm13
        pxor      %xmm11, %xmm12
        paddq     %xmm13, %xmm2
        paddq     .L_2il0floatpacket.690(%rip), %xmm12
        paddq     %xmm12, %xmm2
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm4, %xmm11
        movdqa    %xmm1, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm0, %xmm11
        pxor      %xmm0, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm0, %xmm11
        movdqa    %xmm7, %xmm8
        paddq     %xmm2, %xmm5
        paddq     %xmm11, %xmm12
        paddq     %xmm12, %xmm2
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm3, %xmm8
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pand      %xmm5, %xmm8
        movdqa    432(%rsp), %xmm14
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm13
        pxor      %xmm3, %xmm8
        paddq     %xmm14, %xmm6
        pxor      %xmm13, %xmm15
        movdqa    %xmm2, %xmm12
        paddq     %xmm8, %xmm6
        paddq     .L_2il0floatpacket.691(%rip), %xmm15
        paddq     %xmm15, %xmm6
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm8
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm10
        por       %xmm8, %xmm15
        paddq     %xmm6, %xmm4
        movdqa    448(%rsp), %xmm8
        psrlq     $28, %xmm12
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        por       %xmm9, %xmm12
        paddq     %xmm8, %xmm3
        por       %xmm10, %xmm11
        movdqa    %xmm0, %xmm14
        movdqa    %xmm2, %xmm13
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm1, %xmm14
        pxor      %xmm1, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm12
        movdqa    %xmm5, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm7, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm1, %xmm14
        pand      %xmm4, %xmm9
        pxor      %xmm13, %xmm10
        paddq     %xmm14, %xmm15
        pxor      %xmm7, %xmm9
        pxor      %xmm10, %xmm8
        paddq     %xmm15, %xmm6
        paddq     %xmm9, %xmm3
        paddq     .L_2il0floatpacket.692(%rip), %xmm8
        paddq     %xmm8, %xmm3
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm1, %xmm11
        movdqa    %xmm6, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm2, %xmm11
        pxor      %xmm2, %xmm9
        pxor      %xmm14, %xmm15
        paddq     %xmm3, %xmm0
        pand      %xmm9, %xmm11
        pxor      %xmm15, %xmm8
        movdqa    464(%rsp), %xmm10
        pxor      %xmm2, %xmm11
        paddq     %xmm10, %xmm7
        paddq     %xmm11, %xmm8
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm13
        psrlq     $41, %xmm10
        psllq     $23, %xmm13
        paddq     %xmm8, %xmm3
        por       %xmm13, %xmm10
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm13
        movdqa    %xmm4, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm5, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm0, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm5, %xmm12
        pxor      %xmm9, %xmm10
        movdqa    %xmm3, %xmm11
        paddq     %xmm12, %xmm7
        paddq     .L_2il0floatpacket.693(%rip), %xmm10
        paddq     %xmm10, %xmm7
        movdqa    %xmm3, %xmm10
        psllq     $25, %xmm11
        psrlq     $39, %xmm10
        movdqa    %xmm3, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm3, %xmm11
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm15
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm2, %xmm9
        movdqa    %xmm3, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm6, %xmm9
        pxor      %xmm6, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm6, %xmm9
        paddq     %xmm7, %xmm1
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm7
        movdqa    480(%rsp), %xmm13
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm10
        movdqa    %xmm0, %xmm14
        paddq     %xmm13, %xmm5
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm4, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm1, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm4, %xmm14
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm5
        paddq     .L_2il0floatpacket.694(%rip), %xmm13
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm9
        paddq     %xmm13, %xmm5
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm6, %xmm13
        movdqa    %xmm7, %xmm12
        paddq     %xmm5, %xmm2
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm3, %xmm13
        pxor      %xmm3, %xmm12
        movdqa    %xmm1, %xmm8
        por       %xmm15, %xmm14
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm0, %xmm8
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm9
        pxor      %xmm11, %xmm14
        movdqa    496(%rsp), %xmm15
        pxor      %xmm3, %xmm13
        pand      %xmm2, %xmm8
        psrlq     $41, %xmm12
        psllq     $23, %xmm9
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm10
        pxor      %xmm0, %xmm8
        paddq     %xmm13, %xmm14
        paddq     %xmm15, %xmm4
        paddq     %xmm14, %xmm5
        paddq     %xmm8, %xmm4
        por       %xmm9, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm10
        movdqa    %xmm2, %xmm9
        por       %xmm10, %xmm11
        psrlq     $18, %xmm9
..B7.38:
        movdqa    %xmm2, %xmm8
        movdqa    %xmm5, %xmm13
        psllq     $46, %xmm8
        movdqa    %xmm5, %xmm10
        por       %xmm8, %xmm9
        movdqa    %xmm5, %xmm8
        pxor      %xmm9, %xmm11
        movdqa    %xmm5, %xmm9
        pxor      %xmm11, %xmm12
        movdqa    %xmm5, %xmm11
        paddq     .L_2il0floatpacket.695(%rip), %xmm12
        paddq     %xmm12, %xmm4
        movdqa    %xmm5, %xmm12
        psrlq     $28, %xmm13
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm3, %xmm15
        movdqa    %xmm5, %xmm14
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pxor      %xmm7, %xmm15
        pxor      %xmm7, %xmm14
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pand      %xmm14, %xmm15
        pxor      %xmm13, %xmm8
        pxor      %xmm7, %xmm15
        paddq     %xmm4, %xmm6
        paddq     %xmm15, %xmm8
        paddq     %xmm8, %xmm4
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm11
        por       %xmm11, %xmm8
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm13
        movdqa    %xmm2, %xmm10
        psrlq     $14, %xmm11
        psllq     $50, %xmm12
        psrlq     $18, %xmm14
        psllq     $46, %xmm13
        pxor      %xmm1, %xmm10
        por       %xmm12, %xmm11
        por       %xmm13, %xmm14
        pand      %xmm6, %xmm10
        movdqa    512(%rsp), %xmm9
        pxor      %xmm14, %xmm11
        paddq     %xmm9, %xmm0
        pxor      %xmm1, %xmm10
        pxor      %xmm11, %xmm8
        paddq     %xmm10, %xmm0
        paddq     .L_2il0floatpacket.696(%rip), %xmm8
        paddq     %xmm8, %xmm0
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm10
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm10
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm12
        por       %xmm9, %xmm8
        por       %xmm10, %xmm15
        psrlq     $34, %xmm13
        psllq     $30, %xmm12
        movdqa    %xmm7, %xmm10
        movdqa    %xmm5, %xmm9
        por       %xmm12, %xmm13
        pxor      %xmm5, %xmm10
        pxor      %xmm4, %xmm9
        pxor      %xmm13, %xmm15
        pand      %xmm9, %xmm10
        pxor      %xmm15, %xmm8
        paddq     %xmm0, %xmm3
        pxor      %xmm5, %xmm10
        movdqa    %xmm3, %xmm13
        paddq     %xmm10, %xmm8
        movdqa    %xmm3, %xmm10
        psllq     $23, %xmm13
        psrlq     $41, %xmm10
        movdqa    %xmm3, %xmm9
        paddq     %xmm8, %xmm0
        por       %xmm13, %xmm10
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm13
        movdqa    %xmm2, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm6, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        movdqa    528(%rsp), %xmm11
        pand      %xmm3, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm2, %xmm12
        paddq     %xmm11, %xmm1
        pxor      %xmm9, %xmm10
        movdqa    %xmm0, %xmm11
        paddq     %xmm12, %xmm1
        paddq     .L_2il0floatpacket.697(%rip), %xmm10
        paddq     %xmm10, %xmm1
        movdqa    %xmm0, %xmm10
        psllq     $25, %xmm11
        psrlq     $39, %xmm10
        movdqa    %xmm0, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm0, %xmm11
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm15
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm5, %xmm9
        movdqa    %xmm0, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm4, %xmm9
        pxor      %xmm4, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm4, %xmm9
        paddq     %xmm1, %xmm7
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm1
        movdqa    544(%rsp), %xmm13
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm10
        movdqa    %xmm3, %xmm14
        paddq     %xmm13, %xmm2
        movdqa    %xmm7, %xmm13
        movdqa    %xmm7, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm6, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm7, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm6, %xmm14
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm2
        paddq     .L_2il0floatpacket.698(%rip), %xmm13
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm9
        paddq     %xmm13, %xmm2
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm4, %xmm13
        movdqa    %xmm1, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm0, %xmm13
        pxor      %xmm0, %xmm12
        movdqa    %xmm7, %xmm8
        por       %xmm15, %xmm14
        paddq     %xmm2, %xmm5
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm3, %xmm8
        pxor      %xmm11, %xmm14
        movdqa    560(%rsp), %xmm15
        pxor      %xmm0, %xmm13
        pand      %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        paddq     %xmm15, %xmm6
        paddq     %xmm13, %xmm14
        pxor      %xmm3, %xmm8
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm11
        paddq     %xmm8, %xmm6
        paddq     %xmm14, %xmm2
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm13, %xmm8
        movdqa    %xmm2, %xmm9
        paddq     .L_2il0floatpacket.699(%rip), %xmm8
        paddq     %xmm8, %xmm6
        movdqa    %xmm2, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm0, %xmm9
        movdqa    %xmm2, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm1, %xmm9
        pxor      %xmm1, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm1, %xmm9
        paddq     %xmm6, %xmm4
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm6
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm4, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm4, %xmm13
        movdqa    %xmm5, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm7, %xmm11
        por       %xmm14, %xmm13
        pand      %xmm4, %xmm11
        movdqa    576(%rsp), %xmm10
        pxor      %xmm13, %xmm12
        paddq     %xmm10, %xmm3
        pxor      %xmm7, %xmm11
        pxor      %xmm12, %xmm8
        paddq     %xmm11, %xmm3
        paddq     .L_2il0floatpacket.700(%rip), %xmm8
        paddq     %xmm8, %xmm3
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm1, %xmm11
        movdqa    %xmm6, %xmm10
        pxor      %xmm2, %xmm11
        pxor      %xmm2, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm2, %xmm11
        movdqa    %xmm4, %xmm13
        paddq     %xmm3, %xmm0
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm3
        movdqa    592(%rsp), %xmm12
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm14
        paddq     %xmm12, %xmm7
        movdqa    %xmm0, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm5, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm0, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm5, %xmm13
        pxor      %xmm11, %xmm12
        movdqa    %xmm3, %xmm9
        paddq     %xmm13, %xmm7
        paddq     .L_2il0floatpacket.701(%rip), %xmm12
        paddq     %xmm12, %xmm7
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm2, %xmm11
        movdqa    %xmm3, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm6, %xmm11
        pxor      %xmm6, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm6, %xmm11
        paddq     %xmm7, %xmm1
        paddq     %xmm11, %xmm12
        paddq     %xmm12, %xmm7
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm4, %xmm8
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        movdqa    608(%rsp), %xmm14
        pand      %xmm1, %xmm8
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm5
        pxor      %xmm4, %xmm8
        pxor      %xmm13, %xmm15
        paddq     %xmm8, %xmm5
        paddq     .L_2il0floatpacket.702(%rip), %xmm15
        paddq     %xmm15, %xmm5
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm8
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm10
        paddq     %xmm5, %xmm2
        por       %xmm8, %xmm15
        psrlq     $28, %xmm12
        movdqa    624(%rsp), %xmm8
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        paddq     %xmm8, %xmm4
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        movdqa    %xmm6, %xmm14
        movdqa    %xmm7, %xmm13
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm3, %xmm14
        pxor      %xmm3, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm12
        movdqa    %xmm1, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm0, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm3, %xmm14
        pand      %xmm2, %xmm9
        pxor      %xmm13, %xmm10
        pxor      %xmm0, %xmm9
        paddq     %xmm14, %xmm15
        paddq     %xmm9, %xmm4
        paddq     %xmm15, %xmm5
        pxor      %xmm10, %xmm8
        movdqa    %xmm5, %xmm9
        paddq     .L_2il0floatpacket.703(%rip), %xmm8
        paddq     %xmm8, %xmm4
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm3, %xmm11
        movdqa    %xmm5, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm7, %xmm11
        pxor      %xmm7, %xmm9
        paddq     %xmm4, %xmm6
        pxor      %xmm14, %xmm15
        pand      %xmm9, %xmm11
        movdqa    640(%rsp), %xmm10
        pxor      %xmm15, %xmm8
        pxor      %xmm7, %xmm11
        movdqa    %xmm6, %xmm13
        paddq     %xmm10, %xmm0
        paddq     %xmm11, %xmm8
        movdqa    %xmm6, %xmm10
        psllq     $23, %xmm13
        psrlq     $41, %xmm10
        movdqa    %xmm6, %xmm9
        paddq     %xmm8, %xmm4
        por       %xmm13, %xmm10
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm13
        movdqa    %xmm2, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm1, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm6, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm1, %xmm12
        pxor      %xmm9, %xmm10
        paddq     %xmm12, %xmm0
        paddq     .L_2il0floatpacket.704(%rip), %xmm10
        paddq     %xmm10, %xmm0
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm11
        psrlq     $39, %xmm10
        psllq     $25, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm12
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        movdqa    %xmm4, %xmm15
        por       %xmm12, %xmm11
        movdqa    %xmm4, %xmm12
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm7, %xmm9
        movdqa    %xmm4, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm5, %xmm9
        pxor      %xmm5, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm5, %xmm9
        movdqa    %xmm6, %xmm14
        paddq     %xmm0, %xmm3
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm0
        movdqa    656(%rsp), %xmm13
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm8
        paddq     %xmm13, %xmm1
        movdqa    %xmm3, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm2, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm3, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm2, %xmm14
        pxor      %xmm12, %xmm13
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm12
        paddq     %xmm14, %xmm1
        paddq     .L_2il0floatpacket.705(%rip), %xmm13
        movdqa    %xmm0, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        psrlq     $39, %xmm12
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        por       %xmm15, %xmm12
        paddq     %xmm13, %xmm1
        pxor      %xmm10, %xmm11
        movdqa    %xmm5, %xmm9
        paddq     %xmm1, %xmm7
        pxor      %xmm11, %xmm12
        pxor      %xmm4, %xmm9
..B7.37:
        movdqa    %xmm0, %xmm8
        movdqa    %xmm7, %xmm15
        pxor      %xmm4, %xmm8
        movdqa    %xmm7, %xmm14
        pand      %xmm8, %xmm9
        movdqa    %xmm7, %xmm13
        pxor      %xmm4, %xmm9
        movdqa    %xmm3, %xmm10
        paddq     %xmm9, %xmm12
        paddq     %xmm12, %xmm1
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm11
        psrlq     $14, %xmm15
        psllq     $50, %xmm12
        psrlq     $18, %xmm14
        psllq     $46, %xmm13
        pxor      %xmm6, %xmm10
        psrlq     $41, %xmm8
        psllq     $23, %xmm11
        por       %xmm12, %xmm15
        por       %xmm13, %xmm14
        movdqa    672(%rsp), %xmm9
        pand      %xmm7, %xmm10
        por       %xmm11, %xmm8
        pxor      %xmm14, %xmm15
        paddq     %xmm9, %xmm2
        pxor      %xmm6, %xmm10
        pxor      %xmm15, %xmm8
        paddq     %xmm10, %xmm2
        paddq     .L_2il0floatpacket.706(%rip), %xmm8
        paddq     %xmm8, %xmm2
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm13
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm4, %xmm9
        movdqa    %xmm0, %xmm14
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pxor      %xmm0, %xmm9
        pxor      %xmm1, %xmm14
        pxor      %xmm12, %xmm13
        pand      %xmm14, %xmm9
        pxor      %xmm13, %xmm8
        pxor      %xmm0, %xmm9
        movdqa    %xmm7, %xmm10
        paddq     %xmm2, %xmm5
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm2
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm11
        por       %xmm11, %xmm8
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm12
        movdqa    %xmm5, %xmm13
        por       %xmm12, %xmm11
        movdqa    %xmm5, %xmm12
        psrlq     $18, %xmm12
        psllq     $46, %xmm13
        pxor      %xmm3, %xmm10
        por       %xmm13, %xmm12
        movdqa    688(%rsp), %xmm15
        pand      %xmm5, %xmm10
        pxor      %xmm12, %xmm11
        pxor      %xmm3, %xmm10
        paddq     %xmm15, %xmm6
        pxor      %xmm11, %xmm8
        movdqa    %xmm2, %xmm9
        paddq     %xmm10, %xmm6
        paddq     .L_2il0floatpacket.707(%rip), %xmm8
        paddq     %xmm8, %xmm6
        movdqa    %xmm2, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm2, %xmm10
        por       %xmm9, %xmm8
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm14
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm14
        por       %xmm10, %xmm9
        por       %xmm14, %xmm15
        movdqa    %xmm0, %xmm14
        movdqa    %xmm2, %xmm10
        pxor      %xmm1, %xmm14
        pxor      %xmm1, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm14
        movdqa    %xmm7, %xmm12
        pxor      %xmm9, %xmm8
        paddq     %xmm6, %xmm4
        pxor      %xmm1, %xmm14
        pxor      %xmm5, %xmm12
        paddq     %xmm14, %xmm8
        movdqa    704(%rsp), %xmm11
        pand      %xmm4, %xmm12
        paddq     %xmm11, %xmm3
        paddq     %xmm8, %xmm6
        pxor      %xmm7, %xmm12
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm13
        paddq     %xmm12, %xmm3
        movdqa    %xmm4, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        psrlq     $41, %xmm12
        psllq     $23, %xmm13
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        por       %xmm13, %xmm12
        pxor      %xmm10, %xmm11
        movdqa    %xmm6, %xmm14
        pxor      %xmm11, %xmm12
        psllq     $25, %xmm14
        paddq     .L_2il0floatpacket.708(%rip), %xmm12
        paddq     %xmm12, %xmm3
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm9
        psrlq     $39, %xmm12
        movdqa    %xmm6, %xmm15
        por       %xmm14, %xmm12
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm14
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm14
        movdqa    %xmm1, %xmm11
        movdqa    %xmm6, %xmm10
        por       %xmm15, %xmm9
        por       %xmm14, %xmm8
        pxor      %xmm2, %xmm11
        pxor      %xmm2, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm2, %xmm11
        movdqa    %xmm4, %xmm8
        paddq     %xmm3, %xmm0
        paddq     %xmm11, %xmm12
        paddq     %xmm12, %xmm3
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm9
        psrlq     $14, %xmm14
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm5, %xmm8
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pand      %xmm0, %xmm8
        movdqa    720(%rsp), %xmm13
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm14
        pxor      %xmm5, %xmm8
        paddq     %xmm13, %xmm7
        pxor      %xmm14, %xmm15
        movdqa    %xmm3, %xmm12
        paddq     %xmm8, %xmm7
        paddq     .L_2il0floatpacket.709(%rip), %xmm15
        paddq     %xmm15, %xmm7
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm8
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm10
        por       %xmm8, %xmm15
        paddq     %xmm7, %xmm1
        movdqa    736(%rsp), %xmm8
        psrlq     $28, %xmm12
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        por       %xmm9, %xmm12
        paddq     %xmm8, %xmm5
        por       %xmm10, %xmm11
        movdqa    %xmm2, %xmm14
        movdqa    %xmm3, %xmm13
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm6, %xmm14
        pxor      %xmm6, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm12
        movdqa    %xmm0, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm4, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm6, %xmm14
        pand      %xmm1, %xmm9
        pxor      %xmm13, %xmm10
        paddq     %xmm14, %xmm15
        pxor      %xmm4, %xmm9
        pxor      %xmm10, %xmm8
        paddq     %xmm15, %xmm7
        paddq     %xmm9, %xmm5
        paddq     .L_2il0floatpacket.710(%rip), %xmm8
        paddq     %xmm8, %xmm5
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm6, %xmm11
        movdqa    %xmm7, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm3, %xmm11
        pxor      %xmm3, %xmm9
        pxor      %xmm14, %xmm15
        paddq     %xmm5, %xmm2
        pand      %xmm9, %xmm11
        pxor      %xmm15, %xmm8
        movdqa    752(%rsp), %xmm10
        pxor      %xmm3, %xmm11
        paddq     %xmm10, %xmm4
        paddq     %xmm11, %xmm8
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm13
        psrlq     $41, %xmm10
        psllq     $23, %xmm13
        paddq     %xmm8, %xmm5
        por       %xmm13, %xmm10
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm13
        movdqa    %xmm1, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm0, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm2, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm0, %xmm12
        pxor      %xmm9, %xmm10
        movdqa    %xmm5, %xmm11
        paddq     %xmm12, %xmm4
        paddq     .L_2il0floatpacket.711(%rip), %xmm10
        paddq     %xmm10, %xmm4
        movdqa    %xmm5, %xmm10
        psllq     $25, %xmm11
        psrlq     $39, %xmm10
        movdqa    %xmm5, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm5, %xmm11
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm15
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm3, %xmm9
        movdqa    %xmm5, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm7, %xmm9
        pxor      %xmm7, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm7, %xmm9
        paddq     %xmm4, %xmm6
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm4
        movdqa    768(%rsp), %xmm13
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm10
        movdqa    %xmm2, %xmm14
        paddq     %xmm13, %xmm0
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm1, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm6, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm1, %xmm14
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm0
        paddq     .L_2il0floatpacket.712(%rip), %xmm13
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm9
        paddq     %xmm13, %xmm0
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm7, %xmm13
        movdqa    %xmm4, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm5, %xmm13
        pxor      %xmm5, %xmm12
        movdqa    %xmm6, %xmm8
        por       %xmm15, %xmm14
        paddq     %xmm0, %xmm3
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm2, %xmm8
        pxor      %xmm11, %xmm14
        movdqa    784(%rsp), %xmm15
        pxor      %xmm5, %xmm13
        pand      %xmm3, %xmm8
        movdqa    %xmm3, %xmm10
        paddq     %xmm15, %xmm1
        paddq     %xmm13, %xmm14
        pxor      %xmm2, %xmm8
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm11
        paddq     %xmm8, %xmm1
        paddq     %xmm14, %xmm0
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm13, %xmm8
        movdqa    %xmm0, %xmm9
        paddq     .L_2il0floatpacket.713(%rip), %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm0, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm5, %xmm9
        movdqa    %xmm0, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm4, %xmm9
        pxor      %xmm4, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm4, %xmm9
        paddq     %xmm1, %xmm7
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm7, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm7, %xmm13
        movdqa    %xmm3, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm6, %xmm11
        por       %xmm14, %xmm13
        pand      %xmm7, %xmm11
        movdqa    800(%rsp), %xmm10
        pxor      %xmm13, %xmm12
        paddq     %xmm10, %xmm2
        pxor      %xmm6, %xmm11
        pxor      %xmm12, %xmm8
        paddq     %xmm11, %xmm2
        paddq     .L_2il0floatpacket.714(%rip), %xmm8
        paddq     %xmm8, %xmm2
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm4, %xmm11
        movdqa    %xmm1, %xmm10
        pxor      %xmm0, %xmm11
        pxor      %xmm0, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm0, %xmm11
        movdqa    %xmm7, %xmm13
        paddq     %xmm2, %xmm5
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm2
        movdqa    816(%rsp), %xmm12
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm9
        movdqa    %xmm5, %xmm14
        paddq     %xmm12, %xmm6
        movdqa    %xmm5, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm3, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm5, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm3, %xmm13
        pxor      %xmm11, %xmm12
        movdqa    %xmm2, %xmm9
        paddq     %xmm13, %xmm6
        paddq     .L_2il0floatpacket.715(%rip), %xmm12
        paddq     %xmm12, %xmm6
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm0, %xmm11
        movdqa    %xmm2, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm1, %xmm11
        pxor      %xmm1, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm1, %xmm11
        movdqa    %xmm5, %xmm8
        paddq     %xmm6, %xmm4
        paddq     %xmm11, %xmm12
        pxor      %xmm7, %xmm8
        movdqa    %xmm4, %xmm9
        movdqa    832(%rsp), %xmm14
        pand      %xmm4, %xmm8
        paddq     %xmm12, %xmm6
        paddq     %xmm14, %xmm3
        movdqa    %xmm4, %xmm12
        pxor      %xmm7, %xmm8
        psrlq     $41, %xmm12
        psllq     $23, %xmm9
        paddq     %xmm8, %xmm3
        por       %xmm9, %xmm12
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm11
        psrlq     $14, %xmm9
        psllq     $50, %xmm10
        psrlq     $18, %xmm8
        psllq     $46, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm8
..B7.36:
        pxor      %xmm8, %xmm9
        movdqa    %xmm6, %xmm11
        pxor      %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        paddq     .L_2il0floatpacket.716(%rip), %xmm12
        paddq     %xmm12, %xmm3
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm8
        psrlq     $28, %xmm12
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        movdqa    %xmm1, %xmm14
        movdqa    %xmm6, %xmm13
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pxor      %xmm2, %xmm14
        pxor      %xmm2, %xmm13
        por       %xmm8, %xmm15
        pxor      %xmm11, %xmm12
        pand      %xmm13, %xmm14
        pxor      %xmm12, %xmm15
        paddq     %xmm3, %xmm0
        pxor      %xmm2, %xmm14
        movdqa    %xmm0, %xmm11
        paddq     %xmm14, %xmm15
        movdqa    848(%rsp), %xmm8
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm12
        paddq     %xmm8, %xmm7
        paddq     %xmm15, %xmm3
        movdqa    %xmm4, %xmm9
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm10
        psrlq     $14, %xmm14
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm5, %xmm9
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        por       %xmm11, %xmm14
        por       %xmm12, %xmm13
        pand      %xmm0, %xmm9
        por       %xmm10, %xmm8
        pxor      %xmm13, %xmm14
        pxor      %xmm5, %xmm9
        pxor      %xmm14, %xmm8
        movdqa    %xmm3, %xmm13
        paddq     %xmm9, %xmm7
        paddq     .L_2il0floatpacket.717(%rip), %xmm8
        paddq     %xmm8, %xmm7
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm13
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm2, %xmm9
        movdqa    %xmm6, %xmm15
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pxor      %xmm6, %xmm9
        pxor      %xmm3, %xmm15
        pxor      %xmm12, %xmm13
        pand      %xmm15, %xmm9
        pxor      %xmm13, %xmm8
        pxor      %xmm6, %xmm9
        paddq     %xmm7, %xmm1
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm7
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm1, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm13
        movdqa    %xmm4, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm0, %xmm11
        por       %xmm14, %xmm13
        pand      %xmm1, %xmm11
        movdqa    864(%rsp), %xmm10
        pxor      %xmm13, %xmm12
        paddq     %xmm10, %xmm5
        pxor      %xmm4, %xmm11
        pxor      %xmm12, %xmm8
        paddq     %xmm11, %xmm5
        paddq     .L_2il0floatpacket.718(%rip), %xmm8
        paddq     %xmm8, %xmm5
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        movdqa    %xmm7, %xmm10
        pxor      %xmm3, %xmm11
        pxor      %xmm3, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm3, %xmm11
        movdqa    %xmm1, %xmm13
        paddq     %xmm5, %xmm2
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm5
        movdqa    880(%rsp), %xmm12
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm14
        paddq     %xmm12, %xmm4
        movdqa    %xmm2, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm0, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm2, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm0, %xmm13
        pxor      %xmm11, %xmm12
        movdqa    %xmm5, %xmm9
        paddq     %xmm13, %xmm4
        paddq     .L_2il0floatpacket.719(%rip), %xmm12
        paddq     %xmm12, %xmm4
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm3, %xmm11
        movdqa    %xmm5, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm7, %xmm11
        pxor      %xmm7, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm7, %xmm11
        paddq     %xmm4, %xmm6
        paddq     %xmm11, %xmm12
        paddq     %xmm12, %xmm4
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        movdqa    %xmm2, %xmm8
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm1, %xmm8
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        movdqa    896(%rsp), %xmm14
        pand      %xmm6, %xmm8
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm0
        pxor      %xmm1, %xmm8
        pxor      %xmm13, %xmm15
        paddq     %xmm8, %xmm0
        paddq     .L_2il0floatpacket.720(%rip), %xmm15
        paddq     %xmm15, %xmm0
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm8
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm10
        paddq     %xmm0, %xmm3
        por       %xmm8, %xmm15
        psrlq     $28, %xmm12
        movdqa    912(%rsp), %xmm8
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        paddq     %xmm8, %xmm1
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        movdqa    %xmm7, %xmm14
        movdqa    %xmm4, %xmm13
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm5, %xmm14
        pxor      %xmm5, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm12
        movdqa    %xmm6, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm2, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm5, %xmm14
        pand      %xmm3, %xmm9
        pxor      %xmm13, %xmm10
        pxor      %xmm2, %xmm9
        paddq     %xmm14, %xmm15
        paddq     %xmm9, %xmm1
        paddq     %xmm15, %xmm0
        pxor      %xmm10, %xmm8
        movdqa    %xmm0, %xmm9
        paddq     .L_2il0floatpacket.721(%rip), %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm0, %xmm14
        movdqa    %xmm0, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm5, %xmm11
        movdqa    %xmm0, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm4, %xmm11
        pxor      %xmm4, %xmm9
        paddq     %xmm1, %xmm7
        pxor      %xmm14, %xmm15
        pand      %xmm9, %xmm11
        movdqa    928(%rsp), %xmm10
        pxor      %xmm15, %xmm8
        pxor      %xmm4, %xmm11
        movdqa    %xmm7, %xmm13
        paddq     %xmm10, %xmm2
        paddq     %xmm11, %xmm8
        movdqa    %xmm7, %xmm10
        psllq     $23, %xmm13
        psrlq     $41, %xmm10
        movdqa    %xmm7, %xmm9
        paddq     %xmm8, %xmm1
        por       %xmm13, %xmm10
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm13
        movdqa    %xmm3, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm6, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm7, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm6, %xmm12
        pxor      %xmm9, %xmm10
        paddq     %xmm12, %xmm2
        paddq     .L_2il0floatpacket.722(%rip), %xmm10
        paddq     %xmm10, %xmm2
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm11
        psrlq     $39, %xmm10
        psllq     $25, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm12
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        movdqa    %xmm1, %xmm15
        por       %xmm12, %xmm11
        movdqa    %xmm1, %xmm12
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm4, %xmm9
        movdqa    %xmm1, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm0, %xmm9
        pxor      %xmm0, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm0, %xmm9
        movdqa    %xmm7, %xmm14
        paddq     %xmm2, %xmm5
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm2
        movdqa    944(%rsp), %xmm13
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm9
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm8
        paddq     %xmm13, %xmm6
        movdqa    %xmm5, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm3, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm5, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm3, %xmm14
        pxor      %xmm12, %xmm13
        movdqa    %xmm2, %xmm11
        paddq     %xmm14, %xmm6
        paddq     .L_2il0floatpacket.723(%rip), %xmm13
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm14
        paddq     %xmm13, %xmm6
        movdqa    %xmm2, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm0, %xmm13
        movdqa    %xmm2, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm1, %xmm13
        pxor      %xmm1, %xmm12
        movdqa    %xmm5, %xmm8
        paddq     %xmm6, %xmm4
        por       %xmm15, %xmm14
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm7, %xmm8
        movdqa    960(%rsp), %xmm15
        pxor      %xmm11, %xmm14
        pxor      %xmm1, %xmm13
        pand      %xmm4, %xmm8
        paddq     %xmm15, %xmm3
        paddq     %xmm13, %xmm14
        pxor      %xmm7, %xmm8
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm9
        paddq     %xmm8, %xmm3
        paddq     %xmm14, %xmm6
        movdqa    %xmm4, %xmm8
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        movdqa    %xmm6, %xmm9
        pxor      %xmm13, %xmm8
        psllq     $25, %xmm9
        paddq     .L_2il0floatpacket.724(%rip), %xmm8
        paddq     %xmm8, %xmm3
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm14
        psrlq     $39, %xmm8
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm1, %xmm9
        movdqa    %xmm6, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm2, %xmm9
        pxor      %xmm2, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm2, %xmm9
        movdqa    %xmm4, %xmm11
        paddq     %xmm3, %xmm0
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm3
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm0, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm0, %xmm13
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm5, %xmm11
        por       %xmm14, %xmm13
        movdqa    976(%rsp), %xmm10
        pand      %xmm0, %xmm11
        pxor      %xmm13, %xmm12
        pxor      %xmm5, %xmm11
        paddq     %xmm10, %xmm7
        pxor      %xmm12, %xmm8
        movdqa    %xmm3, %xmm9
        paddq     %xmm11, %xmm7
        paddq     .L_2il0floatpacket.725(%rip), %xmm8
        paddq     %xmm8, %xmm7
        movdqa    %xmm3, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm3, %xmm10
        por       %xmm9, %xmm8
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm2, %xmm11
        movdqa    %xmm3, %xmm10
        pxor      %xmm6, %xmm11
        pxor      %xmm6, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm6, %xmm11
        paddq     %xmm7, %xmm1
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm7
        movdqa    992(%rsp), %xmm12
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm9
        movdqa    %xmm0, %xmm13
        paddq     %xmm12, %xmm5
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm14
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm4, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm1, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm4, %xmm13
        pxor      %xmm11, %xmm12
        paddq     %xmm13, %xmm5
        paddq     .L_2il0floatpacket.726(%rip), %xmm12
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm8
        paddq     %xmm12, %xmm5
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm13
        psrlq     $28, %xmm10
        psllq     $36, %xmm15
        psrlq     $34, %xmm9
        psllq     $30, %xmm8
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm15, %xmm10
        por       %xmm8, %xmm9
        movdqa    %xmm6, %xmm8
        movdqa    %xmm7, %xmm11
        por       %xmm13, %xmm12
        pxor      %xmm9, %xmm10
        pxor      %xmm3, %xmm8
        pxor      %xmm3, %xmm11
        paddq     %xmm5, %xmm2
        pxor      %xmm10, %xmm12
        pand      %xmm11, %xmm8
..B7.35:
        pxor      %xmm3, %xmm8
        movdqa    %xmm2, %xmm14
        paddq     %xmm8, %xmm12
        paddq     %xmm12, %xmm5
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm12
        movdqa    %xmm1, %xmm9
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm10
        psrlq     $14, %xmm14
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm0, %xmm9
        psrlq     $41, %xmm15
        psllq     $23, %xmm10
        por       %xmm11, %xmm14
        por       %xmm12, %xmm13
        pand      %xmm2, %xmm9
        movdqa    1008(%rsp), %xmm8
        por       %xmm10, %xmm15
        pxor      %xmm13, %xmm14
        pxor      %xmm0, %xmm9
        paddq     %xmm8, %xmm4
        pxor      %xmm14, %xmm15
        movdqa    %xmm5, %xmm8
        paddq     %xmm9, %xmm4
        paddq     .L_2il0floatpacket.727(%rip), %xmm15
        paddq     %xmm15, %xmm4
        movdqa    %xmm5, %xmm15
        psllq     $25, %xmm8
        psrlq     $39, %xmm15
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm9
        movdqa    %xmm5, %xmm11
        movdqa    %xmm5, %xmm10
        por       %xmm8, %xmm15
        paddq     %xmm4, %xmm6
        movdqa    1024(%rsp), %xmm8
        psrlq     $28, %xmm12
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        por       %xmm9, %xmm12
        paddq     %xmm8, %xmm0
        por       %xmm10, %xmm11
        movdqa    %xmm3, %xmm14
        movdqa    %xmm7, %xmm13
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm7, %xmm14
        pxor      %xmm5, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm12
        movdqa    %xmm2, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm1, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm7, %xmm14
        pand      %xmm6, %xmm9
        pxor      %xmm13, %xmm10
        paddq     %xmm14, %xmm15
        pxor      %xmm1, %xmm9
        pxor      %xmm10, %xmm8
        paddq     %xmm15, %xmm4
        paddq     %xmm9, %xmm0
        paddq     .L_2il0floatpacket.728(%rip), %xmm8
        paddq     %xmm8, %xmm0
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm7, %xmm11
        movdqa    %xmm4, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm5, %xmm11
        pxor      %xmm5, %xmm9
        pxor      %xmm14, %xmm15
        paddq     %xmm0, %xmm3
        pand      %xmm9, %xmm11
        pxor      %xmm15, %xmm8
        movdqa    1040(%rsp), %xmm10
        pxor      %xmm5, %xmm11
        paddq     %xmm10, %xmm1
        paddq     %xmm11, %xmm8
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm13
        psrlq     $41, %xmm10
        psllq     $23, %xmm13
        paddq     %xmm8, %xmm0
        por       %xmm13, %xmm10
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm13
        movdqa    %xmm2, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm6, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm3, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm2, %xmm12
        pxor      %xmm9, %xmm10
        movdqa    %xmm0, %xmm11
        paddq     %xmm12, %xmm1
        paddq     .L_2il0floatpacket.729(%rip), %xmm10
        paddq     %xmm10, %xmm1
        movdqa    %xmm0, %xmm10
        psllq     $25, %xmm11
        psrlq     $39, %xmm10
        movdqa    %xmm0, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm0, %xmm11
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm15
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm5, %xmm9
        movdqa    %xmm0, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm4, %xmm9
        pxor      %xmm4, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm4, %xmm9
        paddq     %xmm1, %xmm7
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm1
        movdqa    1056(%rsp), %xmm13
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm10
        movdqa    %xmm3, %xmm14
        paddq     %xmm13, %xmm2
        movdqa    %xmm7, %xmm13
        movdqa    %xmm7, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm6, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm7, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm6, %xmm14
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm2
        paddq     .L_2il0floatpacket.730(%rip), %xmm13
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm9
        paddq     %xmm13, %xmm2
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm4, %xmm13
        movdqa    %xmm1, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm0, %xmm13
        pxor      %xmm0, %xmm12
        movdqa    %xmm7, %xmm8
        por       %xmm15, %xmm14
        paddq     %xmm2, %xmm5
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm3, %xmm8
        pxor      %xmm11, %xmm14
        movdqa    1072(%rsp), %xmm15
        pxor      %xmm0, %xmm13
        pand      %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        paddq     %xmm15, %xmm6
        paddq     %xmm13, %xmm14
        pxor      %xmm3, %xmm8
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm11
        paddq     %xmm8, %xmm6
        paddq     %xmm14, %xmm2
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm13, %xmm8
        movdqa    %xmm2, %xmm9
        paddq     .L_2il0floatpacket.731(%rip), %xmm8
        paddq     %xmm8, %xmm6
        movdqa    %xmm2, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm0, %xmm9
        movdqa    %xmm2, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm1, %xmm9
        pxor      %xmm1, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm1, %xmm9
        paddq     %xmm6, %xmm4
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm6
        movdqa    %xmm4, %xmm8
        movdqa    %xmm4, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm4, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm4, %xmm13
        movdqa    %xmm5, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm7, %xmm11
        por       %xmm14, %xmm13
        pand      %xmm4, %xmm11
        movdqa    1088(%rsp), %xmm10
        pxor      %xmm13, %xmm12
        paddq     %xmm10, %xmm3
        pxor      %xmm7, %xmm11
        pxor      %xmm12, %xmm8
        paddq     %xmm11, %xmm3
        paddq     .L_2il0floatpacket.732(%rip), %xmm8
        paddq     %xmm8, %xmm3
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm1, %xmm11
        movdqa    %xmm6, %xmm10
        pxor      %xmm2, %xmm11
        pxor      %xmm2, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm2, %xmm11
        movdqa    %xmm4, %xmm13
        paddq     %xmm3, %xmm0
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm3
        movdqa    1104(%rsp), %xmm12
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm14
        paddq     %xmm12, %xmm7
        movdqa    %xmm0, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm5, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm0, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm5, %xmm13
        pxor      %xmm11, %xmm12
        movdqa    %xmm3, %xmm9
        paddq     %xmm13, %xmm7
        paddq     .L_2il0floatpacket.733(%rip), %xmm12
        paddq     %xmm12, %xmm7
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm2, %xmm11
        movdqa    %xmm3, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm6, %xmm11
        pxor      %xmm6, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm6, %xmm11
        paddq     %xmm7, %xmm1
        paddq     %xmm11, %xmm12
        paddq     %xmm12, %xmm7
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        pxor      %xmm4, %xmm8
        psrlq     $41, %xmm15
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        movdqa    1120(%rsp), %xmm14
        pand      %xmm1, %xmm8
        por       %xmm9, %xmm15
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm5
        pxor      %xmm4, %xmm8
        pxor      %xmm13, %xmm15
        paddq     %xmm8, %xmm5
        paddq     .L_2il0floatpacket.734(%rip), %xmm15
        paddq     %xmm15, %xmm5
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm8
        psrlq     $39, %xmm15
        psllq     $25, %xmm8
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm10
        paddq     %xmm5, %xmm2
        por       %xmm8, %xmm15
        psrlq     $28, %xmm12
        movdqa    1136(%rsp), %xmm8
        psllq     $36, %xmm9
        psrlq     $34, %xmm11
        psllq     $30, %xmm10
        paddq     %xmm8, %xmm4
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        movdqa    %xmm6, %xmm14
        movdqa    %xmm7, %xmm13
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm10
        pxor      %xmm11, %xmm12
        pxor      %xmm3, %xmm14
        pxor      %xmm3, %xmm13
        psrlq     $41, %xmm8
        psllq     $23, %xmm10
        pxor      %xmm12, %xmm15
        pand      %xmm13, %xmm14
        por       %xmm10, %xmm8
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm12
        movdqa    %xmm1, %xmm9
        psrlq     $14, %xmm10
        psllq     $50, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm12
        pxor      %xmm0, %xmm9
        por       %xmm11, %xmm10
        por       %xmm12, %xmm13
        pxor      %xmm3, %xmm14
        pand      %xmm2, %xmm9
        pxor      %xmm13, %xmm10
        pxor      %xmm0, %xmm9
        paddq     %xmm14, %xmm15
        paddq     %xmm9, %xmm4
        paddq     %xmm15, %xmm5
        pxor      %xmm10, %xmm8
        movdqa    %xmm5, %xmm9
        paddq     .L_2il0floatpacket.735(%rip), %xmm8
        paddq     %xmm8, %xmm4
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm11
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm11
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm12
        por       %xmm9, %xmm8
        por       %xmm11, %xmm15
        psrlq     $34, %xmm14
        psllq     $30, %xmm12
        movdqa    %xmm3, %xmm11
        movdqa    %xmm5, %xmm9
        por       %xmm12, %xmm14
        pxor      %xmm7, %xmm11
        pxor      %xmm7, %xmm9
        paddq     %xmm4, %xmm6
        pxor      %xmm14, %xmm15
        pand      %xmm9, %xmm11
        movdqa    1152(%rsp), %xmm10
        pxor      %xmm15, %xmm8
        pxor      %xmm7, %xmm11
        movdqa    %xmm6, %xmm13
        paddq     %xmm10, %xmm0
        paddq     %xmm11, %xmm8
        movdqa    %xmm6, %xmm10
        psllq     $23, %xmm13
        psrlq     $41, %xmm10
        movdqa    %xmm6, %xmm9
        paddq     %xmm8, %xmm4
        por       %xmm13, %xmm10
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm13
        movdqa    %xmm2, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm1, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        pand      %xmm6, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm1, %xmm12
        pxor      %xmm9, %xmm10
        paddq     %xmm12, %xmm0
        paddq     .L_2il0floatpacket.736(%rip), %xmm10
        paddq     %xmm10, %xmm0
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm11
        psrlq     $39, %xmm10
        psllq     $25, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm12
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        movdqa    %xmm4, %xmm15
        por       %xmm12, %xmm11
        movdqa    %xmm4, %xmm12
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm7, %xmm9
        movdqa    %xmm4, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm5, %xmm9
        pxor      %xmm5, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm5, %xmm9
        movdqa    %xmm6, %xmm14
        paddq     %xmm0, %xmm3
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm0
        movdqa    1168(%rsp), %xmm13
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm9
        movdqa    %xmm3, %xmm11
        movdqa    %xmm3, %xmm10
        pxor      %xmm2, %xmm14
        paddq     %xmm13, %xmm1
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pand      %xmm3, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pxor      %xmm2, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        paddq     %xmm14, %xmm1
        pxor      %xmm12, %xmm13
..B7.34:
        movdqa    .L_2il0floatpacket.737(%rip), %xmm8
        movdqa    %xmm0, %xmm10
        paddq     %xmm8, %xmm13
        paddq     %xmm13, %xmm1
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm9
        psrlq     $28, %xmm13
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm5, %xmm15
        movdqa    %xmm0, %xmm14
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        pxor      %xmm4, %xmm15
        pxor      %xmm4, %xmm14
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pand      %xmm14, %xmm15
        pxor      %xmm13, %xmm8
        pxor      %xmm4, %xmm15
        paddq     %xmm1, %xmm7
        paddq     %xmm15, %xmm8
        paddq     %xmm8, %xmm1
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm11
        por       %xmm11, %xmm8
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm13
        movdqa    %xmm3, %xmm10
        psrlq     $14, %xmm11
        psllq     $50, %xmm12
        psrlq     $18, %xmm14
        psllq     $46, %xmm13
        pxor      %xmm6, %xmm10
        por       %xmm12, %xmm11
        por       %xmm13, %xmm14
        pand      %xmm7, %xmm10
        movdqa    1184(%rsp), %xmm9
        pxor      %xmm14, %xmm11
        paddq     %xmm9, %xmm2
        pxor      %xmm6, %xmm10
        pxor      %xmm11, %xmm8
        paddq     %xmm10, %xmm2
        paddq     .L_2il0floatpacket.738(%rip), %xmm8
        paddq     %xmm8, %xmm2
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm10
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        psrlq     $28, %xmm15
        psllq     $36, %xmm10
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm12
        por       %xmm9, %xmm8
        por       %xmm10, %xmm15
        psrlq     $34, %xmm13
        psllq     $30, %xmm12
        movdqa    %xmm4, %xmm10
        movdqa    %xmm0, %xmm9
        por       %xmm12, %xmm13
        pxor      %xmm0, %xmm10
        pxor      %xmm1, %xmm9
        pxor      %xmm13, %xmm15
        pand      %xmm9, %xmm10
        pxor      %xmm15, %xmm8
        paddq     %xmm2, %xmm5
        pxor      %xmm0, %xmm10
        movdqa    %xmm5, %xmm13
        paddq     %xmm10, %xmm8
        movdqa    %xmm5, %xmm10
        psllq     $23, %xmm13
        psrlq     $41, %xmm10
        movdqa    %xmm5, %xmm9
        paddq     %xmm8, %xmm2
        por       %xmm13, %xmm10
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm13
        movdqa    %xmm3, %xmm12
        psrlq     $14, %xmm9
        psllq     $50, %xmm14
        psrlq     $18, %xmm8
        psllq     $46, %xmm13
        pxor      %xmm7, %xmm12
        por       %xmm14, %xmm9
        por       %xmm13, %xmm8
        movdqa    1200(%rsp), %xmm11
        pand      %xmm5, %xmm12
        pxor      %xmm8, %xmm9
        pxor      %xmm3, %xmm12
        paddq     %xmm11, %xmm6
        pxor      %xmm9, %xmm10
        movdqa    %xmm2, %xmm11
        paddq     %xmm12, %xmm6
        paddq     .L_2il0floatpacket.739(%rip), %xmm10
        paddq     %xmm10, %xmm6
        movdqa    %xmm2, %xmm10
        psllq     $25, %xmm11
        psrlq     $39, %xmm10
        movdqa    %xmm2, %xmm12
        por       %xmm11, %xmm10
        movdqa    %xmm2, %xmm11
        psrlq     $28, %xmm11
        psllq     $36, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm15
        psrlq     $34, %xmm12
        psllq     $30, %xmm15
        movdqa    %xmm0, %xmm9
        movdqa    %xmm2, %xmm8
        por       %xmm15, %xmm12
        pxor      %xmm1, %xmm9
        pxor      %xmm1, %xmm8
        pxor      %xmm12, %xmm11
        pand      %xmm8, %xmm9
        pxor      %xmm11, %xmm10
        pxor      %xmm1, %xmm9
        paddq     %xmm6, %xmm4
        paddq     %xmm9, %xmm10
        paddq     %xmm10, %xmm6
        movdqa    1216(%rsp), %xmm13
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm11
        movdqa    %xmm4, %xmm10
        movdqa    %xmm5, %xmm14
        paddq     %xmm13, %xmm3
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm8
        psrlq     $14, %xmm12
        psllq     $50, %xmm9
        psrlq     $18, %xmm11
        psllq     $46, %xmm10
        pxor      %xmm7, %xmm14
        psrlq     $41, %xmm13
        psllq     $23, %xmm8
        por       %xmm9, %xmm12
        por       %xmm10, %xmm11
        pand      %xmm4, %xmm14
        por       %xmm8, %xmm13
        pxor      %xmm11, %xmm12
        pxor      %xmm7, %xmm14
        pxor      %xmm12, %xmm13
        paddq     %xmm14, %xmm3
        paddq     .L_2il0floatpacket.740(%rip), %xmm13
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm8
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm9
        paddq     %xmm13, %xmm3
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm15
        psrlq     $28, %xmm11
        psllq     $36, %xmm8
        psrlq     $34, %xmm10
        psllq     $30, %xmm9
        movdqa    %xmm1, %xmm13
        movdqa    %xmm6, %xmm12
        psrlq     $39, %xmm14
        psllq     $25, %xmm15
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pxor      %xmm2, %xmm13
        pxor      %xmm2, %xmm12
        movdqa    %xmm4, %xmm8
        por       %xmm15, %xmm14
        paddq     %xmm3, %xmm0
        pxor      %xmm10, %xmm11
        pand      %xmm12, %xmm13
        pxor      %xmm5, %xmm8
        pxor      %xmm11, %xmm14
        movdqa    1232(%rsp), %xmm15
        pxor      %xmm2, %xmm13
        pand      %xmm0, %xmm8
        movdqa    %xmm0, %xmm10
        paddq     %xmm15, %xmm7
        paddq     %xmm13, %xmm14
        pxor      %xmm5, %xmm8
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm11
        paddq     %xmm8, %xmm7
        paddq     %xmm14, %xmm3
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm9
        psrlq     $14, %xmm13
        psllq     $50, %xmm10
        psrlq     $18, %xmm12
        psllq     $46, %xmm11
        psrlq     $41, %xmm8
        psllq     $23, %xmm9
        por       %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm9, %xmm8
        pxor      %xmm12, %xmm13
        pxor      %xmm13, %xmm8
        movdqa    %xmm3, %xmm9
        paddq     .L_2il0floatpacket.741(%rip), %xmm8
        paddq     %xmm8, %xmm7
        movdqa    %xmm3, %xmm8
        psllq     $25, %xmm9
        psrlq     $39, %xmm8
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm10
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm11
        por       %xmm9, %xmm8
        psrlq     $28, %xmm14
        psllq     $36, %xmm10
        psrlq     $34, %xmm12
        psllq     $30, %xmm11
        movdqa    %xmm2, %xmm9
        movdqa    %xmm3, %xmm15
        por       %xmm10, %xmm14
        por       %xmm11, %xmm12
        pxor      %xmm6, %xmm9
        pxor      %xmm6, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm15, %xmm9
        pxor      %xmm14, %xmm8
        pxor      %xmm6, %xmm9
        paddq     %xmm7, %xmm1
        paddq     %xmm9, %xmm8
        paddq     %xmm8, %xmm7
        movdqa    %xmm1, %xmm8
        movdqa    %xmm1, %xmm12
        psrlq     $41, %xmm8
        psllq     $23, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm13
        psrlq     $14, %xmm12
        psllq     $50, %xmm13
        movdqa    %xmm1, %xmm14
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm13
        movdqa    %xmm0, %xmm11
        psrlq     $18, %xmm13
        psllq     $46, %xmm14
        pxor      %xmm4, %xmm11
        por       %xmm14, %xmm13
        pand      %xmm1, %xmm11
        movdqa    1248(%rsp), %xmm10
        pxor      %xmm13, %xmm12
        paddq     %xmm10, %xmm5
        pxor      %xmm4, %xmm11
        pxor      %xmm12, %xmm8
        paddq     %xmm11, %xmm5
        paddq     .L_2il0floatpacket.742(%rip), %xmm8
        paddq     %xmm8, %xmm5
        movdqa    %xmm7, %xmm8
        movdqa    %xmm7, %xmm9
        psrlq     $39, %xmm8
        psllq     $25, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm11
        psrlq     $28, %xmm9
        psllq     $36, %xmm10
        psrlq     $34, %xmm15
        psllq     $30, %xmm11
        por       %xmm10, %xmm9
        por       %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        movdqa    %xmm7, %xmm10
        pxor      %xmm3, %xmm11
        pxor      %xmm3, %xmm10
        pxor      %xmm15, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm8
        pxor      %xmm3, %xmm11
        movdqa    %xmm1, %xmm13
        paddq     %xmm5, %xmm2
        paddq     %xmm11, %xmm8
        paddq     %xmm8, %xmm5
        movdqa    1264(%rsp), %xmm12
        movdqa    %xmm2, %xmm11
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm14
        paddq     %xmm12, %xmm4
        movdqa    %xmm2, %xmm12
        psrlq     $14, %xmm11
        psllq     $50, %xmm8
        psrlq     $18, %xmm10
        psllq     $46, %xmm9
        pxor      %xmm0, %xmm13
        psrlq     $41, %xmm12
        psllq     $23, %xmm14
        por       %xmm8, %xmm11
        por       %xmm9, %xmm10
        pand      %xmm2, %xmm13
        por       %xmm14, %xmm12
        pxor      %xmm10, %xmm11
        pxor      %xmm0, %xmm13
        pxor      %xmm11, %xmm12
        movdqa    %xmm5, %xmm9
        paddq     %xmm13, %xmm4
        paddq     .L_2il0floatpacket.743(%rip), %xmm12
        paddq     %xmm12, %xmm4
        movdqa    %xmm5, %xmm12
        movdqa    %xmm5, %xmm13
        psrlq     $39, %xmm12
        psllq     $25, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm13
        psrlq     $28, %xmm9
        psllq     $36, %xmm15
        psrlq     $34, %xmm8
        psllq     $30, %xmm13
        movdqa    %xmm3, %xmm11
        movdqa    %xmm5, %xmm10
        por       %xmm15, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm7, %xmm11
        pxor      %xmm7, %xmm10
        pxor      %xmm8, %xmm9
        pand      %xmm10, %xmm11
        pxor      %xmm9, %xmm12
        pxor      %xmm7, %xmm11
        paddq     %xmm11, %xmm12
        paddq     %xmm4, %xmm6
        paddq     %xmm12, %xmm4
        testl     %eax, %eax
        je        ..B7.25
..B7.22:
        movl      %r12d, %eax
        andl      $6, %eax
        cmpl      $6, %eax
..B7.23:
        paddq     (%rbx), %xmm4
        paddq     16(%rbx), %xmm5
        paddq     32(%rbx), %xmm7
        paddq     48(%rbx), %xmm3
        paddq     64(%rbx), %xmm6
        paddq     80(%rbx), %xmm2
        paddq     96(%rbx), %xmm1
        paddq     112(%rbx), %xmm0
        jmp       ..B7.29
..B7.25:
        testl     $32, %r12d
        jne       ..B7.29
..B7.26:
        testl     $4096, %r12d
        je        ..B7.28
..B7.27:
        paddq     .L_2il0floatpacket.760(%rip), %xmm4
        paddq     .L_2il0floatpacket.761(%rip), %xmm5
        paddq     .L_2il0floatpacket.762(%rip), %xmm7
        paddq     .L_2il0floatpacket.763(%rip), %xmm3
        paddq     .L_2il0floatpacket.764(%rip), %xmm6
        paddq     .L_2il0floatpacket.765(%rip), %xmm2
        paddq     .L_2il0floatpacket.766(%rip), %xmm1
        paddq     .L_2il0floatpacket.767(%rip), %xmm0
        jmp       ..B7.29
..B7.28:
        paddq     .L_2il0floatpacket.768(%rip), %xmm4
        paddq     .L_2il0floatpacket.769(%rip), %xmm5
        paddq     .L_2il0floatpacket.770(%rip), %xmm7
        paddq     .L_2il0floatpacket.771(%rip), %xmm3
        paddq     .L_2il0floatpacket.772(%rip), %xmm6
        paddq     .L_2il0floatpacket.773(%rip), %xmm2
        paddq     .L_2il0floatpacket.774(%rip), %xmm1
        paddq     .L_2il0floatpacket.775(%rip), %xmm0
..B7.29:
        testl     $16, %r12d
        je        ..B7.31
..B7.30:
        pshuflw   $177, %xmm4, %xmm4
        pshufhw   $177, %xmm4, %xmm8
        movdqa    %xmm8, %xmm9
        psrlw     $8, %xmm8
        pshuflw   $177, %xmm6, %xmm6
        psllw     $8, %xmm9
        pxor      %xmm8, %xmm9
        pshufhw   $177, %xmm6, %xmm8
        pshufd    $177, %xmm9, %xmm4
        movdqa    %xmm8, %xmm9
        pshuflw   $177, %xmm2, %xmm2
        psllw     $8, %xmm9
        psrlw     $8, %xmm8
        pxor      %xmm8, %xmm9
        pshufhw   $177, %xmm2, %xmm8
        pshufd    $177, %xmm9, %xmm6
        movdqa    %xmm8, %xmm9
        pshuflw   $177, %xmm1, %xmm1
        psllw     $8, %xmm9
        psrlw     $8, %xmm8
        pxor      %xmm8, %xmm9
        pshufhw   $177, %xmm1, %xmm8
        pshufd    $177, %xmm9, %xmm2
        movdqa    %xmm8, %xmm9
        pshuflw   $177, %xmm5, %xmm5
        psllw     $8, %xmm9
        pshuflw   $177, %xmm7, %xmm7
        psrlw     $8, %xmm8
        pshuflw   $177, %xmm3, %xmm3
        pxor      %xmm8, %xmm9
        pshuflw   $177, %xmm0, %xmm0
        pshufhw   $177, %xmm5, %xmm10
        pshufhw   $177, %xmm7, %xmm12
        movdqa    %xmm10, %xmm11
        pshufhw   $177, %xmm3, %xmm14
        movdqa    %xmm12, %xmm13
        pshufhw   $177, %xmm0, %xmm8
        movdqa    %xmm14, %xmm15
        pshufd    $177, %xmm9, %xmm1
        movdqa    %xmm8, %xmm9
        psllw     $8, %xmm11
        psrlw     $8, %xmm10
        psllw     $8, %xmm13
        psrlw     $8, %xmm12
        psllw     $8, %xmm15
        psrlw     $8, %xmm14
        psllw     $8, %xmm9
        psrlw     $8, %xmm8
        pxor      %xmm10, %xmm11
        pxor      %xmm12, %xmm13
        pxor      %xmm14, %xmm15
        pxor      %xmm8, %xmm9
        pshufd    $177, %xmm11, %xmm5
        pshufd    $177, %xmm13, %xmm7
        pshufd    $177, %xmm15, %xmm3
        pshufd    $177, %xmm9, %xmm0
..B7.31:
        movdqa    %xmm4, (%rbp)
        movdqa    %xmm5, 16(%rbp)
        movdqa    %xmm7, 32(%rbp)
        movdqa    %xmm3, 48(%rbp)
        movdqa    %xmm6, 64(%rbp)
        movdqa    %xmm2, 80(%rbp)
        movdqa    %xmm1, 96(%rbp)
        movdqa    %xmm0, 112(%rbp)
        addq      $1280, %rsp
..___tag_value_SIMDSHA512body.139:
        popq      %rbp
..___tag_value_SIMDSHA512body.141:
        popq      %rbx
..___tag_value_SIMDSHA512body.143:
        popq      %r12
..___tag_value_SIMDSHA512body.145:
        ret       
        .align    16,0x90
..___tag_value_SIMDSHA512body.146:
	.type	SIMDSHA512body,@function
	.size	SIMDSHA512body,.-SIMDSHA512body
	.data
# -- End  SIMDSHA512body
	.section .rodata, "a"
	.space 8, 0x00 	# pad
	.align 16
.L_2il0floatpacket.21:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.21,@object
	.size	.L_2il0floatpacket.21,16
	.align 16
.L_2il0floatpacket.22:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.22,@object
	.size	.L_2il0floatpacket.22,16
	.align 16
.L_2il0floatpacket.23:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.23,@object
	.size	.L_2il0floatpacket.23,16
	.align 16
.L_2il0floatpacket.24:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.24,@object
	.size	.L_2il0floatpacket.24,16
	.align 16
.L_2il0floatpacket.25:
	.long	0xd76aa478,0xd76aa478,0xd76aa478,0xd76aa478
	.type	.L_2il0floatpacket.25,@object
	.size	.L_2il0floatpacket.25,16
	.align 16
.L_2il0floatpacket.26:
	.long	0xe8c7b756,0xe8c7b756,0xe8c7b756,0xe8c7b756
	.type	.L_2il0floatpacket.26,@object
	.size	.L_2il0floatpacket.26,16
	.align 16
.L_2il0floatpacket.27:
	.long	0x242070db,0x242070db,0x242070db,0x242070db
	.type	.L_2il0floatpacket.27,@object
	.size	.L_2il0floatpacket.27,16
	.align 16
.L_2il0floatpacket.28:
	.long	0xc1bdceee,0xc1bdceee,0xc1bdceee,0xc1bdceee
	.type	.L_2il0floatpacket.28,@object
	.size	.L_2il0floatpacket.28,16
	.align 16
.L_2il0floatpacket.29:
	.long	0xf57c0faf,0xf57c0faf,0xf57c0faf,0xf57c0faf
	.type	.L_2il0floatpacket.29,@object
	.size	.L_2il0floatpacket.29,16
	.align 16
.L_2il0floatpacket.30:
	.long	0x4787c62a,0x4787c62a,0x4787c62a,0x4787c62a
	.type	.L_2il0floatpacket.30,@object
	.size	.L_2il0floatpacket.30,16
	.align 16
.L_2il0floatpacket.31:
	.long	0xa8304613,0xa8304613,0xa8304613,0xa8304613
	.type	.L_2il0floatpacket.31,@object
	.size	.L_2il0floatpacket.31,16
	.align 16
.L_2il0floatpacket.32:
	.long	0xfd469501,0xfd469501,0xfd469501,0xfd469501
	.type	.L_2il0floatpacket.32,@object
	.size	.L_2il0floatpacket.32,16
	.align 16
.L_2il0floatpacket.33:
	.long	0x698098d8,0x698098d8,0x698098d8,0x698098d8
	.type	.L_2il0floatpacket.33,@object
	.size	.L_2il0floatpacket.33,16
	.align 16
.L_2il0floatpacket.34:
	.long	0x8b44f7af,0x8b44f7af,0x8b44f7af,0x8b44f7af
	.type	.L_2il0floatpacket.34,@object
	.size	.L_2il0floatpacket.34,16
	.align 16
.L_2il0floatpacket.35:
	.long	0xffff5bb1,0xffff5bb1,0xffff5bb1,0xffff5bb1
	.type	.L_2il0floatpacket.35,@object
	.size	.L_2il0floatpacket.35,16
	.align 16
.L_2il0floatpacket.36:
	.long	0x895cd7be,0x895cd7be,0x895cd7be,0x895cd7be
	.type	.L_2il0floatpacket.36,@object
	.size	.L_2il0floatpacket.36,16
	.align 16
.L_2il0floatpacket.37:
	.long	0x6b901122,0x6b901122,0x6b901122,0x6b901122
	.type	.L_2il0floatpacket.37,@object
	.size	.L_2il0floatpacket.37,16
	.align 16
.L_2il0floatpacket.38:
	.long	0xfd987193,0xfd987193,0xfd987193,0xfd987193
	.type	.L_2il0floatpacket.38,@object
	.size	.L_2il0floatpacket.38,16
	.align 16
.L_2il0floatpacket.39:
	.long	0xa679438e,0xa679438e,0xa679438e,0xa679438e
	.type	.L_2il0floatpacket.39,@object
	.size	.L_2il0floatpacket.39,16
	.align 16
.L_2il0floatpacket.40:
	.long	0x49b40821,0x49b40821,0x49b40821,0x49b40821
	.type	.L_2il0floatpacket.40,@object
	.size	.L_2il0floatpacket.40,16
	.align 16
.L_2il0floatpacket.41:
	.long	0xf61e2562,0xf61e2562,0xf61e2562,0xf61e2562
	.type	.L_2il0floatpacket.41,@object
	.size	.L_2il0floatpacket.41,16
	.align 16
.L_2il0floatpacket.42:
	.long	0xc040b340,0xc040b340,0xc040b340,0xc040b340
	.type	.L_2il0floatpacket.42,@object
	.size	.L_2il0floatpacket.42,16
	.align 16
.L_2il0floatpacket.43:
	.long	0x265e5a51,0x265e5a51,0x265e5a51,0x265e5a51
	.type	.L_2il0floatpacket.43,@object
	.size	.L_2il0floatpacket.43,16
	.align 16
.L_2il0floatpacket.44:
	.long	0xe9b6c7aa,0xe9b6c7aa,0xe9b6c7aa,0xe9b6c7aa
	.type	.L_2il0floatpacket.44,@object
	.size	.L_2il0floatpacket.44,16
	.align 16
.L_2il0floatpacket.45:
	.long	0xd62f105d,0xd62f105d,0xd62f105d,0xd62f105d
	.type	.L_2il0floatpacket.45,@object
	.size	.L_2il0floatpacket.45,16
	.align 16
.L_2il0floatpacket.46:
	.long	0x02441453,0x02441453,0x02441453,0x02441453
	.type	.L_2il0floatpacket.46,@object
	.size	.L_2il0floatpacket.46,16
	.align 16
.L_2il0floatpacket.47:
	.long	0xd8a1e681,0xd8a1e681,0xd8a1e681,0xd8a1e681
	.type	.L_2il0floatpacket.47,@object
	.size	.L_2il0floatpacket.47,16
	.align 16
.L_2il0floatpacket.48:
	.long	0xe7d3fbc8,0xe7d3fbc8,0xe7d3fbc8,0xe7d3fbc8
	.type	.L_2il0floatpacket.48,@object
	.size	.L_2il0floatpacket.48,16
	.align 16
.L_2il0floatpacket.49:
	.long	0x21e1cde6,0x21e1cde6,0x21e1cde6,0x21e1cde6
	.type	.L_2il0floatpacket.49,@object
	.size	.L_2il0floatpacket.49,16
	.align 16
.L_2il0floatpacket.50:
	.long	0xc33707d6,0xc33707d6,0xc33707d6,0xc33707d6
	.type	.L_2il0floatpacket.50,@object
	.size	.L_2il0floatpacket.50,16
	.align 16
.L_2il0floatpacket.51:
	.long	0xf4d50d87,0xf4d50d87,0xf4d50d87,0xf4d50d87
	.type	.L_2il0floatpacket.51,@object
	.size	.L_2il0floatpacket.51,16
	.align 16
.L_2il0floatpacket.52:
	.long	0x455a14ed,0x455a14ed,0x455a14ed,0x455a14ed
	.type	.L_2il0floatpacket.52,@object
	.size	.L_2il0floatpacket.52,16
	.align 16
.L_2il0floatpacket.53:
	.long	0xa9e3e905,0xa9e3e905,0xa9e3e905,0xa9e3e905
	.type	.L_2il0floatpacket.53,@object
	.size	.L_2il0floatpacket.53,16
	.align 16
.L_2il0floatpacket.54:
	.long	0xfcefa3f8,0xfcefa3f8,0xfcefa3f8,0xfcefa3f8
	.type	.L_2il0floatpacket.54,@object
	.size	.L_2il0floatpacket.54,16
	.align 16
.L_2il0floatpacket.55:
	.long	0x676f02d9,0x676f02d9,0x676f02d9,0x676f02d9
	.type	.L_2il0floatpacket.55,@object
	.size	.L_2il0floatpacket.55,16
	.align 16
.L_2il0floatpacket.56:
	.long	0x8d2a4c8a,0x8d2a4c8a,0x8d2a4c8a,0x8d2a4c8a
	.type	.L_2il0floatpacket.56,@object
	.size	.L_2il0floatpacket.56,16
	.align 16
.L_2il0floatpacket.57:
	.long	0xfffa3942,0xfffa3942,0xfffa3942,0xfffa3942
	.type	.L_2il0floatpacket.57,@object
	.size	.L_2il0floatpacket.57,16
	.align 16
.L_2il0floatpacket.58:
	.long	0x8771f681,0x8771f681,0x8771f681,0x8771f681
	.type	.L_2il0floatpacket.58,@object
	.size	.L_2il0floatpacket.58,16
	.align 16
.L_2il0floatpacket.59:
	.long	0x6d9d6122,0x6d9d6122,0x6d9d6122,0x6d9d6122
	.type	.L_2il0floatpacket.59,@object
	.size	.L_2il0floatpacket.59,16
	.align 16
.L_2il0floatpacket.60:
	.long	0xfde5380c,0xfde5380c,0xfde5380c,0xfde5380c
	.type	.L_2il0floatpacket.60,@object
	.size	.L_2il0floatpacket.60,16
	.align 16
.L_2il0floatpacket.61:
	.long	0xa4beea44,0xa4beea44,0xa4beea44,0xa4beea44
	.type	.L_2il0floatpacket.61,@object
	.size	.L_2il0floatpacket.61,16
	.align 16
.L_2il0floatpacket.62:
	.long	0x4bdecfa9,0x4bdecfa9,0x4bdecfa9,0x4bdecfa9
	.type	.L_2il0floatpacket.62,@object
	.size	.L_2il0floatpacket.62,16
	.align 16
.L_2il0floatpacket.63:
	.long	0xf6bb4b60,0xf6bb4b60,0xf6bb4b60,0xf6bb4b60
	.type	.L_2il0floatpacket.63,@object
	.size	.L_2il0floatpacket.63,16
	.align 16
.L_2il0floatpacket.64:
	.long	0xbebfbc70,0xbebfbc70,0xbebfbc70,0xbebfbc70
	.type	.L_2il0floatpacket.64,@object
	.size	.L_2il0floatpacket.64,16
	.align 16
.L_2il0floatpacket.65:
	.long	0x289b7ec6,0x289b7ec6,0x289b7ec6,0x289b7ec6
	.type	.L_2il0floatpacket.65,@object
	.size	.L_2il0floatpacket.65,16
	.align 16
.L_2il0floatpacket.66:
	.long	0xeaa127fa,0xeaa127fa,0xeaa127fa,0xeaa127fa
	.type	.L_2il0floatpacket.66,@object
	.size	.L_2il0floatpacket.66,16
	.align 16
.L_2il0floatpacket.67:
	.long	0xd4ef3085,0xd4ef3085,0xd4ef3085,0xd4ef3085
	.type	.L_2il0floatpacket.67,@object
	.size	.L_2il0floatpacket.67,16
	.align 16
.L_2il0floatpacket.68:
	.long	0x04881d05,0x04881d05,0x04881d05,0x04881d05
	.type	.L_2il0floatpacket.68,@object
	.size	.L_2il0floatpacket.68,16
	.align 16
.L_2il0floatpacket.69:
	.long	0xd9d4d039,0xd9d4d039,0xd9d4d039,0xd9d4d039
	.type	.L_2il0floatpacket.69,@object
	.size	.L_2il0floatpacket.69,16
	.align 16
.L_2il0floatpacket.70:
	.long	0xe6db99e5,0xe6db99e5,0xe6db99e5,0xe6db99e5
	.type	.L_2il0floatpacket.70,@object
	.size	.L_2il0floatpacket.70,16
	.align 16
.L_2il0floatpacket.71:
	.long	0x1fa27cf8,0x1fa27cf8,0x1fa27cf8,0x1fa27cf8
	.type	.L_2il0floatpacket.71,@object
	.size	.L_2il0floatpacket.71,16
	.align 16
.L_2il0floatpacket.72:
	.long	0xc4ac5665,0xc4ac5665,0xc4ac5665,0xc4ac5665
	.type	.L_2il0floatpacket.72,@object
	.size	.L_2il0floatpacket.72,16
	.align 16
.L_2il0floatpacket.73:
	.long	0xf4292244,0xf4292244,0xf4292244,0xf4292244
	.type	.L_2il0floatpacket.73,@object
	.size	.L_2il0floatpacket.73,16
	.align 16
.L_2il0floatpacket.74:
	.long	0x432aff97,0x432aff97,0x432aff97,0x432aff97
	.type	.L_2il0floatpacket.74,@object
	.size	.L_2il0floatpacket.74,16
	.align 16
.L_2il0floatpacket.75:
	.long	0xab9423a7,0xab9423a7,0xab9423a7,0xab9423a7
	.type	.L_2il0floatpacket.75,@object
	.size	.L_2il0floatpacket.75,16
	.align 16
.L_2il0floatpacket.76:
	.long	0xfc93a039,0xfc93a039,0xfc93a039,0xfc93a039
	.type	.L_2il0floatpacket.76,@object
	.size	.L_2il0floatpacket.76,16
	.align 16
.L_2il0floatpacket.77:
	.long	0x655b59c3,0x655b59c3,0x655b59c3,0x655b59c3
	.type	.L_2il0floatpacket.77,@object
	.size	.L_2il0floatpacket.77,16
	.align 16
.L_2il0floatpacket.78:
	.long	0x8f0ccc92,0x8f0ccc92,0x8f0ccc92,0x8f0ccc92
	.type	.L_2il0floatpacket.78,@object
	.size	.L_2il0floatpacket.78,16
	.align 16
.L_2il0floatpacket.79:
	.long	0xffeff47d,0xffeff47d,0xffeff47d,0xffeff47d
	.type	.L_2il0floatpacket.79,@object
	.size	.L_2il0floatpacket.79,16
	.align 16
.L_2il0floatpacket.80:
	.long	0x85845dd1,0x85845dd1,0x85845dd1,0x85845dd1
	.type	.L_2il0floatpacket.80,@object
	.size	.L_2il0floatpacket.80,16
	.align 16
.L_2il0floatpacket.81:
	.long	0x6fa87e4f,0x6fa87e4f,0x6fa87e4f,0x6fa87e4f
	.type	.L_2il0floatpacket.81,@object
	.size	.L_2il0floatpacket.81,16
	.align 16
.L_2il0floatpacket.82:
	.long	0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0
	.type	.L_2il0floatpacket.82,@object
	.size	.L_2il0floatpacket.82,16
	.align 16
.L_2il0floatpacket.83:
	.long	0xa3014314,0xa3014314,0xa3014314,0xa3014314
	.type	.L_2il0floatpacket.83,@object
	.size	.L_2il0floatpacket.83,16
	.align 16
.L_2il0floatpacket.84:
	.long	0x4e0811a1,0x4e0811a1,0x4e0811a1,0x4e0811a1
	.type	.L_2il0floatpacket.84,@object
	.size	.L_2il0floatpacket.84,16
	.align 16
.L_2il0floatpacket.85:
	.long	0xf7537e82,0xf7537e82,0xf7537e82,0xf7537e82
	.type	.L_2il0floatpacket.85,@object
	.size	.L_2il0floatpacket.85,16
	.align 16
.L_2il0floatpacket.86:
	.long	0xbd3af235,0xbd3af235,0xbd3af235,0xbd3af235
	.type	.L_2il0floatpacket.86,@object
	.size	.L_2il0floatpacket.86,16
	.align 16
.L_2il0floatpacket.87:
	.long	0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb
	.type	.L_2il0floatpacket.87,@object
	.size	.L_2il0floatpacket.87,16
	.align 16
.L_2il0floatpacket.88:
	.long	0xeb86d391,0xeb86d391,0xeb86d391,0xeb86d391
	.type	.L_2il0floatpacket.88,@object
	.size	.L_2il0floatpacket.88,16
	.align 16
.L_2il0floatpacket.89:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.89,@object
	.size	.L_2il0floatpacket.89,16
	.align 16
.L_2il0floatpacket.109:
	.long	0x1fa27cf8,0x1fa27cf8,0x1fa27cf8,0x1fa27cf8
	.type	.L_2il0floatpacket.109,@object
	.size	.L_2il0floatpacket.109,16
	.align 16
.L_2il0floatpacket.110:
	.long	0xc4ac5665,0xc4ac5665,0xc4ac5665,0xc4ac5665
	.type	.L_2il0floatpacket.110,@object
	.size	.L_2il0floatpacket.110,16
	.align 16
.L_2il0floatpacket.111:
	.long	0xf4292244,0xf4292244,0xf4292244,0xf4292244
	.type	.L_2il0floatpacket.111,@object
	.size	.L_2il0floatpacket.111,16
	.align 16
.L_2il0floatpacket.112:
	.long	0x432aff97,0x432aff97,0x432aff97,0x432aff97
	.type	.L_2il0floatpacket.112,@object
	.size	.L_2il0floatpacket.112,16
	.align 16
.L_2il0floatpacket.113:
	.long	0xab9423a7,0xab9423a7,0xab9423a7,0xab9423a7
	.type	.L_2il0floatpacket.113,@object
	.size	.L_2il0floatpacket.113,16
	.align 16
.L_2il0floatpacket.114:
	.long	0xfc93a039,0xfc93a039,0xfc93a039,0xfc93a039
	.type	.L_2il0floatpacket.114,@object
	.size	.L_2il0floatpacket.114,16
	.align 16
.L_2il0floatpacket.115:
	.long	0x655b59c3,0x655b59c3,0x655b59c3,0x655b59c3
	.type	.L_2il0floatpacket.115,@object
	.size	.L_2il0floatpacket.115,16
	.align 16
.L_2il0floatpacket.116:
	.long	0x8f0ccc92,0x8f0ccc92,0x8f0ccc92,0x8f0ccc92
	.type	.L_2il0floatpacket.116,@object
	.size	.L_2il0floatpacket.116,16
	.align 16
.L_2il0floatpacket.117:
	.long	0xffeff47d,0xffeff47d,0xffeff47d,0xffeff47d
	.type	.L_2il0floatpacket.117,@object
	.size	.L_2il0floatpacket.117,16
	.align 16
.L_2il0floatpacket.118:
	.long	0x85845dd1,0x85845dd1,0x85845dd1,0x85845dd1
	.type	.L_2il0floatpacket.118,@object
	.size	.L_2il0floatpacket.118,16
	.align 16
.L_2il0floatpacket.119:
	.long	0x6fa87e4f,0x6fa87e4f,0x6fa87e4f,0x6fa87e4f
	.type	.L_2il0floatpacket.119,@object
	.size	.L_2il0floatpacket.119,16
	.align 16
.L_2il0floatpacket.120:
	.long	0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0
	.type	.L_2il0floatpacket.120,@object
	.size	.L_2il0floatpacket.120,16
	.align 16
.L_2il0floatpacket.121:
	.long	0xa3014314,0xa3014314,0xa3014314,0xa3014314
	.type	.L_2il0floatpacket.121,@object
	.size	.L_2il0floatpacket.121,16
	.align 16
.L_2il0floatpacket.122:
	.long	0x4e0811a1,0x4e0811a1,0x4e0811a1,0x4e0811a1
	.type	.L_2il0floatpacket.122,@object
	.size	.L_2il0floatpacket.122,16
	.align 16
.L_2il0floatpacket.123:
	.long	0xf7537e82,0xf7537e82,0xf7537e82,0xf7537e82
	.type	.L_2il0floatpacket.123,@object
	.size	.L_2il0floatpacket.123,16
	.align 16
.L_2il0floatpacket.124:
	.long	0xbd3af235,0xbd3af235,0xbd3af235,0xbd3af235
	.type	.L_2il0floatpacket.124,@object
	.size	.L_2il0floatpacket.124,16
	.align 16
.L_2il0floatpacket.125:
	.long	0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb
	.type	.L_2il0floatpacket.125,@object
	.size	.L_2il0floatpacket.125,16
	.align 16
.L_2il0floatpacket.126:
	.long	0xeb86d391,0xeb86d391,0xeb86d391,0xeb86d391
	.type	.L_2il0floatpacket.126,@object
	.size	.L_2il0floatpacket.126,16
	.align 16
.L_2il0floatpacket.521:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.521,@object
	.size	.L_2il0floatpacket.521,16
	.align 16
.L_2il0floatpacket.522:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.522,@object
	.size	.L_2il0floatpacket.522,16
	.align 16
.L_2il0floatpacket.523:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.523,@object
	.size	.L_2il0floatpacket.523,16
	.align 16
.L_2il0floatpacket.524:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.524,@object
	.size	.L_2il0floatpacket.524,16
	.align 16
.L_2il0floatpacket.553:
	.long	0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0
	.type	.L_2il0floatpacket.553,@object
	.size	.L_2il0floatpacket.553,16
	.align 16
.L_2il0floatpacket.554:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.554,@object
	.size	.L_2il0floatpacket.554,16
	.align 16
.L_2il0floatpacket.555:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.555,@object
	.size	.L_2il0floatpacket.555,16
	.align 16
.L_2il0floatpacket.556:
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
	.type	.L_2il0floatpacket.556,@object
	.size	.L_2il0floatpacket.556,16
	.align 16
.L_2il0floatpacket.557:
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
	.type	.L_2il0floatpacket.557,@object
	.size	.L_2il0floatpacket.557,16
	.align 16
.L_2il0floatpacket.558:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.558,@object
	.size	.L_2il0floatpacket.558,16
	.align 16
.L_2il0floatpacket.559:
	.long	0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0
	.type	.L_2il0floatpacket.559,@object
	.size	.L_2il0floatpacket.559,16
	.align 16
.L_2il0floatpacket.564:
	.long	0x428a2f98,0x428a2f98,0x428a2f98,0x428a2f98
	.type	.L_2il0floatpacket.564,@object
	.size	.L_2il0floatpacket.564,16
	.align 16
.L_2il0floatpacket.565:
	.long	0x71374491,0x71374491,0x71374491,0x71374491
	.type	.L_2il0floatpacket.565,@object
	.size	.L_2il0floatpacket.565,16
	.align 16
.L_2il0floatpacket.566:
	.long	0xb5c0fbcf,0xb5c0fbcf,0xb5c0fbcf,0xb5c0fbcf
	.type	.L_2il0floatpacket.566,@object
	.size	.L_2il0floatpacket.566,16
	.align 16
.L_2il0floatpacket.567:
	.long	0xe9b5dba5,0xe9b5dba5,0xe9b5dba5,0xe9b5dba5
	.type	.L_2il0floatpacket.567,@object
	.size	.L_2il0floatpacket.567,16
	.align 16
.L_2il0floatpacket.568:
	.long	0x3956c25b,0x3956c25b,0x3956c25b,0x3956c25b
	.type	.L_2il0floatpacket.568,@object
	.size	.L_2il0floatpacket.568,16
	.align 16
.L_2il0floatpacket.569:
	.long	0x59f111f1,0x59f111f1,0x59f111f1,0x59f111f1
	.type	.L_2il0floatpacket.569,@object
	.size	.L_2il0floatpacket.569,16
	.align 16
.L_2il0floatpacket.570:
	.long	0x923f82a4,0x923f82a4,0x923f82a4,0x923f82a4
	.type	.L_2il0floatpacket.570,@object
	.size	.L_2il0floatpacket.570,16
	.align 16
.L_2il0floatpacket.571:
	.long	0xab1c5ed5,0xab1c5ed5,0xab1c5ed5,0xab1c5ed5
	.type	.L_2il0floatpacket.571,@object
	.size	.L_2il0floatpacket.571,16
	.align 16
.L_2il0floatpacket.572:
	.long	0xd807aa98,0xd807aa98,0xd807aa98,0xd807aa98
	.type	.L_2il0floatpacket.572,@object
	.size	.L_2il0floatpacket.572,16
	.align 16
.L_2il0floatpacket.573:
	.long	0x12835b01,0x12835b01,0x12835b01,0x12835b01
	.type	.L_2il0floatpacket.573,@object
	.size	.L_2il0floatpacket.573,16
	.align 16
.L_2il0floatpacket.574:
	.long	0x243185be,0x243185be,0x243185be,0x243185be
	.type	.L_2il0floatpacket.574,@object
	.size	.L_2il0floatpacket.574,16
	.align 16
.L_2il0floatpacket.575:
	.long	0x550c7dc3,0x550c7dc3,0x550c7dc3,0x550c7dc3
	.type	.L_2il0floatpacket.575,@object
	.size	.L_2il0floatpacket.575,16
	.align 16
.L_2il0floatpacket.576:
	.long	0x72be5d74,0x72be5d74,0x72be5d74,0x72be5d74
	.type	.L_2il0floatpacket.576,@object
	.size	.L_2il0floatpacket.576,16
	.align 16
.L_2il0floatpacket.577:
	.long	0x80deb1fe,0x80deb1fe,0x80deb1fe,0x80deb1fe
	.type	.L_2il0floatpacket.577,@object
	.size	.L_2il0floatpacket.577,16
	.align 16
.L_2il0floatpacket.578:
	.long	0x9bdc06a7,0x9bdc06a7,0x9bdc06a7,0x9bdc06a7
	.type	.L_2il0floatpacket.578,@object
	.size	.L_2il0floatpacket.578,16
	.align 16
.L_2il0floatpacket.579:
	.long	0xc19bf174,0xc19bf174,0xc19bf174,0xc19bf174
	.type	.L_2il0floatpacket.579,@object
	.size	.L_2il0floatpacket.579,16
	.align 16
.L_2il0floatpacket.580:
	.long	0xe49b69c1,0xe49b69c1,0xe49b69c1,0xe49b69c1
	.type	.L_2il0floatpacket.580,@object
	.size	.L_2il0floatpacket.580,16
	.align 16
.L_2il0floatpacket.581:
	.long	0xefbe4786,0xefbe4786,0xefbe4786,0xefbe4786
	.type	.L_2il0floatpacket.581,@object
	.size	.L_2il0floatpacket.581,16
	.align 16
.L_2il0floatpacket.582:
	.long	0x0fc19dc6,0x0fc19dc6,0x0fc19dc6,0x0fc19dc6
	.type	.L_2il0floatpacket.582,@object
	.size	.L_2il0floatpacket.582,16
	.align 16
.L_2il0floatpacket.583:
	.long	0x240ca1cc,0x240ca1cc,0x240ca1cc,0x240ca1cc
	.type	.L_2il0floatpacket.583,@object
	.size	.L_2il0floatpacket.583,16
	.align 16
.L_2il0floatpacket.584:
	.long	0x2de92c6f,0x2de92c6f,0x2de92c6f,0x2de92c6f
	.type	.L_2il0floatpacket.584,@object
	.size	.L_2il0floatpacket.584,16
	.align 16
.L_2il0floatpacket.585:
	.long	0x4a7484aa,0x4a7484aa,0x4a7484aa,0x4a7484aa
	.type	.L_2il0floatpacket.585,@object
	.size	.L_2il0floatpacket.585,16
	.align 16
.L_2il0floatpacket.586:
	.long	0x5cb0a9dc,0x5cb0a9dc,0x5cb0a9dc,0x5cb0a9dc
	.type	.L_2il0floatpacket.586,@object
	.size	.L_2il0floatpacket.586,16
	.align 16
.L_2il0floatpacket.587:
	.long	0x76f988da,0x76f988da,0x76f988da,0x76f988da
	.type	.L_2il0floatpacket.587,@object
	.size	.L_2il0floatpacket.587,16
	.align 16
.L_2il0floatpacket.588:
	.long	0x983e5152,0x983e5152,0x983e5152,0x983e5152
	.type	.L_2il0floatpacket.588,@object
	.size	.L_2il0floatpacket.588,16
	.align 16
.L_2il0floatpacket.589:
	.long	0xa831c66d,0xa831c66d,0xa831c66d,0xa831c66d
	.type	.L_2il0floatpacket.589,@object
	.size	.L_2il0floatpacket.589,16
	.align 16
.L_2il0floatpacket.590:
	.long	0xb00327c8,0xb00327c8,0xb00327c8,0xb00327c8
	.type	.L_2il0floatpacket.590,@object
	.size	.L_2il0floatpacket.590,16
	.align 16
.L_2il0floatpacket.591:
	.long	0xbf597fc7,0xbf597fc7,0xbf597fc7,0xbf597fc7
	.type	.L_2il0floatpacket.591,@object
	.size	.L_2il0floatpacket.591,16
	.align 16
.L_2il0floatpacket.592:
	.long	0xc6e00bf3,0xc6e00bf3,0xc6e00bf3,0xc6e00bf3
	.type	.L_2il0floatpacket.592,@object
	.size	.L_2il0floatpacket.592,16
	.align 16
.L_2il0floatpacket.593:
	.long	0xd5a79147,0xd5a79147,0xd5a79147,0xd5a79147
	.type	.L_2il0floatpacket.593,@object
	.size	.L_2il0floatpacket.593,16
	.align 16
.L_2il0floatpacket.594:
	.long	0x06ca6351,0x06ca6351,0x06ca6351,0x06ca6351
	.type	.L_2il0floatpacket.594,@object
	.size	.L_2il0floatpacket.594,16
	.align 16
.L_2il0floatpacket.595:
	.long	0x14292967,0x14292967,0x14292967,0x14292967
	.type	.L_2il0floatpacket.595,@object
	.size	.L_2il0floatpacket.595,16
	.align 16
.L_2il0floatpacket.596:
	.long	0x27b70a85,0x27b70a85,0x27b70a85,0x27b70a85
	.type	.L_2il0floatpacket.596,@object
	.size	.L_2il0floatpacket.596,16
	.align 16
.L_2il0floatpacket.597:
	.long	0x2e1b2138,0x2e1b2138,0x2e1b2138,0x2e1b2138
	.type	.L_2il0floatpacket.597,@object
	.size	.L_2il0floatpacket.597,16
	.align 16
.L_2il0floatpacket.598:
	.long	0x4d2c6dfc,0x4d2c6dfc,0x4d2c6dfc,0x4d2c6dfc
	.type	.L_2il0floatpacket.598,@object
	.size	.L_2il0floatpacket.598,16
	.align 16
.L_2il0floatpacket.599:
	.long	0x53380d13,0x53380d13,0x53380d13,0x53380d13
	.type	.L_2il0floatpacket.599,@object
	.size	.L_2il0floatpacket.599,16
	.align 16
.L_2il0floatpacket.600:
	.long	0x650a7354,0x650a7354,0x650a7354,0x650a7354
	.type	.L_2il0floatpacket.600,@object
	.size	.L_2il0floatpacket.600,16
	.align 16
.L_2il0floatpacket.601:
	.long	0x766a0abb,0x766a0abb,0x766a0abb,0x766a0abb
	.type	.L_2il0floatpacket.601,@object
	.size	.L_2il0floatpacket.601,16
	.align 16
.L_2il0floatpacket.602:
	.long	0x81c2c92e,0x81c2c92e,0x81c2c92e,0x81c2c92e
	.type	.L_2il0floatpacket.602,@object
	.size	.L_2il0floatpacket.602,16
	.align 16
.L_2il0floatpacket.603:
	.long	0x92722c85,0x92722c85,0x92722c85,0x92722c85
	.type	.L_2il0floatpacket.603,@object
	.size	.L_2il0floatpacket.603,16
	.align 16
.L_2il0floatpacket.604:
	.long	0xa2bfe8a1,0xa2bfe8a1,0xa2bfe8a1,0xa2bfe8a1
	.type	.L_2il0floatpacket.604,@object
	.size	.L_2il0floatpacket.604,16
	.align 16
.L_2il0floatpacket.605:
	.long	0xa81a664b,0xa81a664b,0xa81a664b,0xa81a664b
	.type	.L_2il0floatpacket.605,@object
	.size	.L_2il0floatpacket.605,16
	.align 16
.L_2il0floatpacket.606:
	.long	0xc24b8b70,0xc24b8b70,0xc24b8b70,0xc24b8b70
	.type	.L_2il0floatpacket.606,@object
	.size	.L_2il0floatpacket.606,16
	.align 16
.L_2il0floatpacket.607:
	.long	0xc76c51a3,0xc76c51a3,0xc76c51a3,0xc76c51a3
	.type	.L_2il0floatpacket.607,@object
	.size	.L_2il0floatpacket.607,16
	.align 16
.L_2il0floatpacket.608:
	.long	0xd192e819,0xd192e819,0xd192e819,0xd192e819
	.type	.L_2il0floatpacket.608,@object
	.size	.L_2il0floatpacket.608,16
	.align 16
.L_2il0floatpacket.609:
	.long	0xd6990624,0xd6990624,0xd6990624,0xd6990624
	.type	.L_2il0floatpacket.609,@object
	.size	.L_2il0floatpacket.609,16
	.align 16
.L_2il0floatpacket.610:
	.long	0xf40e3585,0xf40e3585,0xf40e3585,0xf40e3585
	.type	.L_2il0floatpacket.610,@object
	.size	.L_2il0floatpacket.610,16
	.align 16
.L_2il0floatpacket.611:
	.long	0x106aa070,0x106aa070,0x106aa070,0x106aa070
	.type	.L_2il0floatpacket.611,@object
	.size	.L_2il0floatpacket.611,16
	.align 16
.L_2il0floatpacket.612:
	.long	0x19a4c116,0x19a4c116,0x19a4c116,0x19a4c116
	.type	.L_2il0floatpacket.612,@object
	.size	.L_2il0floatpacket.612,16
	.align 16
.L_2il0floatpacket.613:
	.long	0x1e376c08,0x1e376c08,0x1e376c08,0x1e376c08
	.type	.L_2il0floatpacket.613,@object
	.size	.L_2il0floatpacket.613,16
	.align 16
.L_2il0floatpacket.614:
	.long	0x2748774c,0x2748774c,0x2748774c,0x2748774c
	.type	.L_2il0floatpacket.614,@object
	.size	.L_2il0floatpacket.614,16
	.align 16
.L_2il0floatpacket.615:
	.long	0x34b0bcb5,0x34b0bcb5,0x34b0bcb5,0x34b0bcb5
	.type	.L_2il0floatpacket.615,@object
	.size	.L_2il0floatpacket.615,16
	.align 16
.L_2il0floatpacket.616:
	.long	0x391c0cb3,0x391c0cb3,0x391c0cb3,0x391c0cb3
	.type	.L_2il0floatpacket.616,@object
	.size	.L_2il0floatpacket.616,16
	.align 16
.L_2il0floatpacket.617:
	.long	0x4ed8aa4a,0x4ed8aa4a,0x4ed8aa4a,0x4ed8aa4a
	.type	.L_2il0floatpacket.617,@object
	.size	.L_2il0floatpacket.617,16
	.align 16
.L_2il0floatpacket.618:
	.long	0x5b9cca4f,0x5b9cca4f,0x5b9cca4f,0x5b9cca4f
	.type	.L_2il0floatpacket.618,@object
	.size	.L_2il0floatpacket.618,16
	.align 16
.L_2il0floatpacket.619:
	.long	0x682e6ff3,0x682e6ff3,0x682e6ff3,0x682e6ff3
	.type	.L_2il0floatpacket.619,@object
	.size	.L_2il0floatpacket.619,16
	.align 16
.L_2il0floatpacket.620:
	.long	0x748f82ee,0x748f82ee,0x748f82ee,0x748f82ee
	.type	.L_2il0floatpacket.620,@object
	.size	.L_2il0floatpacket.620,16
	.align 16
.L_2il0floatpacket.621:
	.long	0x78a5636f,0x78a5636f,0x78a5636f,0x78a5636f
	.type	.L_2il0floatpacket.621,@object
	.size	.L_2il0floatpacket.621,16
	.align 16
.L_2il0floatpacket.622:
	.long	0x84c87814,0x84c87814,0x84c87814,0x84c87814
	.type	.L_2il0floatpacket.622,@object
	.size	.L_2il0floatpacket.622,16
	.align 16
.L_2il0floatpacket.623:
	.long	0x8cc70208,0x8cc70208,0x8cc70208,0x8cc70208
	.type	.L_2il0floatpacket.623,@object
	.size	.L_2il0floatpacket.623,16
	.align 16
.L_2il0floatpacket.624:
	.long	0x90befffa,0x90befffa,0x90befffa,0x90befffa
	.type	.L_2il0floatpacket.624,@object
	.size	.L_2il0floatpacket.624,16
	.align 16
.L_2il0floatpacket.625:
	.long	0xa4506ceb,0xa4506ceb,0xa4506ceb,0xa4506ceb
	.type	.L_2il0floatpacket.625,@object
	.size	.L_2il0floatpacket.625,16
	.align 16
.L_2il0floatpacket.626:
	.long	0xbef9a3f7,0xbef9a3f7,0xbef9a3f7,0xbef9a3f7
	.type	.L_2il0floatpacket.626,@object
	.size	.L_2il0floatpacket.626,16
	.align 16
.L_2il0floatpacket.627:
	.long	0xc67178f2,0xc67178f2,0xc67178f2,0xc67178f2
	.type	.L_2il0floatpacket.627,@object
	.size	.L_2il0floatpacket.627,16
	.align 16
.L_2il0floatpacket.628:
	.long	0xc1059ed8,0xc1059ed8,0xc1059ed8,0xc1059ed8
	.type	.L_2il0floatpacket.628,@object
	.size	.L_2il0floatpacket.628,16
	.align 16
.L_2il0floatpacket.629:
	.long	0x367cd507,0x367cd507,0x367cd507,0x367cd507
	.type	.L_2il0floatpacket.629,@object
	.size	.L_2il0floatpacket.629,16
	.align 16
.L_2il0floatpacket.630:
	.long	0x3070dd17,0x3070dd17,0x3070dd17,0x3070dd17
	.type	.L_2il0floatpacket.630,@object
	.size	.L_2il0floatpacket.630,16
	.align 16
.L_2il0floatpacket.631:
	.long	0xf70e5939,0xf70e5939,0xf70e5939,0xf70e5939
	.type	.L_2il0floatpacket.631,@object
	.size	.L_2il0floatpacket.631,16
	.align 16
.L_2il0floatpacket.632:
	.long	0xffc00b31,0xffc00b31,0xffc00b31,0xffc00b31
	.type	.L_2il0floatpacket.632,@object
	.size	.L_2il0floatpacket.632,16
	.align 16
.L_2il0floatpacket.633:
	.long	0x68581511,0x68581511,0x68581511,0x68581511
	.type	.L_2il0floatpacket.633,@object
	.size	.L_2il0floatpacket.633,16
	.align 16
.L_2il0floatpacket.634:
	.long	0x64f98fa7,0x64f98fa7,0x64f98fa7,0x64f98fa7
	.type	.L_2il0floatpacket.634,@object
	.size	.L_2il0floatpacket.634,16
	.align 16
.L_2il0floatpacket.635:
	.long	0xbefa4fa4,0xbefa4fa4,0xbefa4fa4,0xbefa4fa4
	.type	.L_2il0floatpacket.635,@object
	.size	.L_2il0floatpacket.635,16
	.align 16
.L_2il0floatpacket.636:
	.long	0x6a09e667,0x6a09e667,0x6a09e667,0x6a09e667
	.type	.L_2il0floatpacket.636,@object
	.size	.L_2il0floatpacket.636,16
	.align 16
.L_2il0floatpacket.637:
	.long	0xbb67ae85,0xbb67ae85,0xbb67ae85,0xbb67ae85
	.type	.L_2il0floatpacket.637,@object
	.size	.L_2il0floatpacket.637,16
	.align 16
.L_2il0floatpacket.638:
	.long	0x3c6ef372,0x3c6ef372,0x3c6ef372,0x3c6ef372
	.type	.L_2il0floatpacket.638,@object
	.size	.L_2il0floatpacket.638,16
	.align 16
.L_2il0floatpacket.639:
	.long	0xa54ff53a,0xa54ff53a,0xa54ff53a,0xa54ff53a
	.type	.L_2il0floatpacket.639,@object
	.size	.L_2il0floatpacket.639,16
	.align 16
.L_2il0floatpacket.640:
	.long	0x510e527f,0x510e527f,0x510e527f,0x510e527f
	.type	.L_2il0floatpacket.640,@object
	.size	.L_2il0floatpacket.640,16
	.align 16
.L_2il0floatpacket.641:
	.long	0x9b05688c,0x9b05688c,0x9b05688c,0x9b05688c
	.type	.L_2il0floatpacket.641,@object
	.size	.L_2il0floatpacket.641,16
	.align 16
.L_2il0floatpacket.642:
	.long	0x1f83d9ab,0x1f83d9ab,0x1f83d9ab,0x1f83d9ab
	.type	.L_2il0floatpacket.642,@object
	.size	.L_2il0floatpacket.642,16
	.align 16
.L_2il0floatpacket.643:
	.long	0x5be0cd19,0x5be0cd19,0x5be0cd19,0x5be0cd19
	.type	.L_2il0floatpacket.643,@object
	.size	.L_2il0floatpacket.643,16
	.align 16
.L_2il0floatpacket.644:
	.long	0xc1059ed8,0xc1059ed8,0xc1059ed8,0xc1059ed8
	.type	.L_2il0floatpacket.644,@object
	.size	.L_2il0floatpacket.644,16
	.align 16
.L_2il0floatpacket.645:
	.long	0x367cd507,0x367cd507,0x367cd507,0x367cd507
	.type	.L_2il0floatpacket.645,@object
	.size	.L_2il0floatpacket.645,16
	.align 16
.L_2il0floatpacket.646:
	.long	0x3070dd17,0x3070dd17,0x3070dd17,0x3070dd17
	.type	.L_2il0floatpacket.646,@object
	.size	.L_2il0floatpacket.646,16
	.align 16
.L_2il0floatpacket.647:
	.long	0xf70e5939,0xf70e5939,0xf70e5939,0xf70e5939
	.type	.L_2il0floatpacket.647,@object
	.size	.L_2il0floatpacket.647,16
	.align 16
.L_2il0floatpacket.648:
	.long	0xffc00b31,0xffc00b31,0xffc00b31,0xffc00b31
	.type	.L_2il0floatpacket.648,@object
	.size	.L_2il0floatpacket.648,16
	.align 16
.L_2il0floatpacket.649:
	.long	0x68581511,0x68581511,0x68581511,0x68581511
	.type	.L_2il0floatpacket.649,@object
	.size	.L_2il0floatpacket.649,16
	.align 16
.L_2il0floatpacket.650:
	.long	0x64f98fa7,0x64f98fa7,0x64f98fa7,0x64f98fa7
	.type	.L_2il0floatpacket.650,@object
	.size	.L_2il0floatpacket.650,16
	.align 16
.L_2il0floatpacket.651:
	.long	0xbefa4fa4,0xbefa4fa4,0xbefa4fa4,0xbefa4fa4
	.type	.L_2il0floatpacket.651,@object
	.size	.L_2il0floatpacket.651,16
	.align 16
.L_2il0floatpacket.652:
	.long	0x6a09e667,0x6a09e667,0x6a09e667,0x6a09e667
	.type	.L_2il0floatpacket.652,@object
	.size	.L_2il0floatpacket.652,16
	.align 16
.L_2il0floatpacket.653:
	.long	0xbb67ae85,0xbb67ae85,0xbb67ae85,0xbb67ae85
	.type	.L_2il0floatpacket.653,@object
	.size	.L_2il0floatpacket.653,16
	.align 16
.L_2il0floatpacket.654:
	.long	0x3c6ef372,0x3c6ef372,0x3c6ef372,0x3c6ef372
	.type	.L_2il0floatpacket.654,@object
	.size	.L_2il0floatpacket.654,16
	.align 16
.L_2il0floatpacket.655:
	.long	0xa54ff53a,0xa54ff53a,0xa54ff53a,0xa54ff53a
	.type	.L_2il0floatpacket.655,@object
	.size	.L_2il0floatpacket.655,16
	.align 16
.L_2il0floatpacket.656:
	.long	0x510e527f,0x510e527f,0x510e527f,0x510e527f
	.type	.L_2il0floatpacket.656,@object
	.size	.L_2il0floatpacket.656,16
	.align 16
.L_2il0floatpacket.657:
	.long	0x9b05688c,0x9b05688c,0x9b05688c,0x9b05688c
	.type	.L_2il0floatpacket.657,@object
	.size	.L_2il0floatpacket.657,16
	.align 16
.L_2il0floatpacket.658:
	.long	0x1f83d9ab,0x1f83d9ab,0x1f83d9ab,0x1f83d9ab
	.type	.L_2il0floatpacket.658,@object
	.size	.L_2il0floatpacket.658,16
	.align 16
.L_2il0floatpacket.659:
	.long	0x5be0cd19,0x5be0cd19,0x5be0cd19,0x5be0cd19
	.type	.L_2il0floatpacket.659,@object
	.size	.L_2il0floatpacket.659,16
	.align 16
.L_2il0floatpacket.664:
	.long	0xd728ae22,0x428a2f98,0xd728ae22,0x428a2f98
	.type	.L_2il0floatpacket.664,@object
	.size	.L_2il0floatpacket.664,16
	.align 16
.L_2il0floatpacket.665:
	.long	0x23ef65cd,0x71374491,0x23ef65cd,0x71374491
	.type	.L_2il0floatpacket.665,@object
	.size	.L_2il0floatpacket.665,16
	.align 16
.L_2il0floatpacket.666:
	.long	0xec4d3b2f,0xb5c0fbcf,0xec4d3b2f,0xb5c0fbcf
	.type	.L_2il0floatpacket.666,@object
	.size	.L_2il0floatpacket.666,16
	.align 16
.L_2il0floatpacket.667:
	.long	0x8189dbbc,0xe9b5dba5,0x8189dbbc,0xe9b5dba5
	.type	.L_2il0floatpacket.667,@object
	.size	.L_2il0floatpacket.667,16
	.align 16
.L_2il0floatpacket.668:
	.long	0xf348b538,0x3956c25b,0xf348b538,0x3956c25b
	.type	.L_2il0floatpacket.668,@object
	.size	.L_2il0floatpacket.668,16
	.align 16
.L_2il0floatpacket.669:
	.long	0xb605d019,0x59f111f1,0xb605d019,0x59f111f1
	.type	.L_2il0floatpacket.669,@object
	.size	.L_2il0floatpacket.669,16
	.align 16
.L_2il0floatpacket.670:
	.long	0xaf194f9b,0x923f82a4,0xaf194f9b,0x923f82a4
	.type	.L_2il0floatpacket.670,@object
	.size	.L_2il0floatpacket.670,16
	.align 16
.L_2il0floatpacket.671:
	.long	0xda6d8118,0xab1c5ed5,0xda6d8118,0xab1c5ed5
	.type	.L_2il0floatpacket.671,@object
	.size	.L_2il0floatpacket.671,16
	.align 16
.L_2il0floatpacket.672:
	.long	0xa3030242,0xd807aa98,0xa3030242,0xd807aa98
	.type	.L_2il0floatpacket.672,@object
	.size	.L_2il0floatpacket.672,16
	.align 16
.L_2il0floatpacket.673:
	.long	0x45706fbe,0x12835b01,0x45706fbe,0x12835b01
	.type	.L_2il0floatpacket.673,@object
	.size	.L_2il0floatpacket.673,16
	.align 16
.L_2il0floatpacket.674:
	.long	0x4ee4b28c,0x243185be,0x4ee4b28c,0x243185be
	.type	.L_2il0floatpacket.674,@object
	.size	.L_2il0floatpacket.674,16
	.align 16
.L_2il0floatpacket.675:
	.long	0xd5ffb4e2,0x550c7dc3,0xd5ffb4e2,0x550c7dc3
	.type	.L_2il0floatpacket.675,@object
	.size	.L_2il0floatpacket.675,16
	.align 16
.L_2il0floatpacket.676:
	.long	0xf27b896f,0x72be5d74,0xf27b896f,0x72be5d74
	.type	.L_2il0floatpacket.676,@object
	.size	.L_2il0floatpacket.676,16
	.align 16
.L_2il0floatpacket.677:
	.long	0x3b1696b1,0x80deb1fe,0x3b1696b1,0x80deb1fe
	.type	.L_2il0floatpacket.677,@object
	.size	.L_2il0floatpacket.677,16
	.align 16
.L_2il0floatpacket.678:
	.long	0x25c71235,0x9bdc06a7,0x25c71235,0x9bdc06a7
	.type	.L_2il0floatpacket.678,@object
	.size	.L_2il0floatpacket.678,16
	.align 16
.L_2il0floatpacket.679:
	.long	0xcf692694,0xc19bf174,0xcf692694,0xc19bf174
	.type	.L_2il0floatpacket.679,@object
	.size	.L_2il0floatpacket.679,16
	.align 16
.L_2il0floatpacket.680:
	.long	0x9ef14ad2,0xe49b69c1,0x9ef14ad2,0xe49b69c1
	.type	.L_2il0floatpacket.680,@object
	.size	.L_2il0floatpacket.680,16
	.align 16
.L_2il0floatpacket.681:
	.long	0x384f25e3,0xefbe4786,0x384f25e3,0xefbe4786
	.type	.L_2il0floatpacket.681,@object
	.size	.L_2il0floatpacket.681,16
	.align 16
.L_2il0floatpacket.682:
	.long	0x8b8cd5b5,0x0fc19dc6,0x8b8cd5b5,0x0fc19dc6
	.type	.L_2il0floatpacket.682,@object
	.size	.L_2il0floatpacket.682,16
	.align 16
.L_2il0floatpacket.683:
	.long	0x77ac9c65,0x240ca1cc,0x77ac9c65,0x240ca1cc
	.type	.L_2il0floatpacket.683,@object
	.size	.L_2il0floatpacket.683,16
	.align 16
.L_2il0floatpacket.684:
	.long	0x592b0275,0x2de92c6f,0x592b0275,0x2de92c6f
	.type	.L_2il0floatpacket.684,@object
	.size	.L_2il0floatpacket.684,16
	.align 16
.L_2il0floatpacket.685:
	.long	0x6ea6e483,0x4a7484aa,0x6ea6e483,0x4a7484aa
	.type	.L_2il0floatpacket.685,@object
	.size	.L_2il0floatpacket.685,16
	.align 16
.L_2il0floatpacket.686:
	.long	0xbd41fbd4,0x5cb0a9dc,0xbd41fbd4,0x5cb0a9dc
	.type	.L_2il0floatpacket.686,@object
	.size	.L_2il0floatpacket.686,16
	.align 16
.L_2il0floatpacket.687:
	.long	0x831153b5,0x76f988da,0x831153b5,0x76f988da
	.type	.L_2il0floatpacket.687,@object
	.size	.L_2il0floatpacket.687,16
	.align 16
.L_2il0floatpacket.688:
	.long	0xee66dfab,0x983e5152,0xee66dfab,0x983e5152
	.type	.L_2il0floatpacket.688,@object
	.size	.L_2il0floatpacket.688,16
	.align 16
.L_2il0floatpacket.689:
	.long	0x2db43210,0xa831c66d,0x2db43210,0xa831c66d
	.type	.L_2il0floatpacket.689,@object
	.size	.L_2il0floatpacket.689,16
	.align 16
.L_2il0floatpacket.690:
	.long	0x98fb213f,0xb00327c8,0x98fb213f,0xb00327c8
	.type	.L_2il0floatpacket.690,@object
	.size	.L_2il0floatpacket.690,16
	.align 16
.L_2il0floatpacket.691:
	.long	0xbeef0ee4,0xbf597fc7,0xbeef0ee4,0xbf597fc7
	.type	.L_2il0floatpacket.691,@object
	.size	.L_2il0floatpacket.691,16
	.align 16
.L_2il0floatpacket.692:
	.long	0x3da88fc2,0xc6e00bf3,0x3da88fc2,0xc6e00bf3
	.type	.L_2il0floatpacket.692,@object
	.size	.L_2il0floatpacket.692,16
	.align 16
.L_2il0floatpacket.693:
	.long	0x930aa725,0xd5a79147,0x930aa725,0xd5a79147
	.type	.L_2il0floatpacket.693,@object
	.size	.L_2il0floatpacket.693,16
	.align 16
.L_2il0floatpacket.694:
	.long	0xe003826f,0x06ca6351,0xe003826f,0x06ca6351
	.type	.L_2il0floatpacket.694,@object
	.size	.L_2il0floatpacket.694,16
	.align 16
.L_2il0floatpacket.695:
	.long	0x0a0e6e70,0x14292967,0x0a0e6e70,0x14292967
	.type	.L_2il0floatpacket.695,@object
	.size	.L_2il0floatpacket.695,16
	.align 16
.L_2il0floatpacket.696:
	.long	0x46d22ffc,0x27b70a85,0x46d22ffc,0x27b70a85
	.type	.L_2il0floatpacket.696,@object
	.size	.L_2il0floatpacket.696,16
	.align 16
.L_2il0floatpacket.697:
	.long	0x5c26c926,0x2e1b2138,0x5c26c926,0x2e1b2138
	.type	.L_2il0floatpacket.697,@object
	.size	.L_2il0floatpacket.697,16
	.align 16
.L_2il0floatpacket.698:
	.long	0x5ac42aed,0x4d2c6dfc,0x5ac42aed,0x4d2c6dfc
	.type	.L_2il0floatpacket.698,@object
	.size	.L_2il0floatpacket.698,16
	.align 16
.L_2il0floatpacket.699:
	.long	0x9d95b3df,0x53380d13,0x9d95b3df,0x53380d13
	.type	.L_2il0floatpacket.699,@object
	.size	.L_2il0floatpacket.699,16
	.align 16
.L_2il0floatpacket.700:
	.long	0x8baf63de,0x650a7354,0x8baf63de,0x650a7354
	.type	.L_2il0floatpacket.700,@object
	.size	.L_2il0floatpacket.700,16
	.align 16
.L_2il0floatpacket.701:
	.long	0x3c77b2a8,0x766a0abb,0x3c77b2a8,0x766a0abb
	.type	.L_2il0floatpacket.701,@object
	.size	.L_2il0floatpacket.701,16
	.align 16
.L_2il0floatpacket.702:
	.long	0x47edaee6,0x81c2c92e,0x47edaee6,0x81c2c92e
	.type	.L_2il0floatpacket.702,@object
	.size	.L_2il0floatpacket.702,16
	.align 16
.L_2il0floatpacket.703:
	.long	0x1482353b,0x92722c85,0x1482353b,0x92722c85
	.type	.L_2il0floatpacket.703,@object
	.size	.L_2il0floatpacket.703,16
	.align 16
.L_2il0floatpacket.704:
	.long	0x4cf10364,0xa2bfe8a1,0x4cf10364,0xa2bfe8a1
	.type	.L_2il0floatpacket.704,@object
	.size	.L_2il0floatpacket.704,16
	.align 16
.L_2il0floatpacket.705:
	.long	0xbc423001,0xa81a664b,0xbc423001,0xa81a664b
	.type	.L_2il0floatpacket.705,@object
	.size	.L_2il0floatpacket.705,16
	.align 16
.L_2il0floatpacket.706:
	.long	0xd0f89791,0xc24b8b70,0xd0f89791,0xc24b8b70
	.type	.L_2il0floatpacket.706,@object
	.size	.L_2il0floatpacket.706,16
	.align 16
.L_2il0floatpacket.707:
	.long	0x0654be30,0xc76c51a3,0x0654be30,0xc76c51a3
	.type	.L_2il0floatpacket.707,@object
	.size	.L_2il0floatpacket.707,16
	.align 16
.L_2il0floatpacket.708:
	.long	0xd6ef5218,0xd192e819,0xd6ef5218,0xd192e819
	.type	.L_2il0floatpacket.708,@object
	.size	.L_2il0floatpacket.708,16
	.align 16
.L_2il0floatpacket.709:
	.long	0x5565a910,0xd6990624,0x5565a910,0xd6990624
	.type	.L_2il0floatpacket.709,@object
	.size	.L_2il0floatpacket.709,16
	.align 16
.L_2il0floatpacket.710:
	.long	0x5771202a,0xf40e3585,0x5771202a,0xf40e3585
	.type	.L_2il0floatpacket.710,@object
	.size	.L_2il0floatpacket.710,16
	.align 16
.L_2il0floatpacket.711:
	.long	0x32bbd1b8,0x106aa070,0x32bbd1b8,0x106aa070
	.type	.L_2il0floatpacket.711,@object
	.size	.L_2il0floatpacket.711,16
	.align 16
.L_2il0floatpacket.712:
	.long	0xb8d2d0c8,0x19a4c116,0xb8d2d0c8,0x19a4c116
	.type	.L_2il0floatpacket.712,@object
	.size	.L_2il0floatpacket.712,16
	.align 16
.L_2il0floatpacket.713:
	.long	0x5141ab53,0x1e376c08,0x5141ab53,0x1e376c08
	.type	.L_2il0floatpacket.713,@object
	.size	.L_2il0floatpacket.713,16
	.align 16
.L_2il0floatpacket.714:
	.long	0xdf8eeb99,0x2748774c,0xdf8eeb99,0x2748774c
	.type	.L_2il0floatpacket.714,@object
	.size	.L_2il0floatpacket.714,16
	.align 16
.L_2il0floatpacket.715:
	.long	0xe19b48a8,0x34b0bcb5,0xe19b48a8,0x34b0bcb5
	.type	.L_2il0floatpacket.715,@object
	.size	.L_2il0floatpacket.715,16
	.align 16
.L_2il0floatpacket.716:
	.long	0xc5c95a63,0x391c0cb3,0xc5c95a63,0x391c0cb3
	.type	.L_2il0floatpacket.716,@object
	.size	.L_2il0floatpacket.716,16
	.align 16
.L_2il0floatpacket.717:
	.long	0xe3418acb,0x4ed8aa4a,0xe3418acb,0x4ed8aa4a
	.type	.L_2il0floatpacket.717,@object
	.size	.L_2il0floatpacket.717,16
	.align 16
.L_2il0floatpacket.718:
	.long	0x7763e373,0x5b9cca4f,0x7763e373,0x5b9cca4f
	.type	.L_2il0floatpacket.718,@object
	.size	.L_2il0floatpacket.718,16
	.align 16
.L_2il0floatpacket.719:
	.long	0xd6b2b8a3,0x682e6ff3,0xd6b2b8a3,0x682e6ff3
	.type	.L_2il0floatpacket.719,@object
	.size	.L_2il0floatpacket.719,16
	.align 16
.L_2il0floatpacket.720:
	.long	0x5defb2fc,0x748f82ee,0x5defb2fc,0x748f82ee
	.type	.L_2il0floatpacket.720,@object
	.size	.L_2il0floatpacket.720,16
	.align 16
.L_2il0floatpacket.721:
	.long	0x43172f60,0x78a5636f,0x43172f60,0x78a5636f
	.type	.L_2il0floatpacket.721,@object
	.size	.L_2il0floatpacket.721,16
	.align 16
.L_2il0floatpacket.722:
	.long	0xa1f0ab72,0x84c87814,0xa1f0ab72,0x84c87814
	.type	.L_2il0floatpacket.722,@object
	.size	.L_2il0floatpacket.722,16
	.align 16
.L_2il0floatpacket.723:
	.long	0x1a6439ec,0x8cc70208,0x1a6439ec,0x8cc70208
	.type	.L_2il0floatpacket.723,@object
	.size	.L_2il0floatpacket.723,16
	.align 16
.L_2il0floatpacket.724:
	.long	0x23631e28,0x90befffa,0x23631e28,0x90befffa
	.type	.L_2il0floatpacket.724,@object
	.size	.L_2il0floatpacket.724,16
	.align 16
.L_2il0floatpacket.725:
	.long	0xde82bde9,0xa4506ceb,0xde82bde9,0xa4506ceb
	.type	.L_2il0floatpacket.725,@object
	.size	.L_2il0floatpacket.725,16
	.align 16
.L_2il0floatpacket.726:
	.long	0xb2c67915,0xbef9a3f7,0xb2c67915,0xbef9a3f7
	.type	.L_2il0floatpacket.726,@object
	.size	.L_2il0floatpacket.726,16
	.align 16
.L_2il0floatpacket.727:
	.long	0xe372532b,0xc67178f2,0xe372532b,0xc67178f2
	.type	.L_2il0floatpacket.727,@object
	.size	.L_2il0floatpacket.727,16
	.align 16
.L_2il0floatpacket.728:
	.long	0xea26619c,0xca273ece,0xea26619c,0xca273ece
	.type	.L_2il0floatpacket.728,@object
	.size	.L_2il0floatpacket.728,16
	.align 16
.L_2il0floatpacket.729:
	.long	0x21c0c207,0xd186b8c7,0x21c0c207,0xd186b8c7
	.type	.L_2il0floatpacket.729,@object
	.size	.L_2il0floatpacket.729,16
	.align 16
.L_2il0floatpacket.730:
	.long	0xcde0eb1e,0xeada7dd6,0xcde0eb1e,0xeada7dd6
	.type	.L_2il0floatpacket.730,@object
	.size	.L_2il0floatpacket.730,16
	.align 16
.L_2il0floatpacket.731:
	.long	0xee6ed178,0xf57d4f7f,0xee6ed178,0xf57d4f7f
	.type	.L_2il0floatpacket.731,@object
	.size	.L_2il0floatpacket.731,16
	.align 16
.L_2il0floatpacket.732:
	.long	0x72176fba,0x06f067aa,0x72176fba,0x06f067aa
	.type	.L_2il0floatpacket.732,@object
	.size	.L_2il0floatpacket.732,16
	.align 16
.L_2il0floatpacket.733:
	.long	0xa2c898a6,0x0a637dc5,0xa2c898a6,0x0a637dc5
	.type	.L_2il0floatpacket.733,@object
	.size	.L_2il0floatpacket.733,16
	.align 16
.L_2il0floatpacket.734:
	.long	0xbef90dae,0x113f9804,0xbef90dae,0x113f9804
	.type	.L_2il0floatpacket.734,@object
	.size	.L_2il0floatpacket.734,16
	.align 16
.L_2il0floatpacket.735:
	.long	0x131c471b,0x1b710b35,0x131c471b,0x1b710b35
	.type	.L_2il0floatpacket.735,@object
	.size	.L_2il0floatpacket.735,16
	.align 16
.L_2il0floatpacket.736:
	.long	0x23047d84,0x28db77f5,0x23047d84,0x28db77f5
	.type	.L_2il0floatpacket.736,@object
	.size	.L_2il0floatpacket.736,16
	.align 16
.L_2il0floatpacket.737:
	.long	0x40c72493,0x32caab7b,0x40c72493,0x32caab7b
	.type	.L_2il0floatpacket.737,@object
	.size	.L_2il0floatpacket.737,16
	.align 16
.L_2il0floatpacket.738:
	.long	0x15c9bebc,0x3c9ebe0a,0x15c9bebc,0x3c9ebe0a
	.type	.L_2il0floatpacket.738,@object
	.size	.L_2il0floatpacket.738,16
	.align 16
.L_2il0floatpacket.739:
	.long	0x9c100d4c,0x431d67c4,0x9c100d4c,0x431d67c4
	.type	.L_2il0floatpacket.739,@object
	.size	.L_2il0floatpacket.739,16
	.align 16
.L_2il0floatpacket.740:
	.long	0xcb3e42b6,0x4cc5d4be,0xcb3e42b6,0x4cc5d4be
	.type	.L_2il0floatpacket.740,@object
	.size	.L_2il0floatpacket.740,16
	.align 16
.L_2il0floatpacket.741:
	.long	0xfc657e2a,0x597f299c,0xfc657e2a,0x597f299c
	.type	.L_2il0floatpacket.741,@object
	.size	.L_2il0floatpacket.741,16
	.align 16
.L_2il0floatpacket.742:
	.long	0x3ad6faec,0x5fcb6fab,0x3ad6faec,0x5fcb6fab
	.type	.L_2il0floatpacket.742,@object
	.size	.L_2il0floatpacket.742,16
	.align 16
.L_2il0floatpacket.743:
	.long	0x4a475817,0x6c44198c,0x4a475817,0x6c44198c
	.type	.L_2il0floatpacket.743,@object
	.size	.L_2il0floatpacket.743,16
	.align 16
.L_2il0floatpacket.744:
	.long	0xc1059ed8,0xcbbb9d5d,0xc1059ed8,0xcbbb9d5d
	.type	.L_2il0floatpacket.744,@object
	.size	.L_2il0floatpacket.744,16
	.align 16
.L_2il0floatpacket.745:
	.long	0x367cd507,0x629a292a,0x367cd507,0x629a292a
	.type	.L_2il0floatpacket.745,@object
	.size	.L_2il0floatpacket.745,16
	.align 16
.L_2il0floatpacket.746:
	.long	0x3070dd17,0x9159015a,0x3070dd17,0x9159015a
	.type	.L_2il0floatpacket.746,@object
	.size	.L_2il0floatpacket.746,16
	.align 16
.L_2il0floatpacket.747:
	.long	0xf70e5939,0x152fecd8,0xf70e5939,0x152fecd8
	.type	.L_2il0floatpacket.747,@object
	.size	.L_2il0floatpacket.747,16
	.align 16
.L_2il0floatpacket.748:
	.long	0xffc00b31,0x67332667,0xffc00b31,0x67332667
	.type	.L_2il0floatpacket.748,@object
	.size	.L_2il0floatpacket.748,16
	.align 16
.L_2il0floatpacket.749:
	.long	0x68581511,0x8eb44a87,0x68581511,0x8eb44a87
	.type	.L_2il0floatpacket.749,@object
	.size	.L_2il0floatpacket.749,16
	.align 16
.L_2il0floatpacket.750:
	.long	0x64f98fa7,0xdb0c2e0d,0x64f98fa7,0xdb0c2e0d
	.type	.L_2il0floatpacket.750,@object
	.size	.L_2il0floatpacket.750,16
	.align 16
.L_2il0floatpacket.751:
	.long	0xbefa4fa4,0x47b5481d,0xbefa4fa4,0x47b5481d
	.type	.L_2il0floatpacket.751,@object
	.size	.L_2il0floatpacket.751,16
	.align 16
.L_2il0floatpacket.752:
	.long	0xf3bcc908,0x6a09e667,0xf3bcc908,0x6a09e667
	.type	.L_2il0floatpacket.752,@object
	.size	.L_2il0floatpacket.752,16
	.align 16
.L_2il0floatpacket.753:
	.long	0x84caa73b,0xbb67ae85,0x84caa73b,0xbb67ae85
	.type	.L_2il0floatpacket.753,@object
	.size	.L_2il0floatpacket.753,16
	.align 16
.L_2il0floatpacket.754:
	.long	0xfe94f82b,0x3c6ef372,0xfe94f82b,0x3c6ef372
	.type	.L_2il0floatpacket.754,@object
	.size	.L_2il0floatpacket.754,16
	.align 16
.L_2il0floatpacket.755:
	.long	0x5f1d36f1,0xa54ff53a,0x5f1d36f1,0xa54ff53a
	.type	.L_2il0floatpacket.755,@object
	.size	.L_2il0floatpacket.755,16
	.align 16
.L_2il0floatpacket.756:
	.long	0xade682d1,0x510e527f,0xade682d1,0x510e527f
	.type	.L_2il0floatpacket.756,@object
	.size	.L_2il0floatpacket.756,16
	.align 16
.L_2il0floatpacket.757:
	.long	0x2b3e6c1f,0x9b05688c,0x2b3e6c1f,0x9b05688c
	.type	.L_2il0floatpacket.757,@object
	.size	.L_2il0floatpacket.757,16
	.align 16
.L_2il0floatpacket.758:
	.long	0xfb41bd6b,0x1f83d9ab,0xfb41bd6b,0x1f83d9ab
	.type	.L_2il0floatpacket.758,@object
	.size	.L_2il0floatpacket.758,16
	.align 16
.L_2il0floatpacket.759:
	.long	0x137e2179,0x5be0cd19,0x137e2179,0x5be0cd19
	.type	.L_2il0floatpacket.759,@object
	.size	.L_2il0floatpacket.759,16
	.align 16
.L_2il0floatpacket.760:
	.long	0xc1059ed8,0xcbbb9d5d,0xc1059ed8,0xcbbb9d5d
	.type	.L_2il0floatpacket.760,@object
	.size	.L_2il0floatpacket.760,16
	.align 16
.L_2il0floatpacket.761:
	.long	0x367cd507,0x629a292a,0x367cd507,0x629a292a
	.type	.L_2il0floatpacket.761,@object
	.size	.L_2il0floatpacket.761,16
	.align 16
.L_2il0floatpacket.762:
	.long	0x3070dd17,0x9159015a,0x3070dd17,0x9159015a
	.type	.L_2il0floatpacket.762,@object
	.size	.L_2il0floatpacket.762,16
	.align 16
.L_2il0floatpacket.763:
	.long	0xf70e5939,0x152fecd8,0xf70e5939,0x152fecd8
	.type	.L_2il0floatpacket.763,@object
	.size	.L_2il0floatpacket.763,16
	.align 16
.L_2il0floatpacket.764:
	.long	0xffc00b31,0x67332667,0xffc00b31,0x67332667
	.type	.L_2il0floatpacket.764,@object
	.size	.L_2il0floatpacket.764,16
	.align 16
.L_2il0floatpacket.765:
	.long	0x68581511,0x8eb44a87,0x68581511,0x8eb44a87
	.type	.L_2il0floatpacket.765,@object
	.size	.L_2il0floatpacket.765,16
	.align 16
.L_2il0floatpacket.766:
	.long	0x64f98fa7,0xdb0c2e0d,0x64f98fa7,0xdb0c2e0d
	.type	.L_2il0floatpacket.766,@object
	.size	.L_2il0floatpacket.766,16
	.align 16
.L_2il0floatpacket.767:
	.long	0xbefa4fa4,0x47b5481d,0xbefa4fa4,0x47b5481d
	.type	.L_2il0floatpacket.767,@object
	.size	.L_2il0floatpacket.767,16
	.align 16
.L_2il0floatpacket.768:
	.long	0xf3bcc908,0x6a09e667,0xf3bcc908,0x6a09e667
	.type	.L_2il0floatpacket.768,@object
	.size	.L_2il0floatpacket.768,16
	.align 16
.L_2il0floatpacket.769:
	.long	0x84caa73b,0xbb67ae85,0x84caa73b,0xbb67ae85
	.type	.L_2il0floatpacket.769,@object
	.size	.L_2il0floatpacket.769,16
	.align 16
.L_2il0floatpacket.770:
	.long	0xfe94f82b,0x3c6ef372,0xfe94f82b,0x3c6ef372
	.type	.L_2il0floatpacket.770,@object
	.size	.L_2il0floatpacket.770,16
	.align 16
.L_2il0floatpacket.771:
	.long	0x5f1d36f1,0xa54ff53a,0x5f1d36f1,0xa54ff53a
	.type	.L_2il0floatpacket.771,@object
	.size	.L_2il0floatpacket.771,16
	.align 16
.L_2il0floatpacket.772:
	.long	0xade682d1,0x510e527f,0xade682d1,0x510e527f
	.type	.L_2il0floatpacket.772,@object
	.size	.L_2il0floatpacket.772,16
	.align 16
.L_2il0floatpacket.773:
	.long	0x2b3e6c1f,0x9b05688c,0x2b3e6c1f,0x9b05688c
	.type	.L_2il0floatpacket.773,@object
	.size	.L_2il0floatpacket.773,16
	.align 16
.L_2il0floatpacket.774:
	.long	0xfb41bd6b,0x1f83d9ab,0xfb41bd6b,0x1f83d9ab
	.type	.L_2il0floatpacket.774,@object
	.size	.L_2il0floatpacket.774,16
	.align 16
.L_2il0floatpacket.775:
	.long	0x137e2179,0x5be0cd19,0x137e2179,0x5be0cd19
	.type	.L_2il0floatpacket.775,@object
	.size	.L_2il0floatpacket.775,16
	.align 4
.L_2__STRING.3:
	.word	0
	.type	.L_2__STRING.3,@object
	.size	.L_2__STRING.3,2
	.section .rodata.str1.4, "aMS",@progbits,1
	.align 4
	.align 4
.L_2__STRING.2:
	.long	1919967524
	.word	9265
	.byte	0
	.type	.L_2__STRING.2,@object
	.size	.L_2__STRING.2,7
	.space 1, 0x00 	# pad
	.align 4
.L_2__STRING.1:
	.long	2371876
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
	.4byte 0x00000034
	.4byte 0x0000001c
	.8byte ..___tag_value_SIMDmd5body.1
	.8byte ..___tag_value_SIMDmd5body.7-..___tag_value_SIMDmd5body.1
	.byte 0x04
	.4byte ..___tag_value_SIMDmd5body.3-..___tag_value_SIMDmd5body.1
	.4byte 0x040c900e
	.4byte ..___tag_value_SIMDmd5body.4-..___tag_value_SIMDmd5body.3
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SIMDmd5body.5-..___tag_value_SIMDmd5body.4
	.4byte 0x040c900e
	.4byte ..___tag_value_SIMDmd5body.6-..___tag_value_SIMDmd5body.5
	.4byte 0x0000080e
	.4byte 0x00000024
	.4byte 0x00000054
	.8byte ..___tag_value_SIMDmd5body..0.8
	.8byte ..___tag_value_SIMDmd5body..0.12-..___tag_value_SIMDmd5body..0.8
	.byte 0x04
	.4byte ..___tag_value_SIMDmd5body..0.10-..___tag_value_SIMDmd5body..0.8
	.4byte 0x0406a00e
	.4byte ..___tag_value_SIMDmd5body..0.11-..___tag_value_SIMDmd5body..0.10
	.2byte 0x080e
	.byte 0x00
	.4byte 0x000000a4
	.4byte 0x0000007c
	.8byte ..___tag_value_md5cryptsse.13
	.8byte ..___tag_value_md5cryptsse.96-..___tag_value_md5cryptsse.13
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.15-..___tag_value_md5cryptsse.13
	.4byte 0x028c100e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.17-..___tag_value_md5cryptsse.15
	.4byte 0x038d180e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.19-..___tag_value_md5cryptsse.17
	.4byte 0x048e200e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.21-..___tag_value_md5cryptsse.19
	.4byte 0x058f280e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.23-..___tag_value_md5cryptsse.21
	.4byte 0x0683300e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.25-..___tag_value_md5cryptsse.23
	.4byte 0x0786380e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.27-..___tag_value_md5cryptsse.25
	.4byte 0x0435e00e
	.4byte ..___tag_value_md5cryptsse.76-..___tag_value_md5cryptsse.27
	.4byte 0x04c6380e
	.4byte ..___tag_value_md5cryptsse.78-..___tag_value_md5cryptsse.76
	.4byte 0x04c3300e
	.4byte ..___tag_value_md5cryptsse.80-..___tag_value_md5cryptsse.78
	.4byte 0x04cf280e
	.4byte ..___tag_value_md5cryptsse.82-..___tag_value_md5cryptsse.80
	.4byte 0x04ce200e
	.4byte ..___tag_value_md5cryptsse.84-..___tag_value_md5cryptsse.82
	.4byte 0x04cd180e
	.4byte ..___tag_value_md5cryptsse.86-..___tag_value_md5cryptsse.84
	.4byte 0x04cc100e
	.4byte ..___tag_value_md5cryptsse.88-..___tag_value_md5cryptsse.86
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.89-..___tag_value_md5cryptsse.88
	.8byte 0x8c0786068335e00e
	.8byte 0x00058f048e038d02
	.4byte 0x00000000
	.2byte 0x0000
	.4byte 0x00000034
	.4byte 0x00000124
	.8byte ..___tag_value_SIMDmd4body.97
	.8byte ..___tag_value_SIMDmd4body.103-..___tag_value_SIMDmd4body.97
	.byte 0x04
	.4byte ..___tag_value_SIMDmd4body.99-..___tag_value_SIMDmd4body.97
	.4byte 0x040c900e
	.4byte ..___tag_value_SIMDmd4body.100-..___tag_value_SIMDmd4body.99
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SIMDmd4body.101-..___tag_value_SIMDmd4body.100
	.4byte 0x040c900e
	.4byte ..___tag_value_SIMDmd4body.102-..___tag_value_SIMDmd4body.101
	.4byte 0x0000080e
	.4byte 0x00000024
	.4byte 0x0000015c
	.8byte ..___tag_value_SIMDSHA1body.104
	.8byte ..___tag_value_SIMDSHA1body.108-..___tag_value_SIMDSHA1body.104
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA1body.106-..___tag_value_SIMDSHA1body.104
	.4byte 0x0404d00e
	.4byte ..___tag_value_SIMDSHA1body.107-..___tag_value_SIMDSHA1body.106
	.2byte 0x080e
	.byte 0x00
	.4byte 0x0000005c
	.4byte 0x00000184
	.8byte ..___tag_value_SIMDSHA256body.109
	.8byte ..___tag_value_SIMDSHA256body.127-..___tag_value_SIMDSHA256body.109
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA256body.111-..___tag_value_SIMDSHA256body.109
	.4byte 0x028c100e
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA256body.113-..___tag_value_SIMDSHA256body.111
	.4byte 0x038d180e
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA256body.115-..___tag_value_SIMDSHA256body.113
	.4byte 0x0486200e
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA256body.117-..___tag_value_SIMDSHA256body.115
	.4byte 0x0405900e
	.4byte ..___tag_value_SIMDSHA256body.120-..___tag_value_SIMDSHA256body.117
	.4byte 0x04c6200e
	.4byte ..___tag_value_SIMDSHA256body.122-..___tag_value_SIMDSHA256body.120
	.4byte 0x04cd180e
	.4byte ..___tag_value_SIMDSHA256body.124-..___tag_value_SIMDSHA256body.122
	.4byte 0x04cc100e
	.4byte ..___tag_value_SIMDSHA256body.126-..___tag_value_SIMDSHA256body.124
	.8byte 0x000000000000080e
	.4byte 0x0000005c
	.4byte 0x000001e4
	.8byte ..___tag_value_SIMDSHA512body.128
	.8byte ..___tag_value_SIMDSHA512body.146-..___tag_value_SIMDSHA512body.128
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA512body.130-..___tag_value_SIMDSHA512body.128
	.4byte 0x028c100e
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA512body.132-..___tag_value_SIMDSHA512body.130
	.4byte 0x0383180e
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA512body.134-..___tag_value_SIMDSHA512body.132
	.4byte 0x0486200e
	.byte 0x04
	.4byte ..___tag_value_SIMDSHA512body.136-..___tag_value_SIMDSHA512body.134
	.4byte 0x040aa00e
	.4byte ..___tag_value_SIMDSHA512body.139-..___tag_value_SIMDSHA512body.136
	.4byte 0x04c6200e
	.4byte ..___tag_value_SIMDSHA512body.141-..___tag_value_SIMDSHA512body.139
	.4byte 0x04c3180e
	.4byte ..___tag_value_SIMDSHA512body.143-..___tag_value_SIMDSHA512body.141
	.4byte 0x04cc100e
	.4byte ..___tag_value_SIMDSHA512body.145-..___tag_value_SIMDSHA512body.143
	.8byte 0x000000000000080e
# End
