.code64
.intel_syntax noprefix

.globl xtea_encrypt
.globl xtea_decrypt

.section .text
.align 16

.const_data_0:
	.long	0x00000000
	.long	0x00000000
	.long	0x00000000
	.long	0x00000000
.const_data_1:
	.long	0x9E3779B9
	.long	0x9E3779B9
	.long	0x9E3779B9
	.long	0x9E3779B9
.const_data_2:
	.long	0x3C6EF372
	.long	0x3C6EF372
	.long	0x3C6EF372
	.long	0x3C6EF372
.const_data_3:
	.long	0xDAA66D2B
	.long	0xDAA66D2B
	.long	0xDAA66D2B
	.long	0xDAA66D2B
.const_data_4:
	.long	0x78DDE6E4
	.long	0x78DDE6E4
	.long	0x78DDE6E4
	.long	0x78DDE6E4
.const_data_5:
	.long	0x1715609D
	.long	0x1715609D
	.long	0x1715609D
	.long	0x1715609D
.const_data_6:
	.long	0xB54CDA56
	.long	0xB54CDA56
	.long	0xB54CDA56
	.long	0xB54CDA56
.const_data_7:
	.long	0x5384540F
	.long	0x5384540F
	.long	0x5384540F
	.long	0x5384540F
.const_data_8:
	.long	0xF1BBCDC8
	.long	0xF1BBCDC8
	.long	0xF1BBCDC8
	.long	0xF1BBCDC8
.const_data_9:
	.long	0x8FF34781
	.long	0x8FF34781
	.long	0x8FF34781
	.long	0x8FF34781
.const_data_10:
	.long	0x2E2AC13A
	.long	0x2E2AC13A
	.long	0x2E2AC13A
	.long	0x2E2AC13A
.const_data_11:
	.long	0xCC623AF3
	.long	0xCC623AF3
	.long	0xCC623AF3
	.long	0xCC623AF3
.const_data_12:
	.long	0x6A99B4AC
	.long	0x6A99B4AC
	.long	0x6A99B4AC
	.long	0x6A99B4AC
.const_data_13:
	.long	0x08D12E65
	.long	0x08D12E65
	.long	0x08D12E65
	.long	0x08D12E65
.const_data_14:
	.long	0xA708A81E
	.long	0xA708A81E
	.long	0xA708A81E
	.long	0xA708A81E
.const_data_15:
	.long	0x454021D7
	.long	0x454021D7
	.long	0x454021D7
	.long	0x454021D7
.const_data_16:
	.long	0xE3779B90
	.long	0xE3779B90
	.long	0xE3779B90
	.long	0xE3779B90
.const_data_17:
	.long	0x81AF1549
	.long	0x81AF1549
	.long	0x81AF1549
	.long	0x81AF1549
.const_data_18:
	.long	0x1FE68F02
	.long	0x1FE68F02
	.long	0x1FE68F02
	.long	0x1FE68F02
.const_data_19:
	.long	0xBE1E08BB
	.long	0xBE1E08BB
	.long	0xBE1E08BB
	.long	0xBE1E08BB
.const_data_20:
	.long	0x5C558274
	.long	0x5C558274
	.long	0x5C558274
	.long	0x5C558274
.const_data_21:
	.long	0xFA8CFC2D
	.long	0xFA8CFC2D
	.long	0xFA8CFC2D
	.long	0xFA8CFC2D
.const_data_22:
	.long	0x98C475E6
	.long	0x98C475E6
	.long	0x98C475E6
	.long	0x98C475E6
.const_data_23:
	.long	0x36FBEF9F
	.long	0x36FBEF9F
	.long	0x36FBEF9F
	.long	0x36FBEF9F
.const_data_24:
	.long	0xD5336958
	.long	0xD5336958
	.long	0xD5336958
	.long	0xD5336958
.const_data_25:
	.long	0x736AE311
	.long	0x736AE311
	.long	0x736AE311
	.long	0x736AE311
.const_data_26:
	.long	0x11A25CCA
	.long	0x11A25CCA
	.long	0x11A25CCA
	.long	0x11A25CCA
.const_data_27:
	.long	0xAFD9D683
	.long	0xAFD9D683
	.long	0xAFD9D683
	.long	0xAFD9D683
.const_data_28:
	.long	0x4E11503C
	.long	0x4E11503C
	.long	0x4E11503C
	.long	0x4E11503C
.const_data_29:
	.long	0xEC48C9F5
	.long	0xEC48C9F5
	.long	0xEC48C9F5
	.long	0xEC48C9F5
.const_data_30:
	.long	0x8A8043AE
	.long	0x8A8043AE
	.long	0x8A8043AE
	.long	0x8A8043AE
.const_data_31:
	.long	0x28B7BD67
	.long	0x28B7BD67
	.long	0x28B7BD67
	.long	0x28B7BD67
.const_data_32:
	.long	0xC6EF3720
	.long	0xC6EF3720
	.long	0xC6EF3720
	.long	0xC6EF3720

.macro xtea_encrypt_do_round ko1 cd1 ko2 cd2
	mov				r13d, r11d										# r13d = v[1] (second word of the block)
	shl				r13d, 4											# r13d = v1 << 4
	mov				r14d, r11d
	shr				r14d, 5											# r13d = v1 >> 5
	xor				r13d, r14d										# r13d = (v1 << 4) ^ (v1 >> 5)
	add				r13d, r11d										# r13d += v1
	mov				r14d, dword ptr [rdx + 4 * \ko1]					# r14d = key[i]
	add				r14d, \cd1
	xor				r13d, r14d										# r13d ^= key[i]
	add				r10d, r13d										# r13d += v[0] (first word of the block)

	mov				r12d, r10d										# r12d = v[0] (second word of the block)
	shl				r12d, 4											# r12d = v0 << 4
	mov				r14d, r10d
	shr				r14d, 5											# r12d = v0 >> 5
	xor				r12d, r14d										# r12d = (v0 << 4) ^ (v0 >> 5)
	add				r12d, r10d										# r12d += v0
	mov				r14d, dword ptr [rdx + 4 * \ko2]					# r14d = key[i]
	add				r14d, \cd2
	xor				r12d, r14d										# r12d ^= key[i]
	add				r11d, r12d										# r12d += v[1] (first word of the block)
.endm

# Macro to perform two Feistel-cipher rounds of of XTEA.
;
# Parameters:
#   key_offset1: offset into the key for v1s
#   const_data_label1: label of the constant data for v1s
#   key_offset2: offset into the key for v0s
#   const_data_label2: label of the constant data for v0s
;
# Beware:
#   The key pointer must be stored in rdx.
#   The v0s and v1s values must be stored in xmm13 and xmm14 respectively.
;
.macro xtea_encrypt_do_vectorized_round ko1, cdl1, ko2, cdl2
	# v0s += ((v1s << 4) ^ (v1s >> 5) + v1s) ^ (key + data)
	movdqa			xmm2,	xmm14									# xmm2 = v1s
	pslld			xmm2,	4										# xmm2 = v1s << 4
	movdqa			xmm11,	xmm14									# xmm11 = v1s
	psrld			xmm11,	5										# xmm11 = v1s >> 5
	pxor			xmm11,	xmm2									# xmm11 = (v1s << 4) ^ (v1s >> 5)
	paddd			xmm11,	xmm14									# xmm11 = (v1s << 4) ^ (v1s >> 5) + v1s
	movd			xmm2,	dword ptr [rdx + 4 * \ko1]				# xmm2 = key[key_offset1]
	pshufd			xmm10,	xmm2, 0									# broadcast key into xmm10
	movdqa			xmm2,	xmmword ptr [rip + \cdl1]				# xmm2 = data
	paddd			xmm10,	xmm2									# xmm10 = key + data
	pxor			xmm11,	xmm10									# xmm11 = ((v1s << 4) ^ (v1s >> 5) + v1s) ^ (key + data)
	paddd			xmm13,	xmm11									# v0s += ((v1s << 4) ^ (v1s >> 5) + v1s) ^ (key + data)

	# v1s += ((v0s << 4) ^ (v0s >> 5) + v0s) ^ (key + data)
	movdqa			xmm2,	xmm13									# xmm2 = v0s
	pslld			xmm2,	4										# xmm2 = v0s << 4
	movdqa			xmm11,	xmm13									# xmm11 = v0s
	psrld			xmm11,	5										# xmm11 = v0s >> 5
	pxor			xmm11,	xmm2									# xmm11 = (v0s << 4) ^ (v0s >> 5)
	paddd			xmm11,	xmm13									# xmm11 = (v0s << 4) ^ (v0s >> 5) + v0s
	movd			xmm2,	dword ptr [rdx + 4 * \ko2]				# xmm2 = key[key_offset1]
	pshufd			xmm10,	xmm2, 0									# broadcast key into xmm10
	movdqa			xmm2,	xmmword ptr [rip + \cdl2]				# xmm2 = data
	paddd			xmm10,	xmm2									# xmm10 = key + data
	pxor			xmm11,	xmm10									# xmm11 = ((v0s << 4) ^ (v0s >> 5) + v0s) ^ (key + data)
	paddd			xmm14,	xmm11									# v1s += ((v0s << 4) ^ (v0s >> 5) + v0s) ^ (key + data)
.endm

test_sse1_sse2:
	push		rbx
	push		rcx
	push		rdx
	mov			eax, 0x01
	cpuid
	mov			eax, edx
	pop			rdx
	pop			rcx
	pop			rbx
	ret

xtea_encrypt:
	cmp			rsi, 8
	jb			.xtea_encrypt_exit
	push		rbp
	push		r15
	push		r14
	push		r13
	push		r12
	push		rbx
	mov			r8, rsi
	shr			r8, 3
	cmp			rsi, 32
	jb			.xtea_encrypt_prepare

	call		test_sse1_sse2
	test		eax, ~(0b11<<25)
	je			.xtea_encrypt_prepare

	and			rsi, -8
	add			rsi, rdi
	lea			rax, [rdx + 16]
	cmp			rdi, rax
	setb		al
	cmp			rdx, rsi
	setb		cl
	test		al, cl
	je			.xtea_encrypt_vectorized

.xtea_encrypt_prepare:
	mov			rax, rdi
	mov			rcx, r8

.xtea_encrypt:
	xor			esi, esi

.xtea_encrypt_loop:
	mov			r10d, dword ptr [rax + 8*rsi + 0]
	mov			r11d, dword ptr [rax + 8*rsi + 4]

	xtea_encrypt_do_round 0 0x00000000 3 0x9E3779B9
	xtea_encrypt_do_round 1 0x9E3779B9 2 0x3C6EF372
	xtea_encrypt_do_round 2 0x3C6EF372 1 0xDAA66D2B
	xtea_encrypt_do_round 3 0xDAA66D2B 0 0x78DDE6E4
	xtea_encrypt_do_round 0 0x78DDE6E4 0 0x1715609D
	xtea_encrypt_do_round 1 0x1715609D 3 0xB54CDA56
	xtea_encrypt_do_round 2 0xB54CDA56 2 0x5384540F
	xtea_encrypt_do_round 3 0x5384540F 1 0xF1BBCDC8
	xtea_encrypt_do_round 0 0xF1BBCDC8 0 0x8FF34781
	xtea_encrypt_do_round 1 0x8FF34781 0 0x2E2AC13A
	xtea_encrypt_do_round 2 0x2E2AC13A 3 0xCC623AF3
	xtea_encrypt_do_round 3 0xCC623AF3 2 0x6A99B4AC
	xtea_encrypt_do_round 0 0x6A99B4AC 1 0x08D12E65
	xtea_encrypt_do_round 1 0x08D12E65 1 0xA708A81E
	xtea_encrypt_do_round 2 0xA708A81E 0 0x454021D7
	xtea_encrypt_do_round 3 0x454021D7 3 0xE3779B90
	xtea_encrypt_do_round 0 0xE3779B90 2 0x81AF1549
	xtea_encrypt_do_round 1 0x81AF1549 1 0x1FE68F02
	xtea_encrypt_do_round 2 0x1FE68F02 1 0xBE1E08BB
	xtea_encrypt_do_round 3 0xBE1E08BB 0 0x5C558274
	xtea_encrypt_do_round 0 0x5C558274 3 0xFA8CFC2D
	xtea_encrypt_do_round 1 0xFA8CFC2D 2 0x98C475E6
	xtea_encrypt_do_round 2 0x98C475E6 1 0x36FBEF9F
	xtea_encrypt_do_round 3 0x36FBEF9F 1 0xD5336958
	xtea_encrypt_do_round 0 0xD5336958 0 0x736AE311
	xtea_encrypt_do_round 1 0x736AE311 3 0x11A25CCA
	xtea_encrypt_do_round 2 0x11A25CCA 2 0xAFD9D683
	xtea_encrypt_do_round 3 0xAFD9D683 2 0x4E11503C
	xtea_encrypt_do_round 0 0x4E11503C 1 0xEC48C9F5
	xtea_encrypt_do_round 1 0xEC48C9F5 0 0x8A8043AE
	xtea_encrypt_do_round 2 0x8A8043AE 3 0x28B7BD67
	xtea_encrypt_do_round 3 0x28B7BD67 2 0xC6EF3720

	mov			dword ptr [rax + 8 * rsi + 0], r10d
	mov			dword ptr [rax + 8 * rsi + 4], r11d
	inc			rsi
	cmp			rcx, rsi
	jne			.xtea_encrypt_loop

.xtea_encrypt_cleanup:
	pop			rbx
	pop			r12
	pop			r13
	pop			r14
	pop			r15
	pop			rbp

.xtea_encrypt_exit:
	ret

.xtea_encrypt_vectorized:
	# Number of blocks rounded down to a multiple of 4
	mov			rsi, r8
	and			rsi, -4

	# Address of the leftover data after vectorized processing
	lea			rax, [rdi + rsi * 8]

	# number of leftover blocks
	mov			ecx, r8d
	and			ecx, 3

	# Loop counter
	xor 		r9, r9

.xtea_encrypt_vectorized_loop:
	# Load 4 blocks of data
	movups		xmm14, xmmword ptr [rdi + 8 * r9 +  0]
	movups		xmm1, xmmword ptr [rdi + 8 * r9 + 16]

	# Interleave to separate v0s and v1s
	movaps		xmm13, xmm14
	shufps		xmm13, xmm1, 0b10001000
	shufps		xmm14, xmm1, 0b11011101

	xtea_encrypt_do_vectorized_round 0 , .const_data_0,  3, .const_data_1
	xtea_encrypt_do_vectorized_round 1 , .const_data_1,  2, .const_data_2
	xtea_encrypt_do_vectorized_round 2 , .const_data_2,  1, .const_data_3
	xtea_encrypt_do_vectorized_round 3 , .const_data_3,  0, .const_data_4
	xtea_encrypt_do_vectorized_round 0 , .const_data_4,  0, .const_data_5
	xtea_encrypt_do_vectorized_round 1 , .const_data_5,  3, .const_data_6
	xtea_encrypt_do_vectorized_round 2 , .const_data_6,  2, .const_data_7
	xtea_encrypt_do_vectorized_round 3 , .const_data_7,  1, .const_data_8
	xtea_encrypt_do_vectorized_round 0 , .const_data_8,  0, .const_data_9
	xtea_encrypt_do_vectorized_round 1 , .const_data_9,  0, .const_data_10
	xtea_encrypt_do_vectorized_round 2 , .const_data_10, 3, .const_data_11
	xtea_encrypt_do_vectorized_round 3 , .const_data_11, 2, .const_data_12
	xtea_encrypt_do_vectorized_round 0 , .const_data_12, 1, .const_data_13
	xtea_encrypt_do_vectorized_round 1 , .const_data_13, 1, .const_data_14
	xtea_encrypt_do_vectorized_round 2 , .const_data_14, 0, .const_data_15
	xtea_encrypt_do_vectorized_round 3 , .const_data_15, 3, .const_data_16
	xtea_encrypt_do_vectorized_round 0 , .const_data_16, 2, .const_data_17
	xtea_encrypt_do_vectorized_round 1 , .const_data_17, 1, .const_data_18
	xtea_encrypt_do_vectorized_round 2 , .const_data_18, 1, .const_data_19
	xtea_encrypt_do_vectorized_round 3 , .const_data_19, 0, .const_data_20
	xtea_encrypt_do_vectorized_round 0 , .const_data_20, 3, .const_data_21
	xtea_encrypt_do_vectorized_round 1 , .const_data_21, 2, .const_data_22
	xtea_encrypt_do_vectorized_round 2 , .const_data_22, 1, .const_data_23
	xtea_encrypt_do_vectorized_round 3 , .const_data_23, 1, .const_data_24
	xtea_encrypt_do_vectorized_round 0 , .const_data_24, 0, .const_data_25
	xtea_encrypt_do_vectorized_round 1 , .const_data_25, 3, .const_data_26
	xtea_encrypt_do_vectorized_round 2 , .const_data_26, 2, .const_data_27
	xtea_encrypt_do_vectorized_round 3 , .const_data_27, 2, .const_data_28
	xtea_encrypt_do_vectorized_round 0 , .const_data_28, 1, .const_data_29
	xtea_encrypt_do_vectorized_round 1 , .const_data_29, 0, .const_data_30
	xtea_encrypt_do_vectorized_round 2 , .const_data_30, 3, .const_data_31
	xtea_encrypt_do_vectorized_round 3 , .const_data_31, 2, .const_data_32

	# Interleave back to original format
	movdqa		xmm1, xmm13
	punpckhdq	xmm1, xmm14
	punpckldq	xmm13, xmm14

	# Store encrypted blocks
	movdqu		xmmword ptr [rdi + 8 * r9 +  0], xmm13
	movdqu		xmmword ptr [rdi + 8 * r9 + 16], xmm1

	# Next 4 blocks
	add			r9, 4
	cmp			rsi, r9

	# Loop if there is blocks remaining
	jne			.xtea_encrypt_vectorized_loop

	# Encrypt remaining blocks without vectorization
	cmp			r8, rsi
	jne			.xtea_encrypt

	# Cleanup and exit
	jmp			.xtea_encrypt_cleanup

.macro xtea_decrypt_do_round ko1 cd1 ko2 cd2
	mov				r12d, r10d										# r12d = v[0] (second word of the block)
	shl				r12d, 4											# r12d = v0 << 4
	mov				r14d, r10d
	shr				r14d, 5											# r12d = v0 >> 5
	xor				r12d, r14d										# r12d = (v0 << 4) ^ (v0 >> 5)
	add				r12d, r10d										# r12d += v0
	mov				r14d, dword ptr [rdx + 4 * \ko2]			# r14d = key[i]
	add				r14d, \cd2
	xor				r12d, r14d										# r12d ^= key[i]
	sub				r11d, r12d										# r12d += v[1] (first word of the block)

	mov				r13d, r11d										# r13d = v[1] (second word of the block)
	shl				r13d, 4											# r13d = v1 << 4
	mov				r14d, r11d
	shr				r14d, 5											# r13d = v1 >> 5
	xor				r13d, r14d										# r13d = (v1 << 4) ^ (v1 >> 5)
	add				r13d, r11d										# r13d += v1
	mov				r14d, dword ptr [rdx + 4 * \ko1]			# r14d = key[i]
	add				r14d, \cd1
	xor				r13d, r14d										# r13d ^= key[i]
	sub				r10d, r13d										# r13d += v[0] (first word of the block)
.endm

# Macro to perform two Feistel-cipher rounds of of XTEA.
;
# Parameters:
#   key_offset1: offset into the key for v1s
#   const_data_label1: label of the constant data for v1s
#   key_offset2: offset into the key for v0s
#   const_data_label2: label of the constant data for v0s
;
# Beware:
#   The key pointer must be stored in rdx.
#   The v0s and v1s values must be stored in xmm13 and xmm14 respectively.
;
.macro xtea_decrypt_do_vectorized_round ko1, cdl1, ko2, cdl2
	# v1s += ((v0s << 4) ^ (v0s >> 5) + v0s) ^ (key + data)
	movdqa			xmm2,	xmm13									# xmm2 = v0s
	pslld			xmm2,	4										# xmm2 = v0s << 4
	movdqa			xmm11,	xmm13									# xmm11 = v0s
	psrld			xmm11,	5										# xmm11 = v0s >> 5
	pxor			xmm11,	xmm2									# xmm11 = (v0s << 4) ^ (v0s >> 5)
	paddd			xmm11,	xmm13									# xmm11 = (v0s << 4) ^ (v0s >> 5) + v0s
	movd			xmm2,	dword ptr [rdx + 4 * \ko2]				# xmm2 = key[key_offset1]
	pshufd			xmm10,	xmm2, 0									# broadcast key into xmm10
	movdqa			xmm2,	xmmword ptr [rip + \cdl2]				# xmm2 = data
	paddd			xmm10,	xmm2									# xmm10 = key + data
	pxor			xmm11,	xmm10									# xmm11 = ((v0s << 4) ^ (v0s >> 5) + v0s) ^ (key + data)
	psubd			xmm14,	xmm11									# v1s += ((v0s << 4) ^ (v0s >> 5) + v0s) ^ (key + data)

	# v0s += ((v1s << 4) ^ (v1s >> 5) + v1s) ^ (key + data)
	movdqa			xmm2,	xmm14									# xmm2 = v1s
	pslld			xmm2,	4										# xmm2 = v1s << 4
	movdqa			xmm11,	xmm14									# xmm11 = v1s
	psrld			xmm11,	5										# xmm11 = v1s >> 5
	pxor			xmm11,	xmm2									# xmm11 = (v1s << 4) ^ (v1s >> 5)
	paddd			xmm11,	xmm14									# xmm11 = (v1s << 4) ^ (v1s >> 5) + v1s
	movd			xmm2,	dword ptr [rdx + 4 * \ko1]				# xmm2 = key[key_offset1]
	pshufd			xmm10,	xmm2, 0									# broadcast key into xmm10
	movdqa			xmm2,	xmmword ptr [rip + \cdl1]				# xmm2 = data
	paddd			xmm10,	xmm2									# xmm10 = key + data
	pxor			xmm11,	xmm10									# xmm11 = ((v1s << 4) ^ (v1s >> 5) + v1s) ^ (key + data)
	psubd			xmm13,	xmm11									# v0s += ((v1s << 4) ^ (v1s >> 5) + v1s) ^ (key + data)
.endm

xtea_decrypt:
	cmp			rsi, 8
	jb			.xtea_decrypt_exit
	push		rbp
	push		r15
	push		r14
	push		rbx
	mov			r8, rsi
	shr			r8, 3
	cmp			rsi, 32
	jb			.xtea_decrypt_prepare

	call		test_sse1_sse2
	test		eax, ~(0b11<<25)
	je			.xtea_decrypt_prepare

	and			rsi, -8
	add			rsi, rdi
	lea			rax, [rdx + 16]
	cmp			rdi, rax
	setb		al
	cmp			rdx, rsi
	setb		cl
	test		al, cl
	je			.xtea_decrypt_vectorized

.xtea_decrypt_prepare:
	mov			rax, rdi
	mov			rcx, r8

.xtea_decrypt:
	xor			esi, esi

.xtea_decrypt_loop:
	mov			r10d, dword ptr [rax + 8*rsi + 0]
	mov			r11d, dword ptr [rax + 8*rsi + 4]

	xtea_decrypt_do_round 3 0x28B7BD67 2 0xC6EF3720
	xtea_decrypt_do_round 2 0x8A8043AE 3 0x28B7BD67
	xtea_decrypt_do_round 1 0xEC48C9F5 0 0x8A8043AE
	xtea_decrypt_do_round 0 0x4E11503C 1 0xEC48C9F5
	xtea_decrypt_do_round 3 0xAFD9D683 2 0x4E11503C
	xtea_decrypt_do_round 2 0x11A25CCA 2 0xAFD9D683
	xtea_decrypt_do_round 1 0x736AE311 3 0x11A25CCA
	xtea_decrypt_do_round 0 0xD5336958 0 0x736AE311
	xtea_decrypt_do_round 3 0x36FBEF9F 1 0xD5336958
	xtea_decrypt_do_round 2 0x98C475E6 1 0x36FBEF9F
	xtea_decrypt_do_round 1 0xFA8CFC2D 2 0x98C475E6
	xtea_decrypt_do_round 0 0x5C558274 3 0xFA8CFC2D
	xtea_decrypt_do_round 3 0xBE1E08BB 0 0x5C558274
	xtea_decrypt_do_round 2 0x1FE68F02 1 0xBE1E08BB
	xtea_decrypt_do_round 1 0x81AF1549 1 0x1FE68F02
	xtea_decrypt_do_round 0 0xE3779B90 2 0x81AF1549
	xtea_decrypt_do_round 3 0x454021D7 3 0xE3779B90
	xtea_decrypt_do_round 2 0xA708A81E 0 0x454021D7
	xtea_decrypt_do_round 1 0x08D12E65 1 0xA708A81E
	xtea_decrypt_do_round 0 0x6A99B4AC 1 0x08D12E65
	xtea_decrypt_do_round 3 0xCC623AF3 2 0x6A99B4AC
	xtea_decrypt_do_round 2 0x2E2AC13A 3 0xCC623AF3
	xtea_decrypt_do_round 1 0x8FF34781 0 0x2E2AC13A
	xtea_decrypt_do_round 0 0xF1BBCDC8 0 0x8FF34781
	xtea_decrypt_do_round 3 0x5384540F 1 0xF1BBCDC8
	xtea_decrypt_do_round 2 0xB54CDA56 2 0x5384540F
	xtea_decrypt_do_round 1 0x1715609D 3 0xB54CDA56
	xtea_decrypt_do_round 0 0x78DDE6E4 0 0x1715609D
	xtea_decrypt_do_round 3 0xDAA66D2B 0 0x78DDE6E4
	xtea_decrypt_do_round 2 0x3C6EF372 1 0xDAA66D2B
	xtea_decrypt_do_round 1 0x9E3779B9 2 0x3C6EF372
	xtea_decrypt_do_round 0 0x00000000 3 0x9E3779B9

	mov			dword ptr [rax + 8 * rsi + 0], r10d
	mov			dword ptr [rax + 8 * rsi + 4], r11d
	inc			rsi
	cmp			rcx, rsi
	jne			.xtea_decrypt_loop

.xtea_decrypt_cleanup:
	pop			rbx
	pop			r14
	pop			r15
	pop			rbp

.xtea_decrypt_exit:
	ret

.xtea_decrypt_vectorized:
	# Number of blocks rounded down to a multiple of 4
	mov			rsi, r8
	and			rsi, -4

	# Address of the leftover data after vectorized processing
	lea			rax, [rdi + rsi * 8]

	# number of leftover blocks
	mov			ecx, r8d
	and			ecx, 3

	# Loop counter
	xor 		r9, r9

.xtea_decrypt_vectorized_loop:
	# Load 4 blocks of data
	movups		xmm14, xmmword ptr [rdi + 8 * r9 +  0]
	movups		xmm1, xmmword ptr [rdi + 8 * r9 + 16]

	# Interleave to separate v0s and v1s
	movaps		xmm13, xmm14
	shufps		xmm13, xmm1, 0b10001000
	shufps		xmm14, xmm1, 0b11011101

	xtea_decrypt_do_vectorized_round 3, .const_data_31, 2, .const_data_32
	xtea_decrypt_do_vectorized_round 2, .const_data_30, 3, .const_data_31
	xtea_decrypt_do_vectorized_round 1, .const_data_29, 0, .const_data_30
	xtea_decrypt_do_vectorized_round 0, .const_data_28, 1, .const_data_29
	xtea_decrypt_do_vectorized_round 3, .const_data_27, 2, .const_data_28
	xtea_decrypt_do_vectorized_round 2, .const_data_26, 2, .const_data_27
	xtea_decrypt_do_vectorized_round 1, .const_data_25, 3, .const_data_26
	xtea_decrypt_do_vectorized_round 0, .const_data_24, 0, .const_data_25
	xtea_decrypt_do_vectorized_round 3, .const_data_23, 1, .const_data_24
	xtea_decrypt_do_vectorized_round 2, .const_data_22, 1, .const_data_23
	xtea_decrypt_do_vectorized_round 1, .const_data_21, 2, .const_data_22
	xtea_decrypt_do_vectorized_round 0, .const_data_20, 3, .const_data_21
	xtea_decrypt_do_vectorized_round 3, .const_data_19, 0, .const_data_20
	xtea_decrypt_do_vectorized_round 2, .const_data_18, 1, .const_data_19
	xtea_decrypt_do_vectorized_round 1, .const_data_17, 1, .const_data_18
	xtea_decrypt_do_vectorized_round 0, .const_data_16, 2, .const_data_17
	xtea_decrypt_do_vectorized_round 3, .const_data_15, 3, .const_data_16
	xtea_decrypt_do_vectorized_round 2, .const_data_14, 0, .const_data_15
	xtea_decrypt_do_vectorized_round 1, .const_data_13, 1, .const_data_14
	xtea_decrypt_do_vectorized_round 0, .const_data_12, 1, .const_data_13
	xtea_decrypt_do_vectorized_round 3, .const_data_11, 2, .const_data_12
	xtea_decrypt_do_vectorized_round 2, .const_data_10, 3, .const_data_11
	xtea_decrypt_do_vectorized_round 1, .const_data_9,  0, .const_data_10
	xtea_decrypt_do_vectorized_round 0, .const_data_8,  0, .const_data_9
	xtea_decrypt_do_vectorized_round 3, .const_data_7,  1, .const_data_8
	xtea_decrypt_do_vectorized_round 2, .const_data_6,  2, .const_data_7
	xtea_decrypt_do_vectorized_round 1, .const_data_5,  3, .const_data_6
	xtea_decrypt_do_vectorized_round 0, .const_data_4,  0, .const_data_5
	xtea_decrypt_do_vectorized_round 3, .const_data_3,  0, .const_data_4
	xtea_decrypt_do_vectorized_round 2, .const_data_2,  1, .const_data_3
	xtea_decrypt_do_vectorized_round 1, .const_data_1,  2, .const_data_2
	xtea_decrypt_do_vectorized_round 0, .const_data_0,  3, .const_data_1

	# Interleave back to original format
	movdqa		xmm1, xmm13
	punpckhdq	xmm1, xmm14
	punpckldq	xmm13, xmm14

	# Store decrypted blocks
	movdqu		xmmword ptr [rdi + 8 * r9 +  0], xmm13
	movdqu		xmmword ptr [rdi + 8 * r9 + 16], xmm1

	# Next 4 blocks
	add			r9, 4
	cmp			rsi, r9

	# Loop if there is blocks remaining
	jne			.xtea_decrypt_vectorized_loop

	# decrypt remaining blocks without vectorization
	cmp			r8, rsi
	jne			.xtea_decrypt

	# Cleanup and exit
	jmp			.xtea_decrypt_cleanup

.section .note.GNU-stack,"",@progbits
