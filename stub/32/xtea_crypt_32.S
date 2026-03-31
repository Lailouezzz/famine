.code32
.intel_syntax noprefix

.globl xtea_encrypt
.globl xtea_decrypt

.section .text

# void xtea_encrypt(void *data, size_t len, const uint32_t *key)
# cdecl: [esp+4]=data, [esp+8]=len, [esp+12]=key
# esi = v0, edi = v1, ebx = key, edx = data ptr

.macro xtea_enc_round ko1, cd1, ko2, cd2
	mov		eax, edi
	shl		eax, 4
	mov		ecx, edi
	shr		ecx, 5
	xor		eax, ecx
	add		eax, edi
	mov		ecx, [ebx + \ko1]
	add		ecx, \cd1
	xor		eax, ecx
	add		esi, eax

	mov		eax, esi
	shl		eax, 4
	mov		ecx, esi
	shr		ecx, 5
	xor		eax, ecx
	add		eax, esi
	mov		ecx, [ebx + \ko2]
	add		ecx, \cd2
	xor		eax, ecx
	add		edi, eax
.endm

.macro xtea_dec_round ko1, cd1, ko2, cd2
	mov		eax, esi
	shl		eax, 4
	mov		ecx, esi
	shr		ecx, 5
	xor		eax, ecx
	add		eax, esi
	mov		ecx, [ebx + \ko2]
	add		ecx, \cd2
	xor		eax, ecx
	sub		edi, eax

	mov		eax, edi
	shl		eax, 4
	mov		ecx, edi
	shr		ecx, 5
	xor		eax, ecx
	add		eax, edi
	mov		ecx, [ebx + \ko1]
	add		ecx, \cd1
	xor		eax, ecx
	sub		esi, eax
.endm

xtea_encrypt:
	push	ebp
	mov		ebp, esp
	push	ebx
	push	esi
	push	edi

	mov		edx, [ebp+8]
	mov		eax, [ebp+12]
	mov		ebx, [ebp+16]
	shr		eax, 3
	test	eax, eax
	jz		.enc_exit
	push	eax

.enc_loop:
	mov		esi, [edx]
	mov		edi, [edx+4]

	xtea_enc_round  0, 0x00000000, 12, 0x9E3779B9
	xtea_enc_round  4, 0x9E3779B9,  8, 0x3C6EF372
	xtea_enc_round  8, 0x3C6EF372,  4, 0xDAA66D2B
	xtea_enc_round 12, 0xDAA66D2B,  0, 0x78DDE6E4
	xtea_enc_round  0, 0x78DDE6E4,  0, 0x1715609D
	xtea_enc_round  4, 0x1715609D, 12, 0xB54CDA56
	xtea_enc_round  8, 0xB54CDA56,  8, 0x5384540F
	xtea_enc_round 12, 0x5384540F,  4, 0xF1BBCDC8
	xtea_enc_round  0, 0xF1BBCDC8,  0, 0x8FF34781
	xtea_enc_round  4, 0x8FF34781,  0, 0x2E2AC13A
	xtea_enc_round  8, 0x2E2AC13A, 12, 0xCC623AF3
	xtea_enc_round 12, 0xCC623AF3,  8, 0x6A99B4AC
	xtea_enc_round  0, 0x6A99B4AC,  4, 0x08D12E65
	xtea_enc_round  4, 0x08D12E65,  4, 0xA708A81E
	xtea_enc_round  8, 0xA708A81E,  0, 0x454021D7
	xtea_enc_round 12, 0x454021D7, 12, 0xE3779B90
	xtea_enc_round  0, 0xE3779B90,  8, 0x81AF1549
	xtea_enc_round  4, 0x81AF1549,  4, 0x1FE68F02
	xtea_enc_round  8, 0x1FE68F02,  4, 0xBE1E08BB
	xtea_enc_round 12, 0xBE1E08BB,  0, 0x5C558274
	xtea_enc_round  0, 0x5C558274, 12, 0xFA8CFC2D
	xtea_enc_round  4, 0xFA8CFC2D,  8, 0x98C475E6
	xtea_enc_round  8, 0x98C475E6,  4, 0x36FBEF9F
	xtea_enc_round 12, 0x36FBEF9F,  4, 0xD5336958
	xtea_enc_round  0, 0xD5336958,  0, 0x736AE311
	xtea_enc_round  4, 0x736AE311, 12, 0x11A25CCA
	xtea_enc_round  8, 0x11A25CCA,  8, 0xAFD9D683
	xtea_enc_round 12, 0xAFD9D683,  8, 0x4E11503C
	xtea_enc_round  0, 0x4E11503C,  4, 0xEC48C9F5
	xtea_enc_round  4, 0xEC48C9F5,  0, 0x8A8043AE
	xtea_enc_round  8, 0x8A8043AE, 12, 0x28B7BD67
	xtea_enc_round 12, 0x28B7BD67,  8, 0xC6EF3720

	mov		[edx], esi
	mov		[edx+4], edi
	add		edx, 8
	dec		dword ptr [esp]
	jnz		.enc_loop
	add		esp, 4

.enc_exit:
	pop		edi
	pop		esi
	pop		ebx
	pop		ebp
	ret

xtea_decrypt:
	push	ebp
	mov		ebp, esp
	push	ebx
	push	esi
	push	edi

	mov		edx, [ebp+8]
	mov		eax, [ebp+12]
	mov		ebx, [ebp+16]
	shr		eax, 3
	test	eax, eax
	jz		.dec_exit
	push	eax

.dec_loop:
	mov		esi, [edx]
	mov		edi, [edx+4]

	xtea_dec_round 12, 0x28B7BD67,  8, 0xC6EF3720
	xtea_dec_round  8, 0x8A8043AE, 12, 0x28B7BD67
	xtea_dec_round  4, 0xEC48C9F5,  0, 0x8A8043AE
	xtea_dec_round  0, 0x4E11503C,  4, 0xEC48C9F5
	xtea_dec_round 12, 0xAFD9D683,  8, 0x4E11503C
	xtea_dec_round  8, 0x11A25CCA,  8, 0xAFD9D683
	xtea_dec_round  4, 0x736AE311, 12, 0x11A25CCA
	xtea_dec_round  0, 0xD5336958,  0, 0x736AE311
	xtea_dec_round 12, 0x36FBEF9F,  4, 0xD5336958
	xtea_dec_round  8, 0x98C475E6,  4, 0x36FBEF9F
	xtea_dec_round  4, 0xFA8CFC2D,  8, 0x98C475E6
	xtea_dec_round  0, 0x5C558274, 12, 0xFA8CFC2D
	xtea_dec_round 12, 0xBE1E08BB,  0, 0x5C558274
	xtea_dec_round  8, 0x1FE68F02,  4, 0xBE1E08BB
	xtea_dec_round  4, 0x81AF1549,  4, 0x1FE68F02
	xtea_dec_round  0, 0xE3779B90,  8, 0x81AF1549
	xtea_dec_round 12, 0x454021D7, 12, 0xE3779B90
	xtea_dec_round  8, 0xA708A81E,  0, 0x454021D7
	xtea_dec_round  4, 0x08D12E65,  4, 0xA708A81E
	xtea_dec_round  0, 0x6A99B4AC,  4, 0x08D12E65
	xtea_dec_round 12, 0xCC623AF3,  8, 0x6A99B4AC
	xtea_dec_round  8, 0x2E2AC13A, 12, 0xCC623AF3
	xtea_dec_round  4, 0x8FF34781,  0, 0x2E2AC13A
	xtea_dec_round  0, 0xF1BBCDC8,  0, 0x8FF34781
	xtea_dec_round 12, 0x5384540F,  4, 0xF1BBCDC8
	xtea_dec_round  8, 0xB54CDA56,  8, 0x5384540F
	xtea_dec_round  4, 0x1715609D, 12, 0xB54CDA56
	xtea_dec_round  0, 0x78DDE6E4,  0, 0x1715609D
	xtea_dec_round 12, 0xDAA66D2B,  0, 0x78DDE6E4
	xtea_dec_round  8, 0x3C6EF372,  4, 0xDAA66D2B
	xtea_dec_round  4, 0x9E3779B9,  8, 0x3C6EF372
	xtea_dec_round  0, 0x00000000, 12, 0x9E3779B9

	mov		[edx], esi
	mov		[edx+4], edi
	add		edx, 8
	dec		dword ptr [esp]
	jnz		.dec_loop
	add		esp, 4

.dec_exit:
	pop		edi
	pop		esi
	pop		ebx
	pop		ebp
	ret

.section .note.GNU-stack,"",@progbits
