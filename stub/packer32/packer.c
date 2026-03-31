/**
 * @file packer.c
 * @brief 32-bit packer entry point and decryption orchestration.
 */

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "packer.h"

__attribute__((section(".packer.data")))
t_packer_32_data	g_packer_data = {.entry_point = 0x4242, .packer_virt_off = 0x4242};

extern char	packer_begin[];
extern char	packer_end[];
static char	*_base;

// ---
// Static functions declarations
// ---

static Elf32_auxv_t	*_auxv_from_stack(
						uintptr_t *stack
						);

static Elf32_Phdr	*_phdr_from_auxv(
						const Elf32_auxv_t *auxv
						);

static void			_fix_auxv(
						Elf32_auxv_t *auxv,
						void *interp_base
						);

// ---
// Stub entry
// ---

/**
 * @brief Stub main function called from assembly entry.
 * @return Pointer to original entry point.
 */
void *packer_main(void *stack)
{
	Elf32_auxv_t	*auxv;
	Elf32_Phdr		*phdr;

	_base = (char *)packer_begin - g_packer_data.packer_virt_off;
	g_packer_data.ranges_ptr = (uintptr_t)(g_packer_data.ranges_ptr + _base);
	g_packer_data.bss_ranges_ptr = (uintptr_t)(g_packer_data.bss_ranges_ptr + _base);
	decrypt((uint32_t)_base,
		(t_range *)g_packer_data.ranges_ptr, g_packer_data.ranges_len,
		(t_range *)g_packer_data.bss_ranges_ptr, g_packer_data.bss_ranges_len,
		(const char *)g_packer_data.key);
	auxv = _auxv_from_stack(stack);
	if (auxv == nullptr)
		return (g_packer_data.entry_point + _base);
	phdr = _phdr_from_auxv(auxv);
	if (phdr == nullptr)
		return (g_packer_data.entry_point + _base);
	_fix_auxv(auxv, nullptr);

	return (g_packer_data.entry_point + _base);
}

// ---
// Static functions definitions
// ---

static Elf32_auxv_t	*_auxv_from_stack(
						uintptr_t *stack
						) {
	uintptr_t	argc;

	argc = *stack++;
	stack += argc + 1;
	while ((void*)*stack++ != nullptr) ;
	return (Elf32_auxv_t *)(stack);
}

static Elf32_Phdr	*_phdr_from_auxv(
						const Elf32_auxv_t *auxv
						) {
	while (auxv->a_type != AT_NULL) {
		switch (auxv->a_type) {
			case AT_PHDR:
				return ((Elf32_Phdr *)auxv->a_un.a_val);
		}
		++auxv;
	}
	return (nullptr);
}

static void			_fix_auxv(
						Elf32_auxv_t *auxv,
						void *interp_base
						) {
	while (auxv->a_type != AT_NULL) {
		switch (auxv->a_type) {
			case AT_BASE:
				auxv->a_un.a_val = (uintptr_t)interp_base;
				break ;
			case AT_ENTRY:
				auxv->a_un.a_val = (uintptr_t)_base + g_packer_data.entry_point;
				break ;
		}
		++auxv;
	}
}
