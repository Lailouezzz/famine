// ---
// Includes
// ---

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "elf_reader.h"
#include "utils.h"

#define PAGE_SIZE (0x1000)
#define PAGE_MASK (0xFFFULL)

// ---
// Static function declarations
// ---



// ---
// Extern function definitions
// ---

bool	elf_load(
			const char *path,
			void **base,
			void **entry) {
	t_elf_file	s;
	uintptr_t	min_vaddr = (uintptr_t)~0x0ULL;
	uintptr_t	max_vaddr = 0;
	void		*_base;
	uint16_t	phnum;

	if (elf_manager_load(&s, path) == EXIT_FAILURE)
		return (false);
	phnum = s.hdl.eh.get.phnum(&s);
	for (size_t k = 0; k < phnum; ++k) {
		if (s.hdl.ph.get.type(&s, k) != PT_LOAD)
			continue ;
		auto const	start_vaddr = s.hdl.ph.get.vaddr(&s, k);
		auto const	last_vaddr = start_vaddr + s.hdl.ph.get.memsz(&s, k);
		if (min_vaddr > start_vaddr)
			min_vaddr = start_vaddr;
		if (max_vaddr < last_vaddr)
			max_vaddr = last_vaddr;
	}
	_base = mmap(nullptr, ALIGN_UP(max_vaddr - min_vaddr, PAGE_SIZE), PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (_base == MAP_FAILED) {
		elf_manager_close(&s);
		return (false);
	}
	for (size_t k = 0; k < phnum; ++k) {
		if (s.hdl.ph.get.type(&s, k) != PT_LOAD)
			continue ;
		auto const	vaddr = s.hdl.ph.get.vaddr(&s, k) - min_vaddr;
		auto const	memsz = s.hdl.ph.get.memsz(&s, k);
		auto const	filesz = s.hdl.ph.get.filesz(&s, k);
		auto const	poff = s.hdl.ph.get.offset(&s, k);
		auto const	flags = s.hdl.ph.get.flags(&s, k);
		int const	prot = ((flags & PF_R) ? PROT_READ : 0)
						| ((flags & PF_W) ? PROT_WRITE : 0)
						| ((flags & PF_X) ? PROT_EXEC : 0);
		void	*mapping = nullptr;
		if (filesz == 0)
			mapping = mmap(
						(void *)(uintptr_t)ALIGN_DOWN(vaddr + (uintptr_t)_base, PAGE_SIZE),
						ALIGN_UP(memsz + (vaddr & PAGE_MASK), PAGE_SIZE),
						prot, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE,
						-1, 0);
		else
			mapping = mmap(
						(void *)(uintptr_t)ALIGN_DOWN(vaddr + (uintptr_t)_base, PAGE_SIZE),
						ALIGN_UP(filesz + (vaddr & PAGE_MASK), PAGE_SIZE),
						prot, MAP_PRIVATE | MAP_FIXED,
						s.fd, ALIGN_DOWN(poff, PAGE_SIZE));
		if (mapping == MAP_FAILED) {
			elf_manager_close(&s);
			return (false);
		} else if (filesz == 0 || filesz == memsz)
			continue ;
		if (prot & PROT_WRITE) {
			for (char *p = mapping + (vaddr & PAGE_MASK) + filesz; ((uintptr_t)p & PAGE_MASK) != 0; ++p)
				*p = 0;
		}
		if (ALIGN_UP((vaddr & PAGE_MASK) + memsz, PAGE_SIZE) <= ALIGN_UP((vaddr & PAGE_MASK) + filesz, PAGE_SIZE))
			continue ;
		if (mmap(
				(void *)(uintptr_t)ALIGN_UP((uintptr_t)mapping + (vaddr & PAGE_MASK) + filesz, PAGE_SIZE),
				ALIGN_UP(memsz - filesz - (PAGE_SIZE - (((vaddr & PAGE_MASK) + filesz) & PAGE_MASK)), PAGE_SIZE),
				prot, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE,
				-1, 0
			) == MAP_FAILED) {
			elf_manager_close(&s);
			return (false);
		}
	}
	*base = _base - min_vaddr;
	*entry = (void *)(uintptr_t)s.hdl.eh.get.entry(&s);
	elf_manager_close(&s);
	return (true);
}

// ---
// Static function definitions
// ---
