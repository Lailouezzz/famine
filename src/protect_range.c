// ---
// Includes
// ---

#include "elf_reader.h"
#include "protect_range.h"

// ---
// Static function declarations
// ---

static bool	_elf_get_protected_ranges(
				const t_elf_file *elf,
				t_ranges *ranges
				);

static int	_range_cmp(
				const void *a,
				const void *b
				);

static bool	_add_bss_to_range(
				t_ranges *ranges,
				const t_elf_file *elf
				);

// ---
// Extern function definitions
// ---

bool	elf_get_protected_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			) {
	if (!list_push(ranges, MAKE_RANGE(0x0, elf->is_64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr))))
		return (false);
	if (!list_push(ranges, MAKE_RANGE(elf->hdl.eh.get.phoff(elf), elf->hdl.eh.get.phnum(elf) * elf->hdl.eh.get.phentsize(elf))))
		return (false);
	if (!_elf_get_protected_ranges(elf, ranges))
		return (false);
	return (true);
}

bool	elf_get_bss_vaddr_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			) {
	for (size_t k = 0; k < elf->hdl.eh.get.phnum(elf); ++k) {
		auto const filesz = elf->hdl.ph.get.filesz(elf, k);
		auto const memsz = elf->hdl.ph.get.memsz(elf, k);
		if (filesz >= memsz || elf->hdl.ph.get.type(elf, k) != PT_LOAD)
			continue ;
		auto const vaddr = elf->hdl.ph.get.vaddr(elf, k);
		if (!list_push(ranges, MAKE_RANGE(vaddr + filesz, memsz - filesz)))
			return (false);
	}
	return (true);
}

void	range_aggregate(
			t_ranges *ranges
			) {
	if (ranges->len == 0)
		return ;
	quicksort(ranges->data, sizeof(*ranges->data), ranges->len, _range_cmp);
	for (size_t k = 0; k < ranges->len - 1; ++k) {
		const off_t	last_off = ranges->data[k].off + ranges->data[k].len;
		const off_t	next_last_off = ranges->data[k + 1].off + ranges->data[k + 1].len;
		if (last_off >= ranges->data[k + 1].off) {
			if (next_last_off > last_off)
				ranges->data[k].len += next_last_off - last_off;
			list_delete(ranges, k + 1);
			--k;
		}
	}
}

// ---
// Static function definitions
// ---

static bool	_elf_get_protected_ranges(
				const t_elf_file *elf,
				t_ranges *ranges
				) {
	if (!_add_bss_to_range(ranges, elf))
		return (false);
	return (true);
}

static int	_range_cmp(
				const void *a,
				const void *b
				) {
	return (((const t_range *)a)->off - ((const t_range *)b)->off);
}

static bool	_add_bss_to_range(
				t_ranges *ranges,
				const t_elf_file *elf
				) {
	for (size_t k = 0; k < elf->hdl.eh.get.phnum(elf); ++k) {
		auto const filesz = elf->hdl.ph.get.filesz(elf, k);
		auto const memsz = elf->hdl.ph.get.memsz(elf, k);
		if (filesz >= memsz)
			continue ;
		auto const offset = elf->hdl.ph.get.offset(elf, k);
		if ((offset + filesz) % 8 == 0)
			continue ;
		auto const down_addr = ALIGN_DOWN(offset + filesz, 8);
		if (!list_push(ranges, MAKE_RANGE(down_addr, 8)))
			return (false);
	}
	return (true);
}
