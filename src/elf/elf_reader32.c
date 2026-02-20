/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf_reader32.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/16 09:46:23 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 13:20:24 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "int_elf_reader.h"
# include "int_elf_offset.h"

static
uint64_t	_get_eh_entry(
				const t_elf_file *s
				);

static
uint64_t	_get_eh_phoff(
				const t_elf_file *s
				);

static
uint16_t	_get_eh_shstrndx(
				const t_elf_file *s
				);

static
uint16_t	_get_eh_phentsize(
				const t_elf_file *s
				);

static
uint16_t	_get_eh_phnum(
				const t_elf_file *s
				);

static
uint16_t	_get_eh_type(
				const t_elf_file *s
				);

static
void		*_get_pht(
				const t_elf_file *s
				);

static
void		*_get_ph(
				const t_elf_file *s,
				size_t
				);

static
void		_set_eh_phoff(
				t_elf_file *s,
				uint64_t off
				);

static
void		_set_eh_phentsize(
				t_elf_file *s,
				uint16_t entsize
				);

static
void		_set_eh_phnum(
				t_elf_file *s,
				uint16_t num
				);

static
uint64_t	_get_eh_shoff(
				const t_elf_file *s
				);

static
uint16_t	_get_eh_shentsize(
				const t_elf_file *s
				);

static
uint16_t	_get_eh_shnum(
				const t_elf_file *s
				);

static
void		*_get_sht(
				const t_elf_file *s
				);

static
void		*_get_sh(
				const t_elf_file *s,
				size_t
				);

static
void		_set_eh_entry(
				t_elf_file *s,
				uint64_t entry
				);

static
void		_set_eh_shoff(
				t_elf_file *s,
				uint64_t off
				);

static
void		_set_eh_shstrndx(
				t_elf_file *s,
				uint16_t shstrndx
				);

static
void		_set_eh_shentsize(
				t_elf_file *s,
				uint16_t entsize
				);

static
void		_set_eh_shnum(
				t_elf_file *s,
				uint16_t num
				);

static
uint32_t	_get_ph_type(
				const t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_ph_flags(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_offset(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_vaddr(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_paddr(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_filesz(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_memsz(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_align(
				const t_elf_file *s,
				size_t n
				);

static
void		_set_ph_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				);

static
void		_set_ph_flags(
				t_elf_file *s,
				size_t n,
				uint32_t flags
				);

static
void		_set_ph_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				);

static
void		_set_ph_vaddr(
				t_elf_file *s,
				size_t n,
				uint64_t vaddr
				);

static
void		_set_ph_paddr(
				t_elf_file *s,
				size_t n,
				uint64_t paddr
				);

static
void		_set_ph_filesz(
				t_elf_file *s,
				size_t n,
				uint64_t filesz
				);

static
void		_set_ph_memsz(
				t_elf_file *s,
				size_t n,
				uint64_t memsz
				);

static
void		_set_ph_align(
				t_elf_file *s,
				size_t n,
				uint64_t align
				);

static
uint32_t	_get_sh_name(
				const t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_sh_type(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_flags(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_addr(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_offset(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_size(
				const t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_sh_link(
				const t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_sh_info(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_addralign(
				const t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_entsize(
				const t_elf_file *s,
				size_t n
				);

static
void		_set_sh_name(
				t_elf_file *s,
				size_t n,
				uint32_t name
				);

static
void		_set_sh_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				);

static
void		_set_sh_flags(
				t_elf_file *s,
				size_t n,
				uint64_t flags
				);

static
void		_set_sh_addr(
				t_elf_file *s,
				size_t n,
				uint64_t addr
				);

static
void		_set_sh_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				);

static
void		_set_sh_size(
				t_elf_file *s,
				size_t n,
				uint64_t size
				);

static
void		_set_sh_link(
				t_elf_file *s,
				size_t n,
				uint32_t link
				);

static
void		_set_sh_info(
				t_elf_file *s,
				size_t n,
				uint32_t info
				);

static
void		_set_sh_addralign(
				t_elf_file *s,
				size_t n,
				uint64_t addralign
				);

static
void		_set_sh_entsize(
				t_elf_file *s,
				size_t n,
				uint64_t entsize
				);

void	int_elf_load_32bit_handlers(
			t_elf_file *s
			)
{
	// eh getters
	s->hdl.eh.get.entry = _get_eh_entry;
	s->hdl.eh.get.phoff = _get_eh_phoff;
	s->hdl.eh.get.phentsize = _get_eh_phentsize;
	s->hdl.eh.get.shstrndx = _get_eh_shstrndx;
	s->hdl.eh.get.phnum = _get_eh_phnum;
	s->hdl.eh.get.type = _get_eh_type;
	s->hdl.eh.get.shoff = _get_eh_shoff;
	s->hdl.eh.get.shentsize = _get_eh_shentsize;
	s->hdl.eh.get.shnum = _get_eh_shnum;
	s->hdl.eh.get.pht = _get_pht;
	s->hdl.eh.get.ph = _get_ph;
	s->hdl.eh.get.sht = _get_sht;
	s->hdl.eh.get.sh = _get_sh;
	// eh setters
	s->hdl.eh.set.entry = _set_eh_entry;
	s->hdl.eh.set.phoff = _set_eh_phoff;
	s->hdl.eh.set.phentsize = _set_eh_phentsize;
	s->hdl.eh.set.shstrndx = _set_eh_shstrndx;
	s->hdl.eh.set.phnum = _set_eh_phnum;
	s->hdl.eh.set.shoff = _set_eh_shoff;
	s->hdl.eh.set.shentsize = _set_eh_shentsize;
	s->hdl.eh.set.shnum = _set_eh_shnum;
	// ph getters
	s->hdl.ph.get.type = _get_ph_type;
	s->hdl.ph.get.flags = _get_ph_flags;
	s->hdl.ph.get.offset = _get_ph_offset;
	s->hdl.ph.get.vaddr = _get_ph_vaddr;
	s->hdl.ph.get.paddr = _get_ph_paddr;
	s->hdl.ph.get.filesz = _get_ph_filesz;
	s->hdl.ph.get.memsz = _get_ph_memsz;
	s->hdl.ph.get.align = _get_ph_align;
	// ph setters
	s->hdl.ph.set.type = _set_ph_type;
	s->hdl.ph.set.flags = _set_ph_flags;
	s->hdl.ph.set.offset = _set_ph_offset;
	s->hdl.ph.set.vaddr = _set_ph_vaddr;
	s->hdl.ph.set.paddr = _set_ph_paddr;
	s->hdl.ph.set.filesz = _set_ph_filesz;
	s->hdl.ph.set.memsz = _set_ph_memsz;
	s->hdl.ph.set.align = _set_ph_align;
	// sh getters
	s->hdl.sh.get.name = _get_sh_name;
	s->hdl.sh.get.type = _get_sh_type;
	s->hdl.sh.get.flags = _get_sh_flags;
	s->hdl.sh.get.addr = _get_sh_addr;
	s->hdl.sh.get.offset = _get_sh_offset;
	s->hdl.sh.get.size = _get_sh_size;
	s->hdl.sh.get.link = _get_sh_link;
	s->hdl.sh.get.info = _get_sh_info;
	s->hdl.sh.get.addralign = _get_sh_addralign;
	s->hdl.sh.get.entsize = _get_sh_entsize;
	// sh setters
	s->hdl.sh.set.name = _set_sh_name;
	s->hdl.sh.set.type = _set_sh_type;
	s->hdl.sh.set.flags = _set_sh_flags;
	s->hdl.sh.set.addr = _set_sh_addr;
	s->hdl.sh.set.offset = _set_sh_offset;
	s->hdl.sh.set.size = _set_sh_size;
	s->hdl.sh.set.link = _set_sh_link;
	s->hdl.sh.set.info = _set_sh_info;
	s->hdl.sh.set.addralign = _set_sh_addralign;
	s->hdl.sh.set.entsize = _set_sh_entsize;
}

static
uint64_t	_get_eh_entry(
				const t_elf_file *s
				)
{
	return (s->io.read32(s->data, ELF32_OFF__EH_ENTRY));
}

static
uint64_t	_get_eh_phoff(
				const t_elf_file *s
				)
{
	return (s->io.read32(s->data, ELF32_OFF__EH_PHOFF));
}

static
uint16_t	_get_eh_shstrndx(
				const t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF32_OFF__EH_SHSTRNDX));
}

static
uint16_t	_get_eh_phentsize(
				const t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF32_OFF__EH_PHENTSIZE));
}

static
uint16_t	_get_eh_phnum(
				const t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF32_OFF__EH_PHNUM));
}

static
uint16_t	_get_eh_type(
				const t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF32_OFF__EH_TYPE));
}

static
void		*_get_pht(
				const t_elf_file *s
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_phoff(s);

	return ((void *)&base[off]);
}

static
void		*_get_ph(
				const t_elf_file *s,
				size_t n
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_phoff(s);
	const uint32_t	entsize = _get_eh_phentsize(s);

	return ((void *)&base[off + n * entsize]);
}

static
void		_set_eh_entry(
				t_elf_file *s,
				uint64_t entry
				)
{
	s->io.write32(s->data, ELF32_OFF__EH_ENTRY, entry);
}

static
void		_set_eh_phoff(
				t_elf_file *s,
				uint64_t off
				)
{
	s->io.write32(s->data, ELF32_OFF__EH_PHOFF, off);
}

static
void		_set_eh_shstrndx(
				t_elf_file *s,
				uint16_t shstrndx
				)
{
	s->io.write16(s->data, ELF32_OFF__EH_SHSTRNDX, shstrndx);
}

static
void		_set_eh_phentsize(
				t_elf_file *s,
				uint16_t entsize
				)
{
	s->io.write16(s->data, ELF32_OFF__EH_PHENTSIZE, entsize);
}

static
void		_set_eh_phnum(
				t_elf_file *s,
				uint16_t num
				)
{
	s->io.write16(s->data, ELF32_OFF__EH_PHNUM, num);
}

static
uint64_t	_get_eh_shoff(
				const t_elf_file *s
				)
{
	return (s->io.read32(s->data, ELF32_OFF__EH_SHOFF));
}

static
uint16_t	_get_eh_shentsize(
				const t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF32_OFF__EH_SHENTSIZE));
}

static
uint16_t	_get_eh_shnum(
				const t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF32_OFF__EH_SHNUM));
}

static
void		*_get_sht(
				const t_elf_file *s
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_shoff(s);

	return ((void *)&base[off]);
}

static
void		*_get_sh(
				const t_elf_file *s,
				size_t n
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_shoff(s);
	const uint32_t	entsize = _get_eh_shentsize(s);

	return ((void *)&base[off + n * entsize]);
}

static
void		_set_eh_shoff(
				t_elf_file *s,
				uint64_t off
				)
{
	s->io.write32(s->data, ELF32_OFF__EH_SHOFF, off);
}

static
void		_set_eh_shentsize(
				t_elf_file *s,
				uint16_t entsize
				)
{
	s->io.write16(s->data, ELF32_OFF__EH_SHENTSIZE, entsize);
}

static
void		_set_eh_shnum(
				t_elf_file *s,
				uint16_t num
				)
{
	s->io.write16(s->data, ELF32_OFF__EH_SHNUM, num);
}

static
uint32_t	_get_ph_type(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_TYPE));
}

static
uint32_t	_get_ph_flags(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_FLAGS));
}

static
uint64_t	_get_ph_offset(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_OFFSET));
}

static
uint64_t	_get_ph_vaddr(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_VADDR));
}

static
uint64_t	_get_ph_paddr(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_PADDR));
}

static
uint64_t	_get_ph_filesz(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_FILESZ));
}

static
uint64_t	_get_ph_memsz(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_MEMSZ));
}

static
uint64_t	_get_ph_align(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF32_OFF__PH_ALIGN));
}

static
void		_set_ph_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_TYPE, type);
}

static
void		_set_ph_flags(
				t_elf_file *s,
				size_t n,
				uint32_t flags
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_FLAGS, flags);
}

static
void		_set_ph_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_OFFSET, offset);
}

static
void		_set_ph_vaddr(
				t_elf_file *s,
				size_t n,
				uint64_t vaddr
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_VADDR, vaddr);
}

static
void		_set_ph_paddr(
				t_elf_file *s,
				size_t n,
				uint64_t paddr
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_PADDR, paddr);
}

static
void		_set_ph_filesz(
				t_elf_file *s,
				size_t n,
				uint64_t filesz
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_FILESZ, filesz);
}

static
void		_set_ph_memsz(
				t_elf_file *s,
				size_t n,
				uint64_t memsz
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_MEMSZ, memsz);
}

static
void		_set_ph_align(
				t_elf_file *s,
				size_t n,
				uint64_t align
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF32_OFF__PH_ALIGN, align);
}

static
uint32_t	_get_sh_name(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_NAME));
}

static
uint32_t	_get_sh_type(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_TYPE));
}

static
uint64_t	_get_sh_flags(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_FLAGS));
}

static
uint64_t	_get_sh_addr(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_ADDR));
}

static
uint64_t	_get_sh_offset(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_OFFSET));
}

static
uint64_t	_get_sh_size(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_SIZE));
}

static
uint32_t	_get_sh_link(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_LINK));
}

static
uint32_t	_get_sh_info(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_INFO));
}

static
uint64_t	_get_sh_addralign(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_ADDRALIGN));
}

static
uint64_t	_get_sh_entsize(
				const t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF32_OFF__SH_ENTSIZE));
}

static
void		_set_sh_name(
				t_elf_file *s,
				size_t n,
				uint32_t name
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_NAME, name);
}

static
void		_set_sh_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_TYPE, type);
}

static
void		_set_sh_flags(
				t_elf_file *s,
				size_t n,
				uint64_t flags
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_FLAGS, flags);
}

static
void		_set_sh_addr(
				t_elf_file *s,
				size_t n,
				uint64_t addr
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_ADDR, addr);
}

static
void		_set_sh_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_OFFSET, offset);
}

static
void		_set_sh_size(
				t_elf_file *s,
				size_t n,
				uint64_t size
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_SIZE, size);
}

static
void		_set_sh_link(
				t_elf_file *s,
				size_t n,
				uint32_t link
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_LINK, link);
}

static
void		_set_sh_info(
				t_elf_file *s,
				size_t n,
				uint32_t info
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_INFO, info);
}

static
void		_set_sh_addralign(
				t_elf_file *s,
				size_t n,
				uint64_t addralign
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_ADDRALIGN, addralign);
}

static
void		_set_sh_entsize(
				t_elf_file *s,
				size_t n,
				uint64_t entsize
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF32_OFF__SH_ENTSIZE, entsize);
}
