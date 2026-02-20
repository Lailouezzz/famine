/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   int_elf_offset.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/17 11:08:34 by Antoine Mas       #+#    #+#             */
/*   Updated: 2025/12/17 16:45:11 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef INT_ELF_OFFSET_H
# define INT_ELF_OFFSET_H

# include <elf.h>
# include <stddef.h>

# define ELF32_OFF__EH_TYPE offsetof(Elf32_Ehdr, e_type)
# define ELF32_OFF__EH_ENTRY offsetof(Elf32_Ehdr, e_entry)
# define ELF32_OFF__EH_PHOFF offsetof(Elf32_Ehdr, e_phoff)
# define ELF32_OFF__EH_SHOFF offsetof(Elf32_Ehdr, e_shoff)
# define ELF32_OFF__EH_FLAGS offsetof(Elf32_Ehdr, e_flags)
# define ELF32_OFF__EH_EHSIZE offsetof(Elf32_Ehdr, e_ehsize)
# define ELF32_OFF__EH_PHENTSIZE offsetof(Elf32_Ehdr, e_phentsize)
# define ELF32_OFF__EH_SHSTRNDX offsetof(Elf32_Ehdr, e_shstrndx)
# define ELF32_OFF__EH_PHNUM offsetof(Elf32_Ehdr, e_phnum)
# define ELF32_OFF__EH_SHENTSIZE offsetof(Elf32_Ehdr, e_shentsize)
# define ELF32_OFF__EH_SHNUM offsetof(Elf32_Ehdr, e_shnum)

# define ELF32_OFF__PH_TYPE offsetof(Elf32_Phdr, p_type)
# define ELF32_OFF__PH_FLAGS offsetof(Elf32_Phdr, p_flags)
# define ELF32_OFF__PH_OFFSET offsetof(Elf32_Phdr, p_offset)
# define ELF32_OFF__PH_VADDR offsetof(Elf32_Phdr, p_vaddr)
# define ELF32_OFF__PH_PADDR offsetof(Elf32_Phdr, p_paddr)
# define ELF32_OFF__PH_FILESZ offsetof(Elf32_Phdr, p_filesz)
# define ELF32_OFF__PH_MEMSZ offsetof(Elf32_Phdr, p_memsz)
# define ELF32_OFF__PH_ALIGN offsetof(Elf32_Phdr, p_align)

# define ELF32_OFF__SH_NAME offsetof(Elf32_Shdr, sh_name)
# define ELF32_OFF__SH_TYPE offsetof(Elf32_Shdr, sh_type)
# define ELF32_OFF__SH_FLAGS offsetof(Elf32_Shdr, sh_flags)
# define ELF32_OFF__SH_ADDR offsetof(Elf32_Shdr, sh_addr)
# define ELF32_OFF__SH_OFFSET offsetof(Elf32_Shdr, sh_offset)
# define ELF32_OFF__SH_SIZE offsetof(Elf32_Shdr, sh_size)
# define ELF32_OFF__SH_LINK offsetof(Elf32_Shdr, sh_link)
# define ELF32_OFF__SH_INFO offsetof(Elf32_Shdr, sh_info)
# define ELF32_OFF__SH_ADDRALIGN offsetof(Elf32_Shdr, sh_addralign)
# define ELF32_OFF__SH_ENTSIZE offsetof(Elf32_Shdr, sh_entsize)

# define ELF64_OFF__EH_TYPE offsetof(Elf64_Ehdr, e_type)
# define ELF64_OFF__EH_ENTRY offsetof(Elf64_Ehdr, e_entry)
# define ELF64_OFF__EH_PHOFF offsetof(Elf64_Ehdr, e_phoff)
# define ELF64_OFF__EH_SHOFF offsetof(Elf64_Ehdr, e_shoff)
# define ELF64_OFF__EH_FLAGS offsetof(Elf64_Ehdr, e_flags)
# define ELF64_OFF__EH_EHSIZE offsetof(Elf64_Ehdr, e_ehsize)
# define ELF64_OFF__EH_PHENTSIZE offsetof(Elf64_Ehdr, e_phentsize)
# define ELF64_OFF__EH_SHSTRNDX offsetof(Elf64_Ehdr, e_shstrndx)
# define ELF64_OFF__EH_PHNUM offsetof(Elf64_Ehdr, e_phnum)
# define ELF64_OFF__EH_SHENTSIZE offsetof(Elf64_Ehdr, e_shentsize)
# define ELF64_OFF__EH_SHNUM offsetof(Elf64_Ehdr, e_shnum)

# define ELF64_OFF__PH_TYPE offsetof(Elf64_Phdr, p_type)
# define ELF64_OFF__PH_FLAGS offsetof(Elf64_Phdr, p_flags)
# define ELF64_OFF__PH_OFFSET offsetof(Elf64_Phdr, p_offset)
# define ELF64_OFF__PH_VADDR offsetof(Elf64_Phdr, p_vaddr)
# define ELF64_OFF__PH_PADDR offsetof(Elf64_Phdr, p_paddr)
# define ELF64_OFF__PH_FILESZ offsetof(Elf64_Phdr, p_filesz)
# define ELF64_OFF__PH_MEMSZ offsetof(Elf64_Phdr, p_memsz)
# define ELF64_OFF__PH_ALIGN offsetof(Elf64_Phdr, p_align)

# define ELF64_OFF__SH_NAME offsetof(Elf64_Shdr, sh_name)
# define ELF64_OFF__SH_TYPE offsetof(Elf64_Shdr, sh_type)
# define ELF64_OFF__SH_FLAGS offsetof(Elf64_Shdr, sh_flags)
# define ELF64_OFF__SH_ADDR offsetof(Elf64_Shdr, sh_addr)
# define ELF64_OFF__SH_OFFSET offsetof(Elf64_Shdr, sh_offset)
# define ELF64_OFF__SH_SIZE offsetof(Elf64_Shdr, sh_size)
# define ELF64_OFF__SH_LINK offsetof(Elf64_Shdr, sh_link)
# define ELF64_OFF__SH_INFO offsetof(Elf64_Shdr, sh_info)
# define ELF64_OFF__SH_ADDRALIGN offsetof(Elf64_Shdr, sh_addralign)
# define ELF64_OFF__SH_ENTSIZE offsetof(Elf64_Shdr, sh_entsize)

#endif
