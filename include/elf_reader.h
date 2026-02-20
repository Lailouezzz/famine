/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf_reader.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/15 14:05:14 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 13:17:38 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef ELF_READER_H
# define ELF_READER_H

# include <elf.h>

# ifndef DT_RELR
#  define DT_RELR      36
#  define DT_RELRSZ    35
#  define DT_RELRENT   37
# endif

# include <stdlib.h>
# include <stdint.h>

typedef struct s_elf_file	t_elf_file;

typedef struct s_elf_handler
{
	struct
	{
		struct
		{
			uint64_t	(*entry)(const t_elf_file *);
			uint64_t	(*phoff)(const t_elf_file *);
			uint16_t	(*phentsize)(const t_elf_file *);
			uint16_t	(*phnum)(const t_elf_file *);
			uint64_t	(*shoff)(const t_elf_file *);
			uint16_t	(*shentsize)(const t_elf_file *);
			uint16_t	(*shstrndx)(const t_elf_file *);
			uint16_t	(*shnum)(const t_elf_file *);
			uint16_t	(*type)(const t_elf_file *);
			void		*(*pht)(const t_elf_file *);
			void		*(*ph)(const t_elf_file *, size_t);
			void		*(*sht)(const t_elf_file *);
			void		*(*sh)(const t_elf_file *, size_t);
		}	get;
		struct
		{
			void	(*entry)(t_elf_file *, uint64_t);
			void	(*phoff)(t_elf_file *, uint64_t);
			void	(*phentsize)(t_elf_file *, uint16_t);
			void	(*phnum)(t_elf_file *, uint16_t);
			void	(*shoff)(t_elf_file *, uint64_t);
			void	(*shentsize)(t_elf_file *, uint16_t);
			void	(*shstrndx)(t_elf_file *, uint16_t);
			void	(*shnum)(t_elf_file *, uint16_t);
		}	set;
	}	eh;
	struct
	{
		struct
		{
			uint32_t	(*type)(const t_elf_file *, size_t);
			uint32_t	(*flags)(const t_elf_file *, size_t);
			uint64_t	(*offset)(const t_elf_file *, size_t);
			uint64_t	(*vaddr)(const t_elf_file *, size_t);
			uint64_t	(*paddr)(const t_elf_file *, size_t);
			uint64_t	(*filesz)(const t_elf_file *, size_t);
			uint64_t	(*memsz)(const t_elf_file *, size_t);
			uint64_t	(*align)(const t_elf_file *, size_t);
		}	get;
		struct
		{
			void	(*type)(t_elf_file *, size_t, uint32_t);
			void	(*flags)(t_elf_file *, size_t, uint32_t);
			void	(*offset)(t_elf_file *, size_t, uint64_t);
			void	(*vaddr)(t_elf_file *, size_t, uint64_t);
			void	(*paddr)(t_elf_file *, size_t, uint64_t);
			void	(*filesz)(t_elf_file *, size_t, uint64_t);
			void	(*memsz)(t_elf_file *, size_t, uint64_t);
			void	(*align)(t_elf_file *, size_t, uint64_t);
		}	set;
	}	ph;
	struct
	{
		struct
		{
			uint32_t	(*name)(const t_elf_file *, size_t);
			uint32_t	(*type)(const t_elf_file *, size_t);
			uint64_t	(*flags)(const t_elf_file *, size_t);
			uint64_t	(*addr)(const t_elf_file *, size_t);
			uint64_t	(*offset)(const t_elf_file *, size_t);
			uint64_t	(*size)(const t_elf_file *, size_t);
			uint32_t	(*link)(const t_elf_file *, size_t);
			uint32_t	(*info)(const t_elf_file *, size_t);
			uint64_t	(*addralign)(const t_elf_file *, size_t);
			uint64_t	(*entsize)(const t_elf_file *, size_t);
		}	get;
		struct
		{
			void	(*name)(t_elf_file *, size_t, uint32_t);
			void	(*type)(t_elf_file *, size_t, uint32_t);
			void	(*flags)(t_elf_file *, size_t, uint64_t);
			void	(*addr)(t_elf_file *, size_t, uint64_t);
			void	(*offset)(t_elf_file *, size_t, uint64_t);
			void	(*size)(t_elf_file *, size_t, uint64_t);
			void	(*link)(t_elf_file *, size_t, uint32_t);
			void	(*info)(t_elf_file *, size_t, uint32_t);
			void	(*addralign)(t_elf_file *, size_t, uint64_t);
			void	(*entsize)(t_elf_file *, size_t, uint64_t);
		}	set;
	}	sh;
}	t_elf_handler;

typedef struct s_elf_io
{
	uint8_t		(*read8)(const void *, size_t);
	uint16_t	(*read16)(const void *, size_t);
	uint32_t	(*read32)(const void *, size_t);
	uint64_t	(*read64)(const void *, size_t);
	void		(*write8)(void *, size_t, uint8_t);
	void		(*write16)(void *, size_t, uint16_t);
	void		(*write32)(void *, size_t, uint32_t);
	void		(*write64)(void *, size_t, uint64_t);
}	t_elf_io;

struct s_elf_file
{
	size_t			size;
	void			*data;
	size_t			next_available_vaddr;
	size_t			pht_ph_load_index;
	t_elf_handler	hdl;
	t_elf_io		io;
	bool			is_64;
	int				fd;
};

int			elf_manager_load(
				t_elf_file *s,
				const char *path
				);

int			elf_manager_close(
				t_elf_file *s
				);

int			elf_manager_move_pht_and_emplace_entries(
				t_elf_file *s,
				size_t n
				);

int			elf_append_loadable_data_and_locate(
				t_elf_file *s,
				const void *data,
				size_t size,
				size_t align,
				size_t segment_align,
				size_t ph_index,
				uint32_t flags
				);

int			elf_append_loadable_data(
				t_elf_file *s,
				size_t off,
				size_t size,
				size_t align,
				size_t ph_index,
				uint32_t flags
				);

uint64_t	elf_vaddr_to_offset(
				const t_elf_file *s,
				uint64_t vaddr
				);

int			elf_find_ph_index(
				const t_elf_file *s,
				bool(*cond)(const t_elf_file *elf, size_t ph_index)
				);

bool		elf_ph_is_dynamic(
				const t_elf_file *s,
				size_t ph_index
				);

bool		elf_ph_is_interp(
				const t_elf_file *s,
				size_t ph_index
				);

int			elf_manager_finalize(
				t_elf_file *s,
				const char *path
				);

#endif
