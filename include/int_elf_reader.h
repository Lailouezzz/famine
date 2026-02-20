/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   int_elf_reader.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/16 09:03:30 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 13:05:27 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef INT_ELF_READER_H
# define INT_ELF_READER_H

# include "elf_reader.h"

void	int_elf_load_32bit_handlers(
			t_elf_file *s
			);

void	int_elf_load_64bit_handlers(
			t_elf_file *s
			);

void	int_elf_load_le_raw_io(
			t_elf_file *s
			);

void	int_elf_load_be_raw_io(
			t_elf_file *s
			);

#endif
