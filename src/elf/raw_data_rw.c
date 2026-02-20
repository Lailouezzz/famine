/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   raw_data_rw.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/16 09:02:45 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 13:07:20 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "int_elf_reader.h"

#include <stdint.h>
#include <string.h>

static
uint8_t		_read8_le(
				const void *data,
				size_t offset
				);

static
uint8_t		_read8_be(
				const void *data,
				size_t offset
				);

static
uint16_t	_read16_le(
				const void *data,
				size_t offset
				);

static
uint16_t	_read16_be(
				const void *data,
				size_t offset
				);

static
uint32_t	_read32_le(
				const void *data,
				size_t offset
				);

static
uint32_t	_read32_be(
				const void *data,
				size_t offset
				);

static
uint64_t	_read64_le(
				const void *data,
				size_t offset
				);

static
uint64_t	_read64_be(
				const void *data,
				size_t offset
				);

static
void		_write8_le(
				void *data,
				size_t offset,
				uint8_t v
				);

static
void		_write8_be(
				void *data,
				size_t offset,
				uint8_t v
				);

static
void		_write16_le(
					void *data,
					size_t offset,
					uint16_t v
					);

static
void		_write16_be(
					void *data,
					size_t offset,
					uint16_t v
					);

static
void		_write32_le(
					void *data,
					size_t offset,
					uint32_t v
					);

static
void		_write32_be(
					void *data,
					size_t offset,
					uint32_t v
					);

static
void		_write64_le(
					void *data,
					size_t offset,
					uint64_t v
					);

static
void		_write64_be(
					void *data,
					size_t offset,
					uint64_t v
					);

void	int_elf_load_le_raw_io(
			t_elf_file *s
			)
{
	s->io.read8 = _read8_le;
	s->io.read16 = _read16_le;
	s->io.read32 = _read32_le;
	s->io.read64 = _read64_le;
	s->io.write8 = _write8_le;
	s->io.write16 = _write16_le;
	s->io.write32 = _write32_le;
	s->io.write64 = _write64_le;
}

void	int_elf_load_be_raw_io(
			t_elf_file *s
			)
{
	s->io.read8 = _read8_be;
	s->io.read16 = _read16_be;
	s->io.read32 = _read32_be;
	s->io.read64 = _read64_be;
	s->io.write8 = _write8_be;
	s->io.write16 = _write16_be;
	s->io.write32 = _write32_be;
	s->io.write64 = _write64_be;
}

static
uint8_t		_read8_le(
				const void *data,
				size_t offset
				)
{
	return (((uint8_t *)data)[offset]);
}

static
uint8_t		_read8_be(
				const void *data,
				size_t offset
				)
{
	return (((uint8_t *)data)[offset]);
}

static
uint16_t	_read16_le(
				const void *data,
				size_t offset
				)
{
	const uint16_t	a = ((uint8_t *)data)[offset + 0];
	const uint16_t	b = ((uint8_t *)data)[offset + 1];

	return ((a << 0) | (b << 8));
}

static
uint16_t	_read16_be(
				const void *data,
				size_t offset
				)
{
	const uint16_t	a = ((uint8_t *)data)[offset + 0];
	const uint16_t	b = ((uint8_t *)data)[offset + 1];

	return ((b << 0) | (a << 8));
}

static
uint32_t	_read32_le(
				const void *data,
				size_t offset
				)
{
	const uint32_t	a = ((uint8_t *)data)[offset + 0];
	const uint32_t	b = ((uint8_t *)data)[offset + 1];
	const uint32_t	c = ((uint8_t *)data)[offset + 2];
	const uint32_t	d = ((uint8_t *)data)[offset + 3];

	return ((a << 0) | (b << 8) | (c << 16) | (d << 24));
}

static
uint32_t	_read32_be(
				const void *data,
				size_t offset
				)
{
	const uint32_t	a = ((uint8_t *)data)[offset + 0];
	const uint32_t	b = ((uint8_t *)data)[offset + 1];
	const uint32_t	c = ((uint8_t *)data)[offset + 2];
	const uint32_t	d = ((uint8_t *)data)[offset + 3];

	return ((d << 0) | (c << 8) | (b << 16) | (a << 24));
}

static
uint64_t	_read64_le(
				const void *data,
				size_t offset
				)
{
	const uint64_t	a = ((uint8_t *)data)[offset + 0];
	const uint64_t	b = ((uint8_t *)data)[offset + 1];
	const uint64_t	c = ((uint8_t *)data)[offset + 2];
	const uint64_t	d = ((uint8_t *)data)[offset + 3];
	const uint64_t	e = ((uint8_t *)data)[offset + 4];
	const uint64_t	f = ((uint8_t *)data)[offset + 5];
	const uint64_t	g = ((uint8_t *)data)[offset + 6];
	const uint64_t	h = ((uint8_t *)data)[offset + 7];

	return ((a << 0) | (b << 8) | (c << 16) | (d << 24) | (e << 32) | (f << 40) | (g << 48) | (h << 56));
}

static
uint64_t	_read64_be(
				const void *data,
				size_t offset
				)
{
	const uint64_t	a = ((uint8_t *)data)[offset + 0];
	const uint64_t	b = ((uint8_t *)data)[offset + 1];
	const uint64_t	c = ((uint8_t *)data)[offset + 2];
	const uint64_t	d = ((uint8_t *)data)[offset + 3];
	const uint64_t	e = ((uint8_t *)data)[offset + 4];
	const uint64_t	f = ((uint8_t *)data)[offset + 5];
	const uint64_t	g = ((uint8_t *)data)[offset + 6];
	const uint64_t	h = ((uint8_t *)data)[offset + 7];

	return ((h << 0) | (g << 8) | (f << 16) | (e << 24) | (d << 32) | (c << 40) | (b << 48) | (a << 56));
}

static
void		_write8_le(
				void *data,
				size_t offset,
				uint8_t v
				)
{
	uint8_t	*const d = data;

	d[offset] = v;
}

static
void		_write8_be(
				void *data,
				size_t offset,
				uint8_t v
				)
{
	uint8_t	*const d = data;

	d[offset] = v;
}

static
void		_write16_be(
					void *data,
					size_t offset,
					uint16_t v
					)
{
	uint8_t	*const d = data;

	d[offset + 0] = (v >> 8) & 0xFF;
	d[offset + 1] = (v >> 0) & 0xFF;
}

static
void		_write16_le(
					void *data,
					size_t offset,
					uint16_t v
					)
{
	uint8_t	*const d = data;

	d[offset + 0] = (v >> 0) & 0xFF;
	d[offset + 1] = (v >> 8) & 0xFF;
}

static
void		_write32_be(
					void *data,
					size_t offset,
					uint32_t v
					)
{
	uint8_t	*const d = data;

	d[offset + 0] = (v >> 24) & 0xFF;
	d[offset + 1] = (v >> 16) & 0xFF;
	d[offset + 2] = (v >>  8) & 0xFF;
	d[offset + 3] = (v >>  0) & 0xFF;
}

static
void		_write32_le(
					void *data,
					size_t offset,
					uint32_t v
					)
{
	uint8_t	*const d = data;

	d[offset + 0] = (v >>  0) & 0xFF;
	d[offset + 1] = (v >>  8) & 0xFF;
	d[offset + 2] = (v >> 16) & 0xFF;
	d[offset + 3] = (v >> 24) & 0xFF;
}

static
void		_write64_be(
					void *data,
					size_t offset,
					uint64_t v
					)
{
	uint8_t	*const d = data;

	d[offset + 0] = (v >> 56) & 0xFF;
	d[offset + 1] = (v >> 48) & 0xFF;
	d[offset + 2] = (v >> 40) & 0xFF;
	d[offset + 3] = (v >> 32) & 0xFF;
	d[offset + 4] = (v >> 24) & 0xFF;
	d[offset + 5] = (v >> 16) & 0xFF;
	d[offset + 6] = (v >>  8) & 0xFF;
	d[offset + 7] = (v >>  0) & 0xFF;
}

static
void		_write64_le(
					void *data,
					size_t offset,
					uint64_t v
					)
{
	uint8_t	*const d = data;

	d[offset + 0] = (v >>  0) & 0xFF;
	d[offset + 1] = (v >>  8) & 0xFF;
	d[offset + 2] = (v >> 16) & 0xFF;
	d[offset + 3] = (v >> 24) & 0xFF;
	d[offset + 4] = (v >> 32) & 0xFF;
	d[offset + 5] = (v >> 40) & 0xFF;
	d[offset + 6] = (v >> 48) & 0xFF;
	d[offset + 7] = (v >> 56) & 0xFF;
}
