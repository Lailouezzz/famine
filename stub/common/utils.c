/**
 * @file utils.c
 * @brief Runtime decryption utilities for the stub.
 */

// ---
// Includes
// ---


#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "protect_range.h"
#include "utils.h"
#include "encrypt.h"

// ---
// Defines
// ---

#define ishex(c) ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))

// ---
// Static function declarations
// ---

static const char	*_get_self_path();

static size_t		_read_maps(
						char **buf
						);

static uint64_t		_parse_hex(
						char **s
						);

static void		_skip_spaces(
					char **s
					);

static void		_skip_to_nl(
					char **s
					);

static bool		_parse_maps_line(
					char **maps,
					const char *self_path,
					uintptr_t *start,
					uintptr_t *end,
					uint64_t *off,
					int *perm
					);

static void		_decrypt_mapping(
					const t_ranges *ranges,
					uintptr_t start_vaddr,
					uintptr_t end_vaddr,
					off_t off,
					const char *key);

static uint64_t		_get_next_bss_off(
						const t_ranges *bss_ranges,
						uint64_t start_vaddr,
						uint64_t base
						);

// ---
// Extern function definitions
// ---

/**
 * @brief Decrypt all self-mappings using protected ranges.
 * @param base Base address of the loaded binary.
 * @param protected_ranges Array of ranges to skip during decryption.
 * @param ranges_len Number of protected ranges.
 * @param bss_ranges_ptr Array of BSS ranges (unmapped memory).
 * @param bss_ranges_len Number of BSS ranges.
 */
void	decrypt(uintptr_t base, t_range *protected_ranges, uint64_t ranges_len,
		t_range *bss_ranges_ptr, uint64_t bss_ranges_len, const char *key)
{
	char		*maps;
	void		*_maps;
	size_t		maps_size = _read_maps(&maps);
	uintptr_t	start_vaddr;
	uintptr_t	end_vaddr;
	uint64_t	off;
	const char	*self_path = _get_self_path();
	int		prev_perm;
	const t_ranges	ranges = {.data = protected_ranges, .len = ranges_len};
	const t_ranges	bss_ranges = {.data = bss_ranges_ptr, .len = bss_ranges_len};

	_maps = maps;
	while (*maps) {
		if (!_parse_maps_line(&maps, self_path, &start_vaddr, &end_vaddr,
			&off, &prev_perm))
			continue;
		const uint64_t next_bss_off = _get_next_bss_off(&bss_ranges,
			start_vaddr, base);
		mprotect((void *)start_vaddr, end_vaddr - start_vaddr,
			PROT_EXEC | PROT_WRITE | PROT_READ);
		_decrypt_mapping(&ranges, start_vaddr,
			(next_bss_off != 0 ? MIN(next_bss_off, end_vaddr) : end_vaddr) - 1,
			off, key);
		mprotect((void *)start_vaddr, end_vaddr - start_vaddr, prev_perm);
	}

	munmap(_maps, maps_size);
}

// ---
// Static function definitions
// ---

/** @brief Get the path to the current executable. */
static const char	*_get_self_path(void)
{
	static char	buf[0x1000] = {0};
	return readlink("/proc/self/exe", buf, sizeof(buf)) > 0 ? buf : "UNK";
}

/** @brief Read /proc/self/maps into a buffer. */
static size_t	_read_maps(char **buf)
{
	int	fd = open("/proc/self/maps", O_RDONLY);
	size_t	size = 0x1000;
	*buf = mmap(nullptr, size, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	size_t	off = 0;
	ssize_t	ret;
	while ((ret = read(fd, (char *)*buf + off, 0x1000)) != 0) {
		off += ret;
		if (off + 0x1000 > size) {
			*buf = mremap(*buf, size, size + 0x1000, MREMAP_MAYMOVE);
			size += 0x1000;
		}
	}
	close(fd);
	if (ret < 0)
		return 0;
	((char *)*buf)[off + ret] = '\0';
	return size;
}

/** @brief Parse a hexadecimal number from string. */
static uint64_t	_parse_hex(char **s)
{
	uint64_t nb = 0;
	while (ishex(**s)) {
		nb <<= 4;
		if (**s >= '0' && **s <= '9')
			nb += **s - '0';
		else
			nb += **s - 'a' + 10;
		++(*s);
	}
	return nb;
}

/** @brief Skip whitespace characters. */
static void	_skip_spaces(char **s)
{
	while (**s == ' ' || **s == '\t')
		++(*s);
}

/** @brief Skip to the next newline. */
static void	_skip_to_nl(char **s)
{
	while (**s != '\n' && **s)
		++(*s);
}

/**
 * @brief Parse a single line from /proc/self/maps.
 * @param maps Pointer to current position in maps buffer (updated).
 * @param self_path Path to current executable.
 * @param start Output: start virtual address.
 * @param end Output: end virtual address.
 * @param off Output: file offset.
 * @param perm Output: memory permissions (PROT_*).
 * @return true if this line matches self_path, false otherwise.
 */
static bool	_parse_maps_line(char **maps, const char *self_path,
			uintptr_t *start, uintptr_t *end, uint64_t *off, int *perm)
{
	bool	is_self;

	*perm = 0;
	*start = _parse_hex(maps);
	++(*maps); // skip '-'
	*end = _parse_hex(maps);
	_skip_spaces(maps);
	if (**maps != '-')
		*perm |= PROT_READ;
	if (*(++(*maps)) != '-')
		*perm |= PROT_WRITE;
	if (*(++(*maps)) != '-')
		*perm |= PROT_EXEC;
	*maps += 2;
	_skip_spaces(maps);
	*off = _parse_hex(maps);
	_skip_spaces(maps);
	_parse_hex(maps); // dev major
	++(*maps); // skip ':'
	_parse_hex(maps); // dev minor
	_skip_spaces(maps);
	_parse_hex(maps); // inode
	_skip_spaces(maps);
	// Check if path matches self
	is_self = memcmp(*maps, self_path, strlen(self_path)) == 0
		&& (*maps)[strlen(self_path)] == '\n';
	_skip_to_nl(maps);
	++(*maps);
	return is_self;
}

/** @brief Get the next BSS offset after start_vaddr. */
static uint64_t	_get_next_bss_off(const t_ranges *bss_ranges,
			uint64_t start_vaddr, uint64_t base)
{
	size_t vaddr = 0;
	size_t k = 0;
	while (k < bss_ranges->len && vaddr < start_vaddr) {
		vaddr = bss_ranges->data[k].off + base;
		++k;
	}
	if (vaddr <= start_vaddr)
		return 0;
	return vaddr;
}

/** @brief Decrypt a single memory mapping between protected ranges. */
static void	_decrypt_mapping(const t_ranges *ranges, uintptr_t start_vaddr,
			uintptr_t end_vaddr, off_t off, const char *key)
{
	size_t	range_idx = 0;

	while (range_idx < ranges->len && ranges->data[range_idx].off < off)
		++range_idx;
	for (size_t k = MAX(1, range_idx); k < ranges->len; ++k) {
		auto const begin_vaddr = MAX(start_vaddr,
			ALIGN_UP(ranges->data[k - 1].off + ranges->data[k - 1].len, 8)
			+ start_vaddr - off);
		if (begin_vaddr >= end_vaddr)
			return;
		auto const size = MIN(
			((off_t)ALIGN_DOWN(ranges->data[k].off, 8))
			- (begin_vaddr - start_vaddr) - off,
			end_vaddr - begin_vaddr + 1);
		if (size == 0 || ALIGN_UP(ranges->data[k - 1].off
			+ ranges->data[k - 1].len, 8)
			>= ALIGN_DOWN(ranges->data[k].off, 8))
			continue;
		xtea_decrypt((void *)(uintptr_t)begin_vaddr, size,
			(const uint32_t *)key);
	}
	// After the last range TODO: HANDLE FILE SIZE CHANGE AFTER PACKING
	// auto const begin_vaddr = MAX(start_vaddr, ALIGN_UP(ranges->data[ranges->len - 1].off + ranges->data[ranges->len - 1].len, 8) + start_vaddr - off);
	// if (begin_vaddr >= end_vaddr)
	// 	return ;
	// xtea_encrypt((void *)(uintptr_t)begin_vaddr,
	// 	end_vaddr - begin_vaddr + 1, (const uint32_t *)"1234567812345678");
}
