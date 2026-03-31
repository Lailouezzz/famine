#ifndef  PROTECT_RANGE_H
# define PROTECT_RANGE_H

// ---
// Includes
// ---

# include <sys/types.h>
# include "elf_reader.h"
# include "utils.h"

// ---
// Defines
// ---

# define MAKE_RANGE(_off, _len) (t_range){ .off = (_off), .len = (_len) }

// ---
// Typedefs
// ---

/**
 * @brief Parsed content of PT_DYNAMIC segment.
 *
 * All addresses are virtual addresses. Convert to file offsets
 * using elf_vaddr_to_offset() before accessing file data.
 */
typedef struct {
	/* String/Symbol tables */
	uint64_t strtab;           /**< DT_STRTAB - String table address */
	uint64_t strsz;            /**< DT_STRSZ - String table size */
	uint64_t symtab;           /**< DT_SYMTAB - Symbol table address */
	uint64_t syment;           /**< DT_SYMENT - Symbol entry size */

	/* Hash tables */
	uint64_t hash;             /**< DT_HASH - SYSV hash table */
	uint64_t gnu_hash;         /**< DT_GNU_HASH - GNU hash table */

	/* RELA relocations (with addend) */
	uint64_t rela;             /**< DT_RELA - RELA table address */
	uint64_t relasz;           /**< DT_RELASZ - RELA table size */
	uint64_t relaent;          /**< DT_RELAENT - RELA entry size */

	/* REL relocations (without addend) */
	uint64_t rel;              /**< DT_REL - REL table address */
	uint64_t relsz;            /**< DT_RELSZ - REL table size */
	uint64_t relent;           /**< DT_RELENT - REL entry size */

	/* PLT relocations */
	uint64_t jmprel;           /**< DT_JMPREL - PLT relocation table */
	uint64_t pltrelsz;         /**< DT_PLTRELSZ - PLT relocation size */
	uint64_t pltrel;           /**< DT_PLTREL - PLT relocation type (DT_REL/DT_RELA) */

	/* RELR relocations (compact format) */
	uint64_t relr;             /**< DT_RELR - RELR table address */
	uint64_t relrsz;           /**< DT_RELRSZ - RELR table size */
	uint64_t relrent;          /**< DT_RELRENT - RELR entry size */

	/* Initialization/Finalization */
	uint64_t init;             /**< DT_INIT - Init function address */
	uint64_t fini;             /**< DT_FINI - Fini function address */
	uint64_t init_array;       /**< DT_INIT_ARRAY - Init array address */
	uint64_t init_arraysz;     /**< DT_INIT_ARRAYSZ - Init array size */
	uint64_t fini_array;       /**< DT_FINI_ARRAY - Fini array address */
	uint64_t fini_arraysz;     /**< DT_FINI_ARRAYSZ - Fini array size */
	uint64_t preinit_array;    /**< DT_PREINIT_ARRAY - Preinit array address */
	uint64_t preinit_arraysz;  /**< DT_PREINIT_ARRAYSZ - Preinit array size */

	/* Symbol versioning */
	uint64_t versym;           /**< DT_VERSYM - Version symbol table */
	uint64_t verneed;          /**< DT_VERNEED - Version needed table */
	uint64_t verneednum;       /**< DT_VERNEEDNUM - Number of verneed entries */
	uint64_t verdef;           /**< DT_VERDEF - Version definition table */
	uint64_t verdefnum;        /**< DT_VERDEFNUM - Number of verdef entries */

	/* GOT/PLT */
	uint64_t pltgot;           /**< DT_PLTGOT - PLT/GOT address */

	/* Flags */
	uint64_t flags;            /**< DT_FLAGS */
	uint64_t flags_1;          /**< DT_FLAGS_1 */
	bool has_textrel;          /**< True if TEXTREL is set */
}	t_elf_dynamic;

typedef struct s_range {
	int64_t		off;
	uint64_t	len;
}	t_range;

TYPEDEF_LIST(t_range, ranges);

// ---
// Function declartions
// ---

/**
 * @brief 
 *
 * @param elf 
 * @param ranges 
 * @return true success; false error
 */
bool	elf_get_protected_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			);

void	range_aggregate(
			t_ranges *ranges
			);

bool	elf_get_bss_vaddr_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			);

#endif
