/**
 * @file packer_def.h
 * @brief 64-bit packer data structure definition.
 */

#ifndef PACKER_64_PACKER_DEF_H
#define PACKER_64_PACKER_DEF_H

// ---
// Includes
// ---

#include <stdint.h>
#include "famine.h"

// ---
// Typedefs
// ---

/**
 * @brief Stub metadata populated by the packer.
 *
 * This structure is embedded in the packer's .packer.data section and filled
 * at pack time with runtime decryption parameters.
 */
typedef struct __attribute__((packed)) {
	uint64_t	packer_virt_off;   /**< Stub's virtual address offset. */
	uint64_t	entry_point;     /**< Original program entry point. */
	uint64_t	ranges_ptr;      /**< Protected ranges array vaddr. */
	uint64_t	ranges_len;      /**< Number of protected ranges. */
	uint64_t	bss_ranges_ptr;  /**< BSS ranges array vaddr. */
	uint64_t	bss_ranges_len;  /**< Number of BSS ranges. */
	uint8_t		key[16];         /**< XTEA key */
}	t_packer_64_data;

#endif
