/**
 * @file packer.h
 * @brief 64-bit packer declarations.
 */

#ifndef PACKER_64_PACKER_H
#define PACKER_64_PACKER_H

// ---
// Includes
// ---

#include <stdint.h>
#include "packer_def.h"
#include "protect_range.h"

// ---
// Global variables
// ---

/** @brief Stub data populated by the packer. */
__attribute__((section(".packer.data")))
extern t_packer_64_data	g_packer_data;

// ---
// Function declarations
// ---

/**
 * @brief Decrypt all self-mappings using protected ranges.
 * @param base Base address of the loaded binary.
 * @param protected_ranges Array of ranges to skip during decryption.
 * @param ranges_len Number of protected ranges.
 * @param bss_ranges_ptr Array of BSS ranges (unmapped memory).
 * @param bss_ranges_len Number of BSS ranges.
 * @param key XTEA key.
 */
void	decrypt(
			uintptr_t base,
			t_range *protected_ranges,
			uint64_t ranges_len,
			t_range *bss_ranges_ptr,
			uint64_t bss_ranges_len,
			const char *key);

bool	elf_load(
			const char *path,
			void **base,
			void **entry);

#endif
