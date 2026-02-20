/**
 * @file stub.h
 * @brief 32-bit stub declarations.
 */

#ifndef STUB_32_STUB_H
#define STUB_32_STUB_H

// ---
// Includes
// ---

#include <stddef.h>
#include <stdint.h>
#include "stub_def.h"

// ---
// Global variables
// ---

/** @brief Stub data populated by the packer. */
__attribute__((section(".stub.data")))
extern t_stub_32_data	g_stub_data;

// ---
// Function declarations
// ---

bool	elf_load(
			const char *path,
			void **base,
			void **entry);

#endif
