/**
 * @file stub.h
 * @brief 64-bit stub declarations.
 */

#ifndef STUB_64_STUB_H
#define STUB_64_STUB_H

// ---
// Includes
// ---

#include <stdint.h>
#include "stub_def.h"

// ---
// Global variables
// ---

/** @brief Stub data populated by the packer. */
__attribute__((section(".stub.data")))
extern t_stub_64_data	g_stub_data;

// ---
// Function declarations
// ---

bool	elf_load(
			const char *path,
			void **base,
			void **entry);

#endif
