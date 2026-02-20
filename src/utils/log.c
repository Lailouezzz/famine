/**
 * @file
 * @brief Log helpers
 */

// ---
// Includes
// ---

#include <stdarg.h>
#include <errno.h>

#include "utils.h"

// ---
// Local variables
// ---

static bool	_verbose = false;
static const char	*_pn = nullptr;

// ---
// Extern function definitions
// ---

void	verbose(
			const char *fmt, ...
			) {
	va_list	args;

	if (!_verbose)
		return ;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void	error_msg(
			const char *fmt, ...
			) {
	va_list	args;

	fprintf(stderr, "%s: ", _pn);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
}

void	perror_msg(
			const char *fmt, ...
			) {
	va_list	args;

	fprintf(stderr, "%s: ", _pn);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, ": %s\n", strerror(errno));
}

void	set_verbose(bool verbose) {
	_verbose = verbose;
}

void	set_pn(const char *pn) {
	_pn = pn;
}
