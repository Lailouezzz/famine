#include <stdlib.h>
#include <bits/getopt_core.h>
#include "utils.h"
#include "famine.h"

extern char _binary_resources_stub64_bin_start[];
extern char _binary_resources_stub64_bin_end[];
extern char _binary_resources_stub32_bin_start[];
extern char _binary_resources_stub32_bin_end[];

int	main(int argc, char **argv, char **envp) {
	UNUSED(envp);
	int			opt;

	set_pn(*argv);
	opterr = 0;
	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
			case 'v':
				set_verbose(true);
				break ;
		break;
			default:
				break ;
		}
	}
	argc -= optind;
	argv += optind;
	famine(
		_binary_resources_stub32_bin_start,
		_binary_resources_stub32_bin_end,
		_binary_resources_stub64_bin_start,
		_binary_resources_stub64_bin_end);
	return (EXIT_SUCCESS);
}
