#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <err.h>
#include <unistd.h>

#include "filecopy.h"

int
main(int ac, char **av)
{
	filecopy_options_t opts;
	char *src, *dst;
	int recursive = 0;
	int opt;
	char *progname = av[0];
	
	while ((opt = getopt(ac, av, "R")) != -1) {
		switch (opt) {
		case 'R':
			recursive = 1;
			break;
		default:
			errx(1, "Unknown options `%c'", opt);
		}
	}
	ac -= optind;
	av += optind;
	
	if (ac != 2) {
		errx(1, "usage: %s [-R] <src> <dst>", progname);
	}
	src = av[0]; dst = av[1];
	opts = filecopy_options_init();
	filecopy_set_block(opts, fc_option_status_block, ^(const char *k, ...) {
			printf("%s:  %s", src, k);
			if (k == fc_status_extattr_completion) {
				va_list ap;
				const char *eaname;
				va_start(ap, k);
				eaname = va_arg(ap, const char *);
				if (eaname) {
					printf(": %s", eaname);
				}
			}
			printf("\n");
			return FC_CONTINUE;
		});

	if (recursive)
		treecopy(opts, src, dst);
	else
		filecopy(opts, src, dst);
	return 0;
}
