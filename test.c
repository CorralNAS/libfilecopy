#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <err.h>

#include "filecopy.h"

int
main(int ac, char **av)
{
	filecopy_options_t opts;
	char *src, *dst;
	
	if (ac != 3) {
		errx(1, "usage: %s <src> <dst>", av[0]);
	}
	src = av[1]; dst = av[2];
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

	filecopy(opts, src, dst);
	return 0;
}
