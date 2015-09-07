#include <stdio.h>
#include <stdlib.h>
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
	opts = filecopy_options_init();
	src = av[1]; dst = av[2];

	filecopy(opts, src, dst);
	return 0;
}
