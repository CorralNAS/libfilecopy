LIB=    filecopy
SHLIBDIR?= /lib
SHLIB_MAJOR=    1

SRCS=   filecopy.c
INCS=   filecopy.h

MAN=

DEBUG_FLAGS = -O0 -g
CFLAGS+=	-fblocks
CFLAGS+= -I${.CURDIR}
LDADD+= -lBlocksRuntime

.include <bsd.lib.mk>

t:	filecopy.o test.o
	$(CC) -g $(CFLAGS) filecopy.o test.o -lBlocksRuntime -o t

