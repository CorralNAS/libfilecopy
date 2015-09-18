LIB=    filecopy
SHLIBDIR?= /lib
SHLIB_MAJOR=    1

SRCS=   filecopy.c
INCS=   filecopy.h

MAN+=	filecopy.3		\
	filecopy_callbacks.3	\
	filecopy_set_option.3

MLINKS+=	filecopy_callbacks.3 filecopy_set_callback.3 \
		filecopy_callbacks.3 filecopy_set_block.3

MLINKS+=	filecopy_set_option.3 filecopy_options_init.3 \
		filecopy_set_option.3 filecopy_options_release.3 \
		filecopy_set_option.3 filecopy_set_bool.3 \
		filecopy_set_option.3 filecopy_set_int.3 \
		filecopy_set_option.3 fielcopy_set_string.3 \
		filecopy_set_option.3 filecopy_set_option.3

MLINKS==	filecopy.3 treecopy.3

DEBUG_FLAGS = -O0 -g
CFLAGS+=	-fblocks
CFLAGS+= -I${.CURDIR}
LDADD+= -lBlocksRuntime

.include <bsd.lib.mk>

t:	filecopy.o test.o
	$(CC) -g $(CFLAGS) filecopy.o test.o -lBlocksRuntime -o t

