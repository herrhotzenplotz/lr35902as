PROGS=	\
	lr35902dis \
	lr35902as

CLEANFILES=	instrs.h

CC=c99
CFLAGS=	-g -O0

.PHONY: all clean

all: ${PROGS}

instrs.h: opcodes.json genoptable.sh
	./genoptable.sh > instrs.h

lr35902dis.c: instrs.h

clean:
	rm -f ${CLEANFILES} ${PROGS}
