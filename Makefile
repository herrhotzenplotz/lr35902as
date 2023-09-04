PROGS=	\
	lr35902dis \
	lr35902as

CLEANFILES=	instrs.h

CC=c99
CFLAGS=	-g -O0

.PHONY: all clean

all: ${PROGS}
	${MAKE} -C sample

instrs.h: opcodes.json gentab.jq gentab.awk gentab.sh
	sh gentab.sh > instrs.h

lr35902dis.c: instrs.h

clean:
	rm -f ${CLEANFILES} ${PROGS}
