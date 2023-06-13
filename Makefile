PROGS=	\
	lr35902dis \
	lr35902as

CLEANFILES=	instrs.h
MAN=

CSTD=	c99

instrs.h: opcodes.json genoptable.sh
	./genoptable.sh > instrs.h

lr35902dis.c: instrs.h

.include <bsd.progs.mk>
