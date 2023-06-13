/* Sharp LR35902 Disassembler
 *
 * Copyright 2023 Nico Sonack <nsonack@herrhotzenplotz.de>
 *
 * The Sharp LR35902 is a Zilog Z80 / Intel 8080 compatible custom
 * 16-bit microprocessor used in the early Nintendo GameBoys. */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum paramkind {
	PARAM_NONE = 0,
	PARAM_D16,
	PARAM_A16,
	PARAM_D8,
	PARAM_A8,
	PARAM_R8,
	PARAM_SPPLUSR8,
	PARAM_STR,

	PARAM_INDIR = 0x80, /* indirected */
};
union param {
	uint16_t d16;
	uint8_t d8;
	char const *const str;
};

struct instdef
{
	char const *const mnem;
	size_t len;

	union param param0;
	enum paramkind param0kind;
	union param param1;
	enum paramkind param1kind;
};

#include "instrs.h"

struct {
	uint16_t addr;
	uint8_t *begin, *hd;
	size_t len;
} readbuf;

static void
emitparam(unsigned kind, union param *data)
{
	if (kind & PARAM_INDIR)
		putchar('(');

	switch (kind & ~PARAM_INDIR) {
	case PARAM_NONE: {
	} break;
	case PARAM_STR: {
		printf("%s", data->str);
	} break;
	case PARAM_A16:
	case PARAM_D16: {
		uint16_t p = *readbuf.hd++;
		p |= (*readbuf.hd++) << 8;
		printf("%04XH", p);
	} break;
	case PARAM_A8:
	case PARAM_D8: {
		uint8_t p = *readbuf.hd++;
		printf("%02XH", p);
	} break;
	case PARAM_R8: {
		int8_t p = *(int8_t *)readbuf.hd++;
		printf("PC%+"PRId8, p);
	} break;
	case PARAM_SPPLUSR8: {
		int8_t p = *(int8_t *)readbuf.hd++;
		printf("SP%+"PRId8, p);
	} break;
	default: {
		assert(0 && "Not implemented");
	} break;
	}

	if (kind & PARAM_INDIR)
		putchar(')');
}

static void
readinst(void)
{
	uint8_t byte = readbuf.hd[0];
	struct instdef *in;

	printf("0x%04X :", readbuf.addr);

	if (byte == 0xCB) {
		uint8_t nbyte = readbuf.hd[1];
		in = &cbprefixed_instructions[nbyte];
	} else {
	        in = &unprefixed_instructions[byte];
	}

	/* undefined instruction */
	if (in->mnem == NULL) {
		printf(" %02X       : ???\n", byte);
		readbuf.hd += byte == 0xCB ? 2 : 1;
		readbuf.addr += 1;
		readbuf.len -= 1;
		return;
	}

	for (int i = 0; i < in->len; ++i)
		printf(" %02X", *(readbuf.hd + i));

	for (int i = 3; i > in->len; --i)
		printf("   ");

	readbuf.hd += byte == 0xCB ? 2 : 1;

	printf(" : %s", in->mnem);

	if (in->param0kind == PARAM_NONE)
		goto out;

	putchar(' ');

	emitparam(in->param0kind, &in->param0);

	if (in->param1kind == PARAM_NONE)
		goto out;

	printf(", ");

	emitparam(in->param1kind, &in->param1);

out:
	putchar('\n');

	assert((readbuf.addr + in->len) == (readbuf.hd - readbuf.begin));

	readbuf.addr += in->len;
	readbuf.len -= in->len;
}

static void
disassemble(void)
{
	for (;;) {
		if (readbuf.len == 0)
			break;

		readinst();

		if (readbuf.addr == 0)
			break;
	}
}

int
main(int argc, char *argv[])
{
	int fd;
	struct stat sb;

	if (argc != 2)
		errx(1, "missing input file or invalid flags");

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		err(1, "open %s", argv[1]);

	if (fstat(fd, &sb) < 0)
		err(1, "stat");

	readbuf.len = sb.st_size;

	readbuf.begin = mmap(NULL, readbuf.len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (readbuf.begin == MAP_FAILED)
		err(1, "mmap");

	readbuf.hd = readbuf.begin;

	disassemble();

	close(fd);

	return 0;
}
