/* Assembler for the Sharp LR35902
 *
 * Copyright 2023 Nico Sonack <nsonack@herrhotzenplotz.de> */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARRAY_SIZE(xs) ((sizeof(xs) / sizeof(*xs)))

static FILE *fout = NULL;       /* output file */
static FILE *lout = NULL;       /* listing file (optional) */
static FILE *sout = NULL;       /* symbol table file (optional) */
static int pass = 0;            /* pass number */

enum {
	TOKEN_IDENT,
	TOKEN_STRLIT,
	TOKEN_NUMBER,
	TOKEN_OPAREN = '(',
	TOKEN_CPAREN = ')',
	TOKEN_COLON = ':',
	TOKEN_COMMA = ',',
	TOKEN_PLUS = '+',
	TOKEN_MINUS = '-',
	TOKEN_EQ = '=',
	TOKEN_EOF = 0xFF,
};

struct token {
	char *begin, *end;      /* token span */
	int kind;               /* Token kind (see enum) */
	char const *filename;   /* file */
	int line, column;       /* token location */

	union {
		uint16_t number; /* value as a number */
	} value;

	TAILQ_ENTRY(token) next; /* token stack entry */
};

static TAILQ_HEAD(tokstk, token) tstack =
	TAILQ_HEAD_INITIALIZER(tstack); /* tokenstack */

#define token_len(t) ((t)->end - (t)->begin)

struct lexbuf {
	struct lexbuf *parent;  /* Lexbuf chain when processing includes */
	char const *filename;   /* file name */
	int line, column;       /* current location in buffer */
	int fd;                 /* fd of mapped object */

	char *hd, *buffer;      /* front pointer and pointer to mapped buffer */
	char *sol;              /* start of line pointer */
	size_t buflen, len;     /* length of mapped buffer and length
	                         * of buffer at hd */
};

static struct lexbuf *currlexbuf = NULL; /* current lex buffer */

struct label {
	char const *name;
	struct token *token;    /* token that defined the label */
	int has_value;
	uint16_t value;

	TAILQ_ENTRY(label) next;
};

static TAILQ_HEAD(labels, label) labels =
	TAILQ_HEAD_INITIALIZER(labels); /* list of known labels */

static uint16_t curraddr = 0;   /* current assembler address */
static char bytebuf[4096] = {0};

enum {
	REG_A  = 0x01, REG_F  = 0x02, REG_AF = 0x03,
	REG_B  = 0x04, REG_C  = 0x05, REG_BC = 0x06,
	REG_D  = 0x07, REG_E  = 0x08, REG_DE = 0x09,
	REG_H  = 0x0A, REG_L  = 0x0B, REG_HL = 0x0C,
	REG_SP = 0x0D, REG_PC = 0x0E, /* pc not really ever used */

	OP_REG = 0x10,          /* operand involves a register. if not it is an immediate. */
	OP_INDIR = 0x20,        /* operand is indirected */
	OP_INC = 0x40,    /* increment/decrement. opcode value
	                   * determines if inc (0) or dec (1) */
};

enum {
	CC_NZ = 000, CC_Z = 001, CC_NC = 002, CC_C = 003,
};

static char const *const condition_codes[] = {
	[CC_NZ] = "nz",         /* zero clear */
	[CC_Z] = "z",           /* zero set */
	[CC_NC] = "nc",         /* carry clear */
	[CC_C] = "c"            /* carry set */
};

static char *
xstrndup(char const *src, size_t max)
{
	char *result = malloc(max + 1);
	return strncpy(result, src, max);
}

static int
toktoreg(struct token *t)
{
	size_t const len = token_len(t);

	static char const *const regnames[] = {
		"a", "f", "af",
		"b", "c", "bc",
		"d", "e", "de",
		"h", "l", "hl",
		"sp"
	};
	static size_t const nregs = ARRAY_SIZE(regnames);

	for (size_t i = 0; i < nregs; ++i){
		if (strncmp(t->begin, regnames[i], len) == 0)
			return i + 1;
	}

	return 0;
}

struct operand {
	int am;
	uint16_t imm;
};

static inline int
is16bitreg(int reg)
{
	return reg == REG_AF || reg == REG_BC ||
		reg == REG_DE || reg == REG_HL ||
		reg == REG_SP;
}

static inline int
is8bitreg(int reg)
{
	return reg == REG_A || reg == REG_F ||
		reg == REG_B || reg == REG_C ||
		reg == REG_D || reg == REG_E ||
		reg == REG_H || reg == REG_L;
}

static inline int
opis16bitreg(struct operand *op)
{
	if ((op->am & OP_REG) && ((op->am & OP_INDIR) == 0))
		return is16bitreg(op->am & 0xF);
	else
		return 0;
}

static inline int
opis8bitreg(struct operand *op)
{
	if ((op->am & OP_REG) && ((op->am & OP_INDIR) == 0))
		return is8bitreg(op->am & 0xF);
	else
		return 0;
}

static inline int
opisimm(struct operand *op)
{
	return (op->am & ((~0xF)|OP_REG)) == 0;
}

static struct lexbuf *
lexbuf_open(char const *filename)
{
	struct lexbuf *buf;
	struct stat sb;

	buf = calloc(1, sizeof(*buf));
	if (!buf)
		abort();

	buf->fd = open(filename, O_RDONLY);
	if (buf->fd < 0)
		return NULL;

	if (fstat(buf->fd, &sb) < 0)
		goto fail;

	buf->sol = buf->buffer = buf->hd =
		mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, buf->fd, 0);

	if (buf->buffer == MAP_FAILED)
		goto fail;

	buf->buflen = buf->len = sb.st_size;
	buf->filename = filename;
	buf->column = 1;
	buf->line = 1;

	return buf;

fail:
	close(buf->fd);
	free(buf);

	return NULL;
}

static void
lexer_reset(void)
{
	struct token *t;

	currlexbuf->hd = currlexbuf->buffer;
	currlexbuf->sol = currlexbuf->hd;
	currlexbuf->len = currlexbuf->buflen;
	currlexbuf->line = 1;
	currlexbuf->column = 1;

	/* clear out the tokenstack */
	while (!TAILQ_EMPTY(&tstack)) {
		t = TAILQ_FIRST(&tstack);
		TAILQ_REMOVE(&tstack, t, next);
		free(t);
	}
}

static struct label *
label_new(struct token *t)
{
	struct label *l = calloc(1, sizeof(*l));
	if (!l)
		abort();

	size_t len = token_len(t);
	l->name = xstrndup(t->begin, len);

	TAILQ_INSERT_TAIL(&labels, l, next);

	return l;
}

static struct label *
find_label(struct token *t)
{
	struct label *l = NULL;
	size_t const len = token_len(t);

	TAILQ_FOREACH(l, &labels, next) {
		size_t llen = strlen(l->name);
		if (llen != len)
			continue;

		if (memcmp(l->name, t->begin, len) == 0)
			break;
	}

	return l;
}

static void
terror(struct token *t, char const *const fmt, ...)
{
	va_list vp;

	fprintf(stderr, "%s:%d:%d: error: ", t->filename, t->line, t->column);

	va_start(vp, fmt);
	vfprintf(stderr, fmt, vp);
	va_end(vp);

	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

static void
terror_start(struct token *t, char const *const fmt, ...)
{
	va_list vp;

	fprintf(stderr, "%s:%d:%d: error: ", t->filename, t->line, t->column);

	va_start(vp, fmt);
	vfprintf(stderr, fmt, vp);
	va_end(vp);

	fputc('\n', stderr);
}

static void
tnote(struct token *t, char const *const fmt, ...)
{
	va_list vp;

	fprintf(stderr, "%s:%d:%d: note: ", t->filename, t->line, t->column);

	va_start(vp, fmt);
	vfprintf(stderr, fmt, vp);
	va_end(vp);

	fputc('\n', stderr);
}

static void
bail(void)
{
	exit(EXIT_FAILURE);
}

static void
berror(struct lexbuf *b, char const *const fmt, ...)
{
	va_list vp;

	fprintf(stderr, "%s:%d:%d: error: ", b->filename, b->line, b->column);

	va_start(vp, fmt);
	vfprintf(stderr, fmt, vp);
	va_end(vp);

	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

static void
emitlisting(char const *const fmt, ...)
{
	va_list vp;

	if (!pass)
		return;

	if (!lout)
		return;

	va_start(vp, fmt);
	vfprintf(lout, fmt, vp);
	va_end(vp);
}

static void
dumpbytebuf(void)
{
	if (bytebuf[0]) {
		emitlisting("\t;%s\n", bytebuf);
		bytebuf[0] = '\0';
	}
}

static void
whitespace(void)
{
	for (;;) {
		if (currlexbuf->len == 0)
			break;

		switch (*currlexbuf->hd) {
		case '\n':
			emitlisting("%.*s\n", (int)(currlexbuf->hd - currlexbuf->sol), currlexbuf->sol);
			currlexbuf->sol = ++currlexbuf->hd;
			currlexbuf->line++;
			currlexbuf->column = 1;
			break;
		case ' ':
		case '\f':
		case '\v':
		case '\t':
			currlexbuf->hd++;
			currlexbuf->column++;
			break;
		default:
			goto out;
		}

		currlexbuf->len -= 1;
	}
out:
	;
}

static void
comment(void)
{
	char c;
	for (;;) {
		if (currlexbuf->len == 0)
			break;

		c = *currlexbuf->hd++;
		currlexbuf->len--;

		if (c == '\n') {
			currlexbuf->line++;
			currlexbuf->column = 1;
			break;
		}
	}
}

static struct token *
lexidentifier(struct token *t)
{
	char *end;

	end = currlexbuf->hd;
	for (;;) {
		if (!isalnum(*end) && *end != '_' && *end != '.')
			break;

		end++;
	}

	t->end = end;
	t->kind = TOKEN_IDENT;

	currlexbuf->column += token_len(t) - 1;
	currlexbuf->hd = end;
	currlexbuf->len -= token_len(t);

	return t;
}

static struct token *
lexnumber(struct token *t)
{
	char *end, *endptr;

	end = currlexbuf->hd;
	for (;;) {
		if (!isxdigit(*end))
			break;

		end++;
	}

	if (*end == 'h') {
		t->value.number = strtoul(t->begin, &endptr, 16);
		if (end != endptr)
			terror(t, "could not parse hex literal");
		++end;
	} else {
		t->value.number = strtoul(t->begin, &endptr, 10);
		if (end != endptr)
			return NULL; /* try as identifier */
	}

	t->end = end;
	t->kind = TOKEN_NUMBER;

	currlexbuf->column += token_len(t) - 1;
	currlexbuf->hd = t->end;
	currlexbuf->len -= token_len(t);

	return t;
}

static void
skip(void)
{
again:
	if (currlexbuf->len == 0) {
		if (!currlexbuf->parent)
			return;

		/* todo: cleanup */
		emitlisting("\t; < Returning from file %s to file %s\n",
		            currlexbuf->filename,
		            currlexbuf->parent->filename);
		currlexbuf = currlexbuf->parent;
		goto again;
	}

	if (isspace(*currlexbuf->hd)) {
		whitespace();
		goto again;
	}

	if (*currlexbuf->hd == ';') {
		comment();
		goto again;
	}
}

static struct token *
lexsingle(struct token *t, char c)
{
	t->end = ++currlexbuf->hd;
	t->kind = c;

	currlexbuf->column += 1;
	currlexbuf->len -= 1;

	return t;
}

static struct token *
lexstrlit(struct token *t)
{
	t->end = t->begin + 1;
	t->kind = TOKEN_STRLIT;
	currlexbuf->hd += 1;
	currlexbuf->len -= 1;

	for (;;) {
		char c = *t->end;
		switch (c) {
		case '\0':
		case '\n':
			berror(currlexbuf, "unterminated string literal");
			break;
		default:
			t->end += 1;
			currlexbuf->len -= 1;
			currlexbuf->column += 1;
			currlexbuf->hd += 1;

			if (c == '\"')
				return t;
		}
	}
}

static struct token *
lex(void)
{
	struct token *t, *tmptok;
	char c;

	t = calloc(1, sizeof(*t));
	if (!t)
		berror(currlexbuf, "calloc failed: %s", strerror(errno));

	skip();
	t->begin = currlexbuf->hd;
	t->filename = currlexbuf->filename;
	t->line = currlexbuf->line;
	t->column = currlexbuf->column;

	if (currlexbuf->len == 0) {
		t->kind = TOKEN_EOF;
		return t;
	}

	c = *currlexbuf->hd;

	if (isxdigit(c)) {
		tmptok = lexnumber(t);
		if (tmptok)
			return tmptok;
	}

	if (isalpha(c) || c == '.')
		return lexidentifier(t);

	if (c == ':' || c == ',' || c == '(' || c == ')' ||
	    c == '+' || c == '-' || c == '=' || c == '*' ||
	    c == '/')
		return lexsingle(t, c);
	else if (c == '"')
		return lexstrlit(t);
	else
		berror(currlexbuf, "unrecognised character %c", c);

	return NULL;
}

static struct token *
tstacklex(void)
{
	struct token *t = lex();
	TAILQ_INSERT_TAIL(&tstack, t, next);
	return t;
}

static struct token *
peektoken(int n)
{
	struct token *t = TAILQ_FIRST(&tstack);

	for (;;) {
		if (!t)
			t = tstacklex();

		if (n == 0)
			break;
		else
			--n;

		t = TAILQ_NEXT(t, next);
        }

	return t;
}

static struct token *
nexttoken(void)
{
	if (!TAILQ_EMPTY(&tstack)) {
		struct token *t = TAILQ_FIRST(&tstack);
		TAILQ_REMOVE(&tstack, t, next);
		return t;
	}

	return lex();
}

static int
iseof(void)
{
	if (!TAILQ_EMPTY(&tstack))
		return TAILQ_FIRST(&tstack)->kind == TOKEN_EOF;

	skip();

	return !currlexbuf->len;
}

static void
emitsymbol(struct label *l)
{
	if (!sout)
		return;

	fprintf(sout, "%02X:%02X %.*s\n", 0, l->value, (int)(token_len(l->token)),
	        l->token->begin);
}

static void
definelabel(struct token *t)
{
	struct label *l;
	struct token *colon = nexttoken();
	if (colon->kind != TOKEN_COLON)
		terror(colon, "expected a colon");

	/* Only in the first pass we define names for symbols */
	if (pass == 0) {
		if ((l = find_label(t))) {
			terror_start(t, "label redefined");
			tnote(l->token, "previously defined here");
			bail();
		}

		l = label_new(t);
		l->has_value = 1;
		l->value = curraddr;
		l->token = t;
	} else {
		l = find_label(t);
		assert(l);
		if (!l->has_value)
			terror(t, "cannot compute value of label");

		emitlisting("\t; regular label %.*s = %04"PRIx16"h\n",
		            (int)(token_len(l->token)), l->token->begin,
		            l->value);

		emitsymbol(l);
	}
}

static void
readoperand(struct operand *out)
{
	struct token *t;

	t = nexttoken();
	if (t->kind == TOKEN_IDENT) {
		int am = toktoreg(t);
		if (am) { /* plain register */
			out->am = am|OP_REG;
			return;
		}

		/* probably a label. in pass 0 we don't resolve the
		 * label. in pass 1 we do. */
		if (pass == 0) {
			out->am = 0;
		} else {
			struct label *l = find_label(t);
			if (!l)
				terror(t, "undefined reference in operand");

			if (!l->has_value)
				terror(t, "operand value could not be resolved");

			out->am = 0;
			out->imm = l->value;
		}

	} else if (t->kind == TOKEN_OPAREN) {
		readoperand(out);
		t = nexttoken();

		if (t->kind == TOKEN_PLUS) {
			out->am |= OP_INC;
			out->imm = 0;
			t = nexttoken();
		} else if (t->kind == TOKEN_MINUS) {
			out->am |= OP_INC;
			out->imm = 1;
			t = nexttoken();
		}

		if (t->kind != TOKEN_CPAREN)
			terror(t, "expected closing parenthesis");

		out->am |= OP_INDIR;
	} else if (t->kind == TOKEN_NUMBER) {
		out->am = 0;
		out->imm = t->value.number;
	} else {
		terror(t, "invalid addressing mode");
	}
}

static inline int
token_isvalue(struct token *t)
{
	return t->kind == TOKEN_IDENT ||
		t->kind == TOKEN_NUMBER;
}

static inline int
token_isoperator(struct token *t)
{
	return t->kind == '(' || t->kind == ')' || t->kind == '+' ||
		t->kind == '-' || t->kind == '*' || t->kind == '/';
}

static inline int
prec(char c)
{
	switch (c) {
	case '+': return 2;
	case '-': return 2;
	case '/': return 3;
	case '*': return 3;
	default: assert(0 && "unreachable");
	}
}

static inline int
isleftassoc(char c)
{
	return 1;
}

static inline uint16_t
perform(char c, uint16_t left, uint16_t right)
{
	switch (c) {
	case '+': return left + right;
	case '-': return left - right;
	case '*': return left * right;
	case '/': return left / right;
	default: assert(0 && "unreachable");
	}
}

#define STK_MAX 64
static uint16_t
readexpression(struct token *t)
{
        uint16_t valstk[STK_MAX] = {0};
	size_t valsp = 0;
	char opstk[STK_MAX] = {0};
	size_t opsp = 0;
	int found_op = 1;

	for (;;) {
		t = peektoken(0);

		if (found_op == 0 && token_isvalue(t))
			break;


		if (t->kind == TOKEN_NUMBER) {
			if (valsp == STK_MAX)
				terror(t, "value stack overflow");

			valstk[valsp++] = t->value.number;
			found_op = 0;

		} else if (t->kind == '(') {
			if (opsp == STK_MAX)
				terror(t, "operator stack overflow");

			opstk[opsp++] = t->kind;
			found_op = 1;

		} else if (t->kind == TOKEN_IDENT) {
			uint16_t val = 0;

			if (token_len(t) == 1 && t->begin[0] == '.') {
				val = curraddr;
			} else {
				struct label *l = find_label(t);
				if (pass) {
					if (!l)
						terror(t, "reference to undefined symbol");

					val = l->value;
				}
			}

			if (valsp == STK_MAX)
				terror(t, "value stack overflow");

			valstk[valsp++] = val;
			found_op = 0;
		} else if (t->kind == ')') {
			while (opsp && opstk[opsp-1] != '(') {
				uint16_t left, right;
				right = valstk[--valsp];
				left = valstk[--valsp];
				valstk[valsp++] = perform(opstk[--opsp], left, right);
			}

			if (!opsp || opstk[opsp-1] != '(')
				terror(t, "unmatched parenthesis");

			opsp--;
			found_op = 1;
		} else if (token_isoperator(t)) {

			for (;;) {
				uint16_t left, right;
				char o2, o1;

				if (!opsp)
					break;

				o1 = t->kind;
				o2 = opstk[opsp-1];

				if (o2 == '(')
					break;

				if (!(prec(o2) > prec(o1) ||
				      (prec(o1) == prec(o2) && isleftassoc(o1))))
					break;

				--opsp;

				if (valsp < 2)
					terror(t, "unexpected '%c'", o1);

				right = valstk[--valsp];
				left = valstk[--valsp];
				valstk[valsp++] = perform(o2, left, right);
			}

			opstk[opsp++] = t->kind;
			found_op = 1;
		} else {
			terror(t, "unexpected token");
		}

		nexttoken();
	}

	while (opsp) {
		char op;
		uint16_t left, right;
		if ((op = opstk[--opsp]) == '(')
			terror(t, "unbalanced parentheses");

		if (valsp < 2)
			terror(t, "value stack underflow");

		right = valstk[--valsp];
		left = valstk[--valsp];
		valstk[valsp++] = perform(op, left, right);
	}

	if (valsp != 1)
		terror(t, "unexpected token"); // TODO: fix this error message

	return valstk[--valsp];
}

static void
definelabel_expr(struct token *t)
{
	struct label *l;

	if (pass == 0) {
		if ((l = find_label(t))) {
			terror_start(t, "label redefined");
			tnote(l->token, "previously defined here");
			bail();
		}

		l = label_new(t);
		l->has_value = 0;
		l->value = readexpression(t);
		l->token = t;
	} else {
		l = find_label(t);
		assert(l);

		l->value = readexpression(t);
		l->has_value = 1;

		emitlisting("\t; Label %.*s = %04"PRIx16"h\n",
		            (int)(token_len(l->token)),
		            l->token->begin,
		            l->value);
	}
}

static int
readcc(void)
{
	struct token *t = peektoken(0);
	size_t const tlen = token_len(t);

	for (size_t i = 0; i < ARRAY_SIZE(condition_codes); ++i) {
		if (strncmp(t->begin, condition_codes[i], tlen) == 0) {
			nexttoken();
			return i;
		}
	}
	return -1;
}

static inline void
emitbyte(uint8_t b)
{
	curraddr += 1;

	if (pass) {
		char tmp[5] = {0};
		fwrite(&b, 1, 1, fout);

		snprintf(tmp, sizeof(tmp), " %02"PRIx8"h", b);
		strlcat(bytebuf, tmp, sizeof(bytebuf));
	}
}

static inline void
emitword(uint16_t w)
{
	emitbyte(w & 0xFF);
	emitbyte((w & 0xFF00) >> 8);
}

static void
branchcb(struct token *t)
{
	struct token *lname, *cctoken;
	struct label *l;
	uint16_t addr = 0;
	int cc = -1;
	uint8_t opcode = 0;

	/* there is a condition code */
	if (peektoken(1)->kind == TOKEN_COMMA) {
		cctoken = peektoken(0);
		cc = readcc();
		if (cc < 0)
			terror(cctoken, "bad condition code");

		nexttoken(); /* skip comma */
	}

	lname = nexttoken();
	if (lname->kind != TOKEN_IDENT)
		terror(lname, "expected an identifier");

	if (pass) {
		l = find_label(lname);
		if (!l)
			terror(lname, "undefined reference to label");

		if (!l->has_value)
			terror(lname, "cannot compute address of label");

		addr = l->value;
	}

	if (cc < 0) {
		if (*t->begin == 'c')
			opcode = 0315; /* call unconditional */
		else
			opcode = 0303; /* jp unconditional */
	} else {
		if (*t->begin == 'c')
			opcode = 0304; /* call conditional */
		else /* jp */
			opcode = 0302; /* jp conditional */

		opcode |= (cc << 3);
	}

	emitbyte(opcode);
	emitword(addr);
}

static void
jrcb(struct token *t)
{
	struct token *lname, *cctoken;
	struct label *l;
        int8_t offset = 0;
	int cc = -1;
	uint8_t opcode = 0;

	/* there is a condition code */
	if (peektoken(1)->kind == TOKEN_COMMA) {
		cctoken = peektoken(0);
		cc = readcc();
		if (cc < 0)
			terror(cctoken, "bad condition code");

		nexttoken(); /* skip comma */
	}

	lname = nexttoken();
	if (lname->kind != TOKEN_IDENT)
		terror(lname, "expected an identifier");

	if (pass) {
		l = find_label(lname);
		if (!l)
			terror(lname, "undefined reference to label");

		if (!l->has_value)
			terror(lname, "cannot compute address of label");

		/* Displacement is counted after reading the
		 * opcode. At that point the PC has already been
		 * incremented. Here we account for that. */
		int32_t const rel = (int32_t)l->value - (int32_t)curraddr - 1;
		if (rel < (int8_t)0x80 || rel > (int8_t)0x7F)
			terror(t, "jump distance too large");

		offset = (int8_t)(rel);
	}

	if (cc < 0) {
		opcode = 0030;
	} else {
		opcode = 0040;
		opcode |= (cc << 3);
	}

	emitbyte(opcode);
	emitbyte(offset);
}

static void
stackcb(struct token *t)
{
	int is_push = 0;
	struct operand opsrc;
	struct token *next;

	next = peektoken(0);

	readoperand(&opsrc);

	/* is this a push or a pop? */
	if (strncmp(t->begin, "push", token_len(t)) == 0)
		is_push = 1;

	uint8_t instr = is_push ? 0x05 : 0x01;

	if ((opsrc.am & OP_REG) == 0 || (opsrc.am & OP_INDIR))
		terror(t, "invalid addressing mode");

	switch (opsrc.am & 0xF) {
	case REG_BC: instr |= 0xC0; break;
	case REG_DE: instr |= 0xD0; break;
	case REG_HL: instr |= 0xE0; break;
	case REG_AF: instr |= 0xF0; break;
	default:
		terror(t, "invalid register »%.*s« for stack op",
		       (int)token_len(next), next->begin);
	}

	emitbyte(instr);
}

static void
retcb(struct token *t)
{
	int cc;

	if ((cc = readcc()) < 0)
		emitbyte(0311);
	else
		emitbyte(0300 | (cc << 3));
}

static void
orgcb(struct token *t)
{
	struct token *n;

	n = nexttoken();
	if (n->kind != TOKEN_NUMBER)
		terror(n, "expected an address for .org directive");

	curraddr = n->value.number;
	if (pass)
		fseek(fout, curraddr, SEEK_SET);
}

static uint8_t
reg8op2oct(int am)
{
	switch (am) {
	case OP_REG|REG_B:
		return 00;
	case OP_REG|REG_C:
		return 01;
	case OP_REG|REG_D:
		return 02;
	case OP_REG|REG_E:
		return 03;
	case OP_REG|REG_H:
		return 04;
	case OP_REG|REG_L:
		return 05;
	case OP_REG|OP_INDIR|REG_HL:
		return 06;
	case OP_REG|REG_A:
		return 07;
	default:
		assert(0 && "unreachable");
	}
}

static uint8_t
reg16op2oct(int am)
{
	switch (am) {
	case OP_REG|REG_BC:
		return 000;
	case OP_REG|REG_DE:
		return 002;
	case OP_REG|REG_HL:
		return 004;
	case OP_REG|REG_SP:
		return 006;
	default:
		assert(0 && "unreachable");
	}
}

static void
ldcb(struct token *t)
{
	struct operand opdst = {0}, opsrc = {0};
	struct token *comma;

	readoperand(&opdst);
	comma = nexttoken();
	if (comma->kind != TOKEN_COMMA)
		terror(comma, "expected a comma");
	readoperand(&opsrc);

	/* Block of instructions from 40h to 7Fh */
	if ((opis8bitreg(&opsrc) || opsrc.am == (OP_REG|REG_HL|OP_INDIR)) &&
	    (opis8bitreg(&opdst) || opdst.am == (OP_REG|REG_HL|OP_INDIR)))
	{
		uint8_t opcode = 0100;
		if (opsrc.am == (OP_REG|REG_HL|OP_INDIR) &&
		    opdst.am == (OP_REG|REG_HL|OP_INDIR))
			terror(t, "invalid load operands (operation would result in halt)");

		opcode |= reg8op2oct(opdst.am) << 3;
		opcode |= reg8op2oct(opsrc.am);
		emitbyte(opcode);

		return;
	}

	/* 8 bit immediate load */
	if (opis8bitreg(&opdst) && opisimm(&opsrc)) {
		/* check that we don't overflow a byte */
		if (opsrc.imm & 0xFF00)
			terror(t, "immediate overflow");


		emitbyte((reg8op2oct(opdst.am) << 3) | 06);
		emitbyte(opsrc.imm);

		return;
	}

	/* 16 bit immediate load */
	if (opis16bitreg(&opdst) && opisimm(&opsrc)) {
		if ((opdst.am & 0xF) == REG_AF)
			terror(t, "cannot load 16 bit immediate into AF");

		emitbyte((reg16op2oct(opdst.am) << 3) | 01);
		emitword(opsrc.imm);

		return;
	}

	/* Special case: store of accumulator at address. Equivalent
	 * load is below. */
	if (opsrc.am == (OP_REG|REG_A) && (opdst.am == OP_INDIR)) {
		emitbyte(0352);
		emitword(opdst.imm);
		return;
	} else if (opdst.am == (OP_REG|REG_A) && (opsrc.am == OP_INDIR)) {
		emitbyte(0372);
		emitword(opsrc.imm);
		return;
	}

	/* 8 bit load/store of accumulator indirected */
	if (((opsrc.am == (OP_REG|REG_A)) != (opdst.am == (OP_REG|REG_A))) &&
	    ((opsrc.am & OP_INDIR) != (opdst.am & OP_INDIR)))
	{
		uint8_t opcode = 02;
		struct operand iop = opdst; /* indirected 16 bit operand */

		if (opsrc.am == (OP_REG|REG_A|OP_INDIR) ||
		    opdst.am == (OP_REG|REG_A|OP_INDIR))
			terror(t, "cannot indirect 8 bit accumulator");

		if (opdst.am == (OP_REG|REG_A)) {
			opcode |= 010;
			iop = opsrc;
		}

		switch (iop.am & (0xF|OP_INC)) {
		case REG_BC:
			break;
		case REG_DE:
			opcode |= 020;
			break;
		case REG_HL|OP_INC:
			opcode |= 040;
			if (iop.imm)
				opcode |= 020;
			break;
		default:
			terror(t, "invalid register indirection");
		}

		emitbyte(opcode);

		return;
	}

	/* Special Case: store SP at address */
	if (opdst.am == OP_INDIR && opsrc.am == (OP_REG|REG_SP)) {
		emitbyte(0010);
		emitword(opdst.imm);
		return;
	}

	/* Not implemented error */
	terror(t, "invalid combination of load opcode and operands");
}

static void
inccb(struct token *t)
{
	struct operand op = {0};

	readoperand(&op);

	if (opis8bitreg(&op) || op.am == (OP_REG|REG_HL|OP_INDIR)) {
		emitbyte((reg8op2oct(op.am) << 3) | 04);
	} else if (opis16bitreg(&op)) {
		if ((op.am & REG_AF) == REG_AF)
			terror(t, "invalid: inc af");

		emitbyte((reg16op2oct(op.am) << 3) | 03);
	} else {
		terror(t, "bad adressing mode");
	}
}

static void
deccb(struct token *t)
{
	struct operand op;
	readoperand(&op);

	if (opis8bitreg(&op) || op.am == (OP_REG|REG_HL|OP_INDIR)) {
		emitbyte((reg8op2oct(op.am) << 3)  | 04 | 001);
	} else if (opis16bitreg(&op)) {
		if ((op.am & REG_AF) == REG_AF)
			terror(t, "invalid: dec af");

		emitbyte((reg16op2oct(op.am) << 3) | 03 | 010);
	} else {
		terror(t, "bad adressing mode");
	}
}

static void
alu2opscb(struct token *t)
{
	struct operand dst = {0}, src = {0};
	struct token *comma;
	uint8_t opcode = 0, imm = 0;
	size_t const mn_len = token_len(t);

	/* Parse */
	readoperand(&dst);

	comma = nexttoken();
	if (comma->kind != TOKEN_COMMA)
		terror(comma, "expected a comma");

	readoperand(&src);

	/* Generate code */
	if (strncmp(t->begin, "add", mn_len) == 0)
		opcode = 0200;
	else if (strncmp(t->begin, "adc", mn_len) == 0)
		opcode = 0210;
	else if (strncmp(t->begin, "sbc", mn_len) == 0)
		opcode = 0230;
	else
		assert(0 && "unreachable");

	if (dst.am == (OP_REG|REG_HL)) { /* add hl, reg16 */
		if (opcode != 0200)
			terror(t, "bad opcode. can only add to hl in 16 bit");

		if (!opis16bitreg(&src) || src.am == (OP_REG|REG_AF))
			terror(t, "source operand must be a 16 bit register and not AF");

		opcode = 0011 | (reg16op2oct(src.am) << 3);

		emitbyte(opcode);

	} else if (dst.am == (OP_REG|REG_SP)) { /* add sp, r8 */
		if (opcode != 0200)
			terror(t, "bad opcode. can only add to sp in 16 bit");

		if (!opisimm(&src))
			terror(t, "source must be an 8 bit relative address");

		if (src.imm & 0xFF00)
			terror(t, "relative too large");

		emitbyte(0xE8);
		emitbyte((uint8_t)(src.imm & 0xFF));

	} else if (dst.am == (OP_REG|REG_A)) {
		/* 8 bit with register or (hl) */
		if (opis8bitreg(&src) || src.am == (OP_REG|OP_INDIR|REG_HL)) {
			opcode |= reg8op2oct(src.am);
			emitbyte(opcode);
		} else if (opisimm(&src)) { /* 8 bit with immediate */
			if (src.imm & 0xFF00)
				terror(t, "immediate overflow");

			opcode |= 0106;

			emitbyte(opcode);
			emitbyte((uint8_t)(src.imm & 0xFF));
		} else {
			terror(comma,
			       "expected an 8 bit register or an "
			       "immediate after comma");
		}

	} else {
		terror(t, "can only operate on hl or a");
	}

}

static void
alu1opcb(struct token *t)
{
	struct operand op = {0};
	uint8_t opcode = 0;

	readoperand(&op);

	/* dispatch on mnemonic to generate base opcode */
	switch (*t->begin) {
	case 's': opcode = 0220; break; /* sub */
	case 'a': opcode = 0240; break; /* and */
	case 'x': opcode = 0250; break; /* xor */
	case 'o': opcode = 0260; break; /* or  */
	case 'c': opcode = 0270; break; /* cp  */
	default: assert(0 && "unreachable");
	}

	if (opis8bitreg(&op) || op.am == (OP_REG|OP_INDIR|REG_HL)) {
		opcode |= reg8op2oct(op.am);
		emitbyte(opcode);

	} else if (opisimm(&op)) /* immediate */ {
		if (op.imm & 0xFF00)
			terror(t, "immediate overflow");

		opcode |= 0106;

		emitbyte(opcode);
		emitbyte((uint8_t)(op.imm & 0xFF));

	} else {
		terror(t, "bad adressing mode");
	}

}

struct rotdef {
	char const *const mnemonic;
	uint8_t const base_opcode;
} rots[] = {
	{ .mnemonic = "rlc",  .base_opcode = 0000 },
	{ .mnemonic = "rrc",  .base_opcode = 0010 },
	{ .mnemonic = "rl",   .base_opcode = 0020 },
	{ .mnemonic = "rr",   .base_opcode = 0030 },
	{ .mnemonic = "sla",  .base_opcode = 0040 },
	{ .mnemonic = "sra",  .base_opcode = 0050 },
	{ .mnemonic = "swap", .base_opcode = 0060 },
	{ .mnemonic = "srl",  .base_opcode = 0070 },
};

static void
rotatecb(struct token *t)
{
	struct operand op = {0};
	struct rotdef *rdef = NULL;
	size_t const tlen = token_len(t);

	readoperand(&op);

	if (!opis8bitreg(&op) && op.am != (OP_REG|REG_HL|OP_INDIR))
		terror(t, "expected 8 bit register or (hl) as operand");

	for (size_t i = 0; i < ARRAY_SIZE(rots); ++i) {
		if (strlen(rots[i].mnemonic) != tlen)
			continue;

		if (strncmp(t->begin, rots[i].mnemonic, tlen) == 0) {
			rdef = &rots[i];
			break;
		}
	}

	assert(rdef != NULL);

	emitbyte(0xCB);
	emitbyte(rdef->base_opcode | reg8op2oct(op.am));
}

static void
bitcb(struct token *t)
{
	struct operand nop = {0}, regop = {0};
	struct token *ntok, *commatok, *rtok;
	uint8_t opcode = 0;
	size_t const tlen = token_len(t);

	if (strncmp(t->begin, "bit", tlen) == 0)
		opcode = 0100;
	else if (strncmp(t->begin, "res", tlen) == 0)
		opcode = 0200;
	else if (strncmp(t->begin, "set", tlen) == 0)
		opcode = 0300;
	else
		assert(0 && "unreachable");

	ntok = peektoken(0);

	readoperand(&nop);
	if (!opisimm(&nop))
		terror(ntok, "expected an immediate");

	if ((commatok = nexttoken())->kind != TOKEN_COMMA)
		terror(commatok, "expected a comma");

	rtok = peektoken(0);
	readoperand(&regop);
	if (!opis8bitreg(&regop) && regop.am != (OP_REG|REG_HL|OP_INDIR))
		terror(rtok, "expected an 8 bit register or (hl)");

	if (nop.imm > 7)
		terror(ntok, "immediate too large");

	opcode |= (nop.imm << 3);
	opcode |= reg8op2oct(regop.am);

	emitbyte(0xCB);
	emitbyte(opcode);
}

static void
rstcb(struct token *t)
{
	struct operand op = {0};
	struct token *optok;

	optok = peektoken(0);
	readoperand(&op);

	if (!opisimm(&op))
		terror(optok, "expected a number");

	if ((op.imm % 8 != 0) || (op.imm > 0x38))
		terror(optok, "bad reset vector");

	emitbyte(0307 | ((uint8_t)op.imm));
}

static void
ldhcb(struct token *t)
{
	struct operand lop = {0}, rop = {0};
	struct token *ltok, *ctok, *rtok;

	ltok = peektoken(0);
	readoperand(&lop);

	if ((ctok = nexttoken())->kind != TOKEN_COMMA)
		terror(ctok, "expected a comma");

	readoperand(&rop);

	if (lop.am == OP_INDIR && rop.am == (OP_REG|REG_A)) {
		if (lop.imm > 0xFF)
			terror(ltok, "address too large");

		emitbyte(0xE0);
		emitbyte((uint8_t)(lop.imm));
	} else if (lop.am == (OP_REG|REG_A) && rop.am == OP_INDIR) {
		if (rop.imm > 0xFF)
			terror(rtok, "address too large");
		emitbyte(0xF0);
		emitbyte((uint8_t)(rop.imm));
	} else {
		terror(t, "bad addressing mode");
	}
}

static void
includecheck(struct token *t, char *filename)
{
	for (struct lexbuf *buf = currlexbuf; buf; buf = buf->parent)
		if (strcmp(filename, buf->filename) == 0)
			terror(t, "circular inclusion of '%s'", filename);
}

static void
includecb(struct token *t)
{
	char *filename;
	struct token *pathtok = nexttoken();
	struct lexbuf *newbuf;

	if (pathtok->kind != TOKEN_STRLIT)
		terror(t, "expected string literal for include path");

	filename = xstrndup(pathtok->begin + 1, token_len(pathtok) - 2);
	includecheck(t, filename);

	emitlisting("\t; > Including %s\n", filename);

	newbuf = lexbuf_open(filename);
	if (!newbuf)
		terror(pathtok, "could not open %s: %s",
		       filename, strerror(errno));

	newbuf->parent = currlexbuf;
	currlexbuf = newbuf;
}

static void
dwcb(struct token *t)
{
	struct operand op;
	struct token *immtok, *comma;

	for (;;) {
	    immtok = peektoken(0);
	    readoperand(&op);

	    if (!opisimm(&op))
		terror(immtok, "expected a constant value");

	    emitword(op.imm);

	    if ((comma = peektoken(0)) && comma->kind != ',')
		break;

	    nexttoken();
	}
}

static void
dbcb(struct token *t)
{
	struct operand op;
	struct token *immtok, *comma;

	for (;;) {
	    immtok = peektoken(0);
	    readoperand(&op);

	    if (!opisimm(&op))
		terror(immtok, "expected a constant value");

	    if (op.imm & 0xFF00)
		terror(immtok, "constant too large");

	    emitbyte((uint8_t)(op.imm & 0xFF));

	    if ((comma = peektoken(0)) && comma->kind != ',')
		break;

	    nexttoken();
	}
}

static void
asciicb(struct token *t)
{
	struct token *strlit;

	strlit = nexttoken();
	for (size_t i = 1; i < token_len(strlit) - 1; ++i) {
		emitbyte(strlit->begin[i]);
	}
}

static void
asciizcb(struct token *t)
{
	asciicb(t);
	emitbyte(0);
}

static struct instdef {
	char *mnemonic;
	void (*cb)(struct token *t);
} insts[] = {
	{ .mnemonic = ".org",     .cb = orgcb     },
	{ .mnemonic = ".dw",      .cb = dwcb      },
	{ .mnemonic = ".db",      .cb = dbcb      },
	{ .mnemonic = ".include", .cb = includecb },
	{ .mnemonic = ".ascii",   .cb = asciicb   },
	{ .mnemonic = ".asciiz",  .cb = asciizcb  },
	{ .mnemonic = "ld",       .cb = ldcb      },
	{ .mnemonic = "ldh",      .cb = ldhcb     },
	{ .mnemonic = "call",     .cb = branchcb  },
	{ .mnemonic = "push",     .cb = stackcb   },
	{ .mnemonic = "pop",      .cb = stackcb   },
	{ .mnemonic = "ret",      .cb = retcb     },
	{ .mnemonic = "inc",      .cb = inccb     },
	{ .mnemonic = "dec",      .cb = deccb     },
	{ .mnemonic = "add",      .cb = alu2opscb },
	{ .mnemonic = "adc",      .cb = alu2opscb },
	{ .mnemonic = "sbc",      .cb = alu2opscb },
	{ .mnemonic = "sub",      .cb = alu1opcb  },
	{ .mnemonic = "and",      .cb = alu1opcb  },
	{ .mnemonic = "xor",      .cb = alu1opcb  },
	{ .mnemonic = "or",       .cb = alu1opcb  },
	{ .mnemonic = "cp",       .cb = alu1opcb  },
	{ .mnemonic = "jp",       .cb = branchcb  },
	{ .mnemonic = "jr",       .cb = jrcb      },
	{ .mnemonic = "rlc",      .cb = rotatecb  },
	{ .mnemonic = "rrc",      .cb = rotatecb  },
	{ .mnemonic = "rl",       .cb = rotatecb  },
	{ .mnemonic = "rr",       .cb = rotatecb  },
	{ .mnemonic = "sla",      .cb = rotatecb  },
	{ .mnemonic = "sra",      .cb = rotatecb  },
	{ .mnemonic = "swap",     .cb = rotatecb  },
	{ .mnemonic = "srl",      .cb = rotatecb  },
	{ .mnemonic = "bit",      .cb = bitcb     },
	{ .mnemonic = "res",      .cb = bitcb     },
	{ .mnemonic = "set",      .cb = bitcb     },
	{ .mnemonic = "rst",      .cb = rstcb     },
};
static size_t const insts_size = ARRAY_SIZE(insts);

static struct sinstdef {
	char *mnemonic;
	uint8_t opcode;
} simple_insts[] = {
	{ .mnemonic = "nop",   .opcode = 0000 },
	{ .mnemonic = "rlca",  .opcode = 0007 },
	{ .mnemonic = "rrca",  .opcode = 0017 },
	{ .mnemonic = "rla",   .opcode = 0027 },
	{ .mnemonic = "rra",   .opcode = 0037 },
	{ .mnemonic = "daa",   .opcode = 0047 },
	{ .mnemonic = "cpl",   .opcode = 0057 },
	{ .mnemonic = "scf",   .opcode = 0067 },
	{ .mnemonic = "ccf",   .opcode = 0077 },
	{ .mnemonic = "halt",  .opcode = 0166 },
	{ .mnemonic = "di",    .opcode = 0363 },
	{ .mnemonic = "ei",    .opcode = 0373 },
	{ .mnemonic = "reti",  .opcode = 0331 },

	/* Software breakpoint. SameBoy seems to allow
	 * this. Equivalent to 'ld b, b' */
	{ .mnemonic = "brk",   .opcode = 0100 },
};
static size_t const simple_insts_size = ARRAY_SIZE(simple_insts);

static void
parseinstruction(struct token *t)
{
	size_t const tlen = token_len(t);
	for (size_t i = 0; i < insts_size; ++i) {
		if (strncmp(t->begin, insts[i].mnemonic, tlen) == 0) {
			insts[i].cb(t);
			return;
		}
	}
	/* Otherwise try a simple instruction */
	for (size_t i = 0; i < simple_insts_size; ++i) {
		if (strncmp(t->begin, simple_insts[i].mnemonic, tlen) == 0) {
			emitbyte(simple_insts[i].opcode);
			return;
		}
	}
	terror(t, "unrecognised mnemonic");
}

static void
dopass(void)
{
	lexer_reset();
	curraddr = 0;

	for (;;) {
		if (iseof())
			break;

		struct token *t = nexttoken();
		if (t->kind != TOKEN_IDENT)
			terror(t, "expected an identifier");

		struct token *col = peektoken(0);
		if (col->kind == TOKEN_COLON) {
			definelabel(t);
		} else if (col->kind == TOKEN_EQ) {
			nexttoken(); /* skip = */
			definelabel_expr(t);
		} else {
			parseinstruction(t);
		}

		dumpbytebuf();
	}
}

static void
assemble(void)
{
	for (pass = 0; pass < 2; ++pass)
		dopass();
}

static void
usage(void)
{
	fprintf(stderr, "usage: lr35902as [-o out.bin] [-l listing.lst] input.S\n");
	fprintf(stderr, "OPTIONS:\n");
	fprintf(stderr, "  -o out.bin        Assemble into out.bin. Defaults to a.bin\n");
	fprintf(stderr, "  -l listing.lst    Produce a listing file in listing.lst\n");
	fprintf(stderr, "  -s symbols.sym    Produce a symbol table for use in SameBoy\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "LR35902 Assembler.\nCopyright 2023 Nico Sonack\n");
}

static void
parseflags(int argc, char *argv[])
{
	struct option options[] = {
		{ .name = "output",  .has_arg = required_argument, .flag = NULL, .val = 'o' },
		{ .name = "listing", .has_arg = required_argument, .flag = NULL, .val = 'l' },
		{ .name = "symbols", .has_arg = required_argument, .flag = NULL, .val = 's' },
		{0}
	};
	int ch = 0;

	while ((ch = getopt_long(argc, argv, "+o:l:s:", options, NULL)) != -1) {
		switch (ch) {
		case 'o': {
			fout = fopen(optarg, "wb");
			if (!fout)
				err(1, "open output: %s", optarg);
		} break;
		case 'l': {
			lout = fopen(optarg, "w");
			if (!lout)
				err(1, "open listing: %s", optarg);
		} break;
		case 's': {
			sout = fopen(optarg, "w");
			if (!sout)
				err(1, "open symbols: %s", optarg);
		} break;
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	/* open a.bin if -o was not specified */
	if (fout == NULL) {
		fout = fopen("a.bin", "wb");
		if (!fout)
			err(1, "couldn't open a.bin");
	}

	/* maybe support stdin as well? */
	if (argc == 0)
		errx(1, "error: missing input file");


	struct lexbuf *buf = lexbuf_open(argv[0]);
	if (!buf)
		err(1, "open %s", argv[0]);

	buf->parent = currlexbuf;
	currlexbuf = buf;
}

int
main(int argc, char *argv[])
{
	parseflags(argc, argv);
	assemble();
	fclose(fout);

	if (sout)
		fclose(sout);
	if (lout)
		fclose(lout);

	return 0;
}
