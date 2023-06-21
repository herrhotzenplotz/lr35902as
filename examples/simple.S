        ;; Simple demonstration of the Assembler's capabilities
        .include "examples/defs.S"

blab:
	ld      a, 42
blabloop:
	dec     a               ; Little decrement loop
	ret     nz
	jp      loop
