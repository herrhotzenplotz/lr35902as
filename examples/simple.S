        ;; Simple demonstration of the Assembler's capabilities

entry:  ld      sp, 8000h       ; Setup some sort of stack
        call    main
        halt

        .org    100h            ; Set PC
main:   ld      a, 42
loop:   dec     a               ; Little decrement loop
        ret     nz
        jp      loop
