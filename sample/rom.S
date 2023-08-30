        ;; ROM Skeleton

        .org 0100h
entry:  nop
        jp main

        ;; This is the needed nintendo logo for copy protection
        .org 0104h
NINTENDO_LOGO:
        .db CEh, EDh, 66h, 66h, CCh, 0Dh, 00h, 0Bh, 03h, 73h, 00h, 83h, 00h, 0Ch, 00h, 0Dh, 00h, 08h, 11h, 1Fh, 88h, 89h, 00h, 0Eh
        .db DCh, CCh, 6Eh, E6h, DDh, DDh, D9h, 99h, BBh, BBh, 67h, 63h, 6Eh, 0Eh, ECh, CCh, DDh, DCh, 99h, 9Fh, BBh, B9h, 33h, 3Eh

        ;;  ROM title
        .org 0134h
rom_title:
        .asciiz "TESTROM"

        ;; Manufacturer code
        .org 013Fh
        .ascii "NICO"

        ;; CGB flag
        .org 0143h
        .db 80h                 ; The game supports CGB enhancements,
                                ; but is backwards compatible with
                                ; monochrome Game Boys

        .org 0144h
new_licensee_code:
        .ascii "00"             ; None

        ;; Cartidge type
        .org 0147h
cartridge_type:
        .db 00h                 ; ROM only

        ;; ROM size
rom_size:
        .db 00h                 ; 32KiB (no banking, 2 rom banks)

        .org 0149h
ram_size:
        .db 00h                 ; No RAM

        .org 014Bh
old_licensee_code:
        .db 33h                 ; Use new licensee code instead

        .org 014Dh
header_chksum:
        .db 0h                  ; To be filled in

        .org 014Eh              ; To be filled in
global_chksum_msb:
        .db 83h
global_chksum_lsb:
        .db 00h

        ;; Code origin
        .include "main.S"
