        ;; Simple sound example

        .include "sound.S"      ; APU Register Definitions

main:   call apu_init           ; Enable APU and setup channels
        call init_timer         ; init timer
        call irq_init           ; enable timer interrupts

        ;; Channel 1 Sweep setup
        ld hl, NR10
        ld b, 78h               ; pace max, subtraction mode
        ld (hl), b

        ;; Volume and envelope
        ld hl, NR12
        ld b, F0h               ; Initial Volume = max, no sweep
        ld (hl), b

        ;; Period low
        period = 300
        ld de, period

        ld hl, NR13
        ld (hl), e

        ;; Period high

        ld hl, NR14             ; Load original register values
        ld a, (hl)              ;
        ld b, 07h               ; Bitmask for the lower 3 bits
        cp b                    ; invert
        and b                   ; clear the bottom 3 bits (period high)
        ld c, a                 ; move aside the old register -> in c
        ld a, d                 ; load the high period value
        cp b                    ; invert bitmask again
        and b                   ; mask out the period bits
        or c                    ; Or in the other old register bits
        ld (hl), a

        ld c, 3
short_beep:
        ;; Length and duty cycle
        ld hl, NR11
        ld b, 9Fh               ; 50% Wave duty cycle
        ld (hl), b

        ;; Channel control
        ld hl, NR14
        set 6, (hl)             ; Enable sound length triggering the
                                ; channel

        ld b, 15                ; 20 timer interrupts
        call wait
        dec c                   ; short beep counter
        jr nz, short_beep

        ;; Long beeeeeeeeeeeep
        ld hl, NR11
        ld b, 80h               ; 50% Wave duty cycle
        ld (hl), b

        ld hl, NR14
        res 6, (hl)             ; clear length
        set 7, (hl)             ; trigger

        ld b, 20                ; number of interrupts
        call wait               ; wait for the interrupts

        ld hl, NR52             ; disable APU
        res 7, (hl)

        di
        halt

        ;; Wait for B timer interrupts
wait:   push bc

.waitloop:
        call reset_timer
        call enable_timer       ; turns interrupts on

        halt
        dec b
        jr nz, .waitloop

        pop bc
        ret

        ;; Initialise the APU
apu_init:
        push bc
        push hl

        ld hl, NR52             ; Sound on/off register
        ld b, 80h               ; All sound on/off - enables the APU
        ld (hl), b

        ld hl, NR51             ; Sound panning
        ld b, FFh               ; All channels in center
        ld (hl), b

        ld hl, NR50             ; Master volume & VIN panning
        ld b, 77h               ; Max volume on each channel, VIN disabled
        ld (hl), b

        pop hl
        pop bc

        ret

        ;; Initialise the timer for interrupts
init_timer:
        TIMA = FF05h            ; Timer counter
        TMA = FF06h             ; Timer modulo (reset value opun IRQ/TIMA overflow)
        TAC = FF07h             ; Bit 2 = timer enable, bits 1-0 = input clock

        di
        push hl
        push af

        ld a, 0h
        ld (TMA), a             ; value to reload after IRQ

        call reset_timer

        pop af
        pop hl
        ei
        ret

        ;;  Resets the timer to 0
reset_timer:
        push hl
        push af

        ld a, 0h
        ld (TIMA), a

        pop af
        pop hl
        ret

        ;; Initialise interrupts
        IE = FFFFh
irq_init:
        ret

enable_timer:
        push hl
        push af
        di

        ld hl, IE
        set 2, (hl)             ; Enables timer interrupts

        ld a, 04h               ; Enable the timer, highest divider
        ld (TAC), a

        ei
        pop af
        pop hl
        ret

        ;; Requires interrupts to be disabled
disable_timer:
        push hl

        ld hl, TAC
        res 3, (hl)             ; Disable timer

        ld hl, IE
        res 2, (hl)             ; Turn off timer interrupts

        pop hl
        ret


        ;; Timer IRQ handler
        .org 0050h
service_timer_irq:
        call disable_timer
        reti
