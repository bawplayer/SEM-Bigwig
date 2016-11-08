; tiny.asm
  BITS 32
  GLOBAL _start
  SECTION .text
  _start:
                mov     eax, 1		; exit()
                mov     ebx, 42 
                int     0x80
