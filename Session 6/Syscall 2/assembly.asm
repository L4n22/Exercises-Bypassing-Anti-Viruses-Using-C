global _sysNtWriteVirtMem

SECTION .DATA

SECTION .BSS

SECTION .TEXT
    
_sysNtWriteVirtMem:
	 mov     r10, rcx
	 mov     eax, 3Ah
	 syscall
	 ret