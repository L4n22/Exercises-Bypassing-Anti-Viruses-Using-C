global _sysNtAllocVirtMem


SECTION .DATA

SECTION .BSS

SECTION .TEXT
    
_sysNtAllocVirtMem:
    mov r10, rcx
    mov eax, 18h
    syscall 
    ret