extern exit
extern _bypass


SECTION .DATA
  

SECTION .BSS


SECTION .TEXT
    global _runProcAddress
    global _wrapper


_runProcAddress:
    call rcx
    cmp rax, 0
    jl _exit
    ret

    _exit:
        sub rsp, 0x20
        mov rcx, 0
        call exit
        add rsp, 0x20
        ret


_wrapper:
    sub rsp, 40
    call _bypass
    add rsp, 40
    mov rax, 10
    ret