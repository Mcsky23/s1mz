# santinela

This module of `s1mz` is it's "field agent". It gets executed on the target machine and it consists of:
- dropper
- process hijacker
- actual malicious shellcode that gets injected

## Dropper

Dropper downloads the binary from the file server using a custom protocol and it executes it directly in memory using `execveat` syscall.

## Process hijacker

Process hijacker finds a process to attach to and injects the payload into it. It should be able to find a process that is not suspicious.

## Shellcode

Shellcode that gets injected should create a child process that runs a loop that sends me the flags. This should be as stealthy as possible and hijack a non-suspicious process.

## TODO

- [x] make it redundant
- [x] fix: redundancy only works if the process being killed is not the one sending flags
- [x] fix: hijacker doesn't always figure out the opposite process
- [x] fix: kill processes marked as defunct
- [x] make payload get hijacker from remote
- [x] fix: if connection to send flags is unsuccessful, dont spawn other processes
- [x] encode/encrypt flags that get sent to the server
- [x] use the same encryption for the binary 
- [x] make hijack.c search for available processes to inject into
- [x] fix: already injected function is not working
- [ ] modify log paths to hidden random files
- [ ] add user persistencies
- [ ] add other persistencies
- [ ] obfuscate everything

