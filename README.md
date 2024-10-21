# s1mz

s1mz is a backdoor/rootkit that is designed to be stealthy and persistent. It's main purpose is to send flags to the attacker each round, without being detected. It does this by injecting itself into the memory of a non-suspicious/default linux process. From there, it just `forks`, thus creating an infected child process and a clean parent process. The child process is responsible for sending the flags to the attacker.

## Components

### santinela

This module of `s1mz` is it's "field agent". It gets executed on the target machine and it consists of:
- dropper:
    - Dropper downloads the binary from the file server using a custom protocol and it executes it directly in memory using `execveat` syscall.
- process hijacker
    - Process hijacker finds a process to attach to and injects the payload into it. It should be able to find a process that is not suspicious.
- actual malicious shellcode that gets injected

### "dealer" / server

This module runs on the attacker's server and it is responsible for serving encrypted malicious binaries to the dropper and for receiving the flags from the infected machines.

Note: **s1mz** uses a custom protocol and ecryption algorithm for every remote commnication.

### How to use

To be continued...

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





