import socket
import threading
import hashlib
import os

KEY = b"k3ifin..1"

def encrypt_file(data):
    encoded = list(data)
    idx = 0
    for i in range(len(data)):
        # print((((((i << 4) + 97436)) ^ 0x69) & 0xff))
        encoded[i] = (encoded[i] ^ (((((i << 4) + 97436)) ^ 0x69) & 0xff))
    return b"".join([bytes([x]) for x in encoded])

def encode_fn(data):
    aux = bytes.fromhex(hashlib.md5(data.encode()).hexdigest())
    encoded = list(aux)
    for i in range(len(aux) - 1):
        encoded[i] = (encoded[i] ^ encoded[len(aux) - 1]) ^ ((69 + (i << 7) * 1543453) % 256)

    return b"".join([bytes([x]) for x in encoded])

# def decode_fn(self, data):
#     decoded = list(data)
#     for i in range(len(data) - 1):
#         decoded[i] = (decoded[i] ^ decoded[len(data) - 1]) ^ ((69 + (i << 7) * 1543453) % 256)
#     return b"".join([bytes([x]) for x in decoded])

class Server:
    def __init__(self, host, port, filelist):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"[INIT] Listening on {self.host}:{self.port}")

        self.files = {}
        self.files_lookup = {}
        dir = os.listdir(filelist)
        for file in dir:
            aux = encode_fn(file)
            self.files[file] = aux
            self.files_lookup[aux] = file

        print(f"[+] Files: {self.files}")
        #self.file = open(file, "rb").read()



    

    def handle_client(self, client_socket):
        # receive key
        key = client_socket.recv(len(KEY))
        print(f"[*] Received key: {key}")
        
        # receive binary name
        name_enc = client_socket.recv(17)

        if key != KEY:
            client_socket.send(b"\x69\x69")
            return

        #l = bytes.fromhex(hex(len(self.file))[2:].zfill(2))[::-1]

        print(f"[+] Requested download: {name_enc}")
        for file in self.files_lookup:
            if file == name_enc:
                f = open(f"./filelist/{self.files_lookup[file]}", "rb")
                to_send = f.read()
                to_send = encrypt_file(to_send)
                
                f.close()

                l = bytes.fromhex(hex(len(to_send))[2:].zfill(2))
                print(f"[+] Sending file: {self.files_lookup[file]} with size {l.hex()}")
                
                client_socket.send(l)
                client_socket.send(to_send)
                return
            
        print(f"[-] File not found")
        client_socket.send(b"\x69\x69")
        return

            

    def run(self):
        while True:
            client, addr = self.server.accept()
            print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=self.handle_client, args=(client,))
            client_handler.start()

def main():
    host = "0.0.0.0"
    port = 9999
    files = "./filelist"
    server = Server(host, port, "./filelist")
    server.run()

if __name__ == "__main__":
    main()