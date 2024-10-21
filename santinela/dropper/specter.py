from marshal import dumps
from binascii import hexlify
from random import randint, shuffle



banner1 = r'''
  ██████  ██▓███  ▓█████  ▄████▄  ▄▄▄█████▓▓█████  ██▀███               
▒██    ▒ ▓██░  ██▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒             
░ ▓██▄   ▓██░ ██▓▒▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒             
  ▒   ██▒▒██▄█▓▒ ▒▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄               
▒██████▒▒▒██▒ ░  ░░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒             
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░             
░ ░▒  ░ ░░▒ ░      ░ ░  ░  ░  ▒       ░     ░ ░  ░  ░▒ ░ ▒░             
░  ░  ░  ░░          ░   ░          ░         ░     ░░   ░              
      ░              ░  ░░ ░                  ░  ░   ░                  
                         ░'''[1:]

banner2 = r"""
                            ,-.                               
       ___,---.__          /'|`\          __,---,___        
    ,-'    \`    `-.____,-'  |  `-.____,-'    //    `-.     
  ,'        |           ~'\     /`~           |        `.    
 /      ___//              `. ,'          ,  , \___      \  
|    ,-'   `-.__   _         |        ,    __,-'   `-.    |  
|   /          /\_  `   .    |    ,      _/\          \   | 
\  |           \ \`-.___ \   |   / ___,-'/ /           |  /
 \  \           | `._   `\\  |  //'   _,' |           /  /    
  `-.\         /'  _ `---'' , . ``---' _  `\         /,-'   
     ``       /     \    ,='/ \`=.    /     \       ''        
             |__   /|\_,--.,-.--,--._/|\   __|                
             /  `./  \\`\ |  |  | /,//' \,'  \                
            /   /     ||--+--|--+-/-|     \   \               
           |   |     /'\_\_\ | /_/_/`\     |   |              
            \   \__, \_     `~'     _/ .__/   /            
             `-._,-'   `-._______,-'   `-._,-'"""[1:]



class Specter:

    vars = []

    def specterize(script: str) -> str:
        print(print("Starting specterization!"))
        # print(print("Preparing anti skid layer...")) just to be sure
        script = Specter.anti_skid(script=script)
        print(print("Adding layer 1!"))
        script = Specter.layer_1(script=script)
        print(print("Adding layer 2!"))
        script = Specter.layer_2(script=script)
        print(print("Adding layer 3!"))
        script = Specter.layer_3(script=script)
        return script

    def hex(text: str) -> bytes:
        return "b'" + "".join(fr"\x{hexlify(t.encode('utf-8')).decode()}" for t in text) + "'"

    def encrypt(text: str, key: int) -> str:
        return "\x00".join(str(ord(x)+key) for x in text)

    def randvar() -> str:
        var = randint(1000, 9999)
        while var in Specter.vars:
            var = randint(1000, 9999)
        Specter.vars.append(var)
        return f"__{var}__"
    
    def get_key_by_value(vars, key) -> str:
        return list(vars.keys())[list(vars.values()).index(key)]

    def anti_skid(script: str) -> str:
        return r"""
# caca
"""[1:] + script

    def layer_1(script: str) -> str:
        ten_split = []
        key = randint(3, 33)
        splitting = randint(3, 9)
        while True:
            if len(script) >= splitting:
                ten_split.append(Specter.hex(Specter.encrypt(script[:splitting], key)))
                script = script[splitting:]
            else:
                ten_split.append(Specter.hex(Specter.encrypt(script, key)))
                break
        lexec = Specter.hex(Specter.encrypt("exec", key))
        lkey = Specter.hex(str(key))
        ten_split.append(lexec)
        ten_split.append(lkey)
        ten_split.append("globals")
        correct = [x for x in ten_split]
        shuffle(ten_split)
        vars = {Specter.randvar(): x for x in ten_split}
        script = ",".join(vars.keys()) + '=' + ",".join(vars.values()) + '\n'
        all_correct = []
        for x in correct:
            if x not in (lexec, lkey, "globals"):
                all_correct.append(Specter.get_key_by_value(vars, x))
        l1, l2, l3 = Specter.randvar(), Specter.randvar(), Specter.randvar()
        glob = f"{Specter.get_key_by_value(vars, 'globals')}()[{l1}({l2}={Specter.get_key_by_value(vars, lexec)})]"
        print(print("Creating random vars..."))
        lambdas = [fr"{l1}=lambda {l2}:''.join(chr(int({l3})-int({lkey}))for {l3} in {l2}.decode().split('\x00'))",
                   f"(lambda {l3}:{glob}(''.join({l1}({l2}={l2})for {l2} in {l3}),{Specter.get_key_by_value(vars, 'globals')}()))([{','.join(all_correct)}])",]
        script = "from builtins import *\n" + script + '\n'.join(lambdas)
        return script

    def layer_2(script: str) -> str:
        print(print("Compiling and dumping code with marshal..."))
        return dumps(compile(script, 'Specter', 'exec'))

    def layer_3(script: str) -> str:
        split = []
        splitting = 2000
        while True:
            if len(script) >= splitting:
                split.append(script[:splitting])
                script = script[splitting:]
            else:
                split.append(script)
                break
        vars = {Specter.randvar(): x for x in split}
        codevars = "\n".join(f"{a} = Func.calculate({randint(1,9)}){' ' * 500},Func.define('{a}', {b})" for a, b in vars.items())
        print(print("Camouflation of the obfuscated code..."))
        script = fr"""
__code__ = "print('hello world!')"


Any = (...,)

class Specter:
    def __init__(self, code: str) -> None:
        self.code = code
        self.execute(...)
        return None
    def execute(self, code: str = ...) -> None:
        return exec(str(code))
    
class Func:
    def calculate(num: int) -> int:
        return num*2
    def define(key, value: Any) -> Any:
        globals()[key] = value
        return globals()[key]

{codevars}


if __name__ == '__main__':
    Specter(__code__){' ' * 500},exec(__import__('marshal').loads({"+".join(var + "[1]" for var in vars)}),globals())"""[1:]
        return script


def main():
   
    print()

    file = "/tmp/dropper.py"
    print('\n')

    try:
        with open(file, mode='rb') as f:
            script = f.read().decode('utf-8')
        filename = file.split('\\')[-1]
    except:
        print("File not found!")
        return

    script = Specter.specterize(script=script)

    with open(f'/tmp/obf-dropper.py', mode='wb') as f:
        f.write(script.encode('utf-8'))
    
    print('\n')
    input(print("Done!", '!'))


main()