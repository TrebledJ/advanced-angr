from pwn import *
from solve import solve


p = remote("tamuctf.com", 443, ssl=True, sni="labyrinth")

for binary in range(5):
    with open("elf", "wb") as file:
        file.write(bytes.fromhex(p.recvline().rstrip().decode()))
    
    out = solve()
    p.sendline(out.hex().encode())

p.interactive()
