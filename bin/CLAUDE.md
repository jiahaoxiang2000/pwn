# pwn.college Connection Guide

## How pwn.college Works

pwn.college **does NOT use traditional remote network connections** like `remote("host", port)` for their challenges.

Instead, pwn.college uses **SSH access to Docker containers**:

- not need run it in local.

### Running Exploit Scripts:

For pwn.college challenges, your pwntools scripts should use:

```python
# Correct for pwn.college
p = process("/challenge/program-name")
```

**NOT:**

```python
# This won't work for pwn.college
p = remote("host", port)  # ❌ Wrong
```
