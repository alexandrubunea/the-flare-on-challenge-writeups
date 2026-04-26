---
layout: post
title: "Flare-On 2014 - Challenge 3"
date: 2026-04-26 12:35:15 +0200
categories: [Reverse Engineering, Flare-On]
---
# 2014 Flare-On Challenge 3
*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary
This write-up covers the third challenge of the 2014 Flare-On series. The objective is to extract a hidden flag from a Windows executable. The solution involves static analysis to identify self-modifying shellcode built on the stack at runtime, followed by dynamic analysis in a debugger to let the multi-stage XOR decoding chain execute naturally, and finally extracting the flag from the decoded memory dump.

**Tools used:** exiftool, DIE, Ghidra, Binary Ninja (free), x32dbg, Python

---

## 1. Initial Triage

First let's see what we are dealing with. Running exiftool on the file:

![Details from exiftool](/assets/images/2014/Challenge3/image.png)

Good, but not enough. Running it through DIE as well:

![Details from DIE](/assets/images/2014/Challenge3/image-1.png)

So it's an .exe file, we can add the extension to the file now. It's also a very light file. Let's run it and see what happens:

![Running the program](/assets/images/2014/Challenge3/image-2.png)

Not much to go on. Time to open it in a disassembler.

## 2. Static Analysis

Opening the binary in Ghidra, the entry function is straightforward, it calls `FUN_00401000` and passes its return value to `exit`. The interesting logic lives entirely inside `FUN_00401000`.

At first glance it looks like a mess: hundreds of individual `undefined1` local variables being assigned one byte at a time. This is Ghidra failing to recognize a stack-allocated byte array and splitting it into separate variables. The last line is what matters:

```c
(*(code *)&local_205)();
```

The program is building a buffer on the stack byte by byte, then **executing it as code**. This is shellcode.

Switching to Binary Ninja gives a much cleaner representation. It recognises the pattern as two `__builtin_memcpy` calls filling a buffer, followed by a direct call into that buffer:

```c
byte var_205[0x100];
__builtin_memcpy(dest: &var_205, 
    src: "\xe8\x00\x00\x00\x00\x8b\x34\x24\x83\xc6\x1c\xb9\xdf\x01\x00\x00\x83\xf9\x00\x"
    "74\x07\x80\x36\x66\x46\x49\xeb\xf4\xe9\x10\x00\x00\x00\x07\x08\x02\x46\x15\x09\x46"
    "0f\x12\x46\x04\x03\x01\x0f\x08\x15\x0e\x13\x15\x66\x66\x0e\x15\x07\x13\x14\x0e\x08"
    "09\x16\x07\xef\x85\x8e\x66\x66\x66\x66\xed\x52\x42\xe5\xa0\x4b\xef\x97\xe7\xa7\xea"
    "67\x66\x66\xef\xbe\xe5\xa6\x6c\x5f\xbe\x13\x63\xef\x85\xe5\xa5\x62\x5f\xa8\x12\x6e"
    "ec\x75\x56\x70\x25\x20\x8d\x8d\x8f\x57\x66\x66\x66\x6f\x6c\x62\x27\x67\x62\x72\x70"
    "6a\x35\x7c\x66\x"
    count: 0x100);

char var_105;
__builtin_memcpy(dest: &var_105, 
    src:
    "\xe9\x80\x57\xc9\x86\xc9\xbe\x85\x71\x5a\x64\xc7\xac\xcb\xb9\x58\x48\x83\x0a\x"
    "57\xe3\xa5\xf9\x83\x73\x71\xb1\x27\x79\xd0\x77\x7e\x62\x0b\x3f\xab\x9a\xb2\x62\x52"
    "6a\x46\x66\x58\x73\x00\x38\x15\x39\x00\x21\x5f\x25\x15\x24\x1e\x32\x1e\x1f\x5b\x70"
    "42\x7a\x1a\x7b\x18\x7e\x10\x75\x15\x60\x55\x3a\x55\x0d\x60\x78\x17\x61\x4d\x7c\x5a"
    "7a\x46\x26\x40\x65\x0d\x31\x0b\x6f\x4b\x72\x09\x71\x52\xd8\xd1\xe3\x72\x0b\x2a\x17"
    "a4\x30\x18\xdc\xfa\x2f\xb6\xe7\xf0\x94\x06\x16\x2d\x16\xf2\xce\xa2\x8a\x3d\x37\xb8"
    "63\x21\x9b\xdf\x"
    count: 0x101);

(&var_205)();
return 0;
```

Binary Ninja splits the buffer into two variables due to its size, but it is one contiguous block of shellcode. Both Ghidra and Binary Ninja show the call into the buffer starting at `0040249b`. Static analysis alone won't get us further, the payload is obfuscated and decodes itself at runtime. Time for dynamic analysis.

## 3. Dynamic Analysis

Opening the binary in x32dbg and setting a breakpoint at `0040249b`, then stepping into the function reveals the following assembly:

![Hidden assembly code](/assets/images/2014/Challenge3/image-4.png)

The shellcode begins with a classic position-independent self-location trick (`CALL $+5` / `MOV ESI, [ESP]`), followed by a XOR decoding loop:

```asm
0019FD3F  cmp ecx, 0
0019FD42  je 19FD4B
0019FD44  xor byte ptr ds:[esi], 66
0019FD47  inc esi
0019FD48  dec ecx
0019FD49  jmp 19FD3F
0019FD4B  jmp 19FD60
```

The key is `0x66` and the loop runs for `0x1DF` (479) iterations, decoding everything that follows in memory.

Setting a second breakpoint at `0019FD4B`, right after the loop exits, lets the CPU do all the decoding work in one shot:

![Setting 2nd breakpoint](/assets/images/2014/Challenge3/image-5.png)

Inspecting the memory dump at that point reveals the first decoded string:

![Memory dump](/assets/images/2014/Challenge3/image-6.png)

`"and so it begins"` a marker confirming the first decoding stage completed successfully.

Continuing to step through the program, the shellcode contains **multiple chained XOR decoding stages**, each one decoding the next layer using a different key (`nopasaurus`, `bOlG`, `omg is it almost over?!?`). Rather than manually reversing each stage, stepping through lets the program decode everything in memory naturally:

![Keep stepping into the program](/assets/images/2014/Challenge3/image-7.png)

The flag becomes visible directly in the memory dump.

## 4. Extracting the Flag

Saving the decoded memory region to `decoded.bin` and running a Python strings script against it:

```python
with open("decoded.bin", "rb") as f:
    data = f.read()

    import re
    strings = re.findall(b'[ -~]{5,}', data)
    for s in strings:
        print(s.decode())
```

Output:

```
60305
 &   !
 &   !
 BrokenByte
aaaaaand i'm spent
omg is it almost over?!?
nopasaurus
and so it beginshus
hsaurhnopa
get ready to get nop'ed so damn hard in the paint
6bOlG
hr?!?h ovehmostht alhis ihomg
such.5h311010101@flare-on.comhnt
h speh i'mhaandhaaaa
>Fatau
Exitu
hkenBh Bro
```

The flag is:

**`such.5h311010101@flare-on.com`**