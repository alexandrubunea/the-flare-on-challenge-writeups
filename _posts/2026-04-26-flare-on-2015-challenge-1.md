---
layout: post
title: "Flare-On 2015 - Challenge 1"
date: 2026-04-26 12:35:15 +0200
categories: [Reverse Engineering, Flare-On]
---
# 2015 Flare-On Challenge 1

*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary

This write-up covers the first challenge of the 2015 Flare-On series. The objective is to recover a hidden flag from a Windows executable. The solution involves unpacking a cabinet-based self-extractor to retrieve the actual payload, identifying its assembly-level password-checking routine through static analysis in IDA Free, locating the encrypted target string, and decrypting it with a single-byte XOR operation.

**Tools used:** exiftool, Detect It Easy (DIE), 7-Zip, IDA Free, Python

---

## 1. Initial Triage

At first glance, the program resembles an installer based on its icon. Running exiftool confirms this suspicion, the binary is a cabinet self-extractor, and its product name field is set to "Internet Explorer," a common disguise for malicious software.

![exiftool output of the program](/assets/images/2015/Challenge1/image.png)

Detect It Easy (DIE) corroborates this finding, identifying the file as a cabinet-based self-extractor.

![DIE output of the program](/assets/images/2015/Challenge1/image-1.png)

## 2. Unpacking the Cabinet

Rather than executing the installer, the cabinet contents are extracted statically using 7-Zip. Navigating the archive yields the following path to the embedded payload:

```
.rsrc → RCDATA → CABINET
```

The `CABINET` file has no extension by default. Adding `.cab` and opening it reveals the next-stage executable:

```
i_am_happy_you_are_to_playing_the_flareon_challenge.exe
```

## 3. Triage of the Extracted Binary

Before diving into disassembly, exiftool and DIE are run against the extracted executable to understand its nature.

![exiftool output of the extracted executable](/assets/images/2015/Challenge1/image-2.png)

![DIE output of the extracted executable](/assets/images/2015/Challenge1/image-3.png)

DIE reveals that the binary was written in assembly, meaning the Ghidra decompiler would produce limited useful output. IDA Free is a better choice here, as it excels at presenting raw assembly in a readable, structured form.

## 4. Static Analysis in IDA Free

### 4.1 Entry Point and Password Prompt

Loading the binary in IDA Free and examining the entry point reveals the following assembly:

```x86asm
push    ebp
mov     ebp, esp
sub     esp, 10h
mov     [ebp+var_10], eax
push    0FFFFFFF6h      ; nStdHandle
call    GetStdHandle
mov     [ebp+var_C], eax
push    0FFFFFFF5h      ; nStdHandle
call    GetStdHandle
mov     [ebp+hFile], eax
push    0               ; lpOverlapped
lea     eax, [ebp+NumberOfBytesWritten]
push    eax             ; lpNumberOfBytesWritten
push    2Ah ; '*'       ; nNumberOfBytesToWrite
push    offset aLetSStartOutEa ; "Let's start out easy\r\nEnter the passw"...
push    [ebp+hFile]     ; hFile
call    WriteFile
push    0               ; lpOverlapped
lea     eax, [ebp+NumberOfBytesWritten]
push    eax             ; lpNumberOfBytesRead
push    32h ; '2'       ; nNumberOfBytesToRead
push    offset byte_402158 ; lpBuffer
push    [ebp+var_C]     ; hFile
call    ReadFile
xor     ecx, ecx
```

The program uses `WriteFile` to print a password prompt and `ReadFile` to collect user input, a common pattern in console-based crackmes written in raw assembly.

### 4.2 Control Flow and XOR Routine

Switching to IDA's graph view makes the program's logic immediately clear.

![Graph view of the program's control flow](/assets/images/2015/Challenge1/image-4.png)

The graph reveals a loop that XORs each byte of the user's input against the key `0x7D`. The resulting ciphertext is then compared byte-by-byte against a hardcoded encrypted string stored in the `.data` segment. Any mismatch causes the program to branch to a failure path. The flag is never stored in plaintext, only its XOR-encrypted form is embedded in the binary.

---

## 5. Locating and Decrypting the Encrypted String

Double-clicking the reference to the encrypted buffer in IDA navigates directly to it in the `.data` segment:

```x86asm
.data:00402140 byte_402140     db 1Fh                  ; DATA XREF: start+55↑r
.data:00402141                 db    8
.data:00402142                 db  13h
.data:00402143                 db  13h
.data:00402144                 db    4
.data:00402145                 db  22h ; "
.data:00402146                 db  0Eh
.data:00402147                 db  11h
.data:00402148                 db  4Dh ; M
.data:00402149                 db  0Dh
.data:0040214A                 db  18h
.data:0040214B                 db  3Dh ; =
.data:0040214C                 db  1Bh
.data:0040214D                 db  11h
.data:0040214E                 db  1Ch
.data:0040214F                 db  0Fh
.data:00402150                 db  18h
.data:00402151                 db  50h ; P
.data:00402152                 db  12h
.data:00402153                 db  13h
.data:00402154                 db  53h ; S
.data:00402155                 db  1Eh
.data:00402156                 db  12h
.data:00402157                 db  10h
```

Since XOR is its own inverse, decrypting the string requires nothing more than XORing each byte with the same key, `0x7D`. A short Python script handles this:

```python
encrypted = [0x1F, 0x08, 0x13, 0x13, 0x04, 0x22, 0x0E, 0x11, 0x4D, 0x0D,
             0x18, 0x3D, 0x1B, 0x11, 0x1C, 0x0F, 0x18, 0x50, 0x12, 0x13,
             0x53, 0x1E, 0x12, 0x10]
flag = ''.join(chr(b ^ 0x7D) for b in encrypted)
print(flag)
```

Running the script produces the flag without executing the target program even once:

**`bunny_sl0pe@flare-on.com`**