---
layout: post
title: "Flare-On 2015 - Challenge 2"
date: 2026-04-26 12:35:15 +0200
categories: [Reverse Engineering, Flare-On]
challenge_year: 2015
challenge_num: 2
---
# 2015 Flare-On Challenge 2
*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary
This write-up covers the second challenge of the 2015 Flare-On series. The objective is to find the correct password accepted by a hand-written assembly executable. The solution involves static analysis in IDA Free to understand the validation routine, dynamic analysis in x32dbg to observe the register state and locate the encrypted target buffer, and finally reversing the transformation chain in Python to recover the flag.

**Tools used:** exiftool, DIE, IDA Free, x32dbg, Python

---

## 1. Initial Triage

The file arrives with no extension, always a reason to be cautious before running anything. Starting with exiftool:

![exiftool result]({{ "/assets/images/2015/Challenge2/image.png" | relative_url }})

Very small executable. Could be stripped of the standard library, or written directly in assembly. Running it through DIE to find out:

![DIE result]({{ "/assets/images/2015/Challenge2/image-1.png" | relative_url }})

And indeed, it is written in assembly. Time to open it in a disassembler.

## 2. Static Analysis

When dealing with hand-crafted assembly binaries, IDA Free tends to give cleaner output than Ghidra, so that's the tool of choice here.

The entry point is minimal:

```x86asm
public start
start proc near
call    sub_401000
scasd
stosb
lodsd
jmp     short near ptr loc_401096+1
start endp
```

The only meaningful thing happening here is the call to `sub_401000`, so let's follow it.

### sub_401000 - The Main Routine

```x86asm
sub_401000 proc near
pop     eax             ; suspicious, why pop before anything else?
push    ebp
mov     ebp, esp
sub     esp, 10h
mov     [ebp-10h], eax
push    0FFFFFFF6h      ; nStdHandle
call    GetStdHandle
mov     [ebp-0Ch], eax
push    0FFFFFFF5h      ; nStdHandle
call    GetStdHandle
mov     [ebp-8], eax
push    0               ; lpOverlapped
lea     eax, [ebp-4]
push    eax             ; lpNumberOfBytesWritten
push    43h ; 'C'       ; nNumberOfBytesToWrite
push    offset aYouCrushedThat ; "You crushed that last one! Let's up the"...
push    dword ptr [ebp-8] ; hFile
call    WriteFile
push    0               ; lpOverlapped
lea     eax, [ebp-4]
push    eax             ; lpNumberOfBytesRead
push    32h ; '2'       ; nNumberOfBytesToRead
push    offset unk_402159 ; lpBuffer
push    dword ptr [ebp-0Ch] ; hFile
call    ReadFile
push    0               ; lpOverlapped
lea     eax, [ebp-4]
push    eax             ; lpNumberOfBytesWritten
push    11h             ; nNumberOfBytesToWrite
push    dword ptr [ebp-4]
push    offset unk_402159
push    dword ptr [ebp-10h]
call    sub_401084
add     esp, 0Ch
test    eax, eax
jz      short loc_401072
```

There is an unusual `pop eax` right at the start of the routine, before the standard prologue is even established. That is odd, worth keeping in mind for later.

The program writes a prompt to stdout, reads input from stdin into a buffer, passes that input to a validation subroutine `sub_401084`, and then branches depending on the return value. The structure is clear:

![Program branching]({{ "/assets/images/2015/Challenge2/image-2.png" | relative_url }})

The `test eax, eax` / `jz` pattern means: if `sub_401084` returns 0, take the failure branch. So the goal is to understand what `sub_401084` accepts.

### sub_401084 - The Validation Routine

```x86asm
sub_401084 proc near

var_C= byte ptr -0Ch
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
arg_8= dword ptr  10h

push    ebp
mov     ebp, esp
sub     esp, 0
push    edi
push    esi
xor     ebx, ebx        ; ebx = 0
mov     ecx, 25h        ; ecx = 0x25 = 37
cmp     [ebp+arg_8], ecx

loc_401096:
jl      short loc_4010D7    ; input length < 37 -> fail immediately

mov     esi, [ebp+arg_4]    ; esi = pointer to user input
mov     edi, [ebp+arg_0]    ; edi = pointer to something else
lea     edi, [edi+ecx-1]    ; edi points to the END of that buffer

loc_4010A2:
mov     dx, bx
and     dx, 3
mov     ax, 1C7h
push    eax
sahf
lodsb
pushf
xor     al, [esp+10h+var_C]
xchg    cl, dl
rol     ah, cl
popf
adc     al, ah
xchg    cl, dl
xor     edx, edx
and     eax, 0FFh
add     bx, ax
scasb
cmovnz  cx, dx
pop     eax
jecxz   short loc_4010D7

sub     edi, 2
loop    loc_4010A2

jmp     short loc_4010D9

loc_4010D7:
xor     eax, eax        ; return 0 = failure

loc_4010D9:
pop     esi
pop     edi
mov     esp, ebp
pop     ebp
retn
sub_401084 endp
```

A few things stand out immediately.

First, the minimum length check:

```x86asm
mov     ecx, 25h
cmp     [ebp+arg_8], ecx
jl      short loc_4010D7
```

The input must be at least **37 characters** long. Anything shorter fails immediately.

Second, `edi` is set to the end of whatever buffer `arg_0` points at, and `sub edi, 2` at the bottom of the loop means EDI is moving **backwards** through that buffer, net movement of +1 (from `scasb`) then -2 = -1 per iteration.

Third, there is some interesting data sitting at the bottom of the `.text` section:

```x86asm
.text:004010E9    db 0AAh, 0ECh, 0A4h
.text:004010EC    dd 0AAAEAFBAh, 0B0A7C08Ah, 0A5BA9ABCh, 0B8AFBAA5h, 0AEF9B89Dh
.text:00401100    dd 0BCB4AB9Dh, 9A90B3B6h, 0A8h, 3Dh dup(0)
.text:00401200    dd 380h dup(?)
```

These look like they could be the target encrypted bytes that the loop is comparing against. Time to confirm with dynamic analysis.

## 3. Dynamic Analysis

Opening the binary in x32dbg and running up to the point where `sub_401084` is called.

### Tracing the registers

After the two `mov` instructions load `esi` and `edi`:

```x86asm
mov     esi, [ebp+arg_4]
mov     edi, [ebp+arg_0]
```

The register state looks like this:

![State of registers]({{ "/assets/images/2015/Challenge2/image-3.png" | relative_url }})

`ESI` holds the user input. `EDI` points somewhere into the program's own code, let's look at what's there:

![What is present at 004010E4]({{ "/assets/images/2015/Challenge2/image-4.png" | relative_url }})

Running a few more instructions reveals the full content that EDI is pointing to:

![Data from EDI]({{ "/assets/images/2015/Challenge2/image-5.png" | relative_url }})

Those bytes match exactly the mystery data from the static analysis. So the loop is walking the user input byte by byte, transforming each character, and comparing it against these hardcoded encrypted bytes. That is the target.

### Revisiting the suspicious pop eax

Earlier there was that odd `pop eax` at the very beginning of `sub_401000`. Setting a breakpoint there to inspect it:

![Checking pop eax]({{ "/assets/images/2015/Challenge2/image-6.png" | relative_url }})

It is the same address range as EDI. The program is reading from **its own code**. Those bytes in `.text:004010E9` are not dead data, they serve double duty as both instructions and the encrypted password buffer. The `pop eax` is effectively loading the address of the program's own body so it can later be used as the comparison target in `sub_401084`.

### Understanding the transformation

Now let's break down what happens to each input character inside the loop.

The XOR line:

```x86asm
xor al, [esp+10h+var_C]
```

`var_C = -0x0C`, so this simplifies to:

```x86asm
xor al, [esp + 4]
```

Let's look at what is on the stack at that point:

![Value stored at the top of the stack]({{ "/assets/images/2015/Challenge2/image-7.png" | relative_url }})

Tracing it back: just before the XOR, `push eax` was executed with `AX = 0x1C7`:

![Disassembly code of push eax]({{ "/assets/images/2015/Challenge2/image-8.png" | relative_url }})

The XOR operates on `AL` only (the low byte), so the effective XOR key is **`0xC7`**.

Putting it all together, the transformation applied to each character is:

1. `lodsb` loads the next input character into `AL`
2. `xor al, 0xC7` XOR the character with `0xC7`
3. Rotate `AH` left by `(bx & 3)` positions, where `AH` started as `0x01`
4. `adc al, ah` add `AH` to `AL` with carry (carry = 1 from `sahf`, so effectively `al = al + ah + 1`)
5. `scasb` compare the result against `[EDI]`, which is walking backwards through the target buffer

The `bx` register accumulates the transformed value from each iteration:

```x86asm
add bx, ax
```

This creates a **chaining effect**: the rotation amount for character N depends on the sum of all preceding transformed values. You cannot crack each byte in isolation.

```
iteration 1: bx=0,               rotation=0
iteration 2: bx=result1,         rotation depends on result1
iteration 3: bx=result1+result2, rotation depends on both
...
```

If `scasb` finds a mismatch (`ZF=0`), `cmovnz cx, dx` zeroes out `CX` (since `dx` was cleared by `xor edx, edx`), and `jecxz` immediately jumps to the failure path. All 37 characters must transform correctly, there is no partial credit.

### Locating the target bytes

Setting a breakpoint at the `scasb` instruction to confirm exactly which bytes are being compared:

![Found the value stored in [EDI] in x32db and the memory dump]({{ "/assets/images/2015/Challenge2/image-9.png" | relative_url }})

The memory dump confirms the target. And because EDI walks **backwards** through the buffer (net −1 per iteration):

![Image of sub edi, 2]({{ "/assets/images/2015/Challenge2/image-10.png" | relative_url }})

Reading the 37 target bytes from the memory dump in reverse order:

```
AF AA AD EB
AE AA EC A4 BA AF AE AA 8A C0 A7 B0 BC 9A BA A5
A5 BA AF B8 9D B8 F9 AE 9D AB B4 BC B6 B3 90 9A
A8
```
## 4. Reversing the Flag

With the full transformation understood and the 37 target bytes extracted, the process can be reversed in Python. For each position, working from the last byte backwards to match the loop's traversal direction, we solve for the input character that would have produced the expected output:

```python
def rol8(val, n):
    n &= 7
    return ((val << n) | (val >> (8 - n))) & 0xFF

target = [0xAF, 0xAA, 0xAD, 0xEB,
          0xAE, 0xAA, 0xEC, 0xA4, 0xBA, 0xAF, 0xAE, 0xAA, 0x8A, 0xC0, 0xA7, 0xB0,
          0xBC, 0x9A, 0xBA, 0xA5, 0xA5, 0xBA, 0xAF, 0xB8, 0x9D, 0xB8, 0xF9, 0xAE,
          0x9D, 0xAB, 0xB4, 0xBC, 0xB6, 0xB3, 0x90, 0x9A, 0xA8]

bx = 0
flag = []

for i in range(37):
    needed = target[36 - i]
    ah = rol8(0x01, bx & 3)
    c = ((needed - ah - 1) & 0xFF) ^ 0xC7
    flag.append(chr(c))
    bx = (bx + needed) & 0xFFFF

print(''.join(flag))
```

The flag is:

**`a_Little_b1t_harder_plez@flare-on.com`**