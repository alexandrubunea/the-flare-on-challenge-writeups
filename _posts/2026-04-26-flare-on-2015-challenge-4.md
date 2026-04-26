---
layout: post
title: "Flare-On 2015 - Challenge 4"
date: 2026-04-26 12:35:15 +0200
categories: [Reverse Engineering, Flare-On]
challenge_year: 2015
challenge_num: 4
---
# 2015 Flare-On Challenge 4

*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary

This write-up covers the fourth challenge of the 2015 Flare-On series. The objective is to recover a hidden flag from a Windows executable named `youPecks.exe`. The binary is UPX-packed, but with a twist: the challenge authors injected extra code into the UPX stub itself that modifies program behavior at runtime before the main code ever runs. Solving this challenge requires identifying the stub's role, understanding a time-based string selection mechanism, and realizing that the packed binary must be run directly rather than analyzed statically in its unpacked form.

**Tools used:** Detect It Easy (DIE), exiftool, UPX, Ghidra, x32dbg, Python

## 1. Initial Triage

Starting as usual, the file has no extension. Running exiftool on it reveals it is a Windows executable.

![exiftool run on the program]({{ "/assets/images/2015/Challenge4/image.png" | relative_url }})

Throwing it into DIE confirms the most important detail: the program is packed with UPX.

![DIE run on the program]({{ "/assets/images/2015/Challenge4/image-1.png" | relative_url }})

The name `youPecks` is itself a hint, a phonetic play on "UPX."

## 2. Unpacking the Binary

Since the binary is UPX-packed, the natural first step is to unpack it:

```powershell
upx -d youPecks -o unpacked_youPecks.exe
```

Running exiftool and DIE again on the unpacked result shows it is a C++ binary compiled with the Visual Studio toolchain.

![exiftool on unpacked program]({{ "/assets/images/2015/Challenge4/image-2.png" | relative_url }})

![DIE on unpacked program]({{ "/assets/images/2015/Challenge4/image-3.png" | relative_url }})

## 3. Static Analysis in Ghidra

### 3.1 Finding main

Loading the unpacked binary into Ghidra, the real entry point is `___tmainCRTStartup`, which is the MSVC CRT bootstrap. The actual `main` function is identified as `FUN_00401350`, called as:

```c
DAT_004070a8 = FUN_00401350(DAT_00407090, DAT_00407098);
```

The two arguments correspond to `argc` and `argv`. The function is renamed to `main` and its signature is updated to match the official Microsoft documentation.

![Correct main signature]({{ "/assets/images/2015/Challenge4/image-4.png" | relative_url }})

### 3.2 Early Exit Checks

Inside `main`, the code is tangled with many repeating blocks, but two guard conditions stand out immediately.

The first check verifies that exactly one argument was passed:

```c
if (argc != 2) {
    // cleanup and exit
    goto LAB_0040258c;
}
```

The second check evaluates the result of `atoi("5")`:

```c
iVar3 = atoi("5");
// ...
pbVar4 = FUN_00402ae0((basic_ostream<> *)cout_exref, "2 + 2 = ");
pbVar4 = std::basic_ostream<>::operator<<(pbVar4, iVar8);
// ...
if (iVar3 == 5) {
    // cleanup and exit
    goto LAB_0040258c;
}
```

The value `5` is hardcoded, so `iVar3 == 5` is always true, meaning the program always exits early in the unpacked version. The `cout` chain prints `2 + 2 = 5\n` before exiting.

Running the unpacked binary confirms this behavior.

![Running the program to test]({{ "/assets/images/2015/Challenge4/image-5.png" | relative_url }})

### 3.3 Patching the Unpacked Binary

To bypass the hardcoded `5` check and continue analysis, the immediate value in the `CMP` instruction is patched in Ghidra from `0x5` to `0x0`:

```
; Before patch
0040147c    CMP    ESI, 0x5
0040147f    JNZ    LAB_004014ee

; After patch
0040147c    CMP    ESI, 0x0
0040147f    JNZ    LAB_004014ee
```

With `CMP ESI, 0x0` followed by `JNZ`, the program jumps past the early exit block whenever ESI is non-zero, which is always the case for any valid numeric input. The patched binary is exported as `unpacked_youPecks_patched.exe`.

![Patched code in Ghidra]({{ "/assets/images/2015/Challenge4/image-6.png" | relative_url }})

![Saving the patched program]({{ "/assets/images/2015/Challenge4/image-7.png" | relative_url }})

Running the patched binary with an argument still exits immediately, indicating there is more to understand.

![Program behaving the same after patching]({{ "/assets/images/2015/Challenge4/image-8.png" | relative_url }})

## 4. Dynamic Analysis in x32dbg

### 4.1 Loading the Patched Binary

Since the binary was compiled with ASLR disabled at the default base (`0x00400000`), the Ghidra addresses do not directly match x32dbg after loading. Checking the Memory Map tab reveals the actual load address:

```
Address=00F90000   Type=IMG   Page=unpacked_youpecks_patched.exe
```

All Ghidra addresses are offset by `0x00F90000 - 0x00400000 = 0x005F0000`. For example, the `CMP ESI, 0x0` instruction at Ghidra address `0x0040147C` maps to `0x00F9147C` in x32dbg.

### 4.2 Input Transformation and Hash Generation

Stepping through the patched binary with a numeric argument reveals the following logic after the two guard checks pass:

```c
transformedInput = atoi(*(char **)(argv + 4));
byteTransformedInput[0] = (BYTE)(transformedInput + 4);
generateHash(byteTransformedInput, secretKey);
```

The user's input is converted to an integer, incremented by 4, cast to a single byte, and then passed to a hashing function. Inspecting that function reveals it uses the Windows Cryptography API:

```c
CryptAcquireContextW(&local_c, NULL, NULL, 1, 0xf0000000);
CryptCreateHash(local_c, 0x8003, 0, 0, &local_8);  // 0x8003 = CALG_MD5
CryptHashData(local_8, param_1, 1, 0);
CryptGetHashParam(local_8, 2, param_2, &local_10, 0);
```

The constant `0x8003` is `CALG_MD5`. The function computes the MD5 hash of a single byte derived from the user's input and stores the 16-byte digest into `secretKey`. This hash serves as the decryption key.

The function is renamed to `generateHash`.

### 4.3 Time-Based String Selection

Continuing through the code, the program calls `_localtime64_s` to retrieve the current local time. Its return value is an `errno_t`, not the time itself:

```c
localTimeErr = _localtime64_s(&timeStructure, &longTime);
transformedInput = timeStructure.tm_hour;
if (localTimeErr != 0) {
    transformedInput = -1;
}
```

If the call succeeds, `transformedInput` holds the current hour (0-23). If it fails, it is set to `-1` as an error sentinel.

The bulk of `main` is made up of a large block of nearly identical repeating code that initially looks like obfuscation:

```c
freshString = string_constructor((undefined1 *)&timeStructure);
local_c._0_1_ = 6;
vector_string_push_back((uint)freshString);
local_c._0_1_ = 5;
if (0xf < (uint)timeStructure.tm_year) {
    operator_delete((void *)timeStructure.tm_sec);
}
freshString = string_constructor((undefined1 *)&timeStructure);
local_c._0_1_ = 7;
vector_string_push_back((uint)freshString);
// ... repeats 24 times
```

This is not obfuscation. It is the compiler unrolling a loop that populates two `std::vector<std::string>` objects, one entry per iteration, with 24 base64-encoded strings embedded in the binary. Each `vector_string_push_back` call appends one string to one of the two vectors.

Running `strings` on the binary reveals both sets. The first set of 24 shorter strings are the XOR keys, one per hour:

```
K7IfRF4nOiNn9Jsqt9wFCq==
vAvack0BPyMQiq0MkChFqq==
NMImwkviE46VACNHafRqVW==
HMzOnqAQZzalVvP0Re7FAa==
7h9+E7q3qS6gGux3htE1pa==
I7BbEdHKp5ArZgPn5Suxcq==
... (24 total)
```

The second set of 24 longer strings are the encrypted payloads, also one per hour:

```
XTd3NiPLZBQ5N1FqkBN+a/Av6SpqBS/K
am0YoDLZYlREsg5Mt62+mZcil2AdEmRK
YWd+ADeGfR3BakQHzJAXZFTf4ZAlkXtJ
... (24 total)
```

After the vectors are populated, the current hour is used as the index to select the corresponding pair: one XOR key and one encrypted payload. The selection uses `transformedInput * 0x1c` as the byte offset into the vector's internal buffer, since `0x1c` (28 bytes) is `sizeof(std::string)` in MSVC's 32-bit layout:

```c
iStack_a4 = transformedInput * 0x1c;
string_assign_substr(&stack0xfffffee8, (int *)(iStack_a4 + aiStack_ec[0]));
base64_decode((void **)&timeStructure, pcVar6);
```

The selected string is extracted via `string_assign_substr`, then passed to `base64_decode` which decodes it using the runtime-modified alphabet into raw bytes.

### 4.4 The Validation Loop

Before decoding the payload, the program runs a validation loop that checks whether the user-supplied input produces the correct `secretKey` for the current hour. The loop compares the decoded XOR key against the MD5 hash byte by byte:

```c
if (local_b8 != local_bc) {
    do {
        if ((secretKey + transformedInput)[(int)local_bc - (int)secretKey] !=
            secretKey[transformedInput]) {
            // cleanup and exit
            goto LAB_0040258c;
        }
        transformedInput = transformedInput + 1;
    } while (transformedInput != (int)local_b8 - (int)local_bc);
}
```

Breaking this down:

- `local_bc` and `local_b8` are the `begin` and `end` pointers of the vector holding the decoded XOR key bytes. The condition `local_b8 != local_bc` checks that the vector is non-empty.
- `(int)local_b8 - (int)local_bc` gives the number of bytes in the decoded key, i.e. the loop iteration count.
- `secretKey[transformedInput]` indexes into the MD5 hash using the current loop counter.
- `(secretKey + transformedInput)[(int)local_bc - (int)secretKey]` indexes into the decoded XOR key at the same offset.

In plain terms: the loop walks through every byte of the base64-decoded XOR key and checks that it matches the corresponding byte of the MD5 hash derived from the user's input. If any byte mismatches, the program exits immediately. Only when every byte matches does execution continue to the actual decryption and flag output.

This means there is exactly one correct input value per hour, the one whose `MD5(input + 4)` matches the base64-decoded XOR key for that hour. Since the input is transformed as `(atoi(argv[1]) + 4) & 0xFF` before hashing, only 256 distinct MD5 keys are possible regardless of what number the user types. The correct input for hour 15 turns out to be `15` itself, a coincidence specific to this challenge.

### 4.5 Flag Output

Once the validation loop passes, the program selects the corresponding encrypted payload for the current hour, base64-decodes it, XORs it byte by byte against the validated `secretKey`, and builds the result into a string via repeated `string_push_back` calls:

```c
transformedInput = 0;
if (local_c8 != local_cc) {
    do {
        string_push_back();
        transformedInput = transformedInput + 1;
    } while (transformedInput != (int)local_c8 - (int)local_cc);
}
```

The result is then printed to the console via `FUN_00402d30`, which is the `operator<<(ostream&, std::string&)` overload, the string variant of the same output mechanism seen earlier:

```c
pbVar4 = FUN_00402d30((basic_ostream<> *)cout_exref, (char *)local_74);
FUN_00402ae0(pbVar4, "\n");
```

## 5. The Hidden UPX Stub Trick

At this point, running the packed binary directly with different numeric arguments and the current hour as input is the logical next step. However, the patched unpacked binary never produces a flag regardless of input.

The reason becomes clear after consulting the original binary: the UPX stub was modified. In a normal UPX-packed binary, the stub decompresses the payload and jumps to the original entry point. In this binary, the authors injected additional code into the stub that executes before `main` and performs two modifications in memory:

1. **Patches the `"5"` string to `"4"`** in the decompressed code, so the `atoi("5") == 5` check becomes `atoi("4") == 5`, which is false, allowing the program to continue.
2. **XORs the base64 alphabet** used by the custom base64 decoder, swapping the case of every letter. This means the correct alphabet at runtime is `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/` rather than the uppercase-first version stored in the binary.

When `upx -d` is used to unpack, the stub is never executed. The decompressed binary retains the unmodified `"5"` string and the unmodified base64 alphabet, so even with the `JZ` patch in place, the decryption produces garbage because it uses the wrong alphabet.

## 6. Flag Extraction

Running the original packed binary directly with the current hour as the argument produces the flag. At 3 PM (hour 15), the correct input is `15`:

```
youPecks.exe 15
```

![Flag reveal after running the binary with the current hour]({{ "/assets/images/2015/Challenge4/image-9.png" | relative_url }})

The program prints:

```
Uhr1thm3tic@flare-on.com
```

![Running the packed file]({{ "/assets/images/2015/Challenge4/image-10.png" | relative_url }})

**Flag: `Uhr1thm3tic@flare-on.com`**

## Key Takeaways

The central lesson of this challenge is that unpacking a binary statically with `upx -d` does not always reproduce the runtime behavior of the packed version. When code is injected into the UPX stub, it runs only when the packed binary is executed directly. Any analysis done purely on the unpacked output will be missing that behavior, leading to conclusions that appear correct but fail in practice. Always verify that the unpacked binary behaves identically to the packed one before committing to static analysis alone.

## Bonus: Solving the Unpacked Binary Without the Packed Version

Once the role of the UPX stub is understood, it is possible to make the unpacked binary fully functional with two targeted patches in Ghidra, no packed binary required.

**Patch 1: The arithmetic check**

As covered in section 3.3, the immediate value in the `CMP` is changed from `0x5` to `0x0`, bypassing the hardcoded early exit.

**Patch 2: The base64 alphabet**

The `base64_decode` function constructs its lookup alphabet via an `ATL::CStringT` constructor call:

```c
ATL::CStringT<>::CStringT<>(
    (CStringT<> *)&local_2c,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
```

The UPX stub XORs this string in memory at runtime to swap the case of every letter before `main` runs. In the unpacked binary that swap never happens, so the alphabet is wrong and decryption produces garbage. The fix is to patch the string literal directly in the `.rdata` segment, replacing it with the case-swapped version:

```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/
```

The digits and `+/` characters are not affected by case swapping and remain identical. The string length does not change, so no surrounding bytes are disturbed.

With both patches applied, the unpacked binary behaves identically to the packed one. Running it with the current hour as the argument produces the flag cleanly.

**An interesting observation**

This second patch points to a subtle but detectable anomaly in the binary. Anyone with enough base64 familiarity knows that the standard alphabet always begins with uppercase letters. Seeing `ABCDEFGHIJKLMNOPQRSTUVWXYZabc...` hardcoded in the binary but then producing incorrect output is a signal that the alphabet is being modified somewhere at runtime. A sharp analyst could spot this discrepancy, notice the mismatch between the stored alphabet and the expected base64 structure, and arrive at the case-swap conclusion without ever considering the UPX stub at all. It is a niche observation, but it represents exactly the kind of pattern recognition that separates fast reversing from exhaustive debugging.