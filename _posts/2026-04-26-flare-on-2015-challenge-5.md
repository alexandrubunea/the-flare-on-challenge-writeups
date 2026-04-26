---
layout: post
title: "Flare-On 2015 - Challenge 5"
date: 2026-04-26 12:35:15 +0200
categories: [Reverse Engineering, Flare-On]
challenge_year: 2015
challenge_num: 5
---
# 2015 Flare-On Challenge 5

*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary

This write-up covers the fifth challenge of the 2015 Flare-On series. The objective is to recover a hidden flag from a network capture, with the help of a companion Windows executable that reveals how the data was originally produced. The solution involves identifying the binary as a C++ WinINet HTTP sender, reversing two encoding layers applied to a key file (a custom Caesar-style cipher using the string `"flarebearstare"` followed by a non-standard base64 encoding), extracting the encoded payload from HTTP POST requests in the provided packet capture, and inverting both transformations in Python to recover the original plaintext flag.

| Tool | Purpose |
|---|---|
| exiftool | File metadata identification |
| DIE (Detect-It-Easy) | Packer and compiler detection |
| strings | Extracting readable content from the binary |
| Ghidra | Static disassembly and decompilation |
| Wireshark | Packet capture analysis and HTTP stream extraction |
| Python | Decoding script for reversing both encoding layers |

---

## 1. Initial Triage

The challenge ships with two files: `sender` and `challenge.pcap`. The `.pcap` immediately suggests that network communication is central to the challenge. The focus starts on `sender`.

Running `exiftool` on the file:

![exiftool result on the program]({{ "/assets/images/2015/Challenge5/image.png" | relative_url }})

Then running DIE:

![die result on the program]({{ "/assets/images/2015/Challenge5/image-1.png" | relative_url }})

The file is a 32-bit Windows binary compiled with Microsoft Visual C/C++. The extension is absent, so the file is renamed to `sender.exe` before further analysis.

Running `strings` on the binary surfaces several immediately interesting fragments:

![strings result on the program]({{ "/assets/images/2015/Challenge5/image-2.png" | relative_url }})

The output hints at HTTP communication and the presence of a key file. This already suggests a picture: `sender.exe` reads a key, encodes it in some way, and sends it over the network. The `challenge.pcap` likely contains the traffic that was produced when the binary was run.

## 2. Static Analysis

The binary is loaded into Ghidra. Navigating the typical entry point chain for a MSVC binary leads to `main`:

![Main function in Ghidra]({{ "/assets/images/2015/Challenge5/image-3.png" | relative_url }})

The function is renamed accordingly. Two internal functions immediately stand out during initial exploration.

The first is a custom encoding routine:

![Custom encoder found]({{ "/assets/images/2015/Challenge5/image-4.png" | relative_url }})

The structure suggests a base64-like operation but with a non-standard alphabet. It is renamed `custom_encoder` for now and revisited later.

The second is a function that attempts to connect to a host:

![Trying to connect to a host]({{ "/assets/images/2015/Challenge5/image-5.png" | relative_url }})

The target is `127.0.0.1`, confirming that the binary was designed to communicate locally. Whatever it sends to that host should be present in `challenge.pcap`.

The third notable function operates on the key before encoding:

```c
void __fastcall FUN_00401250(int param_1,uint param_2)
{
  uint uVar1;
  
  uVar1 = 0;
  if (param_2 != 0) {
    do {
      *(char *)(uVar1 + param_1) = *(char *)(uVar1 + param_1) + "flarebearstare"[uVar1 % 0xe];
      uVar1 = uVar1 + 1;
    } while (uVar1 < param_2);
  }
  return;
}
```

Ghidra misreads the signature, but the logic is clear: `param_1` is a `char*` buffer and `param_2` is its length. Each byte is incremented by the corresponding byte of `"flarebearstare"`, cycling every `0xe` (14) bytes. This is a rotational additive cipher, a Caesar-type transform using the literal string as its key. The function signature is corrected and it is renamed `apply_flarebearstare`.

With the renamed signature in place, `main` becomes significantly more readable:

![apply_flarebearstare function after modifying the signature]({{ "/assets/images/2015/Challenge5/image-6.png" | relative_url }})

The full decompiled `main` now reads:

```c
void main(void)

{
  DWORD src_len;
  uint uVar1;
  HANDLE hFile;
  char *dst;
  int extraout_EAX;
  int iVar2;
  uint uVar3;
  uint uVar4;
  DWORD DStack_8000c;
  char acStack_80008 [524292];
  
  uVar1 = DAT_00412000 ^ (uint)&stack0xfffffffc;
  DStack_8000c = 0;
  hFile = CreateFileA("key.txt",0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    puts("[!] Could not open key file: %s\n");
    __security_check_cookie((void *)(uVar1 ^ (uint)&stack0xfffffffc));
    return;
  }
  ReadFile(hFile,acStack_80008,0x80000,&DStack_8000c,(LPOVERLAPPED)0x0);
  CloseHandle(hFile);
  src_len = DStack_8000c;
  if (DStack_8000c != 0) {
    apply_flarebearstare(acStack_80008,DStack_8000c);
    uVar4 = (src_len / 3) * 3;
    if (src_len == uVar4) {
      iVar2 = 0;
    }
    else {
      iVar2 = (uVar4 - src_len) + 3;
    }
    uVar4 = ((iVar2 + src_len) / 3) * 4;
    dst = calloc(1,uVar4 + 1);
    custom_encoder(acStack_80008,src_len,dst,uVar4);
    if (extraout_EAX == 0) {
LAB_00401229:
      __security_check_cookie((void *)(uVar1 ^ (uint)&stack0xfffffffc));
      return;
    }
    uVar3 = 0;
    if (uVar4 != 0) {
      do {
        iVar2 = connect_to_host(dst + uVar3);
        if (iVar2 == 0) goto LAB_00401229;
        uVar3 = uVar3 + 4;
      } while (uVar3 < uVar4);
    }
  }
  __security_check_cookie((void *)(uVar1 ^ (uint)&stack0xfffffffc));
  return;
}
```

The execution flow is now fully understood. The binary reads `key.txt`, applies `apply_flarebearstare` to the raw bytes, passes the result through `custom_encoder`, and transmits the output in four-byte chunks via HTTP POST requests to `localhost:80`. The `key.txt` file is not present in the challenge archive, so the original plaintext must be recovered by working backwards from the network capture.

Inspecting `connect_to_host` confirms the HTTP details:

```c
int __fastcall connect_to_host(char *key)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = InternetOpenA("Mozilla/5.0 (Windows NT 6.1; WOW64) KEY",0,0,0,0);
  if (iVar1 == 0) {
    puts("[!] Could not open internet session.\n");
    return 0;
  }
  iVar2 = InternetConnectA(iVar1,"localhost",0x50,0,0,3,0,1);
  if (iVar2 == 0) {
    puts("[!] Could not connect to server: %s\n");
    return 0;
  }
  iVar3 = HttpOpenRequestA(iVar2,"POST","/",0,0,0,0,1);
  if (iVar3 == 0) {
    puts("[!] Could not open internet request.\n");
    return 0;
  }
  iVar4 = HttpSendRequestA(iVar3,0,0,key,4);
  if (iVar4 == 0) {
    puts("[!] Error sending key data.\n");
    InternetCloseHandle(iVar3);
    InternetCloseHandle(iVar2);
    InternetCloseHandle(iVar1);
    return 0;
  }
  InternetCloseHandle(iVar3);
  InternetCloseHandle(iVar2);
  InternetCloseHandle(iVar1);
  return 1;
}
```

Each POST carries exactly 4 bytes of the encoded key, sent in a loop from `main` until the full encoded buffer is transmitted. The User-Agent string `"Mozilla/5.0 (Windows NT 6.1; WOW64) KEY"` is a deliberate marker that will make the traffic trivial to identify in Wireshark.

## 3. Extracting the Flag

With the encoding pipeline fully mapped, the next step is to recover the encoded payload from `challenge.pcap` and invert both transformations.

Opening the capture in Wireshark and filtering for HTTP traffic:

![http requests inside WireShark]({{ "/assets/images/2015/Challenge5/image-7.png" | relative_url }})

The POST request bodies need to be extracted and concatenated in order:

![Data that needs concatenation]({{ "/assets/images/2015/Challenge5/image-8.png" | relative_url }})

Assembling the body bytes in sequence produces the following hex string:

```
55 44 59 73 31 44 37 62 4e 6d 64 45 31 6f 33 67 35 6d 73 31 56 36 52 72 59 43 56 76 4f 44 4a 46 31 44 70 78 4b 54 78 41 4a 39 78 75 5a 57 3d 3d
```

Converting the hex back to ASCII yields:

![Using rapidtables.com to see the string in ASCII]({{ "/assets/images/2015/Challenge5/image-9.png" | relative_url }})

```
UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW==
```

This is the fully encoded form of the original `key.txt` content. Decoding it requires reversing both transformations in the correct order: `custom_encoder` first, then `apply_flarebearstare`.

Testing the hypothesis that `custom_encoder` is a standard base64 with a shifted alphabet (lowercase letters first, then uppercase, rather than the standard ordering) immediately pays off. A Python script handles both decode steps:

```python
import base64

CUSTOM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def decode_custom_encode(s):
    normalized = s.translate(str.maketrans(CUSTOM, STANDARD))
    return base64.b64decode(normalized)

def decode_flarebearstare(s):
    key = bytes("flarebearstare", "utf-8")
    result = []

    for i, b in enumerate(s):
        result.append(b - key[i % 14])
    
    return result

encoded_key = "UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW=="

first_decode = decode_custom_encode(encoded_key)
print(f"Custom base decoded: {first_decode}")

second_decode = decode_flarebearstare(first_decode)
print(f"Decoded flarebearstare: {second_decode}")

flag = "".join([chr(x) for x in second_decode])
print(f"The flag is {flag}")
```

Running the script:

![Result of running the script]({{ "/assets/images/2015/Challenge5/image-10.png" | relative_url }})

**Flag: `Sp1cy_7_layer_OSI_dip@flare-on.com`**