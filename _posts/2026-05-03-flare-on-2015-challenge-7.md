---
layout: post
title: "Flare-On 2015 - Challenge 7"
date: 2026-05-03 20:35:15 +0200
categories: [Reverse Engineering, Flare-On]
challenge_year: 2015
challenge_num: 7
---
# 2015 Flare-On Challenge 7

*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary

This write-up covers the seventh challenge of the 2015 Flare-On series. The objective is to recover a flag delivered as an email address by a tamper-proof .NET executable. The solution involves identifying and stripping SmartAssembly obfuscation with de4dot, statically reversing three cooperating methods in the decompiled source to understand the password construction mechanism, recognizing that both the XOR key and the MD5 hash depend on reflection over the original unmodified binary, and writing a small C# wrapper that loads the original executable as a byte array to faithfully reproduce both computations and extract the correct password, which is then fed to the AES decryption routine to reveal the flag.

| Tool | Purpose |
|---|---|
| exiftool | File metadata identification |
| DIE (Detect-It-Easy) | Packer and compiler detection |
| de4dot | SmartAssembly deobfuscation |
| dnSpy | .NET decompilation and dynamic debugging |
| C# (custom wrapper) | Faithful reproduction of reflection-based key derivation |

---

## 1. Initial Triage

Running `exiftool` on the challenge file confirms it is a Windows PE executable, so the `.exe` extension is added before further analysis.

![Result of running exiftool]({{ "/assets/images/2015/Challenge7/image.png" | relative_url }})

DIE is run next to characterize the binary more precisely.

![Result of running die]({{ "/assets/images/2015/Challenge7/image-1.png" | relative_url }})

Two things stand out immediately: the binary is written in C# targeting the .NET runtime, and it is protected by SmartAssembly with obfuscation active. The detection string lists several heuristics: a modified entry point, a CLR constructor injection, virtualization of select methods, Anti-ILDASM metadata corruption, short renamed symbols, and a watermark. The virtualization heuristic is the most significant, as SmartAssembly's VM is proprietary and has no public devirtualizer.

The first step is to remove everything de4dot can handle. Running it against the binary strips Anti-ILDASM, decrypts static strings, and restores readable symbol names.

![Running de4dot on the program]({{ "/assets/images/2015/Challenge7/image-2.png" | relative_url }})

A second DIE scan on the cleaned output confirms that everything except virtualization has been eliminated.

![Result of running die on the cleaned program]({{ "/assets/images/2015/Challenge7/image-3.png" | relative_url }})

The cleaned binary is loaded into dnSpy. The assembly metadata visible at the top of the file is worth noting before diving into the methods.

![Program in dnSpy]({{ "/assets/images/2015/Challenge7/image-4.png" | relative_url }})

The assembly title reads "Yo dawg, I heard you were meta", a direct reference to the challenge name YUSoMeta. The GUID `deadbeef-1337-beef-babe-f33dc00ffeee` is composed of well-known magic byte sequences. As noted by [Wikipedia](https://en.wikipedia.org/wiki/Magic_number_(programming)#GUID), it is possible to craft GUIDs to be memorable, though this is discouraged as it undermines their uniqueness guarantees. Cross-referencing the components: `DEADBEEF` is a kernel magic value marking freed memory, and `1337` is leet for "elite". The remaining segments have no standalone documented meaning and are purely decorative. These are easter eggs from the FLARE team rather than key material. More importantly, `System.Reflection` appears in the using directives, which together with the self-referential title strongly suggests the program reads its own assembly metadata at runtime to construct the password.

## 2. Static Analysis

Navigating to the entry point at `ns2.Class3.Main` reveals the full program structure.

```csharp
static void Main(string[] args)
{
    Class1 @class = new Class1();
    MD5.Create();
    byte[] array  = new byte[] { 236, 53, 221, 143, 179, 217, 203, 23, 87, 126, 40, 65, 66, 230, 152, 180 };
    byte[] array2 = new byte[] { 31, 100, 116, 97, 0, 84, 69, 21, 115, 97, 109, 29, 79, 68, 21, 104, 115, 104, 21, 84, 78 };
    // ... string arrays omitted for brevity ...
    Console.Write(Encoding.ASCII.GetString(array4));
    string text  = Console.ReadLine().Trim();
    string text2 = Class3.smethod_0(@class, array2) + '_' + Class3.smethod_3();
    if (text == text2)
    {
        Console.Write(Encoding.ASCII.GetString(array7));
        Console.WriteLine(Class3.smethod_1(text, array));
        return;
    }
    Console.WriteLine(Encoding.ASCII.GetString(array5));
}
```

The program asks for a password, constructs the expected value as `smethod_0(array2) + '_' + smethod_3()`, and compares the two. If they match, `smethod_1` is called with the password and `array` to produce the flag email. The fail path simply prints the tamper warning. Decoding the ASCII byte arrays by hand confirms that `array3` is `"Warning! This program is 100% tamper-proof!"`, `array4` is the password prompt, `array5` is the failure message, `array6` is the success message, and `array7` is the "Use the following email address" line.

![Program launch to show the text]({{ "/assets/images/2015/Challenge7/image-5.png" | relative_url }})

A breakpoint is set at the comparison to observe `text2` in the debugger.

![Table of values at the breakpoint]({{ "/assets/images/2015/Challenge7/image-6.png" | relative_url }})

The value of `text2` is `\u001DL{a\0^o\u0017[nm\u001DEn\u0017@|h\u0015^d_6E51105290B0D056B93C06ED630404C6`. The first segment contains non-printable control characters, meaning the password cannot be entered from a keyboard directly. The second segment is 32 hex characters, the length of an MD5 digest. This immediately maps onto the two methods: `smethod_0` produces the first part and `smethod_3` produces the hash.

**Reversing smethod_0**

```csharp
static string smethod_0(Class1 class1_0, byte[] byte_0)
{
    byte[] array = Class3.smethod_2();
    string text = "";
    for (int i = 0; i < byte_0.Length; i++)
        text += (char)(byte_0[i] ^ array[i % array.Length]);
    return text;
}
```

This is a straightforward XOR loop over `array2` using a rolling key sourced from `smethod_2`. The key derivation is where things get interesting.

```csharp
static byte[] smethod_2()
{
    return Assembly.GetExecutingAssembly().ManifestModule.ResolveMethod(100663297).GetMethodBody().GetILAsByteArray();
}
```

The token `100663297` is `0x06000001` in hex. The [Microsoft documentation on metadata and self-describing components](https://learn.microsoft.com/en-us/dotnet/standard/metadata-and-self-describing-components) explains the structure directly: the top byte identifies which metadata table is being indexed, and the lower three bytes give the row within that table. In our case the upper byte `0x06` identifies the MethodDef table, and the lower three bytes `000001` give row index 1, meaning the very first method defined in the assembly. The XOR key is therefore the raw IL bytecode of that method.

Searching dnSpy for token `0x06000001` reveals it belongs to `ns0.Class0`, a default constructor with an empty body.

![Image of the IL code relevant to the function above]({{ "/assets/images/2015/Challenge7/image-7.png" | relative_url }})

The IL consists of three instructions: `ldarg.0`, `call` to `System.Object::.ctor()`, and `ret`.

**Reversing smethod_3**

```csharp
static string smethod_3()
{
    StringBuilder stringBuilder = new StringBuilder();
    MD5 md = MD5.Create();
    foreach (CustomAttributeData customAttributeData in CustomAttributeData.GetCustomAttributes(Assembly.GetExecutingAssembly()))
        stringBuilder.Append(customAttributeData.ToString());
    byte[] bytes = Encoding.Unicode.GetBytes(stringBuilder.ToString());
    byte[] array = md.ComputeHash(bytes);
    return BitConverter.ToString(array).Replace("-", "");
}
```

This concatenates the string representation of every custom attribute on the assembly, encodes the result, and returns its MD5 digest as an uppercase hex string. The output depends entirely on the exact attribute set and their `.ToString()` format as produced by the .NET runtime.

## 3. The Tamper-Proof Constraint and How to Break It

Both `smethod_2` and `smethod_3` call `Assembly.GetExecutingAssembly()`. In the original binary this resolves correctly, but de4dot rewrites the PE layout when cleaning, which changes the IL bytes of the method at RID 1 and alters the assembly's attribute metadata. Running the cleaned binary produces garbage for `smethod_0` and a different MD5 for `smethod_3`, neither of which matches the expected password. The same problem rules out patching and recompiling: any modification changes the IL key and breaks the XOR result. The program is genuinely self-verifying through reflection.

The solution is to write a small C# wrapper that loads the original `YUSoMeta.exe` as raw bytes via `Assembly.Load(File.ReadAllBytes(...))` and runs the exact same reflection logic against that loaded assembly. This gives access to the unmodified IL and attribute data without executing the binary itself, sidestepping the tamper protection entirely.

```csharp
using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

class Program {
    static void Main() {
        Assembly asm = Assembly.Load(System.IO.File.ReadAllBytes("YUSoMeta.exe"));

        byte[] ilKey = asm.ManifestModule.ResolveMethod(100663297).GetMethodBody().GetILAsByteArray();

        byte[] array2 = {31,100,116,97,0,84,69,21,115,97,109,29,79,68,21,104,115,104,21,84,78};
        string part1 = "";
        for (int i = 0; i < array2.Length; i++)
            part1 += (char)(array2[i] ^ ilKey[i % ilKey.Length]);

        StringBuilder sb = new StringBuilder();
        MD5 md5 = MD5.Create();
        foreach (CustomAttributeData attr in CustomAttributeData.GetCustomAttributes(asm))
            sb.Append(attr.ToString());
        byte[] hash = md5.ComputeHash(Encoding.Unicode.GetBytes(sb.ToString()));
        string part2 = BitConverter.ToString(hash).Replace("-", "");

        Console.WriteLine("Password: " + part1 + "_" + part2);
    }
}
```

Running the wrapper against the original binary produces the correct password.

![Secret password extracted]({{ "/assets/images/2015/Challenge7/image-8.png" | relative_url }})

The password is `metaprogrammingisherd_DD9BE1704C690FB422F1509A46ABC988`. Entering it into the running program triggers `smethod_1`, which uses it as the key material to decrypt `array` and print the flag email address.

![Getting the flag]({{ "/assets/images/2015/Challenge7/image-9.png" | relative_url }})

**Flag: `Justr3adth3sourc3@flare-on.com`**