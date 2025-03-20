---
title: PascalCTF 
date: 2025-03-19 23:00:00
categories: [Writeups, ctf-online]
tags: [Reverse-Engineering, Cryptography]
description: Some writupes for challenges in Reverse Engineering, Cryptography and Miscellaneous
image: /assets/ctf/pascalctf/pascalctf.png
---

## X-Ray [Reverse-Engineering]
> Author : AlBovo
>
> I've recently written my first license checker, maybe Steam will buy it...
>
> Flag format: pascalCTF{secret_signature}

> **File**: [x-ray](/assets/files/pascalctf/x-ray)

First we analyze the x-ray file using any reverse engineering tools, in this case we are using Radare 2. We run Radare 2 using `r2 x-ray`, then `aaa` to analyze the file, then list out all functions using `afl`. Finally we print out the disassesmbled function of checkSignature using `pdf@sym.checkSignature`. Output is shown below:

```
└─$ r2 x-ray
Warning: run r2 with -e bin.cache=true to fix relocations in disassembly
[0x00001080]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00001080]> afl
0x00001080    1 38           entry0
0x000012f4    1 13           sym._fini
0x000011fa    9 248          main
0x00001179    9 129          sym.checkSignature
0x00001000    3 27           sym._init
0x00001030    1 6            sym.imp.strlen
0x00001040    1 6            sym.imp.__stack_chk_fail
0x00001050    1 6            sym.imp.printf
0x00001060    1 6            sym.imp.fgets
0x00001070    1 6            sym.imp.fwrite
0x00001170    5 153  -> 60   entry.init0
0x00001120    5 65   -> 55   entry.fini0
0x000010b0    4 41   -> 34   fcn.000010b0
[0x00001080]> pdf@sym.checkSignature
            ; CALL XREF from main @ 0x128e
┌ 129: sym.checkSignature (char *arg1);
│           ; var char *s @ rbp-0x18
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg char *arg1 @ rdi
│           0x00001179      55             push rbp
│           0x0000117a      4889e5         mov rbp, rsp
│           0x0000117d      4883ec20       sub rsp, 0x20
│           0x00001181      48897de8       mov qword [s], rdi          ; arg1
│           0x00001185      488b45e8       mov rax, qword [s]
│           0x00001189      4889c7         mov rdi, rax                ; const char *s
│           0x0000118c      e89ffeffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001191      4883f812       cmp rax, 0x12
│       ┌─< 0x00001195      7407           je 0x119e
│       │   0x00001197      b800000000     mov eax, 0
│      ┌──< 0x0000119c      eb5a           jmp 0x11f8
│      ││   ; CODE XREF from sym.checkSignature @ 0x1195
│      │└─> 0x0000119e      c745fc000000.  mov dword [var_4h], 0
│      │┌─< 0x000011a5      eb41           jmp 0x11e8
│      ││   ; CODE XREF from sym.checkSignature @ 0x11f1
│     ┌───> 0x000011a7      8b45fc         mov eax, dword [var_4h]
│     ╎││   0x000011aa      4863d0         movsxd rdx, eax
│     ╎││   0x000011ad      488b45e8       mov rax, qword [s]
│     ╎││   0x000011b1      4801d0         add rax, rdx
│     ╎││   0x000011b4      0fb608         movzx ecx, byte [rax]
│     ╎││   0x000011b7      8b45fc         mov eax, dword [var_4h]
│     ╎││   0x000011ba      4898           cdqe
│     ╎││   0x000011bc      488d154d0e00.  lea rdx, obj.key            ; 0x2010 ; "*7^tVr4FZ#7S4RFNd2"
│     ╎││   0x000011c3      0fb60410       movzx eax, byte [rax + rdx]
│     ╎││   0x000011c7      31c1           xor ecx, eax
│     ╎││   0x000011c9      8b45fc         mov eax, dword [var_4h]
│     ╎││   0x000011cc      4898           cdqe
│     ╎││   0x000011ce      488d155b0e00.  lea rdx, obj.encrypted      ; 0x2030 ; "xR\bG$G\a\x19kPhgCa5~\t\x01"
│     ╎││   0x000011d5      0fb60410       movzx eax, byte [rax + rdx]
│     ╎││   0x000011d9      38c1           cmp cl, al
│    ┌────< 0x000011db      7407           je 0x11e4
│    │╎││   0x000011dd      b800000000     mov eax, 0
│   ┌─────< 0x000011e2      eb14           jmp 0x11f8
│   ││╎││   ; CODE XREF from sym.checkSignature @ 0x11db
│   │└────> 0x000011e4      8345fc01       add dword [var_4h], 1
│   │ ╎││   ; CODE XREF from sym.checkSignature @ 0x11a5
│   │ ╎│└─> 0x000011e8      8b45fc         mov eax, dword [var_4h]
│   │ ╎│    0x000011eb      4898           cdqe
│   │ ╎│    0x000011ed      4883f811       cmp rax, 0x11
│   │ └───< 0x000011f1      76b4           jbe 0x11a7
│   │  │    0x000011f3      b801000000     mov eax, 1
│   │  │    ; CODE XREFS from sym.checkSignature @ 0x119c, 0x11e2
│   └──└──> 0x000011f8      c9             leave
└           0x000011f9      c3             ret
```

Breaking down what this function does, it first checks if the input (argv1) is 18 (0x12 in hex) characters long. Then XOR the input with obj.key ("*7^tVr4FZ#7S4RFNd2"). Finally, the results is compared with obj.encrypted ("xR\bG$G\a\x19kPhgCa5~\t\x01"). Therefore, in order to reverse the XOR, we simply need to take the obj.key and obj.encrypted and XOR them.

```python
key = "*7^tVr4FZ#7S4RFNd2"
encrypted = b"xR\x08G$G\x07\x19kPhgCa5~\t\x01"

decrypted = "".join(chr(e ^ ord(k)) for e, k in zip(encrypted, key))

print("Correct input (arg1):", decrypted)
```

We will then get the flag, which we wrap it with `pascalCTF{}`.

## Romañs Empyre [Cryptography]

> Author: AlBovo
>
> My friend Elia forgot how to write, can you help him recover his flag??

> **File**: [output.txt](/assets/files/pascalctf/romans_output.txt) [romans_empire.py](/assets/files/pascalctf/romans_empire.py)

We are given an output.txt with an encrypted string with a python source file. Looking at the python file, we can see that what it does is randomly rotate by a number X to encode the flag with ROT X.

```python
import os, random, string

alphabet = string.ascii_letters + string.digits + "{}_-.,/%?$!@#"
FLAG : str = os.getenv("FLAG")
assert FLAG.startswith("pascalCTF{")
assert FLAG.endswith("}")

def romanize(input_string):
    key = random.randint(1, len(alphabet) - 1)
    result = [""] * len(input_string)
    for i, c in enumerate(input_string):
        result[i] = alphabet[(alphabet.index(c) + key) % len(alphabet)]
    return "".join(result)

if __name__ == "__main__":
    result = romanize(FLAG)
    assert result != FLAG
    with open("output.txt", "w") as f:
        f.write(result)
```

Since we know that the alphabet is defined as all ascii letters + all digits + "{}_-.,/%?$!@#", we can brute force them to find the encrypted key using python.

```python
import string

alphabet = string.ascii_letters + string.digits + "{}_-.,/%?$!@#"

encrypted = "TEWGEP6a9rlPkltilGXlukWXxAAxkRGViTXihRuikkos"

def decrypt(input_string, key):
    result = [""] * len(input_string)
    for i, c in enumerate(input_string):
        if c in alphabet:
            result[i] = alphabet[(alphabet.index(c) - key) % len(alphabet)]
    return "".join(result)

for key in range(1, len(alphabet)):
    flag = decrypt(encrypted, key)
    if flag.startswith("pascalCTF{"):
        print(f"key: {key}")
        print(f"flag: {flag}")
        break
```