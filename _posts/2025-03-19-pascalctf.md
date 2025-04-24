---
title: PascalCTF 
date: 2025-03-19 23:00:00
categories: [Writeups, ctf-online]
tags: [Reverse-Engineering, Cryptography]
description: Some writupes for challenges in Reverse Engineering, Cryptography and Miscellaneous
image: /assets/img/ctf/pascalctf/pascalctf.png
---

## X-Ray [Reverse-Engineering]
> Author : AlBovo
>
> I've recently written my first license checker, maybe Steam will buy it...
>
> Flag format: pascalCTF{secret_signature}

> **File**: [x-ray](/assets/files/pascalctf/x-ray)

First we analyze the x-ray file using any reverse engineering tools, in this case we are using Radare 2. We run Radare 2 using `r2 x-ray`, then `aaa` to analyze the file, then list out all functions using `afl`. Finally we print out the disassesmbled function of checkSignature using `pdf@sym.checkSignature`. Output is shown below:

```shell
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

> **File**: [output.txt](/assets/files/pascalctf/romans_output.txt), [romans_empire.py](/assets/files/pascalctf/romans_empire.py)

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

## MindBlowing [Cryptography]

> Author: AlBovo
>
> My friend Marco recently dived into studying bitwise operators, and now he's convinced he's invented pseudorandom numbers! Could you help me figure out his secrets?

> **File**: ["mindblowing.py"](/assets/files/pascalctf/mindblowing.py)

Looing through the code, we can see that it first initializes a list of `SENTENCES`. The list contains: 
1. hardcoded message
2. random 42 bytes
3. flag (redacted)

```python
SENTENCES = [
    b"Elia recently passed away, how will we be able to live without a sysadmin?!!?",
    os.urandom(42),
    os.getenv('FLAG', 'pascalCTF{REDACTED}').encode()
]
```

Then, we see another function called `generate()` that will return a list of integers based on the `seeds` and the `idx` (index). We will explain this function in depth since this is a crucial function for solving the challenge. 

```python
def generate(seeds: list[int], idx: int) -> list[int]:
    result = []
    if idx < 0 or idx > 2:
        return result
    encoded = int.from_bytes(SENTENCES[idx], 'big')
    for bet in seeds:
        # why you're using 1s when 0s exist
        if bet.bit_count() > 40:
            continue
        result.append(encoded & bet)

    return result
```

First, the `generate()` function initializes a list, then return empty when the index is out of range (`idx < 0` or `idx > 2`).

```python
    result = []
    if idx < 0 or idx > 2:
        return result
```

Then, it will get the sentence from the `SENTENCES` list based on the index, and convert it into an integer.

```python
encoded = int.from_bytes(SENTENCES[idx], 'big')
```

After that, it will iterates through the `seeds` list, then it will count the number of 1s in the binary form of `bet`. If the number of 1s in `bet` is higher than 40, it will ignore `bet`, else it will performs a bitwise AND between `encoded` and `bet`, then append the result to `result`.

```python
    for bet in seeds:
        # why you're using 1s when 0s exist
        if bet.bit_count() > 40:
            continue
        result.append(encoded & bet)
```

Lastly, the `result` list will be returned.

```python
return result
```

Next up, we have `menu()` function that displays the menu and `handler()` function that define a timeout handler that prints "Time's up!". Then, comes the main execution part. Since we know the last sentence is the flag, when ask index of the sentence, we will enter `2`. As for the number of seeds, we will enter `1` so that we can control have more control.

```python
if __name__ == '__main__':
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(300) # set timeout of 300 seconds
    while True:
        choice = menu()

        try:
            if choice == '1':
                idx = int(input('Gimme the index of a sentence: '))
                seeds_num = int(input('Gimme the number of seeds: '))
                seeds = []
                for _ in range(seeds_num):
                    seeds.append(int(input(f'Seed of the number {_+1}: ')))
                print(f"Result: {generate(seeds, idx)}")
            elif choice == '2':
                break
            else:
                print("Wrong choice (。_。)")
        except:
            print("Boh ㄟ( ▔, ▔ )ㄏ")
```

First we must know that the resultant for AND operations (`&`) will be 1 (true) if both inputs are 1, therefore, when we perform `AnyNumber & 1111`, the resultant will be `AnyNumber`. Hence, what we need to do here is the same, supply as many 1s as we can as the seed to get back the flag. However, we need to take note that the number of 1s for the seed cannot be higher than 40. We can use `pwntools` to help us do the automation. We can use `11111111`, which is 255 in decimal to get the flag by byte. We then bitshift the `11111111` by 8 to get the next byte.

```python
from pwn import *

p = process(['python', 'mindblowing.py'])

payload = 255
flag = ''

for i in range(20):
    p.recvuntil('> ')
    p.sendline('1'.encode())
    p.recvuntil('Gimme the index of a sentence: ')
    p.sendline('2'.encode())
    p.recvuntil('Gimme the number of seeds: ')
    p.sendline('1'.encode())
    p.recvuntil('Seed of the number 1: ')   

    p.sendline(str(payload).encode())
    response = p.readline()
    byte_num = response.split('['.encode())[-1].split(']'.encode())[0]
    int_num = int(byte_num.decode('ascii'))
    ascii = int_num.to_bytes((int_num.bit_length() + 7) // 8)
    flag += ''.join(chr(b) for b in ascii.rstrip(b'\x00'))
    payload = payload << 8

print('Flag: ', flag[::-1])
p.close()
```

## My favourite number [Cryptography]

> Author: DavideGianessi
>
> Alice and Bob are playing a fun game, can you guess Alice's f
> avourite number too?

> **File**: [myfavourite.py](/assets/files/pascalctf/myfavourite.py), [output.txt](/assets/files/pascalctf/output.txt)

First, we look through the python file and see what it does. We are given a constant `e`, `p`, `q`, and `n` of both alice and bob. We can quickly conclude this is related to RSA..., which actually isn't what we should do here. Analyzing the sendToAlice() and sendToBob() function, it encode the byte strings into long integer, then encrypts it by raising the power of `pt` by `e`, then applying modulus of `n`. (pt ^ e mod n)

```python
def sendToAlice(msg):
    pt = bytes_to_long(msg.encode())
    assert pt < alice_n
    ct = pow(pt, e, alice_n)
    print(f"bob: {ct}")

def sendToBob(msg):
    pt = bytes_to_long(msg.encode())
    assert pt < bob_n
    ct = pow(pt, e, bob_n)
    print(f"alice: {ct}")
```
Then, the flag is encoded from a byte string into a long integer, which is set as alice favourite number after that. alice favourite number is asserted to make sure it is smaller than 2 ^ 50. Alice will first send the message which is then encrypted.

```python
alice_favourite_number = bytes_to_long(FLAG.encode())
assert alice_favourite_number < 2**500

sendToBob("let's play a game, you have to guess my favourite number")
```
We are given upperbound and lowerbound. Then, while the upperbound substracted by lowerbound is larger than 1, it will find out the mid point between upper and lower bound. If the flag (alice favourite number) is larger than mid point, the lowerbound will become the new mid point. If the flag is smaller than mid point, the upperbound will become the new mid point. This is actually a binary search implementation. Since we are given a lot of information on what the porgram does, therefore what we can do is reimplement the same thing to try and get the same output as the output.txt.

```python
upperbound = 2**501
lowerbound = 0
while upperbound - lowerbound > 1:
    mid = (upperbound + lowerbound) // 2
    sendToAlice(f"Is your number greater than {mid}?")
    if alice_favourite_number > mid:
        sendToBob(f"Yes!, my number is greater than {mid}")
        lowerbound = mid
    else:
        sendToBob(f"No!, my number is lower or equal to {mid}")
        upperbound = mid

sendToAlice(f"so your number is {upperbound}?")
assert upperbound == alice_favourite_number
sendToBob("yes it is!")
sendToAlice("that's a pretty cool number")
```
First we set all the constant used (`n`, `e`, `upperbound`, `lowerbound`). Then, we look for alice response to see if the response is `Is your number greater than {mid}` or `No!, my number is lower or equal to {mid}` by repeating the binary search. Finally, after the binary search is done, we will get back alice favourite number, which is the flag.

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

upperbound = 2**501
lowerbound = 0
mid = (upperbound + lowerbound) // 2

alice_n = 170764...622497
bob_n = 240139...330313
e=65537

def sendToBob(msg):
    pt = bytes_to_long(msg.encode())
    return pow(pt, e, bob_n)

with open("output.txt", "r") as f:
    response_number = 0
    for line in f:
        line = line.strip()
        if response_number < 7:
            response_number += 1
            continue
        if line[0:5] == "alice":
            response = int(line.split(": ")[-1])
            possible1 = sendToBob(f"Yes!, my number is greater than {mid}")
            possible2 = sendToBob(f"No!, my number is lower or equal to {mid}")

            if response == possible1:
                lowerbound = mid
            elif response == possible2:
                upperbound = mid
            else:
                print("Error")

            if (upperbound - lowerbound) == 1:
                continue

            mid = (upperbound + lowerbound) // 2

    print(f"Flag number = {long_to_bytes(mid)}")
```