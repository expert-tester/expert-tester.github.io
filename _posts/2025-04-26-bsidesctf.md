---
title: BSidesSF CTF
date: 2025-04-26 12:00:00
categories: [Writeups, ctf-online]
tags: [Mobile, Cryptography, OSINT]
description: Some writupes for challenges in Mobile, Cryptography and OSINT
image: /assets/img/ctf/bsidesctf/bsidesctf.png
---

## dragon-name [Mobile]
> Can you find the flag on the app?
>
> Author: itsc0rg1

>**File**: [dragon-name.apk](/assets/files/bsidesctf/dragon-name.apk)

First we have to decompile the apk file, I used [decompiler.com](https://www.decompiler.com) to help me do so. After it decompiled, we can download the [zip file](https://www.decompiler.com/jar/162805de3e084f6bbbe887aeb0455bce/dragon-name.apk) and look into the `sources\com\example\dragonnames` folder. Inside the folder we will find `MainActivty.java`. Looking through `MainActivity.java`, we will find this interesting function.

```java
    public final String createFlag() {
        String part1 = rot13("PGS");
        String part2 = StringsKt.decodeToString(Base64.decode$default((Base64) Base64.Default, (CharSequence) "dzNhaw==", 0, 0, 6, (Object) null));
        String part3 = "T" + 0;
        String part4 = getResources().getString(R.string.part4);
        Intrinsics.checkNotNullExpressionValue(part4, "getString(...)");
        return part1 + "{" + part2 + part3 + part4 + ("Typ" + 3) + "}";
    }
```

Summarizing what it does, 

#### Part 1 
It first perform ROT13 on `PGS` for part 1 of the flag resulting in a `CTF` string.

#### Part 2
It then base64 decode `dzNhaw==` for the part 2 of the flag resulting in a `w3ak` string.

#### Part 3 
It simply adds `T` and `0` which results in a `T0` string.

#### Part 4 
It gets the string with resource ID `R.string.part4`, which we can find in `resources\res\values\strings.xml`. We will see the line:

```xml
<string name="part4">Fa1ry</string>
```

Lastly, we combine all parts together, adding a `Typ3` string at the end and enclosed them with `{` and `}`.

## pascals-homomorphism-1 [Cryptography]
> We've implemented the Paillier cryptosystem for your hacking pleasure. Can you break it?
>
> Author: symmetric
>
> Web Terminal: https://pascals-homomorphism-561ebdfd.term.challenges.bsidessf.net (or socat STDIO,raw,echo=0,escape=0x03 TCP:pascals-homomorphism-561ebdfd.challenges.bsidessf.net:1999)
>
> https://pascals-homomorphism-561ebdfd.term.challenges.bsidessf.net

When we access web terminal, immediately we are greeted by the menu page below. We can enter `help` to see all commands available.

```bash

                                 #
                                # #
                               #   #
                              # # # #
                             #       #
                            # #     # #
                           #   #   #   #
                          # # # # # # # #
                         #               #
                        # #             # #
                       #   #           #   #
                      # # # #         # # # #
                     #       #       #       #
                    # #     # #     # #     # #
                   #   #   #   #   #   #   #   #
                  # # # # # # # # # # # # # # # #
                 #                               #
                # #                             # #
               #   #                           #   #
              # # # #                         # # # #
             #       #        Pascal's       #       #
            # #     # #     Homomorphism    # #     # #
           #   #   #   #                   #   #   #   #
          # # # # # # # #                 # # # # # # # #
         #               #               #               #
        # #             # #             # #             # #
       #   #           #   #           #   #           #   #
      # # # #         # # # #         # # # #         # # # #
     #       #       #       #       #       #       #       #
    # #     # #     # #     # #     # #     # #     # #     # #
   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #
  # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

New weak key generated (192 bits)
n: 5962456845048703710670672612367767751590032793550530539553
g: n + 1

Try "help" for a list of commands

paillier> help

paillier help:


Commands:
    help                 // Prints this help

    help info            // Details about this tool
    help strength        // Information about weak/strong keys

    genkey <weak|strong> // Generate a weak or strong key
    showkey              // Display the current key

    getflag              // Get an encrypted flag

    encrypt              // Encrypt a message
    decrypt              // Decryption oracle (only available for strong keys)

    exit                 // Exit the digital citizen registery

paillier>
```
Going through all the command we will see this [wikipage](https://en.wikipedia.org/wiki/Paillier_cryptosystem), so we know for sure it's a paillier cryptosystem and how it works. Essentially, its a bit like RSA, except it has an interesting property of being able to perform operations on encrypted data without decrypting it first.

Another command, `help strength` shows us exactly how to solve this challenge, because the N is too small, it can be easily factored.

```bash
paillier> help strength

This tool can generate two different key sizes:

A "weak" size which offers no real security because N is too small and
can easily be factored. This size is available as a warm-up to
familiarize yourself with the Paillier system. The "decrypt" command
is not available when using weak keys.

A "strong" size which is big enough to resist casual factoring. A
truly strong key would need to be larger but that is unnecessarily
cumbersome for the purpose of this tool.

The "getflag" command will choose a flag based on the current key size
and encrypt the flag. The first flag is available when using a weak
key and the second with a strong key.
```

I asked AI to help me generate a script for decrypting Paillier. We can get the p and q from [factordb.com](https://factordb.com/index.php?query=5206928483938053916048860502112177257897523555281707511841). Once we run the script, we will be able to get the flag, and yes, this is actually just math homework :).

```python
from Cryptodome.Util.number import inverse, long_to_bytes
from math import gcd

# Given public key (n, g) and ciphertext c
n = 5206928483938053916048860502112177257897523555281707511841
g = n + 1
c = 10211411986737331328014713004174548052999474764371241480055446187097804276358772145384438095693843644785221283247462

# After factoring n into p and q
p = 71091648200999291069386978001
q = 73242478064601452886545013841

# Compute λ and μ
lambda_val = (p-1)*(q-1) // gcd(p-1, q-1)  # lcm(p-1, q-1)

# Compute L(g^λ mod n²)
def L(x):
    return (x - 1) // n

g_lambda = pow(g, lambda_val, n*n)
mu = inverse(L(g_lambda), n)

# Decrypt c
c_lambda = pow(c, lambda_val, n*n)
m = (L(c_lambda) * mu) % n

print("Decrypted message:", long_to_bytes(m).decode())
```