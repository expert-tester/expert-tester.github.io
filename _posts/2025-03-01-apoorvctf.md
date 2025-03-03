---
title: ApoorvCTF
date: 2025-03-03 12:00:00
categories: [Writeups, ctf-online]
tags: [Forensics, OSINT]
description: Some writupes for challenges in Forensics and OSINT
image: /assets/img/ctf/apoorvctf/ApoorvCTF2025.png
---

## Phantom Connection [Forensics]

> Like a fleeting dream, a connection once existed but has faded into the void. Only shadows of its presence remain. Can you bring it back to light?

File: [phantom.zip](/assets/files/apoorvctf/phantom.zip)

The zip folder we are given contains two files once we extract all of them out

![extracted-phantom.zip](/assets/img/ctf/apoorvctf/extracted-phantom.png)

Lookuping up what .bmc file is,
> BMC file is Cached bitmap file created by the Windows Remote Desktop Client (RDC), which is part of Windows Terminal Services; stores multiple bitmaps that would otherwise be repeatedly sent from the terminal server to the client.
> by: https://fileinfo.com/extension/bmc

Essentially, it's a bunch of cached bitmaps (images) files.

Digging around the Internet, I found a [github repository](https://github.com/ANSSI-FR/bmc-tools) that can parse RDP Bitmap Cache. Now we just have to download the python script and run it.
` python ./bmc-tools.py -s . -d output`
This will return all our output in a output directory

When we open the output directory, the following will be shown

![phantom.png](/assets/img/ctf/apoorvctf/phantom.png)

We can then rearrange from the bitmap files to get the flags


## I Love Japan: Identity Game [OSINT]

> Oh! My friend send me this! So Pretty isn't it ^_^ I wonder who the designer could be?
> Flag Format: apoorvctf{firstname_lastname} Note: The Flag is not a username/ nickname

> Author: Stargazer

We are also given this picture

![pretty.jpeg](/assets/files/apoorvctf/pretty.jpeg)


## Sakura beads [OSINT]

> Hey everyone, I have a friend Sakura. She wanted to learn how programming works so I gave her the best advice anyone could have given her- participate in ApoorvCTF.
> She's trying her best to find flags and could only find the welcome flag, sending /flag XD.
> If you consider yourself real OSINTers — stalk her.

> Author: cooker


## Samurai’s Code

> Unveil the lost code of the Samurai and unlock the mystery hidden within.

file: [samurai.zip](/assets//files/apoorvctf/samurai.zip)
