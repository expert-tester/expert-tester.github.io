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
> **File**: [phantom.zip](/assets/files/apoorvctf/phantom.zip)

The zip folder we are given contains two files once we extract all of them out.
![extracted-phantom.zip](/assets/img/ctf/apoorvctf/extracted-phantom.png)

Lookuping up what .bmc file is,
> BMC file is Cached bitmap file created by the Windows Remote Desktop Client (RDC), which is part of Windows Terminal Services; stores multiple bitmaps that would otherwise be repeatedly sent from the terminal server to the client.
> By: https://fileinfo.com/extension/bmc
Essentially, it's a bunch of cached bitmaps (images) files.

Digging around the Internet, I found a [github repository](https://github.com/ANSSI-FR/bmc-tools) that can parse RDP Bitmap Cache. Now we just have to download the python script and run it.
` python ./bmc-tools.py -s . -d output`
This will return all our output in a output directory.

When we open the output directory, the following will be shown:
![phantom.png](/assets/img/ctf/apoorvctf/phantom.png)

We observe bits of the flags scattered in different bitmap files, we can then rearrange from the bitmap files to get the flags.


## I Love Japan: Identity Game [OSINT]

> Oh! My friend send me this! So Pretty isn't it ^_^ I wonder who the designer could be?
> Flag Format: apoorvctf{firstname_lastname} Note: The Flag is not a username/ nickname

> Author: Stargazer

We are also given this picture.
![pretty.jpeg](/assets/files/apoorvctf/pretty.jpeg)

Using Google Images search, the exact image is found.
![kazShirane.png](/assets/img/ctf/apoorvctf/kazshirane.png)

However, we want his **REAL** name, not his nickname. We look up Kaz Shirane on the Internet and we found his website, with his name on it.
![masakasu-website.png](/assets/img/ctf/apoorvctf/masakasu-website.png)

The flag is Kaz's real name enclosed with apoorvctf{}.


## Sakura beads [OSINT]

> Hey everyone, I have a friend Sakura. She wanted to learn how programming works so I gave her the best advice anyone could have given her- participate in ApoorvCTF.
> She's trying her best to find flags and could only find the welcome flag, sending /flag XD.
> If you consider yourself real OSINTers — stalk her.

> Author: cooker

Searching in the Discord server, we find a user with the display name "sakura flakes" and username "kritical_bug".
![sakura-flakes.png](/assets/img/ctf/apoorvctf/sakura-flakes.png)

Viewing her profile, we can see that she has her Reddit account linked.

![sakura-profile.png](/assets/img/ctf/apoorvctf/sakura-profile.png)

Looking through her Reddit profile, we see ALOT of ranting, which is funny but one thing in particular caught my eye.

![sakura-post.png](/assets/img/ctf/apoorvctf/sakura-post.png)

She mentioned some python project about tasty sakura thing, so let's take a look at that. We quickly found a Github profile that match what we are looking for. (Recall KriticalBug as her username and tasty-sakura-things as the project she is working on)

![kritical-bug.png](/assets/img/ctf/apoorvctf/kritical-bug.png)

Then, we look through her projects along with all the commit history. We find an interesting function under `Commit 3e45879`...

![validate-flag.png](/assets/img/ctf/apoorvctf/validate-flag.png)


Going through the subsequent commit, `Commit 6fc46c4` shows a leaked API key, which is exactly what we need.

![api-key.png](/assets/img/ctf/apoorvctf/api-key.png)


We now visit http://sakura.apoorvctf.xyz:5050/?apiKey=92872d789c838a2bdc523a8de5e54749 with the API key and the flag will be returned.

![sakura-flag.png](/assets/img/ctf/apoorvctf/sakura-flag.png)


## Samurai’s Code

> Unveil the lost code of the Samurai and unlock the mystery hidden within.
> **File**: [samurai.zip](/assets//files/apoorvctf/samurai.zip)

After we extracted all the files/folders, we see a sam.jpg. We can use binwalk to see if there's any embedded files inside the jpeg.
```
└─$ binwalk sam.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, little-endian offset of first image directory: 8
```

We can then extract the TIFF file using binwalk
```
└─$ binwalk -dd=".*" sam.jpg
```

A _sam.jpg.extracted folder should be created and the extracted TIFF file will be in there. Then, we can use `strings C.tiff` (turns out you can do this from the beginning :>) and you will find a bunch of weird symbols at the very bottom of it
```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++.++++++++++++..----.+++.<------------.-----------..>---------------.++++++++++++++.---------.+++++++++++++.-----------------.<-.>++.++++++++..--------.+++++.-------.<.>--.++++++++++++.--.<+.>-------.+++.+++.-------.<.>-.<.++.+++++++++++++++++++++++++.+++++++++++++.>+++++++++++++.<+++++++++++++.----------------------------------.++++++++.>+++++++++.-------------------.<+++++++.>+.<-----.+++++++++.------------.<+++++++++++++++.>>++++++++++++++++.<+++.++++++++.>-.<--------.---------.++++++++++++++++++++.>.<++.>--------------.<<+++++.>.>-----.+++++++.<<++.>--.<++.---------.++.>>+++++++++++.-------------.----.++++++++++++++++++.<<++++++++++++++++.>>--.--.---.<<--.>>+++.-----------.-------.+++++++++++++++++.---------.+++++.-------.
```

This is brainfuck programming language (memes saves the day), we can lookup online brainfuck interpreter to decode this. I used [nayuki.io](https://www.nayuki.io/page/brainfuck-interpreter-javascript) and the output returns a Google Drive link
```
https://drive.google.com/file/d/1JWqdBJzgQhLUI-xLTwLCWwYi2Ydk4W6-/view?usp=sharing
```

We can then download the file from the Google Drive link, which we will get a file called samurai
> **File**: [samurai](/assets/files/apoorvctf/samurai) # just in case the drive link is gone

The samurai file type cannot be recognized when we use the `file` command. Therefore, we can take a closer look at the data using a hex editor. I used [Imhex](https://imhex.werwolv.net) in this case
![samurai-hex](/assets/img/ctf/apoorvctf/samurai-hex.png)

The highlighted hex shows a file signature similar to the standard JFIF file signature (`FF D8 FF E0`). We can deduce that the file itself is swapped every byte. We can then write a simple python script to swap back every byte to its correct order.
```python
def fix_reversed_bytes(input_file, output_file):
    with open(input_file, 'rb') as f:
        reversed_data = bytearray(f.read())

    for i in range(0, len(reversed_data) - 1, 2):
        reversed_data[i], reversed_data[i + 1] = reversed_data[i + 1], reversed_data[i]

    with open(output_file, 'wb') as f:
        f.write(corrected_data)

fix_reversed_bytes("samurai", "corrected")
```

Running the python script:
```
python corrected.py
```

We wll get back the original file. Opening the JFIF file we will see the flag on the image itself.
