---
title: Defeating heavily obfuscated keygen challenge
date: 2024-06-10 21:00:00 +0900
categories: [low level]
tags: [asm, reverse-engineering]     # TAG names should always be lowercase
img_path: /assets/img/posts/defeating_heavily_obfuscated_keygen_challenge/
image:
  path: header.png
  lqip: /assets/img/posts/defeating_heavily_obfuscated_keygen_challenge/header.svg
  alt: header
---

## Introduction

Wild products often have some kind of protection to protect their interectual property and it makes reverser's life harder.
And when i was solving a keygenme I stumbled upon nasty obfuscation, so this time I'll write a journal of how I, as a noob reverser, defeat the obfuscated keygenme program.

The program I'll be dealing with in this article is  [DosX's Obfuscation of C (7 kb crackme)](https://crackmes.one/crackme/66295a2aa562ef06c3b52e66).
Apparently this program is packed with mutated UPX and obfuscated with obfuscator called [obfus.h](https://github.com/DosX-dev/obfus.h) which, surprisingly, are made by the author of keygenme. They're cool stuff so u should check it out!

Even if it's open source, I thought it's boring to look at and take advantage of the obfuscator, I haven't take a look at them.

## Unpack it first

Unpacking was fearly easy for me. The patcher of UPX was well made and it prevents tools from recognizing that it's packed with UPX.
But after a quick debugging on the stub, the overall unpacking flow was not really modified...well I believe.

Also once I look at the sections the binary has there's a suspicious section called '.dosx' which has 0 raw-size but huge virtual size which means something will expand data into it at runtime. Yes, it's most likely normal UPX would do.

U can assume that the stub will write PE contents into that '.dosx' section then execute it. In that case u can change page right to read-write so that whenever the stub try to execute the memory page exception will occurr, and by that timing the main PE content would be written to the section. Only thing to do is just dump the memory area.

## Locate the obfuscation technique

When I look around the assembly a bit, I immediately noticed a few weird points in the code.

Firstly there're less function than I expected, and instead there're tons of local address references. Therefore I wasn't able to view in neither graph mode nor pseudo code. That was a pain in the ass for reverser so I needed to come up with a solution.

Secondly I see bunch of jmp instruction which has `+1` at the end meaning the obfuscation is somehow making IDA misinterprete the assembly. I must fix this otherwise I cannot see the legetimate instruction behind the jump.

Thirdly quite a few conditions of jmp-sorta instruction seems won't change on execution which leads the jmp instruction to take jump always. It's a known obfuscation technique called **Opaque Predicates**.

Lastly there're some functions that does nothing.

## jmp obfuscation