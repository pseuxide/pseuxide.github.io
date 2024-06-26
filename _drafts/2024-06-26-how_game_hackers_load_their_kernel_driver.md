---
title: How do game cheaters load their illegal kernel driver?
date: 2024-06-26 14:06:00 +0900
categories: [kernel, programming]
tags: [cpp, kernel]     # TAG names should always be lowercase
img_path: /assets/img/posts/how_game_cheaters_load_their_illegal_kernel_driver/
image:
  path: header.jpg
  lqip: /assets/img/posts/how_game_cheaters_load_their_illegal_kernel_driver/header.svg
  alt: header
---

## Introduction

Lately it's pretty common that the AAA game titles employ almost uncrackable anti cheat such as Easy anti cheat, Buttle eye and Vanguard.

How it became such robust? Because they utilizes kernel driver to monitor your entire computer in higher level than every other program.
However, skilled game hackers still circumvent those monitors by loading their own kernel driver to suppress anti cheat in kernel mode and manage to hack games that's why dirty cheaters are still present nowadays.

In this post I'll be briefly introduce you to a tool called [kdmapper](https://github.com/TheCruZ/kdmapper) which is used to load their unsigned kernel driver into kernel space.

## What is kernel driver?

For the sake of time and ease, I only write concise explanation here.

If you dont know what's kernel driver and want to learn it deeply, I highly recommend reading [Windows Kernel Programming](https://leanpub.com/windowskernelprogrammingsecondedition). It's very informative and let you understand many about windows kernel.

Basically kernel drivers are special programs differ from normal programs. Normal programs run in user mode and kernel driver runs in kernel space which has much more privilege. It usually wont run by itself, it works by responding request from user mode program. For your ease of understanding, you can think of it as similar to backend server in web development.

The diagram below illustrates the layers of privilege in windows. Note that `Applications` here refer to user mode software.

![windows-rings](windows-rings.webp){: w="600" .center}
_windows ring system_

Windows api offers user mode API for sending request to kernel drivers for example [DeviceIoControl](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol), [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) and [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile), and then kernel drivers can run corresponding tasks that you define.

Even if you can develop a kernel driver, you cannot load it immediately - Windows lays down strong security measures and only allows drivers that have passed Microsoft's and other vendors' review and are officially signed to be loaded.

__So u can't load your driver? No, you still can. This signing system has a significant flaw. Let me explain later.

## [+] dark magic: kdmapper

kdmapper is a user mode application to load your unsigned kernel driver onto your computer using volunerable signed kernel driver called `iqvw64e.sys` which is an old version of official driver in System32 iirc.

`iqvw64e.sys` used to be volunerable. It has strong assets in it including capability of calling kernel APIs to load a random kernel driver without **any access controls**. The volunerability is fixed already but the exploitable old version of driver is still recognized as 'signed' by Windows and that is a flaw I was talking about. The certification has expiry date of course, but to keep backward compatibility Windows decided to allow us loading expired signed driver too.

kdmapper has been opensource quite a while, so it's gonna be detected if you use it as it is. I'll explain about it later.

But now, let's see how kdmapper load your driver to kernel memory!

## [+] process of mapping

Its mapping process can be break down into those steps:

- load `iqvw64e.sys`
- remove it's trace for additional stealthiness
- load raw data of your kernel driver into user memory and calc things.
- map your driver into kernel space using `iqvw64e.sys`
- do relocations

service::RegisterAndStart

## [+] kdmapper's stealthy capabilities

## [+] kdmapper in action

## [-] It's easily detectable...unless you configure it well

## [+] conclusion