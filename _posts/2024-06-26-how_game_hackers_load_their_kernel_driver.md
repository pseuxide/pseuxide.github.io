---
title: How game cheaters install their illegal kernel driver?
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

kdmapper is a user mode application to load your unsigned kernel driver onto your computer using volunerable signed kernel driver called `iqvw64e.sys` which is an old version of network diagnosis driver developed by Intel.

`iqvw64e.sys` used to be volunerable. It has strong assets in it including capability of calling kernel APIs to load a random kernel driver without **any access controls**. The volunerability is fixed already but the exploitable old version of driver is still recognized as 'signed' by Windows and that is a flaw I was talking about. The certification has expiry date of course, but to keep backward compatibility Windows decided to allow us loading expired signed driver too and ended up with being exploited even these days.

I wouldn't say kdmapper is undetected cuz it has been open sourced quite a while, so it's gonna be detected if you use it as is. I'll explain about it later.

But now, let's take a close look at how kdmapper load your driver to kernel memory!

## [+] process of mapping

Its mapping process can be break down into those steps:

- load `iqvw64e.sys`
- remove it's trace for additional stealthiness
- read raw data of your kernel driver into memory
- map your driver into kernel space
- manually call your DriverEntry

#### load iqvw64e.sys
First, it loads `iqvw64e.sys` inside [service::RegisterAndStart](https://github.com/TheCruZ/kdmapper/blob/30f3282a2c0e867ab24180fccfc15cc9b819ebea/kdmapper/service.cpp#L3) function. It sets up corresponding registries first and then uses native NT api NtLoadDriver like this.

```cpp
auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
BOOLEAN SeLoadDriverWasEnabled;
NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
if (!NT_SUCCESS(Status)) {
    Log("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
    return false;
}

std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
UNICODE_STRING serviceStr;
RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

Status = NtLoadDriver(&serviceStr);
```

#### remove it's trace for additional stealthiness

After that it tries to remove some traces that anti-cheat is checking in [intel_driver::Load()](https://github.com/TheCruZ/kdmapper/blob/30f3282a2c0e867ab24180fccfc15cc9b819ebea/kdmapper/intel_driver.cpp#L32).

Each of the function does following

- `ClearPiDDBCacheTable`: clearing driver name from list of drivers in `ntoskrnl.exe`. driver name'll added when you load one.
- `ClearKernelHashBucketList`: deleting driver name and hash of driver certificate from particular list in `ci.dll`
- `ClearMmUnloadedDrivers`: deleting driver name to prevent kernel from remember and add to unloaded driver list.
- `ClearWdFilterDriverList`: unlinking driver name from a linked list in `WdFilter.sys` which holds all running drivers.

```cpp
if (!intel_driver::ClearPiDDBCacheTable(result)) {
    Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
    intel_driver::Unload(result);
    return INVALID_HANDLE_VALUE;
}

if (!intel_driver::ClearKernelHashBucketList(result)) {
    Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
    intel_driver::Unload(result);
    return INVALID_HANDLE_VALUE;
}

if (!intel_driver::ClearMmUnloadedDrivers(result)) {
    Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
    intel_driver::Unload(result);
    return INVALID_HANDLE_VALUE;
}

if (!intel_driver::ClearWdFilterDriverList(result)) {
    Log("[!] Failed to ClearWdFilterDriverList" << std::endl);
    intel_driver::Unload(result);
    return INVALID_HANDLE_VALUE;
}
```

#### read raw data of your kernel driver into memory

Then it read your binary data into memory to calculate image size and header size from its nt header.

```cpp
std::vector<uint8_t> raw_image = { 0 };
if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
    Log(L"[-] Failed to read image to memory" << std::endl);
    intel_driver::Unload(iqvw64e_device_handle);
    PauseIfParentIsExplorer();
    return -1;
}

// ...

const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

// ...

uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

// ...

DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);
```

#### map your driver into kernel space

[kdmapper::MapDriver](https://github.com/TheCruZ/kdmapper/blob/30f3282a2c0e867ab24180fccfc15cc9b819ebea/kdmapper/kdmapper.cpp#L73) function responsible of actual driver mapping.

Then it allocates kernel memory as well as physical memory based on 3 options. Each of them does allocation anyways in AllocMdlMemory, AllocIndependentPages or intel_driver::AllocatePool.

After that it fix relocations just similar to what you do when u inject your dll in manual map way.

```cpp
// Write fixed image to kernel

if (!intel_driver::WriteMemory(iqvw64e_device_handle, realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
    Log(L"[-] Failed to write local image to remote image" << std::endl);
    kernel_image_base = realBase;
    break;
}

```

#### manually call your DriverEntry

Finally it calls your custom DriverEntry like this.

```cpp
NTSTATUS status = 0;
if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
    Log(L"[-] Failed to call driver entry" << std::endl);
    kernel_image_base = realBase;
    break;
}
```

The method it utilizes to call kernel function in [intel_driver::CallKernelFunction](https://github.com/TheCruZ/kdmapper/blob/30f3282a2c0e867ab24180fccfc15cc9b819ebea/kdmapper/include/intel_driver.hpp#L154) is common in kernel exploit dev but interesting, so let's see how it does.

It first construct a shellcode.

- 0x48 and 0xb8 represents x64 constant load into rax register
- The bunch of 0x00s are filled with your DriverEntry's address in the last line.
- 0xff and 0xe0 indicates `jmp rax`

So it's basically assigning your DriverEntry address into rax, then jumping to rax.

```cpp
uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;
```

After shellcode construction, it gets NtAddAtom from kernel and replace first bytes to the shellcode like this!

```cpp
static uint64_t kernel_NtAddAtom = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "NtAddAtom");

if (!ReadMemory(device_handle, kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
    return false;

if (original_kernel_function[0] == kernel_injected_jmp[0] &&
    original_kernel_function[1] == kernel_injected_jmp[1] &&
    original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
    original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
    Log(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
    return false;
}

// Overwrite the pointer with kernel_function_address
if (!WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
    return false;
```

Now all it has to do is calling NtAddAtom from user mode. 
When syscall happens and transitions to kernel, the kernel hook that we set will be kicked automatically.

For easy read I strip out some details but this is where kdmapper calls NtAddAtom:

```cpp
const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

*out_result = Function(arguments...);
Function(arguments...);
```

## [+] kdmapper in action

I'm going to demonstrate how to map your kernel driver using kdmapper here.

Suppose you have desired kernel driver, go to project settings of kernel driver and configure the entry point.

- Configuration Properties
  - Linker
    - All Options
      - ✅ Entry Point -> DriverEntry

It initially should be GsDriverEntry. To let kdmapper call your custom driver entry point, **u need to change it to DriverEntry**.

![custom_entry_point](custom_entry_point.png)
_Entry Point setting_

Once you build it with the custom entry point setting, you can make kdmapper do its magic by drag and drop the .sys file onto kdmapper binary. (unless you want to use options)

> Driver signing enforcement not have to be disabled in this way but make sure no anti cheats or anti virus is running in your vm.
{: .prompt-warning }

![dnd_kdmapper](dnd_kdmapper.png)

There you go! your driver will be mapped in your kernel!

## [-] It's detectable

Well...unless you configure it well. 

The thing is anti cheats has 'suspicious driver list' and periodically check if known volunerable drivers have been loaded and `iqvw64e.sys` is one of them.
You have to exploit your own driver which is capable of read and write memory or some alternative APIs like MmMapIoSpace/MmUnmapIoSpace or ZwMapViewOfSection/ZwUnmapViewOfSection.

But most important thing is **your driver pretends like it's a legit driver**. For example if you use normal communication between user mode application and driver, it will be detected.
Moreover using APIs like KeStackAttachProcess or setting NMI callbacks and stuff are all minitored and easily be flagged if you ever fuck up anything.

Hence, you have to learn or reverse engineer anti cheat and know what it's monitoring.

## conclusion

![footer](footer.jpg)

I believe kdmapper is still very widely used method among game hackers. Very powerful.
However, to utilize it and detour anti cheat's check, u have to strive to make your driver look legetimate process.

Good luck:)