---
title: Calling assembly from x64 C++ program
date: 2023-12-06 14:06:00 +0900
categories: [Low level]
tags: [cpp, asm]     # TAG names should always be lowercase
img_path: /assets/img/posts/calling_assembly_from_cpp/
image:
  path: header.png
  lqip: header_lqip.png
  alt: Responsive rendering of Chirpy theme on multiple devices.
---

## Introduction

Since this is the first article of my blog, I start with relatively very simple subject.

So in this post I'll be talking about how you can call functions defined in independent assembly file from C++.

## Target reader

Those who:
- can read assembly
- can read/write C++
- wonder how to utilize assembly with C++

## Background and expected environment

Why do we have to use independent asm file rather than inline assembly in the first place?
You can simply write inline assembly like this, right?

```cpp
__asm {
  push eax
  xor eax, eax
  // ... whatever
}
```

Well I initially thought of it.

However, lord MSVC compiler doesn't allow us to levarage inline assembly with x64 target architecture.
And one of its work arounds is using `.asm` file while I guess you can pull it off with shell code too yet it might get more complicated.

so the expected environment is:
- Windows 10
- MSVC compiler
- x64 target architecture

## How to do it?

I have suitable repository for this topic so I'll pick up code from there as a reference.
[pseuxide/call_cpuid_asm](https://github.com/pseuxide/call_cpuid_asm/tree/master){:target='_blank'}

### C++ side

Let's implement C++ code first to grasp the overview.

```cpp
#include <iostream>
#include <string>

extern "C" void get_cpu_type(char* sys_type);

std::string get_cpu_type_string()
{
  char sys_type[13];
  get_cpu_type(sys_type);
  sys_type[12] = '\0';
  return std::string(sys_type);
}

int main()
{
  std::string cpu_type = get_cpu_type_string();
  std::cout << "CPU TYPE: " << cpu_type << std::endl;

  std::cin.get();

  return 0;
}
```
{: file='main.cpp'}

Here's the line by line explanation.

```cpp
extern "C" void get_cpu_type(char* sys_type);
```

This is the forward declaration of `get_cpu_type` function which we'll define later in asm file.

```cpp
std::string get_cpu_type_string()
{
  char sys_type[13];
  get_cpu_type(sys_type);
  sys_type[12] = '\0';
  return std::string(sys_type);
}
```

Since the asm function expects buffer as param in our case so we create wrapper function not to mess up the main function.

The buffer size is supposed to be 12 chars + null terminator = 13.
The `get_cpu_type` function will populate the buffer with string and we manually adding null terminator at last and returning it as std::string.

Don't worry once you see the asm function and come back here, you'll get it.

I'll omit main function cuz it's self-explanatory.

### Assembly side

Let's move onto asm side. First create `get_cpu_type.asm` file.

Here I'll explain how to write simple asm in intel syntax for MSVC using this sample code.

```nasm
public get_cpu_type
.code _text
get_cpu_type proc public
    mov     rax, 0
    mov     rdi, rcx
    cpuid
    mov     dword ptr [rdi], ebx
    mov     dword ptr [rdi+4], edx
    mov     dword ptr [rdi+8], ecx
    ret
get_cpu_type endp
end
```
{: file='get_cpu_type.asm'}

I'll describe the code line by line.

```nasm
public get_cpu_type
```

This statement marks the get_cpu_type function global making other files can access this function.
> However, in terms of MASM (Microsoft Macro Assembler) which we gonna use later to compile assembly marks every functions as public by default so actually you dont need to explicitly mark them as public tbh.
{: .prompt-tip }

```nasm
.code _text
```

This line serves as a directive that specifies the beginning of a code section named _text. The part "_text" could be whatever else, even removing it entirely works as well.

```nasm
get_cpu_type proc public
; body
get_cpu_type endp
```

This is the function definition. It should start with `FUNCTION_NAME proc public` and end with `FUNCTION_NAME endp`
> This `public` statement is also optional because of the reason I mentioned prior.
{: .prompt-tip }

```nasm
mov     rax, 0
mov     rdi, rcx
cpuid
mov     dword ptr [rdi], ebx
mov     dword ptr [rdi+4], edx
mov     dword ptr [rdi+8], ecx
ret
```

This is the function body. It basically loading buffer address to `rdi`` and populating the buffer. Each `ebx`, `edx`, `ecx` registers holds byte representations of ascii character, so these 3 lines assigning them into buffer.

Importantly, you must end the function with `ret` instruction of course to get back to return address.

That's it! Simple.

### Visual Studio side

We've done both cpp and asm coding but there is one last thing to do.

By default all `.asm` files are not included in the visual studio project when it comes to user mode application i believe.

1. First right click project in solution explorer and click `Build Customizations`.
![menu](https://github.com/pseuxide/call_cpuid_asm/assets/33578715/08a6ee47-370d-43c3-b562-e2f2323ab116){: w="400" .normal}

2. Check `masm(.targets,.props)` and click `OK`.
![masm](https://github.com/pseuxide/call_cpuid_asm/assets/33578715/942480ed-bb82-4c75-a741-140923a93650){: w="700" .normal}

3. Right click your `get_cpu_type.asm` file and goto `Properties`.
![ap](https://github.com/pseuxide/call_cpuid_asm/assets/33578715/460620d3-356b-4740-8dfe-ef731257acab){: w="400" .normal}

4. Change `Item Type` to `Microsoft Macro Assembler`.
![asm_property](https://github.com/pseuxide/call_cpuid_asm/assets/33578715/d753a2cc-1072-46f4-9ff5-b8f736aacfa4){: w="700" .normal}

Now your asm file is included in compile process and good to go.

## Conclusion

![footer](footer.png)

As you saw, it's actually not that overwhelming to use asm with C++.

I believe using asm in conjunction with C++ has your code more flexible.
Moreover, it makes you feel like you're a gigachad despite of how actually you are.

Thanks for reading my article. :)