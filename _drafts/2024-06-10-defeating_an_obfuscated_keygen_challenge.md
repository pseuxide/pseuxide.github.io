---
title: Defeating an obfuscated keygen challenge
date: 2024-06-10 21:00:00 +0900
categories: [low level]
tags: [asm, reverse-engineering]     # TAG names should always be lowercase
img_path: /assets/img/posts/defeating_an_obfuscated_keygen_challenge/
image:
  path: header.png
  lqip: /assets/img/posts/defeating_an_obfuscated_keygen_challenge/header.svg
  alt: header
---

## Introduction

Wild products often have some kind of protection to protect their interectual property and it makes reverser's life harder.

I found a very cool obfuscator called [obfus.h](https://github.com/DosX-dev/obfus.h) which published 2 month ago and I thought this is a good idea to tackle it and write an article!

The program I'll be dealing with in this article is  [DosX's Obfuscation of C (7 kb crackme)](https://crackmes.one/crackme/66295a2aa562ef06c3b52e66).
As per its description, this program is packed with UPX, but mutated by what's called [UPX patcher](https://github.com/DosX-dev/UPX-Patcher) and obfuscated with aforementioned obfuscator which, surprisingly, are made by the same author of keygenme. They're cool stuff so u should check it out!

Even if the obfuscator is an open source software, I thought it's boring to look at and take advantage of the obfuscator, so I haven't taken a look at them.

## The program

The program of the challenge is a simple keygenme. A Prompt "password >>>" shows up upon run.
It print out "[-]wrong password!" when u type in random string.

## Unpack it first

Right off the bat, let's check if it's actually packed. So the image below is the string list at executable's Entrypoint. NOTHING shows up. This is enough to confirm that it's indeed completely packed.

![packed_strings](packed_strings.png)
_strings view in debugger_

Thanks to the challenges description, I already know it's packed by UPX. The patcher of UPX was well made and it prevents analyzing tools from recognizing UPX.
But after a quick debugging on the stub, the overall unpacking process was not heavily modified...well I believe.

Also once I looked at the sections, the binary has suspicious section called '.dosx' which has 0 raw-size but 118784 bytes of virtual size which indicates something will place data into it at runtime. If you have ever done UPX unpacking, you know... Yes, it's most likely what original UPX would do.
By now I was assuming `.dosx` is the section that will store payload once unpacked, and the `.fish` is the one which is storing the packed payload, you can also confirm it from the high entropy `.fish` section has which is unordinary.

![sections](sections.png)
_sections information_

Anyways the stub will write payload into `.dosx` at some point and eventually the code in the section will be kicked. In that case u can set memory right of `.dosx` section to read-write so that whenever the stub try to execute the memory page exception will occurr, and by that timing the payload would have been written to the section. Only thing to do at last is to dump using Scylla.

After I set memory right, I successfully caught an exception at payload execution.

![breakpoint_at_entrypoint](breakpoint_at_entrypoint.png){: w="600" .center}
_entry point of payload_

As you can see, all the string has been restored!

![unpacked_strings](unpacked_strings.png){: w="600" .center}
_string view after unpack_

Once I reached here dumping was as easy as snapping finger. Because Scylla automatically searches IAT and does relocation and unmapping, the resulting dump file is runnable by itself.

![dumping_scylla](dumping_scylla.png){: w="600" .center}
_dumping payload using Scylla_

## static analysis and locate obfuscation technique

I was like "It's a good timing to conduct a static analysis now", so fired up IDA and loaded the dump.
The image below is a part of the disassembly. I can say that every part of the code was similar to this which was bizzare. Let me explain why.

![first_look](first_look.png)
_what it looked like initially_

When I look around the assembly a bit, I immediately noticed a few weird points in the code.

Firstly there're less subroutines than I expected, and instead there's just a big chunk of contiguous code. Also while subroutine invocations don't appear much yet tons of local address references was present instead. Therefore I wasn't able to view in neither graph mode nor pseudocode. That was a pain in the ass for reverser so I needed to come up with a solution.

Secondly I see bunch of jmp instruction which has `+1` at the end meaning the obfuscator is somehow making IDA misinterprete the assembly. I must've fixed this otherwise I cannot see the legetimate instruction behind the jump. (at `0x4099CC` in image above)

Thirdly quite a few conditions of conditional-jmp instruction seems won't change on execution which leads the jmp instructions pointless. However because jmp is overused the control flow has became very messy to follow. It's a known obfuscation technique called **Opaque Predicates**.

Lastly there're some instructions and even subroutines that doesn't do meaningful thing. Which offen refers to as **Junk code insertion**

At this point I sensed that this is gonna be a tough night lol.

## The plan
Since I couldn't straight away converting code into subroutines, I had to go around and deal with obfuscations one by one.

The impulsory measure to take first is fixing the `+1` jmp obfuscation. otherwise me and also hex-lays decompiler wouldn't understand what it's actually doing. Usually when you can recognize the pattern of instructions around the obfuscation, IDA's powerful scripting feature IDApython comes into very handy.

Next, I see the stray bytes in middle of the code which also stopping IDA from making a subroutine. Not sure at this point but I anyway decided to nop out the bytes for now so that I can make code to subroutines. I used IDApython for this too.

In terms of junk code insertion I only removed the junk subroutine calls for cleaning purpose.

> So I ended up with not dealing with opaque predicates and junk code insertion because even if It screw up the control flow I felt like the assembly and pseudocode was readable. In my view, at the very least, the junk code included `abuse of the cpuid instruction` and `double assignment to registers before use` which, especially latter, is supposed to be time consuming to deal with.
{: .prompt-info }

## Taking over obfuscated jmps

Because I haven't seen this, I couldn't tell whether the jmp is broken or the instruction the jmp tries to jump to is broken. In my opinion It's okey to mess around and investigate to verify what seems correct cuz every action can be Ctrl+z.

After a bit of research, the latter idea of my assumptions seems to be correct. Take a look at the image below. The jz is jumping to `near ptr loc_4099D2+1`. Therefore, undefining `0x4099D2` and make code back again from `0x4099D3` makes very much sense!

![jmp_manual_fix](jmp_manual_fix.png)
_LEFT: obfuscated, RIGHT: deobfuscated_

At this point I thought it's kinda safe to nop out the isolated bytes at `0x4099D2` and convert it to code too. I assumed that it's unlikely to be referenced from other subroutines unless it's dynamically resolved cuz the byte doesnt have xref annotation. I was like 'I can come back fix it later if I was wrong anyway' lol.

So the image below is the final result of deobfuscated jmp looks like. It's absolutely clean isn't it.

![jmp_further_manual_fix](jmp_further_manual_fix.png)
_final result_

I cant afford time of fixing tons of jmps manually, I decided to leverage the power of IDAPython to automatically detect and patch them all.

Here's the code. I dont go into too deep about code so instead I put good amount of comments.

```py
import idc
import idaapi
import idautils

# checking if mnemonic at ea is jmp or conditional jmp
def is_jmp_insn(ea):
    insn = idaapi.insn_t()
    if not idaapi.decode_insn(insn, ea):
        return False
    return insn.itype in [
        idaapi.NN_ja, idaapi.NN_jae, idaapi.NN_jb, idaapi.NN_jbe, idaapi.NN_jc,
        idaapi.NN_je, idaapi.NN_jg, idaapi.NN_jge, idaapi.NN_jl, idaapi.NN_jle,
        idaapi.NN_jna, idaapi.NN_jnae, idaapi.NN_jnb, idaapi.NN_jnbe, idaapi.NN_jnc,
        idaapi.NN_jne, idaapi.NN_jng, idaapi.NN_jnge, idaapi.NN_jnl, idaapi.NN_jnle,
        idaapi.NN_jno, idaapi.NN_jnp, idaapi.NN_jns, idaapi.NN_jnz, idaapi.NN_jo,
        idaapi.NN_jp, idaapi.NN_jpe, idaapi.NN_jpo, idaapi.NN_js, idaapi.NN_jz,
        idaapi.NN_jmp
    ]

# jmp instruction has +1 at the end
def is_jmp_with_plus_one(ea):
    disasm = idc.GetDisasm(ea)
    return "+1" in disasm

# patch bytes to nop (byte representation is 0x90)
def patch_nop(ea):
    idc.patch_byte(ea, 0x90)

# main deobfuscate function.
def deob_mid_jmp(start_ea, end_ea):
    # holds address already fixed to avoid double run at same address
    fixed_targets = set()

    ea = start_ea

    while ea < end_ea:
        if is_jmp_insn(ea):
            # getting jump destination's address
            target = idc.get_operand_value(ea, 0)
            # destination is not invalid address? jump has +1?  destination hasn't been fixed yet?
            if target != idc.BADADDR and is_jmp_with_plus_one(ea) and target not in fixed_targets:
                # undefine the destination-1 with DELIT_EXPAND flag. -1 cancels out +1
                idc.del_items(target - 1, idaapi.DELIT_EXPAND)
                # you need this to refresh internal ida database info
                idaapi.auto_wait()
                # sometimes undefining doesnt done correctly so do it again
                if not idc.GetDisasm(target - 1).startswith("db "):
                    idc.del_items(target - 1, idaapi.DELIT_EXPAND)
                    idaapi.auto_wait()

                # patching isolated byte
                patch_nop(target - 1)

                # converting undefined bytes into code
                if idc.create_insn(target - 1):
                    fixed_targets.add(target)
                else:
                    print(f"Failed to create instruction at {hex(target)}")
        ea = idc.next_head(ea, end_ea)

# .dosx sections are scattered around so u have to iterate over all segments and apply to all .dosx
for seg in idautils.Segments():
    seg_name = idc.get_segm_name(seg)
    if seg_name and seg_name == ".dosx":
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        deob_mid_jmp(seg_start, seg_end)
```
{: file='jmp_deobfuscator.py'}

After running this script all the jmps are correctly fixed and cleaned up. Now let's deobfuscate even further!

## Reconstruct grieved subroutines

So when I look around the assembly I've found a lot of place which looks like an assembly prologue. But somehow IDA didn't get to mark it as a subroutine.
![prologue](prologue.png)
_the stack setup looks promising to me_

One message showed up when I pressed `p` on prologue.

`.dosx:00402263: The function has undefined instruction/data at the specified address.`

That's right, the stray bytes are in the middle of the instruction I'm sure this is also to annoy reversers.

![garbage_bytes](garbage_bytes.png)
_isolated bytes are inserted like this_

After nopping out every stray byts in the subroutine-looking code and then I successfully made a subroutine. The thing is... it's ridiculously ginormous lol. I realized how the control flow obfuscation is disgusting.

![control_flow](control_flow.png)
_I was like what the hell??_

Anyway I automated this process too using IDApython. Here's the code.

> I had to make sure I won't mess up the big chunk of bytes in `.dosx` section which is stored and referenced from other code. so I meticulously pick up the bytes up to 4 in middle of the code. 4 is just a cap I set based on its pattern.
{: .prompt-tip }

```py
import idc
import idautils

def patch_nop(ea):
    idc.patch_byte(ea, 0x90)

def find_and_nop_dbs(start_ea, end_ea):
    db_start_ea = 0 # hold start address of db sequence
    ea = start_ea
    while ea < end_ea:
        if idc.GetDisasm(ea).startswith('db'):
            db_start_ea = ea
            count = 0
            db_start = ea
            # loop until it goes out of db group or count reaches 5
            while ea < end_ea and idc.GetDisasm(ea).startswith('db') and count < 5:
                count += 1
                ea += 1
            # count is lte 4?  db group is surrounded by non-db and non-dd instructions?
            if count <= 4 and not idc.GetDisasm(db_start_ea - 1).startswith('db') and not idc.GetDisasm(db_start_ea - 1).startswith('dd') and not idc.GetDisasm(ea + 1).startswith('dd'): # making sure it's not a part of a string or stored data that will be used
                for addr in range(db_start, ea):
                    patch_nop(addr)
            else:
                ea = db_start + 1
        else:
            ea += 1

def convert_to_subroutine(start_ea, end_ea):
    find_and_nop_dbs(start_ea, end_ea)
    ea = start_ea
    while ea < end_ea:
        # looking for prologue
        if (idc.print_insn_mnem(ea) == "push" and idc.print_operand(ea, 0) == "ebp" and
            idc.print_insn_mnem(idc.next_head(ea, end_ea)) == "mov" and
            idc.print_operand(idc.next_head(ea, end_ea), 0) == "ebp" and
            idc.print_operand(idc.next_head(ea, end_ea), 1) == "esp" and
            idc.print_insn_mnem(idc.next_head(idc.next_head(ea, end_ea), end_ea)) == "sub" and
            idc.print_operand(idc.next_head(idc.next_head(ea, end_ea), end_ea), 0) == "esp"):
            # convert to subroutine at the head of prologue
            idc.add_func(ea)
            ea = idc.next_head(idc.next_head(idc.next_head(ea, end_ea), end_ea), end_ea)
        else:
            ea = idc.next_head(ea, end_ea)

for seg in idautils.Segments():
    seg_name = idc.get_segm_name(seg)
    if seg_name and seg_name == ".dosx":
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        convert_to_subroutine(seg_start, seg_end)
```
{: file='convert_subroutine.py'}



## removing junk subroutines

Lastly since I spotted some pointless subroutines such as the image below, I wrote its removal code.
Funny enough, not only its contents are only nops, this particular subroutine doesn't even setting up the stack lol.

![junk_subroutine](junk_subroutine.png)
_junk subroutine that does nothing_

It was fairly easy to find a commodity of the invocation code.

1. Pushing a value onto the stack (0x0040910F)
2. Calling subroutine (0x00409110)
3. Smashing the stack (0x00409115)

![call_garbage_subroutine](call_garbage_subroutine.png)
_how an invocation of garbage subroutine looks like_

Because the calling conventions of the subroutines are `__cdecl`, the stack cleanup is caller's responsibility. It's piece of cake to nullify the subroutine when u dont have to care about stack corruption XD.

Just nop out the all bytes calling the subroutine!


> I was too lazy to make it the best code. I hardcoded the function's effective address and simply searching them up.
{: .prompt-tip }

```py
import idc
import idautils

# Your IDA base has to be rebased to 0x00400000
junk_function_list = [0x0040905F, 0x00401044, 0x0040906C]

def check_call_to_junk_function(ea):
    if idc.print_insn_mnem(ea) == "call":
        call_target = idc.get_operand_value(ea, 0)
        return call_target in junk_function_list
    return False

def patch_nop(ea, length):
    for i in range(length):
        idc.patch_byte(ea + i, 0x90)

def remove_junk_subroutine_call(start_ea, end_ea):
    ea = start_ea
    while ea < end_ea:
        if check_call_to_junk_function(ea):
            patch_nop(ea, 5)
        ea = idc.next_head(ea, end_ea)

for seg in idautils.Segments():
    seg_name = idc.get_segm_name(seg)
    if seg_name and seg_name == ".dosx":
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        remove_junk_subroutine_call(seg_start, seg_end)
```
{: file='remove_junk_subroutine_call.py'}

## Take a look at keygen

Now least deobfuscation has been done. I can see graph view and pseudocode of main components now so it's a great timing to have a look at actual keygen logic.

Of course I reached for strings first. Recognizing where it's used helps me so much on where to reverse engineer.

![where_message_is_used](where_message_is_used.png)

![length_subroutine](length_subroutine.png)

![analyzed_main](analyzed_main.png)

![side_by_side](side_by_side.png)

![before_analyzed_main](before_analyzed_main.png)
