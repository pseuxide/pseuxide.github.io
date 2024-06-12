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

I found a very cool obfuscator called [obfus.h](https://github.com/DosX-dev/obfus.h) which published very recently and I thought this is a good time to tackle it and write an article!

The program I'll be dealing with in this article is  [DosX's Obfuscation of C (7 kb crackme)](https://crackmes.one/crackme/66295a2aa562ef06c3b52e66).
As per its description, this program is packed with UPX, but mutated by what's called [UPX patcher](https://github.com/DosX-dev/UPX-Patcher) and obfuscated with aforementioned obfuscator which, surprisingly, are made by the same author of keygenme. They're cool stuff so u should check it out!

Even if the obfuscator is an open source software, I thought it's boring to look at and take advantage of the obfuscator, so I haven't take a look at them.

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

When I look around the assembly a bit, I immediately noticed a few weird points in the code.

Firstly there're less subroutines than I expected, and instead there's just a big chunk of contiguous code. Also while subroutine invocations don't appear much yet tons of local address references was present instead. Therefore I wasn't able to view in neither graph mode nor pseudo code. That was a pain in the ass for reverser so I needed to come up with a solution.

Secondly I see bunch of jmp instruction which has `+1` at the end meaning the obfuscator is somehow making IDA misinterprete the assembly. I must've fixed this otherwise I cannot see the legetimate instruction behind the jump. (at `0x4099CC` in image above)

Thirdly quite a few conditions of conditional-jmp instruction seems won't change on execution which leads the jmp instructions pointless. However because jmp is overused the control flow has became very messy to follow. It's a known obfuscation technique called **Opaque Predicates**.

Lastly there're some subroutines that does nothing. Which offen refers to as **Junk code insertion**

At this point I thoght this is gonna be tough night lol.

## The plan

## Taking over obfuscated jmps

![jmp_manual_fix](jmp_manual_fix.png)

I thought at this point it's safe to nop out the isolated bytes to make it code too
So the image below is the final result of deobfuscated jmp looks like.

![jmp_further_manual_fix](jmp_further_manual_fix.png)


```py
import idc
import idaapi
import idautils

# checking if opcode is jmp
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

# patch bytes to nop
def patch_nop(ea):
    idc.patch_byte(ea, 0x90)

def deob_mid_jmp(start_ea, end_ea):
    fixed_targets = set()
    
    ea = start_ea

    while ea < end_ea:
        if is_jmp_insn(ea):
            target = idc.get_operand_value(ea, 0)
            if target != idc.BADADDR and is_jmp_with_plus_one(ea) and target not in fixed_targets:
                idc.del_items(target - 1, idaapi.DELIT_EXPAND)
                idaapi.auto_wait()
                if not idc.GetDisasm(target - 1).startswith("db "):
                    idc.del_items(target - 1, idaapi.DELIT_EXPAND)
                    idaapi.auto_wait()
                
                patch_nop(target - 1)

                if idc.create_insn(target - 1):
                    fixed_targets.add(target)
                else:
                    print(f"Failed to create instruction at {hex(target)}")
        ea = idc.next_head(ea, end_ea)

for seg in idautils.Segments():
    seg_name = idc.get_segm_name(seg)
    if seg_name and seg_name == ".dosx":
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        deob_mid_jmp(seg_start, seg_end)
```
{: file='jmp_deobfuscator.py'}

## reconstruct subroutines


![prologue](prologue.png)

`.dosx:00402263: The function has undefined instruction/data at the specified address.`

![garbage_bytes](garbage_bytes.png)

![subroutine_made](subroutine_made.png)

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
            while ea < end_ea and idc.GetDisasm(ea).startswith('db') and count < 5:
                count += 1
                ea += 1
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
        if (idc.print_insn_mnem(ea) == "push" and idc.print_operand(ea, 0) == "ebp" and
            idc.print_insn_mnem(idc.next_head(ea, end_ea)) == "mov" and
            idc.print_operand(idc.next_head(ea, end_ea), 0) == "ebp" and
            idc.print_operand(idc.next_head(ea, end_ea), 1) == "esp" and
            idc.print_insn_mnem(idc.next_head(idc.next_head(ea, end_ea), end_ea)) == "sub" and
            idc.print_operand(idc.next_head(idc.next_head(ea, end_ea), end_ea), 0) == "esp"):
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


![control_flow](control_flow.png)

## removing junk subroutines

![junk_subroutine](junk_subroutine.png)

![call_garbage_subroutine](call_garbage_subroutine.png)

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

![where_message_is_used](where_message_is_used.png)

![length_subroutine](length_subroutine.png)

![analyzed_main](analyzed_main.png)

![side_by_side](side_by_side.png)

![before_analyzed_main](before_analyzed_main.png)
