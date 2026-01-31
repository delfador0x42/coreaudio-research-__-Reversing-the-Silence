# ROP: Return-Oriented Programming Fundamentals

```
┌─────────────────────────────────────────────────────────────────────────┐
│ AUDIENCE: Intermediate                                                  │
│ PREREQUISITES: Basic assembly understanding, stack concept              │
│ LEARNING OBJECTIVES:                                                    │
│   • Understand why ROP exists (W^X protection)                         │
│   • Learn how the CPU "blindly" follows addresses                      │
│   • Grasp the ret instruction mechanics                                │
│   • Understand gadget chaining                                          │
│   • See the "magazine letter" analogy                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

1. [Why ROP Works](#why-rop-works)
2. [Why the CPU Obeys Us: First Principles](#why-the-cpu-obeys-us-first-principles)
3. [The RET Instruction In Detail](#the-ret-instruction-in-detail)
4. [The Key Realization](#the-key-realization)
5. [Why Gadgets](#why-gadgets)
6. [The Magazine Analogy](#the-magazine-analogy)
7. [Gadget Anatomy](#gadget-anatomy)
8. [ROP Chain Execution](#rop-chain-execution)
9. [Stack Layout During ROP](#stack-layout-during-rop)
10. [Stack Pivot](#stack-pivot)
11. [Common ROP Mistakes](#common-rop-mistakes)

---

## Why ROP Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                     WHY ROP WORKS                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   THE PROBLEM:                                                      │
│   Modern systems have W^X (Write XOR Execute) protection:           │
│   - Pages are either WRITABLE or EXECUTABLE, never both            │
│   - Can't write code and then execute it                           │
│   - Traditional shellcode injection fails                          │
│                                                                     │
│   THE SOLUTION:                                                     │
│   Use code that's ALREADY executable!                               │
│   - Libraries contain billions of instruction sequences            │
│   - Find useful sequences ending in RET ("gadgets")                │
│   - Chain them together via the stack                              │
│                                                                     │
│   KEY INSIGHT:                                                      │
│   RET pops an address from stack into RIP                          │
│   If we control the stack, we control where RET jumps!             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

When you control the stack but can't inject code (due to W^X/NX/DEP), you chain together existing code snippets called "gadgets".

---

## Why the CPU Obeys Us: First Principles

*"But WHY does the CPU just follow our addresses? Doesn't it know it's being exploited?"*

**No.** The CPU is incredibly **STUPID**. It has no concept of "authorized" vs "unauthorized" instructions. It doesn't know what a "hacker" is. It's just a machine that follows a simple loop:

### The CPU's Eternal Loop

```
forever:
    1. Read instruction from memory at address in RIP
    2. Decode that instruction
    3. Execute that instruction
    4. Update RIP to point to next instruction
    5. Go to step 1
```

That's it. That's **ALL** the CPU does. Billions of times per second.
It doesn't think. It doesn't judge. It just fetches, decodes, executes.

---

## The RET Instruction In Detail

What does `ret` actually do? Let's break it down to individual steps:

```
ret = "Return from procedure"

Internally, this is equivalent to:
  1. Read 8 bytes from memory at address RSP (stack pointer)
  2. Put those 8 bytes into RIP (instruction pointer)
  3. Add 8 to RSP (move stack pointer up, "popping" the value)

In pseudo-code:
  RIP = *RSP;      // RIP now contains whatever was at the top of stack
  RSP = RSP + 8;   // Stack shrinks by 8 bytes
```

---

## The Key Realization

The CPU doesn't know **WHO** put that address on the stack. It doesn't **REMEMBER** that a `call` instruction was supposed to put that address there. It just reads the address and jumps.

**Normally:**
- `call function` pushes return address onto stack
- Function executes
- `ret` pops return address, jumps back to caller

But the CPU doesn't verify this relationship! If **ANYONE** modifies the stack, the CPU will happily jump to whatever address is there.

### Demonstration: The CPU's View

```
NORMAL EXECUTION:

Memory at 0x1000:  call printf        ; Pushes 0x1005 onto stack
Memory at 0x1005:  mov eax, 1         ; Return address (after call)

Stack: [0x1005]                       ; Return address
RSP:   0x7fff0100 (points to stack)

Inside printf:
...
Memory at 0x2090:  ret                ; Pop 0x1005 into RIP

After ret:
RIP:   0x1005                         ; Back to caller
RSP:   0x7fff0108                     ; Stack popped

─────────────────────────────────────────────────────────────────────

ROP EXECUTION (WE CONTROL THE STACK):

Stack (we wrote this):
┌──────────────────────┐
│ 0x7fff12340001       │ <-- RSP points here
├──────────────────────┤
│ 0x0000000000000041   │    (argument for pop rdi)
├──────────────────────┤
│ 0x7fff12345678       │    (next gadget address)
└──────────────────────┘

What happens at 'ret':

1. CPU reads 8 bytes at RSP (0x7fff12340001)
2. CPU puts 0x7fff12340001 into RIP
3. CPU adds 8 to RSP
4. CPU fetches instruction at 0x7fff12340001

At 0x7fff12340001: "pop rdi; ret"

5. CPU executes "pop rdi"
   - Reads 8 bytes at RSP (0x41)
   - Puts 0x41 into RDI
   - Adds 8 to RSP

6. CPU executes "ret"
   - Reads 8 bytes at RSP (0x7fff12345678)
   - Puts 0x7fff12345678 into RIP
   - We now control where execution goes AGAIN!
```

---

## Why Gadgets

We can't inject **NEW** instructions because of W^X (Write XOR Execute). Memory pages are either writable OR executable, never both.

But we can **REUSE** existing instructions! The operating system has **BILLIONS** of instructions already loaded:

- `/usr/lib/libSystem.B.dylib` (~25 MB of code)
- `/System/Library/Frameworks/CoreFoundation.framework` (~10 MB)
- Every other library in the process

Within these libraries are countless small sequences that end in `ret`:

```
pop rdi; ret           ; At address 0x7fff12340001
pop rsi; ret           ; At address 0x7fff12340050
pop rdx; ret           ; At address 0x7fff12340080
syscall; ret           ; At address 0x7fff12345678
```

These are our "gadgets" - building blocks we chain together.

---

## The Magazine Analogy

Imagine you want to send a threatening letter, but you don't want your handwriting recognized. You cut out letters from magazines and arrange them into words.

You can't **CREATE** new letters. But you can **FIND** existing letters and **ARRANGE** them into any message you want.

**ROP is the same:**
- You can't **CREATE** new instructions (W^X protection)
- You can **FIND** existing instruction sequences (gadgets)
- You can **ARRANGE** them into any computation you want

Given enough gadgets, ROP is Turing-complete. You can compute **ANYTHING** that a normal program could compute.

---

## Gadget Anatomy

A gadget is a short instruction sequence ending in RET. Examples from `libsystem_c.dylib`:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     COMMON GADGETS                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   pop rdi; ret                   ; Load RDI from stack              │
│   pop rsi; ret                   ; Load RSI from stack              │
│   pop rdx; ret                   ; Load RDX from stack              │
│   pop rax; ret                   ; Load RAX from stack              │
│   xchg rsp, rax; ret             ; STACK PIVOT!                     │
│   mov rdi, rax; ret              ; Move value between regs          │
│   syscall                        ; Invoke kernel                    │
│   add rsp, 0x30; ret             ; Skip stack bytes                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ROP Chain Execution

### Example: Calling open("/path", O_RDWR)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ROP CHAIN EXECUTION                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Stack layout (RSP points here):                                   │
│                                                                     │
│   ┌─────────────────────────┐                                      │
│   │ addr of "pop rdi; ret" │ --> Gadget 1: pop rdi; ret            │
│   ├─────────────────────────┤       RDI = (address of "/path")      │
│   │ address of "/path"     │                                        │
│   ├─────────────────────────┤                                      │
│   │ addr of "pop rsi; ret" │ --> Gadget 2: pop rsi; ret            │
│   ├─────────────────────────┤       RSI = O_RDWR (2)                │
│   │ 0x0000000000000002     │                                        │
│   ├─────────────────────────┤                                      │
│   │ addr of "pop rax; ret" │ --> Gadget 3: pop rax; ret            │
│   ├─────────────────────────┤       RAX = 2 (SYS_open)              │
│   │ 0x0000000000000002     │                                        │
│   ├─────────────────────────┤                                      │
│   │ addr of "syscall"      │ --> syscall executes open()!          │
│   ├─────────────────────────┤                                      │
│   │ ... next chain ...     │                                        │
│   └─────────────────────────┘                                      │
│                                                                     │
│   EXECUTION FLOW:                                                   │
│   1. RET pops "pop rdi; ret" address -> jumps there                │
│   2. pop rdi loads "/path" address into RDI                        │
│   3. ret pops "pop rsi; ret" address -> jumps there                │
│   4. pop rsi loads 2 into RSI                                      │
│   5. ret pops "pop rax; ret" address -> jumps there                │
│   6. pop rax loads 2 into RAX                                      │
│   7. ret pops "syscall" address -> executes syscall                │
│   8. Kernel executes open("/path", O_RDWR)!                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Stack Layout During ROP

Understanding how the stack evolves during ROP execution is crucial:

```
INITIAL STATE (after hijacking control):

RSP --> ┌────────────────────┐
        │ Gadget 1 Address   │  <-- First gadget to execute
        ├────────────────────┤
        │ Gadget 1 Argument  │  <-- Data for pop instruction
        ├────────────────────┤
        │ Gadget 2 Address   │  <-- Second gadget
        ├────────────────────┤
        │ Gadget 2 Argument  │
        ├────────────────────┤
        │ Gadget 3 Address   │
        └────────────────────┘


AFTER FIRST RET:

        ┌────────────────────┐
        │ (consumed)         │
RSP --> ├────────────────────┤
        │ Gadget 1 Argument  │  <-- pop will consume this
        ├────────────────────┤
        │ Gadget 2 Address   │
        ├────────────────────┤
        │ ...                │
        └────────────────────┘

RIP = Gadget 1 Address (e.g., "pop rdi; ret")


AFTER POP RDI:

        ┌────────────────────┐
        │ (consumed)         │
        ├────────────────────┤
        │ (consumed)         │
RSP --> ├────────────────────┤
        │ Gadget 2 Address   │  <-- Next ret will use this
        ├────────────────────┤
        │ ...                │
        └────────────────────┘

RDI = Gadget 1 Argument (our controlled value!)
```

---

## Stack Pivot

Often the controlled stack area is limited. Stack pivot moves RSP to a larger controlled buffer (like heap-sprayed data).

```
┌─────────────────────────────────────────────────────────────────────┐
│                     STACK PIVOT                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   BEFORE PIVOT:                    AFTER PIVOT:                     │
│                                                                     │
│   RSP --> ┌─────────┐             ┌─────────┐                      │
│           │ limited │             │ limited │                      │
│           │ control │             │ control │                      │
│           └─────────┘             └─────────┘                      │
│                                                                     │
│   RAX --> ┌─────────────────┐     RSP --> ┌─────────────────┐      │
│           │ LARGE heap      │             │ LARGE heap      │      │
│           │ buffer with     │             │ buffer with     │      │
│           │ ROP chain       │             │ ROP chain       │      │
│           │ (our payload!)  │             │ NOW EXECUTING!  │      │
│           └─────────────────┘             └─────────────────┘      │
│                                                                     │
│   Gadget: xchg rsp, rax; ret   (swaps RSP and RAX)                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### How xchg rsp, rax Works

The `xchg` instruction swaps two values:

```
BEFORE xchg rsp, rax:
  RSP = 0x7ffeefbff400   (points to program's stack)
  RAX = 0x7f8012340000   (points to our heap spray!)

AFTER xchg rsp, rax:
  RSP = 0x7f8012340000   (now points to our heap!)
  RAX = 0x7ffeefbff400   (old stack, we don't care)
```

That's it! One instruction and RSP now points to our controlled data!

### The Follow-up RET

After the `xchg`, the next instruction is `ret`. But now RSP points to our heap!

```
ret instruction:
  1. Read 8 bytes at RSP (now 0x7f8012340000)
  2. Our heap has: 0x7fff12340001 (first gadget address!)
  3. RIP = 0x7fff12340001
  4. CPU jumps to our first gadget!
  5. RSP += 8 (now points to second entry in our heap data)
```

We've successfully redirected execution to our ROP chain!

---

## Common ROP Mistakes

When building ROP chains, these are the most common errors that will cause your exploit to fail:

### 1. Incorrect Stack Alignment (16-byte on x86-64)

The x86-64 ABI requires 16-byte stack alignment before `call` instructions. Many library functions (especially those using SSE/AVX) will crash if the stack is misaligned.

```
PROBLEM:
  RSP = 0x7fff00000008  <-- Not 16-byte aligned (ends in 8)
  call printf          <-- CRASH! movaps instruction faults

SOLUTION:
  Add a "ret" gadget (just ret, nothing else) to adjust alignment

  Stack layout fix:
  ┌────────────────────┐
  │ addr of "ret"      │  <-- Alignment gadget (adds 8 bytes)
  ├────────────────────┤
  │ addr of "pop rdi"  │  <-- Now properly aligned
  └────────────────────┘
```

### 2. Forgetting Gadgets Clobber Registers

Many gadgets have side effects beyond their primary purpose. A `pop rdi; ret` might be part of a larger sequence that clobbers other registers.

```
PROBLEM:
  You found: pop rdi; pop rbp; ret  (at 0x12345)
  You only wanted to set RDI, but RBP gets clobbered too!

  Stack:
  ┌────────────────────┐
  │ 0x12345            │  <-- Gadget address
  ├────────────────────┤
  │ "/bin/sh"          │  <-- Goes into RDI (good!)
  ├────────────────────┤
  │ ??? OOPS           │  <-- Goes into RBP (forgot this!)
  └────────────────────┘

SOLUTION:
  Account for ALL pops in the gadget:
  ┌────────────────────┐
  │ 0x12345            │
  ├────────────────────┤
  │ "/bin/sh"          │  <-- RDI
  ├────────────────────┤
  │ 0x4141414141414141 │  <-- RBP (padding/junk)
  ├────────────────────┤
  │ next_gadget        │  <-- Continues chain
  └────────────────────┘
```

### 3. Not Accounting for "pop rbp" Side Effects

`pop rbp` is extremely common in function epilogues. If you later use a gadget that references memory via RBP (like `mov [rbp-0x8], rax`), you'll write to an uncontrolled location.

```
PROBLEM:
  Gadget 1: pop rdi; pop rbp; ret
  Gadget 2: mov [rbp-0x8], rax; ret  <-- Writes to RBP-8!

  If RBP contains garbage, this writes to random memory = CRASH

SOLUTION:
  Set RBP to a writable address you control, or avoid gadgets that
  dereference RBP. Search for cleaner gadgets without side effects.
```

### 4. Wrong Endianness in Address Packing

x86-64 is little-endian. Addresses must be packed correctly in memory.

```
PROBLEM:
  You want address 0x00007fff12345678

  WRONG (big-endian thinking):
  buffer = "\x00\x00\x7f\xff\x12\x34\x56\x78"

  RIGHT (little-endian):
  buffer = "\x78\x56\x34\x12\xff\x7f\x00\x00"

SOLUTION in C/Python:
  // C
  uint64_t addr = 0x00007fff12345678;
  memcpy(buffer, &addr, 8);  // Compiler handles endianness

  # Python
  import struct
  buffer = struct.pack("<Q", 0x00007fff12345678)  # "<Q" = little-endian uint64
```

### 5. Syscall Number Confusion (0x2000000 prefix on macOS)

macOS/Darwin syscall numbers have a class prefix. Forgetting this prefix calls the wrong syscall or causes immediate failure.

```
PROBLEM:
  Linux:  RAX = 2       for sys_open
  macOS:  RAX = 2       <-- WRONG! This is sys_fork on macOS!

SOLUTION:
  macOS syscall numbers need the BSD class prefix:

  macOS syscall = 0x2000000 | syscall_number

  Examples:
  ┌─────────────────────────────────────────────────────────────┐
  │ Syscall       │ Linux RAX  │ macOS RAX                      │
  ├───────────────┼────────────┼────────────────────────────────┤
  │ exit          │ 60         │ 0x2000001 (0x2000000 | 1)      │
  │ fork          │ 57         │ 0x2000002 (0x2000000 | 2)      │
  │ read          │ 0          │ 0x2000003 (0x2000000 | 3)      │
  │ write         │ 1          │ 0x2000004 (0x2000000 | 4)      │
  │ open          │ 2          │ 0x2000005 (0x2000000 | 5)      │
  │ close         │ 3          │ 0x2000006 (0x2000000 | 6)      │
  │ execve        │ 59         │ 0x200003B (0x2000000 | 59)     │
  └─────────────────────────────────────────────────────────────┘

  Reference: /usr/include/sys/syscall.h on macOS
```

### Quick Debugging Checklist

When your ROP chain crashes unexpectedly:

1. **Verify alignment**: Is RSP 16-byte aligned before function calls?
2. **Check all pops**: Did you account for every `pop` in each gadget?
3. **Validate addresses**: Are they packed in little-endian format?
4. **Verify syscall numbers**: On macOS, did you add 0x2000000?
5. **Test gadgets individually**: Does each gadget work in isolation?
6. **Check for bad bytes**: Do any addresses contain NULL bytes that get truncated?

---

## Navigation

| Previous | Up | Next |
|----------|----|----- |
| [03-heap-exploitation](03-heap-exploitation.md) | [Index](README.md) | [05-stack-pivot](05-stack-pivot.md) |

---

*This document is part of the CVE-2024-54529 educational case study.*
