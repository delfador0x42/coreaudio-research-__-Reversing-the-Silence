# XNU Kernel Architecture Deep Dive

```
┌─────────────────────────────────────────────────────────────────────────┐
│ AUDIENCE: Intermediate                                                  │
│ PREREQUISITES: Basic OS concepts, understanding of processes/threads    │
│ LEARNING OBJECTIVES:                                                    │
│   • Understand XNU's hybrid kernel architecture                         │
│   • Learn Mach IPC fundamentals (ports, rights, messages)              │
│   • Understand zone allocators and memory management                    │
│   • Grasp how tasks/threads relate to processes                         │
│   • See how CVE-2024-54529 uses these mechanisms                       │
└─────────────────────────────────────────────────────────────────────────┘
```

Written from the perspective of a senior Apple XNU kernel engineer.

> "To truly understand a userspace exploit, you must first understand the
> kernel that makes it possible. Every Mach message, every memory allocation,
> every context switch flows through XNU. The exploit doesn't fight the
> kernel—it dances with it."

This section provides the architectural foundation you need to understand
why CVE-2024-54529 works. We'll trace the path from a sandboxed Safari
process sending a Mach message, through the kernel, to coreaudiod—and
understand every structure the kernel touches along the way.

---

## System Configuration

Captured during documentation:

```bash
$ sysctl kern.version
kern.version: Darwin Kernel Version 25.2.0:
              root:xnu-12377.61.12~1/RELEASE_ARM64_T6031

$ sw_vers
ProductName:    macOS
ProductVersion: 26.2
BuildVersion:   25C56

$ uname -a
Darwin [...] 25.2.0 Darwin Kernel Version 25.2.0 arm64
```

XNU source references are from:
https://github.com/apple-oss-distributions/xnu
(Specific version: xnu-12377.61.12 corresponds to macOS 26.2)

---

## 1.1 The XNU Kernel: A Hybrid Architecture

XNU is not a monolithic kernel like Linux, nor a pure microkernel like
Mach 3.0. It's a **HYBRID**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        XNU KERNEL ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐│
│   │   MACH LAYER    │  │   BSD LAYER     │  │     I/O KIT LAYER      ││
│   │                 │  │                 │  │                         ││
│   │ - IPC (ports)   │  │ - POSIX APIs    │  │ - Driver framework      ││
│   │ - Tasks/Threads │  │ - VFS           │  │ - Power management      ││
│   │ - Scheduling    │  │ - Networking    │  │ - Device matching       ││
│   │ - VM (pmap)     │  │ - Syscalls      │  │ - User clients          ││
│   │ - Zones/kalloc  │  │ - Signals       │  │ - Registry              ││
│   └────────┬────────┘  └────────┬────────┘  └────────────┬────────────┘│
│            │                    │                         │             │
│   ─────────┴────────────────────┴─────────────────────────┴───────────  │
│                                 │                                       │
│                         PLATFORM EXPERT                                 │
│                                 │                                       │
│   ─────────────────────────────────────────────────────────────────────  │
│                                 │                                       │
│                        HARDWARE (ARM64/x86)                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why This Matters for CVE-2024-54529

The exploit uses MACH IPC to communicate with coreaudiod. Understanding
Mach means understanding:
- How messages are sent/received (`mach_msg_trap`)
- How ports are represented in the kernel (`ipc_port`)
- How the kernel validates message buffers
- How audit tokens identify the sender

### XNU Source Reference

| Directory | Contents |
|-----------|----------|
| `osfmk/mach/` | Mach interfaces and headers |
| `osfmk/kern/` | Core kernel (tasks, threads, scheduling) |
| `osfmk/ipc/` | IPC implementation (THIS IS CRITICAL FOR US) |
| `bsd/` | BSD layer (POSIX, networking, VFS) |
| `iokit/` | I/O Kit driver framework |

---

## 1.2 Mach IPC: The Foundation of macOS Communication

Mach IPC is the **ONLY** way for userspace processes to communicate with
system services on macOS. Every XPC call, every MIG message, every
launchd interaction—all built on Mach ports and messages.

### First Principles: What Is a Port?

A Mach port is a **KERNEL-PROTECTED message queue**. Think of it as:
- A one-way mailbox
- Protected by the kernel (you can't forge access)
- Identified by a 32-bit name in your task's port namespace

The kernel maintains the REAL port data. Userspace only sees names.

```
┌──────────────────────────────────────────────────────────────────────┐
│                    TASK A (e.g., Safari)                             │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  PORT NAME SPACE                                               │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐                          │ │
│  │  │ name=0x3│ │name=0x7 │ │name=0x13│                          │ │
│  │  │ (send)  │ │ (recv)  │ │ (send)  │                          │ │
│  │  └────┬────┘ └────┬────┘ └────┬────┘                          │ │
│  │       │           │           │                                │ │
│  └───────┼───────────┼───────────┼────────────────────────────────┘ │
└──────────┼───────────┼───────────┼──────────────────────────────────┘
           │           │           │
═══════════╪═══════════╪═══════════╪═══════ KERNEL BOUNDARY ══════════
           │           │           │
           ▼           ▼           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         XNU KERNEL                                   │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                     │
│  │ ipc_port   │  │ ipc_port   │  │ ipc_port   │                     │
│  │ (coreaudio)│  │ (Safari's) │  │ (launchd)  │                     │
│  │            │  │            │  │            │                     │
│  │ kobject:   │  │ kobject:   │  │ kobject:   │                     │
│  │ ->audiohald│  │ NULL       │  │ ->launchd  │                     │
│  │            │  │            │  │ task       │                     │
│  └────────────┘  └────────────┘  └────────────┘                     │
└──────────────────────────────────────────────────────────────────────┘
```

### The ipc_port Structure

Simplified from `osfmk/ipc/ipc_port.h`:

```c
struct ipc_port {
    struct ipc_object   ip_object;      // Reference count, lock
    struct ipc_mqueue   ip_messages;    // Message queue
    ipc_port_t          ip_nsrequest;   // No-senders notification
    ipc_port_t          ip_pdrequest;   // Port-death notification
    union {
        ipc_kobject_t   kobject;        // Kernel object (for services)
        task_t          receiver;       // Receiving task
    } data;
    natural_t           ip_mscount;     // Make-send count
    natural_t           ip_srights;     // Send rights count
    // ... more fields
};
```

### CVE-2024-54529 Relevance

When Safari sends a message to `com.apple.audio.audiohald`, the kernel:
1. Looks up Safari's send right (a name like 0x1303)
2. Finds the corresponding `ipc_port` in Safari's IPC space
3. Queues the message on coreaudiod's port
4. Attaches Safari's **AUDIT TOKEN** (identity proof)

---

## 1.2.1 Port Rights: The Capability Model

Mach uses a **CAPABILITY** model. You can only interact with a port if you
have a **RIGHT** to it. Rights are:

| Right | Description |
|-------|-------------|
| `MACH_PORT_RIGHT_SEND` | Allows sending messages to the port. Can be copied/transferred to other tasks. Multiple senders can hold send rights to same port. |
| `MACH_PORT_RIGHT_RECEIVE` | Allows receiving messages from the port. **ONLY ONE** task can hold receive right. Whoever has receive right "owns" the port. |
| `MACH_PORT_RIGHT_SEND_ONCE` | Can send exactly one message, then right is consumed. Used for reply ports. |

### Practical Example: Service Lookup Flow

When Safari connects to `com.apple.audio.audiohald`:

1. Safari asks bootstrap (launchd) for a send right
2. launchd looks up the registered service
3. launchd sends Safari a send right (via port transfer)
4. Safari now has a port name that leads to coreaudiod

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SERVICE LOOKUP FLOW                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Safari                    launchd                    coreaudiod       │
│      │                         │                            │           │
│      │ bootstrap_look_up()    │                            │           │
│      │ "com.apple.audio       │                            │           │
│      │  .audiohald"           │                            │           │
│      │ ──────────────────────>│                            │           │
│      │                        │                            │           │
│      │                        │ (launchd has send right    │           │
│      │                        │  to coreaudiod's port)     │           │
│      │                        │                            │           │
│      │     send right         │                            │           │
│      │ <──────────────────────│                            │           │
│      │                        │                            │           │
│      │                             ┌───────────────────────│           │
│      │                             │ coreaudiod holds      │           │
│      │                             │ RECEIVE right         │           │
│      │                             └───────────────────────│           │
│      │                                                     │           │
│      │ mach_msg(send to port 0x1303)                       │           │
│      │ ─────────────────────────────────────────────────────>          │
│      │                                                     │           │
│      │                                                     │ Message   │
│      │                                                     │ received! │
│                                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### launchctl Output Example

```bash
$ launchctl print system/com.apple.audio.coreaudiod

system/com.apple.audio.coreaudiod = {
    active count = 4
    path = /System/Library/LaunchDaemons/com.apple.audio.coreaudiod.plist
    type = LaunchDaemon
    state = running
    program = /usr/sbin/coreaudiod
    domain = system
    username = _coreaudiod
    group = _coreaudiod
    pid = 188
    endpoints = {
        "com.apple.audio.driver-registrar" = {
            port = 0x1d913
            active = 1
            managed = 1
        }
        "com.apple.audio.coreaudiod" = {
            port = 0x2d603
            active = 1
        }
        "com.apple.audio.audiohald" = {
            port = 0x42503     <-- THIS is the port Safari connects to
            active = 1
        }
    }
}
```

### XNU Source Reference

| File | Contents |
|------|----------|
| `osfmk/ipc/ipc_right.c` | Right management |
| `osfmk/kern/ipc_kobject.c` | Kernel object association |
| `osfmk/mach/port.h` | Port right definitions |

---

## 1.2.2 Mach Messages: The Wire Format

When you call `mach_msg()`, you pass a buffer containing a `mach_msg_header_t`
followed by optional descriptors and data. Let's trace what happens:

### The Message Structure

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     MACH MESSAGE LAYOUT                                 │
├─────────┬────────────────────┬─────────┬───────────────────────────────┤
│ Offset  │ Field              │ Size    │ Description                   │
├─────────┼────────────────────┼─────────┼───────────────────────────────┤
│ 0x00    │ msgh_bits          │ 4 bytes │ Rights + complex bit          │
│ 0x04    │ msgh_size          │ 4 bytes │ Total message size            │
│ 0x08    │ msgh_remote_port   │ 4 bytes │ Destination port name         │
│ 0x0C    │ msgh_local_port    │ 4 bytes │ Reply port name               │
│ 0x10    │ msgh_voucher_port  │ 4 bytes │ Voucher port (QoS)            │
│ 0x14    │ msgh_id            │ 4 bytes │ Message ID (MIG routine)      │
├─────────┼────────────────────┼─────────┼───────────────────────────────┤
│ 0x18    │ Body               │ varies  │ Inline data or descriptors    │
├─────────┼────────────────────┼─────────┼───────────────────────────────┤
│ end     │ Trailer (on recv)  │ varies  │ Added by kernel               │
└─────────┴────────────────────┴─────────┴───────────────────────────────┘
```

### Complex Messages

If `MACH_MSGH_BITS_COMPLEX` is set, the body contains **DESCRIPTORS** that
describe out-of-line memory, port rights, or other special data:

```c
typedef struct {
    mach_msg_descriptor_type_t type;  // OOL_DESCRIPTOR, PORT_DESCRIPTOR, etc.
    // ... type-specific fields
} mach_msg_descriptor_t;
```

### The mach_msg_trap Flow

When Safari calls `mach_msg()` with `MACH_SEND_MSG`:

1. **SYSCALL ENTRY** (`osfmk/mach/mach_msg.c`):
   - User thread traps into kernel
   - Kernel validates message header
   - Copyin message from user to kernel buffer (`ipc_kmsg`)

2. **MESSAGE CREATION** (`osfmk/ipc/ipc_kmsg.c`):
   - `ipc_kmsg_alloc()` allocates kernel message buffer
   - `copyin_mach_msg()` copies user data
   - If complex: process descriptors, copyin OOL memory

3. **PORT RESOLUTION** (`osfmk/ipc/ipc_object.c`):
   - Convert user's port name to kernel's `ipc_port*`
   - Verify send right exists and is valid
   - Lock destination port

4. **MESSAGE QUEUEING** (`osfmk/ipc/ipc_mqueue.c`):
   - Attach **AUDIT TOKEN** to message (sender identity!)
   - Add message to destination's `ipc_mqueue`
   - Wake receiving thread if blocked

5. **RECEIVE SIDE**:
   - Receiver calls `mach_msg()` with `MACH_RCV_MSG`
   - Message dequeued from `ipc_mqueue`
   - Copyout to user buffer
   - Audit token available via `MACH_RCV_TRAILER_AUDIT`

### Audit Token - How the Kernel Identifies You

```c
typedef struct {
    uid_t               au_id;       // Audit user ID
    uid_t               au_euid;     // Effective UID
    gid_t               au_egid;     // Effective GID
    uid_t               au_ruid;     // Real UID
    gid_t               au_rgid;     // Real GID
    pid_t               au_pid;      // Process ID
    au_asid_t           au_asid;     // Audit session ID
    struct au_tid_addr  au_tid;      // Terminal ID
} audit_token_t;
```

### CVE-2024-54529 Relevance

coreaudiod uses audit tokens to check if the caller is sandboxed.
**BUT**: the vulnerable handlers don't check if the `object_id` belongs
to the caller! They trust the `object_id` blindly.

### XNU Source Reference

| File | Contents |
|------|----------|
| `osfmk/mach/message.h` | Message structures |
| `osfmk/ipc/ipc_kmsg.c` | Kernel message handling |
| `osfmk/kern/ipc_tt.c` | Thread/Task IPC |
| `bsd/kern/kern_credential.c` | Audit token creation |

---

## 1.3 Zone Allocators: Where Kernel Objects Live

XNU uses **ZONE ALLOCATORS** for fixed-size kernel objects. This is critical
for exploitation because:

- Objects of similar size share memory regions
- Freed objects become **HOLES** that can be reclaimed
- Predictable allocation patterns enable heap spray

### Zone Architecture

```bash
$ zprint (captured output):

zone name            elem    cur      cur      cur   alloc  alloc
                     size   size    #elts    inuse   size  count
-----------------------------------------------------------------------
ipc.ports            144     0K     63706    63706    0K      0
ipc.kmsgs            256     0K      2798     2798    0K      0
ipc.vouchers          56     0K       395      395    0K      0
proc_task           3640     0K      1003     1003    0K      0
threads             2080     0K      3619     3619    0K      0
VM.map.entries        80     0K    468866   468866    0K      0
data.kalloc.128      128     0K     10101    10101    0K      0
data.kalloc.256      256     0K        12       12    0K      0
data.kalloc.1024    1024     0K        12       12    0K      0
```

### Key Zones for Exploitation

| Zone | Size | Purpose |
|------|------|---------|
| `ipc.ports` | 144 bytes | Every Mach port is allocated here. Critical for port UAF exploits (not this CVE). |
| `ipc.kmsgs` | 256 bytes | Kernel message buffers for small messages. Larger messages use kalloc. |
| `data.kalloc.*` | various | General-purpose allocations. Grouped by size class (16, 32, 48, 64, 96, 128, ...) |

### Zone vs Kalloc

- **ZONES**: Fixed-size slabs (e.g., `ipc.ports` always 144 bytes)
- **KALLOC**: Variable-size with size classes

For CVE-2024-54529, coreaudiod runs in **USERSPACE** with its own
malloc zones (not kernel zones). The heap spray targets
libmalloc's `malloc_small` zone with 1152-byte allocations.

### Why Zone Knowledge Matters

Even though this is a userspace exploit, understanding zones helps because:
1. libmalloc is inspired by kernel zone design
2. Size class bucketing applies to both
3. Kernel exploits often chain with userspace bugs

### XNU Source Reference

| File | Contents |
|------|----------|
| `osfmk/kern/zalloc.c` | Zone allocator implementation |
| `osfmk/kern/kalloc.c` | kalloc implementation |
| `osfmk/mach/zone_info.h` | Zone introspection (zprint) |

---

## 1.4 Tasks and Threads: The Execution Model

Every process on macOS is a Mach **TASK** containing one or more **THREADS**.

### task_t Structure

Simplified from `osfmk/kern/task.h`:

```c
struct task {
    lck_mtx_t       lock;           // Task lock
    vm_map_t        map;            // Virtual memory map
    struct ipc_space *itk_space;    // Port namespace
    queue_head_t    threads;        // Thread list
    uint64_t        uniqueid;       // Unique task ID
    struct bsd_info *bsd_info;      // BSD process (proc_t)
    audit_token_t   audit_token;    // Identity token
    // ... many more fields
};
```

### The Relationship: Task to Process

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      TASK ↔ PROCESS RELATIONSHIP                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                      task_t (Mach)                              │  │
│   │                                                                 │  │
│   │   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐    │  │
│   │   │   thread_t    │   │   thread_t    │   │   thread_t    │    │  │
│   │   │   (main)      │   │   (worker)    │   │   (audio)     │    │  │
│   │   └───────────────┘   └───────────────┘   └───────────────┘    │  │
│   │                                                                 │  │
│   │   ┌─────────────────────────────────────────────────────────┐  │  │
│   │   │                 ipc_space_t                             │  │  │
│   │   │   Port namespace: 0x103 → port_A, 0x207 → port_B, ...   │  │  │
│   │   └─────────────────────────────────────────────────────────┘  │  │
│   │                                                                 │  │
│   │   ┌─────────────────────────────────────────────────────────┐  │  │
│   │   │                    vm_map_t                             │  │  │
│   │   │   Virtual memory: text, heap, stack, libraries          │  │  │
│   │   └─────────────────────────────────────────────────────────┘  │  │
│   │                           │                                    │  │
│   └───────────────────────────┼────────────────────────────────────┘  │
│                               │                                       │
│                               ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │                      proc_t (BSD)                               │ │
│   │                                                                 │ │
│   │   PID, credentials, file descriptors, signal handlers           │ │
│   │   sandbox profile, entitlements, code signature                 │ │
│   │                                                                 │ │
│   └─────────────────────────────────────────────────────────────────┘ │
│                                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### CVE-2024-54529 Process Context

**Attacker (Safari):**
- `task_t` with sandboxed `proc_t`
- Limited IPC rights (but `com.apple.audio.audiohald` allowed)
- `audit_token` identifies as sandboxed Safari

**Victim (coreaudiod):**
- `task_t` with privileged `proc_t`
- Runs as `_coreaudiod` user (UID 202)
- **NO sandbox** (full filesystem, network access)
- Holds receive rights to audio service ports

### XNU Source Reference

| File | Contents |
|------|----------|
| `osfmk/kern/task.h` | `task_t` definition |
| `osfmk/kern/thread.h` | `thread_t` definition |
| `bsd/sys/proc_internal.h` | `proc_t` definition |

---

## 1.5 Userspace to Kernel Boundary: The Trust Divide

Data crosses the user/kernel boundary constantly. The kernel must:

1. **VALIDATE** all pointers from userspace
2. **COPYIN** data before using it
3. **COPYOUT** results to user memory
4. **NEVER** trust user-supplied addresses

### Key Functions

```c
copyin(user_addr, kernel_buf, size);
// Copies data FROM userspace TO kernel
// Validates that user_addr is in valid user range
// Faults in pages if necessary

copyout(kernel_buf, user_addr, size);
// Copies data FROM kernel TO userspace
// Validates destination is writable user memory

copyinstr(user_addr, kernel_buf, max_len, &actual_len);
// Copies null-terminated string from userspace
// Respects max_len to prevent overflow
```

### Out-of-Line Descriptors (OOL)

For large data, Mach messages can include OOL memory. The kernel:
1. Maps the sender's pages into a temporary kernel space
2. On receive, maps them into receiver's address space
3. This COPIES or MOVES the memory (`vm_map_copyin`/`copyout`)

### Why This Matters

The CVE-2024-54529 exploit sends Mach messages with inline data
(the plist for heap spray) and complex descriptors (ports).
The kernel faithfully copies this data—it can't know the content
is malicious. The vulnerability is in coreaudiod's **HANDLING** of
the data, not in the kernel's transport of it.

### XNU Source Reference

| File | Contents |
|------|----------|
| `osfmk/kern/copyio.c` | copyin/copyout implementation |
| `osfmk/vm/vm_map.c` | Virtual memory mapping |
| `osfmk/ipc/ipc_kmsg.c` | OOL descriptor handling |

---

## 1.6 MIG: The Mach Interface Generator

MIG (Mach Interface Generator) is a stub generator that creates
client/server code for Mach RPC. It's how coreaudiod exposes its API.

### The MIG Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MIG COMPILATION FLOW                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   audio.defs                    (MIG definition file)                   │
│        │                                                                │
│        ▼                                                                │
│   ┌─────────┐                                                           │
│   │   mig   │  (MIG compiler)                                           │
│   └────┬────┘                                                           │
│        │                                                                │
│   ┌────┴────────────────┬────────────────────┐                          │
│   │                     │                    │                          │
│   ▼                     ▼                    ▼                          │
│ audioUser.c        audioServer.c       audio.h                          │
│ (client stubs)     (server stubs)      (shared types)                   │
│                                                                         │
│                                                                         │
│   CLIENT STUB                     SERVER STUB                           │
│   ─────────────                   ─────────────                         │
│   XSystem_Open() {                _HALB_MIGServer_server() {            │
│     pack args into msg              switch (msg->msgh_id) {             │
│     mach_msg(SEND)                    case 1010000:                     │
│     unpack reply                        XSystem_Open_handler();         │
│   }                                   case 1010034:                     │
│                                         XSetProperty_handler();         │
│                                       case 1010059:   <── OUR BUG!     │
│                                         XIOContext_Fetch_...();         │
│                                     }                                   │
│                                   }                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Message IDs

Each MIG routine has a unique message ID. For CoreAudio:

| Message ID | Routine |
|------------|---------|
| 1010000 | `XSystem_Open` (establish connection) |
| 1010001 | `XSystem_Close` |
| 1010034 | `XObject_SetPropertyData` (heap spray!) |
| 1010059 | `XIOContext_Fetch_Workgroup_Port` (VULN!) |
| 1010060 | `XIOContext_SetClientControlPort` |

### The Dispatch Loop

coreaudiod runs a Mach message loop:

```c
while (1) {
    mach_msg(&request, MACH_RCV_MSG, ...);  // Block for message

    // Dispatch to handler based on msgh_id
    _HALB_MIGServer_server(&request, &reply);

    mach_msg(&reply, MACH_SEND_MSG, ...);   // Send response
}
```

### CVE-2024-54529 Relevance

The vulnerability is in the **SERVER-SIDE** handler code. Specifically:

1. Client sends message ID 1010059 (`XIOContext_Fetch_Workgroup_Port`)
2. Server dispatches to handler
3. Handler calls `CopyObjectByObjectID(object_id)`
4. Handler **ASSUMES** result is IOContext, doesn't check type
5. Handler dereferences offset 0x68 (workgroup pointer)
6. If object is actually Engine, offset 0x68 is uninitialized
7. **BOOM**: arbitrary pointer dereference

### XNU Source Reference

For MIG itself, see `/usr/bin/mig` and related headers.
MIG definitions are typically in `.defs` files.

---

## 1.7 CoreAudiod's Position in the Stack

Where does coreaudiod fit in the system?

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     macOS AUDIO STACK                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   APPLICATION LAYER                                                     │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │
│   │   Safari    │  │   Music.app │  │ GarageBand  │                    │
│   │ (sandboxed) │  │             │  │             │                    │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                    │
│          │                │                │                            │
│          └────────────────┼────────────────┘                            │
│                           │                                             │
│                           ▼                                             │
│   AUDIO FRAMEWORKS                                                      │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  AudioToolbox.framework / AVFoundation.framework               │  │
│   │  (High-level audio APIs)                                        │  │
│   └────────────────────────────────┬────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  CoreAudio.framework (HAL - Hardware Abstraction Layer)        │  │
│   │  Runs in-process, communicates with coreaudiod via Mach IPC    │  │
│   └────────────────────────────────┬────────────────────────────────┘  │
│                                    │                                    │
│   ════════════════════════════════════════════════ MACH IPC BOUNDARY   │
│                                    │                                    │
│                                    ▼                                    │
│   SYSTEM DAEMON                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                      coreaudiod                                 │  │
│   │                                                                 │  │
│   │  • Runs as _coreaudiod user (UID 202)                          │  │
│   │  • NO SANDBOX (full filesystem access!)                         │  │
│   │  • Manages all audio device state                               │  │
│   │  • Receives Mach messages from all audio clients                │  │
│   │  • Stores settings in /Library/Preferences/Audio/               │  │
│   │                                                                 │  │
│   │  HALS_Object hierarchy:                                         │  │
│   │    - System (singleton)                                         │  │
│   │    - Device (one per audio device)                              │  │
│   │    - Stream (audio streams)                                     │  │
│   │    - IOContext ('ioct')                                         │  │
│   │    - Engine ('ngne')  <── TYPE CONFUSION SOURCE                 │  │
│   │                                                                 │  │
│   └────────────────────────────────┬────────────────────────────────┘  │
│                                    │                                    │
│   ════════════════════════════════════════════════ IOKIT BOUNDARY       │
│                                    │                                    │
│                                    ▼                                    │
│   KERNEL                                                                │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  IOAudioFamily.kext (kernel extension)                          │  │
│   │  Audio driver kexts (hardware-specific)                         │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│   HARDWARE                                                              │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Audio hardware (speakers, microphones, USB audio, etc.)        │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why CoreAudiod Is an Attractive Target

1. **REACHABLE FROM SANDBOX:**
   Safari's sandbox allows mach-lookup to `com.apple.audio.audiohald`
   (needed for WebRTC, media playback)

2. **RUNS WITHOUT SANDBOX:**
   Unlike many system daemons, coreaudiod is NOT sandboxed.
   Compromise = full filesystem access.

3. **COMPLEX IPC INTERFACE:**
   72 different MIG message handlers = large attack surface

4. **PERSISTENT STATE:**
   Writes to `/Library/Preferences/Audio/` -> persistence opportunity

### Library Dependencies

```bash
$ otool -L /usr/sbin/coreaudiod:

/usr/sbin/coreaudiod:
    /System/Library/PrivateFrameworks/caulk.framework/.../caulk
    /System/Library/Frameworks/CoreAudio.framework/.../CoreAudio
    /System/Library/Frameworks/CoreFoundation.framework/.../CoreFoundation
    /usr/lib/libAudioStatistics.dylib (weak)
    /System/Library/Frameworks/Foundation.framework/.../Foundation
    /usr/lib/libobjc.A.dylib
    /usr/lib/libc++.1.dylib
    /usr/lib/libSystem.B.dylib
```

---

## 1.8 Sandbox Escapes: The Crown Jewel

A sandbox escape means breaking out of macOS's application sandbox.
CVE-2024-54529 is valuable because it enables this.

### What the Sandbox Restricts

When Safari (or another sandboxed app) is compromised via a browser
bug, the attacker can execute code but is confined:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SAFARI SANDBOX RESTRICTIONS                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   FILESYSTEM:                                                           │
│     ✗ Cannot read /etc, /var, /private                                 │
│     ✗ Cannot read other users' files                                   │
│     ✗ Cannot write outside sandbox container                           │
│     ✓ Can read own container and specific allowed paths                │
│                                                                         │
│   NETWORK:                                                              │
│     ✗ Cannot create raw sockets                                        │
│     ✓ Can make HTTP/HTTPS requests (via WebKit)                        │
│                                                                         │
│   IPC:                                                                  │
│     ✗ Cannot connect to most system services                           │
│     ✓ Explicitly allowed services (mach-lookup rules)                  │
│       - com.apple.audio.audiohald  <── ALLOWED (for audio playback)    │
│       - com.apple.windowserver                                          │
│       - com.apple.SecurityServer                                        │
│       - ... (curated list)                                              │
│                                                                         │
│   PROCESSES:                                                            │
│     ✗ Cannot fork/exec arbitrary binaries                              │
│     ✗ Cannot ptrace other processes                                    │
│     ✗ Cannot inject into other apps                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### After CVE-2024-54529

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    POST-ESCAPE CAPABILITIES                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   FILESYSTEM:                                                           │
│     ✓ Read any file owned by _coreaudiod or world-readable             │
│     ✓ Write to /Library/Preferences/Audio/                             │
│     ✓ Potentially create LaunchAgents for persistence                  │
│                                                                         │
│   NETWORK:                                                              │
│     ✓ Make arbitrary network connections                               │
│     ✓ Exfiltrate data, download payloads                               │
│                                                                         │
│   PROCESSES:                                                            │
│     ✓ Fork/exec new processes (as _coreaudiod)                         │
│     ✓ Potentially escalate further to root                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1.9 Connecting the Dots: XNU Concepts in CVE-2024-54529

Let's trace how every XNU concept we covered enables the exploit:

| Exploit Step | XNU Concept Used |
|--------------|------------------|
| 1. Safari obtains send right to coreaudiod | Mach ports, capability model, `bootstrap_look_up` |
| 2. Exploit sends heap spray messages (large plists) | `mach_msg`, `ipc_kmsg`, `copyin`, OOL descriptors |
| 3. coreaudiod deserializes and allocates strings | BSD layer (plist parsing), userspace malloc zones |
| 4. Exploit creates Engine objects via MIG | MIG dispatch, message ID routing, object ID allocation |
| 5. Exploit triggers type confusion handler | Type confusion in MIG handler, object lookup without type check |
| 6. ROP chain executes | Not kernel-level, but enabled by successful sandbox escape |
| 7. File written to disk | BSD VFS layer, `_coreaudiod` credentials (no sandbox) |

### The Fundamental Insight

The kernel did its job correctly. Every message was validated,
every copyin was bounds-checked, every port right was verified.

The bug is in **USERSPACE LOGIC** in coreaudiod:
- It trusted that object IDs were the right type
- It didn't validate before dereferencing

But the **IMPACT** comes from the kernel's trust model:
- Sandbox allows the IPC connection
- No sandbox on coreaudiod = full post-exploit capabilities

---

## 1.10 Hands-On: Commands to Explore XNU Yourself

This section provides actual commands you can run to explore the kernel
concepts we've discussed. All outputs shown are from a real macOS system.

### Step 1: Identify Your Kernel Version

First, let's see exactly what kernel you're running:

```bash
$ sysctl kern.version kern.osversion kern.osproductversion hw.machine

kern.version: Darwin Kernel Version 25.2.0: Tue Nov 18 21:09:41 PST 2025;
              root:xnu-12377.61.12~1/RELEASE_ARM64_T6031
kern.osversion: 25C56
kern.osproductversion: 26.2
hw.machine: arm64
```

The version string tells you:
- XNU version: 12377.61.12 (maps to macOS 26.2)
- Architecture: ARM64 (Apple Silicon) with T6031 (M-series chip)
- Build: RELEASE (not DEBUG kernel)

You can find XNU source at: https://github.com/apple-oss-distributions/xnu
Match the xnu-XXXX tag to your version.

### Step 2: Examine Kernel Zone Allocators with zprint

The `zprint` command shows all kernel zones and their statistics:

```bash
$ zprint | head -40

zone name                   elem    cur     max     cur     max     cur
                            size   size    size   #elts   #elts   inuse
-------------------------------------------------------------------------
ipc.ports                    144     0K      0K   64249   64249   64249
ipc.kmsgs                    256     0K      0K    2841    2841    2841
ipc.vouchers                  56     0K      0K     404     404     404
proc_task                   3640     0K      0K    1061    1061    1061
threads                     2080     0K      0K    3698    3698    3698
data.kalloc.128              128     0K      0K   10232   10232   10232
data.kalloc.256              256     0K      0K      12      12      12
```

**Key Observations:**

- `ipc.ports` (144 bytes): Every Mach port in the kernel is allocated here. 64,249 ports currently in use on this system. Critical for port-based exploits (UAF, etc.)

- `ipc.kmsgs` (256 bytes): Kernel message buffers for Mach IPC. Messages larger than inline buffer use kalloc.

- `data.kalloc.*` (various sizes): General-purpose allocations bucketed by size. `kalloc.128` for 65-128 byte allocs, `kalloc.256` for 129-256 byte allocs.

**CVE-2024-54529 Relevance:**
coreaudiod runs in USERSPACE with libmalloc (not kernel zones).
But the SAME size-class bucketing concept applies:
- `malloc_small` has similar bucketing
- 1152-byte Engine objects land in a predictable size class

### Step 3: Examine CoreAudiod's Mach Service Registration

See how coreaudiod registers its Mach ports with launchd:

```bash
$ launchctl print system/com.apple.audio.coreaudiod

system/com.apple.audio.coreaudiod = {
    path = /System/Library/LaunchDaemons/com.apple.audio.coreaudiod.plist
    state = running
    program = /usr/sbin/coreaudiod
    domain = system
    username = _coreaudiod
    group = _coreaudiod
    pid = 188
    immediate reason = ipc (mach)  <-- Started due to Mach IPC!

    endpoints = {
        "com.apple.audio.audiohald" = {
            port = 0x18233           <-- THE PORT SAFARI CONNECTS TO
            active = 1
            managed = 1
        }
        "com.apple.audio.driver-registrar" = {
            port = 0x1d913
            active = 1
        }
    }
}
```

**Key Observations:**
- coreaudiod runs as `_coreaudiod` user (UID 202)
- It exposes `com.apple.audio.audiohald` service
- Port 0x18233 is the Mach port where messages arrive
- "immediate reason = ipc (mach)" means it was started on-demand

**CVE-2024-54529 Relevance:**
When Safari calls `bootstrap_look_up("com.apple.audio.audiohald")`,
launchd returns a send right to port 0x18233. Messages Safari sends
to this port wake coreaudiod (if sleeping) and dispatch to MIG handlers.

### Step 4: Extract and Examine CoreAudio Symbols

On modern macOS, CoreAudio is in the dyld shared cache. Extract it:

```bash
$ brew install blacktop/tap/ipsw  # If not installed

$ ipsw dyld info /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

Magic          = "dyld_v1  arm64e"
Platform       = macOS
OS Version     = 26.2
Num Images     = 3551
Shared Region: 5GB, address: 0x180000000 -> 0x2D0FA4000

$ mkdir -p /tmp/extracted
$ ipsw dyld extract /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
    "/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio" \
    --output /tmp/extracted
```

Now examine the symbols:

```bash
$ nm /tmp/extracted/CoreAudio | wc -l
39119   <-- Nearly 40,000 symbols!

$ nm /tmp/extracted/CoreAudio | grep -E "^[0-9a-f]+ t __X" | wc -l
79      <-- 79 MIG handler functions!
```

List MIG handlers (the attack surface):

```bash
$ nm /tmp/extracted/CoreAudio | grep -E "t __X" | head -20

0000000183c14968 t __XObject_AddPropertyListener
0000000183c1a860 t __XObject_GetPropertyData
0000000183c16070 t __XObject_SetPropertyData      <-- HEAP SPRAY TARGET
0000000183c1c998 t __XSystem_Close
0000000183c1c4a4 t __XSystem_CreateIOContext
0000000183c11ce0 t __XIOContext_Fetch_Workgroup_Port  <-- THE VULNERABLE HANDLER!
0000000183c0d000 t __XIOContext_PauseIO
0000000183c1b8cc t __XIOContext_SetClientControlPort
0000000183c1b7ac t __XIOContext_Start
0000000183c1b338 t __XIOContext_Stop
```

**CVE-2024-54529 Relevance:**
The vulnerable function is `__XIOContext_Fetch_Workgroup_Port` at
address 0x183c11ce0. When message ID 1010059 arrives, it dispatches
to this function. The function calls `CopyObjectByObjectID()` but
doesn't validate the returned object type before dereferencing.

### Step 5: Find HALS Object Hierarchy Symbols

Search for HALS_Object related symbols to understand the class hierarchy:

```bash
$ nm /tmp/extracted/CoreAudio | grep -i "iocontext\|engine" | head -20

00000001837491ec t _HALS_IOContext_SetClientControlPort
0000000183749bf0 t _HALS_IOContext_StartAtTime
0000000183746ad0 t _HALS_System_CreateIOContext
0000000183c11ce0 t __XIOContext_Fetch_Workgroup_Port  <-- VULNERABLE!
0000000183c0d000 t __XIOContext_PauseIO
0000000183c1c4a4 t __XSystem_CreateIOContext
0000000183c1c190 t __XSystem_DestroyIOContext
```

The naming convention reveals the class hierarchy:
- `HALS_IOContext`: The context object (type 'ioct')
- `HALS_Engine`: Engine objects (type 'ngne')
- `HALS_Device`: Audio device objects
- `HALS_Stream`: Audio stream objects

### Step 6: Trace Mach IPC with DTrace (Requires Reduced SIP)

If you have SIP disabled for debugging, you can trace Mach messages:

```bash
$ sudo dtrace -n 'mach_msg_trap:entry { printf("pid=%d msg_id=%d",
                                                pid, arg5); }'
```

To see kernel IPC probes available:

```bash
$ sudo dtrace -ln 'fbt:mach_kernel:ipc*:entry'

ID   PROVIDER   MODULE        FUNCTION              NAME
540752 fbt      mach_kernel   ipc_port_release_send entry
```

**NOTE:** Most IPC probes require fully disabled SIP. On production systems,
use `log stream` instead:

```bash
$ log stream --predicate 'process == "coreaudiod"' --info
```

### Step 7: Examine CoreAudiod Process State

See coreaudiod's current process state:

```bash
$ ps aux | grep coreaudiod

_coreaudiod  188  0.1 435459456 115840 /usr/sbin/coreaudiod
```

The 435MB virtual size is mostly shared libraries (dyld cache mapping).
Actual resident memory is ~115MB.

See loaded libraries:

```bash
$ otool -L /usr/sbin/coreaudiod

/usr/sbin/coreaudiod:
    .../caulk.framework/caulk
    .../CoreAudio.framework/CoreAudio      <-- THE VULNERABLE CODE
    .../CoreFoundation.framework/CoreFoundation
    /usr/lib/libAudioStatistics.dylib (weak)
    .../Foundation.framework/Foundation
    /usr/lib/libobjc.A.dylib
    /usr/lib/libc++.1.dylib
    /usr/lib/libSystem.B.dylib
```

**CVE-2024-54529 Relevance:**
The vulnerable code is in CoreAudio.framework, which coreaudiod
links against. The `_HALB_MIGServer_server()` function in CoreAudio
dispatches incoming Mach messages to handler functions like
`__XIOContext_Fetch_Workgroup_Port`.

---

## Summary: What You've Learned

After working through this material, you now understand:

1. **KERNEL ZONES**: How the kernel allocates fixed-size objects (`ipc.ports`, `ipc.kmsgs`) in predictable buckets

2. **SERVICE REGISTRATION**: How coreaudiod exposes Mach services that Safari can connect to from inside its sandbox

3. **MIG DISPATCH**: How incoming messages are routed to handler functions based on message ID

4. **SYMBOL ANALYSIS**: How to extract and examine CoreAudio to understand its internal structure and attack surface

5. **PROCESS INTROSPECTION**: How to examine coreaudiod's state, libraries, and port namespace

With this knowledge, you can:
- Understand EXACTLY how the exploit flows through the system
- Reproduce the analysis on your own machine
- Apply these techniques to find similar bugs

> "The kernel is the foundation. If you understand it, you understand
> both how exploits work and how to prevent them."

---

## Navigation

| Previous | Next |
|----------|------|
| [Table of Contents](./00-table-of-contents.md) | [Vulnerability Research Foundations](./02-vuln-research-foundations.md) |
