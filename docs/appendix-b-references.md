# Appendix B: References and Bibliography

```
┌─────────────────────────────────────────────────────────────────────────┐
│ AUDIENCE: All Levels                                                    │
│ PREREQUISITES: None                                                     │
│ PURPOSE: Central reference for all citations, tools, and further reading│
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Navigation

- [Main Documentation Index](README.md)
- [Previous: Appendix A - Experiments](appendix-a-experiments.md)
- [Introduction](00-introduction.md)

---

## Table of Contents

1. [XNU/Kernel Sources](#1-xnukernel-sources)
2. [Mach IPC Documentation](#2-mach-ipc-documentation)
3. [Exploitation Techniques](#3-exploitation-techniques)
4. [ROP Research](#4-rop-research)
5. [PAC/ARM64 Research](#5-pacarm64-research)
6. [CoreAudio Internals](#6-coreaudio-internals)
7. [Fuzzing Resources](#7-fuzzing-resources)
8. [Detection/Blue Team](#8-detectionblue-team)
9. [Tools](#9-tools)
10. [Project Zero Research](#10-project-zero-research)
11. [ / Gamozo Labs](#11-brandon-falk--gamozo-labs)
12. [Open Problems / Future Research Directions](#12-open-problems--future-research-directions)

---

## 1. XNU/Kernel Sources

### Official Apple Open Source

- **XNU Kernel Source (GitHub Mirror)**: [https://github.com/apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu)
  - Version xnu-12377.61.12 corresponds to macOS 26.2

- **XNU Kernel Source (Apple)**: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

- **Core Foundation (CF)**: [https://github.com/apple-oss-distributions/CF](https://github.com/apple-oss-distributions/CF)
  - CFString.c line 166 for string internals
  - [Direct link to CFBinaryPList.c](https://opensource.apple.com/source/CF/CF-1153.18/CFBinaryPList.c)

- **libmalloc Source**: [https://opensource.apple.com/source/libmalloc/](https://opensource.apple.com/source/libmalloc/)
  - macOS heap allocator internals

### Key XNU Directories

```
osfmk/mach/          - Mach interfaces and headers
osfmk/kern/          - Core kernel (tasks, threads, scheduling)
osfmk/ipc/           - IPC implementation (ports, messages)
bsd/kern/            - BSD layer (processes, files, sockets)
iokit/               - I/O Kit device driver framework
```

---

## 2. Mach IPC Documentation

### Technical Deep Dives

- **XNU IPC Part I: Mach Messages**: [https://dmcyk.xyz/post/xnu_ipc_i_mach_messages/](https://dmcyk.xyz/post/xnu_ipc_i_mach_messages/)
  - Excellent introduction to Mach message structure

- **task_t Considered Harmful (Project Zero)**: [https://projectzero.google/2016/10/taskt-considered-harmful.html](https://projectzero.google/2016/10/taskt-considered-harmful.html)
  - MIG type confusion fundamentals
  - Reference counting bugs

- **Property Lists Documentation**: [https://developer.apple.com/library/archive/documentation/General/Conceptual/DevPedia-CocoaCore/PropertyList.html](https://developer.apple.com/library/archive/documentation/General/Conceptual/DevPedia-CocoaCore/PropertyList.html)

### XPC and IPC Security

- **HackTricks macOS XPC Guide**: [https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/index.html](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/index.html)

---

## 3. Exploitation Techniques

### Pwn2Own Safari Research (RET2 Systems)

Complete 6-part series on Safari exploitation:

1. **Exploit Development Overview**: [https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/](https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/)

2. **Vulnerability Discovery**: [https://blog.ret2.io/2018/06/13/pwn2own-2018-vulnerability-discovery/](https://blog.ret2.io/2018/06/13/pwn2own-2018-vulnerability-discovery/)

3. **Root Cause Analysis**: [https://blog.ret2.io/2018/06/19/pwn2own-2018-root-cause-analysis/](https://blog.ret2.io/2018/06/19/pwn2own-2018-root-cause-analysis/)

4. **JSC Exploit**: [https://blog.ret2.io/2018/07/11/pwn2own-2018-jsc-exploit/](https://blog.ret2.io/2018/07/11/pwn2own-2018-jsc-exploit/)

5. **Safari Sandbox**: [https://blog.ret2.io/2018/07/25/pwn2own-2018-safari-sandbox/](https://blog.ret2.io/2018/07/25/pwn2own-2018-safari-sandbox/)

6. **Sandbox Escape**: [https://blog.ret2.io/2018/08/28/pwn2own-2018-sandbox-escape/](https://blog.ret2.io/2018/08/28/pwn2own-2018-sandbox-escape/)
   - CFString spray technique
   - objc_msgSend exploitation

### macOS Sandbox Escapes

- **A New Era of macOS Sandbox Escapes**: [https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)

- **Endless Exploits**: [https://jhftss.github.io/Endless-Exploits/](https://jhftss.github.io/Endless-Exploits/)

### Sandbox Analysis Tools

- **sbtool (Jonathan Levin)**: [https://web.archive.org/web/20240519054616/https://newosxbook.com/src.jl?tree=listings&file=/sbtool.c](https://web.archive.org/web/20240519054616/https://newosxbook.com/src.jl?tree=listings&file=/sbtool.c)

- **Jonathan Levin's macOS Tools**: [newosxbook.com/tools](http://newosxbook.com/tools)

---

## 4. ROP Research

### Foundational Papers

- **What is a Good Memory Corruption Vulnerability?**: [https://projectzero.google/2015/06/what-is-good-memory-corruption.html](https://projectzero.google/2015/06/what-is-good-memory-corruption.html)
  - Project Zero analysis of exploit primitives

### Key Concepts

ROP (Return-Oriented Programming) chains existing code snippets ("gadgets") to achieve arbitrary code execution without injecting new code.

**Gadget Requirements:**
- End with `ret` (or equivalent control flow instruction)
- Perform useful operations (move registers, syscall, etc.)
- Be at known/predictable addresses

---

## 5. PAC/ARM64 Research

### Project Zero PAC Analysis

- **Examining Pointer Authentication on the iPhone XS**: [https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html)
  - Comprehensive PAC implementation analysis
  - Bypass techniques discussion

### Academic Research

- **PACMAN Attack (MIT)**: [https://pacmanattack.com/](https://pacmanattack.com/)
  - Speculative execution PAC bypass
  - Hardware-level attack surface

### Critical Note on arm64e

> The CVE-2024-54529 type confusion vulnerability exists on ARM64, but exploitation is significantly harder due to PAC. Achieving code execution requires:
> 1. A signing gadget (code that signs pointers for you)
> 2. A PAC oracle (leak signed pointers to reuse)
> 3. Or exploitation of a non-PAC-protected code path

---

## 6. CoreAudio Internals

### Apple Documentation

- **What is Core Audio**: [https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/WhatisCoreAudio/WhatisCoreAudio.html](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/WhatisCoreAudio/WhatisCoreAudio.html)

- **Core Audio Essentials**: [https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/CoreAudioEssentials/CoreAudioEssentials.html](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/CoreAudioEssentials/CoreAudioEssentials.html)

### Research Articles

- **coreaudiod Process Journey**: [https://medium.com/@boutnaru/the-macos-process-journey-coreaudiod-core-audio-daemon-c17f9044ca22](https://medium.com/@boutnaru/the-macos-process-journey-coreaudiod-core-audio-daemon-c17f9044ca22)

### Key CoreAudio Components

```
/usr/sbin/coreaudiod              - Main daemon
/System/Library/Frameworks/CoreAudio.framework
/System/Library/PrivateFrameworks/CoreAudioKit.framework

Mach Service: com.apple.audio.audiohald
```

---

## 7. Fuzzing Resources

### Coverage-Guided Fuzzing

- **AFL++ Repository**: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

- **libFuzzer Documentation**: [https://llvm.org/docs/LibFuzzer.html](https://llvm.org/docs/LibFuzzer.html)

- **honggfuzz**: [https://github.com/google/honggfuzz](https://github.com/google/honggfuzz)

### OWASP Resources

- **Fuzzing Guide**: [https://owasp.org/www-community/Fuzzing](https://owasp.org/www-community/Fuzzing)

- **Attack Surface Analysis Cheat Sheet**: [https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)

### Theoretical Foundations

- **Finding Bugs Efficiently (Ned Williamson, ASU 2024)**: [https://github.com/nedwill/presentations/blob/main/asu-2024.pdf](https://github.com/nedwill/presentations/blob/main/asu-2024.pdf)
  - Kolmogorov complexity in fuzzing
  - Program analysis models

- **Kolmogorov Complexity**: [https://en.wikipedia.org/wiki/Kolmogorov_complexity](https://en.wikipedia.org/wiki/Kolmogorov_complexity)

- **AFL Technical Details**: [https://lcamtuf.coredump.cx/afl/technical_details.txt](https://lcamtuf.coredump.cx/afl/technical_details.txt)

### Symbolic Execution

- **KLEE Symbolic Execution Engine**: [https://klee.github.io/](https://klee.github.io/)

---

## 8. Detection/Blue Team

### Vulnerability Databases

- **CVE-2024-54529 (NVD)**: [https://nvd.nist.gov/vuln/detail/CVE-2024-54529](https://nvd.nist.gov/vuln/detail/CVE-2024-54529)

- **CWE-843: Type Confusion**: [https://cwe.mitre.org/data/definitions/843.html](https://cwe.mitre.org/data/definitions/843.html)

- **Apple Security Advisory**: [https://support.apple.com/en-us/121839](https://support.apple.com/en-us/121839)

- **CVE Details**: [https://www.cvedetails.com/cve/CVE-2024-54529/](https://www.cvedetails.com/cve/CVE-2024-54529/)

### Detection Strategies

Key indicators for CVE-2024-54529:

1. **Process Monitoring**
   - Unusual coreaudiod behavior
   - Unexpected child processes from coreaudiod

2. **File Monitoring**
   - Suspicious writes to `/Library/Preferences/Audio/`
   - Large binary plist files with embedded data

3. **Log Analysis**
   - Unified log entries for coreaudiod crashes
   - HALS_Engine allocation patterns

### Research References

- **First Principles Vulnerability Assessment**: [https://www.researchgate.net/publication/215535352_First_principles_vulnerability_assessment](https://www.researchgate.net/publication/215535352_First_principles_vulnerability_assessment)

---

## 9. Tools

### Disassemblers and Reverse Engineering

#### Ghidra (Free, NSA Open Source)

- **Website**: [https://ghidra-sre.org/](https://ghidra-sre.org/)

```bash
# Installation
# Download from website, requires Java 17+
unzip ghidra_*.zip
cd ghidra_*
./ghidraRun
```

#### IDA Pro (Commercial)

- **Website**: [https://hex-rays.com/ida-pro/](https://hex-rays.com/ida-pro/)

#### Hopper Disassembler (macOS Native)

- **Website**: [https://www.hopperapp.com/](https://www.hopperapp.com/)

#### Binary Ninja (Modern UI)

- **Website**: [https://binary.ninja/](https://binary.ninja/)

#### radare2 (Free, Open Source)

- **Website**: [https://rada.re/](https://rada.re/)

```bash
# Installation
brew install radare2

# Basic usage
r2 /usr/sbin/coreaudiod
```

### ROP Gadget Finders

#### ROPgadget

- **Repository**: [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget)

```bash
# Installation
pip install ROPgadget

# Usage
ROPgadget --binary /usr/sbin/coreaudiod --ropchain
```

#### Ropper

- **Repository**: [https://github.com/sashs/Ropper](https://github.com/sashs/Ropper)

```bash
# Installation
pip install ropper

# Usage
ropper --file /usr/sbin/coreaudiod --search "pop rdi"
```

### Fuzzing Infrastructure

#### TinyInst (Project Zero)

- **Repository**: [https://github.com/googleprojectzero/TinyInst](https://github.com/googleprojectzero/TinyInst)
- **Hook Documentation**: [https://github.com/googleprojectzero/TinyInst/blob/master/hook.md](https://github.com/googleprojectzero/TinyInst/blob/master/hook.md)

```bash
# Installation
git clone --recursive https://github.com/googleprojectzero/TinyInst
cd TinyInst
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### CoreAudioFuzz (Project Zero)

- **Repository**: [https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- **Exploit Directory**: [https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz/exploit](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz/exploit)

#### AFL++

- **Repository**: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

```bash
# Installation
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

### macOS Binary Analysis

#### ipsw (IPSW/dyld_shared_cache tool)

- **Repository**: [https://github.com/blacktop/ipsw](https://github.com/blacktop/ipsw)

```bash
# Installation
brew install blacktop/tap/ipsw

# Extract dyld_shared_cache
ipsw dyld extract /System/Library/dyld/dyld_shared_cache_arm64e

# List frameworks
ipsw dyld list /System/Library/dyld/dyld_shared_cache_arm64e
```

### Memory Debugging

```bash
# Enable malloc debugging
export MallocStackLogging=1
export MallocGuardEdges=1
export MallocScribble=1

# Run with stack logging
MallocStackLogging=1 /usr/sbin/coreaudiod 2>&1 | grep HALS_Engine

# Use heap inspection (requires SIP disabled)
heap -s 1152 <pid>
```

---

## 10. Project Zero Research

### Primary Research for CVE-2024-54529

- **Breaking the Sound Barrier Part I: Fuzzing**: [https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)

- **Breaking the Sound Barrier Part II**: [https://projectzero.google/2026/01/sound-barrier-2.html](https://projectzero.google/2026/01/sound-barrier-2.html)

- **About Project Zero**: [https://googleprojectzero.blogspot.com/p/about-project-zero.html](https://googleprojectzero.blogspot.com/p/about-project-zero.html)

### Issue Tracker

- **CVE-2024-54529 Issue**: [https://project-zero.issues.chromium.org/issues/372511888](https://project-zero.issues.chromium.org/issues/372511888)

- **Sound Barrier Issue**: [https://project-zero.issues.chromium.org/issues/406271181](https://project-zero.issues.chromium.org/issues/406271181)

- **task_t Issue (CVE-2016-7613)**: [https://project-zero.issues.chromium.org/issues/42452370](https://project-zero.issues.chromium.org/issues/42452370)

- **Additional Issues**:
  - [https://project-zero.issues.chromium.org/issues/42452484](https://project-zero.issues.chromium.org/issues/42452484)
  - [https://project-zero.issues.chromium.org/issues/42451567](https://project-zero.issues.chromium.org/issues/42451567)

### Disclosure Policy

- **Project Zero Disclosure Policy**: [https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html)

### Related Project Zero Research

- **In-the-Wild iOS Exploit Chain**: [https://projectzero.google/2019/08/in-wild-ios-exploit-chain-2.html](https://projectzero.google/2019/08/in-wild-ios-exploit-chain-2.html)
  - iOS exploitation techniques

- **VoucherSwap (MIG Reference Counting)**: [https://googleprojectzero.blogspot.com/2019/01/voucherswap-exploiting-mig-reference.html](https://googleprojectzero.blogspot.com/2019/01/voucherswap-exploiting-mig-reference.html)

- **libwebp Vulnerability Analysis**: [https://security.googleblog.com/2023/09/googles-libwebp-vulnerability-and-its.html](https://security.googleblog.com/2023/09/googles-libwebp-vulnerability-and-its.html)

---

## 11.  / Gamozo Labs

### Blog Posts

- **Gamozo Labs Blog**: [https://gamozolabs.github.io/](https://gamozolabs.github.io/)

- **FuzzOS: Snapshot Fuzzing**: [https://gamozolabs.github.io/fuzzing/2020/12/06/fuzzos.html](https://gamozolabs.github.io/fuzzing/2020/12/06/fuzzos.html)
  - Snapshot-based fuzzing architecture
  - Deterministic reset for each iteration

- **Byte-Level MMU for Corruption Detection**: [https://gamozolabs.github.io/fuzzing/2018/11/19/vectorized_emulation_mmu.html](https://gamozolabs.github.io/fuzzing/2018/11/19/vectorized_emulation_mmu.html)
  - Detecting 1-byte corruptions
  - Guard bytes at allocation boundaries

- **Vectorized Emulation**: [https://gamozolabs.github.io/fuzzing/2018/10/14/vectorized_emulation.html](https://gamozolabs.github.io/fuzzing/2018/10/14/vectorized_emulation.html)
  - SIMD-accelerated emulation for fuzzing

- **Fuzzing Thoughts and Methodology**: [https://gamozolabs.github.io/2020/08/11/some_fuzzing_thoughts.html](https://gamozolabs.github.io/2020/08/11/some_fuzzing_thoughts.html)

### Tools and Repositories

- **Cannoli**: High-performance QEMU tracing
  - [https://github.com/gamozolabs/cannoli](https://github.com/gamozolabs/cannoli)

- **Chocolate Milk**: Research kernel written in Rust
  - [https://github.com/gamozolabs/chocolate_milk](https://github.com/gamozolabs/chocolate_milk)

- **Applepie**: Hypervisor-based fuzzer
  - [https://github.com/gamozolabs/applepie](https://github.com/gamozolabs/applepie)

- **Mesos**: Coverage without binary modification
  - [https://github.com/gamozolabs/mesos](https://github.com/gamozolabs/mesos)

### Social Media

- ** on X/Twitter**: [https://x.com/gamozolabs](https://x.com/gamozolabs)

---

## 12. Open Problems / Future Research Directions

### Type Confusion Audit Targets

Services with similar object map patterns that warrant security audit:

| Service | Interest | Access |
|---------|----------|--------|
| WindowServer | Window/surface object registries, GPU access | App sandbox allowed |
| launchd | Service registrations, root-level | System-wide |
| configd | Network/preference objects | Trusted by many |
| notifyd | Notification objects | Nearly every app |
| securityd | Key/certificate objects | High value |
| diskarbitrationd | Disk objects | Runs as root |

### Fuzzing Architecture Improvements

1. **Snapshot Fuzzing**
   - Run daemon in VM/QEMU with snapshot/restore
   - Microsecond resets instead of multi-second restarts
   - See: FuzzOS methodology

2. **Byte-Level Corruption Detection**
   - Implement byte-level MMU in emulator
   - Catch off-by-one before they become exploitable
   - Guard bytes at every allocation boundary

3. **Distributed/Scaled Fuzzing**
   - Near-linear scaling up to network bandwidth
   - Independent workers with periodic corpus sync
   - "~50-100 cores" standard at security research firms

### Research Questions

- What other Mach services have similar object map patterns?
- How would Intel PT coverage compare to TinyInst overhead?
- Can VM snapshotting achieve deterministic execution?
- What's the bug density in MIG-generated dispatch code?
- Could symbolic execution guide fuzzers to type confusion paths?

### arm64e Exploitation Research

- Build corpus of PAC signing gadgets
- Study non-PAC-protected code paths
- Investigate PACMAN-style speculative attacks
- Analyze kernel PAC implementation differences

### Automated Analysis

- Static analysis rules for type confusion patterns
- Automated MIG handler auditing for missing type checks
- Compare against "known secure" implementations

---

## Apple Security Resources

### Reporting Vulnerabilities

- **Apple Security Bounty**: [https://developer.apple.com/security-bounty/](https://developer.apple.com/security-bounty/)

- **How to Report Security Issues**: [https://support.apple.com/en-us/HT201220](https://support.apple.com/en-us/HT201220)

---

## Local Repository Files

| File | Description |
|------|-------------|
| `exploit/exploit.mm` | Main exploit and comprehensive documentation |
| `exploit/build_rop.py` | ROP chain generator |
| `helpers/message_ids.h` | Message ID enumeration |
| `harness.mm` | Fuzzing harness |
| `cve-2024-54529-poc-macos-sequoia-15.0.1.c` | Crash PoC |
| `references_and_notes/xnu/` | XNU kernel source reference |

---

## Citation Format

When citing CVE-2024-54529 research:

```
Franke, D. (2025). Breaking the Sound Barrier: Fuzzing and Exploiting CoreAudio.
Google Project Zero.
https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html

CVE-2024-54529. (2024). CoreAudio Type Confusion Vulnerability.
National Vulnerability Database.
https://nvd.nist.gov/vuln/detail/CVE-2024-54529
```

---

## Navigation

- [Back to Top](#appendix-b-references-and-bibliography)
- [Main Documentation Index](README.md)
- [Previous: Appendix A - Experiments](appendix-a-experiments.md)
- [Next: Introduction](00-introduction.md)

---

*Document Version: 1.0*
*Last Updated: 2026-01-31*
