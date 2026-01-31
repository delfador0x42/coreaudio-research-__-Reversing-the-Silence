# CVE-2024-54529: Introduction

```
        ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ██████╗ ███████╗███████╗
        ██║   ██║██║   ██║██║     ████╗  ██║    ██╔══██╗██╔════╝██╔════╝
        ██║   ██║██║   ██║██║     ██╔██╗ ██║    ██████╔╝█████╗  ███████╗
        ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ██╔══██╗██╔══╝  ╚════██║
         ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ██║  ██║███████╗███████║
          ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝╚══════╝

     CVE-2024-54529: CoreAudio Type Confusion to Sandbox Escape

     A Comprehensive Vulnerability Research Case Study
     From First Principles to Full Exploitation
```

---

## Audience Guide

```
┌─────────────────────────────────────────────────────────────────────────┐
│ AUDIENCE: All Levels                                                    │
│ PREREQUISITES: None                                                     │
│ LEARNING OBJECTIVES:                                                    │
│   • Understand the document structure and how to navigate it            │
│   • Know what CVE-2024-54529 is at a high level                        │
│   • Understand the critical ARM64/PAC limitation                        │
│   • Choose the right reading path for your experience level             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Document Structure

This comprehensive case study is organized into the following parts:

### Core Content

| Part | Title | Description |
|------|-------|-------------|
| **Part -1** | XNU Kernel Architecture Deep Dive | Mach IPC, zones, tasks, audit tokens |
| **Part 0** | Vulnerability Research Foundations | Attack surface, target selection, methodology |
| **Part 1** | Header Imports and Code Origins | Function documentation, Mach structures |
| **Part 2** | System Traces and Kernel Internals | Kernel-level traces, XNU structures |
| **Part 3** | Exploitation Details | Heap grooming, type confusion, ROP chains |
| **Part 4** | Advanced Techniques & References | Zone internals, task port context |
| **Part 5** | CoreAudio Architecture Deep Dive | HAL, HALS_Object hierarchy, MIG |
| **Part 6** | Bug Hunting Methodology | Knowledge-driven fuzzing, coverage-guided discovery |
| **Part 7** | Defensive Lessons and Patching | Apple's fix, variant analysis, detection |
| **Part 8** | ARM64 Exploitation and PAC | Pointer Authentication deep dive |

### Appendices

| Appendix | Title | Description |
|----------|-------|-------------|
| **A** | Notes for Elite Researchers | Open problems, research directions |
| **B** | Live Experiments | Real command outputs, hands-on exercises |

---

## How to Read This Document

### For Complete Beginners
*No exploit development experience*

```
Recommended Path:
  1. Part 0: Vulnerability Research Foundations
  2. Part -1: XNU Architecture (sections 1.1-1.4 only)
  3. Part 3: First-principles explanations (skip code details first pass)
  4. Appendix B: Beginner exercises

Time estimate: Read at your own pace. Understanding > speed.
```

### For Intermediate Researchers
*Some systems/security experience*

```
Recommended Path:
  1. Part -1: XNU context
  2. Part 5: CoreAudio specifics
  3. Part 6: Fuzzing methodology
  4. Appendix B: Reproduce experiments

Focus on: Understanding the bug hunting methodology
```

### For Expert Researchers
*Looking for variant analysis*

```
Recommended Path:
  1. Jump to Part 3, Section K.2 (Root Cause Analysis)
  2. Part 7: Defensive Lessons
  3. Appendix A: Open Problems

Focus on: Generalizable patterns and new research directions
```

### For Detection Engineers
*Blue team focus*

```
Recommended Path:
  1. Part 7: Detection section
  2. Appendix B: Experiments 8-10
  3. YARA rules and log monitoring commands

Focus on: IOCs, detection rules, forensic artifacts
```

### For Students
*Academic/learning context*

```
Recommended Path:
  1. Read linearly from Part -1 through Part 7
  2. Do ALL exercises in Appendix B
  3. Reproduce every experiment
  4. Challenge yourself with advanced exercises

Focus on: Deep understanding through doing
```

---

## Critical Limitation: PAC / Apple Silicon (arm64e)

> **THIS EXPLOIT IS INTEL (x86-64) ONLY AS PRESENTED.**

From Project Zero: *"I only analyzed and tested this issue on x86-64 versions of MacOS."*

On Apple Silicon (arm64e), Pointer Authentication Codes (PACs) make exploitation significantly harder:

- Code pointers must be signed with a secret key
- `AUTDA`/`AUTIB` instructions verify signature before use
- Invalid signature → crash (not arbitrary code execution)

### To exploit on arm64e, an attacker would need:

1. **A signing gadget** - code that signs pointers for you
2. **A PAC oracle** - leak signed pointers to reuse
3. **Or** exploitation of a non-PAC-protected code path

### Important Distinction:

| Aspect | Status on ARM64 |
|--------|-----------------|
| The TYPE CONFUSION vulnerability | **Still VALID** |
| The BUG exists | **Yes** |
| Achieving CODE EXECUTION | **Requires PAC bypass** |

This is why Apple Silicon Macs have better security posture - even when the same bugs exist, exploitation is harder.

### References:

- ["Examining Pointer Authentication on the iPhone XS"](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html) (Google P0)
- Brandon Azad's KTRR/PAC research
- [PACMAN attack (MIT)](https://pacmanattack.com/)

See **Part 8: ARM64 Exploitation and PAC** for comprehensive coverage.

---

## CVE Details

| Field | Value |
|-------|-------|
| CVE ID | CVE-2024-54529 |
| Affected Component | CoreAudio framework / coreaudiod daemon |
| Vulnerability Type | Type Confusion / Insufficient Type Validation |
| CVSS v3.1 Score | 7.8 (HIGH) |
| CVSS Vector | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |

### Timeline

| Date | Event |
|------|-------|
| 2024-10-09 | Reported to Apple by Dillon Franke (Google Project Zero) |
| 2024-12-11 | Fixed in macOS Sequoia 15.2, Sonoma 14.7.2, Ventura 13.7.2 |
| 2025-01-07 | 90-day disclosure deadline |

### Affected Versions

- macOS Sequoia < 15.2
- macOS Sonoma < 14.7.2
- macOS Ventura < 13.7.2

### References

- [Project Zero Blog Post](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2024-54529)
- [P0 Tools Repository](https://github.com/googleprojectzero/p0tools/blob/master/CoreAudioFuzz/)

---

## System Configuration

This documentation was created and tested on:

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
- https://github.com/apple-oss-distributions/xnu
- Specific version: xnu-12377.61.12 (corresponds to macOS 26.2)

---

## Document Philosophy

This documentation follows the **Feynman Teaching Method**:

> *"If you can't explain it simply, you don't understand it well enough."*
> — Often attributed to Richard Feynman

Every concept is explained from first principles. We assume nothing. We build from the ground up.

The goal is not just to show *what* the exploit does, but to teach *why* it works at every level—from how the CPU executes instructions to why malloc returns the memory it does.

---

## Next Steps

→ Continue to [01-xnu-architecture.md](01-xnu-architecture.md) for kernel internals

→ Or jump to [02-vulnerability-foundations.md](02-vulnerability-foundations.md) if you're new to vuln research
