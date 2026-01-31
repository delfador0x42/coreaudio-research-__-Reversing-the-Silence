# CVE-2024-54529: CoreAudio Type Confusion to Sandbox Escape

## A Comprehensive Vulnerability Research Case Study
### From First Principles to Full Exploitation

---

## Document Index

This documentation is a parallel representation of the comprehensive `exploit.mm` file, split into focused markdown documents for easier navigation and reading.

### Core Documentation

| # | Document | Description | Audience Level |
|---|----------|-------------|----------------|
| 00 | [Introduction](00-introduction.md) | Overview, document structure, critical limitations | All |
| 01 | [XNU Architecture](01-xnu-architecture.md) | Kernel internals, Mach IPC, zones, tasks | Intermediate |
| 02 | [Vulnerability Foundations](02-vulnerability-foundations.md) | Attack surface analysis, target selection, methodology | Beginner |
| 03 | [Type Confusion](03-type-confusion.md) | The vulnerability class explained from first principles | Beginner → Advanced |
| 04 | [ROP Fundamentals](04-rop-fundamentals.md) | Return-Oriented Programming explained | Intermediate |
| 05 | [Exploitation](05-exploitation.md) | Complete exploit chain details, gadgets, syscalls | Expert |
| 06 | [Fuzzing Methodology](06-fuzzing-methodology.md) | How the bug was found, coverage-guided fuzzing | Intermediate |
| 07 | [Detection and Defense](07-detection-and-defense.md) | Blue team perspective, YARA rules, IOCs | All Levels |

### Appendices

| Document | Description | Audience Level |
|----------|-------------|----------------|
| [Appendix A: Experiments](appendix-a-experiments.md) | Live command outputs, hands-on exercises | Beginner → Expert |
| [Appendix B: References](appendix-b-references.md) | Bibliography, tools, further reading | All |

---

## Quick Start Guides

### For Complete Beginners
**No exploit development experience required**

1. Start with [02-vulnerability-foundations.md](02-vulnerability-foundations.md) to understand the "why"
2. Read [03-type-confusion.md](03-type-confusion.md) for first-principles explanation
3. Skim [01-xnu-architecture.md](01-xnu-architecture.md) sections 1.1-1.4
4. Try the beginner exercises in [Appendix A](appendix-a-experiments.md)

### For Intermediate Researchers
**Some systems/security experience**

1. [01-xnu-architecture.md](01-xnu-architecture.md) for macOS internals context
2. [06-fuzzing-methodology.md](06-fuzzing-methodology.md) for bug hunting techniques
3. [Appendix A experiments](appendix-a-experiments.md) to reproduce the analysis
4. [05-exploitation.md](05-exploitation.md) for exploitation details

### For Expert Researchers
**Looking for variant analysis and new research directions**

1. Jump to [05-exploitation.md](05-exploitation.md) Section K.2 (Root Cause)
2. [07-detection-and-defense.md](07-detection-and-defense.md) for defensive patterns
3. Open problems section in [Appendix B](appendix-b-references.md)

### For Detection Engineers
**Blue team focus**

1. [07-detection-and-defense.md](07-detection-and-defense.md) - YARA rules, log monitoring
2. [Appendix A](appendix-a-experiments.md) - Experiments 8-10 for detection setup
3. IOC extraction and forensic timeline sections

### For Students
**Academic/learning context**

1. Read the documents in numerical order
2. Complete ALL exercises in [Appendix A](appendix-a-experiments.md)
3. Run every command and document your observations
4. Attempt the challenge exercises at each difficulty level

---

## Original Source

The complete, unified documentation is available in:
```
exploit/exploit.mm
```

This is an 18,000+ line comprehensive document containing everything in one file with extensive cross-referencing. The markdown files here are a parallel representation for easier navigation.

---

## CVE Information

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-54529 |
| **Component** | CoreAudio / coreaudiod |
| **Type** | Type Confusion |
| **CVSS** | 7.8 (HIGH) |
| **Researcher** | Dillon Franke (Google Project Zero) |
| **Reported** | 2024-10-09 |
| **Fixed** | 2024-12-11 (macOS 15.2, 14.7.2, 13.7.2) |

---

## Critical Limitation

> **This exploit is Intel (x86-64) only as presented.**
>
> On Apple Silicon (arm64e), Pointer Authentication Codes (PAC) make exploitation significantly harder. The TYPE CONFUSION vulnerability exists on ARM64, but achieving CODE EXECUTION requires bypassing PAC.
>
> See [05-exploitation.md](05-exploitation.md) Part 8 for ARM64/PAC deep dive.

---

## Repository Structure

```
CoreAudioFuzz/
├── docs/                          # ← You are here
│   ├── README.md                  # This file
│   ├── 00-introduction.md
│   ├── 01-xnu-architecture.md
│   ├── 02-vulnerability-foundations.md
│   ├── 03-type-confusion.md
│   ├── 04-rop-fundamentals.md
│   ├── 05-exploitation.md
│   ├── 06-fuzzing-methodology.md
│   ├── 07-detection-and-defense.md
│   ├── appendix-a-experiments.md
│   └── appendix-b-references.md
│
├── exploit/
│   ├── exploit.mm                 # Complete unified documentation + code
│   └── build_rop.py               # ROP chain generator
│
├── jackalope-modifications/       # Fuzzing harness modifications
│   ├── function_hooks.cpp
│   ├── function_hooks.h
│   ├── main.cpp
│   └── README.md
│
├── harness.mm                     # Fuzzing harness
├── cve-2024-54529-poc-macos-sequoia-15.0.1.c  # Crash PoC
└── references_and_notes/          # Additional research materials
```

---

## Acknowledgments

- **Dillon Franke** (Google Project Zero) - Original vulnerability research
- **Google Project Zero** - Fuzzing infrastructure and disclosure
- **Brandon Falk** - Fuzzing methodology inspiration
- **Sergei Glazunov** - iOS/macOS exploitation techniques
- **Clement Lecigne** - Detection methodology
- **Manfred Paul** - Type confusion expertise

---

## License

This documentation is provided for educational and defensive security research purposes only.

---

## Version

**Document Version**: 1.3
**Last Updated**: 2026-01-31
**macOS Version Tested**: 26.2 (Build 25C56)
