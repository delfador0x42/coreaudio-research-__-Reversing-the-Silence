# Part 6: Fuzzing Methodology Case Study

```
┌─────────────────────────────────────────────────────────────────────────┐
│ AUDIENCE: Intermediate                                                  │
│ PREREQUISITES: Programming experience, basic fuzzing concepts           │
│ LEARNING OBJECTIVES:                                                    │
│   • Understand knowledge-driven fuzzing approach                        │
│   • Learn API call chaining technique                                   │
│   • See coverage-guided discovery in action                             │
│   • Understand harness construction for MIG services                    │
│   • Learn crash triage methodology                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

**Navigation:** [README](README.md) | [Previous: 00-introduction](00-introduction.md) | Next: 07-defensive-lessons (coming soon)

---

This section documents how CVE-2024-54529 was discovered, providing a template for finding similar vulnerabilities in other services.

## Table of Contents

1. [Fuzzing Tools and Resources](#fuzzing-tools-and-resources)
2. [Knowledge-Driven Fuzzing](#knowledge-driven-fuzzing)
3. [The API Call Chaining Technique](#the-api-call-chaining-technique)
4. [Building the Fuzzing Harness](#building-the-fuzzing-harness)
5. [Jackalope Modifications](#jackalope-modifications)
6. [Function Hooks](#function-hooks)
7. [Coverage Metrics and Improvements](#coverage-metrics-and-improvements)
8. [Corpus Evolution](#corpus-evolution)
9. [Crash Triage Methodology](#crash-triage-methodology)
10. [Setting Up a Fuzzing Environment](#setting-up-a-fuzzing-environment)
11. [Common Fuzzing Mistakes](#common-fuzzing-mistakes)

---

## Fuzzing Tools and Resources

### TinyInst (Project Zero's Instrumentation Tool)

```bash
# Installation
$ git clone https://github.com/googleprojectzero/TinyInst
$ cd TinyInst && mkdir build && cd build
$ cmake .. && make
```

Repository: https://github.com/googleprojectzero/TinyInst

### Project Zero CoreAudio Fuzzer

Repository: https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz

This is the actual fuzzer that found CVE-2024-54529. Contains: harness code, message generators, coverage tracking.

### Alternative Fuzzers

| Tool | Repository | Notes |
|------|------------|-------|
| AFL++ | https://github.com/AFLplusplus/AFLplusplus | `brew install afl-fuzz` |
| libFuzzer | https://llvm.org/docs/LibFuzzer.html | Compile with: `clang -fsanitize=fuzzer,address target.c` |
| Honggfuzz | https://github.com/google/honggfuzz | Good for macOS system fuzzing |

---

## Knowledge-Driven Fuzzing

Traditional "dumb" fuzzing throws random bytes at targets. Knowledge-driven fuzzing uses understanding of the target to generate smarter inputs.

```
┌─────────────────────────────────────────────────────────────────────┐
│            FUZZING EVOLUTION                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   GENERATION 1: Dumb Fuzzing                                        │
│   ─────────────────────────                                         │
│   • Random byte flipping                                            │
│   • No understanding of format                                      │
│   • Most inputs rejected immediately                                │
│   • Very low coverage                                               │
│                                                                     │
│   GENERATION 2: Grammar-Based Fuzzing                               │
│   ────────────────────────────────                                  │
│   • Understands input format                                        │
│   • Generates syntactically valid inputs                            │
│   • Better coverage of parser code                                  │
│   • Still misses semantic issues                                    │
│                                                                     │
│   GENERATION 3: Coverage-Guided Fuzzing (AFL, libFuzzer)            │
│   ───────────────────────────────────────────────────               │
│   • Tracks code coverage                                            │
│   • Mutates inputs that find new paths                              │
│   • Evolutionary approach                                           │
│   • Much better at finding deep bugs                                │
│                                                                     │
│   GENERATION 4: Knowledge-Driven Fuzzing  <== THIS IS WHAT WE USE   │
│   ──────────────────────────────────────                            │
│   • Understands API semantics                                       │
│   • Chains API calls in valid sequences                             │
│   • Knows about state dependencies                                  │
│   • Targets specific vulnerability classes                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

For IPC fuzzing, knowledge-driven fuzzing means:
- Understanding which messages create objects
- Understanding which messages reference objects by ID
- Understanding which messages require specific object types
- **Deliberately sending wrong object types to see what happens**

---

## The API Call Chaining Technique

Many IPC handlers require prior state to be useful. For example:
- You can't fetch a workgroup port without first creating an IOContext
- You can't create an IOContext without first opening a client
- You can't do most things without first registering

API Call Chaining solves this by automatically discovering and executing the prerequisite API calls:

```
┌─────────────────────────────────────────────────────────────────────┐
│              API CALL CHAINING EXAMPLE                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   GOAL: Fuzz XIOContext_Fetch_Workgroup_Port (ID: 1010059)          │
│                                                                     │
│   PROBLEM: Handler requires valid IOContext object ID               │
│                                                                     │
│   SOLUTION: Chain prerequisite calls                                │
│                                                                     │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │                                                            │    │
│   │  Step 1: XSystem_Open                                      │    │
│   │          └── Creates client, returns client_id             │    │
│   │                                                            │    │
│   │  Step 2: XDevice_CreateIOContext (using client_id)         │    │
│   │          └── Creates IOContext, returns iocontext_id       │    │
│   │                                                            │    │
│   │  Step 3: XIOContext_Fetch_Workgroup_Port (iocontext_id)    │    │
│   │          └── THIS IS WHAT WE FUZZ                          │    │
│   │                                                            │    │
│   └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│   THE KEY INSIGHT:                                                  │
│   Instead of passing iocontext_id, pass engine_id!                  │
│   The handler doesn't verify the type => TYPE CONFUSION             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

The fuzzer discovers this by:
1. Recording all object IDs created by any message
2. When fuzzing a handler that takes an object ID, try ALL known IDs
3. Including IDs of wrong object types
4. Monitor for crashes or unexpected behavior

---

## Building the Fuzzing Harness

Project Zero built a custom harness for fuzzing coreaudiod:

```
┌─────────────────────────────────────────────────────────────────────┐
│              FUZZING HARNESS ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Traditional Approach (SLOW):                                      │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │ Fuzzer -> mach_msg() -> kernel -> coreaudiod -> handler    │    │
│   │                                                            │    │
│   │ Problems:                                                  │    │
│   │   • Kernel context switching is slow                       │    │
│   │   • Hard to get coverage from separate process             │    │
│   │   • Crashes kill the daemon (need restart)                 │    │
│   └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│   Project Zero Approach (FAST):                                     │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │ Fuzzer -> _HALB_MIGServer_server() directly (in-process)   │    │
│   │                                                            │    │
│   │ Benefits:                                                  │    │
│   │   • No kernel overhead                                     │    │
│   │   • Direct coverage instrumentation                        │    │
│   │   • Can catch crashes and continue                         │    │
│   │   • Much higher throughput                                 │    │
│   └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│   Implementation:                                                   │
│   1. Link fuzzer against CoreAudio framework                        │
│   2. Call _HALB_MIGServer_server() with crafted messages            │
│   3. Use TinyInst for dynamic instrumentation                       │
│   4. Track coverage and evolve inputs                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Harness Structure (Pseudo-code)

```c
void *handle = dlopen("CoreAudio.framework/CoreAudio", RTLD_NOW);
typedef void (*mig_server_t)(mach_msg_header_t *, mach_msg_header_t *);
mig_server_t server = dlsym(handle, "_HALB_MIGServer_server");
// Call server() with mutated messages
```

### Knowledge-Driven Selector Fuzzing

From harness.mm (lines 102-137):

```c
kValidSelectors = {'grup', 'agrp', 'acom', 'mktp', ...}

// 95% probability of using VALID selectors
if (flip_weighted_coin(0.95, fuzz_data)) {
    body[end-16] = choose_one_of(fuzz_data, kValidSelectors);
    body[end-12] = choose_one_of(fuzz_data, kValidScopes);
}
```

**Why 95% valid selectors matters:**
- If selectors were random -> most messages rejected early -> shallow coverage
- With 95% valid -> messages reach complex handler logic -> find deeper bugs

---

## Jackalope Modifications

The mutation strategy uses probability-weighted selection. From `jackalope-modifications/main.cpp`:

```cpp
class BinaryFuzzer : public Fuzzer {
  Mutator *CreateMutator(int argc, char **argv, ThreadContext *tc) override;
  bool TrackHotOffsets() override { return true; }
};

Mutator * BinaryFuzzer::CreateMutator(int argc, char **argv, ThreadContext *tc) {
  // A probability-weighted mutation strategy
  PSelectMutator *pselect = new PSelectMutator();

  // Select one of the mutators below with corresponding probabilities
  pselect->AddMutator(new ByteFlipMutator(), 0.8);          // 80%
  pselect->AddMutator(new ArithmeticMutator(), 0.2);        // 20%
  pselect->AddMutator(new AppendMutator(1, 128), 0.2);      // 20%
  pselect->AddMutator(new BlockInsertMutator(1, 128), 0.1); // 10%
  pselect->AddMutator(new BlockFlipMutator(2, 16), 0.1);    // 10%
  pselect->AddMutator(new BlockFlipMutator(16, 64), 0.1);   // 10%
  pselect->AddMutator(new BlockFlipMutator(1, 64, true), 0.1);
  pselect->AddMutator(new BlockDuplicateMutator(1, 128, 1, 8), 0.05);
  pselect->AddMutator(new BlockDuplicateMutator(1, 16, 1, 64), 0.05);

  // Interesting values (magic numbers, boundary values)
  InterestingValueMutator *iv_mutator = new InterestingValueMutator(true);
  pselect->AddMutator(iv_mutator, 0.1);                     // 10%

  // Splice mutator for corpus cross-pollination
  pselect->AddMutator(new SpliceMutator(1, 0.5), 0.1);      // 10%
  pselect->AddMutator(new SpliceMutator(2, 0.5), 0.1);      // 10%

  // Repeat mutations (multiple mutations per cycle)
  RepeatMutator *repeater = new RepeatMutator(pselect, 0);

  // Default: 1000 iterations per round
  // Mode: Deterministic mutations first, then non-deterministic
  NRoundMutator *mutator = new NRoundMutator(repeater, nrounds);
  return mutator;
}
```

### Fuzzer Configuration

```bash
# Jackalope fuzzer command
$ ./fuzzer -instrument_module CoreAudio \
    -target_module harness -target_method _fuzz -nargs 1 -iterations 1000 \
    -persist -loop -dump_coverage -cmp_coverage -generate_unwind -nthreads 5 \
    -- ./harness -f @@
```

---

## Function Hooks

The `function_hooks.cpp` file intercepts problematic functions to prevent the fuzzer from getting stuck on unrelated crashes.

```cpp
// From jackalope-modifications/function_hooks.cpp

void HALSWriteSettingHook::OnFunctionEntered() {
    printf("HALS_SettingsManager::_WriteSetting Entered\n");

#if defined(__x86_64__)
    if (!GetRegister(RDX)) {  // NULL plist check
        printf("NULL plist passed as argument, returning to prevent NULL CFRelease\n");

        // Skip function, return early
        SetRegister(RAX, 0);
        SetRegister(RIP, GetReturnAddress());
        SetRegister(RSP, GetRegister(RSP) + 8); // Simulate a ret instruction
    }
#elif defined(__arm64__)
    // On Apple Silicon, use X2 instead of RDX, SP instead of RSP, PC instead of RIP
    if (!GetRegister(X2)) {
        printf("NULL plist passed as argument, returning to prevent NULL CFRelease\n");

        SetRegister(X0, 0); // X0 is usually return value on ARM64
        SetRegister(PC, GetReturnAddress());
        SetRegister(SP, GetRegister(SP) + 8); // Simulate a return instruction
    }
#endif
}

FunctionHookInst::FunctionHookInst() {
    printf("Registering function hooks!\n");
    RegisterHook(new HALSWriteSettingHook());
}
```

**Why this hook matters:**
- HALS_SettingsManager::_WriteSetting crashes if passed a NULL plist
- Without the hook, the fuzzer would get stuck on CFRelease crashes
- This allowed the fuzzer to explore deeper into the message handlers

---

## Coverage Metrics and Improvements

The effectiveness of fuzzing can be measured by code coverage:

```
┌─────────────────────────────────────────────────────────────────────┐
│              COVERAGE IMPROVEMENT JOURNEY                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   BASELINE: Random message fuzzing                                  │
│   └── Coverage: ~5% of reachable code                               │
│       Most messages rejected as malformed                           │
│                                                                     │
│   IMPROVEMENT 1: Valid message structure                            │
│   └── Coverage: ~15%                                                │
│       Messages accepted but fail auth/validation                    │
│                                                                     │
│   IMPROVEMENT 2: Client registration                                │
│   └── Coverage: ~30%                                                │
│       Can now reach handlers that require client                    │
│                                                                     │
│   IMPROVEMENT 3: API call chaining                                  │
│   └── Coverage: ~60%                                                │
│       Can create objects and reference them                         │
│                                                                     │
│   IMPROVEMENT 4: Cross-type object ID fuzzing                       │
│   └── Coverage: ~70%+                                               │
│       Tests type confusion scenarios                                │
│       FOUND CVE-2024-54529!                                         │
│                                                                     │
│   Project Zero reported >2000% coverage improvement using these     │
│   techniques compared to naive fuzzing.                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Performance Metrics

| Metric | Value |
|--------|-------|
| Messages/sec per core | ~2,000 |
| With coverage tracking | ~800 messages/sec |
| On 8 cores | ~6,000 messages/sec total |
| Coverage collection overhead | ~50% of iteration time |

---

## Corpus Evolution

"The corpus tells the story of the hunt."

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CORPUS EVOLUTION TIMELINE                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase 0: Initial Corpus (T=0)

| Metric | Value |
|--------|-------|
| Files | 10 hand-crafted Mach messages |
| Coverage | ~2.1% of _HALB_MIGServer_server |
| Message types | XSystem_Open only (basic connection) |

**Example initial corpus file (hexdump):**
```
00000000: 1300 0080 3800 0000  ....8...  ; msgh_bits=0x80001300
00000008: 0000 0000 0000 0000  ........  ; msgh_remote_port, local_port
00000010: 0000 0000 70620f00  ....pb..  ; msgh_voucher, msgh_id=1010000
00000018: 0100 0000 ...       .....     ; descriptor_count=1
```

**Problem:** Messages immediately hit error paths:
- "Client not initialized" -> early return
- "Invalid object ID" -> early return
- "Missing required field" -> early return

Coverage stalled at 2.1% because 97.9% of handler code requires valid state setup first.

### Phase 1: Initialization Fix (T + 1 day)

| Metric | Value |
|--------|-------|
| Files | 15 (+50%) |
| Coverage | ~8.3% (+295% improvement) |
| NEW coverage | XSystem_GetObjectInfo, XDevice_* handlers |

**KEY INSIGHT:** Messages MUST start with XSystem_Open (ID 1010005) to initialize client state.

**Fix Applied:** Hardcoded initialization sequence:
1. Send XSystem_Open -> get client_id
2. Store client_id for subsequent messages
3. Now other handlers accept messages

*This was a HUMAN INSIGHT, not found by blind fuzzing.*

### Phase 2: API Chaining (T + 3 days)

| Metric | Value |
|--------|-------|
| Files | 47 (+213%) |
| Coverage | ~23.7% (+185% improvement) |
| NEW coverage | XIOContext_*, property operations |

**KEY INSIGHT:** Object IDs from creation responses must be captured and reused.

```cpp
// FuzzedDataProvider pattern
uint32_t device_id = created_objects[fdp.ConsumeIntegral<size_t>()
                                     % created_objects.size()];
message.object_id = device_id;
```

### Phase 3: Format Constraints (T + 5 days)

| Metric | Value |
|--------|-------|
| Files | 89 (+89%) |
| Coverage | ~47.2% (+99% improvement) |
| NEW coverage | Deep handler paths, property setters, error conditions |

**KEY INSIGHT:** Valid selectors dramatically reduce early-exit conditions.

Known valid selectors extracted via reverse engineering:
- `'acom'` - Audio component
- `'grup'` - Group
- `'glob'` - Global scope
- `'wild'` - Wildcard
- `'mast'` - Master

### Phase 4: Type Confusion Discovery (T + 8 days)

| Metric | Value |
|--------|-------|
| Files | 142 (+60%) |
| Coverage | ~52.8% (+12% improvement) |
| Unique crashes | 47 total, 12 security-relevant after triage |

**THE BUG WAS FOUND when the fuzzer:**
1. Created an Engine object (ID = 0x3000)
2. Sent XIOContext_Fetch_Workgroup_Port with object_id = 0x3000
3. Handler expected IOContext, got Engine
4. CRASH at dereference of uninitialized memory

**Crash signature:**
```
Thread 0 Crashed:: Dispatch queue: com.apple.main-thread
0   CoreAudio    0x00007ff813a4b2c4 _XIOContext_Fetch_Workgroup_Port + 68
1   CoreAudio    0x00007ff813a3f1e0 _HALB_MIGServer_server + 1200

Crash address: 0xaaaaaaaaaaaaaaaa (MallocPreScribble pattern!)
```

### Coverage Metrics Summary

```
┌─────────────┬──────────┬──────────────┬────────────────────────────┐
│ Phase       │ Coverage │ Corpus Size  │ Key Unlocking Insight      │
├─────────────┼──────────┼──────────────┼────────────────────────────┤
│ Initial     │ 2.1%     │ 10 files     │ None (blind)               │
│ Phase 1     │ 8.3%     │ 15 files     │ Init sequence required     │
│ Phase 2     │ 23.7%    │ 47 files     │ Object ID reuse            │
│ Phase 3     │ 47.2%    │ 89 files     │ Valid selectors/scopes     │
│ Phase 4     │ 52.8%    │ 142 files    │ Type confusion attempts    │
└─────────────┴──────────┴──────────────┴────────────────────────────┘

TOTAL IMPROVEMENT: 52.8% / 2.1% = 25x (2400% improvement)
TIME TO BUG: 8 days (with knowledge-driven approach)
```

### Differential Coverage Analysis

**Blind Fuzzing (baseline):**
```bash
$ ./fuzzer -t 100000 -corpus blind_corpus/
# After 100,000 iterations:
Coverage: 2.1%
Crashes: 3 (all NULL deref, not security-relevant)
XIOContext handlers reached: 0%
```

**Knowledge-Driven Fuzzing:**
```bash
$ ./fuzzer -t 100000 -corpus smart_corpus/
# After 100,000 iterations:
Coverage: 52.8%
Crashes: 47 (12 security-relevant)
XIOContext handlers reached: 78.3%
```

**CRITICAL INSIGHT:** Blind fuzzing would NEVER have found this bug. The initialization requirements create a "coverage wall" that random mutation cannot penetrate.

---

## Crash Triage Methodology

Of 47 crashes found, here's how they were triaged:

### Step 1: Deduplicate by Crash Location

```bash
$ for f in crashes/*.bin; do
    addr=$(atos -o CoreAudio -l 0x0 $(head -1 "$f" | grep -oE '0x[0-9a-f]+') 2>/dev/null)
    echo "$addr $(basename $f)"
  done | sort | uniq -c | sort -rn
```

Result: 47 crashes -> 18 unique crash sites

### Step 2: Categorize by Root Cause

```
┌──────────────────────────────────────────────────────────────────────┐
│ Category                 │ Count │ Exploitable │ Example             │
├──────────────────────────┼───────┼─────────────┼─────────────────────┤
│ NULL dereference         │ 6     │ Usually No  │ Missing object      │
│ Uninitialized read       │ 4     │ YES         │ CVE-2024-54529!     │
│ Out-of-bounds read       │ 3     │ Maybe       │ Array index         │
│ Type confusion           │ 3     │ YES         │ Wrong object type   │
│ Use-after-free           │ 1     │ YES         │ Race condition      │
│ Stack buffer overflow    │ 1     │ YES         │ String copy         │
└──────────────────────────┴───────┴─────────────┴─────────────────────┘
```

### Step 3: Prioritize by Exploitability

| Priority | Category | Reason |
|----------|----------|--------|
| TOP | Type confusion + uninit read | CVE-2024-54529 |
| HIGH | UAF and stack overflow | Direct code execution potential |
| MEDIUM | OOB read | Info leak potential |
| LOW | NULL deref | DoS only |

### Step 4: Minimize Reproducer

```bash
$ ./minimizer -input crash_large.bin -output crash_min.bin
```

For CVE-2024-54529:
- Original crash input: 2,847 bytes
- Minimized input: 127 bytes (4.5% of original)

The minimized input showed:
1. XSystem_Open (init)
2. XDevice_CreateEngine (create Engine, get ID=0x3000)
3. XIOContext_Fetch_Workgroup_Port(object_id=0x3000) <- BOOM

### Crash Analysis Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│              CRASH ANALYSIS WORKFLOW                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   STEP 1: CRASH TRIAGE                                              │
│   • Is it reproducible?                                             │
│   • What's the crash signature?                                     │
│   • Is it a null deref, wild pointer, or controlled?                │
│   • Does ASAN/Guard Malloc reveal more?                             │
│                                                                     │
│   STEP 2: ROOT CAUSE ANALYSIS                                       │
│   • Why did this happen?                                            │
│   • What assumption was violated?                                   │
│   • What's the underlying bug class?                                │
│                                                                     │
│   STEP 3: EXPLOITABILITY ASSESSMENT                                 │
│   • Can we control the corrupted data?                              │
│   • What primitives does this give us?                              │
│   • Are there mitigations to bypass?                                │
│                                                                     │
│   STEP 4: EXPLOIT DEVELOPMENT                                       │
│   • Develop heap grooming strategy                                  │
│   • Build ROP chain for code execution                              │
│   • Stabilize and increase reliability                              │
│   • Write exploit code and PoC                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Setting Up a Fuzzing Environment

### Step 1: Clone and Build TinyInst

```bash
$ git clone --recursive https://github.com/googleprojectzero/TinyInst
$ cd TinyInst
$ mkdir build && cd build
$ cmake -G Ninja ..
$ ninja
```

### Step 2: Create a Fuzzing Harness

The harness needs to:
1. Load CoreAudio.framework
2. Find the _HALB_MIGServer_server function
3. Call it directly with crafted messages
4. Track coverage and crashes

### Step 3: Generate Valid Message Structures

Use the message structures from:
- `exploit/exploit.mm`, lines 640-750 (message struct definitions)
- `helpers/message_ids.h` (message ID enumeration)

### Step 4: Implement API Call Chaining

Track object IDs returned by creation messages. When fuzzing handlers that take object IDs:
- Try valid IDs of correct type
- Try valid IDs of WRONG type (type confusion!)
- Try invalid IDs (null, -1, huge numbers)

### Step 5: Run with Coverage Tracking

```bash
$ ./tinyinst -instrument_module CoreAudio \
    -coverage_file coverage.txt \
    -- ./harness
```

### Step 6: Analyze Crashes

```bash
$ lldb ./harness
(lldb) run < crash-xxx
(lldb) bt
```

### Step 7: Enable Guard Malloc

```bash
$ export MallocPreScribble=1
$ export MallocScribble=1
$ ./harness < crash-xxx
```

Uninitialized memory shows as 0xAAAA... pattern.

### Commands to Reproduce Coverage Analysis

```bash
# Generate coverage with TinyInst
$ ./fuzzer -instrument_module CoreAudio \
    -coverage_file cov.txt \
    -corpus corpus/ \
    -t 10000

# Count unique coverage points
$ wc -l cov.txt

# Map coverage addresses to functions
$ for addr in $(cat cov.txt | head -1000); do
    atos -o /System/Library/Frameworks/CoreAudio.framework/CoreAudio \
         -l 0x0 $addr 2>/dev/null
  done | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -20

# Generate HTML coverage report (if using LLVM coverage)
$ llvm-cov show ./harness -instr-profile=cov.profdata -format=html > cov.html
```

---

## Common Fuzzing Mistakes

### 1. Not Initializing State Properly Between Iterations

**Problem:** The fuzzer accumulates state from previous iterations, causing non-reproducible behavior.

**Symptoms:**
- Same input produces different results
- Crashes that can't be reproduced
- Coverage numbers fluctuate wildly

**Solution:**
```cpp
// Reset state at the start of each iteration
void reset_fuzzer_state() {
    // Clear any created objects
    created_objects.clear();

    // Reset client connection
    if (client_initialized) {
        close_client();
        client_initialized = false;
    }

    // Optionally: fork() before each iteration for clean slate
}
```

### 2. Wrong Message ID Sequences

**Problem:** Sending messages in invalid order causes early rejection, wasting fuzzer cycles.

**Symptoms:**
- Coverage stuck at very low percentage
- Most messages return error codes
- Never reaching interesting handlers

**Solution:**
```cpp
// Always initialize before fuzzing other handlers
void fuzz_iteration() {
    // Step 1: Required initialization
    send_XSystem_Open();

    // Step 2: Create required objects
    uint32_t engine_id = send_XDevice_CreateEngine();

    // Step 3: NOW fuzz the interesting handlers
    fuzz_XIOContext_handlers(engine_id);
}
```

### 3. Not Using Sanitizers (MallocScribble, etc.)

**Problem:** Memory corruption bugs may not crash immediately, hiding real issues.

**Symptoms:**
- Strange behavior that's hard to explain
- Crashes in unrelated code
- Missing bugs that exist

**Solution:**
```bash
# Enable memory debugging
export MallocPreScribble=1    # Fill new allocations with 0xAA
export MallocScribble=1       # Fill freed allocations with 0x55
export MallocGuardEdges=1     # Detect buffer overflows
export MallocCheckHeapStart=1 # Verify heap on each allocation

# Or use AddressSanitizer for compiled code
clang -fsanitize=address -g target.c -o target
```

### 4. Ignoring Coverage Feedback

**Problem:** Generating random inputs without tracking which ones explore new code paths.

**Symptoms:**
- Running for hours with no new coverage
- Finding the same trivial bugs repeatedly
- Missing deep, interesting bugs

**Solution:**
```cpp
// Use coverage to guide input selection
void update_corpus(Sample *sample, CoverageInfo *cov) {
    if (cov->has_new_edges()) {
        // This input found new code paths - save it!
        corpus.add(sample);
        printf("New coverage! Total edges: %zu\n", cov->total_edges());
    }
}
```

### 5. Poor Corpus Management

**Problem:** Corpus grows unbounded with redundant samples, slowing down fuzzing.

**Symptoms:**
- Fuzzer getting slower over time
- Disk filling up with corpus files
- Mutation wasting time on redundant inputs

**Solution:**
```bash
# Periodically minimize corpus
$ afl-cmin -i corpus_large/ -o corpus_min/ -- ./harness @@

# Remove samples that don't add coverage
$ ./fuzzer -minimize -corpus corpus/ -output corpus_min/

# Keep corpus size manageable (100-1000 files typically)
```

### Fuzzing Checklist

| Check | Description |
|-------|-------------|
| [ ] State reset | Clean state between iterations |
| [ ] Init sequence | Proper message ordering |
| [ ] Sanitizers | MallocScribble or ASAN enabled |
| [ ] Coverage tracking | Know which code you're hitting |
| [ ] Corpus management | Regular minimization |
| [ ] Valid selectors | Use knowledge-driven approach |
| [ ] Object ID tracking | Record and reuse created objects |
| [ ] Type confusion tests | Deliberately use wrong types |

---

## References

- Project Zero Blog: [Breaking the Sound Barrier Part I: Fuzzing](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- TinyInst: https://github.com/googleprojectzero/TinyInst
- CoreAudioFuzz: https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz
- AFL++: https://github.com/AFLplusplus/AFLplusplus
- libFuzzer: https://llvm.org/docs/LibFuzzer.html

---

**Navigation:** [README](README.md) | [Previous: 00-introduction](00-introduction.md) | Next: 07-defensive-lessons (coming soon)
