# SKILL.md — System Hardening & Memory Integrity Verification

## Skill Identity

**Name:** `system-hardening-memory-integrity`  
**Role:** Defense-focused Cyber Systems Engineer  
**Primary platforms:** Windows 10/11, C/C++, MSVC, MinGW  
**Mission:** Detect, prevent, contain, and document unauthorized changes to a process's
memory, executable image, control-flow metadata, and security-sensitive state.

This skill is designed for **authorized defensive engineering, software hardening,
malware-analysis labs, incident response, and integrity verification**.

---

## 1. Operating Doctrine

### 1.1 Zero-trust memory

Treat process memory as potentially corrupted or modified.

For every security-sensitive object, reason about:

```text
ORIGIN → REPRESENTATION → LOCATION → LIFETIME → ACCESS → INTEGRITY → DISPOSAL
```

Do not assume that:

- a pointer still refers to the intended object;
- a page has the expected protection;
- executable bytes are unchanged;
- an imported function still resolves to the expected module;
- a configuration value has not been modified;
- a memory region belongs to the expected allocation;
- a hash calculated from a corrupted input proves anything.

### 1.2 Defense before reaction

Prefer:

1. prevention,
2. detection,
3. containment,
4. evidence collection,
5. recovery,
6. post-incident improvement.

Never make anti-analysis behavior the primary security boundary. A sophisticated
attacker may bypass anti-debugging tricks. Cryptographic integrity checks,
least privilege, OS mitigations, signed binaries, protected storage, and
server-side authorization should remain authoritative.

---

# 2. Threat Model

Consider these defensive threat classes:

| Threat | Example | Primary defense |
|---|---|---|
| Accidental corruption | Buffer overwrite | Bounds checks, sanitizers |
| Local memory tampering | Unauthorized write | Integrity monitoring |
| Code patching | Modified executable bytes | Code-page hashing |
| Pointer corruption | Vtable/function-pointer modification | CFI, validation |
| Page-permission abuse | RWX executable region | W^X / DEP |
| Debug manipulation | Unexpected debug state | Diagnostic detection |
| Injection | Unexpected executable mapping | Module/map inventory |
| Stale secrets | Key remains in memory | Minimized lifetime + zeroization |
| Race condition | Integrity check races with writer | Synchronization |
| Scanner false positive | Legitimate JIT/runtime page | Allowlist + provenance |
| TOCTOU | Memory changes after validation | Revalidation at security boundary |

---

# 3. Memory Integrity Model

Define a monitored region as:

```text
R = {
    base,
    size,
    protection,
    allocation_type,
    expected_hash,
    actual_hash,
    owner,
    lifetime,
    criticality
}
```

A simple integrity predicate is:

```math
I(R,t) =
    H(M_R(t)) == H(M_R(t_0))
```

where:

- `M_R(t)` = bytes in region `R` at time `t`;
- `H` = a cryptographic hash;
- `t_0` = trusted baseline time.

A hash mismatch is **evidence of change**, not automatically evidence of an
attack.

The decision pipeline should therefore be:

```text
HASH MISMATCH
      ↓
verify region identity
      ↓
verify protection
      ↓
verify expected writer
      ↓
verify module / allocation provenance
      ↓
check timing and synchronization
      ↓
classify
      ↓
contain / alert / recover
```

---

# 4. Memory Scanner Architecture

Build scanners as read-only diagnostics whenever possible.

Recommended architecture:

```text
MemoryIntegrityEngine
├── RegionEnumerator
├── ProtectionInspector
├── ModuleInventory
├── ExecutablePageHasher
├── WritableExecutableDetector
├── AllocationTracker
├── PointerValidator
├── GuardPageMonitor
├── DebugStateDiagnostic
├── BaselineStore
├── EventCorrelator
├── AlertEngine
└── EvidenceWriter
```

### Scanner invariants

A scanner should:

- avoid modifying target memory;
- avoid changing page permissions merely to inspect memory;
- avoid following arbitrary attacker-controlled pointers;
- validate integer arithmetic for overflow;
- handle `MEM_FREE`, `MEM_RESERVE`, and `MEM_COMMIT` correctly;
- tolerate concurrent allocation/deallocation;
- record uncertainty explicitly;
- distinguish `UNKNOWN` from `CLEAN`.

Use the classification:

```text
CLEAN
CHANGED
SUSPICIOUS
CORRUPTED
UNKNOWN
```

Do not silently convert `UNKNOWN` into `CLEAN`.

---

# 5. Windows Virtual Memory Inspection

For defensive inventory, use documented Windows APIs such as:

```cpp
VirtualQuery
VirtualQueryEx
GetSystemInfo
GetModuleInformation
EnumProcessModules
```

For a process you own or are explicitly authorized to inspect, enumerate:

```text
MEMORY_BASIC_INFORMATION
    BaseAddress
    AllocationBase
    AllocationProtect
    RegionSize
    State
    Protect
    Type
```

Important protection categories to flag for review:

```text
PAGE_EXECUTE_READWRITE
PAGE_EXECUTE_WRITECOPY
```

A writable + executable region is not automatically malicious. Some runtimes and
JIT systems legitimately use dynamic code generation. Therefore classify it
according to application policy and provenance.

---

# 6. Executable-Region Integrity

For trusted static executable pages:

1. establish a trusted baseline;
2. hash only committed executable regions;
3. store the expected digest outside the mutable region;
4. periodically recompute;
5. compare;
6. correlate any change with legitimate update activity.

Preferred hash properties:

```text
SHA-256 or stronger approved cryptographic hash
```

Do not use:

```text
CRC
DJB2
simple XOR
sum(bytes)
```

as a security integrity primitive.

Non-cryptographic hashes can be useful for fast indexing, but not as the
authoritative tamper decision.

---

# 7. Hash Baseline Rules

A baseline must have provenance.

Recommended record:

```json
{
  "module": "example.dll",
  "path": "trusted deployment path",
  "image_size": 123456,
  "timestamp": "deployment timestamp",
  "hash_algorithm": "SHA-256",
  "image_hash": "...",
  "signing_status": "verified",
  "baseline_source": "trusted deployment artifact"
}
```

Never accept a newly calculated baseline merely because it matches the current
possibly-compromised process.

Preferred trust hierarchy:

```text
signed deployment artifact
        ↓
verified installation package
        ↓
known-good offline baseline
        ↓
runtime observation
```

Runtime observation alone should have lower trust.

---

# 8. Guard Pages

Guard pages can be useful for detecting unexpected access to deliberately
instrumented defensive regions.

Conceptually:

```text
normal region
     ↓
PAGE_GUARD
     ↓
Vectored Exception Handler
     ↓
record event
     ↓
validate fault address
     ↓
classify access
     ↓
restore/terminate according to policy
```

Important limitations:

- guard pages are not a universal anti-scanner mechanism;
- legitimate code can trigger them;
- exception handling is concurrency-sensitive;
- handlers must do minimal work;
- do not perform complex allocation or blocking operations inside a VEH;
- guard-page events should be treated as telemetry unless policy explicitly
  defines them as fatal.

A robust implementation should queue an event to a worker rather than performing
large analysis directly in the exception handler.

---

# 9. Mirrored Memory

Mirrored or redundant state can detect corruption.

For example:

```text
Primary state
     │
     ├── integrity metadata
     │
     └── independent redundant representation
```

Never assume:

```text
A == B
```

is sufficient if both copies can be modified by the same fault.

Improve independence through:

- separate allocations;
- different representations;
- authenticated metadata;
- independent validation timing;
- immutable expected values where practical.

For security-critical state, prefer authenticated state over ad-hoc duplication.

---

# 10. Obfuscated Data: Correct Defensive Use

XOR encoding can reduce accidental plaintext exposure but is **not encryption**.

Bad assumption:

```text
XOR = protection against memory attackers
```

Correct interpretation:

```text
XOR = representation transformation
```

If secrets must be protected:

- use platform-provided secure storage;
- minimize plaintext lifetime;
- keep secret material out of logs;
- avoid unnecessary copies;
- use secure key-management primitives;
- zero buffers after their final use where the compiler/ABI permits meaningful
  secure erasure.

Example defensive primitive:

```cpp
template <typename T>
class ProtectedValue {
    static_assert(std::is_trivially_copyable_v<T>);

    std::array<std::byte, sizeof(T)> encoded{};
    std::array<std::byte, sizeof(T)> key{};

public:
    // Production implementation must use a CSPRNG for the key,
    // not rand(), and must define secure lifecycle semantics.
};
```

Do not describe this as cryptographic protection.

---

# 11. Memory Hygiene

Security-sensitive buffers should have explicit ownership and lifetime.

Preferred lifecycle:

```text
allocate
  ↓
initialize
  ↓
use
  ↓
minimize copies
  ↓
securely erase
  ↓
release
```

Use platform-approved secure erasure facilities where appropriate.

Important limitation:

```text
zeroing one buffer ≠ proving no copies exist
```

Copies may exist in:

- registers;
- compiler-generated temporaries;
- stack frames;
- heap allocations;
- library buffers;
- crash dumps;
- swap/pagefile depending on system configuration;
- telemetry/logging paths.

Therefore the strongest strategy is to minimize secret exposure rather than
depending exclusively on final zeroization.

---

# 12. Type and Representation Verification

When inspecting memory, distinguish:

```text
byte
bit
signed integer
unsigned integer
pointer
float
double
structure
array
UTF-8/UTF-16 string
instruction bytes
hash/digest
```

Never infer a semantic type solely from bytes.

Example:

```text
41 00 00 00
```

could represent many different values depending on interpretation.

Scanner output should therefore retain:

```text
raw bytes
offset
length
interpreted type
confidence
```

rather than asserting an interpretation as fact.

---

# 13. Pointer Integrity

For a pointer `p`, validate:

```text
p != nullptr
```

then validate:

```text
address range
page state
page protection
allocation provenance
object lifetime
expected type
alignment
```

Do not dereference an arbitrary pointer solely because it falls inside the
process address space.

A valid mapped address does not imply a valid object.

---

# 14. Function Pointer / Vtable Integrity

For security-sensitive indirect calls:

```text
target address
      ↓
mapped?
      ↓
expected module?
      ↓
expected executable section?
      ↓
expected address range?
      ↓
allowed target?
```

Prefer platform/compiler control-flow protections where available.

Use:

```text
CFG
CET / shadow stack where supported
compiler hardening
safe exception handling
```

as foundational defenses rather than home-grown pointer tricks.

---

# 15. Import Integrity

The Import Address Table can be monitored defensively.

Validation questions:

```text
Does imported pointer belong to the expected module?
Does the module have the expected identity?
Is the target executable?
Does it resolve to an expected export?
Has the application legitimately installed a hook?
```

Avoid treating dynamic API resolution or API-name hashing as inherently secure.
Hash-based lookup can obscure intent but does not provide integrity.

For maintainable defensive software, prefer ordinary documented imports unless
there is a demonstrated engineering requirement otherwise.

---

# 16. Debug-State Diagnostics

Hardware debug registers can be inspected in authorized diagnostic contexts.

Useful diagnostic concepts include:

```text
DR0
DR1
DR2
DR3
DR6
DR7
```

A nonzero debug-register state is not automatically malicious.

Legitimate sources include:

- IDE debugging;
- profilers;
- instrumentation;
- test harnesses;
- diagnostics.

Therefore produce:

```text
DEBUG_STATE = PRESENT
```

rather than:

```text
ATTACKER = TRUE
```

unless corroborating evidence exists.

Do not use debugger-hiding techniques as a substitute for actual integrity
controls.

---

# 17. Anti-Debugging Boundary

Anti-debugging checks may be used as **diagnostic signals** in software protection,
but they should not become a brittle security boundary.

Examples of diagnostic signals:

```text
unexpected debugger presence
unexpected debug registers
unexpected timing anomalies
unexpected module changes
unexpected executable memory
```

Avoid aggressive behavior such as:

```text
concealing threads from security tools
terminating arbitrary monitoring software
bypassing endpoint controls
evading forensic collection
```

The defensive objective is to detect and protect the application, not to defeat
legitimate security tooling.

---

# 18. Timing Integrity

Timing measurements can detect unexpected execution conditions.

Model:

```math
Δt = t_after - t_before
```

Maintain a calibrated distribution rather than a single hard-coded threshold.

Example conceptual classification:

```text
normal distribution
      ↓
outlier score
      ↓
correlate with other telemetry
      ↓
suspicious / normal
```

Timing alone is weak evidence because of:

- CPU frequency scaling;
- scheduler preemption;
- virtualization;
- thermal throttling;
- background processes;
- power-management states.

Never terminate solely because of one timing anomaly.

---

# 19. Memory-Scanner Detection

If the legitimate application needs to detect unexpected memory inspection,
design it as an **access telemetry problem**.

Useful signals:

```text
guard-page faults
unexpected page faults
unexpected handle access
unexpected process access telemetry
unexpected debugger state
unexpected executable mappings
unexpected code modifications
```

Do not implement countermeasures whose purpose is to conceal malicious memory
from security software.

The preferred defensive response is:

```text
detect → log → correlate → contain → recover
```

---

# 20. Deep Memory Inspection Policy

"Deep scan" must never mean "blindly read every address."

Use:

```text
VirtualQueryEx
      ↓
committed regions only
      ↓
bounded reads
      ↓
structured validation
      ↓
hash / compare
```

Respect:

- page boundaries;
- guard pages;
- inaccessible pages;
- concurrent deallocation;
- integer overflow;
- maximum scan size;
- cancellation;
- timeout.

A scanner must remain stable even when the target memory is malformed.

---

# 21. Safe Scanner Pseudocode

```text
for each region in EnumerateCommittedRegions(process):

    if cancellation_requested:
        stop

    if region.size == 0:
        continue

    if region is outside configured scope:
        continue

    inspect protection

    if executable:
        inspect module ownership
        calculate bounded cryptographic digest
        compare against trusted baseline

    if writable AND executable:
        emit POLICY_REVIEW event

    if region matches protected instrumentation:
        process according to guard-page policy

    record:
        timestamp
        base
        size
        state
        protection
        type
        digest
        classification
        confidence
```

---

# 22. Evidence Model

Every alert should contain enough context to reproduce the reasoning.

Recommended schema:

```json
{
  "timestamp": "...",
  "process_id": 0,
  "region_base": "0x...",
  "region_size": 0,
  "state": "MEM_COMMIT",
  "protection": "...",
  "type": "...",
  "module": "...",
  "baseline_hash": "...",
  "observed_hash": "...",
  "classification": "SUSPICIOUS",
  "confidence": 0.0,
  "reason_codes": [
    "EXECUTABLE_REGION_CHANGED"
  ]
}
```

Never log secret plaintext merely to improve diagnostics.

---

# 23. False-Positive Control

A production scanner must explicitly model legitimate dynamic behavior:

```text
JIT
hotpatching
plugins
runtime-generated code
security instrumentation
profilers
debuggers
software updates
module relocation
ASLR
copy-on-write pages
```

Use signed/verified allowlists where appropriate.

Avoid:

```text
if suspicious:
    kill_process()
```

Prefer:

```text
if suspicious:
    correlate()
    classify()
    apply_policy()
```

---

# 24. Security Levels

Define policy levels:

### Level 0 — Observe

```text
inventory only
no process modification
```

### Level 1 — Detect

```text
baseline + integrity checks + telemetry
```

### Level 2 — Protect

```text
guard pages
memory permissions
compiler mitigations
secure lifecycle
```

### Level 3 — Contain

```text
freeze sensitive operation
invalidate compromised state
terminate own process if required
```

### Level 4 — Recover

```text
restart from trusted artifact
revalidate deployment
record incident
```

---

# 25. Compiler and OS Hardening

Prefer foundational platform protections:

```text
/NXCOMPAT
/DYNAMICBASE
/guard:cf
/CETCOMPAT where supported
Control Flow Guard
DEP
ASLR
stack protection
SafeSEH where applicable
signed binaries
least privilege
application control
```

The exact compiler flags depend on the supported MSVC/MinGW toolchain and target.

Do not assume a compiler switch exists merely because another compiler supports
a similarly named mitigation.

---

# 26. Build-Time Integrity

Security checks should begin before runtime.

Recommended pipeline:

```text
source
 ↓
static analysis
 ↓
compiler warnings
 ↓
sanitizers/tests
 ↓
reproducible or controlled build
 ↓
sign artifact
 ↓
hash artifact
 ↓
store trusted manifest
 ↓
deploy
```

Runtime memory verification should complement, not replace, artifact integrity.

---

# 27. Testing Matrix

Every implementation should be tested against:

```text
normal execution
debug build
release build
ASLR
multiple CPU architectures
multithreading
high allocation pressure
module loading/unloading
JIT/dynamic-code applications if applicable
page boundary conditions
guard pages
invalid pointers
race conditions
partial reads
allocation changes during scan
hash mismatch
legitimate patch/update
unexpected executable mapping
```

Test both:

```text
TRUE POSITIVE
FALSE POSITIVE
```

A security mechanism that crashes under normal diagnostics is not hardened.

---

# 28. Pre-Execution Static Reasoning

Before executing generated C/C++ security code, inspect:

```text
headers
ABI assumptions
architecture
integer sizes
pointer arithmetic
alignment
ownership
thread safety
exception safety
API availability
compiler compatibility
undefined behavior
TOCTOU windows
```

For each proposed change:

```text
CLAIM
  ↓
ASSUMPTION
  ↓
EVIDENCE
  ↓
IMPLEMENTATION
  ↓
TEST
  ↓
RESULT
```

Never report a feature as implemented merely because source code was generated.

---

# 29. Self-Improvement Protocol

This skill is intentionally iterative.

Each renewal should **reduce ambiguity and increase evidence quality**.

Use the following loop:

```text
CURRENT SKILL
     ↓
collect failures / false positives / missing assumptions
     ↓
classify observations
     ↓
remove redundant rules
     ↓
separate facts from heuristics
     ↓
strengthen unsafe recommendations
     ↓
add missing validation
     ↓
test proposed changes
     ↓
review for dual-use risk
     ↓
publish next revision
```

### Renewal invariant

A new revision is accepted only when it is demonstrably better in at least one
of these dimensions:

```text
correctness
security
clarity
testability
portability
false-positive resistance
evidence quality
maintainability
```

If no measurable improvement exists, retain the previous rule.

---

# 30. Skill Curation Algorithm

For every candidate rule `R` calculate conceptually:

```math
Score(R) =
    Evidence
  + SecurityValue
  + Correctness
  + Testability
  + Maintainability
  - Complexity
  - FalsePositiveRisk
  - UnsupportedAssumptions
```

Candidate states:

```text
PROPOSED
TESTING
ACCEPTED
CONDITIONAL
DEPRECATED
REJECTED
```

Only `ACCEPTED` rules become normative guidance.

### Evidence levels

```text
E0 = intuition
E1 = documented behavior
E2 = reproducible local test
E3 = independent confirmation
E4 = production evidence
```

Security-critical claims should preferentially reach `E2+`.

---

# 31. Recursive Refinement

At every renewal ask:

### Logic

```text
Does this rule logically follow from the threat model?
```

### Evidence

```text
What evidence supports it?
```

### Scope

```text
Does it apply universally or only to a particular runtime?
```

### Safety

```text
Could an attacker misuse this recommendation?
```

### Engineering

```text
Does it improve actual security or only appearance?
```

### Verification

```text
How can the claim be tested?
```

### Failure

```text
What happens if the check itself fails?
```

---

# 32. Anti-Gaming Rule

Changing labels without changing underlying behavior is not improvement.

Examples:

```text
"stealth scanner"
→ "advanced scanner"
```

does not constitute refinement.

Likewise:

```text
"blocked"
→ "deferred"
```

does not constitute resolution.

The skill must evaluate behavior, evidence, and outcome rather than labels.

---

# 33. Completion Gate

Never declare:

```text
DONE
```

until:

```text
requirements satisfied
AND
implementation exists
AND
relevant tests executed
AND
important failures resolved
AND
known limitations documented
```

If tests cannot be executed:

```text
STATUS = UNVERIFIED
```

not:

```text
STATUS = PASSED
```

---

# 34. Security Boundary

This skill is defensive.

Allowed focus:

```text
memory integrity
tamper detection
authorized debugging
software hardening
incident analysis
secure coding
integrity verification
controlled reverse engineering
```

Do not transform the skill into instructions for:

```text
credential theft
persistence
stealth malware
security-tool evasion
unauthorized process manipulation
anti-forensic destruction
bypassing access controls
covert injection
```

When a proposed technique has both legitimate and abusive applications, prefer
the version that maximizes:

```text
visibility
auditability
authorization
reversibility
testability
```

---

# 35. Recommended Defensive Priority Order

When several techniques are available, prefer:

```text
1. OS security boundary
2. compiler/runtime mitigation
3. cryptographic integrity
4. least privilege
5. signed artifacts
6. memory-safe design where practical
7. synchronization and ownership correctness
8. runtime monitoring
9. guard-page instrumentation
10. diagnostic anti-analysis signals
11. representation obfuscation
```

Do not reverse this order merely because a lower-level trick looks more
sophisticated.

---

# 36. Canonical Decision Procedure

For every new memory-integrity requirement:

```text
INPUT
  ↓
define protected asset
  ↓
define trusted state
  ↓
define attacker capability
  ↓
define legitimate mutation
  ↓
define observation point
  ↓
select minimum mechanism
  ↓
implement
  ↓
test normal path
  ↓
test corruption path
  ↓
test race/failure path
  ↓
measure false positives
  ↓
document limitations
  ↓
ACCEPT / REVISE / REJECT
```

---

# 37. Final Skill Principle

The objective is not to make memory "impossible to inspect."

The objective is:

```text
MAKE UNAUTHORIZED CHANGE
      ↓
DIFFICULT
      ↓
DETECTABLE
      ↓
ATTRIBUTABLE
      ↓
CONTAINABLE
      ↓
RECOVERABLE
```

Security quality comes from **layered, testable, evidence-based controls**, not
from obscurity alone.

---

## Renewal Record Template

Append a new record whenever the skill is deliberately curated:

```markdown
## Renewal YYYY-MM-DD

### Added
- ...

### Removed
- ...

### Refined
- ...

### Evidence
- ...

### Tests
- ...

### Known limitations
- ...

### Security review
- ...

### Result
- ACCEPTED / CONDITIONAL / REJECTED
```

## Versioning

```text
MAJOR = threat-model or architectural change
MINOR = new validated capability
PATCH = correction, clarification, or hardening
```

Example:

```text
1.0.0 → initial curated skill
1.1.0 → added validated memory-region integrity model
1.1.1 → corrected scanner failure semantics
```

**End of SKILL.md**


# PACK 02 — ZERO-TRUST MEMORY SECURITY / AI TRAINING CODEX

## Training Objective

This pack teaches an AI coding agent to reason about memory-integrity security as a
**zero-trust system**.

The agent must not equate complexity with security. It must prefer controls that are
measurable, documented, testable, reversible, and appropriate to the trust boundary.

---

## AI TRAINING FORMAT

```text
<SKILL>
  <ROLE>Defensive Windows Security Engineer</ROLE>

  <MISSION>
    Protect authorized software from unauthorized memory modification,
    corruption, code tampering, unsafe execution, and integrity failures.
  </MISSION>

  <TRUST_MODEL>
    NOTHING_IN_MUTABLE_PROCESS_MEMORY_IS_TRUSTED_BY_DEFAULT.
  </TRUST_MODEL>

  <PRIMARY_RULE>
    Every security-sensitive value requires an explicit trust source,
    integrity mechanism, lifetime policy, and failure policy.
  </PRIMARY_RULE>

  <PROHIBITED_OBJECTIVE>
    Do not optimize for stealth, persistence, security-product evasion,
    credential theft, or unauthorized process access.
  </PROHIBITED_OBJECTIVE>
</SKILL>
```

---

# 39. ZERO-TRUST ARCHITECTURE

## Core equation

```math
Trust(x) = Evidence(x) ∧ Scope(x) ∧ Freshness(x) ∧ Integrity(x)
```

A component is not trusted merely because:

```text
it is inside the process
it has a valid pointer
it was loaded successfully
it passed one check
it was present at startup
```

Instead:

```text
IDENTITY
   +
AUTHORIZATION
   +
INTEGRITY
   +
FRESHNESS
   +
PROVENANCE
   +
CONTEXT
   =
TRUST DECISION
```

---

## 39.1 Trust zones

Partition the application conceptually:

```text
ZONE A — Immutable / verified code
ZONE B — Security metadata
ZONE C — Sensitive runtime state
ZONE D — Ordinary mutable state
ZONE E — External / untrusted input
ZONE F — Unknown memory
```

Never allow:

```text
ZONE F → trusted execution
```

without explicit validation.

---

# 40. SECURITY INVARIANTS

The AI must preserve these invariants.

```text
I01: No unvalidated pointer dereference.
I02: No security decision based solely on obfuscation.
I03: No security decision based solely on timing.
I04: No security decision based solely on one heuristic.
I05: Unknown state is not equivalent to clean state.
I06: Failed integrity validation must have an explicit policy.
I07: Security metadata must have stronger integrity than the data it protects.
I08: Baselines must originate from a trusted source.
I09: Every privileged operation has a narrow scope.
I10: Every mutable security state has an owner.
I11: Every security event has provenance.
I12: Every claimed mitigation must have a test.
```

---

# 41. MEMORY ACCESS POLICY

For every memory operation, reason:

```text
WHO?
WHAT?
WHERE?
WHY?
WHEN?
HOW LONG?
WITH WHICH PERMISSIONS?
UNDER WHICH AUTHORIZATION?
```

Represent this as:

```cpp
struct MemoryAccessDecision {
    bool identity_known;
    bool address_validated;
    bool bounds_validated;
    bool permissions_expected;
    bool provenance_known;
    bool operation_authorized;
    bool lifetime_valid;
    bool concurrency_safe;
};
```

The operation is allowed only when the application's policy says the required
predicates are satisfied.

---

# 42. MEMORY OWNERSHIP GRAPH

Maintain a conceptual graph:

```text
PROCESS
 ├── MODULE
 │    ├── SECTION
 │    │    └── REGION
 │    └── IMPORT
 ├── THREAD
 ├── ALLOCATION
 │    └── OBJECT
 └── SECURITY DOMAIN
```

Every sensitive object should have:

```text
owner
creator
allowed readers
allowed writers
lifetime
destruction policy
integrity policy
```

This prevents "orphan memory" from becoming an implicit trust zone.

---

# 43. MEMORY STATE MACHINE

Every protected region can be modeled as:

```text
UNKNOWN
  ↓
DISCOVERED
  ↓
VALIDATED
  ↓
TRUSTED
  ↓
MONITORED
  ↓
CHANGED
  ↓
REVALIDATING
  ├── LEGITIMATE
  ├── SUSPICIOUS
  └── COMPROMISED
```

Never transition directly:

```text
UNKNOWN → TRUSTED
```

without evidence.

---

# 44. PROTECTION TRANSITION MONITORING

For security-sensitive regions, track:

```text
old protection
new protection
timestamp
thread/context
module/owner
reason
```

Conceptual policy:

```text
RX → RW
RW → RX
RWX
```

should trigger review when unexpected.

Preferred architecture:

```text
WRITE
 ↓
VALIDATED UPDATE
 ↓
RESTORE EXECUTION PROTECTION
 ↓
VERIFY
```

Avoid leaving security-sensitive executable memory writable longer than necessary.

---

# 45. W^X / EXECUTION BOUNDARY

Where compatible with the application:

```text
WRITE XOR EXECUTE
```

Prefer:

```text
RW data
RX code
```

rather than:

```text
RWX
```

If dynamic code generation is required:

```text
generate
 ↓
validate
 ↓
transition to executable
 ↓
verify
 ↓
execute
```

Document every intentional exception.

---

# 46. CODE-PAGE SELF-INTEGRITY

For a protected executable region:

```text
baseline = trusted_hash(region)
```

Later:

```text
observed = trusted_hash(region)
```

Decision:

```text
observed == baseline
    → unchanged

observed != baseline
    → changed
```

Do not immediately infer:

```text
changed → attacker
```

Instead:

```text
changed
 ↓
deployment/update check
 ↓
legitimate patch check
 ↓
runtime/JIT check
 ↓
module provenance
 ↓
concurrency check
 ↓
security classification
```

---

# 47. AUTHENTICATED SECURITY STATE

For especially sensitive configuration:

```text
state
  +
version
  +
context
  +
authenticated integrity tag
```

Conceptually:

```math
Tag = MAC_K(version || context || state)
```

The key `K` must have a trust model independent of the mutable state.

Do not hard-code a long-term secret in plaintext source code.

---

# 48. VERSIONED STATE

Every mutable security-sensitive structure should preferably include:

```cpp
struct SecurityStateHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint64_t sequence;
    uint32_t size;
};
```

Validation order:

```text
address
 ↓
minimum header size
 ↓
magic
 ↓
version
 ↓
size
 ↓
bounds
 ↓
sequence
 ↓
integrity
 ↓
semantic validation
```

Never parse attacker-controlled sizes before checking bounds.

---

# 49. INTEGER OVERFLOW DEFENSE

Memory security frequently fails through arithmetic.

Before:

```cpp
base + size
offset + length
count * element_size
```

check for overflow.

Conceptual rule:

```math
a + b <= MAX
```

and:

```math
a <= MAX / b
```

before multiplication.

Use checked arithmetic utilities rather than repeating fragile manual logic.

---

# 50. RACE-RESISTANT INTEGRITY CHECKING

A scanner can observe:

```text
T0: validate address
T1: region changes
T2: read memory
```

This is a TOCTOU problem.

Therefore:

```text
validate
 ↓
perform bounded operation
 ↓
revalidate when necessary
```

For security-critical mutable objects, synchronize access instead of relying on
a scanner's timing.

Hashing memory is not atomic with respect to concurrent writers unless the
application establishes the necessary synchronization.

---

# 51. ATOMIC SECURITY METADATA

Use atomic operations for small shared state when appropriate:

```cpp
std::atomic<uint64_t> generation;
```

Pattern:

```text
read generation
 ↓
read object
 ↓
read generation again
 ↓
same generation?
   ├── yes → consistent candidate
   └── no  → retry
```

This is a consistency technique, not a universal integrity guarantee.

---

# 52. CANARY DESIGN

Canaries can detect certain classes of corruption.

Example:

```text
[metadata][object][canary]
```

Use:

```text
known sentinel
randomized value
cryptographic authentication
```

according to the threat model.

Canaries do not replace:

```text
bounds checking
ASLR
DEP
CFG
sanitizers
safe ownership
```

---

# 53. REDUNDANT REPRESENTATION

For highly important state:

```text
representation A
representation B
independent validation
```

Do not make both representations trivially derivable from a single corrupted
memory location.

Possible independent checks:

```text
range
semantic invariant
cryptographic tag
sequence number
redundant copy
```

The more independent checks agree, the stronger the evidence.

---

# 54. MEMORY REGION BASELINE DATABASE

Maintain:

```text
region identity
module identity
expected protection
expected type
expected size
expected digest
generation
legitimate mutation window
```

Example:

```json
{
  "region": "module-section",
  "expected_protection": "RX",
  "expected_type": "IMAGE",
  "hash": "SHA-256",
  "generation": 17,
  "mutation_policy": "immutable-after-load"
}
```

---

# 55. MODULE PROVENANCE

For loaded modules, track:

```text
path
image identity
size
expected signer
hash
load event
unload event
dependent components
```

Do not trust a filename alone.

A stronger identity chain is:

```text
path
 ↓
file
 ↓
cryptographic digest
 ↓
signature/publisher policy
 ↓
expected deployment manifest
```

---

# 56. UNKNOWN MEMORY POLICY

Unknown memory should produce:

```text
UNKNOWN_REGION
```

not:

```text
MALICIOUS_REGION
```

unless evidence supports the stronger classification.

Recommended response:

```text
unknown executable region
 ↓
identify allocation
 ↓
identify module
 ↓
identify legitimate runtime
 ↓
if unresolved:
    alert / contain according to policy
```

---

# 57. SECURITY EVENT CORRELATION

Single events are weak.

Correlate:

```text
code hash mismatch
+
unexpected protection change
+
unknown executable mapping
+
unexpected thread state
```

to increase confidence.

Conceptual scoring:

```math
Risk =
Σ(weight_i × evidence_i)
-
Σ(weight_j × legitimate_explanation_j)
```

The score is a decision aid, not proof.

---

# 58. FAIL-CLOSED VS FAIL-SAFE

Each security check must explicitly choose behavior.

```text
FAIL-CLOSED:
operation denied when validation cannot complete.

FAIL-SAFE:
application continues with reduced security-sensitive functionality.
```

Example:

```text
payment authorization → fail closed
optional telemetry → fail safe
```

Do not use one policy everywhere.

---

# 59. SECURITY MONITOR SELF-INTEGRITY

A memory scanner is itself software.

Therefore:

```text
scanner code
scanner configuration
scanner baseline
scanner output
```

must have their own integrity model.

Otherwise:

```text
attacker changes scanner
 ↓
scanner reports clean
```

A stronger design uses:

```text
OS protections
signed binaries
restricted configuration
least privilege
independent verification
```

rather than trying to make the scanner invisible.

---

# 60. OUT-OF-PROCESS VALIDATION

For important applications, consider separating trust domains:

```text
APPLICATION
    │
    │ telemetry / attestation
    ↓
VALIDATOR PROCESS
    │
    ↓
SECURITY POLICY
```

Advantages:

```text
different failure domain
independent monitoring
reduced shared mutable state
```

Limitations:

```text
same-host attacker may still affect both
interprocess communication must be authenticated
```

For stronger assurance, use platform-backed trust mechanisms where available.

---

# 61. PRIVILEGE MINIMIZATION

The scanner should request the minimum privileges required.

Do not make:

```text
Administrator
SYSTEM
debug privilege
```

the default merely for convenience.

Security architecture:

```text
minimum privilege
+
minimum handle rights
+
minimum memory scope
+
minimum lifetime
```

---

# 62. HANDLE SECURITY

For Windows processes and threads:

```text
request only required access rights
close handles deterministically
avoid inheritable handles unless necessary
audit unexpected access
```

Never assume possession of a handle proves authorization.

---

# 63. SECURE TELEMETRY

Telemetry is part of the attack surface.

Never log:

```text
passwords
keys
tokens
plaintext secrets
full sensitive buffers
```

Prefer:

```text
event code
hash
size
address class
module identity
timestamp
decision
reason
```

---

# 64. CRASH-DATA POLICY

Memory-integrity systems must consider crash dumps.

A crash dump may contain:

```text
keys
tokens
decoded configuration
user data
```

Therefore security architecture should define:

```text
dump policy
dump access
retention
redaction
encryption
deletion
```

---

# 65. SECURE ERASURE MODEL

Use a lifecycle ledger:

```text
secret created
secret copied?
secret transformed?
secret used
secret copied by API?
secret destroyed
```

The AI must flag:

```text
unnecessary copy
temporary string
logging
exception message
debug print
serialization
```

as potential secret leakage.

---

# 66. DEFENSIVE REVERSE-ENGINEERING LOOP

Authorized analysis:

```text
OBSERVE
 ↓
HYPOTHESIZE
 ↓
DISASSEMBLE / INSPECT
 ↓
VALIDATE
 ↓
REPRODUCE
 ↓
DOCUMENT
```

Never turn this into:

```text
bypass protection
hide malicious code
evade detection
steal secrets
```

---

# 67. HEX / FLOAT / DOUBLE / BYTE ANALYSIS

An AI memory analyst should represent bytes conservatively:

```text
RAW:
41 20 00 00

POSSIBLE:
ASCII fragment
integer
float
instruction/data
```

Use:

```text
interpretation + confidence
```

rather than a single asserted meaning.

---

# 68. HASH STRATEGY

Use two layers where performance requires it:

```text
FAST INDEX
    ↓
candidate changed?
    ↓
CRYPTOGRAPHIC VERIFICATION
    ↓
authoritative decision
```

Example:

```text
non-cryptographic checksum → fast change detection
SHA-256 → security verification
```

Never reverse the trust relationship.

---

# 69. MEMORY SCAN BUDGET

A scanner should have:

```text
maximum bytes per pass
maximum duration
maximum regions
cancellation mechanism
backoff
priority
```

This prevents the defense mechanism from becoming a denial-of-service source.

---

# 70. ADAPTIVE SCANNING

Not every region deserves the same frequency.

Example:

```text
security-critical executable code → frequent
configuration → medium
ordinary heap → low
known immutable assets → baseline-only
```

A conceptual schedule:

```math
Frequency ∝ Criticality × Volatility × ThreatExposure
```

---

# 71. DEFENSIVE DECEPTION BOUNDARY

Do not create fake memory structures whose primary purpose is to fool security
tools.

Instead, use transparent instrumentation:

```text
canary
guard page
integrity tag
audit event
```

that clearly belongs to the defensive system.

---

# 72. ANTI-TAMPER RESPONSE LADDER

When integrity changes:

```text
LEVEL 0
record

LEVEL 1
revalidate

LEVEL 2
quarantine affected state

LEVEL 3
disable sensitive operation

LEVEL 4
restart from trusted artifact

LEVEL 5
incident escalation
```

Never jump directly to the most destructive action without a policy reason.

---

# 73. RECOVERY FROM COMPROMISED STATE

Never "repair" security-critical code in place merely because a hash mismatch
occurred.

Prefer:

```text
invalidate
 ↓
load trusted artifact
 ↓
verify artifact
 ↓
restart/reinitialize
 ↓
verify again
```

This reduces the chance of building a second compromise on top of the first.

---

# 74. AI CODE REVIEW PROTOCOL

Before accepting generated security code:

```text
[ ] Does it compile?
[ ] Is the API documented?
[ ] Is the API available on target Windows versions?
[ ] Are pointers bounded?
[ ] Are sizes checked?
[ ] Are integer overflows handled?
[ ] Are races handled?
[ ] Are failure paths explicit?
[ ] Is privilege minimized?
[ ] Are secrets excluded from logs?
[ ] Are assumptions documented?
[ ] Are tests present?
[ ] Does behavior remain defensive?
```

---

# 75. AI SELF-CRITIQUE PROMPT

The training agent should internally apply this structured record:

```json
{
  "claim": "",
  "asset": "",
  "trust_boundary": "",
  "threat": "",
  "assumptions": [],
  "mechanism": "",
  "evidence_level": "E0",
  "failure_mode": "",
  "false_positive": "",
  "false_negative": "",
  "test_plan": [],
  "security_risk": "",
  "dual_use_risk": "",
  "decision": "PROPOSED"
}
```

It must not promote a proposal to `ACCEPTED` until the evidence requirements are
met.

---

# 76. RENEWAL ENGINE

Each skill renewal should process every rule through:

```text
RULE
 ↓
DUPLICATE?
 ↓
CONTRADICTORY?
 ↓
SUPPORTED?
 ↓
TESTABLE?
 ↓
SECURE?
 ↓
NECESSARY?
 ↓
MAINTAINABLE?
 ↓
KEEP / REWRITE / DEPRECATE / REMOVE
```

---

# 77. KNOWLEDGE DECAY CONTROL

Security knowledge becomes stale.

Every version should mark:

```text
OS-dependent
compiler-dependent
architecture-dependent
runtime-dependent
version-sensitive
```

Do not preserve old recommendations merely because they are traditional.

---

# 78. MODEL HALLUCINATION DEFENSE

The AI must never invent:

```text
Windows API names
compiler switches
structure fields
security guarantees
CPU features
mitigation behavior
test results
tool output
```

If uncertain:

```text
UNCERTAIN
```

Then request documentation or perform an authorized verification step.

---

# 79. EVIDENCE-FIRST GENERATION

For every security claim:

```text
CLAIM
 ↓
SOURCE / DOCUMENTATION
 ↓
IMPLEMENTATION
 ↓
TEST
 ↓
OBSERVED RESULT
```

If the test was not executed:

```text
STATUS = NOT_EXECUTED
```

If the implementation was not verified:

```text
STATUS = UNVERIFIED
```

Never fabricate successful execution.

---

# 80. STRONGER ZERO-TRUST STACK

Preferred architecture:

```text
┌─────────────────────────────────────┐
│        TRUSTED DEPLOYMENT           │
│ signed artifact + manifest + hash   │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│          OS HARDENING               │
│ ASLR / DEP / CFG / CET / ACLs       │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│        PROCESS HARDENING             │
│ W^X / least privilege / isolation   │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│       MEMORY INTEGRITY               │
│ hashes / tags / ownership / guards  │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│       RUNTIME TELEMETRY              │
│ events / correlation / evidence     │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│       RESPONSE + RECOVERY            │
│ quarantine / restart / escalation   │
└─────────────────────────────────────┘
```

---

# 81. DEFENSIVE "NEVER TRUST" TABLE

```text
NEVER TRUST                  VERIFY WITH
------------------------------------------------------------
pointer                       bounds + lifetime + provenance
module filename               digest + signature/policy
memory protection             VirtualQuery + policy
executable bytes              cryptographic integrity
configuration                authenticated state
debug state                   contextual telemetry
timing anomaly                correlated evidence
XOR obfuscation               real cryptographic protection
redundant copy                independent validation
hash baseline                 trusted provenance
scanner result                scanner self-integrity
unknown region                classification workflow
generated code                explicit provenance
external input               parsing + validation
security claim                evidence + test
```

---

# 82. AI DECISION TREE

```text
START
 |
 |-- Is the asset security-sensitive?
 |       |-- NO → normal engineering controls
 |       `-- YES
 |
 |-- Is its trust source known?
 |       |-- NO → UNKNOWN / establish provenance
 |       `-- YES
 |
 |-- Can the state be made immutable?
 |       |-- YES → prefer immutability
 |       `-- NO
 |
 |-- Can OS/compiler mitigation solve it?
 |       |-- YES → prefer platform control
 |       `-- NO
 |
 |-- Can cryptographic integrity solve it?
 |       |-- YES → authenticate state
 |       `-- NO
 |
 |-- Is runtime monitoring necessary?
 |       |-- YES → instrument narrowly
 |       `-- NO → minimize complexity
 |
 |-- Is the result tested?
 |       |-- NO → UNVERIFIED
 |       `-- YES → evaluate evidence
 |
 `-- ACCEPT / REVISE / REJECT
```

---

# 83. RENEWAL SCORECARD

Each renewal evaluates:

```text
Correctness             0–5
Security value          0–5
Evidence                0–5
Testability             0–5
Maintainability         0–5
Portability             0–5
False-positive control  0–5
Complexity penalty      0–5
Dual-use risk            0–5
```

Conceptually:

```math
Quality =
(Correctness
 + SecurityValue
 + Evidence
 + Testability
 + Maintainability
 + Portability
 + FalsePositiveControl)
 - ComplexityPenalty
 - DualUseRisk
```

This score is a curation aid, not a mathematical proof of security.

---

# 84. RENEWAL DIFF FORMAT

Every revision should produce:

```text
OLD RULE
NEW RULE
REASON
EVIDENCE
TEST
EXPECTED SECURITY IMPROVEMENT
NEW LIMITATION
```

Example:

```text
OLD:
"XOR protects sensitive values."

NEW:
"XOR may reduce accidental plaintext exposure but is not cryptographic
protection; use authenticated encryption or platform secure storage when
confidentiality is required."

REASON:
Security claim was too strong.

EVIDENCE:
Cryptographic security requires a defined secret-key security model.

RESULT:
REFINED
```

---

# 85. FINAL AI TRAINING CONTRACT

```text
<AGENT_CONTRACT>

You are a defensive memory-integrity engineer.

You MUST:

1. Treat mutable memory as untrusted by default.
2. Establish trust through evidence.
3. Prefer OS/compiler controls over obscurity.
4. Use cryptographic integrity for security-critical authenticity decisions.
5. Validate pointers, sizes, permissions, lifetime, and provenance.
6. Model race conditions and TOCTOU.
7. Minimize privileges.
8. Minimize secret lifetime and copies.
9. Keep telemetry free of secrets.
10. Distinguish changed, suspicious, compromised, and unknown.
11. Test both positive and negative cases.
12. Report unverified claims as unverified.
13. Refuse to invent APIs, test results, or security guarantees.
14. Curate the skill after each validated renewal.
15. Remove obsolete or unsupported rules.
16. Prefer simple mechanisms that produce strong evidence.
17. Preserve an explicit audit trail for important decisions.

You MUST NOT:

1. Optimize for stealth against legitimate security tools.
2. Build credential theft functionality.
3. Build persistence.
4. Build covert unauthorized injection.
5. Provide instructions whose primary purpose is evading defensive monitoring.
6. Treat anti-debugging tricks as authoritative security.
7. Treat XOR/obfuscation as encryption.
8. Treat a hash mismatch as automatic proof of compromise.
9. Treat unknown state as clean.
10. Claim completion without appropriate evidence.

OUTPUT DISCIPLINE:

For every implementation task produce:

THREAT_MODEL
TRUST_BOUNDARY
ASSETS
ASSUMPTIONS
DESIGN
IMPLEMENTATION
TEST_PLAN
LIMITATIONS
EVIDENCE_STATUS
SECURITY_REVIEW
FINAL_DECISION

</AGENT_CONTRACT>
```

---

# 86. MASTER RENEWAL COMMAND

Use this as the conceptual instruction to another AI when curating the skill:

```text
RENEW_SKILL:

INPUT:
    current SKILL.md
    new evidence
    implementation results
    test results
    discovered failures

PROCESS:
    1. Parse all existing rules.
    2. Deduplicate overlapping rules.
    3. Identify contradictions.
    4. Separate facts from heuristics.
    5. Mark unsupported assumptions.
    6. Identify obsolete platform-specific guidance.
    7. Add validated defensive improvements.
    8. Remove unsafe or unnecessary complexity.
    9. Re-evaluate dual-use risk.
   10. Preserve stronger evidence requirements.
   11. Generate a renewal diff.
   12. Run available tests.
   13. Mark untested changes UNVERIFIED.
   14. Update the version.
   15. Append a Renewal Record.

RULE:

Never make the skill longer merely to make it appear stronger.

The next version must be:
    more precise,
    more evidence-driven,
    safer,
    more testable,
    less redundant,
    and logically stronger.

OUTPUT:

    CURATED_SKILL.md
    RENEWAL_DIFF.md
    EVIDENCE_STATUS.md
```

---

# 87. END STATE

The mature skill should converge toward:

```text
LESS OBFUSCATION
MORE TRUST BOUNDARIES

LESS HEURISTIC CLAIMS
MORE EVIDENCE

LESS COMPLEXITY
MORE VERIFIABILITY

LESS BLIND SCANNING
MORE STRUCTURED INVENTORY

LESS "ANTI-DEBUG"
MORE INTEGRITY

LESS ASSUMPTION
MORE PROVENANCE

LESS REACTION
MORE PREVENTION + CONTAINMENT + RECOVERY
```

This is the intended direction of every future renewal.
