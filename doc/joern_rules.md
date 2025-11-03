# Joern C/C++ Security Rule Set

This document enumerates Joern analysis rules targeting high-impact C and C++ vulnerability classes.
Each rule entry describes: the sensitive data *sources* and dangerous *sinks*, the preferred Joern detection strategy, a high-level matching concept, and recommended remediation guidance.

> **Implementation note:** A runnable set of Joern queries covering the top rules in this catalog is provided in `joern/rules/cpp_security_rules.sc`. Load the script through `joern --script` (or `:load` inside the console) to execute the automated checks described below.

> **Testing note:** The repository now ships an intentionally vulnerable regression corpus under `joern/testcases/`. Each snippet triggers one rule and is accompanied by `pytest` coverage (`tests/test_cpp_security_rules.py`) to ensure the samples and rule metadata stay in sync.

> **Detection strategy legend**
> • **DFA** – Data-flow analysis powered by semantic CPG traversals (preferred when both feasible).
> • **PM** – Structural/pattern matching via AST/CFG/Call graph queries.

## 1. Memory Access Vulnerabilities

### 1.1 Buffer Overflow (Stack & Heap)
- **Sensitive sources:** External input APIs (`recv`, `read`, `gets`, `fgets`, `scanf`, `strcpy`, `strncpy`, `strcat`, `sprintf`, `vsprintf`, `memcpy`, `memmove`), untrusted parameters.  
- **Dangerous sinks:** Writes into fixed-size buffers (arrays, `char buf[N]`, heap allocations) without bounds validation; calls to `strcpy`, `sprintf`, `memcpy`, `strcat`, `gets`, `scanf` with `%s`, custom loops indexing arrays.  
- **Detection strategy:** **DFA** tracking tainted length/control expressions into buffer writes; complemented by **PM** for direct unsafe API calls lacking size limits.  
- **Rule description:**  
  - Use `cpg.call("(strcpy|strcat|gets|sprintf|vsprintf)")` without a length-limited variant, flag when the destination argument is a fixed-size buffer or stack array.  
  - Data-flow from untrusted input into the length parameter of `memcpy`/`memmove`/`read` or into loop bounds controlling array writes where the bound exceeds buffer capacity.  
- **Remediation:** Prefer bounds-checked APIs (`strncpy`, `snprintf`, `fgets`), validate lengths against buffer capacity, or dynamically size buffers.

### 1.2 Array Out-of-Bounds Access
- **Sources:** Loop counters, index expressions derived from external input, arithmetic results.  
- **Sinks:** Array subscripts `arr[index]`, pointer arithmetic dereferences `(ptr + index)` writing/reading.  
- **Detection strategy:** **DFA** from untrusted index expressions to array accesses; **PM** when index is constant exceeding declared size.  
- **Rule description:**  
  - Query array accesses (`cpg.call.name("<operator>.indexAccess")`) and evaluate index vs. array bounds; flag when index is tainted and lacks preceding range checks or when constant index ≥ size.  
- **Remediation:** Enforce explicit bound checks (`0 <= index < size`), use safe iterators, encapsulate access in helper validating inputs.

### 1.3 NULL Pointer Dereference
- **Sources:** Functions returning nullable pointers (`malloc`, `calloc`, `realloc`, `fopen`, `dlsym`), API parameters allowed to be null.  
- **Sinks:** Dereferences via `*ptr`, `ptr->field`, `ptr[index]`, calling methods on pointer.  
- **Detection strategy:** **DFA** verifying dereference path lacks prior null-check.  
- **Rule description:**  
  - Track allocations or external-returned pointers to dereferences; ensure a dominating condition `ptr != NULL` or error handling. Absence triggers alert.  
- **Remediation:** Always check pointer validity before use; handle allocation failures gracefully.

### 1.4 Dangling / Wild Pointer
- **Sources:** Pointers to freed memory (`free`, `delete`, `delete[]`), stack addresses escaping scope, uninitialized pointers.  
- **Sinks:** Subsequent dereference, pointer arithmetic, or re-free on same pointer.  
- **Detection strategy:** **DFA** tracking pointer state transitions; detect uses after `free` without reinitialization.  
- **Rule description:**  
  - Identify `free(p)` then follow data-flow of `p` to dereference or assignment; verify pointer set to `NULL` before reuse.  
- **Remediation:** Nullify pointer post-free, redesign ownership semantics (smart pointers), avoid returning addresses of stack locals.

### 1.5 Use of Uninitialized Memory
- **Sources:** Local variables without initialization, partially initialized structs, stack buffers.  
- **Sinks:** Reads in expressions, function arguments, syscalls.  
- **Detection strategy:** **DFA** on reaching definitions; highlight reads without preceding assignment.  
- **Rule description:**  
  - Use `cpg.identifier.isParameter.not` to find locals and ensure `cpg.cfg.reachableBy` from assignment exists before read.  
- **Remediation:** Initialize variables upon declaration; use `memset` or constructors.

### 1.6 Double Free
- **Sources:** Pointers freed once (`free`, `delete`, `delete[]`).  
- **Sinks:** Subsequent identical deallocation.  
- **Detection strategy:** **DFA** verifying pointer state (freed) before additional `free`.  
- **Rule description:**  
  - Track pointer alias set; detect repeated deallocation without intervening re-allocation; check alias writes.  
- **Remediation:** After free, set pointer to `NULL`, ensure unique ownership semantics.

### 1.7 Use-After-Free (UAF)
- **Sources:** Pointers freed via `free`, `delete`, `close`-like API releasing resources.  
- **Sinks:** Any dereference/read/write, function calls using pointer, reallocation length using freed pointer.  
- **Detection strategy:** **DFA** to follow pointer lifetime transitions.  
- **Rule description:**  
  - Identify frees, propagate pointer flows; warn when pointer is used in CFG after free without re-assignment. Handle path-sensitive alias detection.  
- **Remediation:** Refrain from using pointer post-free; reallocate before use; apply smart pointers or RAII.

## 2. Integer and Arithmetic Vulnerabilities

### 2.1 Integer Overflow / Underflow
- **Sources:** Arithmetic on user-controlled integers, length calculations, multiplication/ addition for allocation.  
- **Sinks:** Size arguments to `malloc`, `new`, array indexing, pointer arithmetic, loop bounds.  
- **Detection strategy:** **DFA** linking tainted operands to overflow-prone arithmetic; **PM** for dangerous casts (signed to unsigned).  
- **Rule description:**  
  - Identify operations `+`, `-`, `*`, `<<` on tainted values lacking range checks; watch for wrap-around when used to allocate memory or compute lengths.  
- **Remediation:** Validate ranges before arithmetic, use safe math helpers (`__builtin_add_overflow`), adopt unsigned size discipline.

### 2.2 Signedness Errors
- **Sources:** Mixed signed/unsigned values from external inputs, conversions.  
- **Sinks:** Comparisons, casts to size types, loops, array indexing.  
- **Detection strategy:** **PM** combined with **DFA** on type transitions; detect when signed negative becomes large unsigned.  
- **Rule description:**  
  - Find assignments/casts from signed to unsigned where value lacks non-negative validation; track to memory operations.  
- **Remediation:** Normalize to consistent types, enforce explicit bounds checks before casting.

## 3. String and Format Vulnerabilities

### 3.1 Format String Vulnerability
- **Sources:** Untrusted strings (`argv`, network data, `gets`, `fgets`) passed as format specifier.  
- **Sinks:** `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog`, `vprintf`, `vsnprintf`.  
- **Detection strategy:** **DFA** from untrusted input to first parameter of formatting calls; **PM** for direct variable forwarding without literal.  
- **Rule description:**  
  - Query format functions where format argument is non-literal or tainted; flag missing length-limited variants for buffers.  
- **Remediation:** Use constant format strings; sanitize or reformat user input before use.

### 3.2 Missing NULL Termination
- **Sources:** Functions returning raw buffers without ensuring `\0`, custom copy loops, length-truncated copies.  
- **Sinks:** APIs assuming null-terminated strings (`printf`, `strlen`, `strcpy`).  
- **Detection strategy:** **PM** verifying copy loops that write exactly `n` bytes without terminator; **DFA** when string length flows to usage expecting termination.  
- **Rule description:**  
  - Detect copies using `memcpy`/`strncpy` where destination length equals buffer size and no explicit terminator added before use.  
- **Remediation:** Ensure destination buffer ends with `\0`, use safer functions (`strlcpy`), manage string length metadata.

### 3.3 Unsafe String Copy/Concatenation
- **Sources:** Tainted input to `strcpy`, `strcat`, `gets`, `scanf` with `%s`, `sprintf`.  
- **Sinks:** Destination buffers with fixed size.  
- **Detection strategy:** **DFA** for tainted lengths; **PM** for calls to inherently unsafe APIs.  
- **Rule description:**  
  - Flag direct use of unbounded string functions; check `strncpy` usage without ensuring null termination.  
- **Remediation:** Replace with bounded functions, track buffer capacities, sanitize input lengths.

## 4. Concurrency and Synchronization

### 4.1 Race Condition
- **Sources:** Shared data accessed by threads, signal handlers, interrupt routines.  
- **Sinks:** Writes/reads outside critical sections, non-atomic operations.  
- **Detection strategy:** **DFA** analyzing accesses to shared variables without synchronization context; **PM** for known thread APIs (`pthread_create`, `std::thread`).  
- **Rule description:**  
  - Identify shared state (`static`, global, heap) accessed along multiple paths; flag when updates occur without guarding mutex lock/unlock pairs.  
- **Remediation:** Introduce locks, atomics, or thread-safe patterns; avoid sharing mutable state.

### 4.2 TOCTOU (Time-Of-Check Time-Of-Use)
- **Sources:** File paths or resources validated (e.g., `stat`, `access`).  
- **Sinks:** Later operations on same path (`open`, `fopen`, `unlink`, `chmod`).  
- **Detection strategy:** **DFA** ensuring path value stable between check and use; detect missing secure patterns (`open` with `O_CREAT|O_EXCL`).  
- **Rule description:**  
  - Track variable storing path after check; warn when check and use are separated allowing attacker to modify resource (no `open` with `O_NOFOLLOW`).  
- **Remediation:** Use atomic operations (`open` with `O_CREAT|O_EXCL`, `fstat` on file descriptor), minimize window or revalidate after acquisition.

## 5. Logic and Resource Management

### 5.1 Resource Leak
- **Sources:** Resource acquisitions (`open`, `fopen`, `socket`, `malloc`, `new`, `pthread_mutex_init`).  
- **Sinks:** Function exit without corresponding release (`close`, `fclose`, `delete`, `free`, `pthread_mutex_destroy`).  
- **Detection strategy:** **DFA** for resource lifetime ensuring release on all paths; **PM** for missing RAII destructors.  
- **Rule description:**  
  - Model resource types; ensure every exit path of function has release call. Flag missing cleanup in error handling branches.  
- **Remediation:** Apply RAII (`std::unique_ptr`, `std::vector`), use `goto cleanup` pattern ensuring release, adopt smart handles.

### 5.2 Privilege/Access Control Errors
- **Sources:** User-supplied identifiers, file paths, capability tokens.  
- **Sinks:** Operations requiring elevated privileges (`setuid`, `chown`, file writes).  
- **Detection strategy:** **DFA** linking authorization checks to privileged calls; flag absence of gating condition.  
- **Rule description:**  
  - Trace path to sensitive operations; ensure preceding check verifying user rights (UID comparison, ACL). Without guard, raise issue.  
- **Remediation:** Centralize authorization logic; ensure privileged APIs only run after verifying identity or permissions.

### 5.3 Improper Error Handling
- **Sources:** Functions returning error codes (`read`, `write`, `malloc`, `strncpy`, `pthread_mutex_lock`).  
- **Sinks:** Ignored return values, silent failure, fallback to insecure defaults.  
- **Detection strategy:** **PM** for call results unused; **DFA** for error flows not handled.  
- **Rule description:**  
  - Detect when return values are discarded (no assignment, no check). For `errno`-setting functions, ensure error branch present.  
- **Remediation:** Check return status, propagate errors, fail secure, log appropriately.

## 6. Undefined Behavior & Type Safety

### 6.1 Type Confusion
- **Sources:** Casts between unrelated struct/class pointers, union reuse with mismatched type tags.  
- **Sinks:** Dereferences assuming wrong layout, virtual dispatch on wrong type.  
- **Detection strategy:** **PM** on casts with incompatible types; **DFA** verifying runtime type checks missing.  
- **Rule description:**  
  - Identify `reinterpret_cast`, C-style casts crossing inheritance without `dynamic_cast` or type tag verification.  
- **Remediation:** Use proper polymorphism (`dynamic_cast` with null check), maintain discriminated unions.

### 6.2 Misaligned Memory Access
- **Sources:** Casting byte buffers to wider types, packed structs.  
- **Sinks:** Dereferencing misaligned pointer causing hardware traps.  
- **Detection strategy:** **PM** for casts from `char*` to `uint32_t*` without alignment checks; data-flow for pointer arithmetic.  
- **Rule description:**  
  - Flag pointer casts where alignment requirement exceeds buffer alignment and no `memcpy` used.  
- **Remediation:** Use `memcpy` or `std::aligned_storage`, ensure allocations respect alignment.

### 6.3 Undefined Behavior (General)
- **Sources:** Shifts beyond width, signed overflow, invalid pointer arithmetic, sequence point violations.  
- **Sinks:** Execution of such operations.  
- **Detection strategy:** **PM** for shift operations with dynamic operands lacking bounds checks; **DFA** for pointer arithmetic using tainted offsets.  
- **Rule description:**  
  - Detect `value << count` where `count` >= bit width or negative; pointer arithmetic leaving allocated object; highlight suspicious casts.  
- **Remediation:** Validate shift counts, use standard library helpers, avoid undefined idioms.

## 7. External Input & System Interaction

### 7.1 Command Injection
- **Sources:** User-controlled strings, environment variables, network inputs.  
- **Sinks:** `system`, `popen`, `execvp`, `execl`, `CreateProcess` with `/bin/sh` or shell invocation.  
- **Detection strategy:** **DFA** from untrusted input to command execution argument.  
- **Rule description:**  
  - Trace tainted data to shell command functions; ensure sanitization or whitelist. Flag concatenation of user input into command string.  
- **Remediation:** Avoid shell invocation; use APIs accepting argv arrays; sanitize/escape inputs.

### 7.2 Path Traversal
- **Sources:** File paths from users, HTTP params, config.  
- **Sinks:** File access APIs (`open`, `fopen`, `ifstream`, `stat`, `mkdir`).  
- **Detection strategy:** **DFA** for tainted path reaching file API without canonicalization; **PM** for string operations adding "../".  
- **Rule description:**  
  - Detect user input concatenated to directory path and passed to file API without validation; check for canonicalization functions (`realpath`).  
- **Remediation:** Normalize paths, reject `..`, enforce chroot/jail, use secure filename mappings.

### 7.3 File Race / Link Attacks
- **Sources:** Temp file names, predictable paths.  
- **Sinks:** `open`, `fopen`, `mktemp`, file operations without secure flags.  
- **Detection strategy:** **PM** for `mktemp` usage and file opens without `O_EXCL`; **DFA** linking file path to open call.  
- **Rule description:**  
  - Flag `mktemp`/`tmpnam`; ensure `open` uses `O_CREAT|O_EXCL` and `O_NOFOLLOW`.  
- **Remediation:** Use `mkstemp`, secure file APIs, set restrictive permissions.

## 8. Sensitive Information Handling

### 8.1 Information Disclosure
- **Sources:** Uninitialized memory, debug logs, cryptographic material.  
- **Sinks:** Logging functions, network sends, error messages, HTTP responses.  
- **Detection strategy:** **DFA** tracing sensitive data types to output functions; **PM** for printing stack memory (`printf("%s", buffer)`).  
- **Rule description:**  
  - Tag sensitive variables (passwords, keys) via annotations; flag flows to `printf`, `fprintf`, logging, `send`.  
- **Remediation:** Scrub sensitive data, limit logging, mask outputs.

### 8.2 Hardcoded Secrets
- **Sources:** String literals matching secret patterns (API keys, passwords).  
- **Sinks:** Inclusion in binaries, repositories.  
- **Detection strategy:** **PM** scanning literals with regex for secret patterns; optionally **DFA** tracking to crypto APIs.  
- **Rule description:**  
  - Use Joern regex filter on literals (`cpg.literal.code("(?i)(api[_-]?key|secret|password)")`).  
- **Remediation:** Move secrets to secure storage, environment variables, or secret management services.

---

### Implementation Notes
- Leverage Joern's semantic CPG for taint tracking by tagging source nodes via `tagNodes` and propagating to sinks.  
- Combine AST pattern filters with path conditions (dominance, control flow) to reduce false positives.  
- Provide metadata (CWE ID, severity) for each rule when integrating into detection pipeline.

