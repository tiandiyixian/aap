# Joern C/C++ Security Regression Corpus

This directory contains intentionally vulnerable snippets that exercise each rule
shipped in `joern/rules/cpp_security_rules.sc`. Every file focuses on a single
weakness and is annotated with the corresponding rule identifier in a comment
near the triggering line.

## Available scenarios

| Rule ID | File | Vulnerability |
|---------|------|---------------|
| C001 | `buffer_overflow.c` | Unbounded copy into a fixed-size buffer |
| C002 | `array_index_taint.c` | Tainted array index without bounds check |
| C003 | `null_pointer_deref.c` | Dereferencing result of `malloc` without null-check |
| C004 | `double_free.c` | Duplicate `free` on the same pointer |
| C005 | `use_after_free.c` | Dereference after `free` |
| C006 | `format_string.c` | Untrusted format string reaching `printf` |
| C007 | `command_injection.c` | External data reaches `system` |
| C008 | `path_traversal.c` | User-controlled file path passed to `open` |
| C009 | `resource_leak.c` | `fopen` handle not released on all paths |
| C010 | `hardcoded_secret.c` | Suspicious hardcoded credential literal |

## Running the rules with Joern

1. Generate a CPG for the sample snippets (from repository root):
   ```bash
   joern-parse joern/testcases -o testcases.bin
   ```
2. Launch Joern and load the generated CPG:
   ```bash
   joern --workspace testcases.bin --script joern/rules/cpp_security_rules.sc
   ```
3. Inside the Joern shell you can run:
   ```scala
   val findings = CppSecurityRuleSet.runAll()(cpg)
   CppSecurityRuleSet.report(findings)
   ```

The report should contain at least one finding for every rule when executed
against this corpus.
