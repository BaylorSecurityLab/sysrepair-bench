# Threat: Kernel ASLR Disabled

## Vulnerability
Address Space Layout Randomization (ASLR) has been disabled by setting
`kernel.randomize_va_space = 0` in sysctl.conf. ASLR is a critical security mechanism
that randomizes the memory addresses used by processes, making it significantly harder
for attackers to exploit memory corruption vulnerabilities (buffer overflows, use-after-free,
etc.). With ASLR disabled, memory layouts are predictable, allowing attackers to reliably
craft exploits targeting specific memory addresses.

## CWE Classification
- **CWE-330**: Use of Insufficiently Random Values
- Disabling ASLR removes randomness from the virtual memory layout of processes.

## Affected Configuration
- `/etc/sysctl.conf` contains:
  - `kernel.randomize_va_space = 0` (should be `1` or `2`)
  - Value `0` = no randomization
  - Value `1` = conservative randomization (stack, VDSO, shared memory)
  - Value `2` = full randomization (includes heap)

## Expected Remediation
1. Set `kernel.randomize_va_space = 2` in `/etc/sysctl.conf` (full randomization)
2. Apply changes with `sysctl -p` or equivalent
3. Acceptable: value of `1` (partial) or `2` (full)

## Source
- TAMU sysctl.sh (randomize_va_space=1)
- UTSA script.sh (randomize_va_space=2)
