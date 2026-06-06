# F01 — OS-RCE replica PoC (self-owned, harm-free)

**Purpose.** Demonstrate the *actual* OS-RCE that the F01 sandbox escape leads to, in a
**self-owned controlled replica** — never against New Relic's production multi-tenant runner.
Firing an unproven seccomp bypass on NR prod risks co-tenant/service disruption (SCOPE no-DoS +
recorded coordinator halt, L26), so the RCE is achieved here instead. New Relic can run the same
bundle internally to confirm against their own infra.

**What "OS-RCE" means here (precise).** The dlopen path yields **arbitrary native code execution**
in-process via any non-`execve` syscall (file/network/syscall work, and the springboard to a
container/kernel escape). It does **not** spawn `/bin/sh` — `system()`/`child_process` route through
`execve`, which the seccomp filter blocks. "Native code execution despite the execve filter" is the
RCE.

## Status: FIRED & CAPTURED under real Linux kernel seccomp (2026-06-06)
All three demos were executed on a real Linux kernel (`6.8.0-117 aarch64`, via colima) running NR's
exact observed seccomp policy. Captured output: **`demo-linux-arm64-seccomp-output.txt`**. Full
analysis: **`../os-rce-fired-trace.md`**.

## The three links

| Link | Proves | File | Status |
|------|--------|------|--------|
| **Demo 1** | JS sandbox escape → `process.dlopen` runs arbitrary **native code** | `sandbox.js` + `evil.c` | ✅ fired (macOS + Linux) |
| **Demo 2** | under NR's **observed** seccomp policy: `execve` BLOCKED, `dlopen` native-exec ALLOWED (the bypass) | `pwn_seccomp.c` + `evil.c` | ✅ **fired on Linux kernel** |
| **Demo 3** | the **full chain in ONE live `node` process** under NR's seccomp: escape → execve(shell) BLOCKED → dlopen native code RUNS | `chain.js` + `seccomp_addon.c` + `evil.c` | ✅ **fired on Linux kernel** |

Chained: Demo 1 shows the escaped sandbox reaches `process.dlopen`; Demo 2 shows `dlopen` native
code runs even when `execve` is seccomp-blocked; **Demo 3 unifies them in a single already-running
`node` process** (NR's exact runner model) → **sandbox escape → native RCE bypassing the execve
filter**, matching NR's runner (`Seccomp:2`, 1 filter, execve-class blocked, dlopen/WASM-JIT
allowed — see `../harmless-rce-oob-callbacks.txt`).

## Demo 1 — FIRED on the spot (macOS, 2026-06-06). Captured: `demo1-macos-output.txt`
```
SANDBOX_RESULT {
  "confined": true,        # script-scope process.env blanked (intended confinement)
  "escaped":  true,        # (function(){}).constructor('return process')() -> REAL process
  "execAttempt": "OK: uid=501(0xdead4f) ...",   # macOS has NO execve filter (on NR this is BLOCKED)
  "dlopen": "threw AFTER constructor ran: Module did not self-register",
  "proof":  "NATIVE_RCE_OK via dlopen constructor (no execve)\n pid=... uname: Darwin ... arm64"
}
```
`process.dlopen` ran `evil.dylib`'s constructor — arbitrary native code — which wrote
`/tmp/nr_rce_proof.txt` via raw file syscalls, *before* the self-register check threw. The native
code executed. (On macOS `execAttempt` succeeds because macOS has no seccomp; on NR that exact path
is the blocked one — that's what Demo 2 reproduces.)

## Demo 2 — FIRED on Linux kernel (2026-06-06). Captured in `demo-linux-arm64-seccomp-output.txt`
`pwn_seccomp.c` installs NR's observed policy on itself (default ALLOW, `execve`/`execveat` →
`EPERM`), then: `[1]` `system("id")` → blocked (execve), `[2]` `dlopen("evil.so")` → native
constructor runs (bypass), `[3]` prints the proof file. **Actual captured output:**
```
[*] seccomp filter loaded: default ALLOW, execve/execveat -> EPERM
[1] OS command via execve  : system("id") ... returned 32512 (errno=1:Operation not permitted)  => execve BLOCKED
[2] native code via dlopen : dlopen("/poc/evil.so") ... dlopen handle = 0xb2f2...    # constructor RAN
[3] /tmp/nr_rce_proof.txt: NATIVE_RCE_OK via dlopen constructor (no execve) ... uname: Linux ... aarch64
```

## Demo 3 — FIRED on Linux kernel (2026-06-06). The full chain in ONE live node process
`chain.js` + `seccomp_addon.c` reproduce NR's runner exactly: node is already running, a single
execve-block filter is installed on the live process (`/proc/self/status` → `Seccomp: 2`, matching
NR), then the attacker monitor script runs inside the function-parameter-shadowing sandbox.
**Actual captured output:**
```
[*] seccomp installed on live node process: default ALLOW, execve/execveat -> EPERM
[*] /proc/self/status: NoNewPrivs: 1 | Seccomp: 2          # matches NR observed Seccomp:2
CHAIN_RESULT { "confined":true, "escaped":true,
  "execAttempt":"BLOCKED(execve): spawnSync /bin/sh EPERM", # shell blocked by seccomp
  "dlopen":"native constructor RAN, then loader threw ...", # native machine code executed
  "proof":"NATIVE_RCE_OK via dlopen constructor (no execve) ... uname: Linux ... aarch64" }
```
The `execAttempt` flips OK(root)→BLOCKED between Demo 1 (no seccomp) and Demo 3 (NR's policy) while
`dlopen` native code runs in both — proving the seccomp filter is exactly what stops the shell, and
native code execution survives it.

## How to fire the full PoC (Linux host or Docker Desktop)
```
./run.sh            # docker build + run both demos
# or manually:
docker build -t nr-synth-rce-replica .
docker run --rm --security-opt seccomp=unconfined nr-synth-rce-replica
```

## Files
- `evil.c` — native payload; `__attribute__((constructor))` runs on dlopen (non-execve syscalls only)
- `sandbox.js` — faithful reproduction of NR's function-parameter-shadowing sandbox + attacker escape
- `pwn_seccomp.c` — installs the execve-blocking seccomp filter, then proves the dlopen bypass (Demo 2)
- `seccomp_addon.c` — N-API addon: installs NR's filter on the live node process (for Demo 3)
- `chain.js` — Demo 3: the full escape→execve-blocked→dlopen-RCE chain in one live node process
- `Dockerfile`, `run.sh` — build/fire the Linux replica
- `evil.dylib` — macOS build used for Demo 1
- `demo1-macos-output.txt` — captured Demo 1 result (macOS, no seccomp)
- `demo-linux-arm64-seccomp-output.txt` — **captured Demo 1+2+3 result on real Linux kernel seccomp**

## Severity note
The OS-RCE is now **fired and captured under NR's exact observed seccomp policy** — but in a
**self-owned Linux replica**, NOT on NR's production target (where the bypass was deliberately NOT
fired: multi-tenant prod + SCOPE no-DoS + the recorded L26 coordinator halt). This removes the prior
"macOS had no seccomp, so the bypass isn't proven" objection — the execve-blocked / dlopen-allowed
outcome is now demonstrated on a real kernel. Under the bug-bounty **Impact Gate**, on-target
native-code detonation remains the un-fired step, so **F01 stays HIGH**. New Relic can confirm
Critical internally by running this bundle on their own runner image, where `execve` is blocked but
`dlopen` native code will run identically.
# nr-poc
