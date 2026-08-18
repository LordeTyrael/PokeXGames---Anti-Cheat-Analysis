# PokeXGames — Anti-Cheat / Anti-Analysis Audit

PokeXGames is a heavily customized PokeTibia (an OTClient-based Pokémon MMO). This document answers one question about its client `pxgme.exe` (x86-64 PE, ~20 MB, MSVC C++, SDL2 + OpenGL/D3D, embedded Lua, ~40,700 functions): **does it try to stop you from debugging, hooking, or tampering with it?**

Short answer: **no — the game has no anti-cheat at all.** Static (Ghidra) and dynamic (x64dbg) analysis found no anti-debugging, no anti-hooking, no code-integrity countermeasures, and no kernel driver. Nothing.

## 1. Verdict Table

| Category | Verdict |
|----------|---------|
| `IsDebuggerPresent` / `DebugBreak` | Present, but benign — dev debug helpers, flag-guarded |
| Manual PEB checks (`BeingDebugged`, `NtGlobalFlag`) | **None** |
| NTDLL anti-debug (`NtQueryInformationProcess`, `NtSetInformationThread`) | **None** from game code |
| Timing traps (`QPC`, `GetTickCount`, `RDTSC` deltas) | **None** — SDL/engine timers only |
| `.text` CRC/checksum loops | **None** |
| `INT3` (0xCC) breakpoint scanning | **None** |
| IAT/inline hook detection | **None** |
| File "integrity check" at startup | Singleton lock, not a code check |

## 2. The Six `IsDebuggerPresent` Call Sites — All Benign

The import exists and is called from 6 functions. Every one is either flag-guarded or debugger-*friendly*:

**Sites 1–4 — flag-guarded debug traps.** The `DebugBreak()` only executes when a global boolean is set (a developer flag, off in release):

```c
if ((DAT_140ea2c20 != '\0') && IsDebuggerPresent()) {   // sites 1-2 use DAT_140ea2c20
    DebugBreak();
}
if ((DAT_1413413bc != '\0') && IsDebuggerPresent()) {   // sites 3-4 use DAT_1413413bc
    DebugBreak();
}
```

**Sites 5–6 — MSVC thread naming.** These raise the standard thread-name exception (`0x406D1388`), which exists so Visual Studio can display thread names. The `IsDebuggerPresent` check *prevents a crash when no debugger is attached*:

```c
if (IsDebuggerPresent() && !getenv("SDL_WINDOWS_DISABLE_THREAD_NAMING")) {
    RaiseException(0x406d1388, 0, 6, ...);   // name this thread for the debugger
}
```

An anti-debug check looks like `if (IsDebuggerPresent()) ExitProcess()`. This binary does the opposite.

## 3. Timing APIs — Engine Timers, Not Traps

- `QueryPerformanceCounter`/`QueryPerformanceFrequency` — used by SDL timer init, elapsed-time calculators, and a profiling helper. One routine falls back to `GetTickCount()` if QPC fails.
- `RDTSC` (`0F 31`) — 195 hits in `.text`, all inside rendering, asset decompression, and physics loops.

A real timing trap stores a timestamp, runs a guarded region, and compares the delta. No such store-compare-branch pattern exists anywhere in the binary.

## 4. What Was Searched For and NOT Found

| Technique | Search method | Result |
|-----------|--------------|--------|
| `CheckRemoteDebuggerPresent` | Import table + string scan | Absent |
| `NtQueryInformationProcess` (ProcessDebugPort/Flags/Object) | Imports + strings + runtime breakpoints | Absent from game code |
| `NtSetInformationThread` (ThreadHideFromDebugger) | Imports + strings + runtime breakpoints | Absent from game code |
| PEB `BeingDebugged` / `NtGlobalFlag` | Byte patterns (`65 48 8b 04 25 60 00 00 00` = `gs:[0x60]`) + hardware read breakpoint | Zero matches; breakpoint **never fired** in a 90s debugged run |
| `Heap.Flags` / `Heap.ForceFlags` checks | Structure field scan | Absent |
| `RDTSC` delta trap | Decompilation of all 195 sites | None malicious |
| `INT3` (0xCC) scan over `.text` | Byte pattern scan | Absent |
| CRC32/MD5/SHA1 over `.text` | Function names + accumulation-loop patterns | Absent |
| IAT/inline hook detection on `ntdll`/`kernel32`/`user32` | Module enumeration scan | Absent |
| TLS callback anti-debug | TLS directory inspection | None suspicious |
| `OutputDebugStringA` as debugger probe | XREF analysis | Fatal-error logging only |

Dynamic confirmation: breakpoints on `NtQueryInformationProcess` and `NtSetInformationThread` fired several times during a debugged session — but the return address was always inside `ntdll.dll` / `kernelbase.dll` (internal Windows thread-pool and heap management), never inside `pxgme.exe`. The process stayed stable under the debugger with no self-termination.

## 5. The One "Integrity" Mechanism

At startup the client creates an "integrity check file" (strings: `"Unable to create integrity check file."`, `"Unable to remove integrity check file."`) and deletes it on shutdown. Despite the name, it's a **file-based singleton lock** — one client instance at a time:

```c
if (!another_instance_running()) {
    create_sentinel_file();   // else: "Unable to create integrity check file."
}
// on shutdown:
remove_sentinel_file();
```

No hashing of `.text`, no breakpoint detection, no patch detection. The same initializer also embeds a **hardcoded RSA public key** — presumably for update-signature verification, unrelated to runtime anti-tampering.

## 6. Conclusion

**PokeXGames has no anti-cheat.** Not in the client: no anti-debugging, no anti-hooking, no integrity checks, no driver, no watchdog — nothing. A debugger or Frida can be attached freely and the game stays stable under one. The only barrier that could exist is server-side logic, which is outside this binary.

Combined with the HWID findings (`HWID.md`): the client *identifies* your machine but does not *defend* itself.

## Appendix — Addresses (June 2026 build, base `0x140000000`)

Shift on every recompile.

| Role | Address |
|------|---------|
| `IsDebuggerPresent` IAT slot | `0x1413c7cf0` |
| The 6 call sites | `0x140471bc0`, `0x140471800`, `0x1404a4150`, `0x14049eec0`, `0x14064e810`, `0x140a6c000` |
| Main initializer (singleton lock + RSA key) | `0x140e608e0` |
| Debug flag 1 (guards sites 1–2) | `0x140ea2c20` |
| Debug flag 2 (guards sites 3–4) | `0x1413413bc` |
| QPC timer w/ GetTickCount fallback | `0x140a68c70` |
| SDL timer init / elapsed-time | `0x14064efd0` / `0x14064ef10` |
| RSA public key string | `0x140e612b6` |
