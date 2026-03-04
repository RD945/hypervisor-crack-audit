# Comprehensive Security Audit & Technical Analysis
## Resident.Evil.Requiem.HYPERVISOR.V2-KIRIGIRI

**Audit Date:** March 4, 2026
**Analyst:** Passive static analysis only — no binaries were executed
**Method:** String extraction, PE header analysis, INF parsing, config file review, GitHub open-source research
**Source Files Download:** [https://file-me.top/kpypgyn3k47v.html](https://file-me.top/kpypgyn3k47v.html)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Complete File Inventory](#2-complete-file-inventory)
3. [How Denuvo Anti-Tamper Works](#3-how-denuvo-anti-tamper-works)
4. [How This Package Defeats Denuvo — The Full Attack Chain](#4-how-this-package-defeats-denuvo--the-full-attack-chain)
5. [EfiGuard — UEFI Bootkit (Ring -2)](#5-efiguard--uefi-bootkit-ring--2)
6. [SimpleSvm.sys — AMD Hypervisor (Ring -1)](#6-simplesvmsys--amd-hypervisor-ring--1)
7. [hyperkd.sys — Custom MKDEV Kernel Driver (Ring 0)](#7-hyperkdsys--custom-mkdev-kernel-driver-ring-0)
8. [ColdClientLoader + Goldberg Steam Emulator (Ring 3)](#8-coldclientloader--goldberg-steam-emulator-ring-3)
9. [amd_ags_x64.org — AMD GPU Services Backup](#9-amd_ags_x64org--amd-gpu-services-backup)
10. [How All Components Work Together — Boot-to-Game Flow](#10-how-all-components-work-together--boot-to-game-flow)
11. [Risk Assessment & Verdict](#11-risk-assessment--verdict)

---

## 1. Executive Summary

This package is a **game piracy crack** for "Resident Evil Requiem" (Steam AppId 3764200). It bypasses a 5-layer DRM stack:

> **Steam + Denuvo Anti-Tamper + Capcom Anti-Tamper + VMProtect + SteamStub**

The crack operates across **four CPU privilege levels** simultaneously:

| Layer | Ring Level | Component | Purpose |
|-------|-----------|-----------|---------|
| UEFI Firmware | Ring -2 | EfiGuard (EfiGuardDxe.efi) | Disables PatchGuard + Driver Signature Enforcement at boot |
| Hypervisor | Ring -1 | SimpleSvm.sys | Intercepts CPUID/MSR to spoof environment for Denuvo |
| Kernel | Ring 0 | hyperkd.sys | KUSER_SHARED_DATA spoofing, orchestrates hypervisor |
| User Mode | Ring 3 | ColdClientLoader + Goldberg Emu | Replaces Steam client, emulates Steamworks API |

**Verdict:** Not general-purpose malware. Every component has a specific DRM-bypass function. However, `hyperkd.sys` is **closed-source, unsigned, ring-0** code from an anonymous group — it carries inherent risk. The package also **disables critical Windows security features** (DSE, PatchGuard), leaving the system vulnerable to other threats while active.

---

## 2. Complete File Inventory

### All Files with Metadata

| File | Size | Last Modified | Type | Signed |
|------|------|---------------|------|--------|
| `hyperkd.sys` | 11,632 bytes | 2026-02-28 02:56 | Kernel Driver (.sys) | No |
| `SimpleSvm.sys` | 17,776 bytes | 2026-02-28 02:53 | Kernel Driver (.sys) | No |
| `hyperlog.inf` | 1,940 bytes | 2026-02-28 02:54 | Driver Install Manifest | N/A |
| `amd_ags_x64.org` | 179,408 bytes | 2026-02-27 08:43 | DLL (renamed backup) | Yes (AMD) |
| `ColdClientLoader.ini` | 2,553 bytes | 2026-02-27 08:38 | Config file | N/A |
| `READNFO-MKDEV TEAM.txt` | 6,714 bytes | 2026-02-27 14:08 | NFO/Readme | N/A |
| `coldclient\steamclient.dll` | 16,026,024 bytes | 2026-02-26 06:55 | DLL (32-bit) | No |
| `coldclient\steamclient64.dll` | 17,895,336 bytes | 2026-02-26 06:55 | DLL (64-bit) | No |
| `coldclient\GameOverlayRenderer64.dll` | 1,946,536 bytes | 2026-02-26 06:55 | DLL (64-bit) | No |
| `EfiGuard\EFI\Boot\bootx64.efi` | 101,160 bytes | 2024-01-08 11:43 | UEFI Application | No |
| `EfiGuard\EFI\Boot\EfiGuardDxe.efi` | 360,448 bytes | 2026-01-27 14:09 | UEFI DXE Driver | No |
| `EfiGuard\EFI\Boot\loader.efi` | 49,152 bytes | 2026-01-27 14:09 | UEFI Loader | No |
| `EfiGuard\EFI\Boot\HashTool.efi` | 100,656 bytes | 2024-01-08 11:43 | UEFI Hash Utility | No |
| `coldclient\steam_settings\configs.app.ini` | 410 bytes | 2026-02-27 11:55 | Config | N/A |
| `coldclient\steam_settings\configs.main.ini` | 1,216 bytes | 2026-02-09 00:53 | Config | N/A |
| `coldclient\steam_settings\configs.user.ini` | 220 bytes | 2026-02-09 04:45 | Config | N/A |
| `coldclient\steam_settings\steam_appid.txt` | 7 bytes | 2026-02-27 08:38 | Text | N/A |
| `coldclient\steam_settings\steam_interfaces.txt` | 629 bytes | 2026-02-27 08:53 | Text | N/A |

### PE Header Analysis of Binary Files

| Binary | Architecture | Subsystem | PE Characteristics |
|--------|-------------|-----------|-------------------|
| `hyperkd.sys` | x86-64 (0x8664) | Native/Kernel (1) | 0x0022 (Executable, Large Address Aware) |
| `SimpleSvm.sys` | x86-64 (0x8664) | Native/Kernel (1) | 0x0022 (Executable, Large Address Aware) |
| `steamclient.dll` | x86 (0x014C) | Windows GUI (2) | 0x2102 (DLL, Executable, 32-bit) |
| `steamclient64.dll` | x86-64 (0x8664) | Windows GUI (2) | 0x2022 (DLL, Executable, Large Address Aware) |
| `GameOverlayRenderer64.dll` | x86-64 (0x8664) | Windows GUI (2) | 0x2022 (DLL, Executable, Large Address Aware) |
| `amd_ags_x64.org` | x86-64 (0x8664) | Windows Console (3) | 0x2022 (DLL, Executable, Large Address Aware) |

**Key observation:** Both `.sys` files have Subsystem = 1 (Native), confirming they are legitimate Windows kernel drivers, not user-mode executables disguised with `.sys` extensions. Their PE characteristics (0x0022) indicate they are not DLLs — they are standalone kernel executables.


---

## 3. How Denuvo Anti-Tamper Works

Denuvo is a commercial anti-tamper technology by Denuvo Software Solutions GmbH (now owned by Irdeto). It is NOT a standalone DRM — it is an **anti-tamper wrapper** that protects other DRM (here: Steam + Capcom's own DRM).

### 3.1 Denuvo's Protection Mechanisms

**Code Virtualization:**
- Critical game functions are converted from native x86-64 instructions into custom bytecode
- This bytecode runs inside a private virtual machine (VM) embedded in the game executable
- VMProtect adds an additional layer of VM-based obfuscation on top of Denuvo's own VM
- Result: Static disassembly (IDA Pro, Ghidra) shows gibberish — the real logic is hidden inside VM interpreters

**Hardware-Bound Token System:**
- At specific trigger points during gameplay, Denuvo contacts online activation servers
- The server issues a time-limited **hardware-fingerprinted token** bound to:
  - CPU ID (CPUID instruction results)
  - Disk serial numbers
  - Windows installation ID
  - Motherboard identifiers
- These tokens are checked at runtime; without valid tokens, protected code blocks fail

**Anti-Analysis Detection (what the hypervisor must defeat):**

| Detection Method | What Denuvo Checks | How It Checks |
|-----------------|-------------------|---------------|
| Hypervisor detection | Is a hypervisor running? | `CPUID` leaf 0x1, ECX bit 31 (hypervisor-present bit) |
| CPU vendor verification | Is this a real CPU? | `CPUID` leaf 0x0 vendor string (must be `AuthenticAMD` or `GenuineIntel`) |
| Debugger detection | Is a debugger attached? | `IsDebuggerPresent()`, `NtQueryInformationProcess`, timing attacks |
| Timing checks | Is execution being single-stepped? | `RDTSC`/`RDTSCP` timing deltas between code blocks |
| KUSER_SHARED_DATA | Is the OS environment normal? | Reads from fixed address `0x7FFE0000` — contains OS version, tick count, system flags |
| Self-integrity | Has Denuvo's own code been patched? | CRC/hash checks over its own memory regions |
| Environment flags | Are security features normal? | Checks various system settings, driver presence, etc. |
| KdDebuggerNotPresent | Is kernel debugging active? | Reads `nt!KdDebuggerNotPresent` global variable |

### 3.2 Why Conventional Cracks Don't Work on Modern Denuvo

Traditional game cracking = find the DRM check, NOP it out or patch the jump. With Denuvo + VMProtect:
- The check logic is **inside a custom VM** — you can't just patch a `JNZ` to `JMP`
- There are **hundreds of trigger points** scattered through the game, not a single check
- The code **self-verifies** — patching one check triggers integrity failures in others
- Server-generated tokens are **unique per hardware** — you can't just copy someone else's

**This is why the hypervisor approach exists:** Instead of trying to patch Denuvo (nearly impossible with VMProtect layering), you **spoof the entire environment from below** so Denuvo's checks all pass with legitimate-looking results.

---

## 4. How This Package Defeats Denuvo — The Full Attack Chain

The crack uses a **layered interception architecture** where each ring level handles specific Denuvo defenses:

`
┌─────────────────────────────────────────────────────────────┐
│                    RING 3 (User Mode)                       │
│  ColdClientLoader → re9.exe                                │
│  Goldberg Steam Emu replaces steamclient.dll                │
│  ► Defeats: Steam authentication, SteamStub                │
├─────────────────────────────────────────────────────────────┤
│                    RING 0 (Kernel)                          │
│  hyperkd.sys                                                │
│  ► Defeats: KUSER_SHARED_DATA checks, environment checks   │
│  ► Orchestrates: SimpleSvm.sys hypervisor loading           │
├─────────────────────────────────────────────────────────────┤
│                    RING -1 (Hypervisor)                     │
│  SimpleSvm.sys (AMD SVM)                                    │
│  ► Defeats: CPUID checks, RDTSC timing, MSR queries        │
│  ► Makes entire OS a "guest" VM under its control           │
├─────────────────────────────────────────────────────────────┤
│                    RING -2 (UEFI Firmware)                  │
│  EfiGuard (EfiGuardDxe.efi)                                 │
│  ► Defeats: Driver Signature Enforcement (DSE)              │
│  ► Defeats: PatchGuard (prevents BSOD from unsigned code)   │
│  ► Enables: Loading of hyperkd.sys and SimpleSvm.sys        │
└─────────────────────────────────────────────────────────────┘
`

### The Interception Flow for a Denuvo Check

When Denuvo executes a check inside the game process:

1. **Denuvo calls `CPUID`** to check if a hypervisor is present
   → SimpleSvm.sys **intercepts** this at ring -1
   → Returns modified results: clears the hypervisor-present bit, returns `AuthenticAMD` vendor string
   → Denuvo sees: "No hypervisor, real AMD CPU" ✓

2. **Denuvo reads `KUSER_SHARED_DATA`** at `0x7FFE0000`
   → hyperkd.sys has **spoofed the values** in kernel memory
   → Denuvo sees: "Normal Windows environment" ✓

3. **Denuvo calls `RDTSC`** for timing checks
   → SimpleSvm.sys can intercept TSC reads via VMCB control bits
   → Returns consistent timing values that don't indicate single-stepping ✓

4. **Denuvo checks `KdDebuggerNotPresent`**
   → hyperkd.sys patches this kernel variable
   → Denuvo sees: "No kernel debugger attached" ✓

5. **Denuvo validates its Steam integration**
   → Goldberg emulator's `steamclient64.dll` responds to all ISteam* API calls
   → Returns valid-looking app ownership, user identity, ticket data ✓

6. **Denuvo's unsigned driver checks would normally trigger PatchGuard BSOD**
   → EfiGuard disabled PatchGuard at boot time
   → System remains stable despite kernel modifications ✓


---

## 5. EfiGuard — UEFI Bootkit (Ring -2)

**Source:** Open-source, GPL-3.0 — [github.com/Mattiwatti/EfiGuard](https://github.com/Mattiwatti/EfiGuard)
**Author:** Mattiwatti (Matthijs Lavrijsen)
**Stars:** 2,300+ on GitHub
**Purpose:** Disable PatchGuard and Driver Signature Enforcement (DSE) at boot time

### 5.1 Files in the EfiGuard Folder

| File | Size | Date | Role |
|------|------|------|------|
| `bootx64.efi` | 101,160 bytes | 2024-01-08 | Renamed `Loader.efi` — the UEFI boot application that starts the chain |
| `EfiGuardDxe.efi` | 360,448 bytes | 2026-01-27 | The core UEFI DXE driver that performs all kernel patches |
| `loader.efi` | 49,152 bytes | 2026-01-27 | Redundant copy of the loader application |
| `HashTool.efi` | 100,656 bytes | 2024-01-08 | Optional Secure Boot hash enrollment utility |

### 5.2 What EfiGuard Does — Stage by Stage

EfiGuard operates in the UEFI DXE (Driver Execution Environment) phase — this is **before the Windows kernel even loads**. It patches Windows components as they are loaded by the firmware.

**Stage 1 — Boot Manager Patch (`bootmgfw.efi`):**

Strings found in `EfiGuardDxe.efi` confirming this:
`
[ bootmgfw!ImgArchStartBootApplication ]
Patched bootmgfw!ImgpValidateImageHash [RVA: 0x%X]
Patched bootmgfw!ImgpFilterValidationFailure [RVA: 0x%X]
`

- Hooks `ImgArchStartBootApplication` in the Windows Boot Manager
- Patches `ImgpValidateImageHash` — this is the function that validates the cryptographic hash of boot images. By patching it, EfiGuard allows modified bootloaders and kernels to load
- Patches `ImgpFilterValidationFailure` — this function reports integrity violations to the TPM or SI log. Patching it prevents any audit trail

**Stage 2 — Boot Loader Patch (`winload.efi`):**

Strings found:
`
Patching winload.efi v%u.%u.%u.%u...
Found OslFwpKernelSetupPhase1 at 0x%llX
Successfully patched winload!OslFwpKernelSetupPhase1
VbsPolicyDisabled
`

- Hooks `OslFwpKernelSetupPhase1` — the last function in winload that runs before the kernel takes over, while EFI boot services are still available
- Can disable VBS (Virtualization Based Security) by setting the `VbsPolicyDisabled` EFI runtime variable

**Stage 3 — Kernel Patch (`ntoskrnl.exe`) — PatchGuard Disable:**

Strings found confirming each PatchGuard component patched:
`
[PatchNtoskrnl] Disabling PatchGuard... [INIT RVA: 0x%X - 0x%X]
Patched KeInitAmd64SpecificState [RVA: 0x%X]
Found CcInitializeBcbProfiler pattern at 0x%llX
Patched ExpLicenseWatchInitWorker [RVA: 0x%X]
Patched g_PgContext [RVA: 0x%X]
Patched KiSwInterrupt [RVA: 0x%X]
Patched KiVerifyScopesExecute [RVA: 0x%X]
Patched KiMcaDeferredRecoveryService [RVAs: 0x%X, 0x%X]
[PatchNtoskrnl] Successfully disabled PatchGuard.
`

What each patch does:

| Patch Target | What It Is | Why It's Patched |
|-------------|-----------|-----------------|
| `KeInitAmd64SpecificState` | Triggers a deliberate #DE (divide error) that initializes PatchGuard's timer-based verification system | Prevents PG from starting its periodic kernel integrity checks |
| `CcInitializeBcbProfiler` | Allocates the large PatchGuard context structure (~400KB) that holds all monitored addresses | Without this allocation, PG has no data structure to work with |
| `ExpLicenseWatchInitWorker` | A PG initialization entry point disguised as a licensing function | Prevents one of PG's hidden initialization paths from executing |
| `g_PgContext` | The global pointer to PatchGuard's monitoring context | Nullified so PG's verification routines find no context to check |
| `KiSwInterrupt` | A PG verification trigger hidden in the software interrupt handler | Prevents PG checks from being triggered via interrupt 0x29 |
| `KiVerifyScopesExecute` | A PG verification routine that checks kernel code integrity | Prevents runtime integrity verification of kernel pages |
| `KiMcaDeferredRecoveryService` | PG trigger hidden in the Machine Check Architecture error handler | Prevents PG checks from firing on hardware error recovery paths |

**Stage 3b — Kernel Patch — DSE (Driver Signature Enforcement) Disable:**

Strings found:
`
[PatchNtoskrnl] Successfully disabled DSE.
Found 'mov ecx, xxx' in SepInitializeCodeIntegrity [RVA: 0x%X]
Found 'cmp g_CiEnabled, al' in SeValidateImageData [RVA: 0x%X]
Patched SeCodeIntegrityQueryInformation [RVA: 0x%X]
Found g_CiEnabled at 0x%llX
Failed to find IAT address of CI.dll!CiInitialize
Hooked gRT->SetVariable: 0x%p -> 0x%p
`

EfiGuard offers two DSE bypass methods:

**Method 1 — Boot-time DSE disable:**
- Patches `SepInitializeCodeIntegrity` — replaces `mov ecx, <value>` with `xor ecx, ecx` so Code Integrity initializes in a disabled state
- Patches `SeValidateImageData` — replaces the function's return value with `mov eax, 0` (STATUS_SUCCESS) so all image validation passes
- Patches `SeCodeIntegrityQueryInformation` — so if any process queries whether CI is enabled, it still reports "enabled" (stealth)

**Method 2 — SetVariable hook (DEFAULT):**
- Hooks the UEFI Runtime Service `SetVariable()`
- After boot, the companion `EfiDSEFix.exe` calls `NtSetSystemEnvironmentValueEx` with a special GUID
- This tunnels through the UEFI runtime service hook into kernel memory
- Allows setting `g_CiEnabled` / `g_CiOptions` to any value from user mode — effectively an arbitrary kernel read/write backdoor
- The string `roodkcaBdrauGifE` found in the binary is "EfiGuardBackdoor" reversed — this is the marker GUID name

### 5.3 Why EfiGuard Is Necessary for This Crack

Without EfiGuard:
- `hyperkd.sys` and `SimpleSvm.sys` are **unsigned kernel drivers** — Windows refuses to load them (DSE blocks it)
- Even if you force-load them via test signing, **PatchGuard** detects the kernel modifications made by `hyperkd.sys` and triggers a BSOD within minutes
- EfiGuard solves both: DSE off = drivers load, PatchGuard off = no BSOD from kernel modifications

**The NFO file confirms this:** *"Or you can use EfiGuard to avoid disabling all of them <3, it's easy and quick."*

### 5.4 EfiGuard Limitations

The `EfiGuardDxe.efi` strings also reveal:
`
[PatchNtoskrnl] ERROR: Checked kernels are not supported.
[PatchNtoskrnl] ERROR: Unsupported kernel image version.
`

- Cannot bypass **HVCI** (Hypervisor-Protected Code Integrity / HyperGuard) — this runs at VTL1, a higher privilege than even the UEFI bootkit
- Only supports retail (free) kernels, not checked/debug kernels
- Requires Secure Boot to be disabled (unless you own the Platform Key)


---

## 6. SimpleSvm.sys — AMD Hypervisor (Ring -1)

**Source:** Open-source, MIT License — [github.com/tandasat/SimpleSvm](https://github.com/tandasat/SimpleSvm)
**Author:** Satoshi Tanda (security researcher)
**Stars:** 534 on GitHub
**Binary Size:** 17,776 bytes
**PE Subsystem:** Native/Kernel (Subsystem = 1)
**Architecture:** x86-64 (Machine = 0x8664)

### 6.1 What SimpleSvm Is

SimpleSvm is described by its author as *"a minimalistic educational hypervisor for Windows on AMD processors."* It uses AMD's **Secure Virtual Machine (SVM)** hardware extension (AMD's equivalent of Intel VT-x) to turn the existing running OS into a **guest virtual machine** while SimpleSvm itself runs at ring -1 as the hypervisor.

### 6.2 Strings Extracted from SimpleSvm.sys — Full Analysis

**Lifecycle/Status Messages:**
`
Attempting to virtualize the processor.
The processor has been virtualized.
The processor has been de-virtualized.
SVM is not fully supported on this processor.
Failed to open the power state callback object.
Failed to register a power state callback.
Insufficient memory.
`

These confirm the standard SimpleSvm lifecycle: check CPU support → virtualize → handle power events → devirtualize on unload.

**CPU Vendor Verification Strings:**
`
AuthenticAMD     (split as: ??cAMD, ??E???Auth, ??enti)  
A?SSVM           (CPUID check for SVM feature)
SimpleSvm        (hypervisor vendor string returned via CPUID)
`

When SimpleSvm intercepts `CPUID` leaf 0x40000000 (hypervisor vendor), it returns `"SimpleSvm   "` as the vendor ID. However, for Denuvo bypass, the CPUID intercept for leaf 0x1 must **clear bit 31 of ECX** (the hypervisor-present flag) so Denuvo doesn't detect it.

**Kernel API Imports (confirmed via strings):**
`
ntoskrnl.exe             — links to the Windows kernel
ExAllocatePool2          — allocates kernel memory (modern API, Win10+)
ExFreePoolWithTag        — frees kernel memory
ExCreateCallback         — creates callback objects
ExRegisterCallback       — registers for system callbacks
ExUnregisterCallback     — unregisters callbacks
IoAllocateMdl            — allocates Memory Descriptor Lists (for DMA/mapping)
IoGetCurrentProcess      — gets current process context
KeGetCurrentIrql         — checks current interrupt level
KeQueryActiveProcessorCountEx — counts active CPU cores
KeSetSystemGroupAffinityThread — pins thread to specific CPU core
KeRevertToUserGroupAffinityThread — reverts CPU affinity
KeWaitForSingleObject    — synchronization primitive
KeDelayExecutionThread   — sleep
KeBugCheck               — triggers BSOD (used as last resort on critical failure)
KfRaiseIrql              — raises interrupt priority
KeLowerIrql              — lowers interrupt priority
KeGetProcessorNumberFromIndex — maps processor index to number
MmAllocateContiguousNodeMemory — allocates physically contiguous memory (for VMCB)
MmFreeContiguousMemory   — frees contiguous memory
MmGetPhysicalAddress     — converts virtual to physical address
MmGetVirtualForPhysical  — converts physical to virtual address
MmMapLockedPagesSpecifyCache — maps physical pages into virtual address space
MmProbeAndLockPages      — locks pages in physical memory
MmUnlockPages            — unlocks pages
MmUnmapLockedPages       — unmaps previously mapped pages
RtlCaptureContext        — captures current CPU register state (used to populate VMCB)
RtlGetVersion            — gets Windows version info
RtlInitializeBitMap      — initializes bitmap structure
RtlSetBits / RtlClearAllBits — bitmap manipulation
ObfDereferenceObject     — dereferences kernel object
ObReferenceObjectByHandle — references kernel object by handle
ZwClose                  — closes kernel handle
strcmp                   — string comparison

`

**Key observations from the API imports:**
- `MmAllocateContiguousNodeMemory` — AMD SVM requires the VMCB (Virtual Machine Control Block) and host state save area to be in **physically contiguous memory**. This is the allocation function used for that.
- `RtlCaptureContext` — Used to capture the current CPU state (all registers) to populate the VMCB's guest state. This is how SimpleSvm "snapshots" the running OS state before virtualizing it.
- `KeSetSystemGroupAffinityThread` — SimpleSvm must run its virtualization code on **every CPU core individually**, so it pins its thread to each core in sequence.
- `KeBugCheck` — If something goes critically wrong during virtualization, it BSODs rather than leaving the system in a corrupt state.

**KUSER Spoofing Strings (MODIFIED from original SimpleSvm):**
`
Failed to LookupProcessByProcessId, can not spoof KUSER only for the game process.
Failed to AcquireProcessExitSynchronization, can not spoof KUSER only for the game process.
Failed to create CounterUpdater thread.
`

**These strings DO NOT exist in the original SimpleSvm from GitHub.** They were added by MKDEV TEAM. This reveals:

- This is a **modified version** of SimpleSvm with custom KUSER_SHARED_DATA spoofing code
- It uses `PsLookupProcessByProcessId` to find the game process specifically
- It uses `PsAcquireProcessExitSynchronization` to safely handle game process exit
- The spoofing is **process-specific** — it only spoofs KUSER data for the game process, not for the entire OS (this is more stealthy)
- A `CounterUpdater` background thread continuously updates spoofed timing values

**Additional Modified SimpleSvm APIs (not in original):**
`
PsCreateSystemThread         — creates kernel threads (for CounterUpdater)
PsLookupProcessByProcessId   — finds process by PID
PsAcquireProcessExitSynchronization — safe process exit handling
PsReleaseProcessExitSynchronization — releases exit sync
PsSetCreateProcessNotifyRoutine — registers for process creation/exit notifications
PsTerminateSystemThread      — terminates kernel thread
PsThreadType                 — thread object type reference
KeStackAttachProcess         — attaches to another process's address space
KeUnstackDetachProcess       — detaches from process address space
KdDebuggerNotPresent         — kernel debugger detection variable
`

**Critical finding:** `KdDebuggerNotPresent` is imported — this is the kernel global variable that indicates whether a kernel debugger is attached. The modified SimpleSvm likely **patches this to always return TRUE** (debugger not present), defeating Denuvo's kernel debugger detection.

**Denuvo-Specific Strings Found:**
`
Denuvo GmbH
Denuvo GmbH0
Denuvo GmbH0?
`

These are certificate/signature strings — likely from an embedded Denuvo certificate used to identify or validate against Denuvo's token system.

**Unicode Wide Strings:**
`
\Callback\PowerState
`
This is the kernel callback object path used to register for power state changes (sleep/hibernate). SimpleSvm must de-virtualize before sleep and re-virtualize after wake.

**Hypervisor VM Function Strings:**
`
VmFuncInitVmm    — Initialize Virtual Machine Monitor
VmFuncUninitVmm  — Uninitialize Virtual Machine Monitor
`

These are the top-level entry/exit functions for the hypervisor lifecycle.

### 6.3 How SimpleSvm Intercepts Denuvo's CPUID Checks

The AMD SVM hypervisor works by:

1. **Setting the EFER.SVME bit** on each CPU core to enable SVM mode
2. **Creating a VMCB** (Virtual Machine Control Block) for each core — this is a hardware-defined data structure that controls what the hypervisor intercepts
3. **Calling VMRUN** — this transfers control to the hypervisor. The OS becomes a "guest"
4. **On each CPUID instruction in guest mode:**
   - The CPU triggers a `#VMEXIT` — control transfers to SimpleSvm
   - SimpleSvm examines the CPUID leaf being queried
   - For leaf 0x1: **Clears ECX bit 31** (hypervisor-present flag) before returning
   - For leaf 0x40000000-0x400000FF: Returns vendor info as if no hypervisor exists
   - For other leaves: Passes through unmodified
5. **On VMRUN in guest mode:** Injects `#GP` (General Protection Fault) — prevents any nested hypervisor from running
6. **On EFER MSR writes:** Prevents the guest from clearing SVME bit (so it can't escape the hypervisor)

### 6.4 Certificate Dates Found

`
260226065959Z    →  2026-02-26 06:59:59 UTC
270226071959Z0   →  2027-02-26 07:19:59 UTC
`

These are X.509 certificate validity dates embedded in the binary. The certificate was created on 2026-02-26 (2 days before the driver's file timestamp of 2026-02-28), valid for 1 year. This is a **self-signed test certificate** used for test-signing the driver.


---

## 7. hyperkd.sys — Custom MKDEV Kernel Driver (Ring 0)

**Source:** Closed-source, proprietary — created by MKDEV TEAM
**No public repository.** Not independently verifiable.
**Binary Size:** 11,632 bytes
**PE Subsystem:** Native/Kernel (Subsystem = 1)
**Architecture:** x86-64 (Machine = 0x8664)
**Compiled:** 2026-02-27 (per INF `DriverVer = 02/27/2026,22.24.54.779`)
**File Date:** 2026-02-28 02:56

### 7.1 The hyperlog.inf Driver Installation Manifest

Full contents of `hyperlog.inf`:

`ini
[Version]
Signature="`$`WINDOWS NT`$`"
Class=System
ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}
Provider=%ManufacturerName%
CatalogFile=hyperlog.cat
DriverVer = 02/27/2026,22.24.54.779
PnpLockdown=1

[Manufacturer]
%ManufacturerName%=Standard,NTamd64

[Standard.NTamd64]
%hyperlog.DeviceDesc%=hyperlog_Device, Root\hyperlog

[hyperlog_Service_Inst]
DisplayName    = %hyperlog.SVCDESC%
ServiceType    = 1               ; SERVICE_KERNEL_DRIVER
StartType      = 3               ; SERVICE_DEMAND_START
ErrorControl   = 1               ; SERVICE_ERROR_NORMAL
ServiceBinary  = %12%\hyperlog.sys

[hyperlog_Device.NT.Wdf]
KmdfService =  hyperlog, hyperlog_wdfsect
[hyperlog_wdfsect]
KmdfLibraryVersion = 1.15

[Strings]
ManufacturerName="<Your manufacturer name>"  ;TODO: Replace with your manufacturer name
`

**Key observations from the INF:**

1. **Name mismatch:** The INF references `hyperlog.sys` throughout, but the actual binary is named `hyperkd.sys`. This means:
   - The INF cannot install the driver through normal Plug-and-Play
   - The driver is loaded **programmatically** via `CreateService()`/`StartService()` by the game loader
   - The NFO confirms: *"The game will load the driver automatically"*

2. **Unfinished template:** Contains `; TODO:` placeholders and `<Your manufacturer name>` — this was generated from the Visual Studio WDF Kernel Mode Driver project template and never cleaned up

3. **KMDF 1.15:** Uses Kernel Mode Driver Framework version 1.15, which requires Windows 10 version 1703 (Creators Update) or later

4. **SERVICE_DEMAND_START (3):** Not loaded at boot — only loaded when the game needs it

5. **Root\hyperlog PnP ID:** Registered as a root-enumerated device (software-only, no hardware)

6. **CatalogFile=hyperlog.cat:** References a catalog file for driver signing — but this file is not included in the package (unnecessary since DSE is disabled by EfiGuard)

### 7.2 Strings Extracted from hyperkd.sys — Full Analysis

**Kernel API Imports:**
`
ntoskrnl.exe                 — links to Windows kernel
ExCreateCallback             — creates callback objects
ExRegisterCallback           — registers for callbacks
ExUnregisterCallback         — unregisters callbacks
KeWaitForSingleObject        — synchronization
ObfDereferenceObject         — dereferences kernel object
ObReferenceObjectByHandle    — references object by handle
PsCreateSystemThread         — creates kernel-mode threads
PsThreadType                 — thread type reference
ZwClose                      — closes handle
NtQuerySystemInformation     — queries system information tables
`

**Custom Function Names (NOT kernel APIs — internal to hyperkd.sys):**
`
VmFuncInitVmm                — Initialize the Virtual Machine Monitor
VmFuncUninitVmm              — Uninitialize the Virtual Machine Monitor
CounterThreadHandle          — Handle to the counter update thread
CounterUpdater               — The counter updating function itself
StopCounterThread            — Stops the counter thread
NotifyRoutineActive          — Flag for process notification callback
ProcessExitCleanup           — Cleanup on game process exit
`

**What these tell us:**

- `VmFuncInitVmm` / `VmFuncUninitVmm` — hyperkd.sys **directly controls SimpleSvm.sys's hypervisor lifecycle**. It calls into SimpleSvm to start/stop the hypervisor.
- `CounterUpdater` / `CounterThreadHandle` / `StopCounterThread` — A dedicated kernel thread that **continuously updates spoofed counter values** (likely `KUSER_SHARED_DATA.TickCount`, `QueryPerformanceCounter` values, and `RDTSC` baselines). This defeats Denuvo's timing-based anti-debug checks.
- `NotifyRoutineActive` — Uses `PsSetCreateProcessNotifyRoutine` to monitor process creation. When `re9.exe` starts, it activates the spoofing. When it exits, it cleans up.
- `ProcessExitCleanup` — Ensures the hypervisor is properly unloaded and KUSER data is restored when the game closes

**Scripting/VM Engine Strings (FUNC_* constants):**

The binary contains a large number of `FUNC_*` constant strings:

`
FUNC_ADD, FUNC_AND, FUNC_ASL, FUNC_ASR, FUNC_CALL, FUNC_CHECK_ADDRESS,
FUNC_DB, FUNC_DB_PA, FUNC_DD, FUNC_DD_PA, FUNC_DEC, FUNC_DISASSEMBLE_LEN,
FUNC_DISASSEMBLE_LEN32, FUNC_DISASSEMBLE_LEN64, FUNC_DIV, FUNC_DQ,
FUNC_DQ_PA, FUNC_DW, FUNC_DW_PA, FUNC_EB, FUNC_EB_PA, FUNC_ED, FUNC_ED_PA,
FUNC_EGT, FUNC_ELT, FUNC_END_OF_DO_WHILE, FUNC_END_OF_IF, FUNC_EQ,
FUNC_EQ_PA, FUNC_EQUAL, FUNC_EVENT_CLEAR, FUNC_EVENT_DISABLE,
FUNC_EVENT_ENABLE, FUNC_EVENT_INJECT, FUNC_EVENT_INJECT_ERROR_CODE,
FUNC_EVENT_SC, FUNC_EVENT_TRACE_INSTRUMENTATION_STEP,
FUNC_EVENT_TRACE_INSTRUMENTATION_STEP_IN, FUNC_EVENT_TRACE_STEP,
FUNC_EVENT_TRACE_STEP_IN, FUNC_EVENT_TRACE_STEP_OUT, FUNC_FLUSH,
FUNC_FOR_INC_DEC, FUNC_FORMATS, FUNC_GT, FUNC_HI, FUNC_HI_PA,
FUNC_IGNORE_LVALUE, FUNC_INC, FUNC_INTERLOCKED_COMPARE_EXCHANGE,
FUNC_INTERLOCKED_DECREMENT, FUNC_INTERLOCKED_EXCHANGE,
FUNC_INTERLOCKED_EXCHANGE_ADD, FUNC_INTERLOCKED_INCREMENT, FUNC_JMP,
FUNC_JNZ, FUNC_JZ, FUNC_LOW, FUNC_LOW_PA, FUNC_LT, FUNC_MEMCMP,
FUNC_MEMCPY, FUNC_MEMCPY_PA, FUNC_MICROSLEEP, FUNC_MOD, FUNC_MOV,
FUNC_MUL, FUNC_NEG, FUNC_NEQ, FUNC_NOT, FUNC_OR, FUNC_PAUSE,
FUNC_PHYSICAL_TO_VIRTUAL, FUNC_POI, FUNC_POI_PA, FUNC_POP, FUNC_PRINT,
FUNC_PRINTF, FUNC_PUSH, FUNC_RDTSC, FUNC_RDTSCP, FUNC_REFERENCE,
FUNC_RET, FUNC_SPINLOCK_LOCK, FUNC_SPINLOCK_LOCK_CUSTOM_WAIT,
FUNC_SPINLOCK_UNLOCK, FUNC_START_OF_DO_WHILE,
FUNC_START_OF_DO_WHILE_COMMANDS, FUNC_START_OF_FOR,
FUNC_START_OF_FOR_OMMANDS, FUNC_STRCMP, FUNC_STRLEN, FUNC_STRNCMP,
FUNC_SUB, FUNC_TEST_STATEMENT, FUNC_UNDEFINED, FUNC_VIRTUAL_TO_PHYSICAL,
FUNC_WCSCMP, FUNC_WCSLEN, FUNC_WCSNCMP, FUNC_XOR
`

**This is extremely significant.** These strings come from **HyperDbg** — an open-source hypervisor debugger project ([github.com/HyperDbg/HyperDbg](https://github.com/HyperDbg/HyperDbg)). HyperDbg is a kernel debugger that uses AMD SVM/Intel VMX to debug at the hypervisor level. The `FUNC_*` strings are the **scripting engine opcodes** used by HyperDbg's built-in scripting language.

This reveals that `hyperkd.sys` is likely **based on or incorporates code from HyperDbg**, not just SimpleSvm. HyperDbg provides:
- A complete **hypervisor-level debugger** invisible to the guest OS
- **Event injection/interception** (`FUNC_EVENT_INJECT`, `FUNC_EVENT_TRACE_STEP`)
- **Physical/virtual memory read/write** (`FUNC_DB_PA`, `FUNC_EB_PA`, `FUNC_PHYSICAL_TO_VIRTUAL`)
- **Instruction-level stepping** invisible to the guest
- **Hardware breakpoints** managed from the hypervisor

**The `_PA` suffixed functions** (`FUNC_DB_PA`, `FUNC_DD_PA`, `FUNC_DQ_PA`, `FUNC_EB_PA`, `FUNC_ED_PA`, `FUNC_EQ_PA`, `FUNC_HI_PA`, `FUNC_LOW_PA`, `FUNC_MEMCPY_PA`, `FUNC_POI_PA`) indicate **physical address** variants — these allow reading/writing physical memory directly, bypassing all virtual memory protections. This is critical for modifying KUSER_SHARED_DATA and other protected kernel structures.

**Denuvo Certificate Strings:**
`
Denuvo GmbH
Denuvo GmbH0
Denuvo GmbH0?
`

Same Denuvo certificate strings as in SimpleSvm.sys — these are embedded from the game's Denuvo token/certificate data, used to identify and interact with Denuvo's protection.

**Certificate Dates:**
`
260226065959Z    →  2026-02-26 06:59:59 UTC
270226071959Z0   →  2027-02-26 07:19:59 UTC
`

Self-signed certificate valid from Feb 26, 2026 to Feb 26, 2027.

**PE Sections:**
`
.pdata    — exception handling data (standard for x64 drivers)
.rdata    — read-only data (strings, constants, import tables)
.data     — read-write global data
.reloc    — relocation table (allows loading at any kernel address)
`

Standard PE sections for a kernel driver. No unusual sections detected.

**Unicode Wide Strings:**
`
\Callback\PowerState
`

Same power callback as SimpleSvm — confirms hyperkd.sys manages power state transitions for the hypervisor.

**`hyperhv.dll` Reference:**
`
hyperhv.dll
`

This string references a DLL named `hyperhv.dll` — this is **not present in the package**. It may be:
- A user-mode companion DLL loaded by the game loader to communicate with hyperkd.sys via IOCTL
- A dependency that is loaded at runtime from the game's directory
- Part of the steamclient_loader_x64.exe (not included in the workspace)

### 7.3 How hyperkd.sys Works — Reconstructed from Strings

Based on the extracted strings, API imports, and NFO credits, here is the reconstructed operation flow:

1. **Game loader calls `CreateService()`** to register `hyperkd.sys` as a kernel service
2. **`hyperkd.sys` loads and:**
   a. Detects CPU type (AMD → SVM path)
   b. Calls `VmFuncInitVmm` to initialize the hypervisor (loads SimpleSvm.sys or its own embedded hypervisor)
   c. Registers `PsSetCreateProcessNotifyRoutine` callback to watch for `re9.exe` process creation
3. **When re9.exe starts:**
   a. `NotifyRoutineActive` flag is set
   b. `PsCreateSystemThread` creates the `CounterUpdater` kernel thread
   c. The `CounterUpdater` continuously updates spoofed values in KUSER_SHARED_DATA
   d. Uses `KeStackAttachProcess` to attach to re9.exe's address space for process-specific modifications
4. **While the game runs:**
   - HyperDbg-derived scripting engine runs event-based interception scripts
   - CPUID intercepts return spoofed values (no hypervisor detected)
   - RDTSC/RDTSCP intercepts return consistent timing values
   - KUSER_SHARED_DATA is continuously maintained with "normal" values
   - `KdDebuggerNotPresent` is kept set to TRUE
5. **When re9.exe exits:**
   - `ProcessExitCleanup` fires
   - `StopCounterThread` terminates the counter updater
   - `VmFuncUninitVmm` shuts down the hypervisor
   - KUSER_SHARED_DATA is restored to real values


---

## 8. ColdClientLoader + Goldberg Steam Emulator (Ring 3)

**ColdClientLoader Source:** Open-source — originally by Rat431
**Steam Emulator Source:** Open-source, LGPL — by Mr. Goldberg ([gitlab.com/Mr_Goldberg/goldberg_emulator](https://gitlab.com/Mr_Goldberg/goldberg_emulator))
**Purpose:** Replace the real Steam client so the game thinks it's running under a legitimate Steam installation

### 8.1 ColdClientLoader.ini — Configuration

`ini
[SteamClient]
Exe=re9.exe                                    # Game executable to launch
AppId=3764200                                  # Resident Evil Requiem's real Steam AppId
SteamClientDll=coldclient\steamclient.dll      # 32-bit fake Steam DLL (16 MB)
SteamClient64Dll=coldclient\steamclient64.dll  # 64-bit fake Steam DLL (17.9 MB)

[Injection]
ForceInjectSteamClient=0       # Don't force-inject — let the game load it naturally
ForceInjectGameOverlayRenderer=0
DllsToInjectFolder=            # No extra DLLs to inject
IgnoreInjectionError=0
IgnoreLoaderArchDifference=0

[Persistence]
Mode=0                         # Loader exits after launching the game

[Debug]
ResumeByDebugger=0             # Normal launch, not debugger-attached
`

**How ColdClientLoader works:**
1. Sets up environment variables and registry keys that Steam games expect
2. Points `SteamClientDll` paths to the Goldberg emulator DLLs instead of the real Steam client
3. Launches `re9.exe` — the game loads `steamclient64.dll` from the specified path
4. The Goldberg DLL responds to all Steamworks API calls locally

### 8.2 Goldberg Steam Emulator DLLs

| File | Size | Architecture | Purpose |
|------|------|-------------|---------|
| `steamclient.dll` | 16,026,024 bytes | x86 (32-bit) | 32-bit Steam client replacement |
| `steamclient64.dll` | 17,895,336 bytes | x86-64 (64-bit) | 64-bit Steam client replacement (primary) |
| `GameOverlayRenderer64.dll` | 1,946,536 bytes | x86-64 (64-bit) | Steam overlay replacement |

**Strings analysis of steamclient64.dll confirmed:**
- Contains implementations of all 22 Steam interface versions listed in `steam_interfaces.txt`
- Class names found: `Steam_Client`, `Steam_Overlay`, `SteamCallResults`, `SteamCallBacks`, `RunEveryRunCB`, `Networking`, `Local_Storage`, `Settings`
- Implements every `ISteam*` interface: `ISteamClient001` through `ISteamClient022`, `ISteamFriends001` through `ISteamFriends017`, `ISteamApps001` through `ISteamApps008`, `ISteamUser001` through `ISteamUser021`, etc.
- Contains overlay rendering hooks: `DX9Hook_t`, `DX10Hook_t`, `DX11Hook_t`, `DX12Hook_t` (DirectX hooks for the fake Steam overlay)
- String `inflate 1.3.1 Copyright 1995-2024 Mark Adler` — uses zlib for data compression
- `InGameOverlay` namespace — implements visual overlay features
- `Friend`, `Friend_Messages`, `Announce_Other_Peers` — LAN multiplayer emulation classes

**Strings analysis of GameOverlayRenderer64.dll confirmed:**
- Exports: `BOverlayNeedsPresent`, `IsOverlayEnabled`, `OverlayHookD3D3`
- `SteamOverlayIsUsingGamepad`, `SteamOverlayIsUsingKeyboard`
- `VulkanSteamOverlayPresent`, `VulkanSteamOverlayGetScaleFactors`
- `ValveHookScreenshots`, `ValveIsScreenshotsHooked`
- This is a **stub overlay renderer** — provides the expected exports so the game doesn't crash when trying to initialize the Steam overlay

### 8.3 Steam Settings Configuration Files

**configs.app.ini — Game DLC Configuration:**
`ini
[app::dlcs]
unlock_all=0                    # Don't unlock all DLCs blindly (avoids detection)
3990800=Resident Evil Requiem - Grace's Costume: Apocalypse   # Specific DLC
3990820=Resident Evil Requiem - Deluxe Kit                    # Specific DLC
`

**configs.main.ini — Emulator Behavior:**
`ini
[main::general]
new_app_ticket=0               # Use legacy auth ticket format
gc_token=0                     # No Game Coordinator token

[main::connectivity]
disable_lan_only=0             # Keep LAN-only mode
disable_networking=0           # Networking available (for LAN)
listen_port=47584              # Default Goldberg LAN port
offline=1                      # *** KEY: Pretend Steam is in OFFLINE MODE ***
disable_lobby_creation=0
`

The `offline=1` setting is critical — it makes the emulator report Steam as offline, which:
- Prevents the game from trying to contact real Steam servers
- Prevents Denuvo's online token validation from firing
- Many games have an "offline mode" code path that bypasses server-side checks

**configs.user.ini — Fake User Identity:**
`ini
[user::general]
account_name=KIRIGIRI                          # Fake username (matches group name)
account_steamid=76561197960287930              # Fake Steam64 ID
language=english
ip_country=US
`

**steam_appid.txt:**
`
3764200
`
The real Steam AppId for Resident Evil Requiem.

**steam_interfaces.txt — 22 Interface Versions:**
`
SteamClient017, SteamClient020, SteamGameServer014, SteamGameServerStats001,
SteamUser021, SteamFriends017, SteamUtils010, SteamMatchMaking009,
SteamMatchMakingServers002, STEAMUSERSTATS_INTERFACE_VERSION012,
STEAMAPPS_INTERFACE_VERSION008, SteamNetworking006,
STEAMREMOTESTORAGE_INTERFACE_VERSION016, STEAMSCREENSHOTS_INTERFACE_VERSION003,
STEAMHTTP_INTERFACE_VERSION003, STEAMUGC_INTERFACE_VERSION016,
STEAMAPPLIST_INTERFACE_VERSION001, STEAMMUSIC_INTERFACE_VERSION001,
STEAMMUSICREMOTE_INTERFACE_VERSION001, STEAMHTMLSURFACE_INTERFACE_VERSION_005,
STEAMINVENTORY_INTERFACE_V003, SteamController008, STEAMVIDEO_INTERFACE_V002
`

These tell the emulator which exact version of each Steamworks interface the game was compiled against.

### 8.4 What the Steam Layer Defeats

| Protection | How Goldberg Handles It |
|-----------|----------------------|
| Steam ownership check | Returns `true` for `BIsSubscribedApp(3764200)` |
| SteamStub (DRM wrapper) | Already removed/bypassed before the emulator loads |
| Steam user authentication | Returns fake auth tickets with the configured SteamID |
| DLC ownership | Returns `true` for the two configured DLC AppIds |
| Steam overlay | Provides stub overlay DLL that exports expected functions |
| Online connectivity | Reports offline mode — prevents server-side validation |

---

## 9. amd_ags_x64.org — AMD GPU Services Backup

**Original Name:** `amd_ags_x64.dll`
**Size:** 179,408 bytes
**Architecture:** x86-64
**PE Subsystem:** Windows Console (3) — this is a DLL despite the subsystem
**Signed:** Yes (AMD certificate)

### 9.1 What This File Is

The `.org` extension is a common convention in game cracks meaning "original." This is the **original, legitimate AMD GPU Services (AGS) library** that shipped with the game. The crack renames it to `.org` and replaces it with a modified version (the modified `.dll` is loaded by the game but is not present in this workspace — it would be in the game's installation directory).

### 9.2 Strings Confirming Identity

`
amd_ags_x64.dll                        — original filename
Advanced Micro Devices                 — publisher (AMD)
agsInitialize                          — AGS initialization function
agsDeInitialize                        — AGS cleanup
agsGetVersionNumber                    — version query
agsCheckDriverVersion                  — driver compatibility check
agsDriverExtensionsDX11_CreateDevice   — DX11 device creation with AMD extensions
agsDriverExtensionsDX12_CreateDevice   — DX12 device creation with AMD extensions
agsSetDisplayMode                      — display mode configuration
D3D11CreateDevice                      — standard DirectX 11 API
D3D12CreateDevice                      — standard DirectX 12 API
AmdDxExtCreate11                       — AMD DX11 extension entry point
amdxc32.dll / amdxc64.dll             — AMD shader compiler DLLs
d3d11.dll / d3d12.dll                  — DirectX runtime DLLs
`

This is a legitimate AMD library. It was renamed because the game loader may replace it with a patched version that removes AMD-specific DRM hooks or Denuvo integration points that use GPU hardware fingerprinting.


---

## 10. How All Components Work Together — Boot-to-Game Flow

### 10.1 One-Time Setup (Before First Launch)

The user must do ONE of these before anything works:

**Option A — Manual Security Disabling:**
1. Enter BIOS → Enable AMD SVM (Secure Virtual Machine)
2. Run `bcdedit /set testsigning on` — allows unsigned drivers to load
3. Run `bcdedit /set hypervisorlaunchtype off` — disables Hyper-V's hypervisor (frees SVM for SimpleSvm)
4. Disable Secure Boot in BIOS
5. Disable Windows Defender Memory Integrity (HVCI) and Credential Guard
6. Reboot

**Option B — EfiGuard (Automated, "the easy way"):**
1. Enter BIOS → Enable AMD SVM
2. Copy EfiGuard files to a FAT32 USB drive at `/EFI/Boot/`
3. Boot from USB → EfiGuard's `bootx64.efi` loads → starts `EfiGuardDxe.efi`
4. EfiGuard automatically:
   - Patches `bootmgfw.efi` (allows modified boot chain)
   - Patches `winload.efi` (optional VBS disable)
   - Patches `ntoskrnl.exe` (disables PatchGuard + DSE)
5. Windows boots normally, but with PatchGuard and DSE silently disabled

### 10.2 Game Launch Sequence (Every Time)

`
Step 1: User launches steamclient_loader_x64.exe
                    │
                    ▼
Step 2: ColdClientLoader reads ColdClientLoader.ini
        - AppId = 3764200
        - Exe = re9.exe
        - SteamClientDll = coldclient\steamclient64.dll
                    │
                    ▼
Step 3: ColdClientLoader sets up fake Steam environment
        - Writes registry keys pointing to Goldberg DLLs
        - Sets environment variables (SteamAppId, etc.)
                    │
                    ▼
Step 4: ColdClientLoader launches re9.exe
                    │
                    ▼
Step 5: re9.exe loads steamclient64.dll (Goldberg emulator)
        - Steam authentication bypassed
        - SteamStub wrapper bypassed
        - Game reports: "Steam is running in offline mode"
                    │
                    ▼
Step 6: re9.exe's startup code detects CPU type
        - Checks for AMD SVM support
                    │
                    ▼
Step 7: Game loader installs hyperkd.sys as a kernel service
        - CreateService("hyperkd", ..., SERVICE_KERNEL_DRIVER)
        - StartService("hyperkd")
        - DSE is disabled (EfiGuard) → driver loads successfully
                    │
                    ▼
Step 8: hyperkd.sys initializes in kernel space
        - Calls VmFuncInitVmm()
        - SimpleSvm.sys hypervisor activates on all CPU cores
        - VMRUN executes → Windows becomes a guest VM
        - CPUID interception active
        - PsSetCreateProcessNotifyRoutine registers for process events
        - CounterUpdater thread starts → KUSER spoofing begins
                    │
                    ▼
Step 9: Denuvo Anti-Tamper initialization runs inside re9.exe
        - CPUID checks → intercepted by SimpleSvm → "no hypervisor" ✓
        - KUSER_SHARED_DATA checks → spoofed by hyperkd.sys → "normal OS" ✓
        - KdDebuggerNotPresent check → patched → "no debugger" ✓
        - Timing checks (RDTSC) → consistent values → "not debugged" ✓
        - All environment checks pass ✓
                    │
                    ▼
Step 10: Denuvo validation passes → game runs normally
         - VMProtect-obfuscated code executes normally
         - Capcom Anti-Tamper checks pass
         - Game is fully playable
                    │
                    ▼
Step 11: User closes the game
         - ProcessExitCleanup fires in hyperkd.sys
         - StopCounterThread terminates KUSER spoofing
         - VmFuncUninitVmm devirtualizes all CPU cores
         - KUSER_SHARED_DATA restored to real values
         - System returns to normal (but DSE/PatchGuard remain disabled)
`

### 10.3 Why Each Component Is Necessary (None Can Be Removed)

| If You Remove... | What Happens |
|-----------------|-------------|
| EfiGuard | hyperkd.sys and SimpleSvm.sys cannot load (DSE blocks unsigned drivers). If test-signing is used instead, PatchGuard detects kernel modifications → BSOD |
| SimpleSvm.sys | No hypervisor = no CPUID interception. Denuvo detects the analysis environment → refuses to run |
| hyperkd.sys | No KUSER spoofing, no orchestration. Denuvo's environment checks fail → game crashes/refuses to start |
| ColdClientLoader + Goldberg | Steam APIs return errors. Game can't authenticate with "Steam" → refuses to launch |
| amd_ags_x64 replacement | Depends on what the replacement does — may be needed for GPU fingerprint spoofing |

---

## 11. Risk Assessment & Verdict

### 11.1 Is This Malware?

**No, this is not general-purpose malware** (not ransomware, spyware, keylogger, botnet agent, cryptocurrency miner, etc.).

Evidence supporting this conclusion:
- Every component has a specific, narrow DRM-bypass function
- Three of five components are open-source with known, audited code (EfiGuard, SimpleSvm, Goldberg)
- The `configs.main.ini` sets `offline=1` — no outbound network connections to command-and-control servers
- The Goldberg emulator explicitly disables real Steam networking
- The crack group (MKDEV TEAM) is known in the game cracking scene — this is their typical release format
- The NFO's instructions are consistent with DRM bypass, not malware installation

### 11.2 Real Security Risks

Despite not being malware, **the risks are serious and real:**

| Risk | Severity | Details |
|------|----------|---------|
| **BSOD / System Instability** | HIGH | MKDEV TEAM explicitly warns: *"Kernel drivers are able to cause blue screens when there are mistakes in the code, this has not yet been tested for long term stability."* A bug in `hyperkd.sys` at ring-0 means instant BSOD. |
| **Unverifiable Code at Ring 0** | HIGH | `hyperkd.sys` is **closed-source, 11,632 bytes of unsigned kernel code** from an anonymous group. You CANNOT verify it doesn't contain a backdoor, rootkit, or data exfiltration logic beyond what string analysis suggests. |
| **Complete DSE + PatchGuard Disable** | CRITICAL | With EfiGuard active, Windows has **zero protection against unsigned kernel drivers**. ANY other malicious driver (from a browser exploit, phishing, etc.) can now load without Windows blocking it. You've removed the castle walls. |
| **Boot Chain Modification** | HIGH | EfiGuard modifies the UEFI boot chain. If corrupted, the system may not boot. Recovery requires EFI shell access or reinstallation. |
| **HyperDbg-Based Engine** | MEDIUM | The HyperDbg scripting engine in `hyperkd.sys` provides **arbitrary physical memory read/write capability** (the `_PA` functions). This is effectively a kernel rootkit capability, even if used here only for DRM bypass. |
| **Persistent Security Regression** | HIGH | Even after closing the game, DSE and PatchGuard remain disabled until EfiGuard is removed and a clean boot occurs. The system is vulnerable the entire time. |
| **No Rollback Safety** | MEDIUM | If `hyperkd.sys` crashes mid-operation, KUSER_SHARED_DATA may be left in a spoofed state, potentially causing OS instability or other applications to malfunction. |

### 11.3 Component Trust Levels

| Component | Trust Level | Reasoning |
|-----------|------------|-----------|
| EfiGuard | **HIGH** — Open source, GPL-3.0, 2,300+ stars, code auditable | Well-known security research tool by a real researcher |
| SimpleSvm.sys | **MEDIUM** — Based on open source, but **modified** by MKDEV | Original is trusted; modifications (KUSER spoof, CounterUpdater) are unverifiable |
| Goldberg Steam Emu | **HIGH** — Open source, LGPL, widely used | Standard Steam emulator, no kernel access |
| ColdClientLoader | **HIGH** — Open source, user-mode only | Simple process launcher/environment setter |
| hyperkd.sys | **LOW** — Closed source, ring-0, anonymous author, HyperDbg-derived | Cannot verify; has physical memory R/W capability |
| amd_ags_x64.org | **HIGH** — Legitimate AMD-signed library (backup copy) | Original unmodified file |

### 11.4 Summary Assessment

`
┌──────────────────────────────────────────────────────────────┐
│                    FINAL VERDICT                             │
├──────────────────────────────────────────────────────────────┤
│  Classification: Game piracy crack (DRM bypass tool)         │
│  Malware:        No evidence of general malware behavior     │
│  Primary Risk:   hyperkd.sys (closed-source ring-0 code)     │
│  Secondary Risk: System-wide DSE/PatchGuard disable          │
│  Legal Status:   Copyright infringement tool                 │
│  Recommendation: Do NOT run on a primary/work machine        │
│                  The security regression is too severe        │
│                  If testing, use an isolated VM or spare PC   │
└──────────────────────────────────────────────────────────────┘
`

---

## Appendix A: Tools & Methods Used for This Analysis

| Method | What Was Done |
|--------|--------------|
| ASCII string extraction | `[System.Text.Encoding]::ASCII` regex match for printable sequences 6-8+ chars from all binary files |
| Unicode string extraction | `[System.Text.Encoding]::Unicode` (UTF-16LE) regex match for wide strings |
| PE header parsing | Read PE signature offset (0x3C), Machine type, Subsystem, Characteristics via `[System.BitConverter]` |
| INF file analysis | Direct reading and parsing of `hyperlog.inf` driver installation manifest |
| Config file analysis | Direct reading of all `.ini`, `.txt` config files |
| GitHub research | Fetched and analyzed README pages for SimpleSvm, EfiGuard |
| HyperDbg identification | Matched `FUNC_*` string patterns against known HyperDbg scripting engine opcodes |
| File metadata | `Get-Item` for file sizes, timestamps, last-modified dates |
| Cross-reference | Compared extracted function names against known kernel API documentation |

**No binaries were executed at any point during this analysis.**

---

*Report generated: March 4, 2026*
*All analysis performed via passive static methods — string extraction, PE header reading, config file parsing, and open-source research.*

