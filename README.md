# Comprehensive Security Audit for my college project
## Resident.Evil.Requiem.HYPERVISOR.V2-KIRIGIRI

**Audit Date:** March 4, 2026

**Analyst:** Independent student research project -- this is NOT an official or professional security audit

**Method:** Passive static analysis only -- string extraction, PE header analysis, INF parsing, config file review, GitHub open-source research, Ghidra 12.0.4 decompilation. No binaries were executed.

**Source Files Download:** [https://file-me.top/kpypgyn3k47v.html](https://file-me.top/kpypgyn3k47v.html)

**Disclaimer:** I am not an expert like the crack developers or CSRIN mods. Please don't take this as any official guide, I am just showing my findings of how Denuvo is being bypassed using this method. AI-assisted analysis was used in the creation of this report.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Complete File Inventory](#2-complete-file-inventory)
3. [How Denuvo Anti-Tamper Works](#3-how-denuvo-anti-tamper-works)
4. [How This Package Defeats Denuvo -- The Full Attack Chain](#4-how-this-package-defeats-denuvo--the-full-attack-chain)
5. [EfiGuard -- UEFI Bootkit (Ring -2)](#5-efiguard--uefi-bootkit-ring--2)
6. [SimpleSvm.sys -- AMD Hypervisor (Ring -1)](#6-simplesvmsys--amd-hypervisor-ring--1)
7. [hyperkd.sys -- Intel Hypervisor Driver (Ring -1 / Ring 0)](#7-hyperkdsys--intel-hypervisor-driver-ring--1--ring-0)
8. [ColdClientLoader + Goldberg Steam Emulator (Ring 3)](#8-coldclientloader--goldberg-steam-emulator-ring-3)
9. [amd_ags_x64.org -- AMD GPU Services Backup](#9-amd_ags_x64org--amd-gpu-services-backup)
10. [How All Components Work Together -- Boot-to-Game Flow](#10-how-all-components-work-together--boot-to-game-flow)
11. [Risk Assessment & Verdict](#11-risk-assessment--verdict)
12. [Is This Malware and Is It Safe to Use](#12-is-this-malware-and-is-it-safe-to-use)
- [Appendix A: Tools & Methods](#appendix-a-tools--methods-used-for-this-analysis)
- [Appendix B: Ghidra Decompilation Analysis](#appendix-b-ghidra-decompilation-analysis)

---

## 1. Executive Summary

This package is a **game piracy crack** for "Resident Evil Requiem" (Steam AppId 3764200). It bypasses a 5-layer DRM stack:

> **Steam + Denuvo Anti-Tamper + Capcom Anti-Tamper + VMProtect + SteamStub**

The crack operates across **four CPU privilege levels** simultaneously:

| Layer | Ring Level | Component | Purpose |
|-------|-----------|-----------|---------|
| UEFI Firmware | Ring -2 | EfiGuard (EfiGuardDxe.efi) | Disables PatchGuard + Driver Signature Enforcement at boot |
| Hypervisor (AMD) | Ring -1 / Ring 0 | SimpleSvm.sys | AMD SVM hypervisor -- CPUID/MSR interception + KUSER spoofing (self-contained) |
| Hypervisor (Intel) | Ring -1 / Ring 0 | hyperkd.sys + hyperhv.dll | Intel VMX hypervisor -- CPUID/MSR interception + KUSER spoofing (via HyperDbg) |
| User Mode | Ring 3 | ColdClientLoader + Goldberg Emu | Replaces Steam client, emulates Steamworks API |

**What I Found:** Based on the tools and methods I used, I found no evidence of general-purpose malware -- every component has a specific DRM-bypass function. All major components are open source (some not on GitHub). MKDEV TEAM members are known in the scene. However, the package disables critical Windows security features (DSE, PatchGuard), which leaves the system temporarily unprotected. My goal here is to raise awareness about these tools and understand how they work.

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

**Key observation:** Both `.sys` files have Subsystem = 1 (Native), confirming they are legitimate Windows kernel drivers, not user-mode executables disguised with `.sys` extensions. Their PE characteristics (0x0022) indicate they are not DLLs -- they are standalone kernel executables.


---

## 3. How Denuvo Anti-Tamper Works

Denuvo is a commercial anti-tamper technology by Denuvo Software Solutions GmbH (now owned by Irdeto). It is NOT a standalone DRM -- it is an **anti-tamper wrapper** that protects other DRM (here: Steam + Capcom's own DRM).

### 3.1 Denuvo's Protection Mechanisms

**Code Virtualization:**
- Critical game functions are converted from native x86-64 instructions into custom bytecode
- This bytecode runs inside a private virtual machine (VM) embedded in the game executable
- VMProtect adds an additional layer of VM-based obfuscation on top of Denuvo's own VM
- Result: Static disassembly (IDA Pro, Ghidra) shows gibberish -- the real logic is hidden inside VM interpreters

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
| KUSER_SHARED_DATA | Is the OS environment normal? | Reads from fixed address `0x7FFE0000` -- contains OS version, tick count, system flags |
| Self-integrity | Has Denuvo's own code been patched? | CRC/hash checks over its own memory regions |
| Environment flags | Are security features normal? | Checks various system settings, driver presence, etc. |
| KdDebuggerNotPresent | Is kernel debugging active? | Reads `nt!KdDebuggerNotPresent` global variable |

### 3.2 Why Conventional Cracks Don't Work on Modern Denuvo

Traditional game cracking = find the DRM check, NOP it out or patch the jump. With Denuvo + VMProtect:
- The check logic is **inside a custom VM** -- you can't just patch a `JNZ` to `JMP`
- There are **hundreds of trigger points** scattered through the game, not a single check
- The code **self-verifies** -- patching one check triggers integrity failures in others
- Server-generated tokens are **unique per hardware** -- you can't just copy someone else's

**This is why the hypervisor approach exists:** Instead of trying to patch Denuvo (nearly impossible with VMProtect layering), you **spoof the entire environment from below** so Denuvo's checks all pass with legitimate-looking results.

---

## 4. How This Package Defeats Denuvo -- The Full Attack Chain

The crack uses a layered interception architecture. Critically, **hyperkd.sys and SimpleSvm.sys are alternatives for different CPU architectures** -- they are NOT layered together. KIRIGIRI.dll detects the CPU vendor at runtime and loads the appropriate one. Both drivers are open-source (though not hosted on GitHub).

At Ring -2 (UEFI Firmware), EfiGuard (EfiGuardDxe.efi) operates before Windows even boots. It defeats Driver Signature Enforcement (DSE) so that unsigned kernel drivers can load without being blocked. It also defeats PatchGuard, which would otherwise detect kernel modifications and cause a blue screen. EfiGuard is optional -- the crack also has a built-in DSE bypass via UEFI runtime variable patching, and manual methods (test signing mode) also work.

At Ring -1 / Ring 0 (Hypervisor + Kernel), **one** of the following loads depending on CPU:

- **AMD systems:** `SimpleSvm.sys` loads. It is a self-contained AMD SVM hypervisor that handles everything: CPUID interception, RDTSC spoofing, MSR interception, KUSER_SHARED_DATA spoofing, and KdDebuggerNotPresent patching.
- **Intel systems:** `hyperkd.sys` loads. It is a thin shim driver that imports `hyperhv.dll` (a modified build of the open-source HyperDbg project). Together they provide the same capabilities via Intel VMX: CPUID interception, RDTSC spoofing, KUSER_SHARED_DATA spoofing, and KdDebuggerNotPresent patching.

Both achieve the same result: place the OS inside a hypervisor-controlled VM, intercept Denuvo's hardware queries, and return spoofed values so all environment checks pass.

At Ring 3 (User Mode), ColdClientLoader launches the game executable (re9.exe) with the Goldberg Steam Emulator DLLs in place of the real Steam client. This defeats Steam authentication and SteamStub by responding to all Steamworks API calls locally, reporting the game as legitimately owned and running in offline mode. KIRIGIRI.dll also patches static addresses in the game executable for the Capcom DRM and SteamStub bypass.

### The Interception Flow for a Denuvo Check

When Denuvo executes a check inside the game process:

1. **Denuvo calls `CPUID`** to check if a hypervisor is present
   - The active hypervisor driver (SimpleSvm.sys on AMD, hyperkd.sys+hyperhv.dll on Intel) **intercepts** this at ring -1
   - Returns modified results: clears the hypervisor-present bit, returns the real CPU vendor string
   - Denuvo sees: "No hypervisor, real CPU"

2. **Denuvo reads `KUSER_SHARED_DATA`** at `0x7FFE0000`
   - The hypervisor driver has **spoofed the values** via its CounterUpdater thread
   - Denuvo sees: "Normal Windows environment"

3. **Denuvo calls `RDTSC`** for timing checks
   - The hypervisor intercepts TSC reads via VMCB/VMCS control bits
   - Returns consistent timing values that don't indicate single-stepping

4. **Denuvo checks `KdDebuggerNotPresent`**
   - The hypervisor driver patches this kernel variable
   - Denuvo sees: "No kernel debugger attached"

5. **Denuvo validates its Steam integration**
   - Goldberg emulator's `steamclient64.dll` responds to all ISteam* API calls
   - Returns valid-looking app ownership, user identity, ticket data

6. **Denuvo's unsigned driver checks would normally trigger PatchGuard BSOD**
   - EfiGuard disabled PatchGuard at boot time
   - System remains stable despite kernel modifications


---

## 5. EfiGuard -- UEFI Bootkit (Ring -2)

**Source:** Open-source, GPL-3.0 -- [github.com/Mattiwatti/EfiGuard](https://github.com/Mattiwatti/EfiGuard)

**Author:** Mattiwatti (Matthijs Lavrijsen)

**Stars:** 2,300+ on GitHub

**Purpose:** Disable PatchGuard and Driver Signature Enforcement (DSE) at boot time

### 5.1 Files in the EfiGuard Folder

| File | Size | Date | Role |
|------|------|------|------|
| `bootx64.efi` | 101,160 bytes | 2024-01-08 | Renamed `Loader.efi` -- the UEFI boot application that starts the chain |
| `EfiGuardDxe.efi` | 360,448 bytes | 2026-01-27 | The core UEFI DXE driver that performs all kernel patches |
| `loader.efi` | 49,152 bytes | 2026-01-27 | Redundant copy of the loader application |
| `HashTool.efi` | 100,656 bytes | 2024-01-08 | Optional Secure Boot hash enrollment utility |

### 5.2 What EfiGuard Does -- Stage by Stage

EfiGuard operates in the UEFI DXE (Driver Execution Environment) phase -- this is **before the Windows kernel even loads**. It patches Windows components as they are loaded by the firmware.

**Stage 1 -- Boot Manager Patch (`bootmgfw.efi`):**

Strings found in `EfiGuardDxe.efi` confirming this:
`
[ bootmgfw!ImgArchStartBootApplication ]
Patched bootmgfw!ImgpValidateImageHash [RVA: 0x%X]
Patched bootmgfw!ImgpFilterValidationFailure [RVA: 0x%X]
`

- Hooks `ImgArchStartBootApplication` in the Windows Boot Manager
- Patches `ImgpValidateImageHash` -- this is the function that validates the cryptographic hash of boot images. By patching it, EfiGuard allows modified bootloaders and kernels to load
- Patches `ImgpFilterValidationFailure` -- this function reports integrity violations to the TPM or SI log. Patching it prevents any audit trail

**Stage 2 -- Boot Loader Patch (`winload.efi`):**

Strings found:
`
Patching winload.efi v%u.%u.%u.%u...
Found OslFwpKernelSetupPhase1 at 0x%llX
Successfully patched winload!OslFwpKernelSetupPhase1
VbsPolicyDisabled
`

- Hooks `OslFwpKernelSetupPhase1` -- the last function in winload that runs before the kernel takes over, while EFI boot services are still available
- Can disable VBS (Virtualization Based Security) by setting the `VbsPolicyDisabled` EFI runtime variable

**Stage 3 -- Kernel Patch (`ntoskrnl.exe`) -- PatchGuard Disable:**

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

**Stage 3b -- Kernel Patch -- DSE (Driver Signature Enforcement) Disable:**

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

**Method 1 -- Boot-time DSE disable:**
- Patches `SepInitializeCodeIntegrity` -- replaces `mov ecx, <value>` with `xor ecx, ecx` so Code Integrity initializes in a disabled state
- Patches `SeValidateImageData` -- replaces the function's return value with `mov eax, 0` (STATUS_SUCCESS) so all image validation passes
- Patches `SeCodeIntegrityQueryInformation` -- so if any process queries whether CI is enabled, it still reports "enabled" (stealth)

**Method 2 -- SetVariable hook (DEFAULT):**
- Hooks the UEFI Runtime Service `SetVariable()`
- After boot, the companion `EfiDSEFix.exe` calls `NtSetSystemEnvironmentValueEx` with a special GUID
- This tunnels through the UEFI runtime service hook into kernel memory
- Allows setting `g_CiEnabled` / `g_CiOptions` to any value from user mode -- effectively an arbitrary kernel read/write backdoor
- The string `roodkcaBdrauGifE` found in the binary is "EfiGuardBackdoor" reversed -- this is the marker GUID name

### 5.3 Why EfiGuard Is Included (But Not Required)

EfiGuard is presented by the NFO as the **easy alternative** to manually disabling security features. The NFO lists two options:

**Option A (Manual):** Enable test signing (`bcdedit /set testsigning on`), disable Hyper-V, disable Secure Boot, disable HVCI/memory integrity, disable Credential Guard. This handles DSE so the unsigned drivers can load. PatchGuard is not a problem here because the hypervisor-level spoofing (SimpleSvm at ring -1) creates split memory views via nested page tables -- PatchGuard checks real kernel memory at ring 0 and sees it untouched, while the game process sees spoofed values through the hypervisor.

**Option B (EfiGuard):** Boot from the EfiGuard USB and it automatically disables DSE, PatchGuard, and VBS in one step, without needing to manually change any Windows settings.

**The NFO file confirms EfiGuard is optional:** *"Or you can use EfiGuard to avoid disabling all of them <3, it's easy and quick."*

EfiGuard is the more thorough approach (it also disables PatchGuard as an extra safety net), but the manual method works because the critical spoofing happens at the hypervisor level where PatchGuard cannot see it.

### 5.4 EfiGuard Limitations

The `EfiGuardDxe.efi` strings also reveal:
`
[PatchNtoskrnl] ERROR: Checked kernels are not supported.
[PatchNtoskrnl] ERROR: Unsupported kernel image version.
`

- Cannot bypass **HVCI** (Hypervisor-Protected Code Integrity / HyperGuard) -- this runs at VTL1, a higher privilege than even the UEFI bootkit
- Only supports retail (free) kernels, not checked/debug kernels
- Requires Secure Boot to be disabled (unless you own the Platform Key)


---

## 6. SimpleSvm.sys -- AMD Hypervisor (Ring -1)

**Source:** Open-source, MIT License -- [github.com/tandasat/SimpleSvm](https://github.com/tandasat/SimpleSvm)

**Author:** Satoshi Tanda (security researcher)

**Stars:** 534 on GitHub

**Binary Size:** 17,776 bytes

**PE Subsystem:** Native/Kernel (Subsystem = 1)

**Architecture:** x86-64 (Machine = 0x8664)

### 6.1 What SimpleSvm Is

SimpleSvm is described by its author as *"a minimalistic educational hypervisor for Windows on AMD processors."* It uses AMD's **Secure Virtual Machine (SVM)** hardware extension (AMD's equivalent of Intel VT-x) to turn the existing running OS into a **guest virtual machine** while SimpleSvm itself runs at ring -1 as the hypervisor.

### 6.2 Strings Extracted from SimpleSvm.sys -- Full Analysis

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

These confirm the standard SimpleSvm lifecycle: check CPU support -- virtualize -- handle power events -- devirtualize on unload.

**CPU Vendor Verification Strings:**
`
AuthenticAMD (split as: ??cAMD, ??E???Auth, ??enti)
A?SSVM (CPUID check for SVM feature)
SimpleSvm (hypervisor vendor string returned via CPUID)
`

When SimpleSvm intercepts `CPUID` leaf 0x40000000 (hypervisor vendor), it returns `"SimpleSvm "` as the vendor ID. However, for Denuvo bypass, the CPUID intercept for leaf 0x1 must **clear bit 31 of ECX** (the hypervisor-present flag) so Denuvo doesn't detect it.

**Kernel API Imports (confirmed via strings):**
`
ntoskrnl.exe -- links to the Windows kernel
ExAllocatePool2 -- allocates kernel memory (modern API, Win10+)
ExFreePoolWithTag -- frees kernel memory
ExCreateCallback -- creates callback objects
ExRegisterCallback -- registers for system callbacks
ExUnregisterCallback -- unregisters callbacks
IoAllocateMdl -- allocates Memory Descriptor Lists (for DMA/mapping)
IoGetCurrentProcess -- gets current process context
KeGetCurrentIrql -- checks current interrupt level
KeQueryActiveProcessorCountEx -- counts active CPU cores
KeSetSystemGroupAffinityThread -- pins thread to specific CPU core
KeRevertToUserGroupAffinityThread -- reverts CPU affinity
KeWaitForSingleObject -- synchronization primitive
KeDelayExecutionThread -- sleep
KeBugCheck -- triggers BSOD (used as last resort on critical failure)
KfRaiseIrql -- raises interrupt priority
KeLowerIrql -- lowers interrupt priority
KeGetProcessorNumberFromIndex -- maps processor index to number
MmAllocateContiguousNodeMemory -- allocates physically contiguous memory (for VMCB)
MmFreeContiguousMemory -- frees contiguous memory
MmGetPhysicalAddress -- converts virtual to physical address
MmGetVirtualForPhysical -- converts physical to virtual address
MmMapLockedPagesSpecifyCache -- maps physical pages into virtual address space
MmProbeAndLockPages -- locks pages in physical memory
MmUnlockPages -- unlocks pages
MmUnmapLockedPages -- unmaps previously mapped pages
RtlCaptureContext -- captures current CPU register state (used to populate VMCB)
RtlGetVersion -- gets Windows version info
RtlInitializeBitMap -- initializes bitmap structure
RtlSetBits / RtlClearAllBits -- bitmap manipulation
ObfDereferenceObject -- dereferences kernel object
ObReferenceObjectByHandle -- references kernel object by handle
ZwClose -- closes kernel handle
strcmp -- string comparison

`

**Key observations from the API imports:**
- `MmAllocateContiguousNodeMemory` -- AMD SVM requires the VMCB (Virtual Machine Control Block) and host state save area to be in **physically contiguous memory**. This is the allocation function used for that.
- `RtlCaptureContext` -- Used to capture the current CPU state (all registers) to populate the VMCB's guest state. This is how SimpleSvm "snapshots" the running OS state before virtualizing it.
- `KeSetSystemGroupAffinityThread` -- SimpleSvm must run its virtualization code on **every CPU core individually**, so it pins its thread to each core in sequence.
- `KeBugCheck` -- If something goes critically wrong during virtualization, it BSODs rather than leaving the system in a corrupt state.

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
- The spoofing is **process-specific** -- it only spoofs KUSER data for the game process, not for the entire OS (this is more stealthy)
- A `CounterUpdater` background thread continuously updates spoofed timing values

**Additional Modified SimpleSvm APIs (not in original):**
`
PsCreateSystemThread -- creates kernel threads (for CounterUpdater)
PsLookupProcessByProcessId -- finds process by PID
PsAcquireProcessExitSynchronization -- safe process exit handling
PsReleaseProcessExitSynchronization -- releases exit sync
PsSetCreateProcessNotifyRoutine -- registers for process creation/exit notifications
PsTerminateSystemThread -- terminates kernel thread
PsThreadType -- thread object type reference
KeStackAttachProcess -- attaches to another process's address space
KeUnstackDetachProcess -- detaches from process address space
KdDebuggerNotPresent -- kernel debugger detection variable
`

**Critical finding:** `KdDebuggerNotPresent` is imported -- this is the kernel global variable that indicates whether a kernel debugger is attached. The modified SimpleSvm likely **patches this to always return TRUE** (debugger not present), defeating Denuvo's kernel debugger detection.

**Denuvo-Specific Strings Found:**
`
Denuvo GmbH
Denuvo GmbH0
Denuvo GmbH0?
`

These are ASN.1 certificate issuer/subject strings that are part of the **fake Denuvo license data** embedded in the binary. KIRIGIRI.dll writes this data to `KIRIGIRI.bin` and hooks `CreateFileW` to redirect Denuvo's license file reads to this fake file (see Appendix B.5).

**Unicode Wide Strings:**
`
\Callback\PowerState
`
This is the kernel callback object path used to register for power state changes (sleep/hibernate). SimpleSvm must de-virtualize before sleep and re-virtualize after wake.

**Hypervisor VM Function Strings:**
`
VmFuncInitVmm -- Initialize Virtual Machine Monitor
VmFuncUninitVmm -- Uninitialize Virtual Machine Monitor
`

These are the top-level entry/exit functions for the hypervisor lifecycle. In SimpleSvm.sys (AMD), these are **internal functions** compiled directly into the driver. This contrasts with hyperkd.sys (Intel), where these same function names are **imported from `hyperhv.dll`**.

### 6.3 How SimpleSvm Intercepts Denuvo's CPUID Checks

The AMD SVM hypervisor works by:

1. **Setting the EFER.SVME bit** on each CPU core to enable SVM mode
2. **Creating a VMCB** (Virtual Machine Control Block) for each core -- this is a hardware-defined data structure that controls what the hypervisor intercepts
3. **Calling VMRUN** -- this transfers control to the hypervisor. The OS becomes a "guest"
4. **On each CPUID instruction in guest mode:**
   - The CPU triggers a `#VMEXIT` -- control transfers to SimpleSvm
   - SimpleSvm examines the CPUID leaf being queried
   - For leaf 0x1: **Clears ECX bit 31** (hypervisor-present flag) before returning
   - For leaf 0x40000000-0x400000FF: Returns vendor info as if no hypervisor exists
   - For other leaves: Passes through unmodified
5. **On VMRUN in guest mode:** Injects `#GP` (General Protection Fault) -- prevents any nested hypervisor from running
6. **On EFER MSR writes:** Prevents the guest from clearing SVME bit (so it can't escape the hypervisor)

### 6.4 Certificate Dates Found

`
260226065959Z -- 2026-02-26 06:59:59 UTC
270226071959Z0 -- 2027-02-26 07:19:59 UTC
`

These are ASN.1 validity dates embedded in the binary. They are part of the **fake Denuvo license data** (counterfeit certificate) that the crack presents to Denuvo's verification routines. The dates define the validity window of the counterfeit license token. (Note: I incorrectly identified these in the earlier version of this report as a "self-signed test certificate" for driver signing -- my Ghidra decompilation of KIRIGIRI.dll in Appendix B.5 showed these are part of the fake license blob written to `KIRIGIRI.bin`.)


---

## 7. hyperkd.sys -- Intel Hypervisor Driver (Ring -1 / Ring 0)

**Source:** Open source (not hosted on GitHub). Used only on Intel systems.

**Note:** `hyperkd.sys` is the Intel counterpart to `SimpleSvm.sys` (AMD). KIRIGIRI.dll detects the CPU vendor at runtime and loads the appropriate driver. Both are open-source.

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
DisplayName = %hyperlog.SVCDESC%
ServiceType = 1 ; SERVICE_KERNEL_DRIVER
StartType = 3 ; SERVICE_DEMAND_START
ErrorControl = 1 ; SERVICE_ERROR_NORMAL
ServiceBinary = %12%\hyperlog.sys

[hyperlog_Device.NT.Wdf]
KmdfService = hyperlog, hyperlog_wdfsect
[hyperlog_wdfsect]
KmdfLibraryVersion = 1.15

[Strings]
ManufacturerName="<Your manufacturer name>" ;TODO: Replace with your manufacturer name
`

**Key observations from the INF:**

1. **Name mismatch:** The INF references `hyperlog.sys` throughout, but the actual binary is named `hyperkd.sys`. This means:
   - The INF cannot install the driver through normal Plug-and-Play
   - The driver is loaded **programmatically** via `CreateService()`/`StartService()` by the game loader
   - The NFO confirms: *"The game will load the driver automatically"*

2. **Unfinished template:** Contains `; TODO:` placeholders and `<Your manufacturer name>` -- this was generated from the Visual Studio WDF Kernel Mode Driver project template and never cleaned up

3. **KMDF 1.15:** Uses Kernel Mode Driver Framework version 1.15, which requires Windows 10 version 1703 (Creators Update) or later

4. **SERVICE_DEMAND_START (3):** Not loaded at boot -- only loaded when the game needs it

5. **Root\hyperlog PnP ID:** Registered as a root-enumerated device (software-only, no hardware)

6. **CatalogFile=hyperlog.cat:** References a catalog file for driver signing -- but this file is not included in the package (unnecessary since DSE is disabled by EfiGuard)

### 7.2 Strings Extracted from hyperkd.sys -- Full Analysis

**Kernel API Imports:**
`
ntoskrnl.exe -- links to Windows kernel
ExCreateCallback -- creates callback objects
ExRegisterCallback -- registers for callbacks
ExUnregisterCallback -- unregisters callbacks
KeWaitForSingleObject -- synchronization
ObfDereferenceObject -- dereferences kernel object
ObReferenceObjectByHandle -- references object by handle
PsCreateSystemThread -- creates kernel-mode threads
PsThreadType -- thread type reference
ZwClose -- closes handle
NtQuerySystemInformation -- queries system information tables
`

**Imported and Internal Function Names:**
`
VmFuncInitVmm -- Initialize the Virtual Machine Monitor (imported from hyperhv.dll)
VmFuncUninitVmm -- Uninitialize the Virtual Machine Monitor (imported from hyperhv.dll)
CounterThreadHandle -- Handle to the counter update thread (internal)
CounterUpdater -- The counter updating function itself (internal)
StopCounterThread -- Stops the counter thread (internal)
NotifyRoutineActive -- Flag for process notification callback (internal)
ProcessExitCleanup -- Cleanup on game process exit (internal)
`

**What these tell us:**

- `VmFuncInitVmm` / `VmFuncUninitVmm` -- These are **imported from `hyperhv.dll`** (a modified build of the open-source HyperDbg project). hyperkd.sys calls into hyperhv.dll to start/stop the Intel VMX hypervisor. (Note: hyperkd.sys does NOT interact with SimpleSvm.sys -- they are mutually exclusive drivers for different CPU vendors.)
- `CounterUpdater` / `CounterThreadHandle` / `StopCounterThread` -- A dedicated kernel thread created by hyperkd.sys that **continuously updates spoofed counter values** (likely `KUSER_SHARED_DATA.TickCount`, `QueryPerformanceCounter` values, and `RDTSC` baselines). This defeats Denuvo's timing-based anti-debug checks.
- `NotifyRoutineActive` -- Uses `PsSetCreateProcessNotifyRoutine` to monitor process creation. When `re9.exe` starts, it activates the spoofing. When it exits, it cleans up.
- `ProcessExitCleanup` -- Ensures the hypervisor is properly unloaded and KUSER data is restored when the game closes

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

**This is extremely significant.** These strings come from **HyperDbg** -- an open-source hypervisor debugger project ([github.com/HyperDbg/HyperDbg](https://github.com/HyperDbg/HyperDbg)). HyperDbg is a kernel debugger that uses AMD SVM/Intel VMX to debug at the hypervisor level. The `FUNC_*` strings are the **scripting engine opcodes** used by HyperDbg's built-in scripting language.

This confirms that `hyperkd.sys` **links against `hyperhv.dll`**, which is a modified build of HyperDbg. The `FUNC_*` strings appear in `hyperkd.sys` during string extraction because the linker embeds import library metadata from `hyperhv.dll`. The actual HyperDbg engine code resides in `hyperhv.dll`, not in `hyperkd.sys` itself (my Ghidra decompilation in Appendix B confirmed `hyperkd.sys` is a thin 26-function shim). HyperDbg provides:
- A complete **hypervisor-level debugger** invisible to the guest OS
- **Event injection/interception** (`FUNC_EVENT_INJECT`, `FUNC_EVENT_TRACE_STEP`)
- **Physical/virtual memory read/write** (`FUNC_DB_PA`, `FUNC_EB_PA`, `FUNC_PHYSICAL_TO_VIRTUAL`)
- **Instruction-level stepping** invisible to the guest
- **Hardware breakpoints** managed from the hypervisor

**The `_PA` suffixed functions** (`FUNC_DB_PA`, `FUNC_DD_PA`, `FUNC_DQ_PA`, `FUNC_EB_PA`, `FUNC_ED_PA`, `FUNC_EQ_PA`, `FUNC_HI_PA`, `FUNC_LOW_PA`, `FUNC_MEMCPY_PA`, `FUNC_POI_PA`) indicate **physical address** variants -- these allow reading/writing physical memory directly, bypassing all virtual memory protections. This is critical for modifying KUSER_SHARED_DATA and other protected kernel structures.

**Denuvo Certificate Strings:**
`
Denuvo GmbH
Denuvo GmbH0
Denuvo GmbH0?
`

These are ASN.1 certificate issuer/subject strings. They are part of the **fake Denuvo license data** that KIRIGIRI.dll writes to `KIRIGIRI.bin` (see Appendix B.5). The `CreateFileW` IAT hook redirects Denuvo's license file reads to this fake file. The strings appear in both `.sys` drivers because the fake license blob is embedded in the driver binaries.

**Certificate Dates:**
`
260226065959Z -- 2026-02-26 06:59:59 UTC
270226071959Z0 -- 2027-02-26 07:19:59 UTC
`

These are ASN.1 validity dates embedded in the fake Denuvo license data. They define the validity window of the counterfeit license token that the crack presents to Denuvo's verification routines.

**PE Sections:**
`
.pdata -- exception handling data (standard for x64 drivers)
.rdata -- read-only data (strings, constants, import tables)
.data -- read-write global data
.reloc -- relocation table (allows loading at any kernel address)
`

Standard PE sections for a kernel driver. No unusual sections detected.

**Unicode Wide Strings:**
`
\Callback\PowerState
`

Same power callback as SimpleSvm -- confirms hyperkd.sys manages power state transitions for the hypervisor.

**`hyperhv.dll` Reference:**
`
hyperhv.dll
`

This string references `hyperhv.dll` -- a modified build of the open-source **HyperDbg** project. This DLL is **not present in this workspace** but would be present in the game's installation directory. Ghidra decompilation (Appendix B.2) confirmed that `hyperkd.sys` **imports** `VmFuncInitVmm` and `VmFuncUninitVmm` from this DLL. `hyperhv.dll` contains the actual Intel VMX hypervisor engine (762 functions, 27,449 lines of decompiled pseudocode -- see Appendix B.6), while `hyperkd.sys` is merely a thin shim that calls into it.

### 7.3 How hyperkd.sys Works -- Confirmed by My Ghidra Decompilation

Ghidra decompilation (Appendix B.2) confirmed the following operation flow. Note that `hyperkd.sys` is used **only on Intel systems** -- on AMD systems, `SimpleSvm.sys` handles all equivalent functions independently.

1. **KIRIGIRI.dll calls `CreateServiceW()`** to register `hyperkd.sys` as a kernel service named `"denuvo_kirigiri"`, then calls `StartServiceW()` to load it
2. **`hyperkd.sys` DriverEntry runs and:**
   - Registers a `\Callback\PowerState` callback via `ExCreateCallback` / `ExRegisterCallback` for sleep/hibernate handling
   - Checks for an existing hypervisor via `NtQuerySystemInformation(0xC4)` -- aborts if one is already running (e.g., Hyper-V)
   - Calls `VmFuncInitVmm()` (imported from `hyperhv.dll`) with a zeroed 0xA0-byte configuration structure -- this single call starts the Intel VMX hypervisor on all CPU cores via `VMXON` / `VMLAUNCH`
   - Creates the `CounterUpdater` system thread via `PsCreateSystemThread`

3. **While the game runs:**
   - The `CounterUpdater` thread continuously updates spoofed values in KUSER_SHARED_DATA for the game process
   - `hyperhv.dll`'s HyperDbg engine handles all CPUID, RDTSC, and MSR interceptions at ring -1
   - CPUID intercepts return spoofed values (no hypervisor detected)
   - RDTSC/RDTSCP intercepts return consistent timing values
   - KUSER_SHARED_DATA is continuously maintained with "normal" values
   - `KdDebuggerNotPresent` is kept set to TRUE

4. **On driver unload (game exit):**
   - Sets a stop flag to terminate the `CounterUpdater` thread
   - Waits for the thread to exit via `KeWaitForSingleObject`
   - Calls `VmFuncUninitVmm()` (imported from `hyperhv.dll`) to shut down the hypervisor on all cores
   - KUSER_SHARED_DATA is restored to real values

5. **On power state change (sleep/hibernate):**
   - Calls `VmFuncUninitVmm()` to devirtualize before sleep
   - Calls `VmFuncInitVmm()` to revirtualize after wake
   - This prevents BSODs caused by hypervisor state being lost across power transitions


---

## 8. ColdClientLoader + Goldberg Steam Emulator (Ring 3)

**ColdClientLoader Source:** Open-source -- originally by Rat431

**Steam Emulator Source:** Open-source, LGPL -- by Mr. Goldberg ([gitlab.com/Mr_Goldberg/goldberg_emulator](https://gitlab.com/Mr_Goldberg/goldberg_emulator))

**Purpose:** Replace the real Steam client so the game thinks it's running under a legitimate Steam installation

### 8.1 ColdClientLoader.ini -- Configuration

`ini
[SteamClient]
Exe=re9.exe # Game executable to launch
AppId=3764200 # Resident Evil Requiem's real Steam AppId
SteamClientDll=coldclient\steamclient.dll # 32-bit fake Steam DLL (16 MB)
SteamClient64Dll=coldclient\steamclient64.dll # 64-bit fake Steam DLL (17.9 MB)

[Injection]
ForceInjectSteamClient=0 # Don't force-inject -- let the game load it naturally
ForceInjectGameOverlayRenderer=0
DllsToInjectFolder= # No extra DLLs to inject
IgnoreInjectionError=0
IgnoreLoaderArchDifference=0

[Persistence]
Mode=0 # Loader exits after launching the game

[Debug]
ResumeByDebugger=0 # Normal launch, not debugger-attached
`

**How ColdClientLoader works:**
1. Sets up environment variables and registry keys that Steam games expect
2. Points `SteamClientDll` paths to the Goldberg emulator DLLs instead of the real Steam client
3. Launches `re9.exe` -- the game loads `steamclient64.dll` from the specified path
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
- String `inflate 1.3.1 Copyright 1995-2024 Mark Adler` -- uses zlib for data compression
- `InGameOverlay` namespace -- implements visual overlay features
- `Friend`, `Friend_Messages`, `Announce_Other_Peers` -- LAN multiplayer emulation classes

**Strings analysis of GameOverlayRenderer64.dll confirmed:**
- Exports: `BOverlayNeedsPresent`, `IsOverlayEnabled`, `OverlayHookD3D3`
- `SteamOverlayIsUsingGamepad`, `SteamOverlayIsUsingKeyboard`
- `VulkanSteamOverlayPresent`, `VulkanSteamOverlayGetScaleFactors`
- `ValveHookScreenshots`, `ValveIsScreenshotsHooked`
- This is a **stub overlay renderer** -- provides the expected exports so the game doesn't crash when trying to initialize the Steam overlay

### 8.3 Steam Settings Configuration Files

**configs.app.ini -- Game DLC Configuration:**
`ini
[app::dlcs]
unlock_all=0 # Don't unlock all DLCs blindly (avoids detection)
3990800=Resident Evil Requiem - Grace's Costume: Apocalypse # Specific DLC
3990820=Resident Evil Requiem - Deluxe Kit # Specific DLC
`

**configs.main.ini -- Emulator Behavior:**
`ini
[main::general]
new_app_ticket=0 # Use legacy auth ticket format
gc_token=0 # No Game Coordinator token

[main::connectivity]
disable_lan_only=0 # Keep LAN-only mode
disable_networking=0 # Networking available (for LAN)
listen_port=47584 # Default Goldberg LAN port
offline=1 # *** KEY: Pretend Steam is in OFFLINE MODE ***
disable_lobby_creation=0
`

The `offline=1` setting is critical -- it makes the emulator report Steam as offline, which:
- Prevents the game from trying to contact real Steam servers
- Prevents Denuvo's online token validation from firing
- Many games have an "offline mode" code path that bypasses server-side checks

**configs.user.ini -- Fake User Identity:**
`ini
[user::general]
account_name=KIRIGIRI # Fake username (matches group name)
account_steamid=76561197960287930 # Fake Steam64 ID
language=english
ip_country=US
`

**steam_appid.txt:**
`
3764200
`
The real Steam AppId for Resident Evil Requiem.

**steam_interfaces.txt -- 22 Interface Versions:**
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
| Online connectivity | Reports offline mode -- prevents server-side validation |

---

## 9. amd_ags_x64.org -- AMD GPU Services Backup

**Original Name:** `amd_ags_x64.dll`

**Size:** 179,408 bytes

**Architecture:** x86-64

**PE Subsystem:** Windows Console (3) -- this is a DLL despite the subsystem

**Signed:** Yes (AMD certificate)

### 9.1 What This File Is

The `.org` extension is a common convention in game cracks meaning "original." This is the **original, legitimate AMD GPU Services (AGS) library** that shipped with the game. The crack renames it to `.org` and replaces it with a modified version (the modified `.dll` is loaded by the game but is not present in this workspace -- it would be in the game's installation directory).

### 9.2 Strings Confirming Identity

`
amd_ags_x64.dll -- original filename
Advanced Micro Devices -- publisher (AMD)
agsInitialize -- AGS initialization function
agsDeInitialize -- AGS cleanup
agsGetVersionNumber -- version query
agsCheckDriverVersion -- driver compatibility check
agsDriverExtensionsDX11_CreateDevice -- DX11 device creation with AMD extensions
agsDriverExtensionsDX12_CreateDevice -- DX12 device creation with AMD extensions
agsSetDisplayMode -- display mode configuration
D3D11CreateDevice -- standard DirectX 11 API
D3D12CreateDevice -- standard DirectX 12 API
AmdDxExtCreate11 -- AMD DX11 extension entry point
amdxc32.dll / amdxc64.dll -- AMD shader compiler DLLs
d3d11.dll / d3d12.dll -- DirectX runtime DLLs
`

This is a legitimate AMD library. I noted it was renamed because the game replaces it with a **modified proxy DLL**. The modified `amd_ags_x64.dll` simply imports another DLL during startup, which handles the bypass for the Steam and Capcom DRM.


---

## 10. How All Components Work Together -- Boot-to-Game Flow

### 10.1 One-Time Setup (Before First Launch)

The user must do ONE of these before anything works:

**Option A -- Manual Security Disabling:**
1. Enter BIOS -- Enable AMD SVM (Secure Virtual Machine)
2. Run `bcdedit /set testsigning on` -- allows unsigned drivers to load
3. Run `bcdedit /set hypervisorlaunchtype off` -- disables Hyper-V's hypervisor (frees SVM for SimpleSvm)
4. Disable Secure Boot in BIOS
5. Disable Windows Defender Memory Integrity (HVCI) and Credential Guard
6. Reboot

**Option B -- EfiGuard (Automated, "the easy way"):**
1. Enter BIOS -- Enable AMD SVM
2. Copy EfiGuard files to a FAT32 USB drive at `/EFI/Boot/`
3. Boot from USB -- EfiGuard's `bootx64.efi` loads -- starts `EfiGuardDxe.efi`
4. EfiGuard automatically:
   - Patches `bootmgfw.efi` (allows modified boot chain)
   - Patches `winload.efi` (optional VBS disable)
   - Patches `ntoskrnl.exe` (disables PatchGuard + DSE)
5. Windows boots normally, but with PatchGuard and DSE silently disabled

### 10.2 Game Launch Sequence (Every Time)

Step 1: The user launches steamclient_loader_x64.exe, which is the ColdClientLoader entry point.

Step 2: ColdClientLoader reads ColdClientLoader.ini and parses the configuration, including AppId 3764200, the game executable re9.exe, and the path to the Goldberg Steam emulator DLL at coldclient\steamclient64.dll.

Step 3: ColdClientLoader sets up a fake Steam environment by writing registry keys that point to the Goldberg emulator DLLs and setting environment variables such as SteamAppId.

Step 4: ColdClientLoader launches re9.exe with the spoofed Steam environment active.

Step 5: re9.exe loads steamclient64.dll from the Goldberg emulator. Steam authentication is bypassed, the SteamStub wrapper is bypassed, and the game reports that Steam is running in offline mode.

Step 6: KIRIGIRI.dll's entry point runs during game startup. It detects the CPU vendor (AMD or Intel) via CPUID leaf 0.

Step 7: Based on the CPU vendor, KIRIGIRI.dll installs the appropriate hypervisor driver as a kernel service named `"denuvo_kirigiri"` by calling CreateService with SERVICE_KERNEL_DRIVER type and then calling StartService. On AMD systems, it loads `SimpleSvm.sys`. On Intel systems, it loads `hyperkd.sys` (which imports `hyperhv.dll`). Because DSE has been disabled (either by EfiGuard, by the crack's own built-in DSE bypass via UEFI runtime variable patching, or by enabling test signing mode), the unsigned driver loads successfully.

Step 8: The selected hypervisor driver initializes. It activates the hypervisor on all CPU cores (VMRUN on AMD, VMLAUNCH on Intel) and Windows becomes a guest VM. CPUID interception becomes active. PsSetCreateProcessNotifyRoutine registers callbacks for process creation and exit events. The CounterUpdater background thread starts and KUSER_SHARED_DATA spoofing begins. KIRIGIRI.dll then registers the game process with the hypervisor via CPUID magic values (`0x69696969`, `0x1337`).

Step 9: Denuvo Anti-Tamper initialization runs inside re9.exe and performs its environment checks. CPUID checks are intercepted by the hypervisor which reports "no hypervisor present." KUSER_SHARED_DATA checks are spoofed to show a normal OS environment. The KdDebuggerNotPresent check is patched to report no kernel debugger is attached. Timing checks using RDTSC return consistent values that do not indicate debugging or single-stepping. KIRIGIRI.dll patches static addresses for the Capcom DRM and SteamStub protections. All environment checks pass.

Step 10: Denuvo validation passes and the game runs normally. VMProtect-obfuscated code executes without issues, Capcom Anti-Tamper checks pass, and the game is fully playable.

Step 11: When the user closes the game, ProcessExitCleanup fires in the hypervisor driver. StopCounterThread terminates the KUSER spoofing thread. The hypervisor devirtualizes all CPU cores and shuts down. KUSER_SHARED_DATA is restored to its real values. The system returns to normal operation, though the security features disabled during setup (DSE via test signing, or DSE + PatchGuard via EfiGuard) remain disabled until the relevant settings are re-enabled or a clean boot without EfiGuard is performed.

### 10.3 Why Each Component Is Necessary (None Can Be Removed)

| If You Remove... | What Happens |
|-----------------|-------------|
| EfiGuard (if not using manual method) | DSE must be disabled another way (e.g., test signing mode or the crack's built-in DSE bypass). The manual method from the NFO works as an alternative because hypervisor-level spoofing evades PatchGuard by operating at ring -1. EfiGuard provides extra safety by also disabling PatchGuard, but it is not strictly required |
| SimpleSvm.sys (on AMD) | No hypervisor on AMD = no CPUID interception. Denuvo detects the analysis environment -- refuses to run |
| hyperkd.sys (on Intel) | No hypervisor on Intel = no CPUID interception or KUSER spoofing. Denuvo's environment checks fail -- game crashes/refuses to start |
| ColdClientLoader + Goldberg | Steam APIs return errors. Game can't authenticate with "Steam" -- refuses to launch |
| amd_ags_x64.dll replacement | The modified DLL imports another DLL that provides the Steam and Capcom DRM bypass. Without it, that bypass DLL is not loaded during game startup |

---

## 11. Risk Assessment & Verdict

### 11.1 Is This Malware?

Based on what I found, **I detected no evidence of general-purpose malware** (no ransomware, spyware, keylogger, botnet agent, cryptocurrency miner, etc.). However, my analysis has limitations and I may have missed things -- this should not be taken as a definitive answer.

Observations that led me to this assessment:
- Every component has a specific, narrow DRM-bypass function
- All major components are open-source: EfiGuard (GPL-3.0), SimpleSvm (MIT), hyperkd.sys (open source, not on GitHub), hyperhv.dll (based on HyperDbg, open source), Goldberg Steam Emu (LGPL), ColdClientLoader (open source)
- The `configs.main.ini` sets `offline=1` -- I found no outbound network connections to command-and-control servers in any config files
- The Goldberg emulator explicitly disables real Steam networking
- The crack group (MKDEV TEAM) and other team members are known within the cracking/reverse engineering scene
- The NFO's instructions are consistent with DRM bypass, not malware installation
- My Ghidra decompilation of all six binaries found zero network/injection/exfiltration API calls -- but decompilation is not perfect and could miss obfuscated code

### 11.2 Real Security Risks

Despite not being malware, **the risks are serious and real:**

| Risk | Severity | Details |
|------|----------|---------|
| **BSOD / System Instability** | HIGH | MKDEV TEAM explicitly warns: *"Kernel drivers are able to cause blue screens when there are mistakes in the code, this has not yet been tested for long term stability."* A bug in the hypervisor driver at ring-0 means instant BSOD. |
| **Custom Code at Ring 0** | MEDIUM | Both `hyperkd.sys` (Intel) and `SimpleSvm.sys` (AMD) are open-source drivers (not hosted on GitHub). My Ghidra decompilation (see Appendix B) confirmed `hyperkd.sys` is a thin shim that delegates to `hyperhv.dll` (HyperDbg-based, also open source), with no malicious API calls found. Ring-0 code always carries inherent risk, but the open-source nature provides verifiability. |
| **Complete DSE + PatchGuard Disable** | CRITICAL | With EfiGuard active, Windows has **zero protection against unsigned kernel drivers**. ANY other malicious driver (from a browser exploit, phishing, etc.) can now load without Windows blocking it. You've removed the castle walls. |
| **Boot Chain Modification** | HIGH | EfiGuard modifies the UEFI boot chain. If corrupted, the system may not boot. Recovery requires EFI shell access or reinstallation. |
| **HyperDbg-Based Engine** | MEDIUM | The HyperDbg scripting engine in `hyperhv.dll` (used by `hyperkd.sys` on Intel) provides **arbitrary physical memory read/write capability** (the `_PA` functions). HyperDbg itself is open source, and the capability is used here for KUSER_SHARED_DATA spoofing, but it is the same type of capability that kernel rootkits use. |
| **Persistent Security Regression** | HIGH | Even after closing the game, DSE and PatchGuard remain disabled until EfiGuard is removed and a clean boot occurs. The system is vulnerable the entire time. |
| **No Rollback Safety** | MEDIUM | If the hypervisor driver crashes mid-operation, KUSER_SHARED_DATA may be left in a spoofed state, potentially causing OS instability or other applications to malfunction. |

### 11.3 Component Trust Levels

| Component | Trust Level | Reasoning |
|-----------|------------|-----------|
| EfiGuard | **HIGH** -- Open source, GPL-3.0, 2,300+ stars, code auditable | Well-known security research tool by a real researcher |
| SimpleSvm.sys | **HIGH** -- Open source (not on GitHub), AMD-specific; MKDEV modifications are verifiable via decompilation | Base project is MIT-licensed; I decompiled the modifications (KUSER spoof, CounterUpdater) and found them clean |
| Goldberg Steam Emu | **HIGH** -- Open source, LGPL, widely used | Standard Steam emulator, no kernel access |
| ColdClientLoader | **HIGH** -- Open source, user-mode only | Simple process launcher/environment setter |
| hyperkd.sys | **HIGH** -- Open source (not on GitHub), Intel-specific, HyperDbg-derived; my Ghidra decompilation found no malicious APIs | Thin shim driver; real logic lives in hyperhv.dll (HyperDbg-based open source, which I also decompiled) |
| amd_ags_x64.org | **HIGH** -- Legitimate AMD-signed library (backup copy) | Original unmodified file |
| amd_ags_x64.dll (modified) | **HIGH** -- Proxy DLL that imports another DLL for Steam/Capcom DRM bypass | Just a DLL import mechanism |

### 11.4 Summary Assessment

Based on my analysis, this package is a game piracy crack / DRM bypass tool. I found no evidence of general malware behavior (data exfiltration, ransomware, cryptocurrency mining, botnet participation) during string extraction or Ghidra decompilation of all six binaries (41,644 lines of pseudocode -- see Appendix B). All major components are open-source (though some are not hosted on GitHub). MKDEV TEAM and other team members are known within the reverse engineering scene. The notable risks are the system-wide disabling of DSE and PatchGuard, which removes Windows kernel security protections for the duration of the session. I want to note that the entire bypass chain can be built from scratch using open-source components, rather than blindly running pre-built packages. I did this as a student learning exercise and my findings may contain errors. From a legal standpoint, this is a copyright infringement tool.

---

## Appendix A: Tools & Methods I Used

| Method | What I Did |
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
| Ghidra decompilation | Ghidra 12.0.4 headless analysis with custom `ExportDecompiled.java` script -- decompiled all 6 key binaries (1,066 functions, 41,644 lines of C pseudocode) |
| Malicious API sweep | Regex search across all decompiled output for network, injection, and exfiltration API patterns |
| PE export enumeration | Python `pefile` library to enumerate all 290+ exports from `hyperhv.dll` |

**I did not execute any binaries at any point during this analysis.**

---

## 12. Is This Malware and Is It Safe to Use

### 12.1 Is This Malware?

Based on my analysis, **I found no evidence of traditional malware**. I detected no ransomware, spyware, keyloggers, cryptocurrency miners, botnet agents, adware, or data-stealing code through string extraction, PE analysis, or Ghidra decompilation. I found no network communication to external command-and-control servers in any configuration file or extracted string. The Goldberg Steam emulator is explicitly configured with `offline=1`.

Three of the five major components (EfiGuard, the original SimpleSvm, and the Goldberg Steam Emulator) are well-known open-source projects. ColdClientLoader is also open-source and operates entirely in user mode. Both `hyperkd.sys` (Intel) and `SimpleSvm.sys` (AMD) are open source (not hosted on GitHub), and I decompiled the custom MKDEV components (`KIRIGIRI.dll`, `hyperevade.dll`, `hyperhv.dll`) using Ghidra (see Appendix B) -- I found no malicious API calls across any of them.

My string extraction from `hyperkd.sys` revealed only kernel API imports, hypervisor management functions, KUSER_SHARED_DATA spoofing routines, and HyperDbg scripting engine opcodes. I found no strings suggesting network sockets, HTTP requests, file encryption, clipboard monitoring, screenshot capture, keystroke logging, or any other data exfiltration mechanism.

**Important caveat:** I did this analysis as a student learning exercise, not as a professional malware analyst. Static analysis and decompilation have inherent limitations -- they can miss obfuscated payloads, encrypted data sections, or time-delayed behavior. The absence of evidence is not evidence of absence. Please consider waiting for analysis from more experienced or official sources before drawing firm conclusions.

### 12.2 What Are the Risks?

This section documents the risks I observed during my analysis. This is not a definitive safety assessment -- just what I found.

**Risk 1 -- Unsigned kernel code:** Both `hyperkd.sys` (Intel, 11,632 bytes) and `SimpleSvm.sys` (AMD, 17,776 bytes) are open-source kernel drivers (not on GitHub) running at ring 0. My Ghidra decompilation (Appendix B) showed `hyperkd.sys` is a thin shim driver with only 26 functions that delegates to `hyperhv.dll` (HyperDbg-based, also open source). I found no malicious API calls. However, running any ring-0 code inherently carries risk -- bugs can cause BSODs and the drivers have full system access.

**Risk 2 -- DSE and PatchGuard disabled:** EfiGuard disables Driver Signature Enforcement and PatchGuard. These are two of Windows' kernel-level security features. With them disabled, the OS would not block other unsigned kernel drivers from loading.

**Risk 3 -- Persistent security regression:** Even after the game is closed, DSE and PatchGuard remain disabled for the entire Windows session until the EfiGuard boot entry is removed and a clean reboot is performed.

**Risk 4 -- BSOD potential:** MKDEV TEAM themselves acknowledge in their NFO file that kernel drivers can cause blue screens when there are mistakes in the code and that long-term stability has not been tested.

**Risk 5 -- Physical memory access capability:** The HyperDbg-derived engine in `hyperhv.dll` (used by `hyperkd.sys` on Intel) includes physical address memory read and write functions (the _PA variants). HyperDbg is itself an open-source project, and this capability is used for KUSER_SHARED_DATA spoofing, but it is the same type of capability that kernel rootkits use.

### 12.3 Notes and Limitations

I did this analysis as a personal learning project in reverse engineering and security research. Here is what that means:

**This is not an expert or official assessment.** I am a student learning about security, not a professional malware analyst, reverse engineer, or security researcher. The tools I used (string extraction, PE parsing, Ghidra decompilation) are industry-standard, but my interpretation of results may contain errors or miss things that an experienced analyst would catch.

**My findings could be wrong.** Static analysis and automated decompilation have fundamental limitations. Obfuscated code, encrypted payloads, time-delayed behavior, or anti-analysis techniques could evade the methods I used. The fact that I found no malicious API calls in 41,644 lines of decompiled pseudocode is a data point, not a guarantee.

**Please wait for more official or experienced sources.** If you are looking for a definitive answer on whether this package is safe, my report alone should not be that answer. Look for analysis from established security researchers, antivirus vendors, or reverse engineering communities with more experience.

**What the risks could mean in practice:**
- Disabling DSE and PatchGuard removes protections that normally prevent unsigned drivers from loading -- this could leave the system exposed to other threats during the session
- Kernel drivers running at ring 0 have full system access -- a bug could cause a BSOD, and the MKDEV TEAM's own NFO acknowledges this risk
- The security features disabled by EfiGuard stay disabled until a clean reboot without EfiGuard, based on how EfiGuard's patches work
- Using cracked software raises legal concerns in most jurisdictions

**I'm documenting what I found, not what you should do.** My goal was to learn by analyzing the binaries and documenting the technical details. Please do your own research and consult more authoritative sources before making any decisions.

### 12.4 Summary

Based on what I found: I detected no evidence of malware through string extraction, PE analysis, or Ghidra decompilation of all six key binaries (41,644 lines of pseudocode, zero malicious API calls found -- see Appendix B). All major components are open-source (some not on GitHub), and MKDEV TEAM members are known in the scene. The package is a DRM bypass tool. However, it does involve disabling OS security features, which carries the inherent risks I documented above. I want to note that the entire chain can be built from scratch using open-source components rather than blindly running pre-built packages.

---

## Appendix B: Ghidra Decompilation Analysis

I decompiled all six key binaries in this package using **Ghidra 12.0.4** (NSA, open-source reverse engineering framework) running in headless analysis mode. I used a custom Java script (`ExportDecompiled.java`) to automatically decompile every function in each binary and export the results as C pseudocode. This appendix documents my complete findings.

### B.1 Decompilation Summary

| Binary | Functions Decompiled | Lines of Pseudocode | Architecture | Role |
|--------|---------------------|---------------------|--------------|------|
| `hyperkd.sys` | 26 | 603 | x86-64 | Intel kernel driver shim |
| `SimpleSvm.sys` | 87 | 2,268 | x86-64 | AMD SVM hypervisor driver |
| `hyperhv.dll` | 762 | 27,449 | x86-64 | HyperDbg-based Intel hypervisor library |
| `hyperevade.dll` | 12 | 271 | x86-64 | Hypervisor transparency module |
| `KIRIGIRI.dll` | 108 | 2,664 | x86 (32-bit) | Main orchestrator DLL |
| `EfiGuardDxe.efi` | 71 | 8,389 | x86-64 | UEFI DXE bootkit driver |
| **Total** | **1,066** | **41,644** | | |

### B.2 hyperkd.sys -- Decompiled Analysis (26 Functions, 603 Lines)

My Ghidra decompilation reveals that `hyperkd.sys` is a **thin shim driver** -- far simpler than my string analysis in Section 7 suggested. Of its 26 functions, only about 6 contain meaningful logic. The rest are C Runtime (CRT) boilerplate: `memset`, `__security_check_cookie`, `_guard_check_icall`, CPUID feature detection stubs, and stack cookie initialization.

**`entry()` -- Driver Entry Point:**

The `DriverEntry` function performs four actions in sequence:

1. **Registers a PowerState callback** via `ExCreateCallback` / `ExRegisterCallback` on `\Callback\PowerState` -- this lets the driver suspend/resume the hypervisor on sleep/hibernate
2. **Checks for an existing hypervisor** by calling `NtQuerySystemInformation` with information class `0xC4` (SystemHypervisorDetailInformation). If a hypervisor is already running, the driver aborts
3. **Calls `VmFuncInitVmm()`** with a zeroed `0xA0`-byte (160-byte) configuration structure. This function is **imported from `hyperhv.dll`** -- it is not implemented inside `hyperkd.sys` itself. This single call is what actually starts the hypervisor on all CPU cores
4. **Creates the CounterUpdater system thread** via `PsCreateSystemThread` -- this thread performs the KUSER_SHARED_DATA spoofing loop

**`FUN_140001160()` -- Driver Unload:**

Sets a stop flag to terminate the CounterUpdater thread, waits for the thread to exit via `KeWaitForSingleObject`, then calls `VmFuncUninitVmm()` (also imported from `hyperhv.dll`) to shut down the hypervisor on all cores.

**`FUN_140001260()` -- Power State Callback:**

When Windows suspends (sleep/hibernate), calls `VmFuncUninitVmm()` to devirtualize. When Windows resumes, calls `VmFuncInitVmm()` to revirtualize. This prevents BSODs caused by the hypervisor state being lost across power transitions.

**`FUN_14000121c()` -- Hypervisor Check:**

Calls `NtQuerySystemInformation(0xC4)` and returns whether a hypervisor is already present. This is used at startup to avoid loading a second hypervisor (which would conflict with Hyper-V, VirtualBox, or another instance).

**Key Finding:** hyperkd.sys does NOT contain the KUSER_SHARED_DATA spoofing logic, CPUID interception, HyperDbg scripting engine, or any hypervisor code. All of those capabilities reside in `hyperhv.dll` (see Section B.6). The `FUNC_*` strings and HyperDbg opcodes I found during string extraction in Section 7 come from `hyperhv.dll`, which `hyperkd.sys` links against as a dependency. The driver is essentially a 5-function wrapper: init, uninit, power callback, hypervisor check, and counter thread creation.

### B.3 SimpleSvm.sys -- Decompiled Analysis (87 Functions, 2,268 Lines)

SimpleSvm.sys is the AMD-specific hypervisor. Unlike `hyperkd.sys`, this driver is **self-contained** -- all hypervisor logic is compiled directly into the binary. My Ghidra decompilation exposed the full VM interception logic.

**`FUN_140001000()` -- The VMRUN Loop (The Core of the Hypervisor):**

This is the main hypervisor execution loop that runs on each CPU core. My decompiled pseudocode shows:

1. Saves all general-purpose registers (`RAX` through `R15`) plus six XMM registers (`XMM0`-`XMM5`) to the stack
2. Executes the AMD `VMLOAD` instruction to load guest state from the VMCB (Virtual Machine Control Block)
3. Executes `VMRUN` -- this transfers control to the guest (Windows). The CPU runs guest code until an intercepted event occurs
4. Executes `VMSAVE` to save guest state back to the VMCB
5. Restores all saved registers
6. Calls `FUN_140002b10()` (the VMEXIT handler) to process whatever event caused the exit
7. Loops back to step 1

This is a textbook AMD SVM virtualization loop matching the architecture described in the AMD programmer's manual.

**`FUN_1400010bc()` -- SYSRET Fast Path:**

Contains a comparison of `CR3` (the page table base register) against a stored value at `DAT_140005080`. When CR3 matches the target game process, the code takes a special path. This confirms to me that the hypervisor performs **process-specific interception** -- it only applies spoofing to the game process, not to the entire OS.

**`FUN_1400011a0()` -- CounterUpdater Thread (KUSER_SHARED_DATA Spoofing):**

This is the KUSER spoofing implementation for AMD systems. Here is what I found in the decompiled logic:

1. Calls `PsLookupProcessByProcessId` to find the target game process
2. Maps the KUSER_SHARED_DATA page (at virtual address `0x7FFE0000`) into the game's address space using `IoAllocateMdl` + `MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache` (MDL-based mapping)
3. Enters an infinite loop that continuously writes spoofed values into the mapped KUSER page:
   - Fake timestamp/tick count values
   - Fake CPU feature flags
   - Values designed to make Denuvo's environment fingerprint checks pass
4. Uses `PsSetCreateProcessNotifyRoutine` to register a callback that detects when the game process exits
5. When the process exits, unmaps the MDL and terminates the spoofing thread

**`FUN_140001be0()` -- CPUID VMEXIT Handler:**

This function processes intercepted CPUID instructions. My Ghidra decompilation revealed the complete set of magic CPUID values used for hypervisor communication:

| CPUID Input (EAX) | Action | Purpose |
|-------------------|--------|---------|
| `0x69696969` | Stores current process CR3 in `DAT_140005080` | Registers the game process with the hypervisor |
| `0x1` | Returns spoofed values: Family/Model `0x0A20F12`, feature flags `0x178BFBFF` | Hides hypervisor-present bit, returns normal AMD CPU features |
| `0x80000002` | Returns fake brand string part 1 | Together with 0x80000003/4, builds the string |
| `0x80000003` | Returns fake brand string part 2 | "DenuOvOwO CPU @ 1 337 GHz" |
| `0x80000004` | Returns fake brand string part 3 | (mocking Denuvo with "OwO" emoticon) |
| `0x336933` | Stores a value (game-specific data) | Used by KIRIGIRI.dll during initialization |
| `0x1337` | Sets `TargetProcessId` for KUSER spoofing | Tells CounterUpdater which PID to spoof for |
| `0x41414141` | De-virtualization | Shuts down the hypervisor on this core ("AAAA" = devirtualize magic) |
| `0x40000000` | Returns hypervisor vendor ID | Standard hypervisor vendor leaf |
| `0x40000001` | Returns `0x30237648` ("Hv#0") | Hypervisor version identifier |

For CPUID leaf `0x1`, the hypervisor **clears ECX bit 31** (hypervisor-present flag) before returning the result to the guest. This is the critical interception that hides the hypervisor from Denuvo.

**`FUN_14000259c()` -- SVM Initialization:**

Here is the initialization sequence I decompiled:

1. Executes CPUID leaf 0 and checks for "AuthenticAMD" vendor string -- aborts if not AMD
2. Enables SVM by setting the SVME bit in MSR `0xC0010114` (VM_CR)
3. Allocates 4 MB of physically contiguous memory for VMCB structures and nested page tables
4. Configures the VMCB to intercept MSRs `0x4101`, `0x4104`, and `0x4105` (custom MSRs used for hypervisor communication)
5. Saves the original `LSTAR` value (MSR `0xC0000082` -- the syscall entry point) for potential syscall hooking
6. Sets up nested page tables (NPT) for memory virtualization

**`FUN_14000259c()` -- Page Table Walker (`FUN_1400015b0`):**

Walks 4-level AMD page tables (PML4 -> PDPT -> PD -> PT) using `MmGetVirtualForPhysical` to translate between physical and virtual addresses. This is used to set up the nested page table (NPT) entries that create split memory views for the game process.

**`FUN_140002940()` -- DriverEntry:**

- Checks Windows version (requires Windows 8.1 or later via `RtlGetVersion`)
- Creates `\Callback\PowerState` callback registration
- Calls SVM initialization on all processors
- Creates CounterUpdater thread
- Service name found in decompiled strings: `"denuvo_kirigiri"`

### B.4 hyperevade.dll -- Decompiled Analysis (12 Functions, 271 Lines)

This is the smallest binary in the package. My Ghidra decompilation confirms it is a pure **hypervisor transparency module** with no functionality beyond hiding the hypervisor from detection.

**Exported Functions:**

| Function | What I Found in Ghidra |
|----------|------------------|
| `TransparentHideDebugger` | Stores 11 pointer/value pairs into a data structure. These values configure the hypervisor to suppress debugger-related artifacts |
| `TransparentUnhideDebugger` | Reverses `TransparentHideDebugger` by restoring original values |
| `TransparentCheckAndModifyCpuid` | For CPUID leaf 1: clears bit 31 of ECX (hypervisor-present flag). For CPUID leaves 0x40000000-0x40000001: returns `0x40000000` in all registers (generic "no real hypervisor info" response) |
| `TransparentCheckAndModifyMsrRead` | Returns 0 (no-op -- does not modify MSR read results) |
| `TransparentCheckAndModifyMsrWrite` | Returns 0 (no-op -- does not modify MSR write operations) |

All 12 functions are either the 5 exports listed above or CRT boilerplate (`DllEntryPoint`, `_guard_check_icall`, etc.). No file I/O, no network access, no memory manipulation beyond the configuration data structure. This DLL does exactly one thing: hide the hypervisor from CPUID-based detection.

### B.5 KIRIGIRI.dll -- Decompiled Analysis (108 Functions, 2,664 Lines)

My Ghidra decompilation of KIRIGIRI.dll revealed that it is the **true orchestrator** of the entire crack. This DLL does far more than my string extraction alone could show. It is a 32-bit (x86) DLL with one named export (`KIRIGIRI`, which is a no-op stub function).

**`entry()` -- DLL Entry Point (Complete Initialization Flow):**

When KIRIGIRI.dll is loaded (DLL_PROCESS_ATTACH, `param_2 == 1`), it executes the following sequence:

1. **`FUN_130020c3()` -- PEB Spoofing:** Accesses the Process Environment Block (PEB) and overwrites OS version fields: sets `OSMajorVersion` to 16, `OSBuildNumber` to 10, `OSPlatformId` to 6. This makes the process report a fake Windows version to Denuvo.

2. **`FUN_13002e11()` -- Syscall Number Extraction:** Gets module handle for `ntdll.dll`, then calls `GetProcAddress` to find `NtQuerySystemInformation` and `NtQueryFullAttributesFile`. Reads the syscall number (the `DWORD` at offset +4 from each function) and stores them in global variables. These syscall numbers are used later for direct syscall invocation that bypasses any hooks on ntdll.

3. **`FUN_1300259c()` -- Module Cloaking:** This function creates **shadow copies** of four system DLLs in newly allocated RWX (Read/Write/Execute) memory:
   - `ntdll.dll`
   - `kernel32.dll`
   - `kernelbase.dll`
   - `user32.dll`

   For each DLL, it calls `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`, copies the entire DLL image, and then **replaces the module entries in the PEB's three module lists** (`InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`). After this, any code that walks the PEB module list (including Denuvo's anti-tamper) sees the clean, unhooked shadow copies instead of the real system DLLs. This defeats DLL hook detection.

4. **`FUN_13001e27()` -- Service Installation and DSE Patching:** This function:
   - Executes CPUID leaf 0 to get the CPU vendor string
   - If the vendor is `AuthenticAMD` (`0x444D4163` / `0x69746E6568747541`): loads `SimpleSvm.sys`
   - If the vendor is `GenuineIntel` (`0x6C65746E` / `0x49656E69756E6547`): loads `hyperkd.sys`
   - Calls `OpenSCManagerW` and `CreateServiceW` to install the selected driver as a kernel service named `"denuvo_kirigiri"` with `SERVICE_KERNEL_DRIVER` type and `SERVICE_DEMAND_START` start type
   - If service creation succeeds, calls `StartServiceW` to load the driver
   - Calls `FUN_1300132e()` which performs **DSE patching via UEFI runtime variable**: maps `hal.dll` (on older Windows) or `CI.dll` (on newer Windows, determined by checking if the build number is below `0x23F0` = 9200 = Windows 8). It locates the `CiInitialize` function, walks its code to find the code integrity enforcement variable (`g_CiEnabled`/`g_CiOptions`), then calls `NtSetSystemEnvironmentValueEx` with a UEFI variable containing magic value `0xDEADC0DE` to patch it. This is how DSE is disabled **without EfiGuard** -- the crack has its own built-in DSE bypass
   - Launches `watchdog.exe` with `-pid <current_process_id>` argument

5. **`FUN_13003c6c()` -- Hypervisor Registration via CPUID Magic:** Executes a sequence of CPUID instructions with magic values to communicate with the now-loaded hypervisor:
   - `CPUID(0x69696969)` -- Registers the current process's CR3 with the hypervisor (tells it "this is the game process")
   - `CPUID(0x336933)` -- Stores game-specific configuration data
   - Gets the current process ID via `GetCurrentProcessId()`
   - `CPUID(0x1337)` -- Passes the PID to the hypervisor so the CounterUpdater thread knows which process to spoof KUSER data for
   - `Sleep(1000)` -- Waits 1 second for the CounterUpdater thread to start and begin spoofing

6. **`FUN_13002e73()` -- IAT Hook Installation:** Installs Import Address Table hooks on specific Windows API functions. The decompiled code shows it uses `FUN_13002f35()` which writes a 6-byte hook trampoline (`0x68` = `PUSH imm32`, followed by `0xC3` = `RET` -- a classic push/ret hook pattern). The hooked functions include:
   - `NtQuerySystemInformation` / `ZwQuerySystemInformation` -- hooked to hide the hypervisor from system information queries
   - `NtQueryFullAttributesFile` / `ZwQueryFullAttributesFile` -- hooked to hide crack-related files from directory queries
   - `RegQueryValueExA` -- hooked, returns an error for `"HwProfileGuid"` queries (Denuvo uses this for hardware fingerprinting)
   - `CreateFileW` -- hooked to intercept file open requests for Denuvo's license token identifier `"92346205896"` and redirect them to `KIRIGIRI.bin`

7. **`FUN_13002cb7()` -- Fake Denuvo License File Creation:** Creates `KIRIGIRI.bin` in the same directory as the game executable. This file is 6,247 bytes (`0x1867`). The function checks the CPU vendor string and writes different license data depending on whether the system is AMD or Intel (the license blob is different for each architecture). This file is what Denuvo receives when it tries to read its license token -- the `CreateFileW` IAT hook redirects the open to this file.

8. **`FUN_130030e4()` -- PEB Module List Unlinking:** Walks the PEB's `InLoadOrderModuleList` (at PEB offset `0x18 + 0x10`) and finds the entry for KIRIGIRI.dll itself. Unlinks it from all three module lists (`InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`). After this, KIRIGIRI.dll is invisible to any code that enumerates loaded modules (including Denuvo's DLL scanning).

9. **`FUN_13002f40()` -- Inline Code Patches (Capcom DRM + SteamStub):** Uses `VirtualProtect` to make specific code pages writable, then writes immediate byte patches:
   - `0x3CEE9` -- a `JMP` instruction (patching a Capcom DRM / SteamStub check to jump over it)
   - `0x1B0` -- `MOV AL, 1` (making a check function always return TRUE)
   - `0x9090` -- two `NOP` instructions (patching out a conditional branch)
   KIRIGIRI.dll patches **static addresses** for the Capcom DRM and SteamStub -- these are direct patches to known protection check locations in the game executable's memory.

**`FUN_13001bfb()` -- Hypervisor Detection:**

Executes `CPUID(0x40000001)` and checks if the result equals `"Hv#0"` (`0x30237648`). This is how KIRIGIRI.dll checks whether the hypervisor is already loaded before attempting to load it again.

**Named Export -- `KIRIGIRI()`:**

The sole named export is a **1-byte no-op function** (just a `RET` instruction). The export exists solely so the game/loader can call `LoadLibrary("KIRIGIRI.dll")` and the DLL's `entry()` function triggers the full initialization chain. The export name itself is never called.

### B.6 hyperhv.dll -- Decompiled Analysis (762 Functions, 27,449 Lines)

This is the largest binary in the package at 533,360 bytes and 762 decompiled functions. Ghidra decompilation combined with export table analysis via Python pefile confirms this is based on the **HyperDbg** open-source hypervisor debugger ([github.com/HyperDbg/HyperDbg](https://github.com/HyperDbg/HyperDbg)).

**Export Table Analysis (290+ Exports):**

Python pefile export enumeration revealed 290+ exported functions. Key categories:

| Category | Examples | Count |
|----------|----------|-------|
| VM Management | `VmFuncInitVmm`, `VmFuncUninitVmm`, `VmFuncVmxVmcall` | 277 `VmFunc*` exports |
| Broadcasting | `BroadcastDpcResetMsrBitmapRead/Write`, `BroadcastEnableBreakpointOnPmc` | 12+ |
| Configuration | `ConfigureEnableMovToControlRegisterExitingForCr`, `ConfigureExecTrapAddtionalAddProcessId` | 8+ |
| Guest Register Access | `GetGuestRax`, `SetGuestRip`, `GetGuestCs`, `SetGuestIdtr` | 20+ |
| Disassembly | `DisassemblerShowOneInstructionInVmxRootMode`, `DisassemblerShowInstructionsInVmxNonRootMode` | 4+ |
| Debugging | `BreakpointHandleBreakpoints`, `BreakpointCheckAndPerformActions` | 6+ |
| Counter | `CounterUpdater` | 1 |
| Hardware I/O | `PciReadCam`, `PciWriteCam` | 2 |

These function names exactly match the HyperDbg API as documented in its public source code.

**`CounterUpdater()` -- KUSER_SHARED_DATA Spoofing (Intel Path):**

I decompiled this at line ~17860 of the output. This is the Intel-platform equivalent of SimpleSvm.sys's `FUN_1400011a0()`. The logic is identical:

1. Calls `PsLookupProcessByProcessId` to find the game process
2. Maps `0x7FFE0000` (KUSER_SHARED_DATA) via MDL
3. Enters an infinite loop writing spoofed timestamps and feature flags
4. Uses `PsSetCreateProcessNotifyRoutine` for process exit detection
5. Unmaps and cleans up when the game exits

**`VmFuncInitVmm()` -- Hypervisor Initialization:**

Copies 20 configuration values from the caller-provided configuration structure (the 0xA0-byte struct passed by `hyperkd.sys`), then initializes per-processor structures (0x230 bytes per logical core). Calls internal initialization functions and ultimately launches the VMX hypervisor on every processor core using VMX instructions (`VMXON`, `VMCLEAR`, `VMPTRLD`, `VMLAUNCH`).

**HyperDbg Origin Confirmation:**

The 762 function names and their calling patterns are a precise match for HyperDbg's architecture. The `VmFunc*` prefix is HyperDbg's convention for its VMX abstraction layer. The `Broadcast*` functions are its mechanism for sending IPIs (Inter-Processor Interrupts) to execute code on all cores simultaneously. The `Configure*` functions match HyperDbg's event configuration API. This is a modified build of HyperDbg repurposed as a DRM bypass hypervisor for Intel platforms.

### B.7 EfiGuardDxe.efi -- Decompilation Note (71 Functions, 8,389 Lines)

I successfully decompiled EfiGuardDxe.efi (71 functions, 8,389 lines of pseudocode). Since EfiGuard is an open-source project with publicly available source code at [github.com/Mattiwatti/EfiGuard](https://github.com/Mattiwatti/EfiGuard), I did not prioritize detailed decompilation analysis. The decompiler produced 3 warnings about "Unable to read bytes at ram:cccccccc" which are debug fill patterns (`0xCC` = uninitialized memory in MSVC debug builds) and do not indicate any issues. The decompiled output confirms the patching logic I described in Section 5 (PatchGuard disable, DSE disable, boot chain hooks).

### B.8 Malicious API Sweep -- Zero Matches

I ran a comprehensive search across all six decompiled output files (41,644 total lines of C pseudocode) for any API calls associated with malicious behavior:

**Network/Exfiltration APIs Searched:**
`socket`, `connect`, `send`, `recv`, `Http`, `Internet`, `Download`, `WSA`, `TDI`, `NDIS`, `WinHttp`, `WinInet`, `URLDownload`

**Process Injection APIs Searched:**
`CreateRemoteThread`, `WriteProcessMemory`, `ReadProcessMemory`, `OpenProcess`

**Code Execution APIs Searched:**
`ShellExecute`, `WinExec`, `LoadLibrary` (in suspicious contexts)

**Result: ZERO matches across all 41,644 lines.**

In none of the six decompiled binaries did I find any calls to network socket functions, HTTP/internet libraries, remote thread injection, cross-process memory manipulation, or shell command execution. The only process-related APIs I found are `GetCurrentProcessId` (used to pass the game's PID to the hypervisor) and `PsLookupProcessByProcessId` (kernel-mode function used to find the game process for KUSER spoofing).

### B.9 Architectural Revelations from Decompilation

My Ghidra decompilation revealed several facts that I could not discover through string extraction alone:

**1. hyperkd.sys is not the "real" driver.** My string analysis in Section 7 suggested `hyperkd.sys` contained a HyperDbg scripting engine and was the main hypervisor driver. My decompilation proved this wrong -- `hyperkd.sys` is a 26-function shim that imports `VmFuncInitVmm` and `VmFuncUninitVmm` from `hyperhv.dll`. All 762 hypervisor functions, including the HyperDbg scripting engine and the `FUNC_*` opcodes, reside in `hyperhv.dll`. The strings appeared in `hyperkd.sys` during extraction because the linker embeds import library metadata.

**2. KIRIGIRI.dll is the true orchestrator.** My string analysis could not reveal the initialization flow. My decompilation showed that KIRIGIRI.dll's `entry()` function runs a 9-step initialization sequence that handles everything: PEB spoofing, module cloaking, CPU vendor detection, driver selection (AMD vs Intel), service installation, DSE patching, hypervisor registration via CPUID magic values, IAT hooking, and fake license file creation.

**3. The crack has its own DSE bypass.** My decompilation of `FUN_1300132e()` in KIRIGIRI.dll revealed a complete DSE disable mechanism using `NtSetSystemEnvironmentValueEx` with a UEFI runtime variable (magic value `0xDEADC0DE`). This means the crack can disable Driver Signature Enforcement **without EfiGuard**, using the same SetVariable backdoor technique. This I confirmed at the code level -- it's why the NFO says EfiGuard is optional.

**4. CPUID is the hypervisor communication channel.** Both SimpleSvm.sys and `FUN_13003c6c()` in KIRIGIRI.dll show that user-mode code communicates with the hypervisor using CPUID instructions with magic values (`0x69696969`, `0x1337`, `0x336933`, `0x41414141`). The hypervisor intercepts these at ring -1 and performs the requested action. This is a standard technique in hypervisor-based tools to provide a communication channel that does not require IOCTL device objects or shared memory.

**5. The module cloaking is sophisticated.** My decompilation of `FUN_1300259c()` showed that KIRIGIRI.dll creates full shadow copies of four system DLLs in executable memory and replaces the PEB module list entries. This is not simple DLL unhooking (which just remaps clean copies from disk) -- it is full module list manipulation that changes what DLLs the process appears to have loaded.

**6. Inline patching targets Capcom DRM and SteamStub.** `FUN_13002f40()` uses `VirtualProtect` + direct byte writes to patch specific static addresses in the game's memory. These patches target the **Capcom DRM and SteamStub** protections. The patterns (`JMP`, `MOV AL,1`, `NOP NOP`) are classic binary patching patterns that bypass conditional checks at known protection check locations.

### B.10 Decompilation Findings Summary

Across 1,066 decompiled functions and 41,644 lines of pseudocode, here is what I observed:

- **Zero network-related API calls** found in any binary
- **Zero process injection techniques** (no `CreateRemoteThread`, no `WriteProcessMemory` targeting other processes)
- **Zero file exfiltration logic** (no file uploads, no clipboard reading, no screenshot capture, no keystroke logging)
- **Zero cryptocurrency mining indicators** (no hash algorithms, no pool connections, no GPU compute dispatches)

Every decompiled function I reviewed mapped to one of four categories: (1) hypervisor lifecycle management (init/uninit/VMRUN/VMEXIT handling), (2) Denuvo evasion (CPUID spoofing, KUSER spoofing, IAT hooking, module cloaking), (3) driver installation/management (service creation, DSE patching, power state callbacks), or (4) CRT boilerplate (memset, security cookies, guard functions).

My decompilation showed `hyperkd.sys` is a thin wrapper around `hyperhv.dll` with only 6 meaningful functions. The bulk of the hypervisor logic lives in `hyperhv.dll` (762 functions, 533 KB), whose function signatures match the publicly available HyperDbg open-source project. I found no malicious deviations in the decompiled output, but as I've noted throughout this report, decompilation has inherent limitations and I may have missed things.

---

## Contributing & Feedback

This analysis is a living document and a learning project -- it's not perfect. If you spot something wrong, have better technical insight, or know something that should be updated, your input is genuinely welcome and appreciated. My goal is to make this as accurate and useful as possible for the community.

**What could use help:**
- Correcting any technical inaccuracies in my analysis
- Providing additional context about components, tools, or techniques described here
- Updating information that may have changed since I wrote this
- Improving explanations that are unclear or misleading

If you find any issues, please [open an issue](../../issues) on this repository. Whether it's a small typo or a major factual error, all feedback helps improve this report for everyone.

---

*Report generated: March 4, 2026*
*Analysis methods: passive static string extraction, PE header parsing, config file analysis, open-source research, and Ghidra 12.0.4 headless decompilation of all key binaries.*
*This is a student learning project, not a professional security audit. Findings may contain errors.*

