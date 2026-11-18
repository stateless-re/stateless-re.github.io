---
title: "PLOTSAFE's post-quantum loader always picks salt number 3"
date: 2026-11-14T18:28:19+00:00
slug: "plotsafe-kem-loader"
description: "PLOTSAFE's Gen 2 loader runs a Kyber-512 key exchange and 23 checks that corrupt the key instead of exiting, then a Go Sum() call pins its salt to number 3."
tags: ["plotsafe", "acrstealer", "golang", "garble", "emulation", "kyber", "process-injection", "windows"]
sample:
  family: "PLOTSAFE loader (Gen 2)"
  sha256: "2e3e1bcd44cc3cbec4f5ca9991d14a326d3cc6bf76fe6e0d434c9b5f7e1ae6ab"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/2e3e1bcd44cc3cbec4f5ca9991d14a326d3cc6bf76fe6e0d434c9b5f7e1ae6ab)"
toc: true
---

PLOTSAFE's second-generation loader decrypts its payload with an AES-256 key that passes through a Kyber-512 key decapsulation. The private key for that decapsulation is built from a 32-byte mask that 23 sandbox and debugger checks quietly corrupt. A sandbox doesn't get an early exit; it gets the wrong key, and the loader returns without a word.

The step after the key exchange is meant to choose one of 16 salts from a hash of the shared secret. But a Go `hash.Sum(b)` call appends instead of replacing, so the "random" index is the low nibble of the letter `s`: salt number 3, on every run.

With the checks' byte inversions suppressed, the 100,230-byte payload decrypts. It is 32-bit shellcode that the loader writes into a suspended `OpenWith.exe`, and inside it is a stealer that opens the Windows AFD driver directly.

Cisco Talos covered PLOTSAFE on October 8 in [a report on malware that addresses AI-assisted analysis](https://blog.talosintelligence.com/ignore-all-instructions-and-read-this-blog-the-state-of-ai-analysis-evasion-in-malware/) (Ryan Fetterman), with a longer [family write-up](https://github.com/Cisco-Talos/Cognitive-Artifact-Intelligence-Research-Network/blob/main/docs/families/PLOTSAFE.md) in its CAIRN repository. That work is about the decoy sentences the builds carry for language-model triage tools. It is explicit about what it left:

- the C2 "come[s] from sandbox execution and AV labelling only";
- static recovery would have needed emulating about 960 string-decryption sites;
- the stealer payload was never recovered.

Both PLOTSAFE DLLs Talos lists in the blog were on Hybrid Analysis but not on MalwareBazaar. I read them with pefile and capstone and emulated the lifted code with Unicorn. This post follows the Gen 2 build (`2e3e1bcd…`) from its string protection to its third stage.

## What I found

- The roughly 960 string sites Talos counted hide Go standard-library strings (`bufio`, `zlib`, `encoding/hex`, time-zone text), nothing that belongs to the loader. The loader's own strings use a per-string Caesar shift.
- Twenty-three sandbox and debugger checks each invert one byte of a 32-byte mask. The mask feeds the Kyber-512 private key, so a hit is meant to change the AES key.
- The AES key is `SHA-256(shared_secret || "PQC-PE-AES256GCM")`. The salt index is the first byte of `hmac.Sum([]byte("salt-select"))`, masked with `0x0F`, which is always 3.
- The payload is 25 AES-GCM chunks with Ascii85-encoded nonces and tags. It decrypts to x86 shellcode (SHA-256 `2a30450c…`) that XORs and aPLib-unpacks a 319,488-byte PE32 (`7503f54b…`). Neither hash is on MalwareBazaar or Hybrid Analysis.
- The loader starts `C:\Windows\SysWOW64\OpenWith.exe` suspended, writes the shellcode with `Nt*` functions it resolves by SHA-1 of the export name, and patches the entry point with `mov eax, <addr>; jmp eax`.

## Two layers of string hiding, and only one matters

The DLL is Go 1.25.0 built as a c-shared library (`loader_3.dll`, export `DllConfigure`). The function table is intact (5,412 entries) but 4,793 of the names are empty strings and the rest are mostly garbled, and package paths are random words (`JR_ZwBDamQyI/escape.go`). That is [garble](https://github.com/burrowers/garble)'s style, so I started with Mandiant's [GoStringUngarbler](https://github.com/mandiant/gostringungarbler). It found zero strings: its epilogue patterns stop at Go 1.23.

Talos's write-up points at 808 exact 256-byte permutations in `.rdata` (file offset `0x352940`) and calls them obfuscator key material, not ciphertext. That is right. Each string site copies one permutation onto the stack and runs a few rounds of byte substitution and chained XOR over a heap buffer:

```asm
lea  rsi, [rip + 0x2e1ffd]      ; one of the 808 tables
call 0x180068600                ; Go duffcopy, 256 bytes to [rsp+0x1c]
...
movzx esi, byte ptr [rax + rdx] ; buffer byte
movzx esi, byte ptr [rsp + rsi + 0x1c]  ; substitute through the table
```

Rather than reimplement each variant, I emulated every function that loads a table, starting at the function entry and dumping any buffer passed to the next call. The tables are referenced from 960 places in 166 functions. The emulator reached 952 of them; the 8 it missed are in standard-library functions low in `.text`.

The buffers it captured hold 1,117 distinct printable runs:

- time-zone names and Unicode script names;
- `strconv`, `bufio` and `zlib` errors;
- `debug/pe` messages;
- `encoding/hex: odd length hex string` and `illegal ascii85 data at input byte`, in the helpers next to the loader's main.

I searched them for URLs, domains, executable names and the strings the loader uses later; there are none.

So emulating the 960 sites would not have given Talos the C2. The loader's own strings are much simpler, a Caesar shift on letters that changes per string:

```asm
lea  ecx, [rdi - 0x4f]          ; c - 79
imul rcx, rdx                   ; / 26 (0x9d89d89e magic)
imul ecx, ecx, 0x1a
sub  edi, ecx                   ; c - 26 * ((c - 79) / 26)
lea  ecx, [rdi + 0x12]          ; + 18
```

`camz32.ltt` becomes `user32.dll`. The three shifts I checked were 17, 18 and 19.

## Emulating a Go DLL with no symbols

Reading the main function statically was slow: the loader builds everything at run time and calls through Go interfaces. I emulated it instead, which needed three things the bench didn't have.

First, names for the runtime. I downloaded the Go 1.25.0 toolchain, built a small Windows program that imports the same standard packages, and matched functions by instruction sequence with immediates and branch targets masked. That named 1,278 of the DLL's 5,029 functions, including `mallocgc`, `growslice`, `slicebytetostring`, `syscall.(*LazyProc).Call` and `runtime.cgocall`.

Second, a Go runtime that works without being initialized. The emulator replaces the allocators with a bump allocator and gives `r14` a fake `g` with an `m` and a `p` behind it (the `sync.Pool` code reads `m.p.id`, and `deferprocStack` checks `m.curg`). It maps a TLS block so the ABI wrappers' `mov r14, gs:[...]` reload finds that `g`, and it answers every Windows call itself.

Third, real PE files: the loader reads `ntdll.dll`, `kernel32.dll` and `user32.dll` from `System32` with Go's `debug/pe`. I used the PE builds that ship in Ubuntu's `libwine` package. Wine's DLLs keep a COFF symbol table, and `debug/pe` read it 18 bytes at a time, thousands of reads, until the instruction limit. Zeroing the symbol-table pointer in my copies fixed that.

With that, the call graph is short. `0x180276080` is the loader's main:

| Function | What it does |
|---|---|
| `0x180269120` | Checks that `C:\Windows\System32`, `SysWOW64` and the .NET 4 directory open |
| `0x180268aa0` | Hex-decodes a 200,460-character string in `.rdata` (file offset `0x2d4acb`) into 100,230 bytes |
| `0x18026e0c0` | Environment checks, key derivation, decryption |
| `0x18027b8e0` | Hides the console, starts `SysWOW64\dllhost.exe` suspended |
| `0x18026afe0` | Starts `SysWOW64\OpenWith.exe` suspended and injects |

If the decryption returns an empty slice, main returns. No message, no exit code worth reading.

## Twenty-three checks that change the key instead of the control flow

Inside `0x18026e0c0`, the loader Ascii85-decodes a 32-byte mask, `XLCMJDeshSLvAFYMfRKfShzaDNgrTnkb`, and then runs its checks. A hit doesn't branch to an exit. It inverts one byte of the mask:

```asm
mov  esi, 0x7ffe03c0            ; KUSER_SHARED_DATA.ActiveProcessorCount
cmp  dword ptr [rsi], 2
jae  0x18026fec2
movzx esi, byte ptr [rdx + 0xc]
not  esi                        ; one CPU: flip mask byte 0x0c
mov  byte ptr [rdx + 0xc], sil
```

There are 23 of these `not` sites, one for each mask byte from `0x00` to `0x17` except `0x0f`. What they test, from the strings main builds and the code around each site:

- Debuggers: `NtQueryInformationProcess` classes 7, `0x1e` and `0x1f` (debug port, debug object, debug flags), `NtGlobalFlag & 0x70` in the PEB, and the process heap's flags. It also calls `NtSetInformationThread` with class `0x11` to hide its own thread from a debugger.
- Microsoft Defender's emulator: whether it can find exports named `MpVmp32Entry`, `MpReportEventEx` and `NtControlChannel`, and whether `C:\INTERNAL\__empty` exists. As far as I know, only the emulator's DLLs carry those exports.
- Sandbox names. Hosts: `DESKTOP-B0T93D6`, `DESKTOP-BJNL7RX`, `HAL9TH`, `HANSPETER-PC`, `JOHN-PC`, `KLONE_X64-PC`, `MUELLER-PC`, `SANDBOX`, `7SILVIA`, `FORTINET`, `WIN7-TRAPS`. Users: `CurrentUser`, `Emily`, `JohnDoe`, `Johnson`, `Miller`, `Peter Wilson`, `Sandbox`, `timmy`.
- Files and devices: `C:\Users\Public\triage_wallpaper.jpg` and a device called `\\.\A3E64E55_fl`, which I couldn't attribute.
- Hardware, read straight from `KUSER_SHARED_DATA` without an API call: interrupt time below `0x1AD274800` (12 minutes of uptime), fewer than two active processors, fewer than `0x100000` physical pages (4 GiB).
- A field of the mode returned by `EnumDisplaySettingsW` (the dword at offset `0x78` must be at least 29), and Media Foundation: `MFTEnumEx` with `MFT_CATEGORY_VIDEO_DECODER` and flag `0x20` (`MFT_ENUM_FLAG_TRANSCODE_ONLY`). I didn't work out the exact threshold for the decoder count.
- A few more that I didn't map to mask bytes: `OpenProcessToken`/`GetTokenInformation`, `GetCursorPos`, `IsIconic`, and a test of a global flag set earlier.

Why corrupt instead of exit? Because the corruption is invisible. Patching a conditional jump in a sandbox is routine; there is no jump here. Every check runs, every path continues, and the only symptom is a decryption that fails at the end.

My first emulated run showed exactly that. Seven checks fired because of my own API models:

- my `Find` stub reported the three Defender-emulator exports as present (bytes 5 to 7);
- my fake `KUSER_SHARED_DATA` page said zero processors and zero memory (bytes `0x0c` and `0x0d`);
- my display-mode buffer had zeros at offset `0x78` (byte `0x16`);
- a two-condition helper at `0x18024bce0` returned false (byte `0x0a`).

The key that came out failed every GCM tag. Suppressing those seven inversions, and only those, produced a key that authenticated all 25 chunks. So on the build's intended targets no check fires.

I tested the seven together, not one at a time, and I didn't reverse how each mask byte enters the private key.

## The key goes through Kyber-512, then loses its randomness

With the mask in hand, `0x180275a00` assembles a private key from it, 11 encoded fragments and a 64-byte value. I didn't reverse that function; I watched its output, a 1,632-byte buffer. The loader then makes two calls through a Go interface:

| itab offset | Method (circl `kem.Scheme`, sorted) | Arguments seen |
|---|---|---|
| `+0x78` | `UnmarshalBinaryPrivateKey` | 1,632 bytes |
| `+0x20` | `Decapsulate` | private key, 768-byte ciphertext from an Ascii85 string `768:…` |

A 1,632-byte private key and a 768-byte ciphertext are the Kyber-512 sizes. I think this is Cloudflare's [circl](https://github.com/cloudflare/circl) `kem.Scheme`. Gen 2's package paths are garbled, but the Gen 1 build names `github.com/cloudflare/circl/kem/kyber/kyber512` in clear, and Go's itab orders methods by name, which puts `Decapsulate` at slot 1 (`+0x20`) and `UnmarshalBinaryPrivateKey` at slot 12 (`+0x78`). Kyber's decapsulation doesn't fail on a wrong private key. It returns a pseudorandom secret, so a sandbox-corrupted mask leads straight to a well-formed, wrong key.

On a clean run the shared secret is:

```text
63b03e1e3f9180bfcd242f630ad2a4503cfc1fb6b68ef6660239b67a000a3ff3
```

Next comes a step that is meant to pick a salt. The loader XOR-decodes the string `salt-select`, passes `sha256.New` and the shared secret to what looks like `crypto/hmac.New`, writes nothing to the result, and then:

```asm
mov  rbx, rax          ; slice "salt-select", len 11
mov  rax, [rsp+0xa78]  ; the HMAC
call rdx               ; hash.Hash.Sum(b)
movzx ecx, byte ptr [rax]
and  ecx, 0xf          ; index into a table of 16 salts
```

`Sum(b)` in Go appends the digest to `b` and returns the result. The first byte of the returned slice is therefore the first byte of `salt-select`, which is `s`, `0x73`, and `0x73 & 0x0F` is 3. I decoded all 16 table entries, each the XOR of two Ascii85 strings: entry 3 is `PQC-PE-AES256GCM`, and the other 15 are random letters like `ibzhYLqmhulStAAg`. The author wrote a salt lottery and shipped a constant.

The AES key:

```text
key = SHA-256(shared_secret || "PQC-PE-AES256GCM")
    = 04086cb0d0e02b86795724aab3db1d5cdafd82d017307e9657f338edc1f0757b
```

## 25 GCM chunks

The 100,230 ciphertext bytes from the hex blob are split into chunks of 4,096 bytes, 25 in total with a short last one. Each chunk has its own nonce and tag, stored as two 25-entry tables of Ascii85 strings with a length prefix (`12:<*3^WE+MOR=%$mn` is a 12-byte nonce, `16:3*X$*qra-iYAL9aQ8h@k` a 16-byte tag). The loader appends the tag to the chunk and calls the GCM `Open` method with no additional data.

| Item | Where | Format |
|---|---|---|
| Ciphertext | `.rdata`, file offset `0x2d4acb` | 200,460 hex characters |
| Nonces | 25 string headers at VA `0x1803864f0` | `"12:" + Ascii85` |
| Tags | 25 string headers at VA `0x180386680` | `"16:" + Ascii85` |
| Key | derived above | 32 bytes |

I took the nonces for hex at first; they decoded to the wrong length, which is what sent me to the length prefix. In Python with the derived key, all 25 chunks authenticate, and the plaintext is 100,230 bytes with SHA-256 `2a30450c2fa5a2b7ad03bed87f732010e8bcdeda04b2809d3ed336e54b5e17ac`.

## The payload is 32-bit shellcode with a packed PE inside

The plaintext opens with `E8 FC 7D 01 00`, a call over 97,788 bytes of data. That is how Donut shellcode starts, so I ran Volexity's [donut-decryptor](https://github.com/volexity/donut-decryptor) on it. "Found 0 donuts." The code after the data is 2,437 bytes of x86, much smaller than Donut's loader, and it is a self-contained PE loader. It finds `kernel32` through the PEB and resolves seven functions (`VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `LoadLibraryA`, `GetModuleHandleA`, `GetProcAddress`, `ExitProcess`) with a 31-multiplier hash:

```text
h = 0x6c6c6a62
for c in name: h = h * 31 + (c | 0x20)    # mod 2**32
```

The data block in front of the stub has this layout:

| Offset | Size | Field | Value |
|---|---|---|---|
| `0x00` | 4 | unpacked size | `0x4e000` |
| `0x04` | 4 | packed size | `0x17d73` |
| `0x08` | 128 | XOR key | |
| `0x88` | 1 | flag | `0` |
| `0x89` | packed size | data | `data[i] ^ key[i & 0x7f]`, then aPLib |

XOR and aPLib give a 319,488-byte PE32 GUI executable, SHA-256 `7503f54b0766e7257b41ca88f71940b28130c79eaa40bbdb4fe938b088147111`: four sections, no import directory, a zero timestamp. Its strings are built at run time; FLOSS recovered `\Device\Afd\Endpoint` and `AfdOpenPacketXX`. Talking to the AFD driver directly instead of through Winsock is what [Proofpoint documented](https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication) for Amatera, which Proofpoint and [ESET](https://www.welivesecurity.com/en/malware/amatera-how-prolific-infostealer-works-spreads/) both tie to ACR Stealer. Talos's family notes call PLOTSAFE's payload ACRStealer, by AV label. I think stage 3 is an ACR/Amatera build, on those two strings and that label; I didn't decode its configuration.

## Injection into a suspended OpenWith.exe

The loader doesn't run the shellcode itself; it is a 64-bit DLL and the shellcode is 32-bit. `0x18026afe0` resolves its functions by name digest: it walks the export table of the copy of each DLL it read from disk and compares `SHA-1(export name)` with a hex string. The 25 lookups use 21 distinct digests, and 20 match `ntdll`, `kernel32` and `user32` exports, among them `NtAllocateVirtualMemory` (`04262a79…`), `NtWriteVirtualMemory` (`6caed958…`), `NtProtectVirtualMemory` (`059637f5…`), `CreateProcessW` (`540448bf…`) and `ResumeThread` (`753773e2…`). One, `f3f8c92b428c063d72c361b4cda93ecfd793071d`, matches nothing Wine exports.

Those calls go through objects my emulator couldn't name, so the sequence below is labelled from the resolved set and the argument shapes:

1. `CreateProcessW(NULL, "C:\Windows\SysWOW64\OpenWith.exe", …, bInheritHandles=TRUE, CREATE_SUSPENDED, …)` with a `0x70`-byte startup-info block, the size of `STARTUPINFOEXW`.
2. `NtQueryInformationProcess(child, ProcessBasicInformation)`, then a read of 8 bytes at PEB+`0x10` (the image base) and 0x200 bytes of the image header.
3. `NtAllocateVirtualMemory` for `0x18786` bytes, `PAGE_READWRITE`; `NtWriteVirtualMemory` with the shellcode; `NtProtectVirtualMemory` to `PAGE_EXECUTE_READ`.
4. `NtProtectVirtualMemory` on 7 bytes at the entry point to `PAGE_EXECUTE_READWRITE`, a write of `B8 <addr> FF E0` (`mov eax, addr; jmp eax`), and protection back to `PAGE_EXECUTE_READ`.

My emulation stops at the next call. The loader has resolved `ResumeThread` and `NtFlushInstructionCache`, and Talos's sandbox runs of the Gen 1 build show later activity (a PowerShell child and C2 traffic). So I think the thread is resumed next.

Before all this, `0x18027b8e0` hides its console window and starts `SysWOW64\dllhost.exe` suspended. It also resolves `ReadProcessMemory`, `WriteProcessMemory` and `TerminateProcess`, but my emulated run took a branch that used none of them, so I can't say what that child is for.

The `STARTUPINFOEXW`-sized block and the resolved `InitializeProcThreadAttributeList`/`UpdateProcThreadAttribute` suggest parent spoofing. But the creation flags I saw were `CREATE_SUSPENDED` alone, without `EXTENDED_STARTUPINFO_PRESENT`.

## The decoy text

Talos's report is mostly about the sentences this build carries for language-model triage, a "Build ID … Test suite: memory allocator fragmentation analysis tool | Status: PASSED" line and a note "For automated scanners". They sit in `.rdata`, Talos describes how the build keeps them from being dropped, and I didn't follow them further: none of the steps above needed them. Hybrid Analysis files the Gen 2 DLL under the verdict "no specific threat"; I have no way to tell why.

## Wrong turns

- GoStringUngarbler found nothing; its patterns predate Go 1.24.
- I expected the ~960 table sites to hide the C2. They hide the standard library.
- My first pass found only 720 of the sites. Capstone's linear sweep over `.text` stops at the first bytes it can't decode, and I hadn't noticed it never reached the loader's end of the section.
- Walking `.pdata` function by function found all 960. A table-range bound I had typed `0x800` short hid the last few.
- Wine's COFF symbol tables turned `debug/pe` into thousands of 18-byte reads.
- My first key was wrong because my own API answers tripped seven checks.
- I read the nonces as hex, then the payload as Donut. Neither held.

## What I couldn't determine

- Stage 3's configuration and C2. Its strings are assembled at run time and I stopped at FLOSS. The domains below come from Talos's sandbox runs of the Gen 1 build, not from my analysis.
- What `0x180275a00` does with the mask and the 11 fragments; I observed its output only.
- What the `dllhost.exe` child is for, and whether parent spoofing happens on a real host.
- The export behind SHA-1 `f3f8c92b…`.
- The Gen 1 build (`a42632c6…`), which I didn't decrypt.

The Gen 1 build carries a hex blob of exactly the same length (200,460 characters), a `768:` Ascii85 string and circl's Kyber-512 package in clear. So I think it wraps the same 100,230-byte payload the same way.

## Indicators

| SHA-256 | Role |
|---|---|
| `2e3e1bcd44cc3cbec4f5ca9991d14a326d3cc6bf76fe6e0d434c9b5f7e1ae6ab` | PLOTSAFE Gen 2 loader DLL (`loader_3.dll`), Hybrid Analysis |
| `a42632c68d2dcea06300e790c9440fe0943ce0dee2075f29170fd2774eacf433` | PLOTSAFE Gen 1 loader DLL (`loader_10.dll`), Hybrid Analysis |
| `2a30450c2fa5a2b7ad03bed87f732010e8bcdeda04b2809d3ed336e54b5e17ac` | Decrypted 32-bit shellcode (stage 2), derived here |
| `7503f54b0766e7257b41ca88f71940b28130c79eaa40bbdb4fe938b088147111` | Unpacked PE32 (stage 3), derived here |

| Indicator | Type | Source |
|---|---|---|
| `plotsafe[.]icu` | domain | Talos sandbox (Gen 1) |
| `overexert.systemstatus[.]info` | domain | Talos sandbox (Gen 1) |
| `C:\Windows\SysWOW64\OpenWith.exe` (suspended, injected) | process | this analysis |
| `C:\Windows\SysWOW64\dllhost.exe` (suspended) | process | this analysis |
| `\\.\A3E64E55_fl`, `C:\Users\Public\triage_wallpaper.jpg`, `C:\INTERNAL\__empty` | probes | this analysis |

## ATT&CK

| ID | Technique | How PLOTSAFE does it |
|---|---|---|
| T1027 | Obfuscated Files or Information | Permutation-table literals, Caesar-shifted strings, Ascii85 tables |
| T1027.007 | Dynamic API Resolution | SHA-1 of export names (loader), 31-multiplier hash (shellcode) |
| T1140 | Deobfuscate/Decode Files or Information | Kyber-512 + AES-256-GCM payload, XOR + aPLib inner PE |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Host and user blocklists, CPU, RAM, display and decoder checks, Defender emulator exports |
| T1497.003 | Virtualization/Sandbox Evasion: Time Based Evasion | Uptime below 12 minutes from `KUSER_SHARED_DATA` |
| T1622 | Debugger Evasion | Debug port/object/flags, `NtGlobalFlag`, heap flags, `ThreadHideFromDebugger` |
| T1106 | Native API | `Nt*` memory functions for the injection |
| T1055 | Process Injection | Shellcode into suspended `OpenWith.exe`, entry-point `mov eax; jmp eax` |
| T1564.003 | Hidden Window | `GetConsoleWindow` and `ShowWindow` |

## Ending

PLOTSAFE spends a key exchange, a salt table and 23 checks on making sure a sandbox decrypts garbage, and then a single `Sum(b)` call reduces the salt lottery to the letter `s`. The checks are the part to remember: they don't branch, so there is no jump to patch, only a key that comes out wrong. For defenders the dependable moment is later, when a 64-bit process writes 100 KB and a `jmp eax` into a 32-bit `OpenWith.exe` it just started suspended.

## Credits and further reading

- Ryan Fetterman, Cisco Talos: [Ignore all instructions and read this blog](https://blog.talosintelligence.com/ignore-all-instructions-and-read-this-blog-the-state-of-ai-analysis-evasion-in-malware/) and the [PLOTSAFE family notes](https://github.com/Cisco-Talos/Cognitive-Artifact-Intelligence-Research-Network/blob/main/docs/families/PLOTSAFE.md), which identified the family, the permutation tables and the sandbox C2s.
- Proofpoint (Jeremy Hedges, Tommy Madjar): [Amatera Stealer: Rebranded ACR Stealer With Improved Evasion, Sophistication](https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication), for the AFD/NTSockets detail.
- Mario Micucci, ESET: [Amatera: How the prolific infostealer works and spreads](https://www.welivesecurity.com/en/malware/amatera-how-prolific-infostealer-works-spreads/).
- Tools I tried: Mandiant's [GoStringUngarbler](https://github.com/mandiant/gostringungarbler) and Volexity's [donut-decryptor](https://github.com/volexity/donut-decryptor); neither applied here, which was informative in itself. Cloudflare's [circl](https://github.com/cloudflare/circl) for the KEM interface.
