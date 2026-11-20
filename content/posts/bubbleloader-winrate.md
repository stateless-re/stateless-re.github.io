---
title: "BubbleLoader's 24 samples carry one stealer, its downloader, or a stub that only exits"
date: 2026-11-20T18:04:34+00:00
slug: "bubbleloader-winrate"
description: "Every BubbleLoader host ReversingLabs listed delivers WinRateStealer, its downloader or an exit stub. The stealer quits without a 31-character argument."
tags: ["bubbleloader", "winrate", "stealer", "loader", "packer", "windows"]
sample:
  family: "BubbleLoader (WinRate payloads)"
  sha256: "4987af027009d572c26f6d009c5e53e237cb2e3ab9d52094c14dc0b8b6f40b14"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/4987af027009d572c26f6d009c5e53e237cb2e3ab9d52094c14dc0b8b6f40b14)"
scope: medium
toc: true
---

BubbleLoader hides a payload in two PNGs added to a real program, such as WinRAR's command-line `rar.exe` or a Windows Media Player helper, and rewrites the program's entry point to unpack it. ReversingLabs wrote that the final payload "is variable depending on the malware family being distributed in a particular sample". In the 24 samples they listed, it is always one of three things: a stealer that names itself WinRate, its downloader, or a 1,536-byte program that only exits.

None of the three steals anything when the patched program starts without arguments. The stealer returns at once unless it gets exactly one argument of at least 31 characters. The downloader exits with code 63 when it gets none, but any argument will do, and some of its hosts, such as `wmplayer.exe`, normally get one. The stub always exits with code 63.

All 24 hashes were on Hybrid Analysis and none on MalwareBazaar. Sources:

- Robert Simmons (ReversingLabs), [Threat Researcher's Notebook: BubbleLoader](https://www.reversinglabs.com/blog/threat-researchers-notebook-bubbleloader), 2026-11-17: the entry-point patch, the PNG pair, the stage-3 loader and its padding rewrite, and the 24 hashes.
- Microsoft Defender's `Trojan:Win64/Dacic.KK!MTB` signature already includes the string `WinRateStealer`, as published in [mthcht's export of Defender's rules](https://github.com/mthcht/awesome-lists/blob/main/Lists/Others/Defender_yara_rules/Win64/Trojan/Dacic.yara). I found no write-up of the family.

## What I found

- The 24 hosts deliver five PEs: two WinRateStealer builds (8 hosts), one WinRateLoader (9) and two exit stubs (7). The stealer and loader share four C2 domains.
- The key PNG sits among up to nine decoys from the same red-to-blue gradient generator. Only the carrier has bytes after `IEND`.
- ReversingLabs' walkthrough sample checks nothing before it unpacks. Ten other builds check uptime and CPU count first, and three of them also check for a debugger and recent user input.
- The loader's embedded reflective loader sets `WR_UNIQUE_KEY` and calls `SecurityCoreInit`, the stealer's own export.

![Chain from a patched host through BubbleLoader's three stages to three payloads and four C2 domains](/img/bubbleloader-winrate/chain.svg "One BubbleLoader host, three possible payloads")

Every host runs the same stages (two builds add a wrapper layer); only the payload differs. The dashed edge is inferred, because I don't have what the loader downloads.

## The key PNG hides among gradients

The patched `rar.exe` in 07784d65 has six PNG resources, all vertical red-to-blue gradients a few thousand pixels on a side:

![Six PNG resources from one patched rar.exe, all red-to-blue gradients of different sizes; PNG 882 is 659,194 bytes, the others 10 to 42 KB](/img/bubbleloader-winrate/png-resources.png "The PNG resources of 07784d65. PNG 882 carries the payload.")

PNG 882 is the carrier. Its image ends at byte 22,095, and the remaining 637,099 bytes are the fake PNG ReversingLabs described, with the stage-2 code at its tail.

The hosts carry 1 to 10 PNG resources, 146 in all, and every one is a valid gradient with a pure red top row and a pure blue bottom row. Firefox, WinRAR and Windows Media Player don't share artwork, so I take it the builder added them all.

In every host, the carrier is the lowest-numbered PNG and the only one with data after `IEND`. The entry-point patch copies exactly that resource: in 4987af02, `lea rsi, [rbx+0x360d8]` and a length of 0xa6413, PNG 795's offset and size.

## Stage 2 XORs with the whole key PNG

Stage 2 is the last 0xdb bytes of the carrier in the simplest builds. Here it is in 4987af02, offsets relative to the copied resource, junk branches removed:

```asm {title="4987af02 stage 2, opaque predicates removed"}
0xa6358  mov rcx, rbx
0xa635b  add rcx, 0x360d8           ; (1) key: start of the key PNG
0xa6362  mov rdx, rbx
0xa6365  add rdx, 0x360d8
0xa636c  add rdx, 0xaba6            ; (2) data: right after the key PNG
0xa6384  add r8, 0x9b792            ; (3) end of the encrypted region
0xa639c  cmp rcx, r10               ; r10 = start of the data
0xa639f  cmove rcx, r9              ; (4) key pointer wraps to the PNG start
0xa63b0  movzx rax, byte ptr [rcx]
0xa63c1  xor byte ptr [rdx], al
...
0xa63dd  add rbx, 0x40c8e
0xa63e4  call rbx                   ; stage 3, 16 bytes into the fake PNG
```

The key (1) is the entire key PNG, 0xaba6 (43,942) bytes here. The data (2) is the fake PNG that follows it, and (3) is the length decrypted. As a formula, with `K` the key PNG:

```text
stage3[i] = fake[i] ^ K[i % len(K)]
```

My first reading was wrong. I missed the `cmove` at (4) and read the loop as an autokey cipher, with the key running on into freshly decrypted bytes. The first 43,942 bytes come out the same either way, and the stage-3 code sits inside them. The payload after them was noise until I saw the wrap.

Key PNGs in the set run from 9,505 to 46,194 bytes. Two builds, aa71f94a and fd00db1f, add a layer: stage 2 first XORs the rest of itself with nine bytes stored between a `jmp` and its target.

## Stage 3 keeps its key behind a call

Stage 3 decrypts the payload with a second XOR key, nine bytes long. The key sits inline: a `call` jumps over it, and the next instruction pops its address.

```asm {title="4987af02 stage 3"}
0xde   call 0xec                    ; (1) pushes 0xe3, the key's address
0xe3   db "XvBvLCIGu"               ; (2) the key
0xec   pop rcx
0xed   mov r9, rcx
0xf0   lea r10, [rip - 0xb]         ; (3) key end = 0xec
0xf7   lea rdx, [rip + 0x494]       ; payload start, 0x592
0xfe   lea r8, [rip + 0x9b68d]      ; payload end, 0x9b792
```

All 24 builds have different keys, each nine characters from `[A-Za-z0-9]`. Some spell the `pop rcx` as `add rsp, 8; mov rcx, [rsp-8]; push rcx; pop r9`, but the `lea r10` at (3) always points at the byte after the key, so the unpacker anchors on it.

Stage 3 then rewrites the payload's `CC` padding with `rdtsc` bytes as it decrypts, as ReversingLabs described. The XOR keys are fixed, so decrypting statically gives the payload as packed, before any padding changes. For 4987af02 that is `a713022b…`.

### Which padding bytes change

The padding check reads the eight bytes at `rdx-9` to `rdx-2` and the byte at `rdx`, but writes `rdx-8` through `rdx`:

```asm {title="4987af02 stage 3, the padding check"}
0x131  mov rax, 0xcccccccccccccccc
0x13b  cmp qword ptr [rdx - 9], rax   ; (1) rdx-9 .. rdx-2
0x141  cmp byte ptr [rdx], 0xcc       ; (2) rdx
0x14d  rdtsc
0x151  mov byte ptr [rdx + r12], al   ; (3) r12 = 0, -1, ... -8
```

The byte at `rdx-1` is never checked, so a one-byte `ret` function between padding runs looked at risk. My first emulation said it was destroyed. That was an artifact: I had made `rdtsc` return `0xCC`, so randomized bytes still looked like padding to the next check.

With random bytes that don't happen to be `0xCC`, a non-`CC` byte is overwritten only when exactly 8 or 9 `CC` bytes precede it and a `CC` follows. A simulation of the loop confirmed the rule, and no payload in the set has that pattern. Under the same assumption, the rewrite changes 4,493 bytes of the September stealer and 4,494 of the October one, all `CC`, and none in the loader or the stubs.

## Ten builds check the machine first

ReversingLabs' walkthrough sample, 4987af02, runs straight through. Eleven of the other builds call `Sleep(45000)` in the entry-point patch, and ten of those also gate stage 2 on the machine:

| Check | Value | Builds |
|---|---|---|
| `rdtsc` at least | 0x1d1a94a2000 (2,000,000,000,000) | 10 |
| `PEB.NumberOfProcessors` at least | 2 or 4 | 10 (5 need 4) |
| Two back-to-back `rdtsc` reads less than | 400,000,000 cycles apart | 5 |
| Busy-wait on `rdtsc` for | 4,000,000,000 or 12,000,000,000 cycles | 5 |
| `KUSER_SHARED_DATA` InterruptTime at least | 3,600,000,000 or 9,000,000,000 (360 or 900 s) | 5 |
| `PEB.BeingDebugged` is 0 | | 3 |
| `GetLastInputInfo` reports input since boot | | 3 |

A failed check returns from stage 2 and the process ends. At 3 GHz, the first threshold is about 11 minutes of uptime. The `GetLastInputInfo` builds decode their API names with XOR 0xAA and walk the kernel32 and user32 export tables themselves.

## What the 24 hosts deliver

| Payload | Size | PE timestamp (UTC) | Hosts |
|---|---|---|---|
| WinRateStealer `a713022b…` | 635,392 | 2026-09-23 15:11 | 7 |
| WinRateStealer `b2304c30…` | 648,192 | 2026-10-12 10:47 | 1 |
| WinRateLoader `dface52a…` | 13,824 | 2026-10-06 13:18 | 9 |
| Exit stub `c38bb7a3…` (GUI) | 1,536 | 2026-10-08 10:59 | 6 |
| Exit stub `a9d01d75…` (console) | 1,536 | 2026-10-08 10:59 | 1 |

Besides the hosts ReversingLabs named, the set includes Firefox's `maintenanceservice.exe`, `ieinstal.exe`, and the Spice guest tools' `vdservice.exe` and `vdagent.exe`. None has a valid signature. In nine, the security directory points into the enlarged `.rsrc`, while the vendor's certificate blob sits in the overlay.

### WinRateStealer

The stealer is MSVC C++ with nlohmann JSON. Its export directory names it `WinRateStealer.exe`, and its one export is `SecurityCoreInit`. It targets Chromium and Gecko browsers, wallet extensions and desktop wallets, Steam, Telegram and Discord.

For Chrome's app-bound encryption, it starts the browser with `--remote-debugging-port=9222` and attaches as a debugger. The October build adds labels such as `stage:ab-xref-ok` and `stage:ab-bp-set`. I think it breaks on the code that references `OSCrypt.AppBoundProvider.Decrypt.ResultCode` to read the key; the labels suggest that, but I didn't trace it.

The C2 conversation is JSON over `POST /` to the first of the four C2s (HTTPS, port 443) that answers `InternetCheckConnectionA`, with a stock Chrome 131 user agent:

```text
{"type":"create", "build":"SecurityUpdater", "hwid":"<hwid>"}
{"type":"info", ...}          then file uploads, then
{"type":"done","status":"done"}
```

The `create` reply carries an `access_token` that the later requests use. Before any of that, `main` checks its arguments:

```asm {title="a713022b main, 0x14003a0a1"}
0x14003a0a1  cmp ecx, 2              ; (1) argc == 2
0x14003a0a4  jne 0x14003b2f0
0x14003a0aa  mov rcx, qword ptr [rdx + 8]
0x14003a0ae  call 0x14006d720        ; strlen(argv[1])
0x14003a0b3  cmp rax, 0x1f           ; (2) at least 31 characters
0x14003a0b7  jb 0x14003b2f0          ; 0x14003b2f0: return 0
```

Both builds have the check. BubbleLoader maps the EXE into the host process, so `argc` and `argv` come from the host's command line. Someone who double-clicks the patched `rar.exe` gets `argc == 1`, and the stealer returns 0 before it reads anything.

The DLL path works differently. `SecurityCoreInit` reads the environment variable `WR_UNIQUE_KEY`. If that is missing or shorter than 31 characters, it makes up 32 random characters from `[a-z0-9]`, then calls `main(2, {"WinRateStealer", key})`.

### WinRateLoader

The loader is 13,824 bytes of C, and its usage line explains the argument: `usage: wrloader.exe <unique_key>`. With no argument it prints that and calls `ExitProcess(0x3f)`, which is exit code 63. With any argument, it does the following:

1. `POST`s the 21-byte body `LeyJ0eXBlIjoienp6In0=` to `/security/updater` on each C2 in turn. After the `L`, that is Base64 for `{"type":"zzz"}`.
2. RC4-decrypts everything after the marker `endico` in the reply, with the 256-character key below.
3. Requires `MZ` and copies the result next to a 5,120-byte embedded DLL, `rdi.dll`.
4. Starts a thread at `rdi.dll`'s `RdiEntry` export.

```text {title="RC4 key"}
vpjNm4FDCr82AtUfhe39EG5JLwuZszKPyTcXWVMHYnRgBkSQqxzBfb6m75HZV3UyRY8vPxDna4WC2KMAgJjQqukrFdELXeGNSws9SBFXnYJ6ExMyu97KCebD5mTwaUj42NPAvHdkGhVtczWgfrZ3sLyRZg4HuX97AnQtK8xvpLU2CWDhVq5PEfjTNz36wdFasecBrkGSDApf83d6NMyaJCsvcRBq9ZYKthjuw5S27EVzWrPHgkmUxFL4bQSgMa4F
```

It gives up after 10 rounds, 300 seconds apart. `rdi.dll` builds `WR_UNIQUE_KEY` on the stack, sets it to the loader's argument with `SetEnvironmentVariableA` and calls the mapped PE's `SecurityCoreInit`. So the loader expects to download the stealer's DLL form.

### The exit stub

The two stubs are the same 15 bytes of code, `sub rsp, 0x28; mov ecx, 0x3f; call [ExitProcess]`, and differ only in the PE subsystem field. Their exit code is the loader's no-argument exit code. I can't tell whether that is deliberate. Seven of the 24 hosts carry one, including four of the builds with machine checks.

## The unpacker

[families/bubbleloader](https://github.com/stateless-re/tools/tree/main/families/bubbleloader) follows the entry-point patch, decrypts both stages and writes the payload with `-o`. It reports the carrier resource, the Sleep, every stage-2 check it recognises, and the payload's export name and URLs.

Its results match a Unicorn emulation of all three stages on all 24 samples: same payload hashes, same carrier offsets, and the same stage-3 keys in 22 cases. The two exceptions are the wrapped builds, where my emulator mistook the wrapper for stage 3 and recovered no key; the payloads still match.

## What I couldn't determine

- What starts the stealer hosts with a 31-character argument. ReversingLabs doesn't describe the delivery route either, and nothing in these files launches them.
- What the C2s return. I have no `endico` response, so the DLL the loader fetches is inferred from `rdi.dll`.
- Whether the gate parameters are builder options or versions. The payloads don't sort by gate level: the September stealer appears in both an ungated host and a five-check host.

## Indicators

| SHA-256 | Role |
|---|---|
| `a713022bcd5551e78a8ddc0263b5e2557d3942b176268fa297c59ad8577b4809` | WinRateStealer EXE, Sept 23 build |
| `b2304c308717acc27ab01671b7bfdd6dc5f5c33b1490ffd2f368b6ac4db31156` | WinRateStealer EXE, Oct 12 build |
| `dface52ab8420d2f4c57d99943ba38585fdc4cd4c70f9d84276f701bfbdd34d7` | WinRateLoader |
| `c38bb7a3abe46f2b160bbfa536d2cde39da0e8f3bc6152562a1f456a49861ecc` | Exit-63 stub, GUI subsystem |
| `a9d01d75bcfb8519d2cb6f9cd3f299e84e8fdfdd0c447c6faef37cd0b4ff8ce8` | Exit-63 stub, console subsystem |

The 24 BubbleLoader hosts are in ReversingLabs' report. This table maps each one to its payload:

| Host (prefix) | Program | Gates | Payload |
|---|---|---|---|
| `053066c7` | maintenanceservice.exe | none | loader |
| `07784d65` | rar.exe | none | stealer (Sept) |
| `08c98eb0` | desktop-launcher.exe | Sleep, TSC, 2 CPUs | stub |
| `17a34146` | wmpshare.exe | Sleep, TSC, 2 CPUs | stub |
| `184f90da` | unrar.exe | none | stealer (Oct) |
| `1e61e184` | rar.exe | none | stealer (Sept) |
| `3bde84b2` | desktop-launcher.exe | none | loader |
| `4987af02` | vdservice.exe | none | stealer (Sept) |
| `70ece0d8` | wmpshare.exe | Sleep, TSC, 4 CPUs, spin | loader |
| `776e778d` | virtiofs.exe | Sleep, TSC, 4 CPUs, spin | stealer (Sept) |
| `8e01f550` | x64dbg.exe | Sleep, TSC, 2 CPUs | loader |
| `a347e678` | rar.exe | none | stealer (Sept) |
| `aa71f94a` | wmpshare.exe | every check, wrapped | loader |
| `ad70a492` | virtiofs.exe | Sleep, TSC, 2 CPUs | stub (console) |
| `c0974e32` | virtiofs.exe | none | stealer (Sept) |
| `ce86d243` | vdservice.exe | none | stealer (Sept) |
| `d14c71d9` | loaddll.exe | none | loader |
| `d5c8c4e5` | ieinstal.exe | none | stub |
| `da84d6ea` | desktop-launcher.exe | Sleep, TSC, 2 CPUs | stub |
| `df11dd7b` | vdagent.exe | none | loader |
| `e39a78e4` | wmplayer.exe | every check | loader |
| `e4b6699c` | wmpshare.exe | Sleep only | stub |
| `f8889199` | desktop-launcher.exe | none | stub |
| `fd00db1f` | desktop-launcher.exe | every check, wrapped | loader |

"Spin" is the busy-wait with its TSC gap and InterruptTime checks. "Wrapped" is the extra stage-2 layer.

| Network indicator | Role |
|---|---|
| `popularcommunitypic[.]com:443` | stealer and loader C2 |
| `topdiscountonline[.]com:443` | stealer and loader C2 |
| `youmustviewitnow[.]com:443` | stealer and loader C2 |
| `yourworknewspapper[.]com:443` | stealer and loader C2 |
| `/security/updater` | loader path, body `LeyJ0eXBlIjoienp6In0=` |
| `WinRateLoader` | loader's WinINet user agent |

Host-side strings: `WR_UNIQUE_KEY`, `WRL_LOG`, `endico`, `SecurityCoreInit`, `RdiEntry`, `rdi.dll`.

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1036.005 | Match Legitimate Name or Location | real WinRAR, Firefox, WMP, x64dbg, Spice, virtiofs binaries |
| T1027.003 | Steganography | payload appended to a PNG resource among gradient decoys |
| T1140 | Deobfuscate/Decode Files or Information | PNG-keyed XOR, nine-character XOR, RC4 |
| T1620 | Reflective Code Loading | stage 3 and `rdi.dll` map PEs in memory |
| T1480 | Execution Guardrails | stealer needs one argument of 31+ characters, loader needs any argument |
| T1497.001 | System Checks | TSC, CPU count, InterruptTime, `BeingDebugged` |
| T1497.002 | User Activity Based Checks | `GetLastInputInfo` |
| T1497.003 | Time Based Evasion | `Sleep(45000)` and the TSC busy-wait |
| T1555.003 | Credentials from Web Browsers | Chromium and Gecko grabbers |
| T1071.001 | Web Protocols | JSON over HTTPS `POST` |
| T1105 | Ingress Tool Transfer | loader's RC4 download |

ReversingLabs' recommendations already cover the hosts: an altered entry point and a missing signature. To those I'd add a `PNG` resource type in a program that never had one, a security directory pointing into `.rsrc`, and a WinINet user agent of `WinRateLoader`. The more useful detail for responders is what the payloads wait for. A patched `rar.exe` started without arguments does nothing, so a stealer infection means something started it with a long one. A patched `wmplayer.exe` opening a media file is enough for the downloader.

Thanks to Robert Simmons and ReversingLabs for the report and the hash list.
