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
scope: medium
toc: true
---

PLOTSAFE's second-generation loader decrypts its payload with an AES-256 key that passes through a Kyber-512 key decapsulation. The private key for that decapsulation is built from a 32-byte mask that 23 sandbox and debugger checks quietly corrupt. A sandbox doesn't get an early exit; it gets the wrong key, and the loader returns without a word.

The step after the key exchange is meant to choose one of 16 salts from a hash of the shared secret. But a Go `hash.Sum(b)` call appends instead of replacing, so the "random" index is the low nibble of the letter `s`: salt number 3, on every run.

Cisco Talos covered PLOTSAFE on October 8 in [a report on malware that addresses AI-assisted analysis](https://blog.talosintelligence.com/ignore-all-instructions-and-read-this-blog-the-state-of-ai-analysis-evasion-in-malware/) (Ryan Fetterman), with a longer [family write-up](https://github.com/Cisco-Talos/Cognitive-Artifact-Intelligence-Research-Network/blob/main/docs/families/PLOTSAFE.md). That work is about the decoy sentences the builds carry for language-model triage tools. It says the C2 came from sandbox runs only, and that the stealer payload was never recovered.

Both PLOTSAFE DLLs Talos lists were on Hybrid Analysis. This post follows the Gen 2 build (`2e3e1bcd…`) from its string protection to its third stage.

## What I found

- The roughly 960 string sites Talos counted hide Go standard-library strings, nothing that belongs to the loader. The loader's own strings use a per-string Caesar shift.
- Twenty-three checks each invert one byte of a 32-byte mask that feeds the Kyber-512 private key, so a hit changes the AES key.
- The salt index is the first byte of `hmac.Sum([]byte("salt-select"))`, masked with `0x0F`, which is always 3.
- The payload decrypts to x86 shellcode that unpacks a 319,488-byte PE32. Neither hash is on MalwareBazaar or Hybrid Analysis.
- The loader injects the shellcode into a suspended `OpenWith.exe`, through `Nt*` functions it resolves by SHA-1 of the export name.

![Key chain from the check mask through Kyber-512 decapsulation and the fixed salt pick to the AES key, the shellcode and the suspended OpenWith.exe](/img/plotsafe-kem-loader/chain.svg "From the mask to OpenWith.exe")

Everything below the mask depends on it, so one fired check changes the key and the payload never decrypts. The highlighted step is the one that makes the salt table pointless.

## Two layers of string hiding, and only one matters

The DLL is Go 1.25.0 built as a c-shared library (`loader_3.dll`, export `DllConfigure`). Most function names are empty and package paths are random words (`JR_ZwBDamQyI/escape.go`). That is [garble](https://github.com/burrowers/garble)'s style, so I started with Mandiant's [GoStringUngarbler](https://github.com/mandiant/gostringungarbler). It found zero strings: its epilogue patterns stop at Go 1.23.

Talos's write-up points at 808 exact 256-byte permutations in `.rdata` and calls them obfuscator key material. That is right. Each string site copies one permutation onto the stack and runs byte substitution and chained XOR over a buffer:

```asm
lea  rsi, [rip + 0x2e1ffd]      ; one of the 808 tables
call 0x180068600                ; Go duffcopy, 256 bytes to [rsp+0x1c]
...
movzx esi, byte ptr [rax + rdx] ; buffer byte
movzx esi, byte ptr [rsp + rsi + 0x1c]  ; substitute through the table
```

Rather than reimplement each variant, I emulated every function that loads a table and dumped any buffer passed to the next call. The emulator reached 952 of the 960 sites. The buffers hold time-zone names, `strconv`, `bufio` and `zlib` errors, and `debug/pe` messages. There are no URLs, domains or executable names.

I expected these sites to hide the C2; they hide the standard library. The loader's own strings are much simpler, a Caesar shift on letters that changes per string:

```asm
lea  ecx, [rdi - 0x4f]          ; c - 79
imul rcx, rdx                   ; / 26 (0x9d89d89e magic)
imul ecx, ecx, 0x1a
sub  edi, ecx                   ; c - 26 * ((c - 79) / 26)
lea  ecx, [rdi + 0x12]          ; + 18
```

`camz32.ltt` becomes `user32.dll`.

## Emulating a Go DLL with no symbols

Reading the main function statically was slow: the loader builds everything at run time and calls through Go interfaces. I emulated it instead, which needed three things the bench didn't have:

- Names for the runtime. I built a small Windows program with the same Go toolchain and matched functions by instruction sequence, which named 1,278 of the DLL's 5,029 functions.
- A Go runtime that works without being initialized: a bump allocator, and a fake `g` with an `m` and a `p` behind it in `r14` and in a mapped TLS block.
- Real PE files, because the loader reads `ntdll.dll`, `kernel32.dll` and `user32.dll` from `System32` with Go's `debug/pe`. I used Wine's builds, after zeroing their COFF symbol-table pointers: `debug/pe` read those tables 18 bytes at a time until the instruction limit.

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

There are 23 of these `not` sites, one for each mask byte from `0x00` to `0x17` except `0x0f`. What they test:

- Debuggers: `NtQueryInformationProcess` debug port, object and flags, `NtGlobalFlag` and the heap flags.
- Microsoft Defender's emulator: exports named `MpVmp32Entry`, `MpReportEventEx` and `NtControlChannel`, and the file `C:\INTERNAL\__empty`.
- Sandbox host and user names, from `HAL9TH` and `JOHN-PC` to `Peter Wilson` and `timmy`, plus `C:\Users\Public\triage_wallpaper.jpg` and a device `\\.\A3E64E55_fl`.
- Hardware, read straight from `KUSER_SHARED_DATA`: under 12 minutes of uptime, fewer than two processors, under 4 GiB of memory.
- A display-mode field and the count of Media Foundation video decoders.

Why corrupt instead of exit? Because the corruption is invisible. Patching a conditional jump in a sandbox is routine; there is no jump here. Every check runs, every path continues, and the only symptom is a decryption that fails at the end.

My first emulated run showed exactly that. Seven checks fired because of my own API models. Among them, my export lookup claimed the Defender exports existed, and my fake `KUSER_SHARED_DATA` page said zero processors and zero memory. The key that came out failed every GCM tag. Suppressing those seven inversions, and only those, produced a key that authenticated all 25 chunks.

## The key goes through Kyber-512, then loses its randomness

With the mask in hand, `0x180275a00` assembles a 1,632-byte private key from it. I didn't reverse that function; I watched its output. The loader then makes two calls through a Go interface:

| itab offset | Method (circl `kem.Scheme`, sorted) | Arguments seen |
|---|---|---|
| `+0x78` | `UnmarshalBinaryPrivateKey` | 1,632 bytes |
| `+0x20` | `Decapsulate` | private key, 768-byte ciphertext from an Ascii85 string `768:…` |

A 1,632-byte private key and a 768-byte ciphertext are the Kyber-512 sizes. I think this is Cloudflare's [circl](https://github.com/cloudflare/circl): the Gen 1 build names `github.com/cloudflare/circl/kem/kyber/kyber512` in clear, and Go's itab orders methods by name, which matches both slots. Kyber's decapsulation doesn't fail on a wrong private key. It returns a pseudorandom secret, so a corrupted mask leads straight to a well-formed, wrong key.

Next comes a step that is meant to pick a salt. The loader passes `sha256.New` and the shared secret to what looks like `crypto/hmac.New`, writes nothing to the result, and then:

```asm
mov  rbx, rax          ; slice "salt-select", len 11
mov  rax, [rsp+0xa78]  ; the HMAC
call rdx               ; hash.Hash.Sum(b)
movzx ecx, byte ptr [rax]
and  ecx, 0xf          ; index into a table of 16 salts
```

`Sum(b)` in Go appends the digest to `b` and returns the result. The first byte of the returned slice is therefore the first byte of `salt-select`, which is `s`, `0x73`, and `0x73 & 0x0F` is 3. Entry 3 of the salt table is `PQC-PE-AES256GCM`; the other 15 are random letters like `ibzhYLqmhulStAAg`. The author wrote a salt lottery and shipped a constant.

```text
key = SHA-256(shared_secret || "PQC-PE-AES256GCM")
    = 04086cb0d0e02b86795724aab3db1d5cdafd82d017307e9657f338edc1f0757b
```

## 25 GCM chunks

The 100,230 ciphertext bytes are split into chunks of 4,096 bytes, 25 in total. Each chunk has its own nonce and tag, stored as Ascii85 strings with a length prefix (`12:<*3^WE+MOR=%$mn` is a 12-byte nonce).

I took the nonces for hex at first; they decoded to the wrong length, which is what sent me to the prefix. With the derived key, all 25 chunks authenticate, and the plaintext has SHA-256 `2a30450c2fa5a2b7ad03bed87f732010e8bcdeda04b2809d3ed336e54b5e17ac`.

## The payload is 32-bit shellcode with a packed PE inside

The plaintext opens with `E8 FC 7D 01 00`, a call over 97,788 bytes of data. That is how Donut shellcode starts, so I ran Volexity's [donut-decryptor](https://github.com/volexity/donut-decryptor) on it. "Found 0 donuts." The code after the data is a 2,437-byte PE loader of its own, which resolves seven `kernel32` functions with a 31-multiplier hash:

```text
h = 0x6c6c6a62
for c in name: h = h * 31 + (c | 0x20)    # mod 2**32
```

The data block starts with the unpacked size (`0x4e000`), the packed size (`0x17d73`), a 128-byte XOR key and a flag. The data is `data[i] ^ key[i & 0x7f]`, then aPLib.

That gives a 319,488-byte PE32, SHA-256 `7503f54b0766e7257b41ca88f71940b28130c79eaa40bbdb4fe938b088147111`, with no import directory. FLOSS recovered `\Device\Afd\Endpoint` and `AfdOpenPacketXX`. Talking to the AFD driver directly is what [Proofpoint documented](https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication) for Amatera, which Proofpoint and [ESET](https://www.welivesecurity.com/en/malware/amatera-how-prolific-infostealer-works-spreads/) tie to ACR Stealer. Talos calls PLOTSAFE's payload ACRStealer, by AV label. I think stage 3 is an ACR/Amatera build, on those two strings and that label.

## Injection into a suspended OpenWith.exe

The loader doesn't run the shellcode itself; it is a 64-bit DLL and the shellcode is 32-bit. `0x18026afe0` resolves its functions by comparing `SHA-1(export name)` with hex strings, for example `NtWriteVirtualMemory` (`6caed958…`). One digest, `f3f8c92b428c063d72c361b4cda93ecfd793071d`, matches nothing Wine exports.

The calls go through objects my emulator couldn't name, so this sequence is labelled from the resolved set and the argument shapes:

1. `CreateProcessW(NULL, "C:\Windows\SysWOW64\OpenWith.exe", …, CREATE_SUSPENDED, …)`.
2. A read of the child's image base from its PEB.
3. `NtAllocateVirtualMemory` for `0x18786` bytes, `NtWriteVirtualMemory` with the shellcode, `NtProtectVirtualMemory` to `PAGE_EXECUTE_READ`.
4. A write of `B8 <addr> FF E0` (`mov eax, addr; jmp eax`) over 7 bytes at the entry point.

My emulation stops at the next call. The loader has resolved `ResumeThread`, and Talos's sandbox runs of the Gen 1 build show later activity, so I think the thread is resumed next.

Before all this, `0x18027b8e0` starts `SysWOW64\dllhost.exe` suspended. My emulated run took a branch that did nothing more with it, so I can't say what that child is for.

## Wrong turns

- GoStringUngarbler found nothing; its patterns predate Go 1.24.
- My first pass found only 720 of the string sites, because capstone's linear sweep stopped at the first bytes it couldn't decode. Walking `.pdata` found all 960.
- Wine's COFF symbol tables turned `debug/pe` into thousands of 18-byte reads.
- My first key was wrong because my own API answers tripped seven checks.
- I read the nonces as hex, then the payload as Donut. Neither held.

## What I couldn't determine

- Stage 3's configuration and C2. I stopped at FLOSS. The domains below come from Talos's sandbox runs of the Gen 1 build.
- What `0x180275a00` does with the mask; I observed its output only.
- What the `dllhost.exe` child is for, and the export behind SHA-1 `f3f8c92b…`.
- The Gen 1 build (`a42632c6…`), which I didn't decrypt. It carries a hex blob of exactly the same length and circl's Kyber-512 package, so I think it wraps the same payload.

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
| T1497.001 | Sandbox Evasion: System Checks | Host and user blocklists, CPU, RAM, display and decoder checks |
| T1497.003 | Sandbox Evasion: Time Based Evasion | Uptime below 12 minutes from `KUSER_SHARED_DATA` |
| T1622 | Debugger Evasion | Debug port/object/flags, `NtGlobalFlag`, heap flags |
| T1055 | Process Injection | Shellcode into suspended `OpenWith.exe`, entry-point `mov eax; jmp eax` |

## Ending

PLOTSAFE spends a key exchange, a salt table and 23 checks on making sure a sandbox decrypts garbage, and then a single `Sum(b)` call reduces the salt lottery to the letter `s`. The checks are the part to remember: they don't branch, so there is no jump to patch, only a key that comes out wrong. For defenders the dependable moment is later, when a 64-bit process writes 100 KB and a `jmp eax` into a 32-bit `OpenWith.exe` it just started suspended.

## Credits and further reading

- Ryan Fetterman, Cisco Talos: [Ignore all instructions and read this blog](https://blog.talosintelligence.com/ignore-all-instructions-and-read-this-blog-the-state-of-ai-analysis-evasion-in-malware/) and the [PLOTSAFE family notes](https://github.com/Cisco-Talos/Cognitive-Artifact-Intelligence-Research-Network/blob/main/docs/families/PLOTSAFE.md), which identified the family, the permutation tables and the sandbox C2s.
- Proofpoint (Jeremy Hedges, Tommy Madjar): [Amatera Stealer: Rebranded ACR Stealer With Improved Evasion, Sophistication](https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication), for the AFD/NTSockets detail.
- Mario Micucci, ESET: [Amatera: How the prolific infostealer works and spreads](https://www.welivesecurity.com/en/malware/amatera-how-prolific-infostealer-works-spreads/).
- Cloudflare's [circl](https://github.com/cloudflare/circl) for the KEM interface.
