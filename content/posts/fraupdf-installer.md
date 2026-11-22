---
title: "FrauPDF's installer checks its own file name before it asks for a payload"
date: 2026-11-14T11:48:39+00:00
slug: "fraupdf-installer"
description: "FrauPDF's signed .NET installer checks security products, its own file name and a server's digit-parity answer before it maps three DLLs in memory."
tags: ["fraupdf", "dotnet", "loader", "malvertising-lure", "string-decryption", "config-extraction", "windows"]
sample:
  family: "FrauPDF installer (unnamed)"
  sha256: "ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0/)"
scope: medium
toc: true
---

`AppPDF_593771.exe` installs a real PDF and EPUB reader called FrauPDF, but before it does, it decides whether the machine deserves something else. It quits on sight of ESET, Kaspersky, Sandboxie or Frida, keeps going only if its own file name still ends in something like `_593771`, and then asks `thepdfsoftsetup[.]com` for a number.

If the digits of the answer add up to a non-zero even sum, it downloads a blob and maps a 32-bit DLL from it in memory. That DLL produces a second DLL, which produces a third. When the server says no, or the file has been renamed, it installs the reader and nothing else.

The file was the newest entry under MalwareBazaar's `Dotnet` tag on November 14, 2026. The submitter tagged it `TamperedChef`; none of the vendor entries on the page names a family, and ReversingLabs counts 1 of 36 scanners. I found no public write-up for FrauPDF, "The PDF Soft" or the domain.

## What I found

- The installer's strings sit behind a per-byte XOR and a Babel-style encrypted resource that neither NETReactorSlayer nor de4dot decodes. All 241 strings decode.
- The four C2 URLs use one host and fake version parameters whose values are slices of a hard-coded 16-hex token, one token per step.
- The `uid` sent with the download encodes a bitmask of the security products running on the host, XOR'd so the server can undo it.
- The installer XORs only the first quarter of the downloaded blob with a fixed shift-register keystream, and finds a DLL at offset 68.
- That DLL's `cx1` export makes a second DLL, whose `ac` export makes a third, whose `dc` export runs. The parameter names survive in metadata.

## Triage: a signed setup with a broken signature

| Field | Value |
|---|---|
| SHA-256 | `ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0` |
| Type | PE32 .NET Framework 4.8 GUI, 2,820,232 bytes, CLR flags `0x3` (IL only, 32-bit required) |
| Protector (DIE) | .NET Reactor 6.x, control flow and anti-ILDASM |
| Version info | `FrauPDF Setup` 6.4.2.8, "The PDF Soft", `FrauPDF.Inst.exe` |
| PE timestamp | 2026-11-03 10:28:08 UTC |
| Authenticode | GlobalSign EV code signing, leaf serial `5231870f44396fa132602d23`, valid 2026-06-15 to 2027-06-16 |

The certificate was issued to a Wyoming-registered LLC, and it doesn't cover this file. LIEF reports `BAD_DIGEST|BAD_SIGNATURE`: the file's Authenticode hash is `5835f713…` while the signed digest is `9c8376e3…`. I'm not naming the company: the certificate says who bought it, not who wrote the code.

Two manifest resources stand out. `FrauPDF.Inst.x0pack` is a plain ZIP holding one `fraupdf.exe`, and `FrauPDF.Inst.r0bin` is a plain .NET PE. A third, called `oNNFP`, 2,659 bytes long, looks like noise.

## The reader is real

`fraupdf.exe` (3,831,808 bytes, x64) is a Tauri 2 application: Rust with WebView2, and UI text like "This preview opens PDF and EPUB files." I found no host of its own in it. `r0bin` is `FrauPDF.Remove.exe`, an uninstaller the installer writes as `Uninstall.exe`.

So the installer does install a working reader into `%LOCALAPPDATA%\Programs\FrauPDF\`, with shortcuts and an uninstall entry. That is the decoy, and on most paths it is the only thing that happens.

## Getting the strings back

NETReactorSlayer flattened most of the control flow back into readable C#, resolved 4,989 constant expressions and then reported "Couldn't find any encrypted string." I took that at face value for a while.

Then `Main`'s crash handler wrote its log to `Path.Combine(GetTempPath(), Class104.smethod_0(21906))`, and `Class104` was not in the decompiled project at all. ILSpy's project export had silently skipped about 50 types, including the one that matters.

There are two string schemes. The simple one covers 30 strings, the User-Agent and an export name. Each is a fixed-size blob in `<PrivateImplementationDetails>`:

```text
out[i] = blob[i] ^ ((i * 37 + 107) & 0xFF)
```

That gives `FrauPDF.Inst.x0pack`, `Mozilla/5.0`, `cx1`, and status lines like "Srarting setup..." (the typo is theirs).

The other scheme is a string table, and the code that reads it is built at run time. `Class104`'s static constructor opens `oNNFP`, unwraps it with `Class106.smethod_0`, and emits a method with Reflection.Emit that reads the strings into a `Hashtable`. Every `Class104.smethod_0(id)` is a lookup in that table. The emitted code sets the XOR key to 0 when the entry assembly's name contains a tool name such as `SimpleAssemblyExplorer` or `babelvm`, so those tools get the wrong strings.

`Class106` XORs a 37-byte header with the 4 bytes after it (`15 ef 63 31`). The header holds a license string (`lic529D59AB`), flags, and a DES key and IV (`610099aa55b1e0aa`, `02b4b9b9b8d26bac`). The 2,616-byte body is DES-CBC, then compressed.

The decompressor (`Class112`) looks a lot like de4dot's `BabelInflater`: a 4-bit block header and stored-block lengths XORed with a magic value. This one uses different numbers: type 3 is stored, 2 is fixed Huffman, 4 is dynamic, and the magic is `0xF112`. I think this is a Babel-family protection in a build de4dot doesn't know, layered under .NET Reactor. That's an inference from the shared design.

My first inflater died on the second back-reference. I suspected another format tweak and went back into `Class107`'s tables, which were standard. My distance extra-bits array wasn't: I'd written `i // 2` where Deflate needs `i // 2 - 1`. With that fixed, the body inflates to 241 strings, and every `Class104.smethod_0(n)` resolves:

```text
23469  thepdfsoftsetup.com
23638  &p5el=b0663
23594  664dc44ca345a5c2
20507  \AppData\Local\Programs\FrauPDF\
21211  Image host requires a 32-bit process.
20942  Failed to apply base relocations (delta=0x{0:X8}).
```

The left column is the ID the code passes. The last two lines are the first sign of an in-memory PE loader in what claims to be a setup program.

## Four checks before any download

`Main` hands control to a six-step pipeline (`Class59`). ILSpy produced an empty file for that class, so this section comes from IL:

![Decision flow: a security-product match exits; a renamed file or a gate reply whose digit sum is odd, zero or an error installs the decoy reader; otherwise the installer downloads the blob and maps three DLLs](/img/fraupdf-installer/gates.svg "The installer's decisions, in order")

Only the solid path reaches a payload. Every dashed exit installs the reader, so a sandbox that renames the file sees a clean install.

Here is the file name check (`Class57`), rewritten from the IL:

```python
name = strip_suffix(file_name, ".exe")
name = strip_browser_copy_suffix(name)     # "AppPDF_593771 (1)" -> "AppPDF_593771"
if len(name) < 5: return False
run = count_trailing(name, str.isalnum)    # ASCII letters and digits
if not 3 <= run <= 8: return False
return name[-run - 1] in "_-"
```

`AppPDF_593771` passes, and so does a browser's `AppPDF_593771 (1)`. A sandbox that renames the file to its hash or to `sample.exe` fails. I think the number is a per-download ID stamped by the distribution site, because the installer never parses the value.

The token check (`Class52.smethod_8`) looked different in the decompiler than in the IL. The C# read as if any non-digit made it fail. The IL skips non-digits, adds up the digits, fails on a sum of zero, and otherwise passes when the sum is even. The server decides which downloads get a payload, and its answer says so without a recognizable word in it.

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

The values are slices of a constant: the gate token `664dc44ca345a5c2` becomes `ver=664d&chan=c44&lang=ca3&arch=45a&build=5c2`. Only the download request carries `uid` (1). The full URLs are in the indicators.

| Step | Token | Use |
|---|---|---|
| Gate | `664dc44ca345a5c2` | reply is the parity token |
| Beacon | `c0a188a0367d1958` | sent once; if it fails, the installer exits |
| Download | `1e627e8ceed85007` | the payload blob; up to 4 tries |
| Finish | `699ba4b1d99e33f3` | sent after 4 failed tries; the installer then exits |

A failed beacon or four failed downloads end the run with `ExitProcess`, so on those paths nothing gets installed at all, not even the reader.

## The uid is an antivirus report

`Class50` builds the `uid`:

```text
prefix  = first4(hex(GetTickCount() ^ ProcessId))
mask    = pad4(hex(weight))                       # weight from the product bitmask
uid     = prefix + hexdigit(mask[i] ^ token[i] ^ token[i+7] ^ prefix[i]) for i in 0..3
```

`token` is the download token. The server knows it and receives the prefix, so it can XOR both back out and read `weight`, a 14-bit field where bit *k* of the product bitmask adds `0x8000 >> k`.

The bitmask comes from hashing every process, service and module name with 32-bit FNV-1a (lower-cased, XOR'd with `0xC6E39BD8`). I matched the tables against a list of 716 security, analysis and VM tool names, which resolved 62 of the 199 distinct hashes:

| Bit | Names that matched | Effect |
|---|---|---|
| 0 | Norton | reported |
| 1 | ESET | exit |
| 2 | Bitdefender, Ad-Aware, Emsisoft, F-Secure, G DATA, Tencent | reported |
| 5 | Webroot | reported |
| 6 | Malwarebytes | reported |
| 7 | Microsoft Defender | reported |
| 8 | McAfee | reported |
| 9, 11 | none matched | reported |
| 10 | Avast and AVG | reported |
| 12 | `python.exe`, `pythonw.exe` | reported |
| 13 | Kaspersky, Sandboxie, `analyzer.exe` | exit |

Bits 1 and 13 are masked off before the weight is computed, since the installer has already exited on those products. Other tables feed only the exit check: Kaspersky services and the in-process modules `sbiedll.dll` and `frida-agent.dll`.

The Python entry is the odd one in a list of antivirus products. I think it marks analysis machines, since Python processes are rare on the home PCs a fake PDF reader targets.

## The blob: a quarter, an LFSR and a constant that cancels

If the download returns something, `Class31` unwraps it. The decompiled C# had `num3 = num2 / 4`, which I first took for decompiler noise. The IL has `ldc.i4.4; div`. Rewritten from the IL:

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

`lfsr_xor` (`Class22`) is a 32-bit shift register starting at `0x95000000`, with feedback from bits 18 and 17, XORed into the data bit by bit. Every call starts from the same seed, so it is a fixed keystream. That makes (2) busywork: the 32-byte constant gets XOR'd with the keystream and then XOR'd back.

## Three DLLs, mapped in memory

`Class17` is a MemoryModule-style PE mapper for 32-bit DLLs (hence the 32-bit-required CLR flag). `Class26` drives the chain through cdecl function pointers, and the parameter names are the developer's own, preserved in the metadata:

```csharp
// Class23: export signatures, names as in the Param table
int cx1(byte* blob, uint blobLen, byte** out, uint* outLen);
int ac (byte* blob, uint blobLen, char16* filepath, byte** out, uint* outLen,
        byte* serverResponse /*1024*/, byte* sslNumber /*1024*/,
        char16* secretCount, HWND bannerHwnd, char16* strWrapperClass);
int dc (char16* wrapperPath, byte* serverResp, byte* sslNumber, HWND bannerWnd,
        char16* secretCount, HWND bannerHwnd, char16* wrapperId);
```

Stage 1 gets the full blob and returns stage 2. Stage 2's `ac` gets the blob again, the installer's path, two empty 1,024-byte buffers, a fake progress window and `FrauPDF;PDF;\AppData\Local\Programs\FrauPDF\;/S`, and returns stage 3. Stage 3's `dc` gets the filled buffers and the same descriptor.

`secretCount` is not a count: it is 99 characters of `GetTickCount()` digits interleaved with xorshift32 output. The descriptor looks like what a later stage would need to relaunch the "wrapper" quietly, with `/S` as the silent switch. That reading is a guess from the names; I don't have the stages.

While this runs, the user sees a borderless window that says "Starting FrauPDF...". If a stage fails, the installer usually falls back to installing the reader. It exits instead when a new top-level window appeared during the chain, or when HTTP Debugger is running.

## What I couldn't determine

The server's half. Stages 1 to 3 exist only in the reply to the download URL, so I don't know what `cx1`, `ac` and `dc` do, or what the other three quarters of the blob hold. I also can't say what the gate server answers for which visitors.

137 of the 199 distinct hashes didn't match my name list, including all of bits 9 and 11.

Attribution: `TamperedChef` is the submitter's label. Unit 42's [TamperedChef cluster write-up](https://unit42.paloaltonetworks.com/tracking-tampered-chef-clusters/) describes the same kind of business: fake PDF and productivity tools signed with certificates obtained through shell companies. It names no FrauPDF or this domain, and the packaging it describes is different. I don't have enough to tie this sample to it.

## The extractor

The [extractor](https://github.com/stateless-re/tools/tree/main/samples/ecaa3ca51c1e) prints the decoded strings, rebuilt URLs and embedded files for this installer. It also decrypts a captured download blob into stage 1 (`--blob`), decodes a `uid` into product names (`--uid`), and checks a name list against the hash tables (`--names`).

## Indicators

| SHA-256 | Role |
|---|---|
| `ecaa3ca51c1e9ec0f81a167909999af9f808515e3c35587955e61c228939aeb0` | `AppPDF_593771.exe`, FrauPDF installer (.NET) |
| `de7ccf3e05aa70279da9996d414256f8bdac4a61627d73bf29e82ec26c09f33f` | `FrauPDF.Inst.x0pack` resource (ZIP) |
| `117b4f462ca1ca18b206136c63dc03a2a8af07c3c6c0271c3029f9362a524e70` | `fraupdf.exe`, decoy Tauri PDF/EPUB reader (x64) |
| `5d81f494cdf2fab9a9d10384bccdace2899fe73afa58d9be1b156f4930f5b87a` | `FrauPDF.Inst.r0bin`, `FrauPDF.Remove.exe` uninstaller (.NET) |

| Network indicator | Use |
|---|---|
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
| T1036.005 | Match legitimate name or location | Poses as a PDF reader setup and installs a working reader |
| T1553.002 | Code signing | Carries an EV signature that does not match the file |
| T1027 | Obfuscated files or information | XOR and DES/Deflate-variant string tables, .NET Reactor |
| T1518.001 | Security software discovery | Hashed process, service and module names; bitmask in `uid` |
| T1497 | Virtualization/sandbox evasion | Exits on Sandboxie, Frida, `analyzer.exe`; needs its file name |
| T1105 | Ingress tool transfer | Downloads the encrypted stage blob |
| T1620 | Reflective code loading | Maps three DLLs from memory with a custom PE loader |

## Ending

The installer goes to some trouble to look boring to a sandbox. It quits around the usual analysis tools, installs a real reader when renamed, and waits for a server to say yes in digits. The part it can't hide is what happens after the yes: a 32-bit setup program mapping executable code that never touched the disk. That's the behavior to alert on. The file name `AppPDF_593771.exe` is the other cheap lead, because the sample needs it to stay intact.

## Credits and further reading

- [NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) by SychicBoy did the control-flow cleanup; [de4dot](https://github.com/de4dot/de4dot)'s Babel module was the reference for the inflater comparison.
- Unit 42, Joseph Ganter: [Tracking TamperedChef Clusters via Certificate and Code Reuse](https://unit42.paloaltonetworks.com/tracking-tampered-chef-clusters/) (2026-05-20), for the business model this sample resembles.
- G DATA, Karsten Hahn and Louis Sorita: [AppSuite PDF Editor backdoor analysis](https://blog.gdatasoftware.com/2025/08/38257-appsuite-pdf-editor-backdoor-analysis), an earlier fake PDF editor with a server-controlled backdoor.
