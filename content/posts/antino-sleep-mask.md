---
title: "Antino's October sleep mask answered every access violation in the process"
date: 2026-11-14
slug: "antino-sleep-mask"
description: "Five Antino builds from MalwareBazaar, read statically: the Microsoft 365 configs that the vendor reports redacted (secrets still withheld), the sleep-mask cipher Talos left unnamed and how its handler changed during October, the Gen1 session-ID key, and the command-line mode that the Rhai engine exists for."
tags: ["antino", "uat-11587", "rust", "sleep-mask", "microsoft-graph", "config-extraction", "windows"]
sample:
  family: "Antino"
  sha256: "40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d/)"
toc: true
---

The October 14, 2025 build of Antino hides shellcode between sleeps with a keyless byte transform, `rol3((b + 0x35) ^ 0x5A)`, and undoes it from a vectored exception handler that answers every access violation in the process, wherever it happened. Three days later the handler checked the faulting address, and by October 21 the Sleep hook only fired on the shellcode's own thread. Antino is the Rust backdoor that Cisco Talos [tied to UAT-11587](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/) on September 30, and that Unit 42 [found delivered through the Falcon browser framework](https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/) on November 11. Talos describes the mask as the later builds implement it (hooked `Sleep` and `VirtualAlloc`, a handler that "confirms that the fault occurred within the tracked region") and says the hook "encrypts its contents in place" without naming the cipher. Both reports describe the `.cfg` config section; neither publishes the Microsoft 365 identifiers in it.

Five of the twelve Antino hashes in the Talos report are on MalwareBazaar. I read all five statically (Ghidra, pefile, Python; nothing was run). This post covers what the two reports left out, plus a [config extractor](https://github.com/stateless-re/tools/tree/main/families/antino) that also decodes Gen1 session IDs.

## What I found

- The five configs use two Entra ID tenants and three app registrations. The three October builds share one tenant and one app; the two January builds share a second tenant and use one app each. Their `remark` values are `gmail`, `gmail-0326-3`, `mod_sy` and null. The tenant, client and user IDs are below; the client secrets are not.
- The sleep mask is `rol3((b + 0x35) ^ 0x5A)` per byte, with no key, in the four builds whose mask code I read; the fifth carries the same constants. In the October 14 build both mask implementations (one per code path) suspend every other thread when the shellcode sleeps and decode on any access violation. The October 17 memory image already bounds-checks the fault address; the October 21 and January DLLs also tie the mask to one thread and suspend nothing. With the mask on, the `load` commands in the three builds I read leave the shellcode `PAGE_EXECUTE_READWRITE`.
- In the October standalone builds the session ID is Base64 of `pid:host:user:windows x86_64:<field>` XORed with the 5-byte key `KxWNF`. Anyone holding such a session ID can recover the host and user from it.
- The Rhai script engine in the October 14 build has one direct caller: a command-line mode, `<exe> <file> true|false <key>`, that XOR-decodes a shellcode file, runs it through a native function the engine knows as `antino`, and deletes the file. The `load_shellcode` command's restart path writes that file to `%TEMP%\tmp_XXXXXX.dat` and relaunches the current executable with those arguments.
- MalwareBazaar labels two of the five files `RustyStealer`. One of the two carries the file name `..._akira_luca-stealer_rusty-stealer.exe`.

## Five builds, two generations, three dates

Talos splits Antino into Gen1 (October 2025, no `AntinoApp` manifest, host-derived session ID) and Gen2 (December 2025 to January 2026, manifest, random UUID). Here is what MalwareBazaar has, with the PE timestamps and the PDB names (the two January builds give full paths under `D:\a\antino\antino\target\`):

| SHA-256 (prefix) | Talos label | Form | Timestamp (UTC) | PDB |
|---|---|---|---|---|
| `40e7e77a` | configured Gen1 standalone | x64 EXE | 2025-10-14 03:17 | `antino_client_template.pdb` |
| `ca14ad03` | post-unpack standalone memory image | x64 dump, UPX headers | 2025-10-17 02:39 | `antino_client_template.pdb` (string) |
| `1fadc90b` | Gen1 `slc.dll` | x64 DLL | 2025-10-21 14:47 | `slc_template.pdb` |
| `09ef7c73` | Gen2 `slc.dll` | x64 DLL | 2026-01-11 07:54 | `slc_template.pdb` (x86_64 target) |
| `0c392643` | Gen2 fake installer | x86 EXE | 2026-01-11 07:55 | `antino_client_template.pdb` (i686 target) |

The `_template` suffix fits what the files look like: each of the four PE files has a 64 KB section named `.cfg` that is almost all zero bytes, and I think a builder writes the config into it after compilation (the memory image's section table is UPX's, so it has no `.cfg` entry). Four builds were compiled on a GitHub Actions runner (`C:\Users\runneradmin\.cargo\registry\...`). The memory image `ca14ad03` was not. Its paths point to a `J:\` drive and a user profile on a developer's machine, and its Cargo registry is `rsproxy[.]cn`, the Rust mirror Talos mentions. I'm leaving the user name out.

The table also shows the first wrong assumption I made. I expected the line between the two generations to fall between October and January. For the sleep mask it falls inside October, and it isn't one line. `ca14ad03`, three days after `40e7e77a`, already has the bounds-checked handler but still suspends threads. `1fadc90b`, which Talos calls Gen1, has the January mask complete and doesn't contain, in clear text, the session key that `40e7e77a` and `ca14ad03` carry. Talos's split is by manifest and session format, which is a fair way to label builds; the code moved faster than the labels. In what follows, "the October standalone builds" means `40e7e77a` and `ca14ad03`.

## The config is plain JSON behind a two-byte XOR

Talos gives the format: a four-byte little-endian length, then JSON XORed with the alternating key `0xAB 0xCD`. Unit 42 gives the same 4-byte length and "2-byte key 0xABCD", and prints the field names, with the credentials and the remark redacted and `run` and `launch_mode` in clear. The first two encrypted bytes are always `D0 EF`, which is `{"` under that key, and that is what the extractor searches for when there is no `.cfg` section, as in the memory image. The decoded configs, with the secret removed:

```json
{"tenant_id":"df622d8d-49d3-4dea-9222-a3475dd63ead","client_id":"c381c514-9839-4d24-946c-056607961c23","client_secret":"<redacted, 40 chars>","user_id":"6a9a3baa-7873-43f7-b9b8-a63cf1588302","remark":"gmail","run":true,"launch_mode":"dll"}
```

That one is `1fadc90b`. All five:

| Build | `tenant_id` | `client_id` | `user_id` | `remark` | `run` | `launch_mode` |
|---|---|---|---|---|---|---|
| `40e7e77a` | `df622d8d-49d3-4dea-9222-a3475dd63ead` | `c381c514-9839-4d24-946c-056607961c23` | `6a9a3baa-7873-43f7-b9b8-a63cf1588302` | null | absent | absent |
| `ca14ad03` | same | same | same | null | false | `exe` |
| `1fadc90b` | same | same | same | `gmail` | true | `dll` |
| `09ef7c73` | `8f14bf5c-c0d4-40b9-9033-2f43870d29b1` | `ef6b9cb2-0793-4e2f-b906-e7c7d18a10b6` | `fafb1f03-8029-41ef-becf-872c16f34350` | `gmail-0326-3` | true | `dll` |
| `0c392643` | same as `09ef7c73` | `aa8a33dd-3b16-4adf-a74d-a772db6db6bc` | `b2a8fd9b-346f-4f99-93a0-768e29988ecc` | `mod_sy` | true | `exe` |

The config of `40e7e77a` has no `run` or `launch_mode` keys at all; every build compiled after October 14 has them. All three October builds carry the same 40-character secret.

I'm publishing the tenant, client and user IDs and withholding the secrets. The IDs are identifiers, and they appear in traffic: the tenant ID is in the token URL path (`login.microsoftonline[.]com/<tenant>/oauth2/v2.0/token`), and the client ID is in the token request body. A client secret is a working credential for a mailbox and a OneDrive that hold victims' files, and printing it would hand that access to anyone who reads this. I don't know whether these tenants were created by the operator or taken from someone else.

The [extractor](https://github.com/stateless-re/tools/tree/main/families/antino) prints the config with the secret redacted unless you pass `--show-secret`:

```text
$ python families/antino/extract.py ca14ad03...c9b800.exe
  "config_source": "scan at file offset 0x377400",
  "config": {"tenant_id": "df622d8d-49d3-4dea-9222-a3475dd63ead", ..., "remark": null, "run": false, "launch_mode": "exe"}
```

The memory image has no `.cfg` section because its headers are the UPX ones, so the extractor falls back to the `D0 EF` scan and finds the length field at file offset 0x377400.

## The sleep mask, October version

Talos explains what `load_shellcode` with `use_sleep_mask` is for: hook `Sleep` and `VirtualAlloc`, add a vectored exception handler, and keep the shellcode's memory encrypted while it sleeps. The hooks come from the `retour` crate (version 0.3.1 in the Cargo paths). `40e7e77a` contains the mask twice: one copy for the `load_shellcode` command (installer at `0x14021e7c0`) and one for the command-line mode described further down (installer at `0x140017a00`). The two are the same design with different globals. Here is the second, because it's the shorter read:

```c
AddVectoredExceptionHandler(1, veh_unmask);          // (1)
retour_hook(Sleep,        sleep_mask);               // (2)
retour_hook(VirtualAlloc, virtualalloc_track);       // (3)
```

The `VirtualAlloc` hook (3) is four lines. It calls the real function and stores the returned base and requested size in two globals. Only the most recent allocation is tracked, so "the shellcode region" means whatever was allocated last.

The `Sleep` hook (2), at `0x140017390`, is longer. Cleaned up from Ghidra's output, with the SIMD versions of the byte loops removed, and without a leading block that does the same masking for a second address/size pair that nothing else in the binary writes:

```c
snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
for each thread in snap:                             // (5)
    if (owner == GetCurrentProcessId() && tid != GetCurrentThreadId())
        SuspendThread(OpenThread(THREAD_SUSPEND_RESUME, 0, tid));
VirtualProtect(region, size, PAGE_READWRITE, &saved_protect);
for (i = 0; i < size; i++) {
    b = (region[i] + 0x35) ^ 0x5A;                   // (4)
    region[i] = (b << 3) | (b >> 5);
}
real_Sleep(ms);
for each suspended thread: ResumeThread(h);          // (6)
```

Line (4) is the whole cipher: add `0x35`, XOR `0x5A`, rotate left by 3. The vector constants are as plain as the scalar code: sixteen bytes of `0x35` and sixteen of `0x5A` sit at `0x140453c50` and `0x140453c60`, so in a string dump they read as `5555555555555555` and `ZZZZZZZZZZZZZZZZ`. There is no key, so a given shellcode always masks to the same bytes. A common x64 stager prologue, `fc 48 83 e4 f0`, becomes `5b 39 17 1a fb`.

Lines (5) and (6) freeze every other thread in the process for as long as the shellcode sleeps; in the `load_shellcode` copy that includes Antino's own Tokio workers. Then the hook returns, and the region is still masked and still `PAGE_READWRITE`.

Decoding happens on demand. When the shellcode's thread returns from `Sleep` into non-executable memory, the CPU raises an access violation, and the handler from (1) gets it:

```c
LONG veh_unmask(EXCEPTION_POINTERS *e) {
    if (e->ExceptionRecord->ExceptionCode != 0xC0000005)
        return EXCEPTION_CONTINUE_SEARCH;
    VirtualProtect(region, size, saved_protect, &old);   // (7)
    for (i = 0; i < size; i++)
        region[i] = (((region[i] >> 3) | (region[i] << 5)) ^ 0x5A) - 0x35;
    return EXCEPTION_CONTINUE_EXECUTION;                 // (8)
}
```

See if you can spot the problem. The handler checks the exception code and nothing else: not the faulting address, not the thread. The `load_shellcode` copy (`0x14021f030`) has the same check and nothing more. Any access violation anywhere in the process, a null dereference in Antino's own Rust code or one in the shellcode, makes it run (7): restore the protection, "decode" a region that may not be masked, and retry the faulting instruction (8). If the region was not masked, the decode corrupts it. If the fault had nothing to do with the region, the retry faults again, and the handler decodes the same region again on every pass.

The memory image `ca14ad03` (October 17) already fixed this. Its handler (the function at `0x7ff61ae80530` in the dump) follows the `cmp dword ptr [rax], 0xc0000005` with a load of `ExceptionInformation[1]` (`mov r8, [r8 + 0x28]`) and two compares against the region base and end. Its Sleep hook still walks the thread list: the snapshot loop (`Thread32First`/`Thread32Next`) is at `0x7ff61ae7fc9b`.

## The sleep mask, January version

The January DLL `09ef7c73` keeps the same cipher and matches what Talos describes. Its handler, at `0x18003f420`, adds two checks before it touches anything:

```c
if (code != 0xC0000005) return 0;
if (region == NULL || size == 0) return 0;
addr = e->ExceptionRecord->ExceptionInformation[1];        // the inaccessible address
if (addr < region || addr >= region + size) return 0;
```

The Sleep hook (`0x18003f610`) starts with `if (GetCurrentThreadId() != shellcode_tid) goto passthrough;`, so only the shellcode's own sleeps mask the region, and it no longer calls `SuspendThread` at all. `1fadc90b` (October 21) has the same handler (`0x180033640`) and the same thread gate (`0x180033840`). Neither DLL imports `SuspendThread`, `Thread32First` or `CreateToolhelp32Snapshot`. Only `40e7e77a` imports those three, and only it and the memory image contain their names, so their presence marks the two earliest builds; the extractor reports it as `thread_suspension_imports`.

One more detail from the `load` command, and I had it backwards in my first draft. When the mask is on, the command runs the decode transform over the incoming buffer before it executes it, so the operator sends shellcode that is already masked. Then it sets the protection. In `09ef7c73` the path that installs the hooks and the path that finds them already installed both jump to the same `PAGE_EXECUTE_READWRITE` (`0x40`); `PAGE_EXECUTE` (`0x10`) is used only when the mask is off. `1fadc90b` and the `load_shellcode` path of `40e7e77a` also use `0x40`, and the `load_shellcode` handler in `40e7e77a` restores `0x40` after decoding. In the three builds whose `load` code I read, masked shellcode runs from RWX memory; I didn't check `0c392643`. The one exception is the command-line mode in `40e7e77a`, which uses `PAGE_EXECUTE`.

The October DLL `1fadc90b` hides its command field names (more on that below), so I decoded the ones its `load` command reads. There are three: `shellcode`, `use_sleep_mask` and `use_restart_mode`. The third leads to the strangest part of the October standalone build.

## What the Rhai engine is for

Unit 42's command table describes `load` as "Download and execute a Rhai script", and notes that Antino "supports execution of Rhai scripts", an embedded scripting language for Rust, though it never saw one in use. `40e7e77a` and `0c392643` both link `rhai-1.23.4`. In `40e7e77a` I traced the engine back to its callers. The engine is built in one function (`0x140002a50`), the only direct caller of the Rhai setup routine at `0x1400cc9e0`, and that function has one direct caller, `main` (`0x14004cd90`, call at `0x14004d293`):

```c
args = std::env::args();
if (args.len() < 4) { run_client(); return; }        // (9)
path   = args[1];
masked = args[2] == "true";                          // (10)
key    = args[3];
buf = read(path) XOR key (repeating);                // (11)
SHELLCODE = buf; MASKED = masked;
if (rhai_entry() == 0)                               // (12)
    DeleteFileW(path);
```

With fewer than three arguments (9) the binary is the ordinary backdoor. With three, it's a shellcode runner. I first read the argument order as file, key, flag; the offsets into the argument vector say otherwise. `args[2]` is the one compared with `0x65757274` and a length of 4, which is `"true"`, and `args[3]` is the key (10, 11).

`rhai_entry` (12) builds an engine, registers one native function, and calls it by name. The name is hidden: it's rebuilt at runtime from 6 bytes at `0x1404500a0` XORed with `0xf66baf`, `0xae` and `0x40`, behind a pointer computed as `0x140442da0 + f(0xd8d74178)`. The pointer arithmetic follows the pattern of the `obfstr` crate, though the crate leaves no path string behind, so that's an inference. The decoded name is `antino`. The native function behind it checks that the shellcode global is set (otherwise it returns `"error: no shellcode data"` or `"error: no config"`), then spawns a thread. If the flag was `"true"`, the thread first installs the mask hooks. It then copies the buffer into a fresh `PAGE_READWRITE` allocation, runs the unmask transform over it (again only with the flag), switches it to `PAGE_EXECUTE`, and calls it.

So in this build the script engine is a trampoline. The shellcode call goes through an interpreter, which breaks the direct call chain from `main` to the thread that runs the payload. The `load_shellcode` handler (`0x140239740`) makes no direct call into the engine code, and I found no handler that passes operator text to it. I checked direct calls only, not every indirect one. Unit 42's `load` row may describe a build I don't have; in `1fadc90b` the `load` fields are the shellcode ones above, and what `0c392643` does with Rhai I didn't check.

The other half is the restart path in `load_shellcode` (`0x14021f280`). It generates a key and a file name, each 6 characters from `A-Za-z0-9`, with a linear congruential generator (`x * 0x41c64e6d + 0x3039`, the classic C `rand` constants) seeded from the system clock in nanoseconds. It XORs the shellcode with the key, writes it to the temp directory as `tmp_XXXXXX.dat`, and starts the current executable (`GetModuleFileNameW(NULL)`) through `CreateProcessW` with three arguments: the file path, `"true"` or `"false"`, and the key. The child takes the other side of branch (9), decodes the file, deletes it and runs the shellcode in a process with a clean history. For the DLL builds, "the current executable" would be the sideloading host, `GatherOsState.exe`; I haven't confirmed that the DLLs handle those arguments.

## Gen1 session IDs decode with "KxWNF"

Talos writes that Gen1 "XOR- and Base64-encodes the process ID, computer name, username and platform". The pieces are in `40e7e77a`. One function (`0x140016e00`) collects `GetCurrentProcessId()`, `GetComputerNameExW(ComputerNamePhysicalDnsHostname)`, `GetUserNameW` and the platform string, which a two-part format builds as `windows x86_64`. The next one (`0x1400170d0`) formats them:

```c
s = format("{}:{}:{}:{}:{}", pid, host, user, platform, extra);   // (13)
for (i = 0; i < len(s); i++)
    s[i] ^= "KxWNF"[i % 5];                                       // (14)
return base64_standard_padded(s);
```

The five pieces of the format string at `0x1404541b0` are `""` followed by four `":"`, so (13) has five fields. The fifth comes from the caller, as an optional string that becomes empty when unset. I think it's the config `remark`, which is null in both builds that have this code, but I didn't follow the caller far enough to prove it. The key in (14) is the 5 bytes `4b 78 57 4e 46` at `0x140454200`. The Base64 engine right after it uses the standard alphabet with padding. The two functions are called back to back from three call sites (`0x14001e1d1`/`0x14001e372` and two more pairs).

Before I found this function I took the `+0x35 ^0x5A` loop for the session XOR, because Talos had said XOR and it was the first byte loop in the client code. It's the sleep mask. The session XOR has a key that repeats every 5 bytes, which a fixed per-byte transform doesn't.

Base64 of a repeating XOR is no protection. The extractor decodes it:

```text
$ python families/antino/extract.py --session f0pjfHwcK3oLHgo1BwIDcRk5LyoyCyN0MSIWMyExOFgvdnAUTmN0
  "process_id": "4242", "machine_name": "WS-EXAMPLE", "username": "analyst",
  "platform": "windows x86_64", "fifth_field": ""
```

That ID is one I made up with the same function, not one from a victim. I decompiled this code in `40e7e77a` only; `ca14ad03` contains the same key and alphabet. I didn't trace the session ID into the heartbeat file name or the mail subject; Talos says Gen1 uses it there. `KxWNF` is in `40e7e77a` and `ca14ad03` and in none of the other three builds in clear text. `09ef7c73` builds a version-4 UUID (the `& 0xf00 | 0x4000` and `& 0x3f.. | 0x80..` bit masks at `0x18000cd70`). `1fadc90b` builds version-4 UUIDs too, but the ones I found are inside its decoy `SL*` exports (`SLGetLicensingStatusInformation` and two more); I couldn't connect any of them to the session ID.

## Hidden strings

The three builds I decompiled hide some of their strings behind small helper functions that compute an obfuscated pointer (the `& 0xffff) + param_1` shape). My pattern match finds at least 14 in `40e7e77a` and about 30 each in `1fadc90b` and `09ef7c73`, and it misses some variants, so read those as lower bounds. I had first taken the `antino` name for the only hidden string in `40e7e77a`. It isn't: a cluster of helpers sits at `0x14021aa40`–`0x14021abd0`, next to the command code, and none of the five builds has `use_sleep_mask` in clear text. I decoded the three `load` field names in `1fadc90b` by hand, each with its own helper and its own XOR constants (for example, `shellcode` is 9 bytes at `0x18023727d + f(0xc1fa1e28)` XORed with `0x1be634a284277d23` and `0x7b`). A general decoder would need to emulate each helper; I didn't write one, so `1fadc90b`'s session ID scheme is still open.

## What I couldn't determine

- How `1fadc90b` derives its session ID. Its strings are hidden, `KxWNF` isn't there in clear text, and the UUID code I found sits in decoy exports.
- Whether the DLL builds act on the restart-mode arguments when their host process is relaunched.
- What `0c392643`, the 32-bit January build, does with Rhai, and how it masks memory: it has the mask constants but doesn't link `retour`.
- Whether any build's `load` command runs Rhai scripts, as Unit 42's table says.
- Talos describes Gen1 builds that register with `sendsession` mail drafts. None of these five builds contains `sendsession` in clear text, and all five contain the OneDrive heartbeat path `:/antino/heartbeats/.json:`.
- Unit 42's config is 258 bytes long. None of the five here is: their lengths are 225, 257, 259, 260 and 266 bytes. Theirs comes from another file.
- Who controls the two tenants.

## Hunting

On hosts:

- An Antino executable started with three arguments, where the first is `%TEMP%\tmp_` plus 6 alphanumeric characters plus `.dat`, the second is `true` or `false`, and the third is 6 alphanumeric characters. Parent and child are the same image. I've shown this in `40e7e77a` only, but where it applies it's specific; the file is deleted after it's read, so look for the process creation, not the file.
- A private region that is `PAGE_EXECUTE_READWRITE` while the shellcode runs and `PAGE_READWRITE` while it sleeps, flipping back on access violations that a vectored handler resolves. The two earliest builds also suspend every other thread in the process each time the shellcode sleeps. Both are generic sleep-mask behavior, so treat them as a lead to pair with another, not an answer.
- Because the mask has no key, a masked region holds the same bytes on every host. If you know the shellcode, you can compute what it looks like masked (`5b 39 17 1a fb` for `fc 48 83 e4 f0`) and search for that in `PAGE_READWRITE` private memory.
- From Talos's description of the install: `%LOCALAPPDATA%\Windows GatherOSStateKit\` with an HKCU Run value, and the Microsoft-signed `GatherOsState.exe` sideloading an `slc.dll`. A copy of that binary running from a user-writable directory next to an `slc.dll` is worth a look.

On the network, if you can see inside TLS to Microsoft 365:

- Token requests to `login.microsoftonline[.]com/df622d8d-49d3-4dea-9222-a3475dd63ead/oauth2/v2.0/token` or `.../8f14bf5c-c0d4-40b9-9033-2f43870d29b1/...` with one of the three client IDs in the Indicators table. In Entra sign-in logs of your own tenant you won't see these (the app lives in the operator's tenant), so this is a proxy or TLS-inspection search.
- Graph requests for the three user IDs. With app-only credentials there is no `/me`, so I expect them under `/users/<user_id>/`; I didn't find that path as a literal string. Also OneDrive paths with `:/antino/heartbeats/`, `:/antino_uploads/` or `:/antino_downloads/`, and mail filters on `subject eq 'command_req_...'`.

In files:

- A PE section named `.cfg` of exactly 0x10000 bytes, nearly all zero, whose first four bytes are a small little-endian length and whose next two are `D0 EF`. That one check found the config in all four PE files and, as a raw byte scan, in the dump.
- PDB names `slc_template.pdb` and `antino_client_template.pdb`, source paths under `D:\a\antino\antino\`, and the strings `command_req_`, `command_res_` and `:/antino/heartbeats/`.
- `KxWNF` next to a standard Base64 alphabet marks the October standalone builds; `5555555555555555` and `ZZZZZZZZZZZZZZZZ` within 0x50 bytes of each other are in all five (adjacent in three; weak alone).
- Check what your sandbox or repository calls these files. Two of the five are labeled `RustyStealer` on MalwareBazaar.

The [extractor](https://github.com/stateless-re/tools/tree/main/families/antino) takes EXEs, DLLs and memory dumps and prints the config (secret redacted unless `--show-secret`), the PE build details and the markers above; `--session` decodes October session IDs.

## Indicators

Files (all on MalwareBazaar):

| SHA-256 | Role |
|---|---|
| `40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d` | Antino x64 EXE, 2025-10-14, Rhai, October mask, `KxWNF` session |
| `ca14ad0344dc7216f6da29a5cbe4237d886cc5257e8c3a48fb4885a311c9b800` | Antino x64 memory image (UPX headers), 2025-10-17, bounds-checked handler, thread suspension, `KxWNF` session |
| `1fadc90b61ce536abda78eb387a7f3d745f00c16775d3f762845ccc0fde567da` | Antino x64 `slc.dll`, 2025-10-21, January-style mask |
| `09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff` | Antino x64 `slc.dll`, 2026-01-11 |
| `0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd` | Antino x86 EXE `flashcenter_pp_ax_install_en.exe`, 2026-01-11, Rhai |

Microsoft 365 identifiers from the configs:

| Type | Value | Builds |
|---|---|---|
| Entra tenant ID | `df622d8d-49d3-4dea-9222-a3475dd63ead` | `40e7e77a`, `ca14ad03`, `1fadc90b` |
| Entra tenant ID | `8f14bf5c-c0d4-40b9-9033-2f43870d29b1` | `09ef7c73`, `0c392643` |
| App (client) ID | `c381c514-9839-4d24-946c-056607961c23` | `40e7e77a`, `ca14ad03`, `1fadc90b` |
| App (client) ID | `ef6b9cb2-0793-4e2f-b906-e7c7d18a10b6` | `09ef7c73` |
| App (client) ID | `aa8a33dd-3b16-4adf-a74d-a772db6db6bc` | `0c392643` |
| User object ID | `6a9a3baa-7873-43f7-b9b8-a63cf1588302` | `40e7e77a`, `ca14ad03`, `1fadc90b` |
| User object ID | `fafb1f03-8029-41ef-becf-872c16f34350` | `09ef7c73` |
| User object ID | `b2a8fd9b-346f-4f99-93a0-768e29988ecc` | `0c392643` |
| Remark | `gmail`, `gmail-0326-3`, `mod_sy` | `1fadc90b`, `09ef7c73`, `0c392643` |

Talos's report has the delivery infrastructure (Cloudflare Pages and R2 hosts, `microsoft-flash[.]com`, `wps-cn[.]com`); I didn't find anything new there.

## ATT&CK

| ID | Technique | How it shows up here |
|---|---|---|
| T1102.002 | Web Service: Bidirectional Communication | Commands and results through Outlook mail and OneDrive via Microsoft Graph |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | `slc.dll` builds with `SLOpen` and the other `SL*` exports, `launch_mode: dll` |
| T1547.001 | Registry Run Keys / Startup Folder | `run: true` in three of the five configs |
| T1027 | Obfuscated Files or Information | XOR'd `.cfg` config, XOR'd shellcode file, hidden strings, masked memory |
| T1620 | Reflective Code Loading | Shellcode copied into private memory and called in place |
| T1070.004 | Indicator Removal: File Deletion | The command-line mode deletes the shellcode file after reading it |

## Ending

Antino's sleep mask was fixed in two steps within a week of October: first the handler learned to check the address, then the Sleep hook stopped freezing the process. The cipher never changed in the builds I read: no key, one add, one XOR, one rotate. A masked shellcode is as recognizable as an unmasked one, it runs from RWX memory in every `load` path I read, and in the October standalone build the relaunch with `true`/`false` and a six-character key is on the command line for anyone logging process creation.

## Credits and further reading

- Ashley Shen, Cisco Talos: [China-nexus UAT-11587 targets government and policy organizations across Asia with Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/) (September 30, 2026), the source of the hashes, the generation split and the command table.
- Unit 42: [The XG Files: Falcon C2 Flying Under The (Browser) Radar](https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/) (November 11, 2026), for the config field names and the Rhai observation.
- The samples came from MalwareBazaar: [40e7e77a](https://bazaar.abuse.ch/sample/40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d/), [ca14ad03](https://bazaar.abuse.ch/sample/ca14ad0344dc7216f6da29a5cbe4237d886cc5257e8c3a48fb4885a311c9b800/), [1fadc90b](https://bazaar.abuse.ch/sample/1fadc90b61ce536abda78eb387a7f3d745f00c16775d3f762845ccc0fde567da/), [09ef7c73](https://bazaar.abuse.ch/sample/09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff/), [0c392643](https://bazaar.abuse.ch/sample/0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd/).
- The crates whose paths are in the binaries: [retour](https://docs.rs/retour) for the hooks, [rhai](https://docs.rs/rhai) for the script engine, [graph-rs-sdk](https://docs.rs/graph-rs-sdk) for Microsoft Graph.
