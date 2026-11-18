---
title: "BotHelper's anti-VM switch is never turned on, and its NetTask command is a flood kit"
date: 2026-11-18T19:53:11+00:00
slug: "bothelper-paradoxnet"
description: "BotHelper's nine-test anti-VM gate hangs on a flag nothing sets, and its NetTask command starts one of eleven floods under the group name ParadoxNet."
tags: ["bothelper", "paradoxnet", "dotnet", "rat", "ddos", "amsi-bypass"]
sample:
  family: "BotHelper RAT"
  sha256: "0d41ce75da4f3404734358411a72ffc4169376dcfebda52ac50eb66eac73d2f6"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/0d41ce75da4f3404734358411a72ffc4169376dcfebda52ac50eb66eac73d2f6)"
toc: true
---

The BotHelper RAT runs nine environment checks (virtual machine, sandbox, debugger, known analysis machines) before it does anything else, except that none of them ever runs. The gate is `if (Enabled && (...))`, and no instruction in the assembly writes `Enabled`.

The same 52,736-byte .NET client carries a group name, `ParadoxNet`, a version string, `v1.6`, and a command called `NetTask` that dispatches to eleven flood methods. Two of them put the text `Paradox Net` on the wire. The stager in front of it decrypts a container with room for a decoy document, which the captured delivery appears to have left empty.

Point Wild's Lat61 team (Prathamesh Shingare and Kedar Shashikant Pandit) published [BotHelper RAT: From Encrypted Payload to Live Screen Surveillance](https://www.pointwild.com/threat-intelligence/bothelper-rat-from-encrypted-payload-to-live-screen-surveillance/) on 2026-09-24 and named the family after the `Bot.Helper` namespace. Their report walks through the infection chain and the screen-streaming traffic they captured, and lists the command names.

The report doesn't decode the configuration. It gives `NetTask` one row in its command table ("Handed to NetworkManager") and mentions "numbered NetTask classes" without describing them. It describes the payload decryption in prose without a formula.

Both hashes in its indicator table are on Hybrid Analysis and not on MalwareBazaar, so I took them from there.

## What I found

- The stager decrypts `payload.bin` with `out[i] = in[i] ^ k`, `k0 = 0xA7`, `k = 31*k + i`. Inside is a container with a slot for a decoy file, which the captured `payload.bin` appears to leave empty.
- The stager collects a host "profile" it never reads, and its "System Maintenance" install dialog is created hidden; a 500 ms timer clicks for the user.
- The RAT's anti-VM gate, its Defender exclusion, its ACL-based file hiding, its embedded `ParadoxNet` certificate and two of its three install paths are dead code in this build.
- `NetTask` starts one of eleven floods, `NetTaskA` to `NetTaskK`, over HTTP, ICMP, TCP and UDP. Each runs in 10 threads (5 for UDP) until `NetTaskStop`.
- The protocol is `data=` plus Base64 over HTTPS POST, with certificate validation off, and task lines of the form `id|Command|argument`. The pipe separator truncates any shell command that uses a pipe.

## The stager hides its own dialog

The stager `8f39fe88` is a 46,080-byte MinGW x64 executable whose version resource claims to be Microsoft's "Windows Update Service", `WindowsUpdate.exe`, 10.0.19041.1. Its link timestamp is 2026-09-11 06:54:55 UTC, ten hours after the RAT's certificate was minted (more on that below), and it was submitted to Hybrid Analysis the next morning.

Point Wild writes that the stager "asks Windows for the computer name, the logged-in user, the processor details, and the installed memory". They add that "All four buffers sit next to each other, so this is one function gathering one profile."

The calls are there. I expected to find the values in the download request or in a check before it, and went looking for the reads. There aren't any. Here's `WinMain`, with the stack offsets that matter:

```asm {title="WinMain (stager 8f39fe88)"}
140001dee  lea rdi, [rsp+0xe0]
140001e0c  call [GetComputerNameA]       ; (1) into rsp+0xe0
140001e28  call [GetUserNameA]           ; same buffer, overwrites the name
140001e33  call [GetSystemInfo]          ; into rsp+0x70, never read again
140001e67  call [GlobalMemoryStatusEx]   ; into rsp+0xa0
140001e72  call [Sleep]                  ; 0x4b0 = 1,200 ms
...
140001e8e  movups [rsp+0xe0], xmm6       ; (2) WNDCLASSA built over the names
140001f33  call [CreateWindowExA]        ; "System Maintenance", class SMClass
140001f41  call [ShowWindow]             ; (3) nCmdShow = 0, SW_HIDE
140001f58  call [SetTimer]               ; id 1, 500 ms
140001f8d  call rsi                      ; GetMessageA(rsp+0xa0, ...)
```

The computer name and user name land in the same buffer (1), and that buffer becomes the `WNDCLASSA` structure a few instructions later (2). The memory status buffer at `rsp+0xa0` becomes the `MSG` for the message loop. Nothing reads the system info. As far as the stager's own logic goes, the profile does nothing; my guess is that it's there to look like an installer's system check.

The window is a fake installer prompt. Its `WM_CREATE` handler adds a "System Maintenance" label, the text "A scheduled maintenance is available. Click Install to continue." and two buttons, Install (id 1) and Cancel (id 2).

The window style (`0xC80000`) has no `WS_VISIBLE`, and `ShowWindow` with `SW_HIDE` (3) makes sure, so nobody ever sees the buttons. The window procedure starts the download on either `WM_COMMAND` from Install or `WM_TIMER` with id 1, and the timer fires after 500 ms. The stager clicks Install itself.

## The download and the container

The download goes over WinHTTP to `easyllms[.]xyz:443` with the user agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`, path `/f10c2490...07cc126ed/uploads/Files/payload.bin`, and security flags `0x3300` set with `WinHttpSetOption`, which ignores certificate errors. It reads 8 KB chunks into a growing heap buffer and gives up if the result is under 64 bytes. Then it decrypts:

```asm {title="payload.bin decryption"}
14000166b  mov edx, 0xffffffa7           ; (1) key 0xFFFFFFA7, low byte 0xA7
140001670  mov ecx, edx
140001672  xor byte ptr [rbp+rax], dl    ; (2) buf[i] ^= low byte of key
140001676  shl ecx, 5
140001679  sub ecx, edx                  ; ecx = key * 31
14000167b  lea edx, [rcx+rax]            ; (3) key = key * 31 + i
14000167e  add rax, 1
```

Written out: `out[i] = in[i] ^ (k_i & 0xff)`, with `k_0 = 0xFFFFFFA7` (1) and `k_(i+1) = 31 * k_i + i` modulo 2^32 (3). Only the low byte is used (2), and the low byte of the next key depends only on the low byte of the last, so starting from `0xA7` gives the same keystream.

The keystream doesn't depend on the data, so the same loop encrypts and decrypts. Point Wild's "No key is stored anywhere" is right in the sense that there's no key array. The seed and multiplier are the key.

What comes out isn't a bare PE. It's a container, `u32 decoy length | decoy | u32 name length | name | RAT`, and the stager reads a 32-bit length at offset 0 and a second one right after the block it describes:

| Offset | Size | Field | In the observed payload |
|---|---|---|---|
| 0 | 4 | decoy length `L` | 0 |
| 4 | `L` | decoy file bytes | none |
| 4 + `L` | 4 | name length `N`, used if 1 to 249 | 0 |
| 8 + `L` | `N` | decoy file name (copied into a zeroed 256-byte buffer) | none |
| 8 + `L` + `N` | rest | RAT, written as `msedge_proxy.exe` | 52,736 bytes |

If `L` isn't zero and the name's first byte isn't NUL, the stager writes the decoy to `%TEMP%\<name>` and opens it with `ShellExecuteA(..., "open", ..., SW_SHOW)`. That is the slot for a lure document or image. Either way it writes the rest of the buffer to `%TEMP%\msedge_proxy.exe` and starts it with `CreateProcessA`, using `CREATE_NO_WINDOW` and `SW_HIDE`. It resolves `CreateProcessA` through `GetProcAddress` so it stays out of the import table.

The payload Point Wild captured is 52,744 bytes. The RAT it dropped is 52,736. The difference is exactly the 8 bytes of two zero-length fields, so this delivery had no decoy, as long as the report's size is exact and the RAT it lists is the file that came out of this `payload.bin`.

The report also says that after decryption "the buffer starts with MZ and the familiar DOS stub text". That can't be the whole buffer. The stager would read `4D 5A 90 00` as a decoy length of 9,460,301 bytes and then read the name length nine megabytes past the end of a 52 KB allocation. I think the screenshot shows the part at offset 8, or the dropped file.

## Inside the RAT

`0d41ce75` is a .NET Framework 4.6.2 assembly with readable names and plain strings. The only hiding is `IndirectObjectLoader`, which creates and calls `Socket`, `WebClient`, `Process`, `File` and WMI types by name through reflection so they don't appear as direct references. Namespaces are `Bot`, `Bot.Function`, `Bot.Helper` and `Bot.SecurityModule`.

The assembly metadata still says `calc`, "calc © 2021", version 443.424.100.12, which reads like a project template that was never renamed. The PE timestamp decodes to 2089, and the debug directory has a Repro entry (type 16): this is a deterministic build, whose timestamp field holds a hash, not a date.

The configuration is a static class, `AppConfig`, filled in by its static constructor:

| Field | Value | Used |
|---|---|---|
| `hosts[0]` | `hxxps://easyllms[.]xyz/f10c2490...07cc126ed` | no |
| `version` | `v1.6` | yes |
| `Group` | `ParadoxNet` | yes |
| `Mutex` | `vyub75665ANKiuf78` | yes |
| `WatchDogPath` | `C:\Users\<user>\AppData\Local\CrashDumps\Crash.exe` | yes |
| `AdminPath` | `C:\Windows\Performance\WinSAT\issas.exe` | no |
| `NonAdminPath` | `C:\Users\<user>\AppData\Roaming\Microsoft\HTML Help\unsecapp.exe` | no |
| `Certificate` | self-signed, `O=ParadoxNet, CN=easyllms[.]xyz` | no |

`Group` and `version` go into the registration line. The base URL the client actually uses comes from a second copy of the same string in `ServiceClient.Generate()`. "Used" here means some instruction reads the field after the static constructor writes it. For `hosts`, `AdminPath`, `NonAdminPath` and `Certificate` none does.

The certificate is worth a moment anyway. It's self-signed for `easyllms[.]xyz` with `C=EU, ST=State, O=ParadoxNet`, serial `49160F0826D59B8014710A152FB62975C525AEA1`, valid from 2026-09-10 20:50:57 UTC to 2036-09-07.

The client doesn't pin it: its POST and upload helpers set the process-wide validation callback to one that returns `true`, and its `WebClient` downloads inherit that. The domain resolved to Cloudflare in Point Wild's capture (172.67.187[.]30 is in Cloudflare's 172.64.0[.]0/13), and a proxied client sees Cloudflare's certificate, not this one.

My guess is that it's the origin server's, generated the evening before the stager was built. If that's right, it is a better pivot for finding the origin in certificate scan data than anything in the traffic.

## Startup: a log file, a gate that's always open, a mutex that doesn't stop anything

`Main` writes its progress to `%TEMP%\bot_log.txt` (`start`, `vm ok`, `setup ok`, `amsi ok`, `gen ok`, or a `... fail:` line with the exception message), which Point Wild also noted. The first step is the anti-VM gate:

```csharp {title="Bot.Helper.EnvironmentCheck (trimmed)"}
public static bool Enabled;                              // (1)

public static void CheckOrExit()
{
    if (Enabled && (isVM_by_wim_temper() || isVM_by_wim_temper1()
        || IsWindowsXP() || CheckDebugger()
        || IsRunningInVirtualMachine1() || IsRunningInVirtualMachine2()
        || ItsRobertOrFrank() || ProccessorCheck() || EnvironmentDetected()))
        Environment.Exit(0);                             // (2)
}
```

`Enabled` (1) has no initializer and the class has no static constructor. In the IL there is exactly one reference to the field, the `ldsfld` at the start of `CheckOrExit`, and no `stsfld` anywhere in the assembly; nothing reaches it through reflection either. A static `bool` starts as `false`, so the `&&` short-circuits and the exit at (2) is unreachable. The log still writes `vm ok`, which is how a sandbox report ends up suggesting a check passed.

The nine tests that never run:

- empty WMI `Win32_CacheMemory` and `CIM_Memory`
- Windows XP
- an attached managed debugger
- a C: drive under 50 GiB
- under 2,048 MB of RAM
- one CPU
- KVM/QEMU guest drivers (`balloon.sys`, `netkvm.sys`, the `vio*` set) or `qemu-ga`/`SPICE Guest Tools` folders
- "sandbox" in the path
- two hard-coded user/machine pairs: `Robert` on a machine whose name contains `22H2`, `Frank` on one containing `DESKTOP`

Setup copies the running file to `C:\Users\<user>\AppData\Local\CrashDumps\Crash.exe`; the path is built from the user name, not from `%LOCALAPPDATA%`. It marks the file hidden if the copy doesn't exist yet, and runs `schtasks /create /f /sc minute /mo 30 /tn "Crash" /tr "<path>"` on every start. Point Wild didn't give the task name. It is the file name without extension: `Crash`.

Then the mutex, which Point Wild describes as "a mutex to stop a second copy from running". `CreateMutex("vyub75665ANKiuf78")` returning "already exists" only writes `mutex fail` to the log, and `Main` carries on. Nothing in the client stops the original `msedge_proxy.exe` and the `Crash.exe` copy the task starts half an hour later from running side by side, both polling with the same device ID.

### The AMSI patch picks the right bytes for the wrong reason

`SecurityPatch.Bypass` overwrites the start of `AmsiScanBuffer` and chooses the patch by `IntPtr.Size`:

| `IntPtr.Size` | Bytes | Instructions |
|---|---|---|
| 8 | `B8 34 12 07 80 66 B8 32 00 B0 57 C3` | `mov eax,0x80071234`; `mov ax,0x32`; `mov al,0x57`; `ret` |
| 4 | `B8 57 00 07 80 C2 18 00` | `mov eax,0x80070057`; `ret 0x18` |

Both return `0x80070057`, `E_INVALIDARG`. The 64-bit one builds the constant in three moves, which keeps the well-known `B8 57 00 07 80` sequence out of its bytes.

I assumed the x64 patch was the live one on a modern machine. The CLR header says otherwise: its flags are `0x20003`, `ILONLY | 32BITREQUIRED | 32BITPREFERRED`, so the RAT always runs as a 32-bit process. `IntPtr.Size` is always 4, and on 64-bit Windows the patch lands in the WoW64 `amsi.dll`.

The disguised x64 bytes never execute. The x86 patch's `ret 0x18` matches `AmsiScanBuffer`'s six 4-byte stdcall arguments.

### Borrowed helpers

Three helper classes look copied, typo for typo. `EnvironmentDetected` has the same driver list as a decompiled RAT client in a public GitHub repository created in June 2025 (the files carry the decompiler's `Token`/`RID` comments), including `viofs.sys` listed twice.

BotHelper's `FileAttribute.NamingAdm` is `{ "TrustedInsraller", "System" }`, with the same misspelling of TrustedInstaller as that client's `SecrityHidden` class. `WindowsDefenderExclusion.Exc` adds the file's folder to Defender exclusions through the WMI `MSFT_MpPreference.Add` method, just like the client's class of the same name.

The `isVM_by_wim_temper` method name is also one of the strings in [Sekoia's DcRat rule](https://github.com/SEKOIA-IO/Community/blob/main/yara_rules/rat_win_dcrat_qwqdanchun.yar), so the code has been passed around.

In BotHelper, `WindowsDefenderExclusion.Exc`, `FileAttribute.HiddenFile` and `FileAttribute.Unlock` have no callers. Neither do `BrowserControl` and `Utility.GetIpDomain`. They look copied in and never wired up.

## The protocol

Check-in and task traffic goes to `<base>/api/v1/<name>.php` as an HTTPS POST of `data=` plus the Base64 of the UTF-8 text, and those replies are Base64-decoded. Screenshots go as multipart uploads, whose replies are ignored.

The device ID is the SHA-256 hex of the disk model and name, CPU name, BIOS and baseboard serials, processor ID, Windows version string and CPU count with spaces removed, cached in `HKCU\Google`, value `devid`. That is a top-level key under `HKEY_CURRENT_USER`, not under `Software`, which makes it easy to look for.

| Request | Body | Reply used |
|---|---|---|
| `ping.php` | device ID | `hwidnotfound`, `null`, or task lines |
| `connect.php` | registration line (below) | no |
| `task_run.php` | task ID | no |
| `task_failed.php` | task ID | no |
| `screen_upload.php` | multipart, `file` = `<devid>.png` | no |
| `screen_live.php` | multipart, `file` = `<devid>.jpg` | no |

```text {title="connect.php body before Base64, with typical values"}
ParadoxNet|<devid>|<user> @ <machine>|Windows 10 x64|false|v1.6
```

The fields are group, device ID, user and machine, the Windows caption cut down to a short name plus bitness, whether the process is in the Administrators role, and the version. Both multipart uploads also carry a `filename` form field.

The client polls every `30 + Random.Next(-5, 5)` seconds, 25 to 34. A reply of `hwidnotfound` makes it register, and anything else is split into lines of `id|Command|argument`. Each new ID runs on its own thread and is remembered so it doesn't run twice in the same process.

Because the line is split on every `|`, the argument is only what comes before the next pipe: `ExecuteShell` with `tasklist | findstr x` runs `tasklist `.

## Commands

The dispatcher matches 18 exact names and two prefixes:

| Command | Argument | What it does |
|---|---|---|
| `Screenshot` | | PNG of the primary screen to `screen_upload.php` |
| `ScreenStreamStart` | `fps=,q=,scale=` | JPEG frames to `screen_live.php`; defaults 3 fps, quality 40, scale 0.75, fps clamped to 1 to 10 |
| `ScreenStreamStop` | | stops the stream |
| `MessageBox`, `Notepad` | text | shows the text, or writes it to a temp `.txt` and opens it |
| `ExecuteLink` | URL | downloads to `GetTempFileName()` plus the URL's extension and starts it through PowerShell |
| `ExecuteDisk` | file name | same, from `<base>/uploads/Files/` |
| `ExecuteShell`, `ExecutePowershell` | command | `cmd /c <command>` or `powershell /c <command>`, hidden, `runas` verb if admin |
| `PcShutdown`, `PcReboot`, `PcLogout` | | `shutdown /s /f /t 00`, `/r /f /t 00`, `/l /f` |
| `ClientRestart`, `ClientClose` | | restart or exit |
| `ClientUpdate` | URL | runs the new file like `ExecuteLink`, then does what `ClientRemove` does |
| `ClientRemove` | | `File.Delete` on its own running image, errors swallowed, then exits |
| `ClipperStart` | `base64(regex)/replacement` | every 5 s, if the clipboard matches the regex, replaces the whole clipboard |
| `ClipperStop` | | clears all rules |
| `NetTask<X>` | target | starts a flood (next section) |
| `Plugin<Name>` | | downloads `<base>/uploads/Plugins/<Name>.dll`, loads it, calls `Plugin.Plugin.Run(devid, base)` |

Two details here matter for detection. The PowerShell launch line is `cmd /c start /b powershell –ExecutionPolicy Bypass Start-Process -FilePath '"<file>"' & exit`, and the dash before `ExecutionPolicy` is U+2013, an en dash, not a hyphen. PowerShell accepts it, but a command-line rule looking for `-ExecutionPolicy` or `-ep` with an ASCII hyphen won't match.

Second, `ClientRemove` doesn't touch the scheduled task or the `Crash.exe` copy. It calls `File.Delete` on the file it is running from, which Windows refuses for a mapped image, ignores the error and exits. The next 30-minute trigger starts the RAT again. Point Wild noted the same effect from the defender's side, where deleting the temp file isn't enough.

The clipper's argument is split on `/`, but `/` is one of Base64's own characters. So a regex whose encoding contains a slash gets cut at the slash: it either fails to decode or decodes to a shorter regex, and the replacement becomes the leftover Base64. The operator has to pick regexes around that.

## NetTask is eleven floods

`NetworkManager.Start` switches on the eighth character of the command name. Every method loops forever in its own threads until `NetTaskStop` calls `Thread.Abort` on all of them:

| Command | Class | Target | What each thread does |
|---|---|---|---|
| `NetTaskA` | `NetTaskA` | `host:port` | 100 TCP sockets, each sends `HEAD /` with `Content-length: 5235`, then all close |
| `NetTaskB` | `NetTaskB` | host | ICMP echo, 100 ms timeout, DF, TTL 64, payload `Paradox Net`, 1,000 per round |
| `NetTaskC` | `NetTaskC` | URL | TCP connect, `GET /` with `User-Agent: null` and `Referrer: null`, close |
| `NetTaskD` | `NetTaskD` | URL | `WebClient.DownloadString` in a loop |
| `NetTaskE` | `NetTaskE` | URL | `WebClient.UploadString` with body `Paradox Net` in a loop |
| `NetTaskF` | `NetTaskF` | URL | TCP connect, bare `GET / HTTP/1.1` with no `Host`, close |
| `NetTaskG` | `NetTaskG` | URL | 100 TCP sockets, each sends `POST /` headers with `Content-length: 5235` and no body, then all close |
| `NetTaskH` | `NetTaskTcp` | `host:port` | TCP connect, writes 300 to 1,200 random bytes, usually once |
| `NetTaskI` | `NetTaskI` | `host:port` | TCP connect and close |
| `NetTaskJ` | `NetTaskUdp` | `host:port` | non-blocking UDP, 300 to 1,200 random bytes per datagram, 5 threads |
| `NetTaskK` | `NetTaskK` | `host:port` | TCP connect, 100 bytes each in 0 to 99, close |

All but `NetTaskJ` run 10 threads. The raw-socket HTTP methods C, F and G pick port 443 when the target contains `https` and still send plaintext to it. They also strip the target with `Replace("/", "")`, so a URL with a path turns into a host name that doesn't resolve.

In `NetTaskTcp` the decision to keep writing is a random number from 10 to 49 drawn once per connection, and anything over 20 breaks after the first write; 29 of the 40 values do.

These are simple floods, and they are where `ParadoxNet` shows up on the wire: `Paradox Net` is the ICMP payload of B and the POST body of E. I found no public reporting on a family by that name.

The report's command table gives `NetTask` one row next to `Screenshot` and `ExecuteShell`. In this client it is a DDoS feature, and a victim machine is also a flood node.

## What I couldn't determine

The real `payload.bin` isn't public, so the container layout comes from the stager's code and the 8-byte size difference, not from decrypting the captured file. I tested the decoder on containers I built from the RAT with the stager's keystream. I don't know whether other deliveries filled the decoy slot.

No plugin DLL from `/uploads/Plugins/` is available, so what `Plugin<Name>` loads is unknown. The panel side (how `ParadoxNet` groups are used, whether a task served to two copies of one device runs twice) isn't visible from the client.

## The extractor

[families/bothelper](https://github.com/stateless-re/tools/tree/main/families/bothelper) in the tools repo reads both files. For the stager it prints the URL, port, user agent, XOR seed and multiplier (found by the loop's instruction bytes) and the drop name. For the RAT it prints the config, the certificate, the command and flood names, whether the anti-VM flag is ever written, and which config fields are never read. `--payload` decrypts a `payload.bin` and splits the container, with `-o` to write the decoy and RAT to disk.

## Indicators

| SHA-256 | Role |
|---|---|
| `8f39fe882e45dfa8a7446d59dfef86b583a868ff846ade86124a57041f5c63fd` | stager, `WindowsUpdate.exe` (MinGW x64) |
| `0d41ce75da4f3404734358411a72ffc4169376dcfebda52ac50eb66eac73d2f6` | BotHelper RAT v1.6, `msedge_proxy.exe` / `Crash.exe` |

| Network | Note |
|---|---|
| `easyllms[.]xyz` | C2 and payload host (Cloudflare in front) |
| base path (below) | `uploads/Files/payload.bin`, `api/v1/*.php`, `uploads/Plugins/` |
| certificate serial | `49160F0826D59B8014710A152FB62975C525AEA1`, self-signed `CN=easyllms[.]xyz, O=ParadoxNet` |

```text {title="C2 base path"}
hxxps://easyllms[.]xyz/f10c24902875d97a8fef69a3b3a7b5aafb835b7bbfad749c
3c161296c745867ea831d7f0133f2f819cd602b3a4b5e41a3dd69024533d8da49cefdd9
07cc126ed/
```

The path is one 128-character hex segment, wrapped here to fit.

| Host | Value |
|---|---|
| dropped RAT | `%TEMP%\msedge_proxy.exe` |
| persistence copy | `C:\Users\<user>\AppData\Local\CrashDumps\Crash.exe` (hidden) |
| scheduled task | `Crash`, every 30 minutes |
| mutex | `vyub75665ANKiuf78` |
| registry | `HKCU\Google`, value `devid` (64 hex characters) |
| log file | `%TEMP%\bot_log.txt` |
| command line | `powershell –ExecutionPolicy Bypass Start-Process` with an en dash |

## ATT&CK

| ID | Technique | In this sample |
|---|---|---|
| T1036.005 | Masquerading: match legitimate name | `WindowsUpdate.exe` with a Microsoft version resource; `msedge_proxy.exe`; `Crash.exe` in `CrashDumps` |
| T1027.013 | Encrypted/encoded file | `payload.bin`, XOR with `k = 31k + i` |
| T1105 | Ingress tool transfer | stager download; `ExecuteLink`, `ExecuteDisk`, `ClientUpdate`, `Plugin` |
| T1053.005 | Scheduled task | `schtasks /create /sc minute /mo 30 /tn Crash` |
| T1564.001 | Hidden files | `Crash.exe` set hidden |
| T1562.001 | Impair defenses | `AmsiScanBuffer` patched to return `E_INVALIDARG` |
| T1082 | System information discovery | WMI hardware IDs for the device ID; Windows version, admin role |
| T1071.001 | Web protocols | HTTPS POST to `api/v1/*.php` |
| T1132.001 | Standard encoding | Base64 request and reply bodies |
| T1113 | Screen capture | `Screenshot`, `ScreenStreamStart` |
| T1115 | Clipboard data | `ClipperStart` regex replace |
| T1059.001, T1059.003 | PowerShell, Windows command shell | `ExecutePowershell`, `ExecuteShell`, launch line |
| T1529 | System shutdown/reboot | `PcShutdown`, `PcReboot`, `PcLogout` |
| T1498.001, T1499.002 | Direct network flood, service exhaustion flood | `NetTaskA` to `NetTaskK` |

## Ending

BotHelper ships nine anti-VM tests and turns none of them on, a disguised AMSI patch that its own CLR flags keep from running, and a certificate it never reads. It is a half-finished client.

What it does use is plain: a scheduled task called `Crash` every 30 minutes, an `HKCU\Google` key, a log file in `%TEMP%` that narrates every step, and eleven floods with the group name in the payload. For a defender the task and the log file are the quickest things to check, and removing the RAT means deleting the task and `Crash.exe` along with `msedge_proxy.exe`.

## Credits and further reading

- Point Wild Lat61, Prathamesh Shingare and Kedar Shashikant Pandit: [BotHelper RAT: From Encrypted Payload to Live Screen Surveillance](https://www.pointwild.com/threat-intelligence/bothelper-rat-from-encrypted-payload-to-live-screen-surveillance/) (2026-09-24), which found and named the family and published both hashes.
- Samples from Hybrid Analysis: [stager](https://www.hybrid-analysis.com/sample/8f39fe882e45dfa8a7446d59dfef86b583a868ff846ade86124a57041f5c63fd) and [RAT](https://www.hybrid-analysis.com/sample/0d41ce75da4f3404734358411a72ffc4169376dcfebda52ac50eb66eac73d2f6).
- Sekoia: [DcRat YARA rule](https://github.com/SEKOIA-IO/Community/blob/main/yara_rules/rat_win_dcrat_qwqdanchun.yar), for the shared anti-VM method names.
