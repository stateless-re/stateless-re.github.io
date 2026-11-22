---
title: "Lotuslite V2 talks to port 53 without speaking DNS"
date: 2026-11-22T15:24:39+00:00
slug: "lotuslite-v2-pro1"
description: "Four fake PDFgear CommonLib.dll builds: an RSA-wrapped AES-GCM protocol sent raw over UDP/53, two commands, and a C2 missing from the public report."
tags: ["lotuslite", "mustang-panda", "dotnet", "dll-sideloading", "ppid-spoofing", "c2-protocol"]
sample:
  family: "Lotuslite V2 (fake PDFgear CommonLib.dll)"
  sha256: "4748571d98c6af34f4967a3886f73b4421239a1203f048140d3bfdaf8aa78937"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/4748571d98c6af34f4967a3886f73b4421239a1203f048140d3bfdaf8aa78937/)"
scope: medium
toc: true
---

Lotuslite V2 is a .NET backdoor that poses as PDFgear's `CommonLib.dll`. Its first channel is UDP port 53, but nothing it sends there is DNS. Every datagram starts with the four bytes `PRO1`.

Behind that header is a careful protocol: a fresh AES-256 key per session, wrapped with an RSA-2048 key built into the DLL. The operator gets much less than the protocol suggests: shell commands (through `cmd.exe` by default) and file writes.

[Antares Research](https://antares-research.com/reports/lotuslite-v2/) (Kyaw Pyiyt Htet and Phyo Paing Htun) published Lotuslite V2 on November 15 and attributed it to Mustang Panda. They gave the XOR key, two C2 addresses, the `PRO1` magic and the use of AES-256-GCM, but no key exchange, header layout or command list. Their `CommonLib.dll` and three sibling builds are on MalwareBazaar.

## What I found

- The session key is random, sent once under RSA-OAEP, and every frame after login is AES-256-GCM, with a nonce built from header fields.
- UDP/53 carries raw protocol frames. A DNS parser reads the login as transaction ID `0x5052` with 257 questions.
- There are two capabilities: `cmd.exe /c` with output returned through a temp file, and file writes up to 10 MiB. There is no file download.
- Three of the four builds use a first C2, 139.84.169[.]184, that isn't in the report. All four share the second C2 and one RSA key.
- `cmd.exe` children get `explorer.exe` as their parent through PPID spoofing in three builds. The fourth patches ETW and AMSI instead.

![Flow from the lure ZIP through the signed PDFgear host, the fake CommonLib.dll's copy-and-relaunch, to the UDP/53 or WSS C2](/img/lotuslite-v2-pro1/chain.svg "The chain in the CommonLib.dll build")

The first run copies files and sets autorun. The second starts the backdoor.

## A fake library that does nothing until one call

The lure ZIP holds a signed PDFgear executable renamed after the lure, plus `CommonLib.dll`. Antares labels one hash for both the lure EXE and the staged `RegExt.exe`, so it is copied unchanged, and they call it a signed PDFgear executable. The .NET loader looks for `CommonLib.dll` next to it and finds the attacker's copy.

The attacker's `CommonLib.dll` claims to be "PDFgear Common Library", version 2.1.18.0. It has no module initializer and no entry point. It carries empty stubs for the PDFgear API the host calls: `AppManager.GetDefaultFileExts` returns an empty array, `ShellHelper.UpdateFilePinState` returns `true`, and so on. One stub does something:

```csharp {title="CommonLib.Config.SqliteUtils"}
public static void InitializeDatabase(string dbPath)
{
    BeCtrlBootstrap.EnsureStarted();   // (1)
}
```

Line (1) is the only caller of the backdoor's bootstrap in all four builds, so the host must call `SqliteUtils.InitializeDatabase`, presumably early at startup. In the 2.1.18.0 builds the backdoor is 72 top-level types in the `BeCtrl` and `Protocol` namespaces, plus a few in the global one. ILRepack merged in the .NET support libraries. No obfuscator was used, and the names are intact.

### First run: copy, autorun, relaunch, exit

`Persistence.Install` runs first. If the DLL is not yet in `%ProgramData%\Microsoft\DeviceSync`, it copies the host process's main module there as `RegExt.exe`, copies itself next to it, sets autorun, starts the copy and calls `Environment.Exit(0)`.

The report says "the executable creates a staging directory" and drops both files. The bytes that do it are in the DLL. The EXE is unmodified PDFgear code that happens to be running it.

Autorun depends on the account. Both values hold the path of the copied `RegExt.exe`:

| account | key and value |
|---|---|
| SYSTEM | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, value `PDFgear DeviceSync` |
| other | `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, value `Load` |

`Load` is a legacy autostart value. Unless the account is SYSTEM, the relaunch goes through `ExplorerLauncher.Start` (see below).

On the second run the folder matches, so `Install` returns false. The bootstrap then takes a mutex named `Local\` or `Global\PDFgear_DeviceSync_Mutex` and starts a foreground thread called `ConfigSyncWorker`.

## The configuration is five XOR'd strings

`BeCtrl.Config.ClientDefaults` holds the configuration. Its strings are byte arrays decoded by `c ^ 0x55`, as Antares said. Decoded from the CommonLib.dll build:

| setting | value |
|---|---|
| server IPs | 31.59.184[.]185, 103.175.50[.]32 |
| UDP ports | 53 |
| WSS ports | 443, 80, 22, 21, 8080, 1080 |
| order | UDP first, then WSS, for each IP in turn |
| skip TLS validation | true |
| reconnect backoff | 1, 3, 5, 10, 30 s |
| default command | `C:\Windows\System32\cmd.exe` |
| state dir | `C:\ProgramData\MSICache` |
| log dir, logging | `C:\ProgramData\MSICache\logs`, off |

Each (IP, protocol, port) try gets 2 seconds to connect and 2 more to log in. The WSS transport connects to `wss://<ip>:<port>/`, an IP literal, so there is no host name to send as SNI. It also replaces `ServicePointManager.ServerCertificateValidationCallback` with one that accepts everything, for the whole PDFgear process.

## Every frame has a 36-byte header

`Protocol.ProtoHeader` writes all fields big-endian:

![Byte layout of the 36-byte PRO1 header: magic, version, message type, flags, session ID, message ID, sequence, total, payload length, header CRC32](/img/lotuslite-v2-pro1/header.svg "The PRO1 frame header")

After the header comes the payload, then a CRC-32 of the payload (standard reflected CRC-32, the same as `zlib.crc32`). The flags are `Encrypted` (1), `AckReq` (4), `LastChunk` (8) and `IsAck` (0x10). Message types below 0x80 are the implant's, and types from 0x80 up are the server's.

| type | dir | meaning | payload |
|---|---|---|---|
| 0x01 | out | Login | RSA block + GCM client info (below) |
| 0x02 | out | heartbeat | u64 uptime ms, u32 1 |
| 0x10 | out | command output chunk | ref MsgId, exit code, ms, stream, data |
| 0x11 | out | command error | ref MsgId, u16 error, ms, reason |
| 0x20–0x23 | out | upload accepted / chunk ack / done / error | |
| 0x81 | in | LoginOK | session ID, server version, heartbeat, chunk sizes |
| 0x82 | in | heartbeat | |
| 0x90 | in | run command | path, line, timeout, work dir, capture mode |
| 0xA0–0xA3 | in | upload start / data / end / cancel | |

### Login wraps a fresh key with RSA

`LoginCodec.EncodeLogin` draws 32 random bytes for an AES key and 12 for a nonce. It encrypts the 44 bytes with RSA-OAEP (SHA-256), using the public key in the resource `BeCtrl.Keys.public.pem`.

| offset | size | field |
|---|---|---|
| 0 | 2 | `0x0100` (RSA block length, 256) |
| 2 | 256 | RSA-OAEP(key ‖ nonce) |
| 258 | 4 | client info length |
| 262 | n | AES-256-GCM(client info), AAD = header bytes 0–31 |
| 262+n | 16 | GCM tag |

The client info is a u32 `1`, the machine name and `RuntimeInformation.OSDescription` (each with a u16 length in front), and a 32-byte fingerprint. The fingerprint is SHA-256 over a NIC's MAC address, a zero byte, and the C: volume serial as eight hex digits.

The login header is fixed except for `PayloadLen`, which is 318 plus the lengths of the two strings. For a machine called `DESKTOP-01`, the first 36 bytes on UDP/53 would be:

```hexdump {title="Login header (synthetic machine name)"}
00000000: 50 52 4f 31 01 01 00 01 00 00 00 00 00 00 00 00  PRO1............
00000010: 00 00 00 01 00 00 00 00 00 00 00 01 00 00 01 65  ...............e
00000020: 25 a2 cf 7b                                      %..{
```

I built that from the encoder's logic with a placeholder name and OS string, so only the `PayloadLen` and CRC bytes depend on them. To a DNS parser, this is transaction ID `0x5052` with flags `0x4F31`, 257 questions and one answer. A sensor that alerts on malformed DNS should flag it. One that only logs parsed queries may not record it at all.

### After login, the nonce comes from the header

The server answers with LoginOK, encrypted under the session key. The client checks the session ID, a result byte of 0, server version 1, and sane heartbeat and chunk sizes.

Every later frame uses AES-256-GCM with that key. The 12-byte nonce is the low 32 bits of the session ID, then MsgId, then Seq. The AAD is the first 32 header bytes. The client counts MsgId up from 1, and a 1,024-entry replay window drops repeats.

The RSA private key is not in the DLL, so captured traffic can't be decrypted from the sample. An exception string in the 2.1.18.0 builds describes the other end: `Server uses .NET 8`.

## Two capabilities: run a command, write a file

The router acts on three kinds of server message: heartbeat, command and upload.

### Commands go through cmd.exe and a temp file

A command request carries a program path (`cmd.exe` if empty), a command line, a timeout (default 30 s), a working directory and a capture mode. The executor builds one of three argument shapes. Merged mode, the default:

```csharp {title="CmdExecutor.BuildArgs (merged mode)"}
"/c " + cmdLine + " > \"" + stdoutPath + "\" 2>&1"
```

`stdoutPath` is `%TEMP%\` plus 12 hex characters from a GUID, and a random `.tmp`, `.dat` or `.log` extension. Stdout-only mode drops the `2>&1`, and split mode adds a second file for stderr. After the process exits, the executor reads the file, deletes it, and sends the text back in chunks.

In the 2.1.18.0 builds the process starts through `ExplorerLauncher.Start`. It opens the first `explorer.exe` with `PROCESS_CREATE_PROCESS` and calls `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` and flags `0x08080000`, which is `CREATE_NO_WINDOW` plus `EXTENDED_STARTUPINFO_PRESENT`. In a process tree, the operator's commands appear as children of Explorer that redirect output into `%TEMP%`.

### Uploads write files; nothing sends them back

"Upload" means operator to implant. `UploadStart` gives a size (at most 10,485,760 bytes), chunking, an absolute target path without `..`, a SHA-256 and an overwrite policy (reject, force, or rename `a.exe` to `a.exe.1`). Chunks go to `<target>.tmp`, and the file is moved into place only if the hash matches.

There is no download message. To steal a file, the operator has to push it through command output, with `type`, `certutil -encode` or something similar.

## Four builds, two first C2s, one RSA key

The three other uploads share the protocol, the XOR key, the WSS ports and the RSA key (SPKI SHA-256 `544babf3…`). They differ in the first C2 and in the parts that touch the host:

| build | version | first C2 | folder | autorun | instance lock |
|---|---|---|---|---|---|
| 4748571d | v2.1.18.0 | 31.59.184[.]185 | `%ProgramData%\Microsoft\DeviceSync` | HKLM Run or HKCU `Load` | `PDFgear_DeviceSync_Mutex` |
| aa424e71 | v2.1.18.0 | 139.84.169[.]184 | same | same | same |
| 486119e4 | v2.1.18.0 | 139.84.169[.]184 | `%LOCALAPPDATA%\PDFgear\Services` | HKCU Run `PDFgear FileSync` | event `Local\PDFgear_ConfigSync_Instance` |
| 45095e85 | v2.1.16.0 | 139.84.169[.]184 | `%LOCALAPPDATA%\RegExt` | task `RegExtRegistrationTask`, else Startup `RegExt.lnk` | event `Event_441ACBAF4218359F0B566A13AC9A9AB0_104` |

All four have 103.175.50[.]32 as the second C2. In decompiled source, `aa424e71` differs from the report's DLL only in the first IP string.

The 2.1.16.0 build has no PPID spoofing, so its commands are children of `RegExt.exe`. It uses .NET's `RSA.Encrypt` instead of raw BCrypt and stubs fewer PDFgear methods. Its task repeats every five minutes as "Maintains PDFgear file type registrations."

I first wrote that this build was the plainer one. My diff listing had been cut at 30 lines, and the file it hid was `RuntimeInit.cs`. In the other three builds `RuntimeInit.Apply` is empty. In this one it runs before the worker thread starts and patches two functions in memory:

```csharp {title="RuntimeInit.Apply (45095e85)"}
Overwrite("ntdll.dll", "EtwEventWrite", new byte[3] { 49, 192, 195 });
Overwrite("amsi.dll", "AmsiScanBuffer", new byte[6] { 184, 87, 0, 7, 128, 195 });
```

`31 C0 C3` is `xor eax, eax; ret`, so the process stops writing ETW events. `B8 57 00 07 80 C3` makes `AmsiScanBuffer` return `0x80070057` (`E_INVALIDARG`) without scanning. `Overwrite` uses `GetModuleHandle`, so the AMSI patch only lands if `amsi.dll` is already loaded. The [ANY.RUN run](https://app.any.run/tasks/01b82551-c491-4ed1-9e17-e6df28b2def9) linked from Bazaar's record had already tagged this file `amsi-bypass`.

I took the lower version number to mean the older build. ReversingLabs' first-seen dates, as Bazaar shows them, say otherwise: `486119e4` on September 16, `aa424e71` on September 24, `4748571d` on October 12, and `45095e85` on November 5.

I think the version is copied from whichever PDFgear release the build imitates. The stub sets point the same way: a host that calls a missing method fails with `MissingMethodException`, so each build probably stubs what its host release calls.

Two builds (`45095e85`, `486119e4`) turn on "last channel memory". After a successful login they write `C:\ProgramData\MSICache\last_channel.json` with `server_ip`, `protocol`, `port` and `updated_utc`, and try that channel first next time. On those hosts, the file says which C2 worked.

## The extractor

[`families/lotuslite`](https://github.com/stateless-re/tools/tree/main/families/lotuslite) in the tools repo evaluates the IL of the two configuration methods without loading the DLL. It prints the configuration, the RSA key fingerprint, and the lock and persistence strings as JSON, and gives the values above for all four builds.

```console {title="Trimmed"}
$ python -I extract.py 4748571d...937.exe
    "xor_key": "0x55",
    "config": {
      "ServerIps": [
        "31.59.184.185",
        "103.175.50.32"
      ],
      "spki_sha256": "544babf3c6485418c35f8db11f1110e70e06af78f690d556beec1d6008eb1df6",
```

## What I couldn't determine

Antares says `RegExt.exe` points the open command of PDFgear's document ProgID at `DeviceSync\PDFLauncher.exe`. None of the four DLLs contains `PDFLauncher` or the ProgID's name, in ASCII or UTF-16. The methods the fake stubs out are PDFgear's file-association helpers. I suspect the ProgID write is the real `RegExt.exe` doing its own job from its new folder, but I didn't have the host to check.

The nonce has no direction bit, and both sides encrypt with one key. If the server also numbers its messages from 1, the two directions reuse GCM nonces. The client code can't settle that.

The lure ZIP and the host EXE are not on MalwareBazaar or Hybrid Analysis. Bazaar's record links an [ANY.RUN run](https://app.any.run/tasks/b4c1b80f-b06f-4fae-9348-0fc20a986536) and a CAPE analysis of the ZIP, which I didn't use. What the operator ran on real victims is unknown.

## Indicators

| SHA-256 | role |
|---|---|
| `4748571d98c6af34f4967a3886f73b4421239a1203f048140d3bfdaf8aa78937` | CommonLib.dll v2.1.18.0 (Antares sample) |
| `aa424e71f1c25d2455e14dadae35b380950dd4c73988183e7df88e1ed67e4d27` | CommonLib.dll v2.1.18.0 |
| `486119e45dadf2b3bafd974e0ea5e1e8e8bc35be320649bfb03ceb12406e7dcd` | CommonLib.dll v2.1.18.0, PDFgear\Services |
| `45095e850d54f5ccf0ca20527ec6f8aed6d5d8eaa3a002255cea06c87627dd48` | CommonLib.dll v2.1.16.0, scheduled task |

Network: 31.59.184[.]185, 139.84.169[.]184, 103.175.50[.]32, on UDP 53 and TCP 443, 80, 22, 21, 8080 and 1080 (WSS). The first bytes of every frame are `50 52 4F 31 01`.

Host:

- `%ProgramData%\Microsoft\DeviceSync\RegExt.exe` and `CommonLib.dll`; `%LOCALAPPDATA%\PDFgear\Services\`; `%LOCALAPPDATA%\RegExt\`
- `C:\ProgramData\MSICache\last_channel.json`
- Run values `PDFgear DeviceSync` (HKLM), `PDFgear FileSync` (HKCU); HKCU `...\Windows NT\CurrentVersion\Windows\Load`
- Task `RegExtRegistrationTask`; Startup `RegExt.lnk`
- `cmd.exe /c … > "%TEMP%\<12 hex>.tmp|dat|log"` with `explorer.exe` as the parent
- RSA public key SPKI SHA-256 `544babf3c6485418c35f8db11f1110e70e06af78f690d556beec1d6008eb1df6`

## ATT&CK

| ID | technique | here |
|---|---|---|
| T1574.001 | Hijack Execution Flow: DLL | fake `CommonLib.dll` beside the signed PDFgear host |
| T1547.001 | Registry Run Keys / Startup Folder | Run values, `Windows\Load`, Startup `RegExt.lnk` |
| T1053.005 | Scheduled Task | `RegExtRegistrationTask`, every 5 minutes (v2.1.16.0) |
| T1134.004 | Parent PID Spoofing | `cmd.exe` and the relaunch under `explorer.exe` |
| T1059.003 | Windows Command Shell | `cmd.exe /c` with output to `%TEMP%` |
| T1095 | Non-Application Layer Protocol | raw `PRO1` frames on UDP/53 |
| T1573.002 | Asymmetric Cryptography | RSA-OAEP-wrapped session key |
| T1027 | Obfuscated Files or Information | XOR 0x55 configuration strings |
| T1562.001 | Disable or Modify Tools | ETW and AMSI patches (v2.1.16.0) |

The backdoor puts its effort into the transport: RSA, GCM, replay windows, CRCs on the header and the payload. Then it hands the operator a command line and a file writer. For a defender, the parts it can't hide are the plainest ones: datagrams to port 53 that begin `PRO1`, and Explorer starting `cmd.exe` with output redirected into `%TEMP%`.

## Credits

- Kyaw Pyiyt Htet (Mikoyan) and Phyo Paing Htun (ChiLai), [Antares Research](https://antares-research.com/reports/lotuslite-v2/): discovery, the chain, the XOR key, two C2s, the mutex and the Mustang Panda attribution.
- smica83 uploaded the CommonLib.dll build to MalwareBazaar (tagged CtrlNET), and KodaDr the three others ([tag LotusLite](https://bazaar.abuse.ch/browse/tag/LotusLite/)).
