---
title: "2CLoader keys its payload to its own padding"
date: 2026-11-13
description: "Twelve 2CLoader builds unpacked without running one: how the builder rewrites the gaps between functions so every build gets a different AES key, what the 18 identity hooks fake, and two YARA rules."
tags: ["2cloader", "loader", "config-extraction", "yara", "windows"]
sample:
  family: "2CLoader"
  sha256: "0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6/)"
toc: true
---

2CLoader derives the AES-256 key for its payload from the SHA-256 of its own code section, and its builder changes that hash for every build by rewriting the padding between functions. Across 11 builds with the same code layout, 1,644 byte positions differ, and every one of them sits in a gap that a compiler would have filled with `CC`. The gaps hold randomly chosen NOP instructions, XORed with a one-byte key so they don't look like NOPs.

Zscaler ThreatLabz [described 2CLoader](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus) on September 30, 2026, with the config layout, the decryption steps and 20 hashes. The report doesn't say how two builds of the same loader end up with different keys, lists only some of the API hooks, and has no detection rules. Twelve of the 20 hashes are on MalwareBazaar. I pulled all twelve and worked through them statically; nothing was executed. My notes list no family before this one, so this is the first real sample on the blog.

## What I found

- All twelve files are the same loader stub (one import hash, `905d6e2fd95bb9d68bb959ec7e8cfb12`). Eleven have byte-identical `.rdata` and `.data` sections and differ only in 266 padding gaps in `.text`.
- The padding is NOP encodings XORed with one byte. That byte is the string key XOR 0x44 in both stub versions I have (0x37 and 0x73, 0x9e and 0xda).
- The config field `bt` is a Unix build time. The PE timestamps are random (1989 to 2105), but `bt` precedes the MalwareBazaar first-seen time in every sample, by under 5 minutes in one case.
- The 18 identity hooks cover more than names and registry values: SMBIOS tables, disk model and serial, MAC addresses and the display adapter string are rewritten too, from a generator seeded with the process ID and tick count.
- The C2 channel is one-way. The loader posts progress reports and never reads a response body. None of the twelve builds turns on the anti-VM, anti-debug or user-activity checks.

## Twelve files, one stub

Triage looks the same for every file: x64, seven sections, MSVC runtime strings, and one resource of type 88, name 521, with entropy 8.00. The code section is 0x1a1b1 bytes in eleven samples and 0x1a1c1 in the oldest one.

The headers lie. Every sample has a different `TimeDateStamp`, from 1989 to 2105, and a different linker version, from 14.13 to 16.37. Version resources and icons are cloned from legitimate software: Easy Anti-Cheat Service in 7 samples, Clownfish Voice Changer in 3, .NET Host and Windows Error Reporting in 1 each. Ten of the twelve also carry an Authenticode blob copied from a legitimate file. None verifies:

```
00178211  signer: O=EasyAntiCheat Oy          verify: BAD_DIGEST|BAD_SIGNATURE
06185d74  signer: O=Microsoft Corporation, CN=.NET   verify: BAD_DIGEST|BAD_SIGNATURE
1337ed6f  signer: CN=<individual developer>   verify: BAD_DIGEST|BAD_SIGNATURE
066d83b9  unsigned
```

That is LIEF's check of the signed digest against the file's real Authenticode hash, for four of the twelve (eight use the EasyAntiCheat blob). The signers have nothing to do with the malware. The third is a private developer whose name I've left out. All three signatures were lifted from their own files and pasted onto one they don't match. One sample wears Windows Error Reporting version info under an EasyAntiCheat signature, which no real file would.

## The config sits in the last 0xDC bytes of the resource

The loader calls `FindResourceW(module, 0x209, 0x58)`, checks that the resource is larger than 0xEB bytes, and reads a 0xDC-byte structure from its end. ThreatLabz published the layout and it parses all twelve samples. Here it is with offsets, values from the sample in the box above, and the three fields the report left unexplained.

| Offset | Size | Field | Value in `00178211` |
|---|---|---|---|
| 0x00 | 4 | magic | `2C 3D 4E 5F` |
| 0x04 | 4 | execution flags (`fl`) | 0 |
| 0x08 | 4 | encrypted payload size | 515,731 |
| 0x0c | 4 | GCM nonce size | 12 |
| 0x10 | 4 | GCM tag size | 16 |
| 0x14 | 12 | GCM nonce | `d6736f52a855265e25c2e3c0` |
| 0x20 | 16 | GCM tag | `e880b363c85d5c9b04166c4fe5ce58eb` |
| 0x30 | 16 | key mask, low half | `b516699fc392f936613e454da361071e` |
| 0x40 | 16 | key mask, high half | `931eda37165676f5e5649dec8f4c6e1b` |
| 0x50 | 4 | byte sum of the key | 0x1159 |
| 0x54 | 4 | persistence flags | 0x3f |
| 0x58 | 4 | option flags | 0x80 |
| 0x5c | 4 | size of optional dropped file | 0 |
| 0x60 | 4 | size of message box text | 0 |
| 0x64 | 1 | XOR layer 2 step | 189 |
| 0x65 | 1 | XOR layer 2 start | 32 |
| 0x66 | 1 | XOR layer 1 start | 195 |
| 0x68 | 4 | initial sleep, ms | 0 |
| 0x6c | 16 | build ID | `ae9f0bca47ec1659a1be92c19bbb4e83` |
| 0x7c | 64 | injection target | `dllhost.exe` |
| 0xbc | 4 | `bt` | 1788090685 |
| 0xc0 | 16 | `pn` | `build_tbuild.exe` |
| 0xd4 | 4 | task interval, hours | 7 |
| 0xd8 | 4 | decompressed payload size | 1,357,312 |

`bt` is a Unix timestamp: 1788090685 is 2026-08-30 11:51:25 UTC, and MalwareBazaar first saw this file at 15:31:44 the same day. The pattern holds for all twelve. `bt` is always earlier than first-seen, by 4 minutes 49 seconds at the shortest, and by less than 6.5 hours in eleven of twelve. Since the PE timestamp is random, `bt` is the only honest date in the file. The loader sends it home in its first report.

`pn` is 16 bytes and holds a file name: `default.exe` in 4 samples, `build_sbuild.exe` in 4, `build_tbuild.exe` in 3, `build.exe` in 1. I read it as the name of the payload file the operator fed to the builder, because it tracks the payload: all four `default.exe` builds carry a payload of about 225 KB, and all the `build*` ones carry 1.1 to 1.4 MB.

The hours field drives a second scheduled task. The strings next to its only user are a task XML with a `TimeTrigger`, a `<Repetition><Interval>` filled from the format `PT%uH`, the task name `WindowsSecurityHealth`, and a fallback command line `/create /sc HOURLY /mo`. So besides the logon task the report describes, the loader re-runs itself every 3, 6 or 7 hours in these samples.

## The key is a hash of the loader's own code

The decryption routine hashes the first executable section of the running image with SHA-256 (through BCrypt), XORs the digest with the two masks from the config, and compares the byte sum of the result with the stored sum. Variables are renamed and the SIMD expansion of the sum is collapsed:

```c
key[0..15]  = digest[0..15]  ^ cfg.mask_lo;      // (1)
key[16..31] = digest[16..31] ^ cfg.mask_hi;
if (sum_of_bytes(key) == cfg.key_sum) {          // (2)
    plain = aes_gcm_decrypt(key, 32, cfg.nonce, cfg.nonce_size,
                            body, body_size, cfg.tag, cfg.tag_size, &out_size);
    report("aes");
} else {
    report("seed");                              // (3)
}
```

At (1) the code hash becomes the key. At (2) a 32-bit sum catches a wrong key before AES runs, and (3) tells the operator the stub was modified. Patch one byte of `.text`, a breakpoint for instance, and the payload doesn't decrypt.

One detail matters if you reimplement this. The hash covers the section's `VirtualSize` (0x1a1b1 bytes), not its raw size on disk (0x1a200). I computed both for each file. The raw-size digest failed the byte-sum check in all twelve and the virtual-size digest passed in all twelve. For `00178211`:

```
SHA-256(.text[0:0x1a1b1]) = 3d591e0a9090bc6a036992b24ccf98594c653c4965e1b03fa61e2c164f08786f
key                       = 884f77955302455c6257d7ffefae9f47df7be67e73b7c6ca437ab1fac0441674
```

The first line is the code hash, the second is the hash XORed with the masks at 0x30 and 0x40. The byte sum of the key is 0x1159, as the config says.

## The builder rewrites the gaps between functions

If the key is a hash of the code and the code is the same stub every time, every build would share one key, unless the masks alone did the work. They don't. The code hash is different in all twelve files, so something changes `.text` per build.

I diffed the sections of the eleven same-size samples against each other. `.rdata` and `.data` came back identical. `.text` differed in about 1,000 bytes per pair, in short runs at the same addresses. Here is one of those runs in three builds, and the same gap in the oldest build, each starting right after a `ret`:

```
build      bytes after C3 at 0x140001955     same bytes XOR key
00178211   7c 6c f3 73 73 73 73 15 e3 e3     0f 1f 80 00 00 00 00 | 66 90 | 90         (0x73)
066d83b9   7c 6c 33 73 15 e3 15 e3 e3 e3     0f 1f 40 00 | 66 90 | 66 90 | 90 | 90     (0x73)
0a2ef2c3   7c 6c f3 73 73 73 73 7c 6c 73     0f 1f 80 00 00 00 00 | 0f 1f 00           (0x73)
06185d74   bc 4a bc d5 c5 9e da da bc 4a     66 90 | 66 0f 1f 44 00 00 | 66 90         (0xda)
```

A disassembler shows the left column as junk (`jl`, `jae`, `insb`). XORed with 0x73 it is a sequence of standard x86 NOPs: `0f 1f 80 00 00 00 00` is the 7-byte `nop dword ptr [rax+0]`, `66 90` the 2-byte one. Each build fills the same 10-byte gap with a different random mix that adds up to 10 bytes.

My first attempt to measure this went wrong. I took the gaps between consecutive `.pdata` entries as "padding" and tried to decode them all; 94 of 263 failed. Those gaps aren't all padding: leaf functions have no unwind entry, so real code sits in some of them. Comparing builds was the better instrument. Across the eleven samples, 1,644 byte positions vary. Every varying byte is one of nine values (`15 33 37 6c 73 7c e3 f3 f7`), which are exactly the bytes of the NOP encodings XORed with 0x73. They fall in 266 gaps. One gap refused to parse, and that was my own script's fault: it had grown the region one byte too far and swallowed the `33` opcode of the next function.

For a check that needs no second sample, I decoded every run of padding that follows a `ret`. In each of the twelve files that is 181 runs and 1,211 bytes, all valid NOP sequences. None of the twelve `.text` sections contains a single `CC CC` pair, which is itself odd for MSVC output.

Why XOR the NOPs? A stretch of real NOPs between functions is rare but harmless-looking; I think the XOR is there so the filler doesn't form a recognizable byte pattern, though the nine-value alphabet it produces is just as recognizable once you know the key. The padding key is tied to the string key. (A copy of the string key sits in `.data` at RVA 0x29008; it is the only byte of `.data` that differs between the two stub versions.)

| Stub | String key | Padding key | XOR of the two |
|---|---|---|---|
| 11 builds, Aug 13 to Sep 4 | 0x37 | 0x73 | 0x44 |
| 1 build, Aug 1 | 0x9e | 0xda | 0x44 |

Two stub versions are only two data points, but 0x44 held for both.

The string key was my second wrong turn. The report gives 0x37 for the sample it analyzed, and I assumed it for every file. It held for eleven. The August 1 build decoded to garbage, because that stub uses 0x9e. Anything that matches this loader on strings XORed with 0x37 misses it.

## Unpacking twelve payloads without running one

With the key in hand, the rest follows the report. Two XOR layers come off the resource body first, then AES-256-GCM, then decompression:

```
t[i]   = body[i] ^ ((cfg[0x66] + i) & 0xff)
ct[i]  = t[i]    ^ ((cfg[0x65] + cfg[0x64] * i) & 0xff)
plain  = AES-256-GCM-decrypt(key, nonce, ct, tag)
pe     = XpressHuffman-decompress(plain)[0 : cfg[0xd8]]
```

The loader decompresses with `RtlDecompressBufferEx` and format 4 (Xpress Huffman). I wrote a decompressor from the MS-XCA specification so nothing had to be called on Windows. GCM is authenticated, so there's no guessing whether a key is right: the tag verified for all twelve, and all twelve outputs are x64 PE files.

The whole chain, from config to decrypted payload, is now a script: [`families/2cloader`](https://github.com/stateless-re/tools/tree/main/families/2cloader) in my tools repository. It prints each sample's config as JSON and, with `-o`, writes the payloads out. It uses [dissect.util](https://github.com/fox-it/dissect.util)'s Xpress Huffman decoder instead of mine; the two give identical output on all twelve.

| Loader | Built (`bt`, UTC) | `pn` | Options | Payload size | Bazaar tag |
|---|---|---|---|---|---|
| `06185d74` | 2026-08-01 17:49:18 | `build_tbuild.exe` | 0x0 | 1,165,824 | njrat |
| `24671765` | 2026-08-13 06:42:51 | `default.exe` | 0x480 | 228,352 | RemusStealer |
| `1337ed6f` | 2026-08-20 18:28:21 | `build_sbuild.exe` | 0x0 | 1,149,952 | Vidar |
| `2d43d592` | 2026-08-21 16:44:34 | `build_sbuild.exe` | 0x480 | 1,149,952 | Vidar |
| `066d83b9` | 2026-08-21 16:46:11 | `default.exe` | 0x480 | 225,280 | RemusStealer |
| `4c16f5eb` | 2026-08-25 14:02:35 | `default.exe` | 0x480 | 230,912 | RemusStealer |
| `0d2abd7d` | 2026-08-29 06:35:13 | `build_sbuild.exe` | 0x480 | 1,390,592 | Vidar |
| `30cf47ca` | 2026-08-29 06:37:04 | `default.exe` | 0x480 | 227,328 | RemusStealer |
| `00178211` | 2026-08-30 11:51:25 | `build_tbuild.exe` | 0x80 | 1,357,312 | Vidar |
| `2c786f70` | 2026-09-02 03:05:02 | `build_sbuild.exe` | 0x80 | 1,326,080 | Vidar |
| `3286ff47` | 2026-09-04 18:11:56 | `build.exe` | 0x80 | 1,392,128 | Vidar |
| `0a2ef2c3` | 2026-09-04 18:14:06 | `build_tbuild.exe` | 0x80 | 1,392,128 | Vidar |

The family tags are MalwareBazaar's labels for the loader files, not my identification of what's inside; I stopped at the loader. One label I'd distrust: the `njrat` payload is a native x64 PE with no CLR header, built with the same compiler as the Vidar-tagged ones, and njRAT is a .NET program. Builds also come in pairs about two minutes apart (August 21, August 29, September 4), each wrapping a different payload.

*Update, November 13: the payloads are now identified. Eight are Vidar and four are Remus, and the `njrat`-tagged one is Vidar 2.8; configs and C2 indicators are in [What 2CLoader delivered](/2026/what-2cloader-delivered/).*

The other config fields barely vary. All twelve have `fl` 0, persistence 0x3f (all six methods), no sleep, no dropped file, no message box, and `dllhost.exe` as the injection target. The option flags take three values: 0x480 in 6 samples, 0x80 in 4, 0x0 in 2. Using the report's flag meanings, 0x80 is parent-process spoofing and 0x400 is the API hooks. Bit 0x1 (anti-VM), 0x10 (anti-debug), 0x40 (wait for user activity) and 0x100 (lock file) are clear in every sample. The scoring anti-VM code the report walks through is in the stub, along with its lists of VM tools, sandbox DLLs and analyst user names, but no operator in this set switched it on.

## What the hooks fake

When bit 0x400 is set and the payload is mapped into the loader's own process, the stub installs inline hooks before it jumps to the payload. The report describes about six of "about 20" and says their intent is not clear. The installer hooks 18 functions; two more (`WinHttpReadData`, `InternetReadFile`) are hooked separately.

| Module | Function | What the handler changes |
|---|---|---|
| advapi32 | `RegQueryValueExW/A` | selected values, e.g. `MachineGuid`, board manufacturer (per ThreatLabz) |
| advapi32 | `GetUserNameW/A` | user name, from `admin`, `user`, `gamer`, `john`, `alex`, `player` |
| kernel32 | `GetComputerNameW/A`, `GetComputerNameExW/A` | `DESKTOP-` plus random characters |
| kernel32 | `GetEnvironmentVariableW/A` | `USERNAME` and other targeted variables (per ThreatLabz) |
| kernel32 | `GetVolumeInformationW/A` | volume serial number |
| kernel32 | `GetSystemFirmwareTable` | SMBIOS strings and system UUID |
| kernel32 | `DeviceIoControl` | disk vendor, product and serial strings |
| iphlpapi | `GetAdaptersInfo`, `GetAdaptersAddresses` | MAC address of every adapter |
| user32 | `EnumDisplayDevicesW/A` | display adapter name |
| winhttp, wininet | `WinHttpReadData`, `InternetReadFile` | IPv4 addresses in responses (per ThreatLabz) |

The firmware, disk, adapter and display rows are the ones the report doesn't cover. The disk handler shows how they work. It lets the real call run, then edits the result in place (variables renamed):

```c
BOOL hook_DeviceIoControl(HANDLE h, DWORD code, void *in, DWORD in_len,
                          STORAGE_DEVICE_DESCRIPTOR *out, DWORD out_len, DWORD *returned)
{
    BOOL ok = orig_DeviceIoControl(h, code, in, in_len, out, out_len, returned, ...);
    if (ok && out && returned && code == 0x2d1400            // (1)
           && *returned > 0x21 && out->Size <= *returned && out->Size > 0x21) {
        overwrite_string(out, out->Size, out->VendorIdOffset,     fake_vendor);   // (2)
        overwrite_string(out, out->Size, out->ProductIdOffset,    fake_model);
        overwrite_string(out, out->Size, out->SerialNumberOffset, fake_serial);
    }
    return ok;
}
```

0x2d1400 at (1) is `IOCTL_STORAGE_QUERY_PROPERTY`, the usual way to ask a disk for its model and serial. At (2) the handler overwrites the three strings a hardware fingerprint is built from. The firmware handler does the same for `GetSystemFirmwareTable` with provider `RSMB`: it walks the raw SMBIOS table, rewrites the strings of structure types 0 to 3 (BIOS, system, baseboard, chassis) and overwrites the 16-byte system UUID. The adapter handlers write a fake 6-byte MAC into every adapter, XORed with the adapter's index so two adapters don't collide.

The fake values come from pools stored XORed in `.rdata`: board vendors (`ASUSTeK INC.`, `Dell Inc.`, `Lenovo`, `Gigabyte`, `ASRock`), boards (`PRIME Z690-P`, `B550 Steel Legend`, `Z690 Master`), GPUs (`NVIDIA GeForce RTX 3060`, `NVIDIA GeForce RTX 2080`, `AMD Radeon RX` with a random model number), disks (`Samsung SSD 980 Pro`, `Seagate FireCuda 530`, `Crucial MX500`), `Windows 11 Pro`, and a BIOS date of `01/01/2024`. A linear congruential generator picks from them:

```
seed  = (GetTickCount() ^ (pid << 16) ^ 0xa5a5dead) * 0xcfdddf21 + 0xcd1dcf18
state = state * 0x41c64e6d + 0x3039        // each draw uses the top byte
```

The seed mixes the process ID and the uptime in milliseconds, so the same build on the same machine invents a different computer on every run: new name, new user, new machine GUID, new SMBIOS UUID, new MAC, new disk serial.

That gives a better guess at intent than the name hooks alone did. The hooks sit in the process the payload runs in, and the payload here is an infostealer that fingerprints its host. I think the spoofer exists so the stealer sees a plausible, never-seen-before gaming desktop wherever it lands, whether that defeats the stealer's own virtual-machine checks, per-machine deduplication on the panel, or both. I can't tell which from the loader alone. What I can say is that a hardware ID reported by a payload that came through this loader with bit 0x400 set is fiction.

## The reporting channel never reads an answer

The stub resolves seven WinHTTP functions: `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpCloseHandle` and `WinHttpSetTimeouts`. None of them reads a response body. A worker thread takes messages from a 32-slot queue and sends each as `POST /api/beacon` over TLS to `aware-cr1[.]com`, calls `WinHttpReceiveResponse`, and closes the handle. Between messages it sleeps `GetTickCount() % 450 + 50` milliseconds. If the first request can't be opened, reporting is switched off for the rest of the run.

So there is no tasking, and the question the report leaves open about the server's reply has a short answer: the loader ignores it. The body is JSON XORed with a repeating 32-byte key, `body[i] ^ key[i & 0x1f]`, the key being the one ThreatLabz published (`4a7b3c1d…bf50`, in the YARA rule below). It is identical in all twelve samples and both stub versions.

After the `start` registration, each message is a stage report: `{"id":"%s","s":"%s","ok":%d,"t":%u,"x":%u,"ec":%u,"pid":%u}`. The stage names in `s` are stored in plain text next to the code that sends them:

| `s` | Sent when |
|---|---|
| `slp` | the configured initial sleep finished |
| `vm`, `dbg`, `act` | the anti-VM, anti-debug or user-activity check ran |
| `seed` | the derived key failed the byte-sum check |
| `aes` | AES-GCM decryption ran |
| `dec` | decompression ran |
| `loadpe`, `runpe`, `fallback`, `run` | execution stage (names only; I didn't trace these call sites) |
| `wait` | just before the loader exits |

This is build telemetry for a service, with a build ID, a build time and the payload's file name in every registration. The operator can see which build died at which stage on which Windows version.

## What I couldn't determine

Eight of the 20 reported hashes aren't on MalwareBazaar, so the counts above describe twelve samples, not the family. I didn't analyze the payloads, so the family names are borrowed labels. No sample here uses the RunPE path or the .NET path (`fl` is 0 everywhere), so I took the report's description of both and of the remote-process hooks without reading that code. I don't know whether the 0x44 relation between the two XOR keys is designed or an accident of how the builder picks them. And since nothing ran, I can't say whether `aware-cr1[.]com` still answers.

## Detection

Two rules. The first keys on the config trailer: the magic, then the two constant size fields (12 and 16) at +0x0c, anchored to the last 0xDC bytes of a PE resource. It doesn't depend on code or strings, so it should survive a stub rebuild as long as the format does.

```yara
import "pe"

rule TwoCLoader_Config_Trailer
{
    meta:
        description = "2CLoader: 0xDC-byte config trailer at the end of the payload resource"
        reference = "https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus"
        sample = "0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6"
    strings:
        // magic, fl, payload size, nonce size 12, tag size 16
        $cfg = { 2C 3D 4E 5F ?? ?? ?? ?? ?? ?? ?? ?? 0C 00 00 00 10 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0 .. pe.number_of_resources - 1) : (
            pe.resources[i].length > 0xEC and
            $cfg at (pe.resources[i].offset + pe.resources[i].length - 0xDC)
        )
}
```

The second rule matches the stub. The telemetry key and the two report formats are stored in plain text. The remaining strings are XORed with a per-version key, so the rule uses YARA's `xor` modifier and doesn't assume 0x37.

```yara
rule TwoCLoader_Loader_Code
{
    meta:
        description = "2CLoader: telemetry key, report format and XOR-encoded strings in the loader stub"
        reference = "https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus"
        sample = "0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6"
    strings:
        $key  = { 4A 7B 3C 1D 8E 5F A0 D1 62 93 24 F5 B6 47 C8 09 E1 72 53 84 35 A6 D7 18 49 FA 0B 6C 9D 2E BF 50 }
        $json = "{\"id\":\"%s\",\"s\":\"start\",\"ok\":1,\"t\":0,\"os\":[%u,%u,%u]" ascii
        $evt  = "{\"id\":\"%s\",\"s\":\"%s\",\"ok\":%d,\"t\":%u,\"x\":%u,\"ec\":%u,\"pid\":%u}" ascii
        $x1 = "SecurityHealthService.exe" xor(0x01-0xff)
        $x2 = "WindowsSecurityHealth" xor(0x01-0xff)
        $x3 = "UserInitMprLogonScript" xor(0x01-0xff)
        $x4 = "GetSystemFirmwareTable" xor(0x01-0xff)
        $x5 = "NtUnmapViewOfSection" xor(0x01-0xff)
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and
        ( $key or ( 1 of ($json, $evt) and 2 of ($x*) ) or 4 of ($x*) )
}
```

Both rules match all twelve loaders, and every string in the second rule hits in both stub versions. Neither matches the twelve unpacked payloads. For false positives I only had the 2,090 PE files that ship with the .NET SDK, Mono and the other tools on the bench, with no hits; that is not a Windows install, so test against your own corpus before alerting on these.

For hunting on a host, the strings give these:

- A Run or RunOnce value, or a scheduled task, named `SecurityHealthService.exe` that points outside `System32`, and a task named `WindowsSecurityHealth` with an hourly repetition.
- `schtasks.exe /create /tn … /xml` with an XML file named `~st` plus 8 hex digits and `.xml`.
- `HKCU\Environment\UserInitMprLogonScript` or the `Load` value under `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows` being set at all.
- A non-browser process posting `application/octet-stream` to `/api/beacon` with a Chrome 127 user agent.
- Statically: an x64 PE whose Authenticode digest doesn't match, and whose `.text` has no `CC CC` anywhere. Either is weak alone; together they are worth a look.

## Indicators

| SHA-256 | Role |
|---|---|
| `06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e` | loader, built 2026-08-01, string key 0x9e |
| `246717653bc2ae2e09036bac56c9d79940c652972a73f4c6aa9b925c28cce095` | loader, built 2026-08-13 |
| `1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb` | loader, built 2026-08-20 |
| `2d43d592630ad1e012da63ef7279f95dd4a8e94964e12ca2f996051875574fa6` | loader, built 2026-08-21 |
| `066d83b98a2081e0bb075c94376aebc9b0fd6499025cab1762d83bbb4d7576c6` | loader, built 2026-08-21 |
| `4c16f5ebd5c633b7a793ffa2cd96daddc5a503d82ed4fbe636109d89164ec02b` | loader, built 2026-08-25 |
| `0d2abd7d872196abd951f1d7ed6406486499e5d5acc04f28fcd4f45b1851711e` | loader, built 2026-08-29 |
| `30cf47caf9700a74a8ea4a728b8b7c88cb1f8e22261b4ac01575b112c1e224ca` | loader, built 2026-08-29 |
| `0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6` | loader, built 2026-08-30 |
| `2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b` | loader, built 2026-09-02 |
| `3286ff477ccd888479b96d0ffb2bd53962862db7267a4bd1c8d8f8c22fec63d4` | loader, built 2026-09-04 |
| `0a2ef2c360cf6e3e3e5d844ca03fecc31924ba0e8c3ecd8aefa778cae10fb19e` | loader, built 2026-09-04 |
| `b47ac295ab1668d8dd8a767934cb5c6dd263712d0b8ad10b8ca097b9f6a44fca` | payload unpacked from `06185d74` |
| `d488a4b0e6837264517b81596ce5d6fbbc61d3ef68d938c0e0d7b9a9a1915f26` | payload unpacked from `24671765` |
| `2386a9d42404cf0151799ed91a700b4b397ec0ffdc619f8a2b1faf6b21a97122` | payload unpacked from `1337ed6f` |
| `dbe69ce36fbddc64a9db7bda8ebcfd09e7c1a4afe058bef4aff20162a11dc0d1` | payload unpacked from `2d43d592` |
| `8696940855d849d5d6aa1a52896855082bde0fa76da23cdaeca028a5493d4fb1` | payload unpacked from `066d83b9` |
| `4713985869f284136d2d9f9c98a1cd43c2f327a7619d829e31fc69c3589f56cb` | payload unpacked from `4c16f5eb` |
| `2388fdb0911403d553fe7d3c72aa949cc49e7ecd7acd5cc357645429c51e7217` | payload unpacked from `0d2abd7d` |
| `6f3e8965f7cb3d800ca06482ebf3800f6873ab88078d8735c416aa25b81179d6` | payload unpacked from `30cf47ca` |
| `ad9d1679fb2f90477fe8e81a4be51566b84f154eb3f2b7200a7b0faca0715636` | payload unpacked from `00178211` |
| `90d24c7650a3fb563e381c87dc597281f0f4463f032d09a2b4759e5c7093e8ff` | payload unpacked from `2c786f70` |
| `b5236f9b957ca98c643c423601a4399a8cfece061dbead26fd147e5d8cbbd7e8` | payload unpacked from `3286ff47` |
| `99d6a4544b0b3ed39fbe0d2298d7019ccf2d662555f8cf7956730984edfaff01` | payload unpacked from `0a2ef2c3` |

None of the twelve payload hashes was on MalwareBazaar when I checked.

| Indicator | Type |
|---|---|
| `aware-cr1[.]com` | telemetry host, all twelve samples |
| `hxxps://aware-cr1[.]com/api/beacon` | telemetry URL |
| `905d6e2fd95bb9d68bb959ec7e8cfb12` | import hash of the stub, all twelve samples |
| `SecurityHealthService.exe`, `WindowsSecurityHealth` | persistence names |

The eight hashes from the report that I could not obtain, and the in-the-wild download URL, are in the [ThreatLabz post](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus).

## ATT&CK

| ID | Technique | In these samples |
|---|---|---|
| T1027.013 | Encrypted/Encoded File | payload in a resource under two XOR layers, AES-256-GCM and Xpress Huffman |
| T1027.001 | Binary Padding | inter-function padding replaced with encoded NOPs to change the code hash per build |
| T1140 | Deobfuscate/Decode Files or Information | key derived at run time from the SHA-256 of `.text` |
| T1036.001 | Invalid Code Signature | Authenticode blobs copied from legitimate files, 10 of 12 samples |
| T1036.005 | Match Legitimate Resource Name or Location | cloned version info; persistence named `SecurityHealthService.exe` |
| T1620 | Reflective Code Loading | payload mapped in the loader's own process (`fl` 0 in all twelve) |
| T1134.004 | Parent PID Spoofing | option 0x80 set in 10 of 12 samples (meaning per ThreatLabz) |
| T1547.001 | Registry Run Keys / Startup Folder | persistence bits 0x1, 0x2, 0x8, 0x10 set in all twelve |
| T1053.005 | Scheduled Task | logon task, plus `WindowsSecurityHealth` every 3, 6 or 7 hours |
| T1037.001 | Logon Script (Windows) | `UserInitMprLogonScript`, bit 0x20 set in all twelve |
| T1071.001 | Web Protocols | one-way stage reports over HTTPS |

## The padding gives it away

The builder goes to some trouble to make every file unique: a random timestamp, a random linker version, borrowed version info, a borrowed signature, and a few hundred rewritten bytes of filler so the code hash and the key change. The filler is the part that backfires. A stub with no `CC` between its functions and a nine-letter alphabet in the gaps is easier to recognize than one that left the compiler's padding alone, and the config trailer and the telemetry key didn't change across five weeks of builds. Match on those, and treat any hardware ID a wrapped stealer reports as invented.

## Credits

[Muhammed Irfan V A at Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus) found and named 2CLoader and published the config structure, the decryption steps, the flag meanings and the telemetry key that this post builds on; ThreatLabz also published a decryption script and the blocklists. Samples are from [MalwareBazaar](https://bazaar.abuse.ch/). The decompression follows Microsoft's [MS-XCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8) specification.
