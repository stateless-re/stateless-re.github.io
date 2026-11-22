---
title: "2CLoader keys its payload to its own padding"
date: 2026-11-13T21:06:39+00:00
description: "2CLoader derives its AES key from the SHA-256 of its own code, and its builder rewrites the padding between functions so each build gets a different key."
tags: ["2cloader", "loader", "config-extraction", "windows"]
sample:
  family: "2CLoader"
  sha256: "0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/0017821181723261801e24abb9d33c739f382889d46dbf46d320c87ac62e5ca6/)"
scope: medium
toc: true
---

2CLoader derives the AES-256 key for its payload from the SHA-256 of its own code section, and its builder changes that hash for every build by rewriting the padding between functions.

Across 11 builds with the same code layout, 1,644 byte positions differ, and every one of them sits in a gap that a compiler would have filled with `CC`. The gaps hold randomly chosen NOP instructions, XORed with a one-byte key so they don't look like NOPs.

Zscaler ThreatLabz [described 2CLoader](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus) on September 30, 2026, with the config layout, the decryption steps and 20 hashes. The report doesn't say how two builds of the same loader end up with different keys, and lists only some of the API hooks. Twelve of the 20 hashes are on MalwareBazaar, and I pulled all twelve.

## What I found

- All twelve files are the same loader stub (one import hash, `905d6e2fd95bb9d68bb959ec7e8cfb12`). Eleven differ only in 266 padding gaps in `.text`.
- The padding is NOP encodings XORed with one byte. That byte is the string key XOR 0x44 in both stub versions I have.
- The config field `bt` is a Unix build time. It precedes the MalwareBazaar first-seen time in every sample, by under 5 minutes in one case.
- The 18 identity hooks also rewrite SMBIOS tables, disk model and serial, MAC addresses and the display adapter string.
- The C2 channel is one-way. The loader posts progress reports and never reads a response body.

![Chain from the resource config through the code-hash key, two XOR layers, AES-256-GCM and Xpress Huffman to the payload, with one-way telemetry](/img/2cloader-keys-its-payload-to-its-own-padding/chain.svg "From resource to payload")

The highlighted step is this post's subject: the key is a hash of the loader's code.

## Twelve files, one stub

Triage looks the same for every file: x64, seven sections, and one resource of type 88, name 521, with entropy 8.00. The code section is 0x1a1b1 bytes in eleven samples and 0x1a1c1 in the oldest one.

The headers lie. Every sample has a different `TimeDateStamp`, from 1989 to 2105, and a different linker version, from 14.13 to 16.37.

Version info and icons are cloned from legitimate software, mostly Easy Anti-Cheat Service. Ten of the twelve also carry an Authenticode blob copied from a legitimate file. None verifies:

```
00178211  signer: O=EasyAntiCheat Oy          verify: BAD_DIGEST|BAD_SIGNATURE
06185d74  signer: O=Microsoft Corporation, CN=.NET   verify: BAD_DIGEST|BAD_SIGNATURE
1337ed6f  signer: CN=<individual developer>   verify: BAD_DIGEST|BAD_SIGNATURE
066d83b9  unsigned
```

That is LIEF's digest check. The third signer is a private developer whose name I've left out. One sample wears Windows Error Reporting version info under an EasyAntiCheat signature, which no real file would.

## The config sits in the last 0xDC bytes of the resource

The loader calls `FindResourceW(module, 0x209, 0x58)` and reads a 0xDC-byte structure from the end of the resource. ThreatLabz published the layout, and it parses all twelve samples:

![Byte layout of the 0xDC-byte config trailer: magic, sizes, GCM nonce and tag, two key masks, key byte sum, flags, XOR parameters, build ID, injection target, bt, pn, task interval and payload size, with the values from 00178211](/img/2cloader-keys-its-payload-to-its-own-padding/config.svg "The config trailer of 00178211")

The fields that matter below are the key masks at 0x30 and 0x40, the key sum at 0x50, and three the report left unexplained: `bt` at 0xbc, `pn` at 0xc0 and the hours at 0xd4.

`bt` is a Unix timestamp: 1788090685 is 2026-08-30 11:51:25 UTC, and MalwareBazaar first saw this file at 15:31:44 the same day. In all twelve, `bt` is earlier than first-seen, by 4 minutes 49 seconds at the shortest. Since the PE timestamp is random, `bt` is the only honest date in the file.

`pn` holds a file name: `default.exe`, `build_sbuild.exe`, `build_tbuild.exe` or `build.exe`. I read it as the name of the payload the operator fed to the builder, because it tracks the payload: all four `default.exe` builds carry a payload of about 225 KB.

The hours field drives a second scheduled task, `WindowsSecurityHealth`, with a `PT%uH` repetition interval. So besides the logon task the report describes, the loader re-runs itself every 3, 6 or 7 hours in these samples.

## The key is a hash of the loader's own code

The decryption routine hashes the first executable section of the running image with SHA-256, XORs the digest with the two masks, and compares the byte sum of the result with the stored sum. Variables are renamed and the SIMD expansion of the sum is collapsed:

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

One detail matters if you reimplement this. The hash covers the section's `VirtualSize` (0x1a1b1 bytes), not its raw size on disk (0x1a200). The raw-size digest failed the byte-sum check in all twelve and the virtual-size digest passed in all twelve. For `00178211`:

```
SHA-256(.text[0:0x1a1b1]) = 3d591e0a9090bc6a036992b24ccf98594c653c4965e1b03fa61e2c164f08786f
key                       = 884f77955302455c6257d7ffefae9f47df7be67e73b7c6ca437ab1fac0441674
```

The first line is the code hash, the second is the hash XORed with the masks. The byte sum of the key is 0x1159, as the config says.

## The builder rewrites the gaps between functions

The code hash is different in all twelve files, so something changes `.text` per build.

I diffed the sections of the eleven same-size samples. `.rdata` and `.data` came back identical, and `.text` differed in short runs at the same addresses. Here is one run in three builds, and the same gap in the oldest build, each starting right after a `ret`:

```
build      bytes after C3 at 0x140001955     same bytes XOR key
00178211   7c 6c f3 73 73 73 73 15 e3 e3     0f 1f 80 00 00 00 00 | 66 90 | 90         (0x73)
066d83b9   7c 6c 33 73 15 e3 15 e3 e3 e3     0f 1f 40 00 | 66 90 | 66 90 | 90 | 90     (0x73)
0a2ef2c3   7c 6c f3 73 73 73 73 7c 6c 73     0f 1f 80 00 00 00 00 | 0f 1f 00           (0x73)
06185d74   bc 4a bc d5 c5 9e da da bc 4a     66 90 | 66 0f 1f 44 00 00 | 66 90         (0xda)
```

A disassembler shows the left column as junk (`jl`, `jae`, `insb`). XORed with 0x73 it is a sequence of standard x86 NOPs: `0f 1f 80 00 00 00 00` is the 7-byte `nop dword ptr [rax+0]`, `66 90` the 2-byte one. Each build fills the same 10-byte gap with a different random mix.

My first attempt to measure this went wrong. I took the gaps between consecutive `.pdata` entries as padding and tried to decode them all; 94 of 263 failed. Leaf functions have no unwind entry, so real code sits in some of those gaps.

Comparing builds worked better. Across the eleven samples, 1,644 byte positions vary, in 266 gaps. Every varying byte is one of nine values (`15 33 37 6c 73 7c e3 f3 f7`), exactly the bytes of the NOP encodings XORed with 0x73. None of the twelve `.text` sections contains a single `CC CC` pair, which is itself odd for MSVC output.

### The padding key follows the string key

| Stub | String key | Padding key | XOR of the two |
|---|---|---|---|
| 11 builds, Aug 13 to Sep 4 | 0x37 | 0x73 | 0x44 |
| 1 build, Aug 1 | 0x9e | 0xda | 0x44 |

Two stub versions are only two data points, but 0x44 held for both.

The string key was my second wrong turn. The report gives 0x37 for the sample it analyzed, and I assumed it for every file. The August 1 build decoded to garbage, because that stub uses 0x9e. Anything that matches this loader on strings XORed with 0x37 misses it.

## Unpacking twelve payloads

With the key in hand, the rest follows the report. Two XOR layers come off the resource body first, then AES-256-GCM, then decompression:

```
t[i]   = body[i] ^ ((cfg[0x66] + i) & 0xff)
ct[i]  = t[i]    ^ ((cfg[0x65] + cfg[0x64] * i) & 0xff)
plain  = AES-256-GCM-decrypt(key, nonce, ct, tag)
pe     = XpressHuffman-decompress(plain)[0 : cfg[0xd8]]
```

The loader decompresses with `RtlDecompressBufferEx`, format 4 (Xpress Huffman). GCM is authenticated, so there's no guessing whether a key is right: the tag verified for all twelve, and all twelve outputs are x64 PE files.

The whole chain is a script: [`families/2cloader`](https://github.com/stateless-re/tools/tree/main/families/2cloader) prints each sample's config as JSON and, with `-o`, writes the payloads out.

| Loader | Built (`bt`, UTC) | Options | Payload |
|---|---|---|---|
| `06185d74` | 2026-08-01 17:49:18 | 0x0 | Vidar 2.8 |
| `24671765` | 2026-08-13 06:42:51 | 0x480 | Remus |
| `1337ed6f` | 2026-08-20 18:28:21 | 0x0 | Vidar 3.0 |
| `2d43d592` | 2026-08-21 16:44:34 | 0x480 | Vidar 3.1 |
| `066d83b9` | 2026-08-21 16:46:11 | 0x480 | Remus |
| `4c16f5eb` | 2026-08-25 14:02:35 | 0x480 | Remus |
| `0d2abd7d` | 2026-08-29 06:35:13 | 0x480 | Vidar 3.2 |
| `30cf47ca` | 2026-08-29 06:37:04 | 0x480 | Remus |
| `00178211` | 2026-08-30 11:51:25 | 0x80 | Vidar 3.2 |
| `2c786f70` | 2026-09-02 03:05:02 | 0x80 | Vidar 3.2 |
| `3286ff47` | 2026-09-04 18:11:56 | 0x80 | Vidar 3.3 |
| `0a2ef2c3` | 2026-09-04 18:14:06 | 0x80 | Vidar 3.3 |

*Update, November 13: the Payload column comes from [What 2CLoader delivered](/2026/what-2cloader-delivered/), which also has the payload hashes. When this post went out it showed MalwareBazaar's tags, and I distrusted one: `06185d74` was tagged njRAT, a .NET family, but carries a native x64 PE. It is Vidar 2.8.*

Per the report's flag meanings, option 0x80 is parent-process spoofing and 0x400 is the API hooks. The anti-VM, anti-debug and user-activity bits are clear in every sample. The scoring anti-VM code is in the stub; no operator here switched it on.

## What the hooks fake

When bit 0x400 is set and the payload is mapped into the loader's own process, the stub installs inline hooks before it jumps to the payload. The report describes about six of "about 20" and says their intent is not clear. The installer hooks 18 functions:

| Module | Function | What the handler changes |
|---|---|---|
| advapi32 | `RegQueryValueExW/A` | `MachineGuid`, board manufacturer (per ThreatLabz) |
| advapi32 | `GetUserNameW/A` | user name, e.g. `gamer` or `player` |
| kernel32 | `GetComputerNameW/A`, `GetComputerNameExW/A` | `DESKTOP-` plus random characters |
| kernel32 | `GetEnvironmentVariableW/A` | `USERNAME` and others (per ThreatLabz) |
| kernel32 | `GetVolumeInformationW/A` | volume serial number |
| kernel32 | `GetSystemFirmwareTable` | SMBIOS strings and system UUID |
| kernel32 | `DeviceIoControl` | disk vendor, product and serial |
| iphlpapi | `GetAdaptersInfo`, `GetAdaptersAddresses` | MAC address of every adapter |
| user32 | `EnumDisplayDevicesW/A` | display adapter name |

The firmware, disk, adapter and display rows are the ones the report doesn't cover. The disk handler lets the real call run, then edits the result in place (variables renamed):

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

0x2d1400 at (1) is `IOCTL_STORAGE_QUERY_PROPERTY`, the usual way to ask a disk for its model and serial. At (2) the handler overwrites the three strings a hardware fingerprint is built from.

The firmware handler rewrites the SMBIOS strings of structure types 0 to 3 and the 16-byte system UUID. The fake values come from small pools in `.rdata`: `ASUSTeK INC.` and `Dell Inc.` boards, an `NVIDIA GeForce RTX 3060`, a `Samsung SSD 980 Pro`. A linear congruential generator picks from them, seeded from the process ID and the uptime:

```
seed  = (GetTickCount() ^ (pid << 16) ^ 0xa5a5dead) * 0xcfdddf21 + 0xcd1dcf18
state = state * 0x41c64e6d + 0x3039        // each draw uses the top byte
```

So the same build on the same machine invents a different gaming desktop on every run.

The hooks sit in the process the payload runs in, and the payload is an infostealer that fingerprints its host. I think the spoofer defeats the stealer's own VM checks, the panel's per-machine deduplication, or both; the loader alone doesn't say which. Either way, a hardware ID reported through this loader with bit 0x400 set is fiction.

## The reporting channel never reads an answer

The stub resolves seven WinHTTP functions, and none of them reads a response body. A worker thread takes messages from a 32-slot queue, sends each as `POST /api/beacon` over TLS to `aware-cr1[.]com`, and closes the handle.

So there is no tasking, and the question the report leaves open about the server's reply has a short answer: the loader ignores it. The body is JSON XORed with the repeating 32-byte key ThreatLabz published, identical in all twelve samples.

After the `start` registration, each message is a stage report, `{"id":"%s","s":"%s","ok":%d,...}`. The stage names in `s` are stored in plain text:

| `s` | Sent when |
|---|---|
| `slp` | the configured initial sleep finished |
| `vm`, `dbg`, `act` | the anti-VM, anti-debug or user-activity check ran |
| `seed` | the derived key failed the byte-sum check |
| `aes`, `dec` | decryption and decompression ran |
| `loadpe`, `runpe`, `fallback`, `run` | execution stage (I didn't trace these call sites) |
| `wait` | just before the loader exits |

This is build telemetry for a service. The operator can see which build died at which stage on which Windows version.

## What I couldn't determine

Eight of the 20 reported hashes aren't on MalwareBazaar, so the counts above describe twelve samples, not the family. No sample here uses the RunPE path or the .NET path (`fl` is 0 everywhere), so I took the report's description of both on trust.

I don't know whether the 0x44 relation between the two XOR keys is designed or an accident of how the builder picks them. I didn't contact `aware-cr1[.]com`, so I can't say whether it still answers.

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

The twelve payload hashes are in [What 2CLoader delivered](/2026/what-2cloader-delivered/).

| Indicator | Type |
|---|---|
| `hxxps://aware-cr1[.]com/api/beacon` | telemetry URL, all twelve samples |
| `905d6e2fd95bb9d68bb959ec7e8cfb12` | import hash of the stub |
| `SecurityHealthService.exe`, `WindowsSecurityHealth` | persistence names |

## ATT&CK

| ID | Technique | In these samples |
|---|---|---|
| T1027.013 | Encrypted/Encoded File | payload under two XOR layers, AES-256-GCM and Xpress Huffman |
| T1027.001 | Binary Padding | encoded NOPs between functions change the code hash per build |
| T1140 | Deobfuscate/Decode Files or Information | key derived from the SHA-256 of `.text` |
| T1036.001 | Invalid Code Signature | Authenticode blobs copied from legitimate files |
| T1620 | Reflective Code Loading | payload mapped in the loader's own process |
| T1134.004 | Parent PID Spoofing | option 0x80, 10 of 12 samples |
| T1547.001 | Registry Run Keys / Startup Folder | persistence bits set in all twelve |
| T1053.005 | Scheduled Task | logon task, plus `WindowsSecurityHealth` every 3, 6 or 7 hours |
| T1071.001 | Web Protocols | one-way stage reports over HTTPS |

## The padding gives it away

The builder works hard to make every file unique: random timestamps and linker versions, borrowed version info and signatures, and rewritten filler so the key changes. The filler is the part that backfires.

A stub with no `CC` between its functions and a nine-letter alphabet in the gaps is easier to recognize than one that left the compiler's padding alone. And the config trailer and the telemetry key didn't change across five weeks of builds. Match on those, and treat any hardware ID a wrapped stealer reports as invented.

## Credits

- [Muhammed Irfan V A at Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus) found and named 2CLoader and published the config structure, the decryption steps, the flag meanings and the telemetry key that this post builds on.
- The decompression follows Microsoft's [MS-XCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8) specification; the extractor uses [dissect.util](https://github.com/fox-it/dissect.util)'s decoder.
