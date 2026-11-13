---
title: "What 2CLoader delivered: Vidar on Epic Games profiles, Remus on Ethereum"
date: 2026-11-13
slug: "what-2cloader-delivered"
description: "The twelve payloads from the 2CLoader post, identified and configs extracted without running them: eight Vidar builds that look up their C2 on Telegram, Steam, Epic Games and Fandom profiles, four Remus builds that share one build tag and one Ethereum contract, and YARA for both."
tags: ["vidar", "remus", "2cloader", "config-extraction", "dead-drop-resolver", "yara", "windows"]
sample:
  family: "Vidar, Remus"
  sha256: "2386a9d42404cf0151799ed91a700b4b397ec0ffdc619f8a2b1faf6b21a97122"
  source: "Unpacked from 2CLoader [1337ed6f](https://bazaar.abuse.ch/sample/1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb/) (MalwareBazaar)"
toc: true
---

The twelve payloads I unpacked from 2CLoader in [the previous post](/2026/2cloader-keys-its-payload-to-its-own-padding/) are eight Vidar builds and four Remus builds. Seven of the Vidar builds look for their C2 server somewhere I haven't seen in any earlier Vidar report. Five use a profile on the Epic Games developer community, and two use a Fandom user profile, alongside the Telegram channels and Steam profiles Vidar is known for. The file that MalwareBazaar tags `njrat` is Vidar too, the oldest build in the set, with version 2.8 in its config.

That post stopped at the payloads: it decrypted them, listed their hashes and used MalwareBazaar's tags as stand-ins for family names. This one identifies each payload from its own code and data, extracts every configuration, and turns the result into indicators and two YARA rules. As before, nothing was executed. Configs were read from the files and the decryption routines reimplemented in Python.

## What I found

- Eight payloads are native x64 Vidar with no import table. Their configs carry versions 2.8, 3.0, 3.1, 3.2 and 3.3, which rise with the loader build dates from August 1 to September 4, 2026. Together they point to 13 dead-drop accounts: five Telegram channels, four Steam profiles, three Epic Games developer profiles and one Fandom profile.
- Two pairs of Vidar payloads are byte-identical except for 507 and 497 bytes in `.data`, where the config lives. The pair whose configs say 3.0 and 3.1 shares the same code, so the version string comes from the builder, not from a code change.
- Gen Digital's public Vidar config extractor reads all eight configs correctly. Rapid7's earlier one finds nothing, because these builds use a 16-byte XOR key instead of the alphabet substitution it expects.
- The four Remus payloads share one build tag, `03473d3f2d528ba787191417a6e1e5f0` (also the name of the semaphore they use as a run-once lock), and one Ethereum contract. Each carries three ChaCha20-encrypted C2 URLs; eight hosts in total, with `vexdico[.]shop:8539` in all four.
- No public tool I could find extracted the Remus config statically, so I published one ([`families/remus`](https://github.com/stateless-re/tools/tree/main/families/remus)). Malware Cake Factory had already analyzed one of these four payloads in depth, from a different 2CLoader build; I credit it below where it applies.

## Two families, told apart in five minutes

Triage splits the twelve files cleanly. Four are about 225 KB, import 39 to 42 functions from six DLLs (screen capture, COM, desktops) and use the default image base 0x140000000. Eight are 1.1 to 1.4 MB, have an empty import table, a `.data` section whose virtual size is 1.1 to 1.3 MB against 0x1200 bytes on disk, and image bases between 0x110000000 and 0x750000000. The small ones match MalwareBazaar's `RemusStealer` tag on their loaders and the large ones match `Vidar`, with one exception: `06185d74`, tagged `njrat`, belongs with the large group by every measure.

A tag is a label, though. Each family needed evidence from the payload itself, and the two families hide their strings in different ways, so each got its own route in.

## Remus: three encrypted URLs and a blockchain fallback

The Remus payloads build their strings on the stack and decode them in place, one transform per string, the pattern Gen Digital described when it [first wrote about Remus](https://www.gendigital.com/blog/insights/research/remus-64bit-variant-of-lumma-stealer). I emulated the decode loops in Unicorn, starting at every instruction that loads a 16-byte constant from `.rdata`, and stopping at the first call. That gave about 80 strings per payload, among them `\BaseNamedObjects\`, `Host: github.com`, `hxxps://ethereum-rpc.publicnode[.]com`, a system-information template starting `build:` and `  tag: {tag}`, and `honey@pot[.]com.pst`, the sandbox marker Gen lists.

The decode loops look worse than they are. Ghidra shows each as mixed boolean-arithmetic, for example:

```c
k = (i | 0x34) * (i & 0x34) + ((i & 0x34) ^ 0x34) * (i & 0xcb);   // i = 1, 2, 3 ...
buf[i - 1] ^= k;
```

Because `0xcb` is `~0x34`, the identity `(x|y)(x&y) + (x&~y)(~x&y) = x*y` reduces the expression to `i * 0x34`. Every string my emulator recovered follows `c[i] ^ ((i + 1) * k)` with its own constant `k`, in bytes or in 16-bit units (Malware Cake Factory notes some strings in its sample index from `i` instead). A known prefix such as `{"jsonrpc"` gives `k` from the first character, so a scanner needs no per-build constants.

The function that uses the Ethereum string is the C2 selector. Trimmed and renamed from the Ghidra output of `066d83b9`:

```c
idx = selector ^ 0xa6;                         // (1) selector starts at 0xa6
if (idx < 3) {
    chacha20_xor(&state, slots + idx * 0x40, url, 0x40);   // (2)
} else if (idx == 3) {
    body = decode(rdata_0x2f750, 0x89);        // (3) eth_call JSON
    rpc  = decode_wide(stack_string, 0x24);
    resp = http_post(rpc, body);
    hex  = json_get(resp, "result");
    url  = hex_to_wide(hex + strlen(hex) - 0x40);   // (4)
}
```

At (1) the state byte starts at 0xa6, so index 0 comes first. Indices 0 to 2 decrypt one of three 64-byte slots at (2), and index 3 takes the Ethereum path at (3). The JSON body decodes to:

```
{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x999941b74F6bbc921D5174A5b29911562cd2D7CF","data":"0xc2fb26a6"},"latest"]}
```

That is a call to function `0xc2fb26a6` of contract `0x9999…D7CF`. [Malware Cake Factory](https://malwarecakefactory.github.io/malware-analysis/remus-c2-protocol-analysis/) published the same contract and selector in April, and Unit 42 and SpyCloud name the contract as well. At (4) the code hex-decodes the last 64 hex characters of `result` into a UTF-16 string. Malware Cake Factory describes skipping the 128 hex characters of ABI header and decoding the rest. For a C2 string of 32 characters or fewer, the two give the same answer.

The slots are ChaCha20 in its original form: the setup writes `expand 32-byte k`, a 32-byte key from `.rdata`, a 64-bit block counter of zero and an 8-byte nonce stored right after the key. I decrypted the three slots with that key and nonce. Slot 0 came out as `hxxp://vexdico[.]shop:8539/videos`. Slots 1 and 2 came out as noise.

The key was right, so the counter had to be wrong. The cipher function copies the state, runs the rounds, and on its way out writes the incremented block counter back to `state + 0x30`. Every call continues the keystream, and since each slot is exactly one 64-byte block, slot *n* decrypts with counter *n*. With counters 1 and 2, slot 1 is `hxxp://zakuiru[.]shop:9048/contacts` and slot 2 is `hxxp://kupzovo[.]shop:7567/payments`.

### One tag across four builds

The payload creates a named object, `\BaseNamedObjects\` plus a 32-character hex string that a pointer at `.data+0x10` refers to, through a direct syscall. It looks up hash `0x0a8ff4e4` in a table of (hash, service number) pairs and calls the stub with five arguments, `(&handle, 0x1F0003, &object_attributes, 0, 1)`, with `OBJ_OPENIF` in the attributes. My first draft called this an event: `NtCreateMutant` takes four arguments, and five arguments with 0x1F0003 fit `NtCreateEvent`. They fit `NtCreateSemaphore` just as well (initial count 0, maximum 1, `SEMAPHORE_ALL_ACCESS`), and the shape alone can't separate the two. The hash can. Malware Cake Factory published Remus's hash function, a reflected CRC32 with initial value `0x96577E78` and a final inversion. Under it `0x0a8ff4e4` is `NtCreateSemaphore`, and the hash of the next call, which passes the handle, 0 and a timeout, is `NtWaitForSingleObject`. So it is a named semaphore. The same pointer is read in two other places, each time between the code that decodes the string `&exp=` and the code that decodes `tag=`, so it is also the build tag sent at registration. Malware Cake Factory shows the registration body as `tag=<…>&exp=<…>&hwid=<…>`, and Flashpoint notes that Lumma's LID corresponds to Remus's tag.

All four payloads carry the same tag, `03473d3f2d528ba787191417a6e1e5f0`, in plain text. The configs, from my extractor:

| Loader | Payload | Slot 0 | Slot 1 | Slot 2 |
|---|---|---|---|---|
| `24671765` | `d488a4b0` | `mrlketo[.]shop:8932/workspaces` | `vexdico[.]shop:8539/reports` | `shkpiva[.]shop:5627/images` |
| `066d83b9` | `86969408` | `vexdico[.]shop:8539/videos` | `zakuiru[.]shop:9048/contacts` | `kupzovo[.]shop:7567/payments` |
| `4c16f5eb` | `47139858` | `fresok[.]top:9048/messages` | `shhsift[.]click:7647/messages` | `vexdico[.]shop:8539/invoices` |
| `30cf47ca` | `6f3e8965` | `shhsift[.]click:7647/comments` | `vexdico[.]shop:8539/tokens` | `piarl[.]site:9048/notifications` |

All slots use plain HTTP. Every build has `vexdico[.]shop:8539` with a different path, and the path changes per build while the host stays. All four use the same contract, selector and RPC endpoint, and each has its own ChaCha20 key and nonce.

Some of this is already public. The payload in `4c16f5eb` (SHA-256 `4713985869f2…`) is the subject of Malware Cake Factory's [October 7 post](https://malwarecakefactory.github.io/malware-analysis/remus-protected-startup-tasking-analysis/), which reached it through a different 2CLoader build (`5edcaa75…`, one of the eight report hashes I couldn't get). That post gives its three C2s, the tag, the slot selector and the encrypted tasking protocol in far more depth than I do here. The same identical payload inside two loader builds suggests the operator wraps one Remus build several times. Triage's sandbox config for another Remus sample on MalwareBazaar (`78cc6707…`, first seen August 25) also lists `vexdico[.]shop:8539` and `kupzovo[.]shop:7567`. New here are the other three payloads' configs and the observation that one tag spans all four.

## Vidar: a 16-byte XOR key next to the dead drops

The Vidar payloads gave my string emulator nothing. I ran two passes over every function in `.pdata`, first with calls stubbed out and then following direct calls, about nine minutes in total, and got zero strings. That fits [Zscaler ThreatLabz's description](https://www.zscaler.com/blogs/security-research/vidar-adds-virtual-machine-and-custom-stream-ciphers-string-obfuscation) of Vidar's string obfuscation since its internal version 2.0: a small bytecode virtual machine plus a custom stream cipher, which my snippet emulation didn't get through. I didn't reimplement it, because the config turned out not to need it.

The way in was a diff. Two pairs of loaders carry payloads with the same code: `1337ed6f`/`2d43d592` and `3286ff47`/`0a2ef2c3`. Comparing each pair byte for byte gives 12 and 11 runs of differences, 507 and 497 bytes, all of them in `.data`. Whatever the builder writes per build lives there. Following code references to that region led to a function that decrypts it field by field with this helper (from `1337ed6f`, with the junk arithmetic around it left in):

```
0xedcdd  movzx    ecx, byte ptr [r9 + rbx]
0xedce2  xor      edx, edx
0xedce4  mov      rax, qword ptr [rsp + 0xb0]
0xedcec  sub      rax, rcx
0xedcef  mov      qword ptr [rsp + 0xb0], rax
0xedcf7  mov      rax, r9
0xedcfa  div      r8
0xedcfd  mov      cl, byte ptr [rdx + rdi]
0xedd00  mov      al, byte ptr [r9 + rbx]
0xedd04  xor      cl, al
0xedd06  mov      byte ptr [r9 + r10], cl
```

`div r8` leaves `i % 16` in `rdx`, the next two loads fetch `key[i % 16]` and `src[i]`, and the XOR goes to `dst[i]`. The running subtraction into `[rsp+0xb0]` feeds nothing. So each field is `src[i] ^ key[i % 16]`, and the 16-byte key is stored right in front of the fields it protects. My first look at the diff went wrong here: I read the first 34-byte run as one encrypted field and tried to decrypt it whole. It is 15 bytes I never identified, then the key, then the version string `3.0`.

The layout, with offsets from the key and values from `1337ed6f`. Malware Cake Factory had already published the same offsets for version 3.8 in its [Vidar 3.9 versus 3.8](https://malwarecakefactory.github.io/malware-analysis/vidar-3-9-vs-3-8-analysis/) comparison; I found that after doing the work, and these builds agree with it:

| Offset | Size | Field | Value in `1337ed6f` |
|---|---|---|---|
| +0x000 | 16 | XOR key | `299fc1085e4dde0334e829ce6d5edda6` |
| +0x010 | 0x20, length byte at +0x030 | version | `3.0` |
| +0x031 | 0x40, length byte at +0x071 | build ID | `8d7bd1e30cdd417d82de409d83cd441e` |
| +0x072 + n × 0x243 | 0x100, length byte at +0x100 | record n: URL | `hxxps://telegram[.]me/m1duus` |
| record + 0x101 | 0x40, length byte at +0x141 | record n: anchor | `x4tte` |
| record + 0x142 | 0x100, length byte at +0x242 | record n: User-Agent | the Edge string listed below |
| +0x1047 | 1 | record count | 3 |

The code reads the count byte and caps it at 7 (`cmp al, bl` with `ebx = 7`), the same limit of seven records [Rapid7 described](https://www.rapid7.com/blog/post/tr-malicious-websites-wordpress-compromise-advances-global-stealer-operation/) in March for an older build. Only that much carries over: Rapid7's records are three fixed 0x100-byte strings, while these have length bytes and a 0x40-byte anchor. Rapid7 also explains what the anchor is for. Vidar fetches the page, finds the anchor string and takes the C2 that follows it up to a `|`. I didn't trace that parser in these builds, so the anchor's role here rests on Rapid7's and Malware Cake Factory's descriptions, not on my reading.

I wrote an extractor for this layout before searching properly, which was a waste. [Gen Digital's `vidar_config_extractor.py`](https://github.com/gendigitalinc/ioc/tree/master/Vidar) (also shipped in CAPE's parsers as `community/Vidar.py`) parses the same blob, written for versions 1.5 to 1.8. I ran it on all eight payloads, and its output matches mine field for field, so that is the tool to use. Rapid7's [`vidar_v2_extract.py`](https://github.com/rapid7/Rapid7-Labs/tree/main/Malware%20Config%20Extractors) returns empty results for all eight. It looks for printable strings under a 91-character Vigenère-like alphabet and a two-digit version, which is an older Vidar format, not a bug.

### What the eight configs say

| Loader | Built (UTC) | Version | Anchor | Dead drops | User-Agent |
|---|---|---|---|---|---|
| `06185d74` | 2026-08-01 | 2.8 | `ki5goq` | `t[.]me/x0xprs`, Steam `…64897346` | Edg/144 |
| `1337ed6f` | 2026-08-20 | 3.0 | `x4tte` | `telegram[.]me/m1duus`, Epic `YmbKZ`, Steam `…57426610` | Edg/144 |
| `2d43d592` | 2026-08-21 | 3.1 | `h61sh` | `telegram[.]me/s11yme`, Epic `roAjr`, Steam `…52917381` | Firefox/34 (Mac) |
| `0d2abd7d` | 2026-08-29 | 3.2 | `o0oi1` | `telegram[.]me/nag0a`, Epic `EMqJL` | Firefox/34 (Mac) |
| `00178211` | 2026-08-30 | 3.2 | `o0oi1` | `telegram[.]me/nag0a`, Epic `EMqJL` | Firefox/34 (Mac) |
| `2c786f70` | 2026-09-02 | 3.2 | `o0oi1` | `t[.]me/nag0a`, Epic `EMqJL` | Firefox/34 (Mac) |
| `3286ff47` | 2026-09-04 | 3.3 | `i11y` | `telegram[.]me/goof0r`, Steam `…45030031`, Fandom `63771805` | YaBrowser/26.8 |
| `0a2ef2c3` | 2026-09-04 | 3.3 | `i11y` | `telegram[.]me/goof0r`, Steam `…45030031`, Fandom `63771805` | YaBrowser/26.8 |

The build time is the loader's `bt` field from the previous post. Each payload has its own build ID and its own XOR key, even where two builds share every dead drop.

The version column climbs with the build date, and the 3.0 and 3.1 payloads have identical code. So "3.1" is a string the builder writes, whatever it counts. Zscaler's string-obfuscation post lists `2d43d592` as "Vidar v3.1" and calls its version numbers internal ThreatLabz labels. The payload inside that loader happens to say 3.1 in its own config. I can't tell whether that is a coincidence.

The User-Agents are worth a second look, because none of them is what a browser on the infected machine would send:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36 Edg/144.0.0.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) Gecko/20100101 Firefox/34.0
Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 YaBrowser/26.8.0.0
```

The Edge one has no `Chrome/` token and the Yandex one has no `AppleWebKit`, so no real browser sends either. The second is the genuine string of Firefox 34 on Mac OS X 10.10, a release from 2014, arriving from a Windows x64 process. Each is a fixed per-build config value.

The two new URLs are JSON APIs that return a user's public profile. Calling them dead drops is my inference: they sit in the same records as the Telegram and Steam URLs, each with an anchor, and an Epic or Fandom API endpoint can't be the C2 server itself.

```
hxxps://dev.epicgames[.]com/community/api/user_profiles/profile.json?hash_id=EMqJL
hxxps://community.fandom[.]com/wikia.php?controller=UserProfile&method=getUserData&format=json&userId=63771805
```

The first is the Epic Games developer community, the second a Fandom wiki account. There is one conflict with older reporting. Rapid7 found that the build it analyzed resolved a URL only if it contained `.me/` or `amcommunity[.]com`, and used any other URL as the C2 directly. Neither new URL contains those strings, so either the check changed in these builds or these records do nothing useful. Malware Cake Factory describes 3.8 and 3.9 as searching retrieved content for the marker with a direct-use fallback, which fits the first reading. I haven't confirmed it in code. The Vidar reports I read name Telegram and Steam (and, for older builds, Mastodon); none mentions Epic Games or Fandom, and searches for Vidar with either service found nothing. Three of the five builds that use the Epic profiles sit in loaders dressed as Epic's own Easy Anti-Cheat service. I'd call that a coincidence of disguise, not a design.

## The "njrat" payload is Vidar 2.8

`06185d74`'s payload has no CLR header and no imports. It has the same config layout at the same offsets relative to its key, decrypted by the same extractor, with version 2.8, a Telegram channel and a Steam profile. It also contains the same string-cipher code as the other seven, which the first YARA rule below keys on. It is the oldest build in the set (August 1) and the only one whose loader is the older stub variant. I don't know where the `njrat` tag came from; it describes neither the loader nor the payload.

## What I couldn't determine

I didn't open any of the 13 dead-drop pages or query the Ethereum contract. That would mean touching the operator's infrastructure, and the answers would describe today, not the build dates. So the Vidar C2 servers themselves are unknown here, and the Remus Ethereum fallback is known only as a contract and a selector. The 15 bytes in front of each Vidar key differ per build, and I don't know what they are. I didn't reimplement Vidar's string VM, so the Vidar strings, including the anchor parser, are taken from Rapid7's and Zscaler's descriptions and not read by me. For Remus, my emulator recovered one RPC endpoint per build; other reports list as many as seven providers, and I can't rule out more in strings my emulator didn't reach. What `exp` carries and what the shared tag represents on the operator's side are open as well.

## Detection

The first rule matches Vidar's string-cipher key schedule. The code uses the FNV prime `0x01000193` and the constant `0x9E3779B9`, the same constants Zscaler documents for the cipher, and the byte sequences around them are identical in all eight payloads across six distinct compiles. Requiring an empty import table and at least three `rdtsc` timing blocks keeps the rule narrow.

```yara
import "pe"

rule Vidar_x64_StringCipher_NoImports
{
    meta:
        description = "Vidar native x64 build (tested on config versions 2.8-3.3): ARX string-cipher key schedule (FNV prime 0x01000193, 0x9E3779B9) in a PE with no imports"
        reference = "https://www.zscaler.com/blogs/security-research/vidar-adds-virtual-machine-and-custom-stream-ciphers-string-obfuscation"
        sample = "2386a9d42404cf0151799ed91a700b4b397ec0ffdc619f8a2b1faf6b21a97122"
    strings:
        // movzx eax, byte [rcx+rax]; mov ecx,[rsp]; xor ecx,eax; mov eax,ecx; mov [rsp],eax; imul eax,[rsp],0x01000193
        $fnv = { 0F B6 04 01 8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01 89 04 24 }
        // shl eax,8; mov ecx,[rsp]; xor ecx,eax; mov eax,ecx; mov [rsp],eax; mov eax,[rsp]; add eax,0x9E3779B9
        $gold = { C1 E0 08 8B 0C 24 33 C8 8B C1 89 04 24 8B 04 24 05 B9 79 37 9E 89 04 24 }
        // rdtsc; shl rdx,32; or rax,rdx; mov r8,rax; mov rax, <magic>; mul r8
        $tsc = { 0F 31 48 C1 E2 20 48 0B C2 4C 8B C0 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 49 F7 E0 }
    condition:
        uint16(0) == 0x5A4D and pe.is_64bit() and pe.number_of_imports == 0 and
        $fnv and $gold and #tsc >= 3
}
```

The second rule matches Remus's syscall dispatcher, which copies stack arguments with `rep movsq` before `syscall`, together with at least two of three syscall-hash comparisons: `NtClose`, `NtFreeVirtualMemory` and `NtDelayExecution` under the CRC32 above. The hashes are the same constants in all four builds, as you'd expect if the seed is fixed. A first version also required the ChaCha20 constant `expa` as an immediate, because Ghidra showed it as one; it matched nothing. The binary computes those constants through the same mixed boolean-arithmetic, and Ghidra had folded them back.

```yara
import "pe"

rule Remus_x64_Syscall_Hashes
{
    meta:
        description = "Remus stealer x64: direct-syscall stub plus hashed syscall-table lookups"
        reference = "https://www.gendigital.com/blog/insights/research/remus-64bit-variant-of-lumma-stealer"
        sample = "8696940855d849d5d6aa1a52896855082bde0fa76da23cdaeca028a5493d4fb1"
    strings:
        // sub rcx,4; jle +0xd; lea rsi,[rsp+38h]; lea rdi,[rsp+28h]; rep movsq; syscall
        $stub = { 48 83 E9 04 7E 0D 48 8D 74 24 38 48 8D 7C 24 28 F3 48 A5 0F 05 }
        // cmp dword [rcx+rdx*8], <syscall name hash>
        $h1 = { 81 3C D1 8F B8 2D 93 }
        $h2 = { 81 3C D1 F0 F8 C5 EE }
        $h3 = { 81 3C D1 10 05 F8 57 }
    condition:
        uint16(0) == 0x5A4D and pe.is_64bit() and
        $stub and 2 of ($h*)
}
```

The Vidar rule matches all eight Vidar payloads and the Remus rule all four Remus payloads. Neither matches the other family, any of the twelve 2CLoader loaders, or anything among 13,460 clean files on my bench, 5,569 of them PE files (the .NET SDK, Mono and my tool directories). That clean set is not a Windows install, so test against your own before alerting. Both rules target the unpacked payload, which in this chain only exists in memory; run them on memory images or on dumps.

To extract configs: Gen's extractor for Vidar, and for Remus [`families/remus`](https://github.com/stateless-re/tools/tree/main/families/remus) in my tools repository, which prints the C2 slots, the Ethereum contract, the selector and the tag as JSON (`python extract.py PAYLOAD`). It finds the key by the `lea rdx` / `lea r8` pair that passes key and nonce to the cipher setup, and needs no per-build constants.

For hunting on the network and on hosts:

- A non-browser process requesting `dev.epicgames[.]com/community/api/user_profiles/profile.json?hash_id=` or `community.fandom[.]com/wikia.php?controller=UserProfile&method=getUserData`, or a Steam profile or Telegram channel page, followed by a connection to an address that appears in the response.
- A JSON-RPC `eth_call` to `0x999941b74F6bbc921D5174A5b29911562cd2D7CF` with data `0xc2fb26a6`, from anything that isn't a wallet.
- Plain HTTP with a `Host: github.com` header that doesn't match the server (CIS reported Remus forging `github.com` or `microsoft.com`). In this set the real hosts are `.shop`, `.top`, `.click` and `.site` names on ports between 5000 and 9100.
- A semaphore named `\BaseNamedObjects\03473d3f2d528ba787191417a6e1e5f0`.
- The three Vidar User-Agents above: two malformed, one a 2014 macOS Firefox string coming from Windows.

## Indicators

| SHA-256 | Role |
|---|---|
| `b47ac295ab1668d8dd8a767934cb5c6dd263712d0b8ad10b8ca097b9f6a44fca` | Vidar 2.8, from `06185d74` (tagged njrat) |
| `2386a9d42404cf0151799ed91a700b4b397ec0ffdc619f8a2b1faf6b21a97122` | Vidar 3.0, from `1337ed6f` |
| `dbe69ce36fbddc64a9db7bda8ebcfd09e7c1a4afe058bef4aff20162a11dc0d1` | Vidar 3.1, from `2d43d592` |
| `2388fdb0911403d553fe7d3c72aa949cc49e7ecd7acd5cc357645429c51e7217` | Vidar 3.2, from `0d2abd7d` |
| `ad9d1679fb2f90477fe8e81a4be51566b84f154eb3f2b7200a7b0faca0715636` | Vidar 3.2, from `00178211` |
| `90d24c7650a3fb563e381c87dc597281f0f4463f032d09a2b4759e5c7093e8ff` | Vidar 3.2, from `2c786f70` |
| `b5236f9b957ca98c643c423601a4399a8cfece061dbead26fd147e5d8cbbd7e8` | Vidar 3.3, from `3286ff47` |
| `99d6a4544b0b3ed39fbe0d2298d7019ccf2d662555f8cf7956730984edfaff01` | Vidar 3.3, from `0a2ef2c3` |
| `d488a4b0e6837264517b81596ce5d6fbbc61d3ef68d938c0e0d7b9a9a1915f26` | Remus, from `24671765` |
| `8696940855d849d5d6aa1a52896855082bde0fa76da23cdaeca028a5493d4fb1` | Remus, from `066d83b9` |
| `4713985869f284136d2d9f9c98a1cd43c2f327a7619d829e31fc69c3589f56cb` | Remus, from `4c16f5eb` (also in `5edcaa75`, per Malware Cake Factory) |
| `6f3e8965f7cb3d800ca06482ebf3800f6873ab88078d8735c416aa25b81179d6` | Remus, from `30cf47ca` |

The loader hashes are in the [previous post](/2026/2cloader-keys-its-payload-to-its-own-padding/). None of these payload hashes was on MalwareBazaar when I checked.

Vidar dead drops (the C2 is published on these pages):

| Indicator | Builds |
|---|---|
| `hxxps://t[.]me/x0xprs` | 2.8 |
| `hxxps://telegram[.]me/m1duus` | 3.0 |
| `hxxps://telegram[.]me/s11yme` | 3.1 |
| `hxxps://telegram[.]me/nag0a`, `hxxps://t[.]me/nag0a` | 3.2 (three builds) |
| `hxxps://telegram[.]me/goof0r` | 3.3 (two builds) |
| `hxxps://steamcommunity[.]com/profiles/76561198664897346` | 2.8 |
| `hxxps://steamcommunity[.]com/profiles/76561198657426610` | 3.0 |
| `hxxps://steamcommunity[.]com/profiles/76561198652917381` | 3.1 |
| `hxxps://steamcommunity[.]com/profiles/76561198645030031` | 3.3 (two builds) |
| `hxxps://dev.epicgames[.]com/community/api/user_profiles/profile.json?hash_id=YmbKZ` | 3.0 |
| `hxxps://dev.epicgames[.]com/community/api/user_profiles/profile.json?hash_id=roAjr` | 3.1 |
| `hxxps://dev.epicgames[.]com/community/api/user_profiles/profile.json?hash_id=EMqJL` | 3.2 (three builds) |
| `hxxps://community.fandom[.]com/wikia.php?controller=UserProfile&method=getUserData&format=json&userId=63771805` | 3.3 (two builds) |

Remus:

| Indicator | Type |
|---|---|
| `vexdico[.]shop:8539` | C2, all four builds |
| `shhsift[.]click:7647` | C2, two builds |
| `zakuiru[.]shop:9048`, `kupzovo[.]shop:7567`, `mrlketo[.]shop:8932`, `shkpiva[.]shop:5627`, `fresok[.]top:9048`, `piarl[.]site:9048` | C2, one build each |
| `0x999941b74F6bbc921D5174A5b29911562cd2D7CF`, selector `0xc2fb26a6` | Ethereum contract (fallback C2) |
| `ethereum-rpc.publicnode[.]com` | RPC endpoint used for the fallback |
| `03473d3f2d528ba787191417a6e1e5f0` | build tag and named-object suffix, all four builds |

## ATT&CK

| ID | Technique | In these samples |
|---|---|---|
| T1102.001 | Dead Drop Resolver | Vidar reads its C2 from Telegram, Steam, Epic Games and Fandom profiles; Remus from an Ethereum contract |
| T1027.013 | Encrypted/Encoded File | Vidar config under a 16-byte XOR key; Remus C2 slots under ChaCha20 |
| T1027 | Obfuscated Files or Information | Remus strings as `c[i] ^ ((i+1)*k)` behind mixed boolean-arithmetic |
| T1106 | Native API | Remus calls `NtCreateSemaphore` and other Nt functions through a direct-syscall stub, chosen by CRC32 hash |
| T1071.001 | Web Protocols | Remus C2 over plain HTTP on high ports |
| T1555.003 | Credentials from Web Browsers | Remus strings name `Login Data`, `Local State` and `Network\Cookies` |

## The configs outlast the builds

Every build in this set has its own key and its own build ID, and the Vidar builds even move their image base around. The parts a defender can reuse stayed put. One Remus tag and one contract cover four builds, `vexdico[.]shop:8539` sits in all of them, and three Vidar builds share one Telegram channel and one Epic Games profile. Add the `dev.epicgames[.]com` and `community.fandom[.]com` profile APIs to whatever watches for Steam and Telegram lookups from non-browser processes.

## Credits

[Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus) (Muhammed Irfan V A) published the 2CLoader samples these payloads came from, and Ismael Garcia Perez's [Vidar string-obfuscation analysis](https://www.zscaler.com/blogs/security-research/vidar-adds-virtual-machine-and-custom-stream-ciphers-string-obfuscation) supplied the cipher constants the Vidar rule keys on. Gen Digital wrote the [Vidar config extractor](https://github.com/gendigitalinc/ioc/tree/master/Vidar) that reads these builds and, with Vojtěch Krejsa and Jan Rubín, the [first analysis of Remus](https://www.gendigital.com/blog/insights/research/remus-64bit-variant-of-lumma-stealer). Milan Spinka at [Rapid7](https://www.rapid7.com/blog/post/tr-malicious-websites-wordpress-compromise-advances-global-stealer-operation/) documented Vidar's earlier config records and anchor parsing, and Malware Cake Factory's [Vidar 3.9 versus 3.8](https://malwarecakefactory.github.io/malware-analysis/vidar-3-9-vs-3-8-analysis/) (October 21) published the XOR config layout these builds use. Malware Cake Factory's [Remus C2 protocol analysis](https://malwarecakefactory.github.io/malware-analysis/remus-c2-protocol-analysis/) and its [October analysis](https://malwarecakefactory.github.io/malware-analysis/remus-protected-startup-tasking-analysis/) of the `4713985869f2…` payload covered the contract, the selector, the slot selector, the tag and the CRC32 hash function before I did. Unit 42's [Remus note](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-30-Remus-Info-Stealer-Uses-Blockchain-Anchored-C2.txt), [SpyCloud](https://spycloud.com/blog/remus-a-new-infostealer/), [CIS](https://www.cisecurity.org/insights/blog/sltt-c2-traffic-tied-to-remus-malware-distribution-operation) and [Flashpoint](https://flashpoint.io/blog/remus-stealer-a-new-not-so-new-infostealer/) reported the contract, the RPC endpoint, the forged `Host` header and the tag's Lumma lineage. Samples are from [MalwareBazaar](https://bazaar.abuse.ch/).
