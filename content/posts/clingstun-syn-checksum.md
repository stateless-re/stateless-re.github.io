---
title: "ClingSTUN's scanner checksums 20 bytes of every SYN and sends 256"
date: 2026-11-23T14:57:54+00:00
slug: "clingstun-syn-checksum"
description: "ClingSTUN's SYN probes carry checksums targets reject, so its scans can't trigger its HTTP exploits. Plus its command formats and a ChaCha20 string table."
tags: ["clingstun", "cling", "linux", "iot", "botnet", "stun", "proxy"]
sample:
  family: "ClingSTUN (Cling)"
  sha256: "ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81)"
scope: medium
toc: true
---

ClingSTUN is a Linux bot for routers and DVRs that takes its orders through public STUN servers and spreads with seven built-in exploits. Six of those exploits are HTTP requests, and the bot sends one only after a SYN probe gets a SYN-ACK back. Every build with a scanner computes that probe's TCP checksum for a 20-byte segment, then hands the kernel 256 bytes. A host that checks checksums drops the probe.

The bot was written up four times in under a month, so most of its behaviour is already public:

- [eFeSpain](https://blog.efespain.com/cling/) analysed it on 2026-09-04, published on 2026-09-12 and named it Cling. Chapters [19](https://blog.efespain.com/capitulo-19/) and [20](https://blog.efespain.com/capitulo-20/) cover a 7-command build: the 20-byte command datagram, the registration beacon, the scanner's source port 9999.
- China Telecom Security called it UFlowBot on 2026-09-30, according to eFeSpain's timeline. I couldn't find that report.
- [Nozomi Networks Labs](https://www.nozominetworks.com/blog/a-stunning-disguise-cling-malware-masquerades-as-google-) (2026-10-01) caught commands arriving from Google's STUN address, which it judges spoofed, and showed that 145.249.115[.]184 passes registrations to the operator.
- [Fortinet's Vincent Li](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure) (2026-10-05) named it ClingSTUN, listed the entry CVEs and 21 file hashes, and described three "evolutions".

All 21 Fortinet files are public: 13 on MalwareBazaar, the other 8 on Hybrid Analysis. I added Nozomi's two SHA-256 samples. This post is about what those 23 files add: the checksum, how the command format changed between builds, and a string table one build encrypts.

## What I found

- Every scanner SYN should fail a receiver's checksum check, so the bot's own probes can't trigger its six HTTP exploits. Its UDP exploits don't need them.
- Fortinet's 21 files are two builds: 10 binaries that beacon to 24 STUN servers and know a single action, and 9 that use 13 servers and five commands.
- Fortinet's "every endpoint must succeed" doesn't match the x86-64 build it analysed, which needs 7 of 13.
- One of Nozomi's builds encrypts its strings with ChaCha20, under a key built from the byte values 0x00 to 0x1f.

![Dropper, bot, public STUN servers, operator and scanner child, with the beacon going out to the servers and 20-byte commands coming back to the mapped ports](/img/clingstun-syn-checksum/chain.svg "The control channel of the 13-server build")

The operator never connects to the bot. Its orders arrive on the UDP sockets the bot used to ask the STUN servers for its public port.

## Two builds in Fortinet's list

Fortinet lists 22 hash lines. One, 9391c6ad, appears twice, so there are 21 files: two `wget.sh` droppers and 19 ELF binaries for x86-64, i386, ARM, AArch64, PowerPC and MIPS in both byte orders. The binaries split into two groups with no overlap:

| | 24-server build | 13-server build |
|---|---|---|
| Files | 10, fetched as `m.<arch>` | 9, fetched as `<arch>` |
| First Bazaar upload | 2026-08-22 | 2026-09-02 |
| Dropper host | 222.223.152[.]97:800 | 118.145.196[.]225:800 |
| STUN servers | 24 | the first 13 of the same list |
| Group tag kept | 19 characters | 29 characters |
| Command byte | none | offset 8, values 1 to 5 |
| Exploit templates | none | 7 requests, 6 `selfrep` tags |

The 13-server list is the 24-server list cut short, in the same order. Every binary matches a file name in one of the two droppers, so I think none of them is from Fortinet's first "evolution".

Bazaar labels these files Mirai, Gafgyt, Ngioweb or nothing; the labels cut across both groups.

### "Ensures every endpoint connection succeeds"

Fortinet writes that the 24-server build needs at least half its binding requests to succeed, and that the newer one "ensures every endpoint connection succeeds". The first half holds: the x86-64 24-server build gives up unless 12 of 24 succeed. The x86-64 13-server build needs 7 of 13:

```asm {title="13-server build ec199c78, after the 13 binding requests"}
400771  cmp dword ptr [rax], 0x80000000  ; (1) result >= 0 sets carry
400777  adc edx, 0
...
400783  cmp edx, 6
400786  jg 0x4007b0                      ; (2) 7 or more: go on
400788  call 0x401223                    ; close all, sleep 10 s, retry
```

A slot counts as a success when its result isn't negative (1), and seven are enough (2). A slot fails only when `socket`, `bind` or `sendto` fails. A request that gets no reply still counts; its mapped port just stays 0.

## The beacon and the command datagram

The registration beacon is the group tag from `argv[1]` (or `unknown`), with no terminator, followed by each socket's mapped port as a big-endian `u16`. That's the tag plus 26 bytes in the 13-server build, as eFeSpain measured, and the tag plus 48 in the 24-server build.

```text {title="Registration beacon"}
13-server build:  tag (1-29 bytes) | 13 x u16 port, big-endian
24-server build:  tag (1-19 bytes) | 24 x u16 port, big-endian
```

I first read the beacon loop from Ghidra's output as "ten rounds, then quit". The assembly counts failed `sendto` calls (`shr rax, 0x3f` on each result), not successful ones. The loop resends every 5 seconds without end, and gives up only after ten rounds in a row in which more than 7 of the 13 sends failed.

The tag says how the bot arrived. The droppers pass one on the command line, and each exploit passes its own: a bot planted through a KGUARD DVR runs as `sh wget.sh selfrep.kguard`.

![The 20-byte command datagram: bytes 0 to 7 ignored, byte 8 the command, bytes 9 to 12 an IPv4 address, bytes 13 and 14 a port, bytes 15 to 19 unused](/img/clingstun-syn-checksum/datagram.svg "The command datagram in the 13-server build")

The bot reads 20 bytes from any of its sockets and never looks at the sender. Bytes 0 to 7 are where a STUN header keeps its type, length and magic cookie, so the command sits in the transaction ID slot, as eFeSpain and Nozomi describe.

The 24-server build has no command byte. Its IP is at offset 8, its port at offset 12, and any 20-byte datagram means "connect there and run what you receive".

The 13-server build's five commands match the first five in Nozomi's list of eight, in the same order:

| Cmd | Arguments | 13-server build (x86-64) |
|---|---|---|
| 1 | IP, port | TCP connect, read up to 1,500 bytes within 3 s, pass them to `system()` |
| 2 | IP, port | start the scanner; IP:port serves `wget.sh` to new victims |
| 3 | | stop the scanner |
| 4 | IP, port | listen on the port and relay each connection to IP:port; exits if the bot's own address is private |
| 5 | | stop the relay |

Nozomi's two builds keep these five and add a second forwarding pair (6 and 7) and a timed flood (8). I'll leave the flood's parameters out.

## The scanner's SYN probes

Command 2 forks two children. One opens a raw TCP socket, when the bot is root, and waits for SYN-ACKs; the source port of each SYN-ACK picks the exploit. The other picks random public addresses and sends SYNs to ports 80, 8080, 85, 60001 and 52869.

Before it starts, the sender times 1,000 SYNs to 8.8.8[.]8 port 80 to set its pace, which eFeSpain spotted. Every fifth address also gets a KGUARD payload over UDP port 56575. That one needs no handshake.

Here is how the x86-64 13-server build fills in each SYN:

```asm {title="SYN builder at 0x400f2e (ec199c78), trimmed"}
400f42  mov edi, 0x270f        ; source port 9999
...
400f73  and ax, 0xfd0f
400f77  or ax, 0x250           ; (1) data offset 5, flags SYN
400f80  call 0x4041a2          ; window 0xffff
400f85  mov edi, r13d
400f8d  call 0x40419d          ; (2) htonl(source IP), result dropped
400f92  mov edi, r12d
400f95  call 0x40419d          ; (2) htonl(target IP), result dropped
400f9a  mov edi, 0x14
400fa6  mov word ptr [rsp+0x1e], ax  ; (3) TCP length 20
400fb1  movzx esi, word ptr [rax]    ; (4) sum 16 words
400fd7  mov word ptr [rsp+0x10], ax  ; checksum
```

The header is a plain SYN (1). The checksum loop (4) sums the 20-byte header plus a 12-byte pseudo-header, but the code throws away both converted addresses (2) and never writes the protocol byte. Only the length is filled in (3). The checksum therefore depends on nothing but the destination port. The i386 build drops the addresses the same way; the AArch64 build stores them.

I lifted the function into Unicorn and ran it for two address pairs:

```console
$ python3 emu_syn.py ec199c78... C6336401 CB007105 80
syn 270f005000000000000000005002ffff888a0000
sport 9999 dport 80 seq 0 ack 0 off 5 flags 0x2 win 65535 csum 0x888a
correct 0x2249
verify_sum 0x6641
```

For 198.51.100[.]1 to 203.0.113[.]5, the right checksum would be 0x2249; the bot writes 0x888a. Counting the 236 zero bytes the bot also sends (below), a receiver's sum comes to 0x672d instead of 0xffff. With 10.0.0.2 to 8.8.8[.]8 the bot still writes 0x888a. Each port gets one constant: 0x888a for 80, 0x694a for 8080, 0x8885 for 85, 0x9e78 for 60001 and 0xba54 for 52869.

### The builds that store the addresses still fail

The bot sends each SYN with `sendto(raw, buf, 0x100, ...)`: the 20-byte header and 236 zero bytes. The AArch64 build and Nozomi's two builds (90d738a8, and 3a6927a3 below) store the addresses and protocol 6. They all still write 20 as the pseudo-header's length.

In 90d738a8 the send buffer is a `.bss` array. The scanner is the only code that references it and writes 20 bytes, so the other 236 stay zero. A receiver sums with a length of 256 instead of 20. It gets 0x00ec instead of 0xffff on every port I tried: 0xec is 236, the missing length. 3a6927a3 zeroes its 256-byte stack buffer before the loop, so it fails the same way.

### What that does to propagation

A Linux raw socket doesn't compute TCP checksums for the caller, and a receiving stack discards a segment whose checksum fails. So the scanner's SYNs should draw no SYN-ACKs. The six HTTP exploits (Realtek UPnP, LB-LINK, Linksys, TBK, JAWS and the China Mobile `shortcut_telnet.cgi`) can't be reached through the bot's own probes. The dispatcher checks only the SYN and ACK flags and the source port, so a SYN-ACK from one of those ports for any other reason would still set it off.

That's an inference from the code; I didn't put a probe on a wire. It fits what the reports saw, though. Nozomi saw Cling delivered through CVE-2021-35394, the Realtek UDP `orf;` payload that Nozomi's builds send to port 9034, and the KGUARD UDP payload in the 13-server build needs no handshake either. Fortinet traced its infections to three download hosts.

## One build encrypts its strings

None of the bot's own strings in Nozomi's 3a6927a3 are readable; only libc's are. Its `.rodata` entries are noise with zero padding between them. XORing the entries where the STUN addresses should sit against 90d738a8's plaintext list gives the same keystream for each: `26 3b 87 09 a1 86 2e 12 ...`.

The decoder at 0x404ac0 is ChaCha20 (rotations 16, 12, 8 and 7, ten double rounds), restarted at counter 0 for each string:

| Field | Value | Where |
|---|---|---|
| Key | `161e191b111f001d041c0e080b1a120705090d0f060a15010c141f1702031318` | `.data`+0x0c |
| Nonce | `1e004a000000000000000000` | start of `.data` |
| Counter | 0 for every string | |

The key is the byte values 0x00 to 0x1f in shuffled order, except that 0x1f appears twice and 0x10 not at all. Decrypting the 64 call sites gives the same STUN list and paths as 90d738a8, including `/proc/self/oom_score_adj` with `-1000`. It adds a cleanup command for the files the bot copies into `/tmp`.

One call decrypted to garbage. I blamed Ghidra's label, because the ciphertext starting a byte later, at 0x413069, decrypts to `/tmp/statm`. The fact-checker pointed out that the sample itself passes 0x413068 (`addiu $a1, $a1, 0x3068` at 0x40064c), so the bot decrypts ten bytes of garbage there at run time. The bug is the malware's.

## Smaller things

The competitor killer kills a process when its executable lives in `/tmp/` or `/var/tmp/` and the name in its command line differs. The bot runs it once at start-up. The one-second loop eFeSpain describes only starts when hiding fails, which means when the bot isn't root.

As root, the bot copies four files from `/proc/1/` into `/tmp` and bind-mounts `/tmp` over its own `/proc/<pid>`, then names itself with `prctl(PR_SET_NAME, " ")`, a single space. The 13-server dropper starts by unmounting and killing every process whose `/proc/<pid>` has a non-proc filesystem on it, then everything running from `/tmp`. That should clear out any 24-server bot, which runs from `/tmp` and hides the same way, before the replacement starts.

For hunting, these are the stable details:

- STUN Binding Requests with an all-zero transaction ID (Nozomi), then a non-STUN datagram to the same servers every 5 seconds.
- TCP SYNs from source port 9999 with sequence 0, window 65535 and an invalid checksum; scan probes carry 236 zero bytes, the 1,000 timing probes none.
- A `/proc/<pid>` mount entry in `/proc/mounts`, a listener on 127.0.0.1:33957 (13-server and later builds), and a process named " ".

## The extractor

[families/cling](https://github.com/stateless-re/tools/tree/main/families/cling) reads any Cling ELF and prints the STUN list, `selfrep` tags, exploit targets (method and path only) and persistence markers as JSON. For an encrypted build it finds the key itself. On 3a6927a3 it recovers 62 of the 64 strings, skipping the 2-character `.p` and `.r`.

## What I couldn't determine

- Which of Nozomi's two builds is newer.
- What commands 6 and 7 do in detail. I compared their PID slots and stopped there.
- Whether any receiver accepts the bad SYNs. Some embedded stacks might not check, but I have nothing that shows one.
- The 7-command build eFeSpain analysed isn't among these 23 files.

## Indicators

| SHA-256 | Role | Listed by |
|---|---|---|
| `dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a` | wget.sh dropper, 118.145.196[.]225 | Fortinet |
| `5c4e263546fb21f8fe8732789a5b6583eaa8ae11ebeef099462a7c9bf50e022d` | wget.sh dropper, 222.223.152[.]97 | Fortinet |
| `9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068` | 24-server build (ARM) | Fortinet |
| `c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497` | 24-server build (ARM) | Fortinet |
| `f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec` | 24-server build (ARM) | Fortinet |
| `10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da` | 24-server build (MIPS BE) | Fortinet |
| `2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf` | 24-server build (MIPS) | Fortinet |
| `b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad` | 24-server build (PowerPC BE) | Fortinet |
| `284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14` | 24-server build (i386) | Fortinet |
| `6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a` | 24-server build (i386) | Fortinet |
| `e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4` | 24-server build (i386) | Fortinet |
| `dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3` | 24-server build (x86-64) | Fortinet |
| `a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84` | 13-server build (AArch64) | Fortinet |
| `121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487` | 13-server build (ARM) | Fortinet |
| `48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302` | 13-server build (ARM) | Fortinet |
| `4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07` | 13-server build (ARM) | Fortinet |
| `48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73` | 13-server build (MIPS BE) | Fortinet |
| `76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2` | 13-server build (MIPS) | Fortinet |
| `c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8` | 13-server build (i386) | Fortinet |
| `e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c` | 13-server build (i386) | Fortinet |
| `ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81` | 13-server build (x86-64) | Fortinet |
| `90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2` | 8-command build (MIPS) | Nozomi |
| `3a6927a3399f2a10bb2e2229482e5096e5f1c3401a87f7f1730db11243531e28` | 8-command build, ChaCha20 strings (MIPS) | Nozomi |

Network: the droppers' hosts 222.223.152[.]97:800 and 118.145.196[.]225:800 (Fortinet), and the STUN relay 145.249.115[.]184:3478 (Nozomi). The other STUN servers in the list are public services and shouldn't be blocked on this evidence alone.

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1190 | Exploit Public-Facing Application | `selfrep` exploits and the operator's droppers |
| T1037.004 | Boot or Logon Initialization Scripts: RC Scripts | `.cling` copies in `inittab`, `rcS`, `rc.boot` |
| T1564 | Hide Artifacts | bind mount over `/proc/<pid>`, name " " |
| T1095 | Non-Application Layer Protocol | 20-byte UDP commands on STUN-mapped ports |
| T1090 | Proxy | command 4 relay |
| T1027 | Obfuscated Files or Information | ChaCha20 strings in 3a6927a3 |

Cling hides its orders in a STUN transaction ID and its own process behind init's `/proc` files, then sends scan probes that announce themselves twice over: source port 9999 and a checksum that never verifies. For a defender, the probes are the easy part to catch, and for now the UDP exploits are the paths worth patching.

## Credits

eFeSpain's [Cling chapters](https://blog.efespain.com/cling/) came first. [Nozomi Networks Labs](https://www.nozominetworks.com/blog/a-stunning-disguise-cling-malware-masquerades-as-google-) found the relay server, and [Fortinet](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure) published the hashes this post starts from.
