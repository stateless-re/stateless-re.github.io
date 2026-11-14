---
title: "Twenty NIK C2 files, one user ID, and a build that can't read its own config"
date: 2026-11-14
slug: "nik-c2-config"
description: "All eight NIK C2 hashes from the Talos report plus twelve more from MalwareBazaar, read statically: the config XORed with the string \"NIK\", the key that is SHA-256 of the seed's text, how the certificate pin and the fallback address really work, a user ID shared by every build, a v2 build whose protected config can't decode, two delivery wrappers, and an extractor."
tags: ["nik-c2", "nikrat", "go", "config-extraction", "certificate-pinning", "windows"]
sample:
  family: "NIK C2 agent (NIKRAT)"
  sha256: "ae38f1181c9dd0db7224d6023e335eb2cdabb0f441906d14ffba8602b7abca3c"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/ae38f1181c9dd0db7224d6023e335eb2cdabb0f441906d14ffba8602b7abca3c/)"
toc: true
---

The NIK C2 agent stores its C2 address, its AES seed and its agent ID as hex strings XORed with a rolling three-byte key, and the key is the ASCII string `NIK`. Its AES-256-GCM key is SHA-256 of the seed's hex text, and the hard-coded address `2.26.51[.]12` that looks like a fallback is used only when the primary field is empty. Every one of the 17 configs I could decode carries the same user ID, `7b85683a-c3e6-43c2-9bfb-583377ada5f6`, which the agent sends in each heartbeat as `user_uid`. One build stores its config in a different, protected format that, on my reading of its code, the agent itself can't decrypt, which sends it to that default address.

Cisco Talos [described NIK C2](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/) on October 29 (Chetan Raghuprasad): a Go remote access tool with more than 52 commands, three C2 tiers and AES-256-GCM traffic. The report gives one seed and the key derived from it, and says the seed is "stored in obfuscated form in the binary data section" and that the key is "derived from a hardcoded seed", without the encoding or the derivation. Threatray uploaded thirteen files to MalwareBazaar under the name NIKRAT (one on September 29, twelve on October 30, one of those a Talos hash) and published an [IOC list](https://github.com/threatray/threat-research/tree/main/2026-10-30-NIKRAT) of sandbox C2s, mutexes and persistence paths. I read all twenty files statically (pefile, capstone, a small Go symbol-table parser, Python; nothing was run). This post covers the config format and the parts of the network logic the two reports don't, plus a [config extractor](https://github.com/stateless-re/tools/tree/main/families/nikc2).

## What I found

- In every build but one, the C2 URL, the user ID, the seed and the agent ID are hex strings decoded with `out[i] = in[i] ^ (("NIK")[i % 3] + i)`. The AES key is `SHA-256(seed as ASCII hex)`; that reproduces the key Talos published from the seed Talos published.
- Every Go build carries the same hard-coded address, `hxxps://2.26.51[.]12:443`, but it enters the server list only when the primary C2 field is empty. The "embedded encrypted server list" is empty in the 16 builds that have one and whose config decodes, so those agents have exactly one server and never rotate. TLS chain validation is off (`InsecureSkipVerify`); the only check is a pin on the SHA-256 of the server's DER certificate, which a builder placeholder `{{SERVER_FINGERPRINT}}` would disable.
- The 14 builds that kept their Go symbols have 28, 52, 55, 59 or 60 command handlers, and each smaller set is contained in every larger one. The oldest-looking build has no server rotation at all.
- Build `5a39bd95` stores its fields as Base64 blobs shaped `256 bytes | IV | ciphertext`. Its decoder hands the 256-byte blob straight to `aes.NewCipher`, which rejects any key that isn't 16, 24 or 32 bytes, so the fields come out empty and the agent's defaults take over, including the C2 2.26.51[.]12, the address Threatray's IOC list gives for this file.
- Two of the twenty files are wrappers. A PyInstaller binder drops agent `e7f51534` next to a fake game-cheat menu, and a .NET packer called FileCrypt decrypts to agent `876b1dbc` with a master key stored in its own code.

## Twenty files, eighteen agents

The Talos IOC file lists eight SHA-256 hashes. One is on MalwareBazaar (`ae38f118`); the other seven are on Hybrid Analysis, where I downloaded them. MalwareBazaar has twelve more files signed NIKRAT, all uploaded by Threatray: eleven first seen on 2026-10-30 between 15:45 and 15:46 UTC (with `ae38f118`) and one (`e7f51534`) on 2026-09-29. The 18 Go builds, ordered by handler count:

| SHA-256 (prefix) | Source | Handlers | Primary C2 | Pin (prefix) | Masquerade name |
|---|---|---|---|---|---|
| `0fb93dbb` | Bazaar | 28 | `hxxps://2.26.51[.]12:443` | `a8993c1f` | `svchost.exe` |
| `5d25efba` | Talos | 28 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `svchost9999.exe` |
| `a7279f24` | Bazaar | 28 | `hxxps://87.120.196[.]120:443` | `3bd52541` | `svchost53.exe` |
| `bf83345c` | Talos | 28 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `svchostpopa.exe` |
| `2a010563` | Talos | 52 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `oppo.exe` |
| `99573a79` | Talos | 52 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `svchost.exe` |
| `d0abbd4e` | Bazaar | 55 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `svchost.exe` |
| `1fee4cd8` | Talos | 59 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `svchost23.exe` |
| `ae38f118` | Talos, Bazaar | 59 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `simvol.exe` |
| `30817712` | Talos | 60 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `svchost.exe` |
| `507436d5` | Bazaar | 60 | `hxxps://2.26.49[.]181:443` | `6717f6b8` | `svchost.exe` |
| `626619e1` | Bazaar | 60 | `hxxps://2.26.49[.]181:443` | `6717f6b8` | `svchost.exe` |
| `6583eb22` | Talos | 60 | `hxxps://total-sitevv[.]lol:443` | `c0319869` | `svchost.exe` |
| `e7f51534` | Bazaar | 60 | `hxxps://2.26.49[.]181:443` | `6717f6b8` | `svchost.exe` |
| `0008c95f` | Bazaar | no symbols | `hxxps://191.44.109[.]125:443` | `750872a6` | `svchost.exe` |
| `876b1dbc` | Bazaar | no symbols | `hxxps://191.44.109[.]125:443` | `750872a6` | `svchost.exe` |
| `9b228bf5` | Bazaar | no symbols | `hxxps://2.26.49[.]181:443` | `750872a6` | `svchost.exe` |
| `5a39bd95` | Bazaar | no symbols | protected (see below) | `750872a6` | `opsec.exe` |

The other two files are the wrappers: `46bea5c1` (PyInstaller) and `9d9d9901` (.NET). All 18 agents are x64 Go binaries. The 14 with a symbol table were built with go1.23.4; the four without one have no Go version string and no `/opt/nik_panel/...` build path left, and three of them (`0008c95f`, `5a39bd95`, `876b1dbc`) keep only a few hundred `runtime.` strings, which looks like an obfuscator that renames symbols. Their string literals are intact, which is why the same config scan works on them.

The build path Talos quotes, `build_52b79724a1fc4b8f`, belongs to `30817712`, not to `ae38f118`, the one Talos hash on Bazaar (`build_5ab821a2a2bea97a`). Each build has its own directory under `/opt/nik_panel/data/`, which fits a panel that writes a fresh source tree per build.

## The config is hex, XORed with "NIK"

Go stripped the symbols but not the function table, so the names come back: 6,571 functions in `ae38f118`, 261 of them in package `main`. `main.init.0` runs before `main.main` and calls `main.dec` on four string globals, writing each result back over the original. Here is `main.dec`, with the stack check and the empty-string returns trimmed:

```text
0x6d239c: bt   ebx, 0                    ; (1) odd length -> return ""
0x6d23ac: call encoding/hex.DecodeString ; (2)
...
0x6d23c4: lea  rdi, [rip + 0xbe955]      ; (3) 0x790d20 = "NIK"
0x6d23cb: movzx edi, byte ptr [rdi + rax];     key[i % 3]  (i % 3 via the 0xaaaaaaaaaaaaaaab multiply)
0x6d23cf: add  edi, ecx                  ; (4) + i
0x6d23d1: xor  edx, edi                  ;     in[i] ^ ...
0x6d23d3: mov  byte ptr [rsi + rcx], dl
```

The input must have an even length (1) and be valid hex (2). Each byte is then XORed with a key byte from address 0x790d20 (3), which holds `4E 49 4B`, the ASCII string `NIK`, plus the byte's index (4), truncated to 8 bits:

```text
out[i] = in[i] ^ ((key[i % 3] + i) & 0xff),   key = "NIK"
```

Applied to the four globals in `ae38f118`:

| Slot | Encoded (start) | Decoded |
|---|---|---|
| +0x00 | `263e39213e6a7b7f2738…` (56 chars) | `hxxps://total-sitevv[.]lol:443` |
| +0x10 | `792875647b6867317e34…` (72 chars) | `7b85683a-c3e6-43c2-9bfb-583377ada5f6` |
| +0x30 | `7c2f7d602f323660656e…` (128 chars) | `2e01bbb069a24b73438e397701728d399a7b2db5c0afbff35d57273f6cc01d52` (the seed of the AES key) |
| +0x40 | `2f2d12377c6067676061…` (30 chars) | `ag_f103736ad251` |

The globals sit in a block of 16-byte Go string headers, and the rest of the block is plain text. I mapped each slot by following which functions read it and what they do with it:

| Offset | Example (`ae38f118`) | Read by (what it gates) | Meaning |
|---|---|---|---|
| +0x00 | encoded | `init.0`, `initServerList` | primary C2 URL |
| +0x10 | encoded | `init.0`, `heartbeatData` | user ID, sent as `user_uid` |
| +0x20 | `true` | `init.1` → `hideConsole` | hide the console |
| +0x30 | encoded | `init.0`, `aesEncrypt`, `aesDecrypt` | AES seed |
| +0x40 | encoded | `init.0`, `agentID` | agent ID |
| +0x50 | `true` | `main` (`spawnWatchdog`), `heartbeatData` | watchdog process |
| +0x60 | `true` | `main` (`tryMasquerade`, `spoofProcessName` loop), `tryInstallSelf` | copy under a masquerade name, spoof the process name |
| +0x70 | `true` | `main` (`addAutoStart`) | Run-key autostart |
| +0x80 | `true` | `main` (`tryInstallSelf`) | install a copy and relaunch |
| +0x90 | `true` | `tryInstallSelf` (`cleanupBat`), `tryMasquerade` | clean up after relaunching (I followed only the `tryInstallSelf` use) |
| +0xa0 | `simvol.exe` | `main`, `tryMasquerade` | masquerade file name |
| +0xb0 | `c0319869…` | `verifyServerCert` | certificate pin (SHA-256) |

The 60-handler builds insert a `self_heal` flag at +0xb0, read by `handleSelfHeal`, and move the pin to +0xc0. Three of the four symbol-less builds add more slots after the pin: `false`/`true` values and one 8-hex-digit string (`1b704834` in `0008c95f`, `73c50694` in `876b1dbc`, `fcc60f15` in `5a39bd95`) that nothing I followed explains.

Two defaults show the builder at work. If the masquerade name is empty or still equals `{{PROC_NAME}}`, `main.main` replaces it with `svchost.exe`; it compares the global against the bytes of that placeholder, eight, four and one at a time. If the user ID is empty it becomes `default`. The panel evidently fills a template and compiles it, and the agent guards against fields the panel left untouched.

## The AES key is SHA-256 of the seed's text

`main.aesEncrypt` loads the seed string, converts it to a byte slice and calls `crypto/sha256.Sum256`, then `aes.NewCipher` on the 32-byte result and GCM with a 12-byte nonce and 16-byte tag. Nothing hex-decodes the seed first: the key is the hash of the 64 ASCII characters. Talos's seed checks out:

```text
$ python3 -c "import hashlib; print(hashlib.sha256(b'd791dd0ff3228ed29a8d7333d4567be829159c5632ea347780992006f91c5295').hexdigest())"
4887afc0a574e9419a9695ef083460f58e4ef9a1c40793523ce112251273bdf9
```

That is the key Talos printed, and the seed decodes from build `30817712`, the one with Talos's build path. Every build has its own seed except `5d25efba` and `bf83345c`, two 28-handler builds pointed at the same domain, which share `c85a5729…` and therefore one key. If the seed is shorter than 16 characters, `main.main` replaces it with 32 random bytes in hex. A build like that encrypts with a key the server has no way to know, so I take the branch as a guard for a broken build rather than a feature.

The wire format is in the Talos report: a random 12-byte nonce, the ciphertext and the tag, Base64-encoded under the JSON key `e`. With the per-build key from the extractor, anyone holding a capture of this traffic can decrypt it.

## What the three C2 tiers hold

Talos says the agent "routes traffic across three prioritized C2 tiers", "runtime-updated URLs, an embedded encrypted server list, and a hardcoded fallback address", without the values. `main.initServerList` builds the list:

1. the decoded primary URL;
2. each `|`-separated entry of another `dec`-encoded global, skipping any entry equal to the primary;
3. if the list is still empty, the literal `hxxps://2.26.51[.]12:443`.

Because the primary goes in first, the list is empty only when the primary decodes to nothing, and only then does the hard-coded address enter it. `main.nextServer`, which the HTTP loop calls after a failed POST, moves to the next entry only when the list has more than one (`cmp rbx, 1; jle` at 0x6d2b78). In the 16 builds that have a server-list global and a decodable config, that global is an empty string: in `ae38f118` it sits at 0xa448e0, in the zero-filled part of `.data`, and only `initServerList` reads it; no function in package `main` writes the list except `initServerList` itself. So each of those agents has one server, its primary, and never rotates. The literal `hxxps://2.26.51[.]12:443` is the same in all 18 Go builds, but in this set it is reached only by `0fb93dbb`, whose primary is that address, and by `5a39bd95` (below). `0fb93dbb` has no `initServerList`, `getServer` or `nextServer` at all, so it predates rotation. I first read the literal as a fallback every agent would walk to when its primary died; the fact-check of this post caught that the rotation guard makes that impossible with a one-entry list.

The TLS setup is where the pin comes in. `main.pinnedTLSConfig` allocates a `tls.Config` and sets three fields: offset 0xa0 (`InsecureSkipVerify`) to 1, offset 0x80 (`ServerName`) to the host, and offset 0x50 (`VerifyPeerCertificate`) to a closure that calls `main.verifyServerCert`. With chain checks off, the callback is the only check. Its logic, rewritten from the disassembly:

```go
func verifyServerCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
    if pin == "" || pin == "{{SERVER_FINGERPRINT}}" || strings.Contains(pin, "{{") {
        return nil                                        // (1)
    }
    if !currentIsPrimary() {
        return nil                                        // (2)
    }
    sum := sha256.Sum256(rawCerts[0])                     // (3)
    if hex.EncodeToString(sum[:]) != strings.ToLower(pin) {
        return errors.New("server certificate fingerprint mismatch")
    }
    return nil
}
```

An unfilled builder placeholder turns the pin off (1). The pin is skipped when the current server isn't the primary (2), which would matter for a build with a real server list; none of these has one, so `currentIsPrimary` is always true and the pin always applies (`0fb93dbb` has no such check at all). What it hashes is the leaf certificate as sent, DER-encoded (3), so the pin is the ordinary SHA-256 certificate fingerprint that certificate-scan services index. Five pins appear across the 18 builds. Threatray already published one of them, `750872a6…`, for the `CN=2.26.49[.]181` certificate on 2.26.49[.]181 and 191.44.109[.]125; the other four are in the indicators below. Builds with the primary 2.26.49[.]181 pin two different certificates (`6717f6b8…` in the three 60-handler builds, `750872a6…` in `9b228bf5`), so I think that server changed certificates at least once.

## One user ID in every build

The +0x10 slot decodes to the same UUID in all 17 decodable configs. To see where it goes, I read the heartbeat's struct type from Go's type metadata, which keeps field names, offsets and JSON tags:

```text
Hostname       +0x00  json:"hostname"
OS             +0x10  json:"os"
IP             +0x20  json:"ip"
UserUID        +0x30  json:"user_uid"
Username       +0x40  json:"username,omitempty"
ProxyPort      +0x50  json:"proxy_port,omitempty"
Upstream       +0x58  json:"upstream,omitempty"
Ts             +0x68  json:"ts"
Uptime         +0x70  json:"uptime,omitempty"
WatchdogStatus +0x80  json:"watchdog_status,omitempty"
```

`main.heartbeatData` builds this struct at `rsp+0x68` and stores the decoded UUID at `rsp+0x98`, which is offset 0x30: `UserUID`. Every agent therefore reports the same `user_uid`. Read with the empty-field default of `default`, this looks like the ID of the panel account that ordered the build. I can't see the panel, so that reading is an inference, but it predicts that all 17 builds, spread over five C2 addresses and five handler counts, were ordered from one account.

The agent ID is different per build and embedded. `main.agentID` uses the embedded value if there is one (`ag_` plus 12 hex digits in every build here). Only when it's empty does it read `%APPDATA%\NIKPanel\agent.id`, or generate `ag_` plus 16 random hex digits and write that file. The `ag_<16 hex chars>` format in the Talos report matches that generated branch. These 17 builds never reach it, so the `NIKPanel\agent.id` file is not a reliable host indicator for them. The protected build below is the exception.

## The agent grew between builds

The handler names (`main.handleQuickSteal`, `main.handleBootRansom`, ...) survive in the 14 builds with symbols, and the sets are nested:

| Handlers | Builds | Added over the previous set |
|---|---|---|
| 28 | `0fb93dbb`, `5d25efba`, `a7279f24`, `bf83345c` | files, processes, shell, passwords and Wi-Fi keys, clipboard, keylogger, screenshots, SOCKS5/HTTP and reverse proxy, autostart, self-destruct |
| 52 | `2a010563`, `99573a79` | 24 more, including AMSI and UAC bypass, HVNC, webcam, COM hijack, bootkit preparation, wallet export |
| 55 | `d0abbd4e` | `AutoTag`, `ProcessHollow`, `QuickSteal` |
| 59 | `1fee4cd8`, `ae38f118` | `AIGenerate`, `BootRansom`, `Convert`, `MicStream` |
| 60 | `30817712`, `507436d5`, `626619e1`, `6583eb22`, `e7f51534` | `SelfHeal` |

I read this as versions of one code base, for two reasons. The config layout changes in step with it: the `self_heal` slot appears exactly in the 60-handler builds. And the Hybrid Analysis submission dates of the seven Talos files follow the handler counts: the two 28-handler builds on 2026-08-14, the two 52-handler builds on 2026-08-16 and 08-17, then the 59-handler `1fee4cd8` and the 60-handler `30817712` and `6583eb22` on 2026-08-19. Talos notes that the PE timestamps are zeroed, so submission dates are the best clock available. A builder that strips modules per order would also produce nested sets, so this stays an inference, but the dates lean toward versions.

## A build that can't read its own config

`5a39bd95` failed the first pass of my scan. Its config block has the same shape (flags, `opsec.exe`, pin `750872a6…`), but five slots hold Base64 instead of hex:

```text
+0x00  Ib4jJziRR0i/KtTm...7S4w4yDOrAkah23xBQ==|2AnoXapU3sGRBXmQKkDLJg==|33CM9/xj1SdG4wpYOrnM1SjvJVCMfKI7ozQjfkZ/gO8=
+0x30  CWvYP/Rs+c8FL90BjEXr6w==:5iE1Kp2Fv1m1+XjY3qNl4qC61fWCngvLxx8C0URN0a+c/...
```

The `|` fields split into 256, 16 and 16 to 48 bytes; the `:` field into 16 and 80. A 256-byte first part looked like an AES key wrapped with RSA-2048, so I went looking for the private key the agent would need: PEM headers, PKCS#1 and PKCS#8 DER prefixes, PKIX public keys, 512-digit hex numbers. There was none, and the right question was what the code does with the blob.

The build has no symbols, but `.pdata` still gives function boundaries, and cross-references to the config slots lead to one function that decodes four of them in place, as `main.init.0` does. Its decoder dispatches on the separator: a string containing `|` goes to one routine, a string containing `:` to another (passing the seed slot's current value as the key), anything else to the old hex-and-`NIK` routine. The `|` routine splits into three parts, Base64-decodes each with `StdEncoding`, and passes part one straight to a function that accepts only 16-, 24- or 32-byte keys (`aes.NewCipher`; its length switch is the giveaway). Then CBC with part two as the IV. There is no RSA step. A 256-byte key fails, and the routine returns an empty string.

The seed fares no better. When `init` decodes the seed slot, the key it passes is the seed slot's own 133-character encoded string, and `aes.NewCipher` rejects that too. So, on my reading, all five protected fields decode to empty, and `main.main`'s defaults take over: primary C2 `hxxps://2.26.51[.]12:443`, user ID `default`, and a random seed. That address then becomes the first list entry, so the pin `750872a6…` is checked against it. Threatray's IOC list gives 2.26.51[.]12 as this file's C2, which is what that reading predicts. With a random seed, the panel can't read anything this agent sends.

My guess is a builder that started wrapping keys before the agent template learned to unwrap them. Whatever the reason, the build's real C2 is the 32-byte ciphertext in the first field, and without knowing what the panel meant the 256-byte part to be, it stays there.

## Two wrappers

`46bea5c1` is a PyInstaller bundle (Python 3.11) whose entry script, `stub`, is 9,425,098 bytes after decompression. It holds three Base64 strings and writes them to a temporary folder: `Installer.exe`, `Loader.exe` and `_fair_Fair (4).txt`. `Loader.exe` is byte-for-byte agent `e7f51534`. `Installer.exe` (`161fedd7…`, not on MalwareBazaar) is a .NET form named `NewLoaderInstaller` whose strings are a fake cheat menu for the game Rust: `AIMBOT`, `VISUALS`, `[ Loader ] demo dummy v1.2.3`, a `CoolBypass.dll` check. The text file reads `GAME VERIFYED CHECK!` followed by `CLIENT SEED`, `HASH` and two `SALT` lines, all `undefined`, the vocabulary of "provably fair" gambling sites. The lure is aimed at players.

`9d9d9901` is a .NET packer whose own strings call it FileCrypt; its error messages and self-test descriptions are in Russian. The payload is appended to the stub with an 8-byte footer, `<length> "FCX1"`. The blob starts with `SX11`, a 16-byte salt, two 12-byte nonces and a 4-byte ciphertext length, and is encrypted twice: AES-256-GCM inside, ChaCha20-Poly1305 outside, both with associated data `"SX11" || salt`, under keys derived by HKDF-SHA256 from a master key that the packer's code embeds as a Base64 constant (`4jVQKr…`) with the infos `SX11-AES-256-GCM` and `SX11-CHACHA20-POLY1305`. The packer implements GCM and ChaCha20-Poly1305 itself; Python's `cryptography` verifies both tags, so they're standard. Inside is `client (15).exe`, gzip-compressed, which is agent `876b1dbc`. That explains why Threatray's sandbox tied a .NET file to 191.44.109[.]125.

## The extractor

[`families/nikc2/extract.py`](https://github.com/stateless-re/tools/tree/main/families/nikc2) finds the config block from the Go string headers in `.data`, derives the XOR key from the known plaintext at the start of the C2 URL (its `https` scheme) instead of assuming `NIK`, and prints the decoded fields, the AES key, the pin, the flags, the server-list global and the fallback. It finds the decoder by its in-place call pattern instead of by name, so it works on the symbol-less builds, and it unwraps FileCrypt and the PyInstaller binder in memory (`-o DIR` writes the inner files). For a v2 build it reports the shape of each protected field. Abridged output for `ae38f118`, with the URLs defanged:

```json
{
  "format": "v1",
  "xor_key": "4e494b",
  "config": {
    "c2": "hxxps://total-sitevv[.]lol:443",
    "user_uid": "7b85683a-c3e6-43c2-9bfb-583377ada5f6",
    "seed": "2e01bbb069a24b73438e397701728d399a7b2db5c0afbff35d57273f6cc01d52",
    "agent_id": "ag_f103736ad251",
    "process_name": "simvol.exe",
    "cert_pin_sha256": "c03198697d3e4e9250fc8d64a9818cc1677a2afddfdbf3db27ee94e41333764b",
    "aes_key": "e33b53f18bb240ce629f3d987c2c266ce5ae99f480bee658b46d94f929f8f31f"
  },
  "fallback_urls": ["hxxps://2.26.51[.]12:443"],
  "build_path": "/opt/nik_panel/data/build_5ab821a2a2bea97a",
  "handler_count": 59
}
```

It runs on all 20 files in this post and exits 0.

## What I couldn't determine

- The real config of `5a39bd95`. Its fields are wrapped with a key I don't have, and its own code can't unwrap them either.
- What the 8-hex-digit slot in the symbol-less builds is. Talos mentions "the embedded eight-byte hex token matching the build identifier" without a value; these strings are four bytes, and none matches a build path I have.
- Whether the handler sets are versions or per-order module selections (see above).
- The "runtime-updated URLs" tier. In `ae38f118` nothing but `initServerList` writes the server list, so I found no runtime update path in these builds; Talos may have seen it elsewhere.
- What the panel does with `user_uid`. I only see the agent's side.

## Hunting

Host:
- Mutexes `Local\NIK_<16 hex>_agent` and `Local\NIK_<16 hex>_wd`, where the hex is the first 8 bytes of SHA-256 over the executable's full path (Threatray lists the mutex shape; the derivation is from `main.exeHash`). Strong alone.
- A process started with `--watchdog` alongside an identical binary without it. Moderate; the argument is short and generic.
- Copies named `svchost.exe` outside System32, or names like `svchost23.exe`, `svchost53.exe`, `svchost9999.exe`, `svchostpopa.exe`, `simvol.exe`, `oppo.exe`, `opsec.exe`. Threatray lists the drop paths.
- `%APPDATA%\NIKPanel\agent.id`, written only when the agent-ID slot decodes to nothing. The 17 decodable builds never write it; on my reading of `5a39bd95`, that build would.

Network:
- HTTPS to `2.26.51[.]12:443`: the primary of `0fb93dbb` and the default for any build whose primary field is empty or undecodable, such as `5a39bd95`. Agents with a working config don't use it.
- TLS servers whose certificate SHA-256 equals one of the five pins below. Searching certificate-scan data for those fingerprints can find servers set up for agents I haven't seen.
- The URL paths `/api/c2/update`, `/api/c2/result`, `/api/c2/screen`, `/api/c2/file_chunk`, `/api/c2/rproxy_up`, `/api/c2/ws`, and POST bodies with Base64 ciphertext under the JSON key `e` next to the agent ID in clear (both from the Talos report).
- With a capture and the build's AES key, heartbeats (`heartbeatData`, then `encryptPayload`) decrypt to JSON containing `"user_uid":"7b85683a-c3e6-43c2-9bfb-583377ada5f6"` for every build whose config decodes (not `5a39bd95`).

Static:
- Hex strings that decode with the rolling `NIK` key to a URL starting with `https`. Short, cheap to test, and they survive symbol renaming. Strong in combination with a Go PE.
- The literal `{{SERVER_FINGERPRINT}}` next to `server certificate fingerprint mismatch`. Present in all 18 Go builds.
- `/opt/nik_panel/data/build_` in builds that kept their paths.
- A file ending in `FCX1` whose appended blob starts with `SX11`: the FileCrypt packer, whatever it wraps.
- PyInstaller bundles whose script holds Base64 PE files plus a text starting `GAME VERIFYED CHECK!`.

## Indicators

| SHA-256 | Role |
|---|---|
| `ae38f1181c9dd0db7224d6023e335eb2cdabb0f441906d14ffba8602b7abca3c` | agent, 59 handlers (Talos, Bazaar) |
| `30817712277bba54e4cb8640f4005aad35f5172f88cf046aea545d029e12ccba` | agent, 60 handlers (Talos) |
| `6583eb22ca554e749b647d68ae76f7279a8dc538196ebde1412669357a027de5` | agent, 60 handlers (Talos) |
| `1fee4cd8d3560e6c60ba50451860adf6e705f26fd3fe1c1ccc058f4e8b13073a` | agent, 59 handlers (Talos) |
| `2a01056369cc691f5bed6bd2654930a81d1bc240a568a0d5b209aceef3b5c9c9` | agent, 52 handlers (Talos) |
| `99573a79f393299049216237d0d23761d67f6a8507a7a0cfe17cb30837f68f00` | agent, 52 handlers (Talos) |
| `5d25efba2119f52d08214a590fedb45a5c9fe5e2850fd87e7bca24c92745e6d1` | agent, 28 handlers (Talos) |
| `bf83345ca66bdc4bd45ade608a06361d18927dd80351e9a1d8cbe8eda5d78402` | agent, 28 handlers (Talos) |
| `0fb93dbb9525004f9e5b1ee4bcd6b6638700bee576413e955c8c96292fa964ee` | agent, 28 handlers, no rotation |
| `a7279f2425746deafef5c2ff6ebe612c7cc6062601be37d83e07ecdd1bb72ba2` | agent, 28 handlers |
| `d0abbd4e13d026cea0f62d250080f721a37c3a033afb6b5ec368b31e07243f24` | agent, 55 handlers |
| `507436d5132cefeea7e35e3481c5726f00a90e041a6bbb55cfcf50b51e2b3b73` | agent, 60 handlers |
| `626619e1a2ba0cfaf7809ad3fed0d8958762379bcdc549125699ce7e6a938500` | agent, 60 handlers |
| `e7f51534b1106707a7e86b1531dfd4444639b824baec66c5e1ad8005b1f7da0a` | agent, 60 handlers; `Loader.exe` in the binder |
| `0008c95fb43bd97dec04c408b61a66a38f59a7912e4d4a058647ef14407463f2` | agent, no symbols |
| `876b1dbc4bcfc548d1fbf8ac8d4fe7dfa15df80e5085372397dffb814c5e5352` | agent, no symbols; inside FileCrypt |
| `9b228bf578fee16d5ccd880ecafcc7159d3678ef09d7fa5c807d423f97d48a9e` | agent, no symbols |
| `5a39bd95d430a1093b3d179d100389ee2cf60226518b82e02572f3e25df2f803` | agent, v2 protected config |
| `46bea5c1ac50bbcb0fb700e6e8f46d5f09c8ea61c74f677bd19342bace670052` | PyInstaller binder |
| `161fedd71541175dfd8d148f93e0d2ea30c056c7366d3973d59c7f0a61a59802` | `Installer.exe` decoy, from the binder |
| `9d9d9901b318cf30a8764f8b1a4d042e9c73bc22cfd39e159f81ba895a898920` | FileCrypt-packed agent |

| Network indicator | Context |
|---|---|
| `2.26.51[.]12:443` | hard-coded default in all 18 Go builds, used when the primary field is empty; primary of `0fb93dbb`; default C2 of `5a39bd95` |
| `total-sitevv[.]lol:443` | primary of nine builds |
| `87.120.196[.]120:443` | primary of `a7279f24` |
| `2.26.49[.]181:443` | primary of four builds |
| `191.44.109[.]125:443` | primary of two builds |

| Certificate pin (SHA-256 digest of the DER certificate) | Builds that pin it |
|---|---|
| `c03198697d3e4e9250fc8d64a9818cc1677a2afddfdbf3db27ee94e41333764b` | digest pinned by builds with primary `total-sitevv[.]lol` |
| `6717f6b83fabad46f6825fc61d300a67ff7e6046913f54652732bbfe9e065c4a` | digest pinned by builds with primary `2.26.49[.]181` |
| `750872a67ceb2adbe1e31340acabc6574aa9ebbcfe8acaad9ffe05301eca21dc` | digest pinned by builds with primary `2.26.49[.]181`, `191.44.109[.]125`, and by `5a39bd95` |
| `a8993c1f3d1502884858c67011933aa897434af5ce0415fca4e676181f44a470` | digest pinned by builds with primary `2.26.51[.]12` |
| `3bd525410d7e60870d8e156ee86ff084753ed915a683d8a0aee16dc89f47f7ab` | digest pinned by builds with primary `87.120.196[.]120` |

User ID in every decodable config: `7b85683a-c3e6-43c2-9bfb-583377ada5f6`.

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1027 | Obfuscated Files or Information | config fields hex-encoded and XORed with `NIK`; v2 Base64 blobs |
| T1027.002 | Software Packing | FileCrypt `FCX1`/`SX11` wrapper |
| T1036.005 | Masquerading: Match Legitimate Name or Location | copies named `svchost.exe` and similar |
| T1547.001 | Registry Run Keys / Startup Folder | `addAutoStart` flag |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM with `SHA-256(seed)` |
| T1204.002 | User Execution: Malicious File | binder posing as a game cheat |

## Ending

The panel writes a fresh template for every order, with its own seed, agent ID and certificate pin, and then encodes all of it with the same three letters. That is the cheapest place to catch these agents: a hex string that turns into a C2 URL under `NIK` is in every build here except the one that broke its own config. And for responders with packet captures, the extractor's per-build key turns every heartbeat back into JSON that names the same user ID.

## Credits and further reading

- Chetan Raghuprasad, Cisco Talos: [NIK C2: The new AI-enabled command-and-control framework](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/) and the [IOC file](https://github.com/Cisco-Talos/IOCs/blob/main/2026/10/nik-c2-new-ai-enabled-framework.txt).
- Threatray: [NIKRAT IOCs](https://github.com/threatray/threat-research/tree/main/2026-10-30-NIKRAT) (C2s per sample, the `750872a6…` certificate, mutexes, persistence) and the twelve MalwareBazaar uploads.
- Samples: MalwareBazaar ([signature NIKRAT](https://bazaar.abuse.ch/browse.php?search=signature%3ANIKRAT)) and Hybrid Analysis for the seven Talos hashes not on Bazaar.
