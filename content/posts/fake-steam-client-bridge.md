---
title: "A fake steam.exe used to put the real one back. Its September build lets the phishing page read the Steam folder instead"
date: 2026-11-15T11:28:36+00:00
slug: "fake-steam-client-bridge"
description: "Twelve files from one Steam phishing kit, read statically: a .NET launcher that logs every step to %TEMP%, a loader that decodes a fake steam.exe with XOR and a byte interleave, two .NET clients in 32 languages, a restorer that puts the real steam.exe back after the login, and the September builds that drop the restorer and give the phishing page a JavaScript bridge to HTTP and to files in the Steam folder."
tags: ["steam", "phishing", "dotnet", "webview2", "loader", "salat-stealer"]
sample:
  family: "Fake Steam client (.NET build)"
  sha256: "a2200e1c82de90bfc23cf8a4ae183b0fb7514b745734aba467ee154e6bc306c1"
  source: "[MalwareBazaar](https://bazaar.abuse.ch/sample/a2200e1c82de90bfc23cf8a4ae183b0fb7514b745734aba467ee154e6bc306c1/)"
toc: true
---

The fake Steam client in this kit replaces `steam.exe`, shows "Oops! Something went wrong. Please log in using the web version of Steam." and opens a phishing page in an Edge WebView2 window with certificate errors ignored. In the builds from February to July, the moment that window lands on `steamcommunity[.]com` the client drops an 8 KB .NET program that kills Steam and copies the real `steam.exe` back from `steam.back`, so the victim's next launch looks normal. The two builds from September and October no longer carry that program. Instead they inject a script that gives the remote phishing page a `window.steamm` object with `http.request`, `fs.readText` and `fs.writeText`, and the native side answers those calls for files under the folder the fake `steam.exe` runs from: the Steam install folder.

The files were all uploaded to MalwareBazaar on 2026-10-13, nine fake clients and their helpers by the user Daydream and the launcher and three binders by the user Kejult. The upload comments already lay out the chain: a .NET binder that drops Salat Stealer next to a .NET launcher, the launcher that starts a loader after 60 minutes, the loader that writes the fake client over `steam.exe`. I took the two .NET clients from Bazaar's Dotnet tag, followed the chain up and down from there, and read all twelve files with ILSpy, dnfile, Ghidra and FLOSS. No sample ran. I found no other write-up of this kit.

## What I found

- The .NET launcher, `HiddenAutoLauncher`, writes a plain-text log of every step to `%TEMP%\autolauncher_log.txt` and keeps its 60-minute timer in `%TEMP%\autolauncher_tracking.txt`. It rewrites the timer file on every start, so the loader runs only after 60 minutes of uninterrupted uptime.
- The native loader stores the fake client as `out = deinterleave24(blob ^ key6)` and a Microsoft-signed WebView2 bootstrapper as `blob ^ key8`. A generic search for an XORed DOS header finds both, and the same search finds the restorer in all five native client builds from before September under one 16-byte key, `deadbeefcafebabe13374269aa55f00d`.
- The two .NET clients are the same program. They differ in 39 bytes, all of them in four build identifiers (the PE timestamp, the module MVID, the debug-directory timestamp and the PDB GUID).
- Across the nine client builds the WebView2 command line grows from 2 switches to 11 and its list of disabled browser features from 1 to 16, ending with `--inprivate`. The phishing host moves from `7834156259.dojiner[.]at` to `8393546939.dojiner[.]at` to `8909451279.f1shh[.]at/client`.
- In the September and October builds the bridge handler reads each web message as JSON without asking for its source, then dispatches 8 methods. File paths are joined to the executable's folder and rejected if the result leaves it.

## From a binder to a Steam window, one hour later

Kejult's three binders (`0a4048eb…`, `43bd6a55…`, `fe8174a3…`) are tagged SalatStealer on Bazaar. A comment on the launcher's record notes that the binders, which it calls SilentExecuter, drop a UPX-packed Salat build as `svchost.exe` and the launcher as `conhost.exe`, and that the launcher itself contains no Salat code. I didn't download the binders; the chain from the launcher down is what this post covers.

The launcher (`913792a7…`) is a .NET Framework 4.7.2 Debug build with the assembly title `svchost`, the namespace `HiddenAutoLauncher`, and a PDB path under `E:\Project VS\svchost\`. It is small and has no obfuscation, so ILSpy gives back something close to the source, constants included:

```csharp {title="HiddenAutoLauncher.Program (trimmed)"}
private const int DELAY_MINUTES = 60;
private const int CHECK_INTERVAL_MS = 10000;
PERMANENT_COPY_PATH = %APPDATA%\SystemData\svchost.exe;
TRACKING_FILE       = %TEMP%\autolauncher_tracking.txt;
EXTRACTED_STEAM_PATH = %TEMP%\svchost.exe;

if (location != PERMANENT_COPY_PATH) {
    CopyAndLaunchPermanent();                 // (1)
} else {
    AddToStartup();                           // (2) HKCU Run "SystemAutoLauncher"
    InitializeTracking();                     // (3) write DateTime.Now
    RunBackgroundMonitoring();                // (4)
}
```

On first run (1) it creates `%APPDATA%\SystemData`, marks the folder and the copy Hidden and System, starts the copy hidden and exits. The copy adds itself to the Run key as `SystemAutoLauncher` (2), then writes the current time to the tracking file (3) and polls every 10 seconds (4). When the stored time plus 60 minutes has passed, it writes its only resource, `svchost.svchost.exe`, to `%TEMP%\svchost.exe`, starts it, deletes the Run value and calls `Environment.Exit(0)`.

Step (3) runs on every start, not just the first. A user who reboots every half hour never gets the payload: each logon writes a fresh time and the hour starts again. The original first-run copy isn't deleted either. The launcher only logs "Original executable can now be deleted."

The logging is the useful part for anyone cleaning up. Every function writes a timestamped line to `%TEMP%\autolauncher_log.txt`, and the messages are specific:

```text
First launch detected from: <path>
Directory attributes set to Hidden+System
Background monitoring started. Checking every 30 seconds...
Tracking initialized. Steam will launch at <time>
>>> TIME HAS COME! Current: <time>, Target: <time>
Removed from startup. Program will no longer auto-start.
```

"Checking every 30 seconds" is wrong, since the interval constant is 10,000 ms, but the file is a timeline of the infection that the launcher leaves behind on its own. The two lines it would write after a successful start ("Steam launched successfully", "Next launch scheduled for") never appear, because `ExtractAndLaunchSteam` exits the process before control returns to them.

## The loader decodes two PEs

The resource is `14a0b7d5…`, a 2.2 MB x64 PE built with Mingw-w64 (it carries the `Mingw-w64 runtime failure` string; the clients it ships share the llvm-mingw toolchain). It has seven sections with random names, a version resource claiming to be `perfmon_agent.exe` from "Pinnacle Runtime Solutions", and a PE timestamp in 1979. Ghidra's output of the main function has three parts.

First it checks for the WebView2 runtime: the EdgeUpdate client key `{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}` under HKLM (both views) and HKCU, then a version-numbered folder under `C:\Program Files (x86)\Microsoft\EdgeWebView\Application`. If none is there, it decodes a 1,691,856-byte blob with an 8-byte repeating XOR key, writes it to `%TEMP%\MicrosoftEdgeWebview2Setup.exe`, runs it with `/silent /install`, waits up to 120 seconds and deletes it. The decoded file (`0223fa1e…`) carries a valid Microsoft Corporation Authenticode signature. It is the real bootstrapper.

Second, it reads `HKCU\SOFTWARE\Valve\Steam\SteamExe` (falling back to `C:\Program Files (x86)\Steam\steam.exe`), terminates ten processes by name (`Steam.exe`, `streaming_client.exe`, `steamerrorreporter.exe`, `steamerrorreporter64.exe`, `rustclient.exe`, `dota2.exe`, `csgo.exe`, `cs2.exe`, `hl.exe`, `hl2.exe`), sleeps 1.5 to 2.5 seconds and copies `steam.exe` to `steam.back`.

Third, it decodes the fake client and writes it over `steam.exe`. The decoder is two loops; I trimmed Ghidra's SSE shuffles to what they do:

```c {title="FUN_1400013e0, client decode (trimmed)"}
for (i = 0; i < 0x81c00; i++)
    tmp[i] = blob_1400050c0[i] ^ key_1402242c0[i % 6];      // (1)
for (o = 0; o < 0x81c00; o += 24)
    for (j = 0; j < 12; j++) {
        out[o + 2*j]     = tmp[o + j];                       // (2)
        out[o + 2*j + 1] = tmp[o + 12 + j];
    }
```

(1) is a 6-byte repeating XOR with the key `5c18e154351e`. (2) undoes an interleave: the first half of every 24-byte block holds the even bytes, the second half the odd ones. Run in Python over the bytes at those addresses, the two loops give 531,456 bytes whose SHA-256 is `1d52f762…`, the file Daydream uploaded as the fake client from this loader. Daydream's comments on the other client builds name other key lengths and block sizes (8, 12, 16, 20 and 24), so the builder picks both per build.

## The .NET clients

The two oldest clients are .NET Framework 4.7.2 programs with Costura.Fody packing the WebView2 assemblies into resources. Kaspersky first saw `a2200e1c…` on 2026-02-09 and `55249a75…` on 2026-02-18. Their PDB path is `C:\Users\<user>\Desktop\Random file\Проекты\Сурсы\SteamSetup\Steams\obj\Release\Steam.pdb`. The two folder names are Russian for "Projects" and "Sources", and the client's two error messages are Russian too ("Ошибка: …", "Ошибка при распаковке зависимостей").

The program has two windows. The first is a borderless WPF window with a title, a subtitle and a Login button. Its constructor picks the text by `CultureInfo.CurrentUICulture.TwoLetterISOLanguageName` from 32 languages, starting with Russian and Ukrainian, plus an English default. The constructor also writes the `runtimes` resource, a zip holding `WebView2Loader.dll` for arm64, x64 and x86, next to the executable and extracts it, if no `runtimes` folder exists there yet.

Clicking Login opens the second window, a WinForms form titled "Steam Web Browser":

```csharp {title="Steam.Form1 (trimmed)"}
string args = "--ignore-certificate-errors "
            + "--disable-features=msSmartScreenProtection";
env = await CoreWebView2Environment.CreateAsync(null, null,
          new CoreWebView2EnvironmentOptions(args, ...));    // (1)
webView.Source = new Uri("https://7834156259.dojiner.at/");
checkTimer.Interval = 500;                                 // (2)

void CheckTimer_Tick(...) {
    string url = webView.CoreWebView2.Source.ToLower();
    if (!alreadyTriggered && url.Contains("steamcommunity.com")) {
        alreadyTriggered = true;
        File.WriteAllBytes(%TEMP%\Setup.exe, Resources.SteamInstall);
        Process.Start(%TEMP%\Setup.exe);                 // (3)
    }
}
```

(1) passes `null` as the user data folder, which makes WebView2 use its [default location](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder), a folder named after the executable next to it. For a client running as `steam.exe` that is a `steam.exe.WebView2` folder inside the Steam folder. That is an inference from the documentation, not something I watched happen. (2) polls the address twice a second, and (3) fires on any address containing `steamcommunity[.]com`, anywhere in the URL. I think the phishing page sends the browser to the real Steam Community once it has the password and the Steam Guard code, and the client takes that as its signal to clean up.

I expected the two .NET builds to differ in code. Daydream's comments give them different loader keys (`ab5cd491` with 16-byte blocks, `6274d8f92e` with 24-byte blocks), and both builds have different file hashes. The decompiled C# and every resource are identical. A byte compare finds 39 differing bytes, all in four fields:

| Offset | Field | `a2200e1c` | `55249a75` |
|---|---|---|---|
| 0x88 | PE timestamp | `0xcb48b173` | `0xe7cfbae9` |
| 0x82248 | MVID (`#GUID`) | `bb5d5fcd-…` | `b9188b4c-…` |
| 0x828ac | debug timestamp | `0xcb48b173` | `0xe7cfbae9` |
| 0x828e4 | RSDS GUID | `7064b671…` | `ab882169…` |

Both carry a `REPRO` debug entry, which means a deterministic compiler build, where those four values are hashes of the build inputs rather than clocks (the timestamps decode to 2078 and 2093). The loader keys belong to the loaders, not to the clients. Either the same project was rebuilt after a change that touched no IL and no resource, or someone patched the identifiers. I can't tell which from the files.

## The restorer

`Resources.SteamInstall` is a 4-byte length (`0x2000`) followed by an 8,192-byte .NET program, `6594e73e…`, with the PDB path `C:\Users\<user>\source\repos\SteamSetup\SteamInstall\obj\Release\SteamInstall.pdb`. The `SteamSetup` solution name matches the client's. Its whole `Main`:

```csharp {title="SteamInstall.Program.Main"}
string steam = GetSteamExePath();     // HKCU\...\Valve\Steam\SteamExe
if (File.Exists(steam)) {
    string back = Path.Combine(Path.GetDirectoryName(steam), "steam.back");
    if (File.Exists(back)) {
        Kill();                       // the same ten process names
        Thread.Sleep(2000);
        File.Delete(steam);
        File.Copy(back, steam);
        Process.Start(steam);
    }
}
```

The kill list matches with `EndsWith("Steam.exe")`, case-insensitive, so it also ends the fake client, which runs as `steam.exe`. `steam.back` stays on disk after the copy, as do `%TEMP%\Setup.exe` and the `runtimes` folder. Kaspersky's first sighting of this file is 2025-12-08, two months before either .NET client. The restorer is the oldest dated piece of the kit.

The .NET clients store the restorer in plain sight. The native clients don't, so I wrote a search instead of reading each build's decoder. A PE from MSVC or LLD starts with one of two fixed 60-byte DOS headers. For an XOR key of length L, `stored[i] ^ stored[i+L]` equals `header[i] ^ header[i+L]`, because the key cancels out. That makes the search a `bytes.find` over the file XORed with itself shifted by L, for L from 1 to 16 and for each interleave block size. Every hit gets decoded and kept if it parses as a PE that fits in the file. On the loader it finds both blobs in a few seconds, with the keys from Ghidra. On the clients:

| Build | Restorer | Also found |
|---|---|---|
| `a2200e1c`, `55249a75` (.NET) | plain resource | WebView2Loader.dll ×3 (zip) |
| `7bfd3d6c` … `1d52f762` (native) | XOR `deadbeefcafebabe13374269aa55f00d` | x64 `WebView2Loader.dll`, same key |
| `f27af032`, `0edcc906` (native) | none | `WebView2Loader.dll` as resource 300 |

Every client before September carries the same restorer, byte for byte, and the five native ones hide it and the x64 `WebView2Loader.dll` (`2f965e10…`, the same file as in the .NET zip) under the same 16-byte key. `deadbeefcafebabe` followed by `13374269aa55f00d` is about as random as a key gets in a hurry.

## Nine builds, three hosts

Here are the clients in build order, with the phishing host, the number of switches on the WebView2 command line and, after the slash, the number of features in its `--disable-features` list. The native builds' timestamps look like real clocks; the .NET ones are deterministic hashes, so their row uses Kaspersky's first-seen date instead:

| Build | Built | Host | Switches | Restorer | Bridge |
|---|---|---|---|---|---|
| `a2200e1c` | ≤2026-02-09 | `7834156259.dojiner[.]at` | 2/1 | yes | no |
| `55249a75` | ≤2026-02-18 | `7834156259.dojiner[.]at` | 2/1 | yes | no |
| `7bfd3d6c` | 2026-03-15 | `8393546939.dojiner[.]at` | 2/1 | yes | no |
| `e17fa895` | 2026-04-26 | `8393546939.dojiner[.]at` | 2/1 | yes | no |
| `53ba0183` | 2026-06-10 | `8393546939.dojiner[.]at` | 2/1 | yes | no |
| `bcd91a48` | 2026-07-23 | `8393546939.dojiner[.]at` | 2/1 | yes | no |
| `1d52f762` | 2026-07-27 | `8909451279.f1shh[.]at` | 8/5 | yes | no |
| `f27af032` | 2026-09-22 | `8909451279.f1shh[.]at` | 11/16 | no | yes |
| `0edcc906` | 2026-10-05 | `8909451279.f1shh[.]at` | 11/16 | no | yes |

All seven native builds are llvm-mingw: six carry the literal `llvm-mingw` string and all seven the `Mingw-w64 runtime failure` string, with the stripped `1d52f762` keeping only the latter. The four from March to July 23 keep `.buildid` and DWARF sections with a `clang version 21.1.8` string; from July 27 on the builds are stripped. The native builds pass their switches through the `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` environment variable instead of the options object. The ones up to July use a profile folder named `SteamWV2Data`. The command line in `1d52f762` adds six switches to the original two, among them `--allow-running-insecure-content`, `--disable-web-security` and `--disable-client-side-phishing-detection`, and four Edge safety features to the disabled list (`msEnhancedSecurityMode`, `msSafeLinksValidation`, `EdgeSafetyTips`, `InternetExplorerIntegration`). September adds `--disable-domain-reliability`, `--no-pings` and `--inprivate`, and eleven more disabled features, among them `SafeBrowsing`, `PhishingProtection`, `HttpsUpgrades` and `CertificateTransparencyComponentUpdater`.

This is where I took a wrong turn. My first URL pass over the September build printed `hxxps://8909451279[.]f1shh[.]at/clie` and I nearly put that in the table as the host's path. The string is UTF-16 on the stack, built 16 bytes at a time, and the plain string scan only saw the first chunk. FLOSS's stack-string pass rebuilt `hxxps://8909451279[.]f1shh[.]at/client`. On `1d52f762` FLOSS recovered nothing useful, so the `f1shh` host in its row comes from Daydream's comment, which says it was recovered with FLOSS. I couldn't reproduce that.

## September: a bridge instead of a restorer

`f27af032` and `0edcc906` have no `steamcommunity[.]com` string, no `Setup.exe` and no restorer. Nothing in them puts `steam.exe` back. What they have instead is a 4,131-character UTF-16 script, the same in both builds, that defines a `window.steamm` object:

```javascript {title="injected script (trimmed)"}
window.steamm = {
  invoke(method, params) {                                   // (1)
    const id = nextId++;
    pending.set(id, { res, rej });
    b.postMessage({ id, method, params: params || {} });
  },
  win: { minimize(), close(), drag(), resize(edge) },
  http(url, opts) { return invoke('http.request',
                      { url, method, headers, body }); },    // (2)
  readText(path) { return invoke('fs.readText', { path }); },
  writeText(path, text) {
    return invoke('fs.writeText', { path, text }); },        // (3)
  openExternal(url) { return invoke('shell.open', { url }); },
  on(event, cb) { ... }
};
// Overlay: close button + drag strip (like Steam/Riot)
```

(1) is the usual WebView2 pattern: post a message with an ID to `chrome.webview`, resolve a promise when the host answers with the same ID. The page gets an HTTP client that runs outside the browser (2), so it isn't bound by CORS or by the WebView's cookie jar, and file access (3). The comment about Steam and Riot survives in the binary. The overlay draws a 28-pixel drag strip and a close button over whatever page is loaded, so the phishing site can look like a frameless client window.

The native side is the `WebMessageReceived` handler. It calls the event argument's vtable slot at `+0x20`, which is `get_WebMessageAsJson` in `ICoreWebView2WebMessageReceivedEventArgs`, and never the slot at `+0x18`, `get_Source`. Every page in that window, from any origin, can call the bridge. The handler parses `method` and `params` and dispatches on eight strings:

| Method | Params | What the handler does |
|---|---|---|
| `win.min`, `win.close`, `win.drag` | none | minimize, close, start a window drag |
| `win.resize` | `edge` | resize from an edge or corner (`right`, `topleft`, …) |
| `http.request` | `url`, `method`, `headers`, `body` | WinINet request with the user agent `Steam/1.0`; returns `{"status":…,"body":…}` |
| `fs.readText` | `path` | path check, then `CreateFileW` read in 8 KB chunks; returns `{"text":…}` |
| `fs.writeText` | `path`, `text` | path check, then `CreateFileW(CREATE_ALWAYS)` and write |
| `shell.open` | `url` | `ShellExecuteW("open")`, only for `http`/`https` |

The path check (`FUN_140004620`) is the one piece of restraint. At startup the client takes `GetModuleFileNameW`, strips the file name with libc++'s `std::filesystem` path code and keeps the folder in a global. The check joins the requested path to that folder, canonicalizes it, and compares the result's first characters with the folder. A relative path stays inside; `..` and absolute paths fail. I read that from Ghidra's output of the libc++ code, so treat the exact rules as my reading of it. Since the loader writes the client over `steam.exe`, the folder is the Steam install folder, and the page can read and overwrite text files there. Steam keeps `config\loginusers.vdf` and `config\config.vdf` in that folder. Whether the kit reads them I can't say: that would be in the page's JavaScript, on a server I didn't contact.

The September builds also stop extracting a `runtimes` folder. They write `WebView2Loader.dll` from resource 300 to disk (the first folder the code builds is `%LOCALAPPDATA%\Steam`) and load it with `LoadLibraryW`.

## What I couldn't determine

- What the phishing pages do. The client loads them and gives them the bridge; the code that calls `window.steamm` lives on the servers.
- Which loader carried the September builds. Daydream's comments give their XOR keys and block sizes, but only one loader (`14a0b7d5…`) is public, and it carries `1d52f762`.
- The order of a few events in July. The build timestamp of `1d52f762` is 2026-07-27 18:24 UTC, and Kaspersky's first sighting of the loader that embeds it is 16:17 the same day. At least one of those clocks is off.
- What ran before December 2025. The restorer is older than every client here, so earlier clients probably exist.

## The extractor

[`families/fakesteam`](https://github.com/stateless-re/tools/tree/main/families/fakesteam) in the tools repo takes any file from this chain and prints the phishing URLs it can see, the WebView2 switches, whether the restore trigger and the bridge methods are present, and every embedded PE it finds, as plain resources or with the XOR and interleave search described above, with key and block size. `-o DIR` writes the decoded PEs, named by SHA-256. It reports only URLs stored as whole strings, so for the stripped native builds use FLOSS. I tested it on all twelve kit files.

## Indicators

| SHA-256 | Role |
|---|---|
| `913792a7cec3a062742f3390d7941a7e95aeeb7e1537e4a52590049d54c5c5e8` | HiddenAutoLauncher (.NET) |
| `14a0b7d57f22378472a4e1d20fc50d38db5dab72d46007b472d466049181ab0b` | loader (`svchost.svchost.exe`) |
| `a2200e1c82de90bfc23cf8a4ae183b0fb7514b745734aba467ee154e6bc306c1` | fake client, .NET |
| `55249a75e9ae5d378fbb24422a200bcfb68d23e4194418647d54ef956b2ffc10` | fake client, .NET |
| `7bfd3d6cf9eaebd0766c09c1703c1d0ba4165b9e2125eca70340278115e8dfcf` | fake client, native |
| `e17fa89521afd0ae54f17b8149a9781baf334f640c061daf270539f609c8a628` | fake client, native |
| `53ba0183abb4294f0f8cf1c94c06eceac3ef1abfa60e2de16dafca73f783997f` | fake client, native |
| `bcd91a487e13c62246fdf696a19015795c1ea45a24950a7b9e4b31c5b3f5432d` | fake client, native |
| `1d52f76213582b58cd3d0161dee345f42184b05a359607e4719f96c511e7fd3c` | fake client, native (from the loader) |
| `f27af032b01fc6982ff936086eaeeaa6a517a9b3fad74939ee4e50729c9e3b2c` | fake client, native, bridge |
| `0edcc9061d88c6f0c24ff35d0a2e22387636461db707020d3a70b23cbd523579` | fake client, native, bridge |
| `6594e73edf525c356651e37e5a6876a82c1d0ec554a1062051de5ea8e6101dab` | restorer `SteamInstall.exe` (.NET) |
| `0a4048ebe7a683ffef1cae2902477b713980fe4142ee703be02c7544ebbf66b4` | binder (Bazaar label SalatStealer) |
| `43bd6a55a0829f571e68891b27b8267d4d1cba419d5ee2da3b153374ab4b105a` | binder (Bazaar label SalatStealer) |
| `fe8174a3605239522f774af91f04b4a9f62cbbff4f72e0756a932e97d9ac3131` | binder (Bazaar label SalatStealer) |

The loader also carries the genuine Microsoft WebView2 bootstrapper (`0223fa1e…`), and the native clients carry the genuine `WebView2Loader.dll` (`2f965e10…`, `a9a09232…`). Don't block those hashes.

Network:

- `7834156259.dojiner[.]at`
- `8393546939.dojiner[.]at`
- `8909451279.f1shh[.]at` (path `/client`)
- HTTP user agent `Steam/1.0` (bridge requests, September builds)

Host:

- `%APPDATA%\SystemData\svchost.exe` (Hidden, System), Run value `SystemAutoLauncher`
- `%TEMP%\autolauncher_log.txt`, `%TEMP%\autolauncher_tracking.txt`, `%TEMP%\svchost.exe`
- `steam.back` next to `steam.exe`; a `steam.exe` that isn't signed by Valve
- `%TEMP%\Setup.exe` (restorer), `%TEMP%\MicrosoftEdgeWebview2Setup.exe`
- a `runtimes\win-*\native\WebView2Loader.dll` tree or a `SteamWV2Data` folder where Steam lives

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1547.001 | Registry Run keys | `HKCU\...\Run\SystemAutoLauncher` until the loader starts |
| T1564.001 | Hidden files and directories | `%APPDATA%\SystemData` and the copy marked Hidden and System |
| T1036.005 | Match legitimate name or location | `svchost.exe`, `conhost.exe`, and the client written over `steam.exe` |
| T1497.003 | Time based evasion | 60 minutes of uptime before the loader runs |
| T1027 | Obfuscated files or information | XOR and 24-byte interleave in the loader; restorer XORed in the native clients |
| T1562.001 | Disable or modify tools | WebView2 started with SmartScreen, Safe Browsing and phishing detection off |
| T1056.003 | Web portal capture | the Steam login page loaded in the fake client |
| T1070.004 | File deletion | restorer replaces the fake `steam.exe` with the original after the login |

## Ending

The February client was polite about it: take the login, put Steam back, leave a `steam.back` and a log file behind. The September client stays. If you find a `steam.back` next to `steam.exe`, check the signature on `steam.exe` and look for `%TEMP%\autolauncher_log.txt`, which will tell you when it all started. Any Steam password typed into that window since then should be treated as known to the kit's operators, along with the text files in the Steam folder.

## Credits and further reading

- Daydream on MalwareBazaar, for uploading the nine clients, the loader and the restorer on 2026-10-13 with comments that map the chain, the per-build loader keys and the Salat bundles. Start from [`1d52f762`](https://bazaar.abuse.ch/sample/1d52f76213582b58cd3d0161dee345f42184b05a359607e4719f96c511e7fd3c/) and [`14a0b7d5`](https://bazaar.abuse.ch/sample/14a0b7d57f22378472a4e1d20fc50d38db5dab72d46007b472d466049181ab0b/).
- Kejult on MalwareBazaar, for the launcher [`913792a7`](https://bazaar.abuse.ch/sample/913792a7cec3a062742f3390d7941a7e95aeeb7e1537e4a52590049d54c5c5e8/) and the binders.
- Microsoft's WebView2 documentation on [user data folders](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder).
- Splunk's [Bundled to Steal: The Salat Stealer Campaign](https://www.splunk.com/en_us/blog/security/bundled-to-steal-salat-stealer-campaign.html) (2026-07-06) covers a different Salat bundle, a Xeno Executor package. It doesn't mention this Steam kit.
