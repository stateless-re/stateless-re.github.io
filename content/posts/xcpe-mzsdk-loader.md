---
title: "Three x.cpe builds hide a second loader, and its string key is \"UTF-8\""
date: 2026-11-14
slug: "xcpe-mzsdk-loader"
description: "Eight builds of x.cpe, the preinstalled agent behind the XCPE TV-box botnet, read statically: one AES-CFB config key in all of them, four signed with Android's public test platform key, and in three of them an embedded ad loader (MzSDK) whose strings, core jar and C2 protocol come apart with keys it carries in the clear."
tags: ["xcpe", "x.cpe", "mzsdk", "moyu", "android", "android-tv", "supply-chain", "stringfog", "dynamic-code-loading"]
sample:
  family: "x.cpe (XCPE botnet agent), build 6.6.0"
  sha256: "07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179"
  source: "[Hybrid Analysis](https://www.hybrid-analysis.com/sample/07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179)"
toc: true
---

Three of the eight `x.cpe` builds I could get carry a second loader that neither vendor report mentions. It sits in a package called `com.ocean.zoe`, hides its strings with StringFog, and the XOR key for those strings is the five bytes `UTF-8`, the charset name, sitting in the argument slot where StringFog expects a key. Undo that and the loader gives up everything else. Its core is a 37,035-byte resource XORed with `letu`, and the core asks `dcsdk.100ulife[.]com` for updates and plugin APKs, encrypting with an AES key written out in the strings. The agent around it is barely hidden either: all eight builds wrap their configuration traffic with the same AES-128-CFB key, and four are signed with the platform key that ships, public, in the Android source tree.

`x.cpe` is the management agent preinstalled on the Android TV boxes behind the XCPE botnet, which Google and partners disrupted in the last week of October; both write-ups below are dated November 2. Google's Threat Intelligence Group [attributes the backdoor to the device maker Videostrong](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet) and documents its endpoints, its MQTT topic layout and its capabilities. [TrendAI Research's post](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/trendaitm-research-helps-disrupt-android-tv-botnet-of-more-than-13-million-pre-infected-devices) says the agent "used obfuscation techniques to evade pre-release security tests" and publishes an IoC list with ten `x.cpe` SHA-256 hashes. None of the ten is on MalwareBazaar; eight are on Hybrid Analysis. I read those eight, plus one `com.abc.nexus` build, with jadx and androguard. Nothing ran.

## What I found

- All eight builds (versions 6.5.0 to 6.8.6) encrypt their configuration requests and responses (`/router/config/*`, or `/cpe/config/*` in 6.5.0) as base64 AES-128-CFB with the key and IV both set to the ASCII string `Iz4iWGbzcm2pHjSm`. Google's post says the body is "an AES-encrypted JSON object"; the key and mode weren't published.
- Four builds are signed with the AOSP test platform certificate (SHA-1 `27196e38…`), two with a Videostrong certificate (the one TrendAI lists), and two with a third certificate that copies the AOSP subject line. All eight request `android.uid.system`.
- Builds 6.5.0 and both 6.6.0 builds embed MzSDK: a StringFog-protected shell, a core jar in `letu.jet`, and a plugin manager that downloads APKs and runs their code inside an `x.cpe` process, under its UID. The shell runs only when the server config sets `adDevourUse`.
- The MzSDK core asks `dcsdk.100ulife[.]com` for core updates and plugin lists over HTTPS with certificate checks switched off; the files themselves come from whatever URLs the server returns. It sends AES-256-ECB, uppercase hex, with a 32-character key in its constants. The domain is already on blocklists (Plume's XCPE list, and maltrail under an Android.Vo1d label), but I found no description of the SDK.
- In 6.8.x the SDK is gone, matching Google's account of modules moving into `com.abc.nexus`. Nexus 1.5.3 keeps a `DevourService` with the same default channel, `lx102`, and it starts `com.mm.a.moyu`.

## Eight builds, three signers

TrendAI's IoC file labels 49 lines "x.cpe sample APK": ten are SHA-256 hashes and 39 are 40 hex characters long, so SHA-1. I looked up all 60 SHA-256 hashes in the file on Hybrid Analysis, and 17 of them (all ten `x.cpe` hashes, the five signed nexus builds and the two `com.mm.a.moyu` files) on MalwareBazaar. MalwareBazaar had none of the 17. Hybrid Analysis had 21 of the 60, including eight of the ten `x.cpe` APKs (`247ee397…` and `b01cd8e6…` returned 404). Only one of the eight had a malicious verdict on Hybrid Analysis: `07b511a6`, flagged by 2 of 23 engines in its Metadefender scan. The other seven sat at "unknown".

The manifests and signing blocks, from `apkinfo.py` (androguard):

| Build | Version (code) | Signer SHA-1 | Signer subject | HA `submitted_at` |
|---|---|---|---|---|
| `6a995ad8` | 6.5.0 (43) | `27196e38…` | AOSP test platform key | 2026-11-05 |
| `5ae5df84` | 6.5.7 (45) | `27196e38…` | AOSP test platform key | 2026-11-05 |
| `07b511a6` | 6.6.0 (48) | `27196e38…` | AOSP test platform key | 2026-09-28 |
| `5e9e0f8d` | 6.6.0 (48) | `a48cd72e…` | `CN=www.videostrong[.]com, O=VS` | 2026-03-09 |
| `539913c9` | 6.8.3 (58) | `27196e38…` | AOSP test platform key | 2026-02-18 |
| `6f7f4b22` | 6.8.5 (60) | `64be9010…` | AOSP-style subject, issued 2022-11-30 | 2026-06-09 |
| `1de0a368` | 6.8.6 (61) | `64be9010…` | AOSP-style subject, issued 2022-11-30 | 2026-01-13 |
| `c96e32f7` | 6.8.6 (61) | `a48cd72e…` | `CN=www.videostrong[.]com, O=VS` | 2026-02-18 |

`27196e386b875e76adf700e7ea84e4c6eee33dfa` is the SHA-1 fingerprint of `platform.x509.pem` in AOSP's `build/target/product/security/` directory. I fetched the file from googlesource and compared. That key is the test key every AOSP checkout ships with, private half included, and it is supposed to be replaced before a device goes to market. `a48cd72e…` is the certificate TrendAI lists as the "x.cpe signing certificate". `64be9010…` has the same `CN=Android, O=Android, L=Mountain View` subject as the test key but a 2022 issue date, so it is a different key that copies the subject line.

Every build sets `android:sharedUserId="android.uid.system"`. Android only lets an APK join that UID if it carries the same certificate as the firmware's platform package. A box that runs a test-key build as the system user therefore has firmware signed with the AOSP test platform key, and on such a box any APK signed with that public key can claim the system UID too. I had no firmware images, so this follows from Android's rules rather than from an image I inspected. TrendAI writes that the implant "runs as a system app signed with the manufacturer's key". Only two of these eight builds carry a certificate with the manufacturer's name in it; four carry the public test key, and I can't say who owns `64be9010…`.

## One config key in every build

Google's post describes the bootstrap: the agent picks a host such as `stb[AndroidVersion][Type].anyevonline[.]com:8000` and posts "an AES-encrypted JSON object containing hardware telemetry" to `/router/config/mqtt`, `/router/config/acs` and `/router/config/app`. (The oldest build here, 6.5.0, uses `/cpe/config/mqtt` and `/cpe/config/acs` instead, and has no `app` endpoint.) The encryption lives in `x.cpe.util.EncryptUtils`:

```java
private static final String CIPHER_CFB_NOPADDING = "AES/CFB/NoPadding";
private static final String KEY = "Iz4iWGbzcm2pHjSm";

public static String encrypt(String content) {
    byte[] bytes = KEY.getBytes("UTF-8");
    SecretKeySpec skeySpec = new SecretKeySpec(bytes, "AES");
    Cipher cipher = Cipher.getInstance(CIPHER_CFB_NOPADDING);
    IvParameterSpec iv = new IvParameterSpec(KEY.getBytes("UTF-8"));   // (1)
    cipher.init(1, skeySpec, iv);
    return Base64.encodeToString(cipher.doFinal(content.getBytes("UTF-8")), 0);
}
```

The 16-byte key is also the IV (1). Java's `CFB` here is full-block CFB-128, so every message under this key starts from the same keystream block. The request body is built in `WorkService.createBasicParams()` and wrapped as `{"encryption": "<base64>"}`:

| Field | Source |
|---|---|
| `sn` | device serial |
| `mac` | MAC address of `eth0` |
| `oui`, `vendor`, `model` | derived OUI, `Build.MANUFACTURER`, model |
| `chipId` | CPU serial, or a device ID if there is none |
| `androidVersion` | release plus `GMS` or `GTVS` |
| `softwareVersion`, `hardwareVersion` | `ro.product.firmware` and a hardware-version property |
| `country`, `cpeVersion`, `timestamp` | cached country, `versionCode|versionName`, milliseconds |

Responses use the same wrapper, and `x.cpe` stores the still-encrypted string in its preferences, decrypting it on each read. The extractor below reads the key from each APK's `EncryptUtils.KEY` field. All eight builds report the same key, so one key decrypts anything captured from any of them, including what sits on the device in preferences.

The host changes between builds. 6.5.0 builds `ott{major}{gms|gtvs}.szbboys[.]com`. 6.5.7 and later build `stb{major}{gms|gtvs}.anyevonline[.]com`, and 6.8.x adds a fixed `mcstb.anyevonline[.]com` when the `ro.mecool.device` property is true. The MQTT topic list grows from 32 actions in 6.5.0 to 44 in 6.8.x. Google gives the topic layout and the capabilities but not the action strings; I'll leave them out here too, and the extractor prints them per build.

## The Devour switch

The `acs` config has a flag Google mentions in passing: `adDevourUse`, with `adDevourCode`. In `ServerConfig` the code defaults to `lx102`. In 6.5.0 and 6.6.0 the flag starts this, in `AdvertiseService` (log strings kept, the rest trimmed):

```java
if (finalServerConfig.isAdBwmActive()) {
    LogUtils.d("start ad...sn4(20220413215417)");
    h.start(AdvertiseService.this.getApplicationContext());              // (1)
}
if (finalServerConfig.isAdDevourUse()) {
    LogUtils.d("start ad...devour20200630 ->" + finalServerConfig.getAdDevourCode());
    MzEntry.init(AdvertiseService.this.getApplicationContext(),
                 finalServerConfig.getAdDevourCode());                      // (2)
}
```

(1) is the bandwidth module, a proxy client whose only hard-coded endpoint is `bmw.bestipip[.]com:16000`, already in TrendAI's list. (2) is the subject of the rest of this post. `com.ocean.zoe.MzEntry` has three methods (`init`, `kill`, `showAdvert`), and the log tag it writes under is `MzEntry`, so I'll call the whole thing MzSDK. Build 6.5.7 has the same flag and the same `AdvertiseService`, but its `run()` stops after the `adBwmActive` branch, and `com.ocean.zoe` isn't in the APK. The 6.8.x builds have no `AdvertiseService` at all.

## StringFog with the charset as the key

Every interesting string in the shell sits in one class of constants, each wrapped in a call:

```java
public static final String f76a = u.a("PSAyXUtve2lJWyYwLQMJZWQzQVEzMWhOVzh7NUlT");
public static final String r    = u.a("NjsrA0sgOmhKWTk1PlQWOT0kA3c2MSdDcTs9Mg==");
public static final String f78x = u.a("ERF0GAoTbQduD2NmcmkPZ2d0HAoQYwMaCGxjdBwLYRA");
```

The class names in the decompiled output (`StringFog.java`, `StringFogImpl.java`) say what this is. StringFog is an open-source Gradle plugin that replaces string literals with base64 and an XOR against a key chosen at build time. I expected to go looking for that key. It was one line away:

```java
public final class u {
    public static final v b = new v();
    public static String a(String str) {
        return b.a(str, "UTF-8");                     // (1)
    }
}

public final class v {
    public String a(String str, String str2) {
        return new String(a(d.a(str, 2), str2), "UTF-8");
    }
    public static byte[] a(byte[] bArr, String str) {
        for (int i = 0, i2 = 0; i < bArr.length; i++, i2++) {
            if (i2 >= str.length()) i2 = 0;
            bArr[i] = (byte) (bArr[i] ^ str.charAt(i2));   // (2)
        }
        return bArr;
    }
}
```

The wrapper (1) hands `"UTF-8"` to a function whose second argument is the XOR key (2). So the decoding is `out[i] = b64decode(s)[i] ^ "UTF-8"[i % 5]`. Applied to all 25 constants:

| Field | Decoded |
|---|---|
| `f76a`, `b` | `hxxps://dcsdk.100ulife[.]com/sdk`, `hxxps://dcsdk.100ulife[.]com/reportcomp` |
| `p`, `q`, `v` | `dalvik.system.DexClassLoader`, `loadClass`, `java.lang.ClassLoader` |
| `r` | `com.sun.galaxy.lib.OceanInit` |
| `s`, `t`, `u` | `letu`, `.jar`, `/com/ocean/zoe/letu.jet` |
| `w`, `f78x` | `AES`, `DE252F9AC7624D723212E7E70972134D` |
| `c`–`l` | JSON keys: `data`, `versionNo`, `url`, `md5`, `channel`, `terminalVersion`, `deviceId`, `packageName`, `mac`, `androidId` |
| `m`, `n`, `o`, `y` | `init`, `showAdvert`, `kill`, `KEY_SHELL_BURY` |

That one table is the C2, the reflection targets, the resource name and the network key. Past the strings, the shell has only a shrinker's short class names, and `x.cpe` itself keeps its full names, so both read almost like source.

## letu.jet is the core, XORed with its own name

The shell is a stage-one loader. On `init(context, channel)` it posts a JSON request to `/sdk`. If the server offers a newer core, the shell downloads it, checks its MD5 and loads it with `DexClassLoader` (a failed download is retried every 60 seconds, up to 30 times). If the server offers nothing newer, or can't be reached, the core comes from the APK itself:

```java
private boolean a(Context context, String str) {
    InputStream in = MzEntry.class.getResourceAsStream(g.u);   // "/com/ocean/zoe/letu.jet"
    return in == null ? r.a(context, g.s, str)
                      : r.a(context, in, g.s, str);              // (1) XOR with "letu"
}
```

(1) copies the resource into `files/.honor/` and XORs it with `g.s`, the string `letu`. The XOR restarts at the key's first byte for every 1,024-byte read, and 1,024 is a multiple of 4, so for full reads this is `out[i] = in[i] ^ "letu"[i % 4]`. The file name is the CRC32 of `letu` plus the version, so the built-in version 39 lands at `files/.honor/2184177399.jar`. The shell also runs `chmod 777` on `.honor`.

```text
$ python3 -c '...xor with b"letu"...'  letu.jet
37035 b'PK\x03\x04'
be9d36d87fde4fb31bc3a53acaadbfcea40ea136b49f5e9406a2bab3b2ffcff6  letu.jet
49e9aaefcb01d69433430e6039a9492f731da7cc456f56070ec697e6fb397488  letu_v39.jar
```

The result is a zip with one `classes.dex` (80,120 bytes) and entries dated 2022-05-07. The three MzSDK builds carry a byte-identical `letu.jet` and so the same core. Neither hash is in TrendAI's or Plume's lists. The shell loads `com.sun.galaxy.lib.OceanInit` from it, and calls `init(context, "com.ocean.zoe.acg.func.m")`: it hands the core the name of its own class, which holds a static `HashMap` the two stages use to talk.

## The core: updates, plugins and a takeover handshake

The core's own constants are in plain text (`com.sun.galaxy.lib.b` and `.s`): base URL `hxxps://dcsdk.100ulife[.]com/`, paths `sdk`, `pluginsync`, `report`, `reportcomp`, and the same `DE252F9AC7624D723212E7E70972134D`. Its HTTP helper installs a trust manager that accepts any certificate and a hostname verifier that returns `true`, so the HTTPS is decoration.

JSON bodies go out as `hex(AES(json))` in uppercase and come back the same way. `Cipher.getInstance("AES")` with no mode means ECB with PKCS#5 padding in Java, and the key is the 32 ASCII characters themselves, so AES-256. Reports to `/reportcomp` are gzipped before encryption and sent as raw bytes.

| Endpoint | Request fields | Response fields | What the core does with it |
|---|---|---|---|
| `/sdk` | `channel`, `terminalVersion` (39), `deviceId`, `packageName`, `mac`, `androidId`, `ramMemory` | `code`, `data{versionNo, url, md5}`, `intervalTime`, `time` | If `versionNo` > 39, downloads a new core from `url`, checks MD5, and tells the shell to switch |
| `/pluginsync` | `channel`, `deviceId`, `localPluginInfos[{packageName, versionNo}]` | `code` (`0000` is success), `data[{packageName, versionNo, url, md5, status}]` | Downloads each plugin with `status` 0 from its `url`, checks MD5, loads it |
| `/reportcomp` | list of `{uploadKey, uploadValue, ext1–3, channel, deviceId, macAddress, androidId, androidBrand, androidModel, androidVersion, terminalVersion, terminalTime}` | not parsed for content | Telemetry: `SDK_INIT`, `MZ_DOWNLOAD`, `DOWNLOAD_TIMES`, `ERROR_DOWNLOAD`, `PLUG_MANAGER` 112/718/719/720, `CRASH_EXCEPTION` |

The shell's own `/sdk` request uses the same key, but it parses `data` as a string holding JSON rather than as an object, so the two stages expect slightly different server answers. The core asks `/pluginsync` every 900,000 ms (15 minutes) plus 0 to 24 seconds of jitter, and re-checks `/sdk` on a separate timer of 120 to 199 one-minute ticks, never more often than every 15 minutes. A server-sent `intervalTime` replaces the 15 minutes. The jar and APK URLs come from the server's answers, so the files can live on any host.

Plugins are APKs. The core keeps a plugin list as JSON in `.honor`, stores each APK as `files/.honor/<CRC32(package + version)>.apk`, and loads it with a class loader of its own:

```java
private DexClassLoader c(String str) {
    return new DexClassLoader(str, this.c.getDir("dex", 0).getAbsolutePath(),
                              this.b /* files/.honor/ss */, this.c.getClassLoader());
}
...
String str2 = jVar.b;                                   // first <activity> in the plugin's manifest
Class<?> cls = Class.forName(str2, true, jVar.c);
Method init = cls.getDeclaredMethod("init", Context.class, Bundle.class, Class.class);
init.invoke(null, this.c, bundle, DataReporter.class);  // (1)
```

The entry point is the plugin's first activity class, but nothing starts it as an activity. The core calls a static `init(Context, Bundle, Class)` on it (1), passing the reporter class so plugins can send telemetry through the same channel. The class names (`DLPluginManager`, `DLProxyActivity`, `DLIntent`) match the open-source dynamic-load-apk framework. A plugin therefore runs in `x.cpe`'s `:AdvService` process, with the system UID, and never shows up as an installed package.

Upgrades between cores are polite. The shell's shared map holds the channel under the key `letu`, and each core, on start, looks under `MDz19AA` for a `Method` left by the core before it, invokes it (the log line translates to "I told the previous SDK to kill itself"), and then stores its own `callAbort` there. Loaded plugins are carried across under `b2XyDz211`.

## What 6.8.x does instead

Google writes that "earlier versions of x.cpe directly embedded malicious monetization modules" and that in late 2024 the modules moved into `com.abc.nexus`, which `x.cpe` drives over IPC, with configuration arriving on the MQTT action `ext/lib/config`. MzSDK is one of those embedded modules, and the builds show the switch. The 6.8.3, 6.8.5 and 6.8.6 builds have no `com.ocean.zoe` and no `AdvertiseService`, and they add three actions: `ext/lib/config`, `ext/lib/status/report` and `ext/lib/upgrade`.

The hand-off is an Android `Messenger` on a service bound through the action `com.abc.nexus.data`. `what=1050` carries the config down; nexus answers with 100 (apply result) or 102 (a scheduled report, which `x.cpe` republishes on `ext/lib/status/report`). `ext/lib/upgrade` downloads and installs an APK from a URL in the message. If nexus isn't installed, `x.cpe` instead reports a `signFeature` number computed from its own signature, I'd guess so the operator can send a nexus build signed to match.

The Devour name and its default survive the move. Nexus 1.5.3 has a `DevourService` whose default channel is `lx102`, the same default `x.cpe`'s `ServerConfig` uses, and it calls `com.mm.a.moyu.start(context, code)`.

## MzSDK is probably an older Moyu (medium confidence)

I think, with medium confidence, that MzSDK is an earlier, embedded form of what Google calls Moyu. The evidence:

- Google says Moyu is started on these devices by `com.abc.nexus.service.DevourService`. MzSDK is started by the Devour flag in `x.cpe`, with the same default channel `lx102` that nexus's `DevourService` uses.
- Google describes Moyu as three stages: "an offline dropper that reconstructs and loads an embedded second stage", a second stage that "polls an update C2 to download, decrypt, and load the third stage". MzSDK's shell can rebuild `letu.jet` offline (it asks `/sdk` first and falls back to the embedded copy), and its core polls `/pluginsync` and loads what comes back. The fit is loose: MzSDK checks plugins by MD5 but doesn't decrypt them.

Against it: I haven't compared code with a Moyu sample from nexus, and the strings, packages and C2 differ. The core's own log tags are `MzSDK` and `com.mz.sdk.MzInnerEntry`, which suggests its developers called it `com.mz.sdk`, a name that doesn't point at Moyu or away from it. TrendAI also lists a `com.mm.a.moyu` dropper and inner DEX (`d4eba0aa…`, `e42d31c3…`), but neither was on Hybrid Analysis.

## Wrong turns

I went into the StringFog layer expecting a per-build secret, and planned to brute-force it from known plaintext such as the scheme at the start of a URL. The wrapper function had it as a literal. Reading the call site first would have saved the plan.

My extractor's first version picked the `letu.jet` XOR key by looking for a four-letter lowercase string among the decoded constants. It found `data` before `letu` and reported `jar_is_zip: false` for all three builds. The key now comes from the stem of the decoded resource path, which is what the shell itself uses.

I nearly called `dcsdk.100ulife[.]com` a new indicator. A code search turned it up in Plume's XCPE IoC file (with `com.ocean.zoe` in its package list) and in maltrail's `android_vo1d` trail. What's new here is how the SDK works, not that the domain exists.

## What I couldn't determine

- What the plugins were. No plugin APK, plugin list or server response is in any sample, and Hybrid Analysis ran static analysis only on `07b511a6`, so there is no captured traffic either. The `config` and `sdk` decrypt modes of the extractor are tested by round trip against the reconstructed scheme, not on real captures.
- What `feggen` was for. The shell carries twelve classes compiled from files named `HookManager`, `Hook`, `ArtMethod`, `DalvikMethod`, `SizeOf` and the like, around a native class `feggen` that loads `libege.so` and turns `Method` objects into raw addresses: an ART method-hooking helper. Nothing on the shell's code path references those classes, and `libege.so` isn't in any of the three APKs or in the core, so in these builds it's dead code.
- Two of TrendAI's ten `x.cpe` SHA-256 hashes, which neither service had. I didn't look up the 39 SHA-1-length values.
- Whether [Synthient's write-up](https://synthient.com/blog/the-internals-of-a-badbox-operation) or Plume's gated whitepaper already cover MzSDK. The first returned 403 to my fetch and the second needs a form, so I couldn't read either.

## Hunting

On a device, or in an image of one:

- `/data/data/x.cpe/files/.honor/`. In these builds only MzSDK creates it. `2184177399.jar` is the built-in core; other `<digits>.jar` files are core updates, and `<digits>.apk` files are plugins. `.honor/ss/` holds plugin native libraries. Strong alone.
- `x.cpe` processes named `x.cpe:AdvService` with network connections, on 6.5.x and 6.6.x builds.
- Any system app, not only `x.cpe`, signed with SHA-1 `27196e386b875e76adf700e7ea84e4c6eee33dfa`. On a retail device that certificate means test-signed firmware. Strong, and not specific to this botnet.
- `com.abc.nexus` installed alongside `x.cpe`, or a bound connection from `x.cpe` to the `com.abc.nexus.data` service action.

On the network:

- HTTPS to `dcsdk.100ulife[.]com` with a request body that is all uppercase hex. Strong alone.
- HTTP POST on port 8000 to `/router/config/mqtt`, `/router/config/acs` or `/router/config/app` (`/cpe/config/mqtt` or `/cpe/config/acs` for 6.5.0) with a JSON body `{"encryption":"..."}`. The [extractor](https://github.com/stateless-re/tools/tree/main/families/xcpe) decrypts the field (`extract.py config`), which turns a proxy log into device serials, MACs and models.
- DNS for `stb*.anyevonline[.]com`, `mcstb.anyevonline[.]com` or `ott*.szbboys[.]com`.

Statically, in APKs and firmware:

- The resource `com/ocean/zoe/letu.jet`, or the class `com.ocean.zoe.MzEntry`. Strong.
- The strings `Iz4iWGbzcm2pHjSm` or `DE252F9AC7624D723212E7E70972134D` in a DEX. Strong; neither looks like anything but a key.
- Any APK that calls a StringFog-style decoder with the literal `"UTF-8"` as its key is worth a second look on its own: it means the strings decode with a fixed key.

The extractor (`extract.py apk`) prints the signer and test-key flag, config key, hosts and MQTT topics for any `x.cpe` build and, where MzSDK is present, the decoded strings, the core's hash, URLs and key; `-o` writes the core jar.

## Indicators

Files (all read from Hybrid Analysis, or derived from those files):

| SHA-256 | Role |
|---|---|
| `6a995ad8cf248875b47f9d89518c7a21ec7cce2c252c181414e8935c6001ea36` | x.cpe 6.5.0, test key, MzSDK |
| `5ae5df84cdce0100eb957cf235d1f3fd85fa634592e7ca137de12535e9f8ad2a` | x.cpe 6.5.7, test key |
| `07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179` | x.cpe 6.6.0, test key, MzSDK |
| `5e9e0f8dc96fbf4d3e78dae90d434c424045c823316dea394e3ca39d97cda9bb` | x.cpe 6.6.0, Videostrong cert, MzSDK |
| `539913c9769de4c60151fd0c4dc5d5a669fbd48b64194b727f2f46e512e74b3f` | x.cpe 6.8.3, test key |
| `6f7f4b22eb7841d2b828f1eda77173880d42267a33b387bee9cee983c03bf291` | x.cpe 6.8.5 |
| `1de0a368599ab04b8863c0e61c2d5a75e00f742a3326325f2870a9a72ee8d200` | x.cpe 6.8.6 |
| `c96e32f7cbb8dda3cfb1f94f2c3d51dbcb68e2e5879093e18385f0b8f3b1a63b` | x.cpe 6.8.6, Videostrong cert |
| `a552bcb7d37c2bdb5c71e923157571598643de4051bfa3e5158fde3cb8709de7` | com.abc.nexus 1.5.3 |
| `be9d36d87fde4fb31bc3a53acaadbfcea40ea136b49f5e9406a2bab3b2ffcff6` | `com/ocean/zoe/letu.jet` (embedded, XORed) |
| `49e9aaefcb01d69433430e6039a9492f731da7cc456f56070ec697e6fb397488` | MzSDK core v39 jar (`letu.jet` XOR `letu`) |

Certificates (SHA-1): `27196e386b875e76adf700e7ea84e4c6eee33dfa` (AOSP test platform key), `a48cd72ea1e0ebceb21a441c906745f886770b29` (Videostrong), `64be901038dc39d77c3d877333c9c9340d3549a9` (AOSP-style subject).

Network:

| Indicator | Role |
|---|---|
| `dcsdk.100ulife[.]com` | MzSDK update-check, plugin-list and report server (jar and APK URLs come from its answers) |
| `hxxps://dcsdk.100ulife[.]com/sdk`, `/pluginsync`, `/reportcomp` | MzSDK endpoints (the core also defines `report`, but no request I found uses it) |
| `stb{major}{gms,gtvs}.anyevonline[.]com:8000` (for example `stb12gms`) | x.cpe config, 6.5.7 and later |
| `mcstb.anyevonline[.]com:8000` | x.cpe config, 6.8.x on devices with `ro.mecool.device` |
| `ott{major}{gms,gtvs}.szbboys[.]com:8000` | x.cpe config, 6.5.0 (`/cpe/config/*`) |
| `bmw.bestipip[.]com:16000` | bandwidth-module proxy endpoint (also in TrendAI's list) |

## ATT&CK

| ID | Technique | Here |
|---|---|---|
| T1474.003 | Supply Chain Compromise: Compromise Software Supply Chain | `x.cpe` ships in firmware as a system-UID app |
| T1406 | Obfuscated Files or Information | StringFog strings XORed with `UTF-8`; core jar XORed with `letu` |
| T1407 | Download New Code at Runtime | MzSDK core updates and plugin APKs loaded with `DexClassLoader` |
| T1437.001 | Application Layer Protocol: Web Protocols | HTTP config on port 8000; HTTPS to `dcsdk.100ulife[.]com` |
| T1521.001 | Encrypted Channel: Symmetric Cryptography | AES-128-CFB config bodies; AES-256-ECB SDK bodies |
| T1426 | System Information Discovery | serial, model, firmware and Android versions in every config request |
| T1422 | System Network Configuration Discovery | `eth0` MAC in config requests; MAC and Android ID in SDK requests |

## Ending

TrendAI's phrase was "obfuscation techniques", and in a sense it was right: there is a hidden loader, and its strings are encrypted. But the key for those strings is the name of a character set, the next layer's key is the name of its own file, and the network key is a constant in the clear. The domain made it onto blocklists; what the SDK does once it's running hadn't been written down. For defenders the durable part is the folder: a `.honor` directory under `x.cpe`'s data, and the test-key certificate on the system apps beside it.

## Credits and further reading

- TrendAI Research, [TrendAI Research Helps Disrupt Botnet of More Than 1.3 Million Pre-Infected Set-Top Boxes](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/trendaitm-research-helps-disrupt-android-tv-botnet-of-more-than-13-million-pre-infected-devices) (November 2, 2026), and its IoC list, where the hashes came from.
- Google Threat Intelligence Group, [Shutting the Door on the XCPE Botnet](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet) (November 2, 2026): endpoints, topics, commands, nexus and Moyu.
- Plume, [XCPE indicator list](https://github.com/plume-design/security-labs/tree/master/2026-10-XCPE), which already carries `dcsdk.100ulife[.]com` and `com.ocean.zoe`.
- stamparm's [trails](https://github.com/stamparm/trails) (the maltrail feed), whose `malware/android_vo1d.txt` lists the same domain.
- Synthient, [The internals of a BADBOX operation](https://synthient.com/blog/the-internals-of-a-badbox-operation) (not readable from here).
- The samples: [Hybrid Analysis](https://www.hybrid-analysis.com/sample/07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179) for `07b511a6`; the other hashes resolve the same way.
- The extractor: [families/xcpe](https://github.com/stateless-re/tools/tree/main/families/xcpe).
