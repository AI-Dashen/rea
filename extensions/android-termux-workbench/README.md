# REA Android Workbench

**Android/Termux ARM64 Analysis & Evidence Extension for REA 6.5.0**

REA Android Workbench is a community-maintained extension of [REA](https://github.com/morluto/rea) for on-device Android analysis in a native Termux/Bionic environment. It adds bounded large-APK indexing, class-on-demand decompilation, Android package/version intelligence, reproducible evidence graphs, and a fail-closed dynamic-analysis control plane.

This is not an official REA release. Upstream REA remains the general-purpose MCP reverse-engineering platform; this branch specializes it for Android/ARM64 devices.

## 中文定位

这是一个面向 Android 真机和 Termux ARM64 的本地逆向分析与可验证证据工作台。它将大型 APK 的结构索引、按需反编译、版本差异、Native 分析、证据图谱和受控 Frida 动态验证组合到 REA 的能力体系中。

## Capability status

| Capability | Status | Verified scope |
| --- | --- | --- |
| REA 6.5.0 Android/ARM64 host adaptation | VERIFIED | Native Termux build and owned APK MCP flow |
| APK/AAB/APKS/Split inspection | VERIFIED | Container, manifest, resources and native inventory |
| APK V1–V4 / AAB JAR signature inspection | VERIFIED | Local package evidence |
| Bounded multi-DEX SQLite index | VERIFIED | 170,975,042-byte APK; 3 DEX; 31,290 classes |
| Class-on-demand JADX decompilation | VERIFIED | Exact-class lookup after index |
| Android structural version diff | VERIFIED | Classes, methods, DEX, manifest, resources and native libraries |
| ARM64 native/Ghidra evidence | VERIFIED | Controlled local samples and target libraries |
| Evidence Graph v2 | VERIFIED | Source, exactness, confidence and stable fingerprints |
| Dynamic Session Broker state machine | TESTED | 11/11 simulated-backend tests |
| Frida Node 17.23.3 native Termux build | VERIFIED | ARM64 binding load and loopback transport |
| Owned Android app process enumeration | VERIFIED | OnePlus 15 / Android 16 |
| Owned Android app attach/script/detach | VERIFIED | Attach-only read probe against `com.mobileai.console` |
| Production Broker-to-Frida adapter | PENDING | Persistent TTL/session backend not wired |
| Repeated hot-process attach stability | PARTIAL | One immediate repeat timed out; fresh app process passed |
| Universal unpacking / automated deobfuscation | NOT CLAIMED | Outside current verified scope |

## Why this branch exists

Desktop-first reverse-engineering workflows often assume abundant RAM, glibc, full application decompilation and a privileged host. This extension instead uses:

- bounded/mmap DEX parsing;
- SQLite symbol indexes and resumable checkpoints;
- targeted JADX decompilation only after exact class lookup;
- explicit STATIC / DYNAMIC / INFERRED evidence types;
- EXACT / PARTIAL / APPROXIMATE precision labels;
- Android UID/PID/package identity checks;
- loopback-only, attach-only Frida probes;
- denial of Android system targets and UIDs below 10000.

## Layout

```text
extensions/android-termux-workbench/
├── bin/                 # Termux entry points
├── tools/rea/           # analysis, evidence, diff and dynamic controls
├── docs/                # design, implementation and real-device acceptance
├── evidence/            # sanitized owned-app evidence
└── THIRD_PARTY_NOTICES.md
```

Large third-party runtime binaries, target APKs, models, credentials and private application data are deliberately excluded from Git.

## Termux requirements

This project targets native Android/Termux ARM64. It does not require Debian, proot, chroot or another Linux rootfs.

Typical dependencies include Python, Node.js, OpenJDK, JADX, Android build tools and optional Ghidra/Frida components. Exact dependencies vary by capability. Set external runtime paths with environment variables instead of committing binaries.

```sh
export REA_JADX_MCP_JAR=/absolute/path/to/jadx-headless-mcp.jar
export REA_SOURCE_ROOT=/absolute/path/to/rea
```

## Static workbench

```sh
extensions/android-termux-workbench/bin/rea-workbench index \
  --input <authorized-apk> --job <job-name>

extensions/android-termux-workbench/bin/rea-workbench search \
  --index <index-dir> --kind class --query <query>

extensions/android-termux-workbench/bin/rea-workbench class \
  --index <index-dir> --name <fully-qualified-class>
```

Only analyze applications and devices you own or are authorized to test.

## Dynamic probe

The real-device probe is intentionally attach-only. It does not expose spawn gating, arbitrary process killing or system-process recovery.

```sh
extensions/android-termux-workbench/tools/rea/run-frida-attach-probe.sh \
  --package <authorized.non.system.package> \
  --server <frida-server-17.23.3-android-arm64> \
  --module-root <frida-node-runtime-17.23.3> \
  --output-dir <evidence-dir>
```

The launcher requires a running non-system application, checks UID/PID/cmdline, binds Frida to `127.0.0.1`, rejects Android system packages, and removes its temporary server/helper files after the probe. Root authorization and Android system-impact approval remain the operator's responsibility.

## Verification

Generate the owned fixtures and run the portable suite:

```sh
extensions/android-termux-workbench/bin/run-portable-tests
```

Set `REA_JADX_JAR` when JADX is not installed at a standard Termux path. Ghidra headless integration and the real-device Frida attach probe are separate environment-dependent checks.

The local implementation passed:

- 30 workbench acceptance checks;
- 54 Python unit/specialized tests;
- 9 REA Android process-ownership tests;
- 11 JADX Android configuration tests;
- one real owned-app process enumeration/attach/script/detach flow.

See [implementation evidence](docs/WORKBENCH_V2_IMPLEMENTATION.md) and [real app attach evidence](docs/REAL_APP_ATTACH.md).

## Relationship to upstream

The `main` branch should track upstream REA. Android/Termux work remains on `android-termux-workbench`; narrowly reusable fixes can be proposed upstream independently. Experimental runtime work belongs on a separate `experimental/android-dynamic` branch.

## License

REA is MIT licensed; the original copyright and license are preserved at the repository root. Third-party runtimes retain their own licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
