# REA Android Workbench development rules

- Analyze only applications, binaries and devices that the operator owns or is authorized to test.
- Keep Android/Termux support native to Bionic/ARM64; do not add Debian, proot, chroot or a second Linux rootfs.
- Preserve upstream REA architecture and keep generally reusable fixes separable from the Android extension.
- Never commit target APKs, models, credentials, private app data, Frida/Ghidra/JADX binaries or generated analysis databases.
- `VERIFIED` requires a real execution result. Installation, compilation or documentation support alone is not verification.
- Dynamic tools are attach-only by default. Deny Android system packages, UIDs below 10000, spawn gating and arbitrary process killing.
- Root operations require an explicit operator authorization and must use loopback-only services, owned process identities and deterministic cleanup.
- Keep production Broker integration distinct from one-shot probes; do not promote simulated backend tests to real-device verification.
