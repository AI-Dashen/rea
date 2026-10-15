# REA Android Workbench：真实 App Attach 验收

日期：2026-10-15
设备：OnePlus 15 / Android 16 / ARM64 / Termux
目标：自有第三方应用 `com.mobileai.console`
授权：用户批准本批次 Root Frida 临时调试；禁止系统进程、系统分区和持久系统修改。

## 结论

`Frida 17.23.3 Termux Node client → Root loopback frida-server → 自有 Android App` 的枚举、Attach、脚本加载、App 内只读探针、Unload、Detach 已真实通过。

状态：

- Android 进程枚举：`VERIFIED`
- 自有第三方 App Attach：`VERIFIED`
- App 内脚本执行与结果回传：`VERIFIED`
- 显式 Detach：`VERIFIED`
- 服务与 Helper 清理：`VERIFIED`
- Dynamic Session Broker 真实 backend 接线：`PENDING`
- 连续热进程重复 Attach 稳定性：`PARTIAL`

## 安全边界

- 服务只监听 `127.0.0.1:27042`。
- 目标 UID 为 `10406`，大于系统 UID 边界 `10000`。
- Attach 前验证 package、PID、UID 和 `/proc/<pid>/cmdline`。
- 入口拒绝 `android` 与 `com.android.*`。
- 未启用 spawn gating；未附加 zygote、system_server、SystemUI 或 SurfaceFlinger。
- 服务退出后删除本次 `/data/local/tmp/rea-frida-*` 和本会话创建的 Helper。
- 未修改 Boot、VBMeta、SELinux、Magisk 配置、系统分区或持久系统属性。

## 真实结果

最终包装入口：

```sh
tools/rea/run-frida-attach-probe.sh \
  --package com.mobileai.console \
  --server <frida-server-17.23.3-android-arm64> \
  --module-root <frida-node-runtime-17.23.3> \
  --output-dir <evidence-dir>
```

最终结果：

- process count：367
- enumerated target：`AI 中枢`
- PID：7301
- agent arch：arm64
- pointer size：8
- page size：4096
- attach：PASS
- script load：PASS
- detach：PASS
- target after detach：ALIVE
- zygote / zygote64 / system_server / surfaceflinger：`TracerPid=0`
- 27042 listener after cleanup：不存在
- `/data/local/tmp/rea-frida-*` / `frida-helper*` after cleanup：不存在

Frida 在 Android 进程枚举中返回应用显示名“AI 中枢”，不是 Linux 包名。最终入口以 Root 读取的 UID、PID、cmdline 作为身份依据，不再错误地用显示名代替包名。

Termux 编译的 Node binding 会把本次 RPC 返回包装成 JSON 字符串，并伴随 GLib GValue 警告；兼容层只解析固定 `frida:rpc / ok` envelope，实际 payload 与目标 PID 一致。Attach、脚本执行和 Detach未因此失败。

## 失败与恢复记录

- 第一次流程在 shell UID 解析转义处提前退出，未执行 Attach，trap 清理成功。
- 第二次因 cmdline 尾部空白触发身份拒绝，未执行 Attach，清理成功。
- 第三次因 Frida 返回显示名而非包名触发拒绝，已完成进程枚举但未 Attach，清理成功。
- 首次真实 Attach 完整 PASS。
- 紧接着对同一热进程重复 Attach 曾出现 `Unexpectedly timed out while waiting for stop`；进程保持 sleeping、`TracerPid=0`，服务和临时目录清理成功。
- 重启自有目标 App 后，通过正式包装入口再次完整 PASS。

因此“真实 Attach 能力”已验证，但高频重复热 Attach 仍需退避/重启目标策略，不能宣称任意状态下重复附加都稳定。

## 证据

- `evidence/live-attach-2026-10-15/frida-real-app-attach.json`
- `evidence/live-attach-wrapper-2026-10-15-run3/frida-real-app-attach.json`
- `evidence/live-attach-wrapper-2026-10-15-run3/target-identity.txt`
- `evidence/live-attach-wrapper-2026-10-15-run3/post-attach-system-tracers.txt`
- `tools/rea/frida-attach-probe.mjs`
- `tools/rea/run-frida-attach-probe.sh`

## 尚未完成

生产级 Dynamic Session Broker 仍只有模拟 backend 的 11/11 测试；本次安全包装入口尚未实现 `DynamicBackend` 的持久 Session/TTL/恢复适配。因此不能把整个动态控制平面标为 `DEVICE_VERIFIED`。
