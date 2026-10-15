# REA Android Workbench v2.0 升级验收

日期：2026-10-15
环境：OnePlus 15 / Android 16 / Termux ARM64
最终状态：**PARTIAL（静态核心 VERIFIED；动态执行后端 PENDING）**

## 1. 本轮完成内容

### REA 6.5.0 Android/Termux 适配

- 固定上游版本：`rea-agents-6.5.0`，commit `3b79af28e80785afce9f5998d8f03289402a1847`。
- 将现有 Android ARM64 进程归属与 JADX 配置补丁重放到 6.5.0。
- 补丁：`tools/rea/patches/0002-rea-6.5-termux-android-process-ownership.patch`。
- 补丁 SHA-256：`2890f900cebad3c05fb58dcc756b48f7c1a1a552ac87fc6b1925cf2b1ad356cf`。
- `bin/rea-termux` 默认入口已切换到隔离构建的 6.5.0，可用 `REA_SOURCE_ROOT` 显式指定其他已验证源码树。
- 自有 APK 真实 MCP 闭环通过：`binary_session → inspect_android_package → search_android_classes → inspect_android_class → inspect_android_method`。
- Server 返回版本 6.5.0，方法体 `owned.acceptance.OwnedArithmetic.add` 可用；关闭后无 Server 残留。

### 大 APK 分层索引与按需反编译

新增：

- `tools/rea/dex_layer.py`
- `rea-workbench index`
- `rea-workbench search`
- `rea-workbench class`

实现：

- mmap + 有界 DEX 原始结构解析；
- SQLite 存储全部 DEX 单元、类、声明方法、字符串和归档成员；
- 每个 DEX 独立状态与 checkpoint；
- `--resume` 只复用哈希一致且已验证的 DEX 单元；
- 指定精确类名后才调用 JADX `--single-class`；
- 缓存绑定 JADX 1.5.6、JAR SHA-256、参数和配置 SHA-256；
- 输入变化、索引越界、类歧义和损坏 DEX 均 fail closed。

真实 170,975,042 字节豆包输入法 APK：

- APK SHA-256：`abb24d0a33cee91a9d96783243b75950151bc478ce47da629e5fdf8844607f26`
- 3 个 DEX；
- 193,775 个字符串；
- 31,290 个类；
- 154,469 个声明方法；
- 3,293 个归档成员；
- SQLite `quick_check=ok`；
- 状态 `VERIFIED`；
- 初次完整轻量索引约 10.27 秒；
- `ServiceImpl` 单类按需反编译约 19.7 秒，结果 `VERIFIED`；
- 再次运行从 checkpoint 恢复，三个 DEX 均标记 `resumed=true`。

这替代了大包必须等待全量 JADX 的旧瓶颈。全量 Java 源码仍不宣称完整恢复。

### 版本差异分析

新增：

- `tools/rea/android_version_diff.py`
- `rea-workbench diff`

全部变化保存在 SQLite，JSON 只给受限样例。比较范围包括：类、方法、字符串、DEX、Manifest、资源、资产和 Native 库。

自有两个 APK 版本实测：

- 状态 `VERIFIED`；
- 完整差异 37 项；
- 包含类、方法、DEX、Manifest、Native 和字符串变化；
- SQLite `quick_check=ok`；
- Evidence Graph v2 节点已生成。

### Evidence Contract / Graph v2

`tools/rea/evidence_contract.py` 保留 v1 输出形状，同时新增 v2：

- 输入 SHA-256；
- 工具准确版本；
- 配置 SHA-256；
- UTC 规范时间；
- `STATIC / DYNAMIC / INFERRED`；
- `EXACT / PARTIAL / APPROXIMATE`；
- session、authorization、invocation 引用；
- source refs；
- 置信度与人工确认；
- 稳定 claim fingerprint 与独立 observation ID；
- 图节点去重、边端点校验和防篡改校验。

DEX 索引与版本差异的真实输出已直接携带 `evidence_graph_v2`，不是只存在一套未接入的类定义。

### Dynamic Session Broker

新增：

- `tools/rea/dynamic_session_broker.py`

安全边界：

- package、UID、PID、TTL、用途和授权引用强绑定；
- 拒绝 UID `<10000`、zygote、system_server、SystemUI、Launcher 等系统目标；
- 仅 loopback、仅采用本次 Broker 创建并能核验身份的 Frida Server；
- attach 前两次核对 PID/UID/package/cmdline/start_ticks；
- 只清理本 Session 拥有的 attachment/server；
- TTL 到期回收；
- 检测系统 runtime 被 trace 后标记全局 `DIRTY` 并阻断新会话；
- 不提供 spawn gating、任意 kill、系统进程恢复或 Root 绕行接口。

当前状态为 **TESTED（模拟后端 11/11）**，尚未做真实 Android/Frida attach，因此不标 `DEVICE_VERIFIED`。

## 2. Frida 17.23.3 Termux 原生编译结果

官方 Android arm64 server 与匹配的 Node client 均已完成本机校验：

- 官方 server 压缩包 SHA-256：`f61e98db10dc1692be1cfe209e4ec32f5381759c722ab1a3f79db36730e6234e`；
- server 解压后 SHA-256：`8887fb3dc84222416e2cdde706a10037c920df01d7858025168739d926c2fe17`；
- `frida@17.23.3` npm 源包 SHA-256：`8551deb27f180bf7acf159e23ce94b660cbe8c03f4f89a17e628351625d1edf7`；
- Frida Vala 固定 commit：`172348fa9123ff4a95d541c5f9e56837434c4b6e`；
- SDK 固定版本：`20261004`；
- Termux 原生未裁剪 binding：93,947,888 字节，SHA-256 `dcb66c53d4db74db2b207c6c06dd4eb5c716e4ab5bac615134e28c5516f5cbef`；
- 裁剪运行版 binding：67,212,744 字节，SHA-256 `e66b54b298fdb9c755f717d440b975f50929b653bde0daa1d6c559ab87b359de`。

真实结果：

- ARM64 Android 24 `.node` 编译：`VERIFIED`；
- Node 加载 binding：`VERIFIED`；
- `getDeviceManager()` 与本地设备列表：`VERIFIED`；
- 匹配 17.23.3 client/server 的 loopback 连接：`VERIFIED`；
- Android 进程枚举：`FAILED`，官方 server 试图在 `/data/local/tmp` 创建 helper DEX，非 Root Termux 进程收到 `Permission denied`；
- Android App attach：`PENDING`，本轮未使用 Root、未附加任何 App、未修改 Android 系统。

新增可复现资产：

- `tools/rea/build-frida-node-termux.sh`；
- `tools/rea/frida-node-probe.mjs`；
- `tools/rea/patches/0003-frida-node-17.23.3-termux-top-level.patch`；
- `tools/rea/patches/0004-frida-node-17.23.3-termux-subprojects.patch`；
- `docs/research/rea-followup/evidence/frida-node-17.23.3-termux-build.json`。

这已经消除了“匹配 Termux client 无法编译”的旧阻塞，但没有把“loopback 握手成功”冒充为“动态附加已完成”。完整 Android 动态后端仍须在另行授权的第三方测试 App 上完成受控真机验收。

## 3. 多 AI 会审与裁决

- **Jev**：做任务分类、风险概率和初始路由；结果只作提示。
- **Claude**：建议明确 DEX shard 状态、缓存版本、租约 TTL、启动恢复、证据溯源和异常清理。
- **Gemini 网页**：当前账号核对为 `cooocvc@gmail.com`，页面模型显示 `Gemini Argon`；建议精确 PID attach、SQLite 索引优先、结构/IR 差异和延迟证据关联。
- **Codex**：完成真实代码、测试、版本核验与最终裁决。

未采纳：自动操作 zygote/system_server、`SIGCONT` 系统进程、持久调试属性、Root 绕过、Debian/proot、万能脱壳承诺。原因是超出安全边界或缺乏本机证据。

## 4. 测试结果

- Workbench Python：30 项验收 + 54 项单元/专项 = **84/84 PASS**。
- REA 6.5 Android 进程归属：**9/9 PASS**；JADX Android 配置：**11/11 PASS**。
- Evidence Contract v2：**7/7 PASS**（包含在 54 项中）。
- Dynamic Session Broker：**11/11 PASS**（包含在 54 项中）。
- DEX/版本差异：**6/6 PASS**（包含在 54 项中）。
- REA 6.5 `compile:termux`：**PASS**。
- Frida Node 17.23.3 Termux 原生编译与 binding 加载：**PASS**；可复现构建脚本续建自检：**PASS**。
- Frida 17.23.3 loopback transport：**PASS**；Android 进程枚举因 `/data/local/tmp` 权限：**FAILED（如实保留）**。
- REA 6.5 自有 APK MCP E2E：**PASS**。
- 170MB 真实 APK 分层索引：**VERIFIED**。
- 单类真实按需反编译：**VERIFIED**。
- Python `py_compile`、`git diff --check`：**PASS**。

## 5. 入口

```sh
# REA 6.5
bin/rea-termux --version

# Frida Node 17.23.3 Termux 原生运行包自检
node tools/rea/frida-node-probe.mjs --module-root run/rea-upgrade-v2/frida-node-runtime-17.23.3

# 大 APK 索引
bin/rea-workbench index --input <REA允许目录内的APK> --job <job>

# 搜索
bin/rea-workbench search --index <index目录> --kind class --query <关键词>

# 精确类按需反编译
bin/rea-workbench class --index <index目录> --name <完整类名>

# 两版本差异
bin/rea-workbench diff --old-index <旧索引> --new-index <新索引> --job <job>
```

## 6. 最终判断

本轮已经把工具从“全量反编译脚本集合”升级为：

> 大包先快速建完整索引，目标再按需反编译，版本差异完整落盘，证据带可复现来源，动态会话默认拒绝危险目标。

静态核心可投入当前自用分析；匹配的 Frida 17.23.3 Termux client 已从源码成功编译、裁剪并加载，loopback client/server transport 已打通。官方 server 的 Android helper 路径仍受 `/data/local/tmp` 权限限制，真实 App attach 和 Broker 后端接线尚未验收，因此整体状态保持 `PARTIAL`，不能称为“万能动态逆向已完成”。

## 7. 2026-10-15 补充：真实 App Attach

本文件第2、4、6节记录的是未获Root动态测试授权时的原始结果，历史结论保留。后续用户批准限定批次后，新增证据已将以下能力推进：

- Android进程枚举：`FAILED → VERIFIED`
- 自有第三方App Attach：`PENDING → VERIFIED`
- App内脚本执行/结果回传/Detach：`VERIFIED`
- 服务、Helper和系统追踪状态清理：`VERIFIED`

目标为本项目自有 `com.mobileai.console`；未附加系统进程。正式安全包装入口为 `tools/rea/run-frida-attach-probe.sh`。同一热进程紧接重复Attach曾一次超时，重启目标App后完整PASS；Dynamic Session Broker真实backend接线仍为`PENDING`。完整证据见 `REAL_APP_ATTACH_2026-10-15.md`。
