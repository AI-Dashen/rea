# REA Android Workbench v2.0 四方会审与升级裁决

> 实施更新：v2.0 静态核心已完成并真实验证；动态执行后端仍为 PENDING。详见 [WORKBENCH_V2_IMPLEMENTATION_2026-10-15.md](WORKBENCH_V2_IMPLEMENTATION_2026-10-15.md)。

日期：2026-10-15
范围：现有 REA Android Workbench、JADX、Ghidra、Frida 与 Evidence Graph
状态：`REVIEWED`；升级实现尚未开始

## 1. 结论

现有工具仍有明显升级空间。下一版不应追求“万能脱壳”或继续堆砌工具数量，而应把已经能工作的静态、原生和动态分析能力，升级成一套 **可恢复、可追溯、不会拖垮手机的目标限定分析系统**。

v2.0 的三项最高优先级是：

1. **动态会话安全**：彻底避免 Frida 残留、误附加系统进程和全局 spawn gating 再次阻断 Android 应用启动。
2. **超大 APK 分层分析**：不再依赖一次性全量 JADX；先建轻量索引，再按需反编译，失败时保留可用结果。
3. **证据可复现**：每条结论带输入哈希、工具版本、参数、来源和可信度，能够重跑和比较。

建议产品名称继续使用 **REA Android Workbench**，下一阶段版本为 **v2.0**。不要将它描述成万能逆向、万能脱壳或闭源模型通用转换器。

## 2. 四方分工与实际结果

| 参与方 | 分工 | 实际结果 |
|---|---|---|
| Codex | 核对本机版本、代码、历史验证、官方资料并作最终裁决 | 完成 |
| Jev | 快速分类、风险概率和路由 | 判定为信息/架构研究；高影响概率 0.15；不要求立即审批 |
| Claude | 审查产品边界、架构、状态机、失败恢复和验收遗漏 | 完成，建议分层 JADX、证据溯源、动态会话协议和回归基线 |
| Gemini 网页通道 | 审查 Android/Termux/Frida 技术路线和性能方向 | 完成；当前账号核对为 `cooocvc@gmail.com`，网页显示模型为 Gemini Argon |

两位外部专家只提供建议，未修改代码或操作设备。最终路线由 Codex 根据本机证据和官方资料裁决。

## 3. 当前真实基线

### 3.1 已具备

- APK、AAB、APKS、Split 容器预检。
- APK V1–V4 与 AAB JAR 签名检查。
- Manifest、权限、资源、类和方法分析。
- Java ↔ JNI ↔ Native 关系图。
- Ghidra ARM64 符号、地址、字符串引用与近似反编译。
- Evidence Graph、任务状态、原子 checkpoint 和失败后部分结果保留。
- FLUTE v2 只读结构解析。
- v1.1 累计 60 项检查/测试通过。

### 3.2 当前限制

- 170,975,042 字节的豆包输入法 APK，在 45 秒预算下保留 7,910 个 Java 文件，在 300 秒预算下保留 9,196 个，仍是 `PARTIAL`。
- 当前全量 JADX 路线耗时长，无法可靠断点续作，也不能在大包上保证完整性。
- 动态分析缺少正式 Session Broker。近期 Frida 曾让 `zygote64` 进入 `tracing stop`，造成新应用普遍白屏/无法启动。
- 证据节点尚未全面携带工具版本、配置哈希、授权来源和保真度。
- 闭源模型的权重编码、算子语义和训练材料仍未还原，不能从“运行轨迹可观察”推断“模型可通用转换”。

## 4. 版本核验（2026-10-15）

| 组件 | 本机 | 当前官方信息 | 裁决 |
|---|---:|---:|---|
| REA | 6.3.0，固定 commit `6543405252d7c740c87a3bb433cf666187af41fa` | npm/GitHub Release 6.5.0 | 在隔离目录升级验证；保留 Android 补丁，不直接覆盖工作版本 |
| Frida | 17.2.14 | 17.23.3 | 建立匹配 client/server 的旁路候选版；通过安全回归后再替换 |
| JADX | 1.5.6 | 1.5.6 | 已是当前正式版，不升级 |
| jadx-headless-mcp | 0.7.1 all.jar | 当前 Workbench 固定依赖 | 先确认内嵌 jadx-core 的准确版本，再决定是否调整 |
| Ghidra | 12.1.4 | 当前 Workbench 已验证版本 | 暂不升级，避免与本轮目标无关的变量 |

元数据体积：

- `rea-agents@6.5.0` npm 解包约 25,564,765 字节、1,650 个文件。
- `frida@17.23.3` npm 解包约 4,750,838 字节、346 个文件；这不是 Android frida-server 资产体积。

REA 6.5.0 与 Frida 17.23.3 均未在本手机完成安装或运行，因此当前只能标记为 `PENDING`。

## 5. 外部意见的共识与裁决

### 5.1 采纳

- 全量反编译改为：轻量 DEX 索引 → 目标类/方法按需反编译 → smali 降级。
- 每个 DEX 使用隔离子进程、独立超时和资源上限，允许单个 DEX 失败而不丢失整个任务。
- 统一输出 `FULL`、`PARTIAL`、`SMALI_ONLY`、`FAILED`，禁止把部分结果写成完成。
- 建立 Dynamic Session Broker，明确目标包、UID/PID、TTL、用途、授权引用和本次 Frida 服务 PID。
- 动态证据必须回流 Evidence Graph，并与静态 Java/JNI/Native 节点关联。
- 建立版本矩阵和回归样本，工具升级不得破坏现有 60 项验证。
- 增加同一应用不同版本的差异分析，优先定位新增网络端点、权限、Native 库、JNI 注册和业务分支。

### 5.2 不采纳或暂缓

- **eBPF uprobes**：仅保留可行性研究。它依赖内核配置、BTF、SELinux 和 Root 域，本机没有真实证据；若未来测试，还涉及系统级操作，需单独批准。
- **自动杀死任意 tracer 并向系统进程发送 SIGCONT**：不采纳。检测器只能停止自己创建的进程并把环境标记为 `DIRTY`，不能误杀其他合法调试器或自动操作系统进程。
- **默认使用 `am set-debug-app -w --persistent`**：不采纳。该操作修改系统调试状态且可能持久化，只能作为另行批准的专项实验。
- **全局 spawn gating、常驻 Frida、默认 Hook 第三方应用**：不采纳。
- **万能脱壳、自动恢复任意混淆业务、闭源模型一键转通用格式**：不设为承诺目标。
- **Debian/proot/chroot**：违反本项目 Android + Termux 原生唯一原则，淘汰。

## 6. v2.0 实施路线

### P0-A：依赖升级旁路验证

1. 在独立目录获取 REA 6.5.0，比较 6.3.0→6.5.0 的 Android、MCP schema 和 provider 变化。
2. 把现有三处 Android/Termux 兼容改动重放到新版本，优先改成可维护的最小 patch。
3. 在独立目录准备 Frida 17.23.3 client/server 候选，强制版本一致。
4. 保留现有 6.3.0/17.2.14 可执行物，未通过验收不替换。

### P0-B：Dynamic Session Broker

每次动态分析创建结构化 session：

- `session_id`
- 允许的 package、UID、PID
- 目标 APK/version/hash
- TTL、用途、授权引用
- Frida client/server 版本与自有 server PID
- 状态：`CREATED → PRECHECKED → ATTACHED → COLLECTING → CLEANING → CLOSED`
- 异常状态：`DENIED / FAILED / DIRTY`

强制规则：

- 默认只附加已经运行、且身份二次核对成功的授权目标 PID。
- 硬拒绝 `zygote*`、`system_server`、SystemUI、Launcher、UID < 10000。
- 不启用全局 spawn gating。
- 存在不受管的 frida-server 时拒绝启动新 session。
- attach 前再次读取 UID、cmdline、package，防止 PID 复用。
- `finally/trap` 只清理本次创建的会话和进程。
- 清理失败时标记 `DIRTY`，阻止下一次动态分析；系统恢复动作仍按系统操作规则取得批准。

### P0-C：大 APK 分层静态分析

1. 先解析 APK/Split 与全部 DEX 清单。
2. 为每个 DEX 建立类、方法、字符串、调用引用、JNI 候选的轻量索引。
3. 搜索和证据图默认使用索引，不等待全部 Java 源码。
4. 用户或分析器选中目标后，再调用 JADX 反编译具体类/方法。
5. Java 失败时保留 smali 和引用证据。
6. 每个 DEX 独立 checkpoint、内存/时间上限和状态。

### P0-D：Evidence Graph v2

每个证据节点新增：

- 输入 SHA-256、工具名和准确版本
- 配置哈希、命令/调用标识、时间
- `STATIC / DYNAMIC / INFERRED`
- `EXACT / PARTIAL / APPROXIMATE`
- session/授权引用
- 相关源文件、类、方法、地址、Native 符号
- 置信度与人工确认状态

### P1：跨层和差异分析

- Java 调用点 → JNI 声明/动态注册 → Native 符号/Ghidra 函数。
- 受控动态证据 → 静态节点自动关联。
- 同应用不同版本的权限、组件、端点、类、Native 库和模型资产差异。
- 固定样本和工具版本矩阵；升级前后输出可比结果。

### P2：研究项

- eBPF 只做内核能力检查和无修改可行性报告，不默认实现。
- 证据图可视化、HTML 报告和人工标注。
- 针对具体授权应用生成最小探针模板，仍由 Session Broker 控制。

## 7. 验收标准

### 动态安全

- 自有测试 APK 连续 30–50 次 attach/detach、客户端异常退出、脚本异常和目标崩溃测试。
- 全程 `zygote*`、`system_server` 的 `TracerPid=0`。
- 退出后无本次 frida-server、会话或注入残留。
- 不出现新应用启动积压、SystemUI 重启、触摸 ANR。
- 正式替换 Frida 前建议扩大到 100 次回归。

### 大 APK

- 对现有 170MB 基线包，在有界内存下完成全部 DEX 的轻量索引。
- 指定目标类能按需生成 Java 或明确降级为 smali。
- 中断后可从最近 DEX/checkpoint 恢复。
- 每个阶段的完整度状态真实可读。

### 证据

- 随机抽取至少 20 条结论，能够从 Evidence Graph 回溯到输入、工具、版本、参数和原始证据。
- 同一输入、相同版本和配置可重放；差异有明确说明。

### 兼容性

- 原有 60 项测试全部通过。
- REA upstream 测试及本机 Android 补丁测试通过。
- 原有小 APK、Ghidra ARM64、FLUTE v2 基线无回归。

## 8. 下一批实施所需下载

按照项目下载规则，实施 P0-A 前需单独获得用户对以下精确清单的同意：

1. 官方 npm `rea-agents@6.5.0`，解包约 25.6MB，来源 `registry.npmjs.org`。
2. 官方 Frida 17.23.3 的 Android arm64 server 与匹配 client；实际压缩包大小需在下载前从官方 Release 元数据再次核对。

下载仅进入隔离工作目录，不替换当前成功版本，不修改 Android 系统。

## 9. 最终判断

升级空间很大，而且方向已经明确。最值得做的不是增加“更强的破解按钮”，而是把工具提升为：

> 静态先索引、目标再深挖、动态有边界、失败可恢复、证据能复现。

完成 P0 后，Workbench 才适合持续分析大型 Android 应用；完成 P1 后，才会从“工具集合”升级成真正的跨层逆向分析系统。
