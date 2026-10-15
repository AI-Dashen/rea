<div align="center">

# Android/Termux 逆向分析工作台增强版 · rea

**将大体积 APK 索引、按需反编译与受控 Frida 挂载带入 Android/Termux ARM64 环境。**

</div>

本项目派生自 REA 上游并保留 MIT 许可。针对移动端大包分析痛点，在专用分支中拓展了 Android/Termux ARM64 运行适配，引入 SQLite 索引加速、签名与资源分析、版本差异对比及 Evidence Graph 证据链追踪。

## 值得关注的技术

- Android/Termux ARM64 本地适配与大体积 APK SQLite 索引及按需反编译
- 支持 APK 签名/资源解析、跨版本 Diff 对比与 Evidence Graph 建模
- 支持临时 Frida 受控 attach 动态辅助分析

## 当前进度

Android/Termux 增强功能位于 android-termux-workbench 分支；动态 Broker 的生产适配仍待接通，重复热进程附加稳定性仍有限制。

## 手机增强版入口

[查看 Android/Termux 分支](https://github.com/AI-Dashen/rea/tree/android-termux-workbench) · [安装、命令与能力证据](https://github.com/AI-Dashen/rea/blob/android-termux-workbench/extensions/android-termux-workbench/README.md)

本仓库由 [morluto/rea](https://github.com/morluto/rea) 派生；上游通用能力与本项目手机增强分别维护，原始 MIT 许可与第三方声明保留。`main` 保留通用代码，手机增强位于上述分支。

## 文档与来源

[通用安装指南](docs/installation.md) · [MCP工具契约](docs/mcp-contracts.md) · [第三方说明](THIRD_PARTY_NOTICES.md) · [MIT许可证](LICENSE)
