# Third-party notices

This extension does not vendor the large runtime binaries listed below. Build/download scripts and integration points may use them when the operator installs them separately.

| Component | Version used for verification | License / upstream |
| --- | --- | --- |
| REA / rea-agents | 6.5.0 | MIT, https://github.com/morluto/rea |
| Frida Node | 17.23.3 | LGPL-2.0 WITH WxWindows-exception-3.1, https://github.com/frida/frida-node |
| Frida Core/Server | 17.23.3 | See the Frida source distribution and COPYING files, https://github.com/frida/frida |
| JADX | 1.5.6 / compatible headless bridge | Apache-2.0, https://github.com/skylot/jadx |
| Ghidra | compatible headless distribution | Apache-2.0, https://github.com/NationalSecurityAgency/ghidra |

Any binary release must include the exact component version, source reference, build parameters, SHA-256 and the license/notices required by that component. The repository source branch intentionally excludes runtime binaries and analyzed third-party applications.
