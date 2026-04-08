# vortex

**EN:** Terminal-oriented security monitoring for **macOS** (Java + shell + optional Python tools).  
**中文：** 面向 **macOS** 的终端安全监控项目（Java + Shell + 可选 Python 工具）。

**Languages / 语言:** [English](#english) · [中文](#中文)

---

## Disclaimer / 法律与使用声明

**EN:** This project includes hooks to external tools (e.g. network scanning, ARP scripts, stress-test lab scripts, `hydra` launcher). **Use only on systems and networks you are legally authorized to test.** Misuse may violate law. Authors are not responsible for misuse.

**中文：** 本项目会调用外部工具（网络扫描、ARP 相关脚本、压力测试实验脚本、`hydra` 启动等）。**仅可在您依法有权测试的系统与网络上使用。** 滥用可能违法，作者不对滥用承担责任。

---

## English

Current version: `0.1.1` (see `VERSION`)

### Overview

- Monitors **established TCP** connections via `netstat`, scores IPv4 risk / security coefficient, sliding **60s** window for repeated access.
- **Wide heuristic alerts** (same alert log): UDP socket summary, Bluetooth profile snapshot changes, local **Tor** listener ports (9050/9150), VPN/AWDL hints, macOS **system proxy** (`scutil`), mail client processes, **cookie store file mtime** changes for major browsers (no cookie contents read).
- Interactive **command** console: block/unblock IPv4, optional Python toolchains (ARP, stress lab, hydra launcher).
- **Three Terminal windows** via `start_vortex.sh`: monitor, command, alerts.

### Requirements

- macOS  
- **JDK 17+** recommended (often works on **11+**)

### Build & run

```bash
chmod +x build.sh start_vortex.sh
./build.sh
./start_vortex.sh
```

Single-window modes:

```bash
java -cp out vortex.VortexMain monitor
java -cp out vortex.VortexMain command
java -cp out vortex.VortexMain alerts
```

### Hydra (optional)

The **`hydra`** command **prefers** `thc-hydra-9.6/hydra` after you build from source; otherwise it falls back to `hydra` on **PATH**.

```bash
cd thc-hydra-9.6 && ./configure && make
# optional: brew install libssh openssl  … if configure asks for deps
```

Use only where legally permitted.

### Integrated bundles (optional)

| Area | Notes |
|------|--------|
| `arpSproofing-main/` | Python + Scapy; `pip install -r arpSproofing-main/requirements.txt`; invoked via `sudo python3` from vortex. |
| `DDos-Attack-master/` | Python 3 UDP lab script; `udpstress` command; authorized targets only. |
| `thc-hydra-9.6/` | Source tree; `hydra-check` for install/version hints. |

Env: **`VORTEX_PYTHON`** overrides `python3`.

### pf firewall (optional)

```bash
./setup_pf_table.sh
```

Then use `block` / `unblock` in the command console.

### Auto layout & auto-close windows

`start_vortex.sh` sets Terminal window sizes/titles and `VORTEX_AUTO_CLOSE=1`. First run may require **Automation** permission for Java to control **Terminal** (System Settings → Privacy & Security → Automation).

### LaunchAgent (optional)

Copy `launchd/com.local.vortex.plist.example` to `~/Library/LaunchAgents/`, replace `REPLACE_WITH_ABSOLUTE_PATH_TO_VORTEX` with your clone path, then `launchctl load`.

### Repository layout (main)

| Path | Role |
|------|------|
| `src/vortex/VortexMain.java` | Entry, modes |
| `src/vortex/NetSnapshotCollector.java` | TCP sampling |
| `src/vortex/WideSignalCollector.java` | Multi-channel heuristics |
| `src/vortex/RiskEngine.java` | Scoring |
| `src/vortex/BlocklistManager.java` | Blocklist + optional `pfctl` |
| `build.sh` / `start_vortex.sh` | Build & launch |

### Do not commit

See `.gitignore`: `out/`, `logs/*.log`, etc.

---

## 中文

当前版本：`0.1.1`（见 `VERSION` 文件）

### 概述

- 通过 `netstat` 监控 **已建立 TCP**，对 IPv4 做风险/安全系数评估，**60 秒**滑动窗口统计重复访问。
- **广域启发式告警**（与低安全 IP 告警写入同一日志）：UDP 概况、蓝牙配置快照变化、本机 **Tor** 监听（9050/9150）、VPN/AWDL、`scutil` **系统代理**、邮件客户端进程、主流浏览器 **Cookie 库文件 mtime**（**不读** cookie 内容）。
- **命令**控制台：封禁/解封 IPv4、可选 Python 工具链（ARP、压力实验、hydra 启动）。
- **`start_vortex.sh`** 一次打开三个终端：监控 / 命令 / 告警。

### 环境要求

- macOS  
- 推荐 **JDK 17+**（**11+** 多数可编译运行）

### 编译与运行

```bash
chmod +x build.sh start_vortex.sh
./build.sh
./start_vortex.sh
```

单窗口：

```bash
java -cp out vortex.VortexMain monitor
java -cp out vortex.VortexMain command
java -cp out vortex.VortexMain alerts
```

### Hydra（可选）

**`hydra`** 命令**优先**使用仓库内编译好的 **`thc-hydra-9.6/hydra`**，没有该文件时才用 **PATH** 里的 `hydra`。编译示例：

```bash
cd thc-hydra-9.6 && ./configure && make
```

仅限合法授权场景。

### 可选集成目录

| 目录 | 说明 |
|------|------|
| `arpSproofing-main/` | Python + Scapy；先 `pip install -r arpSproofing-main/requirements.txt`；由 vortex 以 `sudo python3` 调用。 |
| `DDos-Attack-master/` | Python3 UDP 实验脚本；命令 `udpstress`；须合法授权。 |
| `thc-hydra-9.6/` | 源码目录；`hydra-check` 做安装/版本检测。 |

环境变量 **`VORTEX_PYTHON`** 可指定 Python 路径。

### 防火墙（可选）

```bash
./setup_pf_table.sh
```

然后在命令窗口使用 `block` / `unblock`。

### 三窗口布局与退出关窗

`start_vortex.sh` 用 AppleScript 设置窗口大小/标题，并设置 `VORTEX_AUTO_CLOSE=1`。首次退出时系统可能询问是否允许 **java** 自动化控制 **终端**（系统设置 → 隐私与安全性 → **自动化**）。

### 登录启动（可选）

将 `launchd/com.local.vortex.plist.example` 复制到 `~/Library/LaunchAgents/`，把路径占位符换成你本机克隆目录的**绝对路径**，再 `launchctl load`。

### 广域告警说明

- 多为 **启发式/元数据**，不是全流量审计；`system_profiler` 等已 **降频**（如蓝牙约每 30 秒）。
- Tor 仅检测本机 **9050 / 9150**；Cookie 仅 **mtime** 变化告警，同文件 **90 秒**冷却。

### 勿提交仓库的内容

见 `.gitignore`：`out/`、运行日志等。

---


