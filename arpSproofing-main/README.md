# arpSproofing-main（与 macOS 说明）

## 依赖

```bash
python3 -m pip install -r requirements.txt
```

## macOS 兼容性要点

| 项目 | 说明 |
|------|------|
| **权限** | Scapy 发二层包、抓包通常需要 **root**：`sudo python3 arp_defense.py ...` |
| **网卡名** | 一般为 `en0`（Wi‑Fi）、`en1` 等，不是 Linux 的 `eth0`。请用 `-i en0` 指定 |
| **ping** | `ip_detection.py` 已对 **Darwin** 单独使用 `ping -W 1000`（毫秒），避免与 Linux 的 `-W`（秒）混淆 |
| **防火墙 / SIP** | 部分环境可能限制原始套接字；若失败请检查是否已授权终端/ Python 的网络权限 |

## 运行示例

```bash
cd arpSproofing-main
sudo python3 ip_detection.py -m auto -i en0
sudo python3 arp_defense.py -i en0 -g 192.168.1.1
```

若自动识别网段失败或扫不到主机，请显式指定网段（常见家用路由为 `192.168.0.0/24` 而非 `192.168.1.0/24`）：

```bash
sudo python3 ip_detection.py -m auto -i en0 -t 192.168.0.0/24
```

在 vortex 命令行：

```text
vortex> netscan -m auto -i en0 -t 192.168.0.0/24
```

## 法律与伦理

ARP 相关脚本仅适用于**自己拥有授权**的网络与设备上的安全研究与教学。未经授权对他人网络使用可能违法。
