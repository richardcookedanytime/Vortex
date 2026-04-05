package vortex;

import java.nio.file.Path;
import java.nio.file.Paths;

public final class VortexPaths {
    public static final Path ROOT = Paths.get("").toAbsolutePath();
    public static final Path LOG_DIR = ROOT.resolve("logs");
    public static final Path CONNECTION_LOG = LOG_DIR.resolve("ip_connections.log");
    public static final Path ALERT_LOG = LOG_DIR.resolve("low_security_alerts.log");
    public static final Path BLOCKLIST_FILE = ROOT.resolve("blocked_ips.txt");
    public static final Path SHUTDOWN_SIGNAL = LOG_DIR.resolve("vortex.shutdown");
    /** Python ARP / 网络扫描工具包目录 */
    public static final Path ARP_TOOLKIT_DIR = ROOT.resolve("arpSproofing-main");
    /** 实验用 UDP 压力脚本目录（须合法授权后使用） */
    public static final Path DDOS_LAB_DIR = ROOT.resolve("DDos-Attack-master");
    /** Hydra 源码目录（仅做版本/安装兼容检测，不执行爆破功能） */
    public static final Path HYDRA_DIR = ROOT.resolve("thc-hydra-9.6");

    private VortexPaths() {
    }
}
