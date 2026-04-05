package vortex;

import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

public class VortexMain {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String mode = args[0].trim().toLowerCase();
        switch (mode) {
            case "monitor" -> runMonitor();
            case "command" -> runCommandConsole();
            case "alerts" -> runAlertConsole();
            default -> printUsage();
        }
    }

    private static void runMonitor() throws Exception {
        NetSnapshotCollector collector = new NetSnapshotCollector();
        WideSignalCollector wideCollector = new WideSignalCollector();
        BlocklistManager blocklist = new BlocklistManager(VortexPaths.BLOCKLIST_FILE);
        RiskEngine riskEngine = new RiskEngine();
        LogBus logBus = new LogBus();

        try {
            MinimalFx.startPulse("monitor.start");
            System.out.println("VORTEX monitor started.");
            System.out.println("Wide signals: TCP risk + UDP/BT/Tor/VPN/proxy/mail/cookie-store heuristics → alerts log.");
            System.out.println("Watching established TCP connections every 2 seconds...");
            while (true) {
                if (isShutdownRequested()) {
                    MinimalFx.quitFold("monitor.quit ");
                    System.out.println("Shutdown signal received. Monitor stopping.");
                    return;
                }
                List<NetSnapshotCollector.RawConn> rows = collector.collectEstablishedTcp();
                for (NetSnapshotCollector.RawConn raw : rows) {
                    int recentHits = riskEngine.registerAndGetRecentHits(raw.remoteIp, raw.timestamp);
                    boolean blocked = blocklist.isBlocked(raw.remoteIp);
                    int risk = riskEngine.computeRisk(raw.remoteIp, raw.remotePort, recentHits, blocked);
                    int security = Math.max(0, 100 - risk);
                    ConnectionRecord record = new ConnectionRecord(
                            raw.timestamp,
                            raw.protocol,
                            raw.localIp,
                            raw.localPort,
                            raw.remoteIp,
                            raw.remotePort,
                            risk,
                            security,
                            recentHits
                    );
                    System.out.println(record.asConnectionLine());
                    logBus.appendConnection(record);

                    if (security < 40 && recentHits >= 3) {
                        String alert = String.format(
                                "%s | ALERT low-security repeated IPv4=%s security=%d hits60s=%d localPort=%d remotePort=%d",
                                Instant.now(),
                                raw.remoteIp,
                                security,
                                recentHits,
                                raw.localPort,
                                raw.remotePort
                        );
                        System.out.println(alert);
                        logBus.appendAlert(alert);
                    }
                }
                wideCollector.poll(logBus);
                Thread.sleep(2000);
            }
        } finally {
            MacTerminalSelfClose.maybeCloseOwnWindow("vortex · monitor");
        }
    }

    private static void runCommandConsole() throws Exception {
        BlocklistManager blocklist = new BlocklistManager(VortexPaths.BLOCKLIST_FILE);
        Files.createDirectories(VortexPaths.LOG_DIR);

        try {
            MinimalFx.startPulse("command.start");
            System.out.println("VORTEX command console");
            System.out.println("Commands: block, unblock, list, netscan, arpwatch, arpspoof, udpstress, hydra, hydra-check, help, quit");
            runCommandLoop(blocklist);
        } finally {
            MacTerminalSelfClose.maybeCloseOwnWindow("vortex · command");
        }
    }

    private static void runCommandLoop(BlocklistManager blocklist) throws Exception {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.print("vortex> ");
                String line = scanner.nextLine().trim();
                if (line.isEmpty()) {
                    continue;
                }
                String[] parts = line.split("\\s+");
                String cmd = parts[0].toLowerCase();
                try {
                    if ("block".equals(cmd) && parts.length == 2) {
                        System.out.println(blocklist.blockIp(parts[1]));
                    } else if ("unblock".equals(cmd) && parts.length == 2) {
                        System.out.println(blocklist.unblockIp(parts[1]));
                    } else if ("list".equals(cmd)) {
                        Set<String> ips = blocklist.listBlocked();
                        if (ips.isEmpty()) {
                            System.out.println("(empty)");
                        } else {
                            ips.forEach(System.out::println);
                        }
                    } else if ("netscan".equals(cmd)) {
                        if (!ArpToolkitRunner.toolkitPresent()) {
                            System.out.println("ARP toolkit missing. Expected: " + VortexPaths.ARP_TOOLKIT_DIR.toAbsolutePath());
                            continue;
                        }
                        String[] pyArgs = tailArgs(parts, 1);
                        if (pyArgs.length == 0) {
                            pyArgs = new String[]{"-m", "auto"};
                        }
                        System.out.println("[vortex] netscan (sudo + python3 ip_detection.py) — macOS 上 Scapy 通常需要管理员密码");
                        int code = ArpToolkitRunner.runNetScan(pyArgs);
                        System.out.println("[vortex] netscan exited with code " + code);
                    } else if ("arpwatch".equals(cmd)) {
                        if (!ArpToolkitRunner.toolkitPresent()) {
                            System.out.println("ARP toolkit missing. Expected: " + VortexPaths.ARP_TOOLKIT_DIR.toAbsolutePath());
                            continue;
                        }
                        String[] pyArgs = tailArgs(parts, 1);
                        System.out.println("[vortex] arpwatch (sudo + python3 arp_defense.py) — Ctrl+C 结束");
                        int code = ArpToolkitRunner.runArpDefense(pyArgs);
                        System.out.println("[vortex] arpwatch exited with code " + code);
                    } else if ("arpspoof".equals(cmd)) {
                        if (!ArpToolkitRunner.toolkitPresent()) {
                            System.out.println("ARP toolkit missing. Expected: " + VortexPaths.ARP_TOOLKIT_DIR.toAbsolutePath());
                            continue;
                        }
                        String[] pyArgs = tailArgs(parts, 1);
                        if (pyArgs.length == 0) {
                            System.out.println("Usage: arpspoof -t <victim_ip> [-g <gateway_ip>] [-i en0] [--interval N]");
                            System.out.println("  省略 -g 时，脚本会尝试从本机默认路由检测网关（macOS/Linux）。");
                            System.out.println("仅可在您有权测试的网络上使用；未经授权可能违法。");
                            continue;
                        }
                        System.out.println("[vortex] 警告: arpspoof 仅用于授权安全测试。将启动 sudo + python3 arp_attack.py");
                        int code = ArpToolkitRunner.runArpAttack(pyArgs);
                        System.out.println("[vortex] arpspoof exited with code " + code);
                    } else if ("udpstress".equals(cmd)) {
                        if (!LabToolkitRunner.ddosLabPresent()) {
                            System.out.println("Lab script missing. Expected: " + VortexPaths.DDOS_LAB_DIR.toAbsolutePath());
                            continue;
                        }
                        String[] pyArgs;
                        if (parts.length >= 2 && "--".equals(parts[1])) {
                            pyArgs = tailArgs(parts, 2);
                            if (pyArgs.length == 0) {
                                System.out.println("Usage: udpstress -- -t <ip> -p <port> [-d 秒] [--pps N]");
                                continue;
                            }
                        } else if (parts.length >= 3) {
                            if (parts.length >= 4) {
                                pyArgs = new String[]{"-t", parts[1], "-p", parts[2], "-d", parts[3]};
                            } else {
                                pyArgs = new String[]{"-t", parts[1], "-p", parts[2]};
                            }
                        } else {
                            System.out.println("Usage: udpstress <ip> <port> [duration_sec]");
                            System.out.println("   或: udpstress -- -t <ip> -p <port> [-d 10] [--pps 500]");
                            System.out.println("仅可对已书面授权的目标做压力测试；未授权使用违法。");
                            continue;
                        }
                        System.out.println("[vortex] udpstress → python3 ddos-attack.py（无 sudo，默认约 10s / 500pps 上限）");
                        int code = LabToolkitRunner.runDdosLab(pyArgs);
                        System.out.println("[vortex] udpstress exited with code " + code);
                    } else if ("hydra".equals(cmd)) {
                        String[] hydraArgs = tailArgs(parts, 1);
                        String hydraExe = HydraCompatibility.resolvedHydraExecutable();
                        if (hydraExe == null) {
                            System.out.println("[hydra] 未找到可执行文件：请在 thc-hydra-9.6 目录执行 make 生成 hydra，或安装到 PATH。");
                            continue;
                        }
                        List<String> hydraCmd = new ArrayList<>();
                        hydraCmd.add(hydraExe);
                        hydraCmd.addAll(Arrays.asList(hydraArgs));
                        System.out.println("[vortex] exec: " + String.join(" ", hydraCmd));
                        ProcessBuilder pb = new ProcessBuilder(hydraCmd);
                        if (HydraCompatibility.bundledHydraPresent()) {
                            pb.directory(VortexPaths.HYDRA_DIR.toFile());
                        }
                        pb.inheritIO();
                        int hcode = pb.start().waitFor();
                        System.out.println("[vortex] hydra exited with code " + hcode);
                    } else if ("hydra-check".equals(cmd)) {
                        System.out.println("[vortex] Hydra compatibility check only (no attack execution).");
                        System.out.print(HydraCompatibility.diagnosticReport());
                    } else if ("help".equals(cmd)) {
                        System.out.println("block <ip>   - add IPv4 to blocklist");
                        System.out.println("unblock <ip> - remove IPv4 from blocklist");
                        System.out.println("list         - show blocked IPv4 list");
                        System.out.println("netscan ...  - ip_detection.py (默认 -m auto)；参数原样传给 Python");
                        System.out.println("arpwatch ... - arp_defense.py；例: arpwatch -i en0 -g 192.168.1.1");
                        System.out.println("arpspoof ... - arp_attack.py；例: arpspoof -t 192.168.1.10 -g 192.168.1.1 -i en0");
                        System.out.println("  也可: arpspoof -t 192.168.1.10 （不写 -g 时尝试自动检测网关）");
                        System.out.println("udpstress <ip> <port> [秒] — DDos-Attack-master/ddos-attack.py（仅授权靶机）");
                        System.out.println("  或 udpstress -- -t IP -p PORT [-d 10] [--pps 500]");
                        System.out.println("hydra ...     - 优先 thc-hydra-9.6/hydra (make)，否则 PATH");
                        System.out.println("hydra-check   - 检查 hydra 9.6 是否安装/版本是否匹配（仅检测）");
                        System.out.println("  netscan/arp* 使用 sudo + scapy；udpstress 仅需 python3，无额外 pip");
                        System.out.println("  hydra 仅可在合法授权场景使用");
                        System.out.println("  环境变量 VORTEX_PYTHON 可指定 Python 路径");
                        System.out.println("quit         - exit command console");
                    } else if ("quit".equals(cmd) || "exit".equals(cmd)) {
                        requestShutdown();
                        System.out.println("Shutdown signal sent. Waiting monitor/alerts to stop...");
                        Thread.sleep(1500);
                        MinimalFx.quitFold("command.quit ");
                        System.out.println("Bye.");
                        return;
                    } else {
                        System.out.println("Unknown command. Type help.");
                    }
                } catch (IllegalArgumentException | IOException e) {
                    System.out.println("Error: " + e.getMessage());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    System.out.println("Interrupted.");
                }
            }
        }
    }

    private static void runAlertConsole() throws Exception {
        try {
            new LogBus();
            MinimalFx.startPulse("alerts.start ");
            AlertWatcher watcher = new AlertWatcher(VortexPaths.ALERT_LOG);
            watcher.run();
        } finally {
            MacTerminalSelfClose.maybeCloseOwnWindow("vortex · alerts");
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  java -cp out vortex.VortexMain monitor");
        System.out.println("  java -cp out vortex.VortexMain command");
        System.out.println("  java -cp out vortex.VortexMain alerts");
    }

    private static boolean isShutdownRequested() {
        return Files.exists(VortexPaths.SHUTDOWN_SIGNAL);
    }

    private static void requestShutdown() throws IOException {
        Files.createDirectories(VortexPaths.LOG_DIR);
        Files.writeString(VortexPaths.SHUTDOWN_SIGNAL, Instant.now().toString() + System.lineSeparator());
    }

    private static String[] tailArgs(String[] parts, int fromInclusive) {
        if (fromInclusive >= parts.length) {
            return new String[0];
        }
        return Arrays.copyOfRange(parts, fromInclusive, parts.length);
    }
}
