package vortex;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * 从 vortex 命令行启动 {@code arpSproofing-main} 下的 Python 脚本（macOS 上 Scapy 通常需 root）。
 */
public final class ArpToolkitRunner {

    private ArpToolkitRunner() {
    }

    public static boolean toolkitPresent() {
        Path dir = VortexPaths.ARP_TOOLKIT_DIR;
        return Files.isDirectory(dir)
                && Files.isRegularFile(dir.resolve("ip_detection.py"))
                && Files.isRegularFile(dir.resolve("arp_defense.py"))
                && Files.isRegularFile(dir.resolve("arp_attack.py"));
    }

    /**
     * @param script 例如 {@code ip_detection.py}
     * @param args   传给脚本的参数（不含脚本名）
     * @return 进程退出码
     */
    public static int runWithSudo(String script, String[] args) throws IOException, InterruptedException {
        if (!toolkitPresent()) {
            throw new IOException(
                    "ARP toolkit not found at: " + VortexPaths.ARP_TOOLKIT_DIR.toAbsolutePath()
            );
        }
        Path scriptPath = VortexPaths.ARP_TOOLKIT_DIR.resolve(script);
        if (!Files.isRegularFile(scriptPath)) {
            throw new IOException("Script missing: " + scriptPath.toAbsolutePath());
        }

        String python = Optional.ofNullable(System.getenv("VORTEX_PYTHON")).filter(s -> !s.isBlank()).orElse("python3");

        List<String> cmd = new ArrayList<>();
        cmd.add("sudo");
        cmd.add("-E");
        cmd.add(python);
        cmd.add(scriptPath.toAbsolutePath().toString());
        if (args != null && args.length > 0) {
            cmd.addAll(Arrays.asList(args));
        }

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(VortexPaths.ARP_TOOLKIT_DIR.toFile());
        pb.inheritIO();

        System.out.println("[vortex] exec: " + String.join(" ", cmd));
        Process p = pb.start();
        return p.waitFor();
    }

    public static int runNetScan(String[] args) throws IOException, InterruptedException {
        return runWithSudo("ip_detection.py", args);
    }

    public static int runArpDefense(String[] args) throws IOException, InterruptedException {
        return runWithSudo("arp_defense.py", args);
    }

    public static int runArpAttack(String[] args) throws IOException, InterruptedException {
        return runWithSudo("arp_attack.py", args);
    }
}
