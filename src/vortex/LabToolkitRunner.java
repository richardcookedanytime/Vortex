package vortex;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * 启动 {@code DDos-Attack-master} 下经改造的实验脚本（Python 3，非交互）。
 * 不需要 sudo；使用者须自行确保对目标拥有合法授权。
 */
public final class LabToolkitRunner {

    private LabToolkitRunner() {
    }

    public static boolean ddosLabPresent() {
        Path dir = VortexPaths.DDOS_LAB_DIR;
        return Files.isDirectory(dir) && Files.isRegularFile(dir.resolve("ddos-attack.py"));
    }

    /**
     * @param args 传给 {@code ddos-attack.py} 的参数（完整，含 -t/-p 等）
     */
    public static int runDdosLab(String[] args) throws IOException, InterruptedException {
        if (!ddosLabPresent()) {
            throw new IOException("Lab toolkit not found at: " + VortexPaths.DDOS_LAB_DIR.toAbsolutePath());
        }
        Path script = VortexPaths.DDOS_LAB_DIR.resolve("ddos-attack.py");
        String python = Optional.ofNullable(System.getenv("VORTEX_PYTHON")).filter(s -> !s.isBlank()).orElse("python3");

        List<String> cmd = new ArrayList<>();
        cmd.add(python);
        cmd.add(script.toAbsolutePath().toString());
        if (args != null && args.length > 0) {
            cmd.addAll(Arrays.asList(args));
        }

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(VortexPaths.DDOS_LAB_DIR.toFile());
        pb.inheritIO();
        System.out.println("[vortex] exec: " + String.join(" ", cmd));
        return pb.start().waitFor();
    }
}
