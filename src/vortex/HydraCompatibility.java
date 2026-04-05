package vortex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Hydra：优先使用项目内 {@code thc-hydra-9.6/hydra}（{@code make} 产物），否则回退到 PATH 中的 {@code hydra}。
 */
public final class HydraCompatibility {

    private HydraCompatibility() {
    }

    /** 是否存在本地编译的 {@code thc-hydra-9.6/hydra} 文件。 */
    public static boolean bundledHydraPresent() {
        Path p = VortexPaths.HYDRA_DIR.resolve("hydra");
        return Files.isRegularFile(p);
    }

    /**
     * 启动 Hydra 时应使用的可执行文件绝对路径；优先 bundled，否则 PATH；均无时返回 {@code null}。
     */
    public static String resolvedHydraExecutable() {
        Path bundled = VortexPaths.HYDRA_DIR.resolve("hydra");
        if (Files.isRegularFile(bundled)) {
            return bundled.toAbsolutePath().toString();
        }
        return resolveHydraFromPath();
    }

    public static String diagnosticReport() {
        StringBuilder sb = new StringBuilder();
        Path hydraDir = VortexPaths.HYDRA_DIR;
        sb.append("[hydra] directory: ").append(hydraDir.toAbsolutePath()).append(System.lineSeparator());
        sb.append("[hydra] source-present: ").append(Files.isDirectory(hydraDir) ? "yes" : "no").append(System.lineSeparator());
        sb.append("[hydra] bundled-binary: ").append(bundledHydraPresent() ? "yes (thc-hydra-9.6/hydra)" : "no (run: cd thc-hydra-9.6 && make)")
                .append(System.lineSeparator());

        String binaryPath = resolvedHydraExecutable();
        if (binaryPath == null) {
            sb.append("[hydra] binary: not found (no thc-hydra-9.6/hydra file and no hydra in PATH)")
                    .append(System.lineSeparator());
            sb.append("[hydra] action: cd thc-hydra-9.6 && make   OR   brew install hydra")
                    .append(System.lineSeparator());
            return sb.toString();
        }

        sb.append("[hydra] binary: ").append(binaryPath).append(System.lineSeparator());
        sb.append("[hydra] source: ").append(bundledHydraPresent() ? "bundled" : "PATH").append(System.lineSeparator());
        String ver = readHydraVersion(binaryPath);
        if (ver == null || ver.isBlank()) {
            sb.append("[hydra] version: unknown").append(System.lineSeparator());
            return sb.toString();
        }
        sb.append("[hydra] version: ").append(ver).append(System.lineSeparator());
        if (ver.contains("v9.6") || ver.contains(" 9.6")) {
            sb.append("[hydra] compatibility: OK (9.6 detected)").append(System.lineSeparator());
        } else {
            sb.append("[hydra] compatibility: partial (expected 9.6)").append(System.lineSeparator());
        }
        return sb.toString();
    }

    private static String resolveHydraFromPath() {
        try {
            Process p = new ProcessBuilder("sh", "-c", "command -v hydra").start();
            int code = p.waitFor();
            if (code != 0) {
                return null;
            }
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line = br.readLine();
                return line == null || line.isBlank() ? null : line.trim();
            }
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String readHydraVersion(String hydraBin) {
        try {
            Process p = new ProcessBuilder(hydraBin, "-h").start();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    String low = line.toLowerCase();
                    if (low.contains("hydra") && low.contains("v")) {
                        return line.trim();
                    }
                }
            }
            p.waitFor();
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } catch (IOException ignored) {
        }
        return null;
    }
}
