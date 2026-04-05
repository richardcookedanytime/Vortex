package vortex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class BlocklistManager {
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$"
    );

    private final Path blocklistPath;

    public BlocklistManager(Path blocklistPath) {
        this.blocklistPath = blocklistPath;
    }

    public synchronized Set<String> listBlocked() throws IOException {
        ensureFile();
        List<String> lines = Files.readAllLines(blocklistPath, StandardCharsets.UTF_8);
        Set<String> blocked = new LinkedHashSet<>();
        for (String line : lines) {
            String ip = line.trim();
            if (!ip.isEmpty()) {
                blocked.add(ip);
            }
        }
        return blocked;
    }

    public synchronized boolean isBlocked(String ip) throws IOException {
        return listBlocked().contains(ip);
    }

    public synchronized String blockIp(String ip) throws IOException, InterruptedException {
        validateIp(ip);
        Set<String> blocked = listBlocked();
        if (blocked.contains(ip)) {
            return "IP already in blocklist: " + ip;
        }
        blocked.add(ip);
        Files.write(blocklistPath, blocked, StandardCharsets.UTF_8);
        String pfResult = syncPf(ip, true);
        return "Blocked IP: " + ip + "\n" + pfResult;
    }

    public synchronized String unblockIp(String ip) throws IOException, InterruptedException {
        validateIp(ip);
        Set<String> blocked = listBlocked();
        if (!blocked.remove(ip)) {
            return "IP not found in blocklist: " + ip;
        }
        Files.write(blocklistPath, blocked, StandardCharsets.UTF_8);
        String pfResult = syncPf(ip, false);
        return "Unblocked IP: " + ip + "\n" + pfResult;
    }

    private void ensureFile() throws IOException {
        if (!Files.exists(blocklistPath)) {
            Files.createFile(blocklistPath);
        }
    }

    private static void validateIp(String ip) {
        if (!IPV4_PATTERN.matcher(ip).matches()) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }
    }

    private static String syncPf(String ip, boolean add) throws IOException, InterruptedException {
        String action = add ? "add" : "delete";
        Process process = new ProcessBuilder("sh", "-c",
                "sudo pfctl -t vortex_blocklist -T " + action + " " + ip).start();
        int exitCode = process.waitFor();
        if (exitCode == 0) {
            return "pfctl sync success.";
        }
        return "pfctl sync skipped/failed (need sudo and table setup). You can still use local blocklist.";
    }
}
