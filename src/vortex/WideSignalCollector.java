package vortex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 广域信号采集（macOS）：蓝牙、UDP、Tor 监听、VPN 接口、系统代理、邮件客户端、浏览器 Cookie 存储变更等。
 * 多数为<strong>启发式</strong>（mtime、进程、端口），不读取 cookie 内容、不解密流量。
 */
public final class WideSignalCollector {

    private static final int BLUETOOTH_EVERY_TICKS = 15;
    private static final int PROXY_VPN_EVERY_TICKS = 5;

    private int tick;
    private String lastBluetoothDigest;
    private Boolean lastTorListen;
    private String lastVpnDigest;
    private String lastProxyDigest;
    private Boolean lastMailRunning;
    private Integer lastUdpWildcardFreeLines;
    private final Map<String, Long> cookieMtimes = new HashMap<>();
    private final Map<String, Instant> cookieLastAlert = new HashMap<>();
    private static final Duration COOKIE_ALERT_COOLDOWN = Duration.ofSeconds(90);

    public List<String> poll(LogBus logBus) throws IOException, InterruptedException {
        tick++;
        List<String> alerts = new ArrayList<>();
        Instant now = Instant.now();

        alerts.addAll(pollUdp(now));
        if (tick % PROXY_VPN_EVERY_TICKS == 0) {
            alerts.addAll(pollVpn(now));
            alerts.addAll(pollSystemProxy(now));
        }
        alerts.addAll(pollTor(now));
        alerts.addAll(pollMailClient(now));
        alerts.addAll(pollCookieStores(now));
        if (tick % BLUETOOTH_EVERY_TICKS == 0) {
            alerts.addAll(pollBluetooth(now));
        }

        for (String line : alerts) {
            System.out.println(line);
            logBus.appendAlert(line);
        }
        return alerts;
    }

    private List<String> pollUdp(Instant now) throws IOException, InterruptedException {
        List<String> out = new ArrayList<>();
        String text = runShell("netstat -anv -p udp", 8_000);
        int flows = 0;
        for (String line : text.split("\n")) {
            String t = line.trim();
            if (!t.startsWith("udp4") && !t.startsWith("udp6")) {
                continue;
            }
            if (t.contains("*.*")) {
                continue;
            }
            flows++;
        }
        if (lastUdpWildcardFreeLines != null) {
            int delta = Math.abs(flows - lastUdpWildcardFreeLines);
            if (delta < 6) {
                return out;
            }
        }
        lastUdpWildcardFreeLines = flows;
        if (flows > 0) {
            out.add(String.format(
                    Locale.ROOT,
                    "%s | ALERT [NET-UDP] udp_socket_lines_no_wildcard=%d (heuristic, mDNS等常不含此行)",
                    now,
                    flows
            ));
        }
        return out;
    }

    private List<String> pollBluetooth(Instant now) throws IOException, InterruptedException {
        List<String> out = new ArrayList<>();
        String text = runShell("system_profiler SPBluetoothDataType", 25_000);
        String digest = sha256Short(text);
        if (Objects.equals(digest, lastBluetoothDigest)) {
            return out;
        }
        lastBluetoothDigest = digest;
        int connected = 0;
        for (String line : text.split("\n")) {
            if (line.toLowerCase(Locale.ROOT).contains("connected: yes")) {
                connected++;
            }
        }
        out.add(String.format(
                Locale.ROOT,
                "%s | ALERT [BT] bluetooth_profile_updated connected_yes_lines=%d",
                now,
                connected
        ));
        return out;
    }

    private List<String> pollTor(Instant now) throws IOException, InterruptedException {
        List<String> out = new ArrayList<>();
        String text = runShell("lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null", 6_000);
        boolean tor = text.contains(":9050") || text.contains(":9150");
        if (lastTorListen != null && lastTorListen == tor) {
            return out;
        }
        lastTorListen = tor;
        if (tor) {
            out.add(String.format(
                    Locale.ROOT,
                    "%s | ALERT [TOR] socks_listener_detected ports 9050/9150 (local service present)",
                    now
            ));
        }
        return out;
    }

    private List<String> pollVpn(Instant now) throws IOException, InterruptedException {
        List<String> out = new ArrayList<>();
        String text = runShell("ifconfig", 5_000);
        String digest = sha256Short(text);
        if (Objects.equals(digest, lastVpnDigest)) {
            return out;
        }
        lastVpnDigest = digest;
        int utun = 0;
        int ipsec = 0;
        for (String line : text.split("\n")) {
            String l = line.trim().toLowerCase(Locale.ROOT);
            if (l.startsWith("utun")) {
                utun++;
            }
            if (l.contains("ipsec")) {
                ipsec++;
            }
        }
        boolean awdl = text.contains("awdl0:");
        if (utun > 0 || ipsec > 0 || awdl) {
            out.add(String.format(
                    Locale.ROOT,
                    "%s | ALERT [VPN/L2] utun=%d ipsec_mentions=%d awdl0=%s",
                    now,
                    utun,
                    ipsec,
                    awdl
            ));
        }
        return out;
    }

    private static final Pattern SCUTIL_HTTP_ENABLE = Pattern.compile("HTTPEnable\\s*:\\s*1");
    private static final Pattern SCUTIL_SOCKS_ENABLE = Pattern.compile("SOCKSEnable\\s*:\\s*1");

    private List<String> pollSystemProxy(Instant now) throws IOException, InterruptedException {
        List<String> out = new ArrayList<>();
        String text = runShell("scutil --proxy", 4_000);
        String digest = sha256Short(text);
        if (Objects.equals(digest, lastProxyDigest)) {
            return out;
        }
        lastProxyDigest = digest;
        boolean http = SCUTIL_HTTP_ENABLE.matcher(text).find();
        boolean socks = SCUTIL_SOCKS_ENABLE.matcher(text).find();
        if (http || socks) {
            out.add(String.format(
                    Locale.ROOT,
                    "%s | ALERT [PROXY] system_proxy http=%s socks=%s (scutil)",
                    now,
                    http,
                    socks
            ));
        }
        return out;
    }

    private List<String> pollMailClient(Instant now) throws IOException, InterruptedException {
        List<String> out = new ArrayList<>();
        boolean mail = exitCode("pgrep", "-x", "Mail") == 0;
        boolean outlook = exitCode("pgrep", "-x", "Microsoft Outlook") == 0;
        boolean active = mail || outlook;
        if (lastMailRunning != null && lastMailRunning == active) {
            return out;
        }
        lastMailRunning = active;
        if (active) {
            out.add(String.format(
                    Locale.ROOT,
                    "%s | ALERT [MAIL] client_process mail.app=%s outlook=%s",
                    now,
                    mail,
                    outlook
            ));
        }
        return out;
    }

    private List<String> pollCookieStores(Instant now) {
        List<String> out = new ArrayList<>();
        Path home = Path.of(System.getProperty("user.home", "."));
        List<Path> watch = new ArrayList<>();
        watch.add(home.resolve("Library/Application Support/Google/Chrome/Default/Cookies"));
        watch.add(home.resolve("Library/Application Support/Microsoft Edge/Default/Cookies"));
        watch.add(home.resolve(
                "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"));
        watch.add(home.resolve("Library/Cookies/Cookies.binarycookies"));
        Path ffProfiles = home.resolve("Library/Application Support/Firefox/Profiles");
        if (Files.isDirectory(ffProfiles)) {
            try (var stream = Files.newDirectoryStream(ffProfiles, "*.default-release")) {
                for (Path dir : stream) {
                    watch.add(dir.resolve("cookies.sqlite"));
                }
            } catch (IOException ignored) {
            }
        }
        for (Path p : watch) {
            try {
                if (!Files.isRegularFile(p)) {
                    continue;
                }
                long m = Files.getLastModifiedTime(p).toMillis();
                String key = p.toString();
                Long prev = cookieMtimes.put(key, m);
                if (prev != null && prev != m) {
                    Instant last = cookieLastAlert.get(key);
                    if (last == null || Duration.between(last, now).compareTo(COOKIE_ALERT_COOLDOWN) >= 0) {
                        cookieLastAlert.put(key, now);
                        out.add(String.format(
                                Locale.ROOT,
                                "%s | ALERT [COOKIE_STORE] file_mtime_changed path=%s",
                                now,
                                p
                        ));
                    }
                }
            } catch (IOException ignored) {
            }
        }
        return out;
    }

    private static int exitCode(String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).start();
        return p.waitFor();
    }

    private static String runShell(String script, int waitMs) throws IOException, InterruptedException {
        Process p = new ProcessBuilder("sh", "-c", script).start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            long deadline = System.currentTimeMillis() + waitMs;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
                if (System.currentTimeMillis() > deadline) {
                    p.destroyForcibly();
                    break;
                }
            }
        }
        p.waitFor();
        return sb.toString();
    }

    private static String sha256Short(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                hex.append(String.format(Locale.ROOT, "%02x", d[i]));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(s.length());
        }
    }
}
