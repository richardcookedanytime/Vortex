package vortex;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class RiskEngine {
    private static final Set<Integer> SUSPICIOUS_PORTS = new HashSet<>();
    private final Map<String, Deque<Instant>> perIpHits = new HashMap<>();

    static {
        SUSPICIOUS_PORTS.add(22);
        SUSPICIOUS_PORTS.add(23);
        SUSPICIOUS_PORTS.add(445);
        SUSPICIOUS_PORTS.add(3389);
        SUSPICIOUS_PORTS.add(5900);
    }

    public synchronized int registerAndGetRecentHits(String ip, Instant now) {
        Deque<Instant> hits = perIpHits.computeIfAbsent(ip, ignored -> new ArrayDeque<>());
        hits.addLast(now);
        trimOld(hits, now);
        return hits.size();
    }

    public int computeRisk(String remoteIp, int remotePort, int recentHits, boolean blocked) {
        int score = 5;
        if (!isPrivateOrLoopback(remoteIp)) {
            score += 20;
        }
        if (SUSPICIOUS_PORTS.contains(remotePort)) {
            score += 20;
        }
        if (recentHits >= 5) {
            score += 20;
        }
        if (recentHits >= 10) {
            score += 15;
        }
        if (blocked) {
            score += 30;
        }
        return Math.min(score, 100);
    }

    private static void trimOld(Deque<Instant> hits, Instant now) {
        while (!hits.isEmpty()) {
            Instant first = hits.peekFirst();
            if (Duration.between(first, now).getSeconds() > 60) {
                hits.removeFirst();
            } else {
                break;
            }
        }
    }

    private static boolean isPrivateOrLoopback(String ip) {
        return ip.startsWith("10.")
                || ip.startsWith("192.168.")
                || ip.startsWith("172.16.")
                || ip.startsWith("172.17.")
                || ip.startsWith("172.18.")
                || ip.startsWith("172.19.")
                || ip.startsWith("172.2")
                || ip.startsWith("172.30.")
                || ip.startsWith("172.31.")
                || ip.startsWith("127.")
                || ip.equals("0.0.0.0");
    }
}
