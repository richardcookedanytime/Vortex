package vortex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class NetSnapshotCollector {

    public List<RawConn> collectEstablishedTcp() throws IOException {
        Process process = new ProcessBuilder("sh", "-c", "netstat -anv -p tcp").start();
        List<RawConn> result = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                RawConn parsed = parseLine(line);
                if (parsed != null) {
                    result.add(parsed);
                }
            }
        }
        return result;
    }

    private static RawConn parseLine(String line) {
        String trimmed = line.trim();
        if (!(trimmed.startsWith("tcp4") || trimmed.startsWith("tcp6"))) {
            return null;
        }
        if (!trimmed.contains("ESTABLISHED")) {
            return null;
        }
        String[] parts = trimmed.split("\\s+");
        if (parts.length < 6) {
            return null;
        }
        String local = parts[3];
        String remote = parts[4];
        Endpoint localEp = parseEndpoint(local);
        Endpoint remoteEp = parseEndpoint(remote);
        if (localEp == null || remoteEp == null || remoteEp.ip.contains(":")) {
            return null;
        }
        return new RawConn(Instant.now(), parts[0], localEp.ip, localEp.port, remoteEp.ip, remoteEp.port);
    }

    private static Endpoint parseEndpoint(String text) {
        int idx = text.lastIndexOf('.');
        if (idx <= 0 || idx == text.length() - 1) {
            return null;
        }
        String ip = text.substring(0, idx);
        String portStr = text.substring(idx + 1);
        try {
            int port = Integer.parseInt(portStr);
            return new Endpoint(ip, port);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    public static class RawConn {
        final Instant timestamp;
        final String protocol;
        final String localIp;
        final int localPort;
        final String remoteIp;
        final int remotePort;

        RawConn(Instant timestamp, String protocol, String localIp, int localPort, String remoteIp, int remotePort) {
            this.timestamp = timestamp;
            this.protocol = protocol;
            this.localIp = localIp;
            this.localPort = localPort;
            this.remoteIp = remoteIp;
            this.remotePort = remotePort;
        }
    }

    private static class Endpoint {
        final String ip;
        final int port;

        Endpoint(String ip, int port) {
            this.ip = ip;
            this.port = port;
        }
    }
}
