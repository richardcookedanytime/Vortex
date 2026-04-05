package vortex;

import java.time.Instant;

public class ConnectionRecord {
    private final Instant timestamp;
    private final String protocol;
    private final String localIp;
    private final int localPort;
    private final String remoteIp;
    private final int remotePort;
    private final int riskScore;
    private final int securityCoefficient;
    private final int recentHits;

    public ConnectionRecord(
            Instant timestamp,
            String protocol,
            String localIp,
            int localPort,
            String remoteIp,
            int remotePort,
            int riskScore,
            int securityCoefficient,
            int recentHits
    ) {
        this.timestamp = timestamp;
        this.protocol = protocol;
        this.localIp = localIp;
        this.localPort = localPort;
        this.remoteIp = remoteIp;
        this.remotePort = remotePort;
        this.riskScore = riskScore;
        this.securityCoefficient = securityCoefficient;
        this.recentHits = recentHits;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getLocalIp() {
        return localIp;
    }

    public int getLocalPort() {
        return localPort;
    }

    public String getRemoteIp() {
        return remoteIp;
    }

    public int getRemotePort() {
        return remotePort;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public int getSecurityCoefficient() {
        return securityCoefficient;
    }

    public int getRecentHits() {
        return recentHits;
    }

    public String asConnectionLine() {
        return String.format(
                "%s | %s | local=%s:%d remote=%s:%d | risk=%d security=%d hits60s=%d",
                timestamp,
                protocol,
                localIp,
                localPort,
                remoteIp,
                remotePort,
                riskScore,
                securityCoefficient,
                recentHits
        );
    }
}
