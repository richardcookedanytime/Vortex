package vortex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class LogBus {
    public LogBus() throws IOException {
        Files.createDirectories(VortexPaths.LOG_DIR);
        if (!Files.exists(VortexPaths.CONNECTION_LOG)) {
            Files.createFile(VortexPaths.CONNECTION_LOG);
        }
        if (!Files.exists(VortexPaths.ALERT_LOG)) {
            Files.createFile(VortexPaths.ALERT_LOG);
        }
    }

    public synchronized void appendConnection(ConnectionRecord record) throws IOException {
        appendLine(VortexPaths.CONNECTION_LOG, record.asConnectionLine());
    }

    public synchronized void appendAlert(String alertLine) throws IOException {
        appendLine(VortexPaths.ALERT_LOG, alertLine);
    }

    private void appendLine(Path path, String line) throws IOException {
        Files.writeString(
                path,
                line + System.lineSeparator(),
                StandardCharsets.UTF_8,
                StandardOpenOption.APPEND
        );
    }
}
