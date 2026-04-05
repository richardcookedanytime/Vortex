package vortex;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;

public class AlertWatcher {
    private final Path alertLog;

    public AlertWatcher(Path alertLog) {
        this.alertLog = alertLog;
    }

    public void run() throws IOException, InterruptedException {
        System.out.println("VORTEX alert console started.");
        System.out.println("Watching for low-security repeated IPv4 alerts...");

        try (RandomAccessFile raf = new RandomAccessFile(alertLog.toFile(), "r")) {
            long pointer = raf.length();
            while (true) {
                if (Files.exists(VortexPaths.SHUTDOWN_SIGNAL)) {
                    MinimalFx.quitFold("alerts.quit  ");
                    System.out.println("Shutdown signal received. Alert console stopping.");
                    return;
                }
                long len = raf.length();
                if (len < pointer) {
                    pointer = len;
                }
                if (len > pointer) {
                    raf.seek(pointer);
                    String line;
                    while ((line = raf.readLine()) != null) {
                        System.out.println(line);
                    }
                    pointer = raf.getFilePointer();
                }
                Thread.sleep(1000);
            }
        }
    }
}
