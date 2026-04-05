package vortex;

import java.util.Locale;
import java.util.Objects;

/**
 * 在 macOS 上退出 vortex 时关闭当前「终端」窗口（需与 {@code start_vortex.sh} 设置的标题一致）。
 * 仅当设置环境变量 {@code VORTEX_AUTO_CLOSE=1} 或系统属性 {@code -Dvortex.autoClose=true} 时生效，
 * 避免手动在终端里跑 java 时被误关窗口。
 */
public final class MacTerminalSelfClose {

    private MacTerminalSelfClose() {
    }

    public static boolean isAutoCloseEnabled() {
        if ("1".equals(System.getenv("VORTEX_AUTO_CLOSE"))) {
            return true;
        }
        String p = System.getProperty("vortex.autoClose");
        return "true".equalsIgnoreCase(p) || "1".equals(p);
    }

    /**
     * @param titleSubstring 与 Terminal 窗口标题匹配的子串，例如 {@code vortex · monitor}
     */
    public static void maybeCloseOwnWindow(String titleSubstring) {
        if (!isAutoCloseEnabled()) {
            return;
        }
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("mac")) {
            return;
        }
        String marker = Objects.requireNonNullElse(titleSubstring, "").trim();
        if (marker.isEmpty()) {
            return;
        }
        String safe = escapeAppleScriptString(marker);
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "osascript",
                    "-e", "tell application \"Terminal\"",
                    "-e", "  try",
                    "-e", "    close (first window whose name contains \"" + safe + "\") saving no",
                    "-e", "  end try",
                    "-e", "end tell"
            );
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            p.waitFor();
        } catch (Exception ignored) {
            // 无权限或未找到窗口时静默忽略
        }
    }

    private static String escapeAppleScriptString(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
