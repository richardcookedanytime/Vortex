package vortex;

/**
 * Minimal terminal "hacker" vibe: dim green, single-line progress, hex tail.
 * ANSI is used; plain terminals usually ignore or render it fine.
 */
public final class MinimalFx {

    private static final String RESET = "\u001b[0m";
    private static final String DIM_GREEN = "\u001b[2;32m";

    private MinimalFx() {
    }

    public static void startPulse(String label) throws InterruptedException {
        String tag = label.trim();
        String[] phases = {"RX", "DEC", "KEY", "ACK"};
        int steps = 16;
        for (int i = 1; i <= steps; i++) {
            String phase = phases[Math.min((i * phases.length - 1) / steps, phases.length - 1)];
            String bar = bar(i, steps, 18);
            String tail = hexTail(i);
            line(tag, bar, phase, tail);
            Thread.sleep(42);
        }
        lineDone(tag, bar(steps, steps, 18), "LINK_UP", "0x" + Integer.toHexString(0xfeed & 0xffff));
    }

    public static void quitFold(String label) throws InterruptedException {
        String tag = label.trim();
        String[] phases = {"HALT", "FLUSH", "DROP", "EOF"};
        int steps = 14;
        for (int i = steps; i >= 0; i--) {
            String phase = phases[Math.min((steps - i) * phases.length / (steps + 1), phases.length - 1)];
            String bar = bar(i, steps, 18);
            String tail = hexTail(steps - i + 7);
            line(tag, bar, phase, tail);
            Thread.sleep(48);
        }
        lineDone(tag, bar(0, steps, 18), "SESSION_END", "0x0000");
    }

    private static void line(String tag, String bar, String phase, String tail) {
        String left = "> vortex::" + tag;
        System.out.print("\r" + DIM_GREEN + padRight(left, 28) + " |" + bar + "| " + padRight(phase, 7) + " " + tail + RESET);
    }

    private static void lineDone(String tag, String bar, String phase, String tail) {
        String left = "> vortex::" + tag;
        System.out.print("\r" + DIM_GREEN + padRight(left, 28) + " |" + bar + "| " + padRight(phase, 11) + " " + tail + RESET + "\n");
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) {
            return s.substring(0, width);
        }
        return s + " ".repeat(width - s.length());
    }

    private static String bar(int filled, int total, int width) {
        int n = total <= 0 ? 0 : (filled * width) / total;
        n = Math.max(0, Math.min(width, n));
        StringBuilder sb = new StringBuilder(width);
        for (int i = 0; i < width; i++) {
            sb.append(i < n ? '#' : '.');
        }
        return sb.toString();
    }

    private static String hexTail(int salt) {
        int a = (salt * 0x9e37) & 0xffff;
        int b = (salt * 0x517c) & 0xffff;
        return "0x" + String.format("%04x:%04x", a, b);
    }
}
