#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

bash "$PROJECT_DIR/build.sh"
rm -f "$PROJECT_DIR/logs/vortex.shutdown"

# 三个窗口尺寸（列 × 行），与 Terminal 标题便于辨认
MON_COLS=99
MON_ROWS=27
ALT_COLS=101
ALT_ROWS=26
CMD_COLS=203
CMD_ROWS=24

osascript <<EOF
tell application "Finder"
	set db to bounds of window of desktop
end tell
set screenLeftEdge to item 1 of db
set screenTopEdge to item 2 of db
set screenRight to item 3 of db
set screenBottom to item 4 of db
set margin to 36
set gap to 10
-- 主屏顶部留出菜单栏区域
set topY to screenTopEdge + margin + 28

tell application "Terminal"
	activate

	-- 1) monitor — ${MON_COLS}×${MON_ROWS}
	do script "export VORTEX_AUTO_CLOSE=1; cd \"$PROJECT_DIR\" && java -cp out vortex.VortexMain monitor"
	delay 0.45
	tell front window
		set custom title to "vortex · monitor (${MON_COLS}×${MON_ROWS})"
		tell selected tab
			set number of columns to ${MON_COLS}
			set number of rows to ${MON_ROWS}
		end tell
	end tell
	delay 0.4
	tell front window
		set b to bounds
		set winW to (item 3 of b) - (item 1 of b)
		set winH to (item 4 of b) - (item 2 of b)
		set monLeft to screenLeftEdge + margin
		set monTop to topY
		set bounds to {monLeft, monTop, monLeft + winW, monTop + winH}
	end tell
	set monB to bounds of front window

	-- 2) alerts — ${ALT_COLS}×${ALT_ROWS}
	do script "export VORTEX_AUTO_CLOSE=1; cd \"$PROJECT_DIR\" && java -cp out vortex.VortexMain alerts"
	delay 0.45
	tell front window
		set custom title to "vortex · alerts (${ALT_COLS}×${ALT_ROWS})"
		tell selected tab
			set number of columns to ${ALT_COLS}
			set number of rows to ${ALT_ROWS}
		end tell
	end tell
	delay 0.4
	tell front window
		set b to bounds
		set winW to (item 3 of b) - (item 1 of b)
		set winH to (item 4 of b) - (item 2 of b)
		set alLeft to (item 3 of monB) + gap
		set alTop to (item 2 of monB)
		set alRight to alLeft + winW
		if alRight > screenRight - margin then set alRight to screenRight - margin
		set bounds to {alLeft, alTop, alRight, alTop + winH}
	end tell
	set alertB to bounds of front window

	-- 3) command — ${CMD_COLS}×${CMD_ROWS}
	do script "export VORTEX_AUTO_CLOSE=1; cd \"$PROJECT_DIR\" && java -cp out vortex.VortexMain command"
	delay 0.45
	tell front window
		set custom title to "vortex · command (${CMD_COLS}×${CMD_ROWS})"
		tell selected tab
			set number of columns to ${CMD_COLS}
			set number of rows to ${CMD_ROWS}
		end tell
	end tell
	delay 0.4
	tell front window
		set b to bounds
		set winW to (item 3 of b) - (item 1 of b)
		set winH to (item 4 of b) - (item 2 of b)
		if (item 4 of monB) > (item 4 of alertB) then
			set cmdTop to (item 4 of monB) + gap
		else
			set cmdTop to (item 4 of alertB) + gap
		end if
		set cmdLeft to screenLeftEdge + margin
		set cmdRight to cmdLeft + winW
		if cmdRight > screenRight - margin then set cmdRight to screenRight - margin
		set cmdBottom to cmdTop + winH
		if cmdBottom > screenBottom - margin then set cmdBottom to screenBottom - margin
		set bounds to {cmdLeft, cmdTop, cmdRight, cmdBottom}
	end tell
end tell
EOF

echo "VORTEX started: monitor ${MON_COLS}×${MON_ROWS}, alerts ${ALT_COLS}×${ALT_ROWS}, command ${CMD_COLS}×${CMD_ROWS}."
