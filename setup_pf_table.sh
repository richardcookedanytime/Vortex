#!/usr/bin/env bash
set -euo pipefail

echo "Preparing pf table: vortex_blocklist"
echo "This requires sudo password."

sudo sh -c 'printf "\ntable <vortex_blocklist> persist\nblock drop from <vortex_blocklist> to any\n" >> /etc/pf.conf'
sudo pfctl -f /etc/pf.conf
sudo pfctl -e || true

echo "pf table ready. You can now use block/unblock in vortex command console."
