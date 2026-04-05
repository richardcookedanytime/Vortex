#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP 压力测试脚本（仅用于你已获书面授权的目标：自有服务器 / 渗透实验环境 / 课程靶机）。
禁止对未授权目标使用；可能违法并导致账号与法律责任。
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(
        description="UDP lab stress tool (authorized targets only)"
    )
    parser.add_argument("-t", "--target", required=True, help="目标 IPv4 / 主机名")
    parser.add_argument("-p", "--port", type=int, required=True, help="目标 UDP 端口 (1-65535)")
    parser.add_argument(
        "-d",
        "--duration",
        type=float,
        default=10.0,
        help="持续时间（秒），默认 10，最大 600",
    )
    parser.add_argument(
        "--pps",
        type=int,
        default=500,
        help="每秒最大报文数（安全上限，默认 500）",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        print("[!] 端口必须在 1-65535 之间", file=sys.stderr)
        return 2
    if args.duration <= 0 or args.duration > 600:
        print("[!] duration 须在 (0, 600] 秒内", file=sys.stderr)
        return 2
    if args.pps < 1 or args.pps > 50_000:
        print("[!] pps 建议在 1-50000 之间", file=sys.stderr)
        return 2

    print("=" * 60)
    print("警告：仅对你拥有合法授权的系统使用。未授权使用可能构成犯罪。")
    print("=" * 60)
    print(f"目标: {args.target}:{args.port}  时长: {args.duration}s  上限: {args.pps} pps")
    print("3 秒后开始… Ctrl+C 可中止")
    time.sleep(3)

    try:
        addr_info = socket.getaddrinfo(
            args.target, args.port, socket.AF_INET, socket.SOCK_DGRAM
        )
    except socket.gaierror as e:
        print(f"[!] 无法解析目标: {e}", file=sys.stderr)
        return 1

    sockaddr = addr_info[0][4]
    payload = os.urandom(512)  # 小包；兼容 Python 3.8+

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        end = time.monotonic() + args.duration
        interval = 1.0 / args.pps
        next_send = time.monotonic()
        sent = 0
        while time.monotonic() < end:
            now = time.monotonic()
            if now < next_send:
                time.sleep(min(next_send - now, 0.05))
                continue
            sock.sendto(payload, sockaddr)
            sent += 1
            next_send += interval
            if sent % max(1, args.pps) == 0:
                print(f"[*] 已发送约 {sent} 个 UDP 报文…", end="\r", flush=True)
        print(f"\n[+] 结束，共发送约 {sent} 个报文。")
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        return 130
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
