#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
import sys
import json
from datetime import datetime
from collections import defaultdict
from scapy.layers.l2 import ARP, Ether

class ARPMonitor:
    def __init__(self, interface=None, gateway_ip=None):
        """
        Inisialisasi ARP Monitor
        
        Args:
            interface (str): Interface jaringan yang akan dimonitor
            gateway_ip (str): IP address gateway untuk monitoring khusus
        """
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.arp_table = {}  # Menyimpan mapping IP -> MAC
        self.suspicious_activities = []
        self.is_monitoring = False
        
        # Counter untuk statistik
        self.packet_count = 0
        self.suspicious_count = 0
        
        print("[*] Inisialisasi ARP Monitor...")
        if gateway_ip:
            self._get_initial_gateway_mac()
    
    def _get_initial_gateway_mac(self):
        """
        Mendapatkan MAC address gateway yang asli sebagai referensi
        """
        print(f"[*] Mendapatkan MAC address gateway {self.gateway_ip}...")
        
        try:
            # Buat ARP request untuk gateway
            arp_request = ARP(pdst=self.gateway_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Kirim dan tunggu response
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            if answered_list:
                gateway_mac = answered_list[0][1].hwsrc
                self.arp_table[self.gateway_ip] = gateway_mac
                print(f"[+] Gateway MAC address: {gateway_mac}")
            else:
                print(f"[!] Tidak dapat menemukan MAC address untuk gateway {self.gateway_ip}")
                
        except Exception as e:
            print(f"[!] Error mendapatkan MAC address gateway: {e}")
    
    def _analyze_arp_packet(self, packet):
        """
        Menganalisis paket ARP untuk mendeteksi anomali
        
        Args:
            packet: Paket ARP yang akan dianalisis
        """
        try:
            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                
                # Hanya proses ARP reply (op=2)
                if arp_layer.op == 2:  # ARP Reply
                    src_ip = arp_layer.psrc
                    src_mac = arp_layer.hwsrc
                    
                    self.packet_count += 1
                    
                    # Cek apakah IP ini sudah ada di ARP table
                    if src_ip in self.arp_table:
                        stored_mac = self.arp_table[src_ip]
                        
                        # Jika MAC address berubah, ini mencurigakan
                        if stored_mac != src_mac:
                            self._handle_suspicious_activity(src_ip, stored_mac, src_mac)
                    else:
                        # IP baru, simpan ke ARP table
                        self.arp_table[src_ip] = src_mac
                        print(f"[+] IP baru terdeteksi: {src_ip} -> {src_mac}")
                        
                        # Jika ini adalah gateway, beri perhatian khusus
                        if src_ip == self.gateway_ip:
                            print(f"[!] Gateway {src_ip} terdeteksi dengan MAC: {src_mac}")
                            
        except Exception as e:
            print(f"[!] Error menganalisis paket ARP: {e}")
    
    def _handle_suspicious_activity(self, ip, old_mac, new_mac):
        """
        Menangani aktivitas mencurigakan (perubahan MAC address)
        
        Args:
            ip (str): IP address yang MAC-nya berubah
            old_mac (str): MAC address lama
            new_mac (str): MAC address baru
        """
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Buat record aktivitas mencurigakan
        suspicious_record = {
            "timestamp": current_time,
            "ip_address": ip,
            "old_mac": old_mac,
            "new_mac": new_mac,
            "severity": "HIGH" if ip == self.gateway_ip else "MEDIUM"
        }
        
        self.suspicious_activities.append(suspicious_record)
        self.suspicious_count += 1
        
        # Tampilkan alert
        self._display_alert(suspicious_record)
        
        # Update ARP table dengan MAC baru
        self.arp_table[ip] = new_mac
    
    def _display_alert(self, record):
        """
        Menampilkan alert untuk aktivitas mencurigakan
        
        Args:
            record (dict): Record aktivitas mencurigakan
        """
        print("\n" + "="*60)
        print("⚠️  ALERT: POSSIBLE ARP SPOOFING DETECTED!")
        print("="*60)
        print(f"Waktu        : {record['timestamp']}")
        print(f"IP Address   : {record['ip_address']}")
        print(f"MAC Lama     : {record['old_mac']}")
        print(f"MAC Baru     : {record['new_mac']}")
        print(f"Tingkat      : {record['severity']}")
        
        if record['ip_address'] == self.gateway_ip:
            print("🚨 CRITICAL: Gateway MAC address berubah!")
            print("   Ini kemungkinan besar adalah serangan ARP spoofing!")
        
        print("="*60 + "\n")
    
    def _display_statistics(self):
        """
        Menampilkan statistik monitoring
        """
        print(f"\n[*] Statistik Monitoring:")
        print(f"    Total paket ARP: {self.packet_count}")
        print(f"    Aktivitas mencurigakan: {self.suspicious_count}")
        print(f"    Entri di ARP table: {len(self.arp_table)}")
    
    def _packet_handler(self, packet):
        """
        Handler untuk setiap paket yang ditangkap
        
        Args:
            packet: Paket jaringan yang ditangkap
        """
        self._analyze_arp_packet(packet)
    
    def start_monitoring(self):
        """
        Memulai monitoring ARP traffic
        """
        self.is_monitoring = True
        print(f"\n[*] Memulai monitoring ARP traffic...")
        print(f"[*] Interface: {self.interface if self.interface else 'Default'}")
        if self.gateway_ip:
            print(f"[*] Gateway khusus: {self.gateway_ip}")
        print("[*] Tekan Ctrl+C untuk menghentikan monitoring\n")
        
        try:
            # Mulai sniffing paket ARP
            scapy.sniff(
                filter="arp",
                prn=self._packet_handler,
                iface=self.interface,
                store=False
            )
            
        except KeyboardInterrupt:
            print("\n[*] Monitoring dihentikan oleh user")
            self.stop_monitoring()
        except Exception as e:
            print(f"\n[!] Error saat monitoring: {e}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """
        Menghentikan monitoring dan menampilkan ringkasan
        """
        self.is_monitoring = False
        print("\n[*] Menghentikan monitoring...")
        
        # Tampilkan statistik
        self._display_statistics()
        
        # Tampilkan ARP table saat ini
        self._display_arp_table()
        
        # Tampilkan ringkasan aktivitas mencurigakan
        self._display_suspicious_summary()
    
    def _display_arp_table(self):
        """
        Menampilkan ARP table saat ini
        """
        if self.arp_table:
            print(f"\n[*] ARP Table saat ini:")
            print("-" * 50)
            print(f"{'IP Address':<20} {'MAC Address':<20}")
            print("-" * 50)
            for ip, mac in self.arp_table.items():
                marker = " (Gateway)" if ip == self.gateway_ip else ""
                print(f"{ip:<20} {mac:<20}{marker}")
            print("-" * 50)
    
    def _display_suspicious_summary(self):
        """
        Menampilkan ringkasan aktivitas mencurigakan
        """
        if self.suspicious_activities:
            print(f"\n[*] Ringkasan Aktivitas Mencurigakan ({len(self.suspicious_activities)} kejadian):")
            print("-" * 80)
            for i, activity in enumerate(self.suspicious_activities, 1):
                print(f"{i:2d}. {activity['timestamp']} - {activity['ip_address']}")
                print(f"    {activity['old_mac']} -> {activity['new_mac']} [{activity['severity']}]")
        else:
            print("\n[+] Tidak ada aktivitas mencurigakan terdeteksi")
    
    def save_log(self, filename=None):
        """
        Menyimpan log aktivitas ke file
        
        Args:
            filename (str): Nama file output
        """
        if not filename:
            filename = f"arp_monitor_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            log_data = {
                "timestamp": datetime.now().isoformat(),
                "statistics": {
                    "total_packets": self.packet_count,
                    "suspicious_activities": self.suspicious_count,
                    "arp_table_entries": len(self.arp_table)
                },
                "arp_table": self.arp_table,
                "suspicious_activities": self.suspicious_activities
            }
            
            with open(filename, 'w') as f:
                json.dump(log_data, f, indent=2)
            
            print(f"[+] Log berhasil disimpan ke: {filename}")
            
        except Exception as e:
            print(f"[!] Error menyimpan log: {e}")

def main():
    """
    Fungsi utama program
    """
    parser = argparse.ArgumentParser(description="ARP Spoofing Detection Tool")
    parser.add_argument("-i", "--interface", 
                       help="Network interface untuk monitoring")
    parser.add_argument("-g", "--gateway", 
                       help="IP address gateway untuk monitoring khusus")
    parser.add_argument("--save-log", 
                       help="Simpan log ke file (optional)")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("    ARP SPOOFING DETECTION TOOL")
    print("    Untuk deteksi serangan ARP spoofing")
    print("=" * 50)
    
    try:
        # Inisialisasi monitor
        monitor = ARPMonitor(args.interface, args.gateway)
        
        # Mulai monitoring
        monitor.start_monitoring()
        
    except KeyboardInterrupt:
        print("\n[*] Program dihentikan")
    except PermissionError:
        print("[!] Error: Program memerlukan akses administrator/root")
        print("    Jalankan dengan sudo (Linux/Mac) atau sebagai administrator (Windows)")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        # Simpan log jika diminta
        if 'monitor' in locals() and args.save_log:
            monitor.save_log(args.save_log)
        
        print("\n[*] Program selesai")

if __name__ == "__main__":
    main()