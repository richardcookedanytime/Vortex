#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import sys
import subprocess
import platform
import socket
import ipaddress
import threading
import time
import json
import csv
from datetime import datetime
from scapy.layers.l2 import ARP, Ether, arping as l2_arping
from scapy.layers.inet import IP, TCP, UDP, ICMP
import concurrent.futures
import requests
import re


def _darwin_default_interface():
    """macOS: 从默认路由读取出站网卡（如 en0），避免 Scapy 选错 lo0。"""
    try:
        r = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def _darwin_ipconfig_addresses():
    """macOS: 依次尝试常见接口取 IPv4。"""
    for iface in ("en0", "en1", "en2", "en3", "en4", "bridge100"):
        try:
            r = subprocess.run(
                ["ipconfig", "getifaddr", iface],
                capture_output=True,
                text=True,
                timeout=3,
            )
            ip = (r.stdout or "").strip()
            if ip and not ip.startswith("127.") and r.returncode == 0:
                yield ip
        except Exception:
            continue


class NetworkScanner:
    def __init__(self, target_network=None, interface=None):
        """
        Inisialisasi Network Scanner
        
        Args:
            target_network (str): Network range yang akan di-scan (e.g., 192.168.1.0/24)
            interface (str): Interface jaringan yang akan digunakan
        """
        self.target_network = target_network
        self.interface = interface
        self.discovered_hosts = []
        self.scan_results = {}
        self.port_scan_results = {}
        
        # Dapatkan informasi jaringan lokal jika tidak dispesifikasi
        if not self.target_network:
            self.target_network = self._get_local_network()

        # macOS: 未指定网卡时自动用默认路由接口（否则 ARP 常走 lo0，结果为空）
        if not self.interface and platform.system().lower() == "darwin":
            self.interface = _darwin_default_interface()

        print(f"[*] Network Scanner initialized")
        print(f"[*] Target network: {self.target_network}")
        print(f"[*] Interface: {self.interface if self.interface else 'Default'}")
    
    def _get_local_ip_udp(self):
        """Tanpa DNS: paket UDP ke 8.8.8.8 hanya untuk memilih route lokal."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    return ip
        except OSError:
            pass
        # 离线时尝试公共 DNS 端口（仍不真正发包）
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect(("1.1.1.1", 53))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    return ip
        except OSError:
            pass
        return None

    def _get_local_network(self):
        """
        Mendapatkan network range lokal secara otomatis
        
        Returns:
            str: Network range (e.g., 192.168.1.0/24)
        """
        local_ip = None
        try:
            # 1) 优先 UDP（不依赖 hostname 能否被 DNS 解析；避免 macOS Errno 8）
            local_ip = self._get_local_ip_udp()

            # 2) macOS ipconfig
            if (not local_ip or local_ip.startswith("127.")) and platform.system().lower() == "darwin":
                for ip in _darwin_ipconfig_addresses():
                    local_ip = ip
                    break

            # 3) 最后才用 gethostbyname（许多 Mac 上 hostname 不在 /etc/hosts 会失败）
            if not local_ip or local_ip.startswith("127."):
                try:
                    local_ip = socket.gethostbyname(socket.gethostname())
                except OSError:
                    local_ip = None

            if not local_ip or local_ip.startswith("127."):
                raise OSError("无法确定本机局域网 IPv4（请用 -t 指定网段，如 192.168.0.0/24）")

            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            print(f"[*] 检测到本机 IPv4: {local_ip} → 扫描网段 {network}")
            return str(network)

        except Exception as e:
            print(f"[!] Error mendapatkan network lokal: {e}")
            print("[*] Menggunakan default network range 192.168.1.0/24（若不对请使用: -t 你的网段/24）")
            return "192.168.1.0/24"
    
    def _ping_scan(self, ip):
        """
        Melakukan ping scan ke IP address
        
        Args:
            ip (str): IP address yang akan di-ping
            
        Returns:
            bool: True jika host aktif, False jika tidak
        """
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "1000", ip],
                    capture_output=True,
                    timeout=3,
                )
            elif platform.system().lower() == "darwin":
                # macOS (BSD) ping: -W is wait time in milliseconds per packet, not seconds like GNU ping
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1000", ip],
                    capture_output=True,
                    timeout=5,
                )
            else:
                # Linux GNU ping: -W timeout in seconds
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip],
                    capture_output=True,
                    timeout=3,
                )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _arp_scan(self, target_network):
        """
        Melakukan ARP scan untuk menemukan host aktif
        
        Args:
            target_network (str): Network range yang akan di-scan
            
        Returns:
            list: List of discovered hosts
        """
        try:
            print(f"[*] Melakukan ARP scan pada {target_network}...")

            iface = self.interface
            if not iface and platform.system().lower() == "darwin":
                iface = _darwin_default_interface()

            hosts = []

            # Scapy: 对整段 CIDR 用 arping 更可靠；单包 ARP(pdst=/24) 在部分环境无效
            try:
                arping_kw = {"timeout": 5, "verbose": 0}
                if iface:
                    arping_kw["iface"] = iface
                answered, _unans = l2_arping(target_network, **arping_kw)
                for _sent, received in answered:
                    if received is None:
                        continue
                    hosts.append({
                        "ip": received.psrc,
                        "mac": received.hwsrc,
                        "method": "ARP",
                    })
                if not hosts:
                    print(
                        "[*] arping 未发现主机（确认已 sudo；可试: -i en0 -t 实际网段/24，例如 192.168.0.0/24）"
                    )
                return hosts
            except Exception as inner:
                print(f"[!] arping 失败: {inner}")
                print("[*] 请确认使用 sudo，并尝试 -i en0 与正确 -t 网段")
                return hosts

        except Exception as e:
            print(f"[!] Error saat ARP scan: {e}")
            return []
    
    def _get_hostname(self, ip):
        """
        Mendapatkan hostname dari IP address
        
        Args:
            ip (str): IP address
            
        Returns:
            str: Hostname atau 'Unknown' jika tidak ditemukan
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def _get_vendor_info(self, mac):
        """
        Mendapatkan informasi vendor dari MAC address
        (Implementasi sederhana berdasarkan OUI)
        
        Args:
            mac (str): MAC address
            
        Returns:
            str: Vendor information atau 'Unknown'
        """
        # Dictionary OUI (Organizationally Unique Identifier) untuk vendor umum
        oui_database = {
            "00:50:56": "VMware",
            "00:0c:29": "VMware",
            "00:05:69": "VMware",
            "00:1c:42": "Parallels",
            "08:00:27": "Oracle VirtualBox",
            "00:15:5d": "Microsoft Hyper-V",
            "00:16:3e": "Xen",
            "52:54:00": "QEMU/KVM",
            "02:00:4c": "Docker",
            "70:66:55": "Intel",
            "00:1b:21": "Intel",
            "ac:de:48": "Intel",
            "00:50:b6": "Intel",
            "f0:de:f1": "Intel",
            "00:24:d7": "Intel",
            "a0:36:9f": "Intel",
            "b4:2e:99": "Intel",
            "04:92:26": "Intel",
            "3c:07:54": "Intel",
            "e4:a4:71": "Intel",
            "00:19:d1": "Intel",
            "00:1e:67": "Intel",
            "00:21:6a": "Intel",
            "00:22:fa": "Intel",
            "00:24:d6": "Intel",
            "d4:be:d9": "Intel",
            "88:ae:1d": "Intel",
            "9c:b6:d0": "Intel",
            "dc:53:60": "Intel",
            "00:23:24": "Apple",
            "00:26:4a": "Apple",
            "28:cf:e9": "Apple",
            "a4:5e:60": "Apple",
            "b8:e8:56": "Apple",
            "00:1f:5b": "Apple",
            "00:23:df": "Apple",
            "00:25:00": "Apple",
            "00:26:bb": "Apple",
            "04:0c:ce": "Apple",
            "04:15:52": "Apple",
            "f8:1e:df": "Apple",
            "f8:4f:ad": "Apple",
            "fc:25:3f": "Apple",
            "00:23:6c": "Samsung",
            "00:26:e8": "Samsung",
            "30:07:4d": "Samsung",
            "54:88:0e": "Samsung",
            "b0:ec:71": "Samsung",
            "00:12:fb": "Samsung",
            "78:52:1a": "Samsung",
            "98:52:3d": "Samsung",
            "fc:db:b3": "Samsung",
            "a0:88:b4": "Realtek",
            "00:e0:4c": "Realtek",
            "52:54:00": "Red Hat",
            "00:16:3e": "Xensource",
            "00:a0:c9": "Intel",
            "00:d0:b7": "Intel",
            "90:2b:34": "Hon Hai",
            "20:cf:30": "Hon Hai",
            "b0:35:9f": "Hon Hai",
            "00:19:99": "Fujitsu",
            "00:26:82": "Fujitsu",
            "00:50:c2": "IEEE",
            "00:00:00": "Xerox",
            "aa:bb:cc": "Locally Administered"
        }
        
        try:
            # Ambil 3 oktet pertama dari MAC address
            mac_prefix = mac.upper()[:8]
            return oui_database.get(mac_prefix, "Unknown")
        except:
            return "Unknown"
    
    def _get_vendor_online(self, mac):
        """
        Mendapatkan informasi vendor dari MAC address melalui API online
        
        Args:
            mac (str): MAC address
            
        Returns:
            str: Vendor information atau 'Unknown'
        """
        try:
            # Gunakan API macvendors.com
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return response.text.strip()
            else:
                return self._get_vendor_info(mac)
        except:
            return self._get_vendor_info(mac)
    
    def _detect_os(self, ip):
        """
        Melakukan OS detection sederhana berdasarkan TTL
        
        Args:
            ip (str): IP address target
            
        Returns:
            str: OS information atau 'Unknown'
        """
        try:
            # Kirim ICMP ping dan analisis TTL
            response = scapy.sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=False)
            
            if response:
                ttl = response.ttl
                
                # Estimasi OS berdasarkan TTL
                if ttl <= 64:
                    if ttl > 60:
                        return "Linux/Unix"
                    else:
                        return "Linux/Unix (Router)"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Cisco/Network Device"
                else:
                    return "Unknown"
            else:
                return "Unknown"
                
        except Exception:
            return "Unknown"
    
    def _port_scan(self, ip, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080]):
        """
        Melakukan port scan sederhana
        
        Args:
            ip (str): IP address target
            ports (list): List port yang akan di-scan
            
        Returns:
            list: List port yang terbuka
        """
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    
            except Exception:
                pass
        
        # Scan ports menggunakan threading
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        # Tunggu semua thread selesai
        for thread in threads:
            thread.join()
        
        return sorted(open_ports)
    
    def _get_service_info(self, port):
        """
        Mendapatkan informasi service berdasarkan port
        
        Args:
            port (int): Port number
            
        Returns:
            str: Service information
        """
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            8080: "HTTP-Alt"
        }
        
        return service_map.get(port, f"Port {port}")
    
    def _threaded_ping_scan(self, ip_list):
        """
        Melakukan ping scan menggunakan threading untuk efisiensi
        
        Args:
            ip_list (list): List IP address yang akan di-scan
        """
        threads = []
        
        def ping_worker(ip):
            if self._ping_scan(ip):
                host_info = {
                    "ip": ip,
                    "mac": "Unknown",
                    "method": "PING",
                    "hostname": self._get_hostname(ip),
                    "vendor": "Unknown"
                }
                self.discovered_hosts.append(host_info)
                print(f"[+] Host ditemukan: {ip}")
        
        print("[*] Memulai ping scan...")
        for ip in ip_list:
            thread = threading.Thread(target=ping_worker, args=(ip,))
            threads.append(thread)
            thread.start()
            
            # Batasi jumlah thread concurrent
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Tunggu thread yang tersisa
        for t in threads:
            t.join()
    
    def scan_network(self, method="auto", include_ports=False, include_os=False):
        """
        Melakukan scan jaringan
        
        Args:
            method (str): Metode scanning ('arp', 'ping', 'auto')
            include_ports (bool): Apakah melakukan port scan
            include_os (bool): Apakah melakukan OS detection
        """
        print(f"\n[*] Memulai network scan...")
        print(f"[*] Target: {self.target_network}")
        print(f"[*] Method: {method}")
        print(f"[*] Include ports: {include_ports}")
        print(f"[*] Include OS detection: {include_os}")
        print(f"[*] Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.discovered_hosts = []
        start_time = time.time()
        
        try:
            if method == "arp" or method == "auto":
                # ARP scan
                arp_hosts = self._arp_scan(self.target_network)
                for host in arp_hosts:
                    host["hostname"] = self._get_hostname(host["ip"])
                    host["vendor"] = self._get_vendor_online(host["mac"])
                    self.discovered_hosts.append(host)
            
            if method == "ping" or (method == "auto" and len(self.discovered_hosts) == 0):
                # Ping scan sebagai backup
                network = ipaddress.IPv4Network(self.target_network, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
                
                # Batasi scan untuk network besar
                if len(ip_list) > 254:
                    print(f"[!] Network terlalu besar ({len(ip_list)} hosts)")
                    print("[*] Membatasi scan ke 254 host pertama")
                    ip_list = ip_list[:254]
                
                self._threaded_ping_scan(ip_list)
            
            # Hapus duplikasi berdasarkan IP
            unique_hosts = []
            seen_ips = set()
            for host in self.discovered_hosts:
                if host["ip"] not in seen_ips:
                    unique_hosts.append(host)
                    seen_ips.add(host["ip"])
            
            self.discovered_hosts = unique_hosts
            
            # Lakukan port scan dan OS detection jika diminta
            if include_ports or include_os:
                print("[*] Melakukan analisis lanjutan...")
                
                for host in self.discovered_hosts:
                    ip = host["ip"]
                    
                    if include_ports:
                        print(f"[*] Scanning ports untuk {ip}...")
                        open_ports = self._port_scan(ip)
                        host["open_ports"] = open_ports
                        host["services"] = [self._get_service_info(port) for port in open_ports]
                    
                    if include_os:
                        print(f"[*] Detecting OS untuk {ip}...")
                        host["os"] = self._detect_os(ip)
            
            end_time = time.time()
            scan_duration = end_time - start_time
            
            print(f"\n[*] Scan selesai dalam {scan_duration:.2f} detik")
            print(f"[*] Ditemukan {len(self.discovered_hosts)} host aktif")
            
        except Exception as e:
            print(f"[!] Error saat scanning: {e}")
    
    def display_results(self, detailed=False):
        """
        Menampilkan hasil scan dalam format tabel
        
        Args:
            detailed (bool): Apakah menampilkan informasi detail
        """
        if not self.discovered_hosts:
            print("\n[!] Tidak ada host yang ditemukan")
            return
        
        print(f"\n{'='*80}")
        print("HASIL NETWORK SCAN")
        print(f"{'='*80}")
        
        if detailed:
            for i, host in enumerate(self.discovered_hosts, 1):
                print(f"\n[{i}] Host Information:")
                print(f"    IP Address : {host['ip']}")
                print(f"    MAC Address: {host['mac']}")
                print(f"    Hostname   : {host.get('hostname', 'Unknown')}")
                print(f"    Vendor     : {host.get('vendor', 'Unknown')}")
                print(f"    Method     : {host['method']}")
                
                if 'os' in host:
                    print(f"    OS         : {host['os']}")
                
                if 'open_ports' in host and host['open_ports']:
                    print(f"    Open Ports : {', '.join(map(str, host['open_ports']))}")
                    print(f"    Services   : {', '.join(host['services'])}")
                
                print(f"    {'-'*50}")
        else:
            print(f"{'No':<3} {'IP Address':<16} {'MAC Address':<18} {'Hostname':<20} {'Vendor':<15} {'Method':<6}")
            print(f"{'-'*80}")
            
            for i, host in enumerate(self.discovered_hosts, 1):
                print(f"{i:<3} {host['ip']:<16} {host['mac']:<18} {host.get('hostname', 'Unknown'):<20} {host.get('vendor', 'Unknown'):<15} {host['method']:<6}")
        
        print(f"\n{'-'*80}")
        print(f"Total host ditemukan: {len(self.discovered_hosts)}")
    
    def save_results(self, filename=None, format_type="txt"):
        """
        Menyimpan hasil scan ke file
        
        Args:
            filename (str): Nama file output
            format_type (str): Format file ('txt', 'json', 'csv')
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.{format_type}"
        
        try:
            if format_type == "json":
                with open(filename, 'w') as f:
                    scan_data = {
                        "scan_info": {
                            "timestamp": datetime.now().isoformat(),
                            "target_network": self.target_network,
                            "total_hosts": len(self.discovered_hosts)
                        },
                        "hosts": self.discovered_hosts
                    }
                    json.dump(scan_data, f, indent=2)
                    
            elif format_type == "csv":
                with open(filename, 'w', newline='') as f:
                    fieldnames = ['ip', 'mac', 'hostname', 'vendor', 'method', 'os', 'open_ports', 'services']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for host in self.discovered_hosts:
                        row = {
                            'ip': host['ip'],
                            'mac': host['mac'],
                            'hostname': host.get('hostname', 'Unknown'),
                            'vendor': host.get('vendor', 'Unknown'),
                            'method': host['method'],
                            'os': host.get('os', 'Unknown'),
                            'open_ports': ','.join(map(str, host.get('open_ports', []))),
                            'services': ','.join(host.get('services', []))
                        }
                        writer.writerow(row)
                        
            else:  # txt format
                with open(filename, 'w') as f:
                    f.write("Network Scan Results\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target Network: {self.target_network}\n")
                    f.write(f"Total Hosts Found: {len(self.discovered_hosts)}\n\n")
                    
                    for i, host in enumerate(self.discovered_hosts, 1):
                        f.write(f"{i:2d}. IP: {host['ip']:<16} MAC: {host['mac']:<18}\n")
                        f.write(f"    Hostname: {host.get('hostname', 'Unknown')}\n")
                        f.write(f"    Vendor: {host.get('vendor', 'Unknown')}\n")
                        f.write(f"    Method: {host['method']}\n")
                        
                        if 'os' in host:
                            f.write(f"    OS: {host['os']}\n")
                        
                        if 'open_ports' in host and host['open_ports']:
                            f.write(f"    Open Ports: {', '.join(map(str, host['open_ports']))}\n")
                            f.write(f"    Services: {', '.join(host['services'])}\n")
                        
                        f.write("\n")
            
            print(f"[+] Hasil scan disimpan ke: {filename}")
            
        except Exception as e:
            print(f"[!] Error menyimpan file: {e}")
    
    def get_target_suggestions(self):
        """
        Memberikan saran target untuk ARP spoofing berdasarkan hasil scan
        """
        if not self.discovered_hosts:
            print("[!] Tidak ada host yang ditemukan untuk dijadikan target")
            return
        
        print(f"\n{'='*60}")
        print("SARAN TARGET UNTUK ARP SPOOFING")
        print(f"{'='*60}")
        
        # Cari gateway (biasanya .1 atau .254)
        gateway_candidates = []
        regular_hosts = []
        
        for host in self.discovered_hosts:
            ip_parts = host['ip'].split('.')
            last_octet = int(ip_parts[-1])
            
            if last_octet == 1 or last_octet == 254:
                gateway_candidates.append(host)
            else:
                regular_hosts.append(host)
        
        print("\n[*] Kandidat Gateway:")
        if gateway_candidates:
            for host in gateway_candidates:
                print(f"    {host['ip']} ({host.get('hostname', 'Unknown')})")
        else:
            print("    Tidak ditemukan kandidat gateway")
        
        print("\n[*] Host Regular:")
        if regular_hosts:
            for host in regular_hosts[:10]:  # Tampilkan 10 host pertama
                hostname = host.get('hostname', 'Unknown')
                vendor = host.get('vendor', 'Unknown')
                print(f"    {host['ip']} - {hostname} ({vendor})")
            
            if len(regular_hosts) > 10:
                print(f"    ... dan {len(regular_hosts) - 10} host lainnya")
        else:
            print("    Tidak ditemukan host regular")
    
    def get_network_statistics(self):
        """
        Menampilkan statistik jaringan
        """
        if not self.discovered_hosts:
            print("[!] Tidak ada data untuk statistik")
            return
        
        print(f"\n{'='*50}")
        print("STATISTIK JARINGAN")
        print(f"{'='*50}")
        
        # Hitung vendor
        vendor_count = {}
        method_count = {}
        os_count = {}
        
        for host in self.discovered_hosts:
            vendor = host.get('vendor', 'Unknown')
            method = host.get('method', 'Unknown')
            os = host.get('os', 'Unknown')
            
            vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
            method_count[method] = method_count.get(method, 0) + 1
            os_count[os] = os_count.get(os, 0) + 1
        
        print(f"Total Host: {len(self.discovered_hosts)}")
        print(f"Target Network: {self.target_network}")
        
        print("\nVendor Distribution:")
        for vendor, count in sorted(vendor_count.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(self.discovered_hosts)) * 100
            print(f"  {vendor}: {count} ({percentage:.1f}%)")
        
        print("\nDetection Method:")
        for method, count in method_count.items():
            percentage = (count / len(self.discovered_hosts)) * 100
            print(f"  {method}: {count} ({percentage:.1f}%)")
        
        if any('os' in host for host in self.discovered_hosts):
            print("\nOS Distribution:")
            for os, count in sorted(os_count.items(), key=lambda x: x[1], reverse=True):
                if os != 'Unknown':
                    percentage = (count / len(self.discovered_hosts)) * 100
                    print(f"  {os}: {count} ({percentage:.1f}%)")
        
        # Hitung port yang paling sering terbuka
        all_ports = []
        for host in self.discovered_hosts:
            if 'open_ports' in host:
                all_ports.extend(host['open_ports'])
        
        if all_ports:
            port_count = {}
            for port in all_ports:
                port_count[port] = port_count.get(port, 0) + 1
            
            print("\nMost Common Open Ports:")
            for port, count in sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:5]:
                service = self._get_service_info(port)
                print(f"  {port} ({service}): {count} hosts")


def main():
    """
    Fungsi utama untuk menjalankan network scanner
    """
    parser = argparse.ArgumentParser(description="Network Scanner - IP Detection Tool")
    parser.add_argument("-t", "--target", help="Target network (e.g., 192.168.1.0/24)")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-m", "--method", choices=['arp', 'ping', 'auto'], 
                       default='auto', help="Scan method")
    parser.add_argument("-p", "--ports", action='store_true', 
                       help="Include port scanning")
    parser.add_argument("-o", "--os", action='store_true', 
                       help="Include OS detection")
    parser.add_argument("-d", "--detailed", action='store_true', 
                       help="Show detailed results")
    parser.add_argument("-s", "--save", help="Save results to file")
    parser.add_argument("-f", "--format", choices=['txt', 'json', 'csv'], 
                       default='txt', help="Output format")
    parser.add_argument("--stats", action='store_true', 
                       help="Show network statistics")
    parser.add_argument("--targets", action='store_true', 
                       help="Show target suggestions for ARP spoofing")
    
    args = parser.parse_args()
    
    try:
        # Inisialisasi scanner
        scanner = NetworkScanner(target_network=args.target, interface=args.interface)
        
        # Lakukan scan
        scanner.scan_network(method=args.method, include_ports=args.ports, include_os=args.os)
        
        # Tampilkan hasil
        scanner.display_results(detailed=args.detailed)
        
        # Tampilkan statistik jika diminta
        if args.stats:
            scanner.get_network_statistics()
        
        # Tampilkan saran target jika diminta
        if args.targets:
            scanner.get_target_suggestions()
        
        # Simpan hasil jika diminta
        if args.save:
            scanner.save_results(filename=args.save, format_type=args.format)
        
    except KeyboardInterrupt:
        print("\n[!] Scan dihentikan oleh user")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()