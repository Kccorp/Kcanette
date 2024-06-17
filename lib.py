from datetime import datetime

import scapy.all as scapy
import ipaddress
import socket


class Host:
    def __init__(self, ip: str, mac: str, hostname: str, ports: list, os: str):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.ports = ports
        self.os = os

    def get(self):
        print(f"[+] Host IP : {self.ip}, MAC: {self.mac}, Hostname : {self.hostname}")
        print(f"[+] OS detected : {self.os}")
        print(f"[+] Open ports : {self.ports}")


def generate_scan_id():
    now = datetime.now()
    return now.strftime("scanid-%H%M%S%s")


class Scanner:
    def __init__(self, ip_range):
        self.id = generate_scan_id()
        self.hosts = []
        self.range = ip_range
        print(f"[*] Scanning {self.range}...")

    def get_results(self):
        for host in self.hosts:
            host.get()

    def start_scan(self):
        self.detect_alive_host()
        for host in self.hosts:
            self.detect_os(host)
            self.scan_port(host)
            host.get()

    def detect_alive_host(self):
        ip_network = ipaddress.ip_network(self.range, strict=False)

        for ip in ip_network.hosts():
            print(f"[*] Scanning {ip}...")
            arp_request = scapy.ARP(pdst=str(ip))
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            for sent, received in answered_list:
                hostname = self.get_hostname(received.psrc)
                host = Host(ip=received.psrc, mac=received.hwsrc, hostname=hostname, ports=[], os="")
                self.hosts.append(host)

    def detect_os(self, host):
        ttl_os_mapping = {
            64: "Linux",
            128: "Windows",
            255: "Cisco",
        }

        pkt = scapy.IP(dst=host.ip)/scapy.TCP(dport=80, flags="S")
        response = scapy.srp(pkt, timeout=2, verbose=False)[0]

        for _, rcv in response:
            if scapy.IP in rcv:
                ttl = rcv[scapy.IP].ttl
                host.os = ttl_os_mapping.get(ttl, "Unknown")

    def scan_port(self, host):
        open_ports = []
        for port in range(1, 1024):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host.ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        host.ports = open_ports

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"
