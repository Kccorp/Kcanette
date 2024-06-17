from scapy.all import *
import ipaddress
import argparse


def host(ip):
    send_icmp = IP(dst=ip) / ICMP()
    response_icmp = sr1(send_icmp, timeout=2, verbose=0)
    if response_icmp:
        return True

    return False


def os_detection(ip):
    syn_packet = IP(dst=ip) / TCP(dport=80, flags='S')
    response = sr1(syn_packet, timeout=2, verbose=0)
    if response:
        if response.haslayer(TCP):
            tcp_options = response.getlayer(TCP).options
            if ('Timestamp', '') in tcp_options:
                return "Linux"
            else:
                return "Windows"
    return "Unknown"


def services(ip, ports):
    open_ports = []
    for port in ports:
        syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')
        response = sr1(syn_packet, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                rst_packet = IP(dst=ip) / TCP(dport=port, flags='R')
                send(rst_packet, verbose=0)
    return open_ports


def scan_ip(ip):
    print(f"\nScanning {ip}...")
    if host(ip):
        print(f"Host {ip} is up.")
        os = os_detection(ip)
        print(f"Detected OS: {os}")

        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
                        8080]
        open_ports = services(ip, common_ports)
        if open_ports:
            print(f"Open ports on {ip}: {open_ports}")
        else:
            print(f"No open ports found on {ip}.")
    else:
        print(f"Host {ip} is down.")


def main(target):
    try:
        ip_network = ipaddress.ip_network(target, strict=False)
        for ip in ip_network.hosts():
            scan_ip(str(ip))
    except ValueError:
        scan_ip(target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Cibler une adresse IP ou une range entiÃ¨re')
    args = parser.parse_args()
    main(args.target)
