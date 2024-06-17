from lib import Scanner, Host
from scapy.all import *

if __name__ == "__main__":
    # dumb_host = Host("127.0.0.1", "localhost", [])
    # dumb_host.get()

    range = "192.168.1.0/24"

    scanner = Scanner(range)
    scanner.detect_alive_host()
    scanner.start_scan()
    scanner.get_results()
