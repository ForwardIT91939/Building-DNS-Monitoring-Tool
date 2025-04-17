import pyshark
import argparse
from colorama import Fore, Style, init

class DNSSecurityTool:
    def __init__(self, interface='eth0', threshold=1000):
        self.interface = interface
        self.threshold = threshold

def packet_callback(self, packet):
        try:
            if hasattr(packet, 'dns'):
                if int(packet.length) > self.threshold:
                    src_ip = packet.ip.src
                    print(f"{Fore.RED}ALERT! High byte DNS packet detected: {packet.length} bytes from IP: {src_ip}{Style.RESET_ALL}")
        except AttributeError:
            pass

def start_monitoring(self):
        print(f"{Fore.GREEN}Starting DNS monitoring on {self.interface}...{Style.RESET_ALL}")
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            capture.apply_on_packets(self.packet_callback)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Monitoring stopped by user.{Style.RESET_ALL}")
            
if __name__ == "__main__":
    init(autoreset=True)

    parser = argparse.ArgumentParser(description="DNS Security Tool for detecting DDoS and DoS attacks")
    parser.add_argument("-i", "--interface", type=str, default='eth0', help="Network interface to monitor (default is 'eth0')")
    parser.add_argument("-t", "--threshold", type=int, default=1000, help="Byte size threshold for alerts (default is 1000 bytes)")

    args = parser.parse_args()

    dns_tool = DNSSecurityTool(interface=args.interface, threshold=args.threshold)
    dns_tool.start_monitoring()

