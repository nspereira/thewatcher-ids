from scapy.all import IP, ARP, DNS, DHCP
from utils import get_mac

def arp_spoofing(pkt):
    if pkt[ARP].op == 2:
        try:
            real_mac = get_mac(pkt[ARP].psrc)
            response_mac = pkt[ARP].hwsrc
            print(real_mac != response_mac, pkt[ARP].pdst, pkt[ARP].hwdst)
            if real_mac != response_mac:
                return f"Your network is under attack real: {real_mac.upper()} fake: {response_mac.upper()}"
        except IndexError:
            print('error could not find mac')
            pass

def ip_spoofing(pkt):
    pass

def dns_spoofing(pkt):
    pass

def dhcp_spoofing(pkt):
    pass
