from scapy.all import ARP, Ether, TCP, srp
from collections import Counter
from utils import get_mac, BROADCAST
from time import time

nr_arp = 0
nr_tcp = 0
tcp_cnt = Counter()
arp_cnt = Counter()

def host_discovery(pkt):
    request = Ether(dst=BROADCAST) / ARP(pdst="192.168.1.0/24")
    ans, unans = srp(request, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return print(result)

def detect_host_discovery(pkt):
    global nr_arp
    if pkt[ARP].op == 1:
            global nr_arp_req
            nr_arp += 1
            print(f"Request {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}")
            if pkt[ARP].psrc == '00:00:00:00:00:00':
                print(f'NEW DEVICE DETECTED: {get_mac(pkt[ARP].pdst)}')
            if nr_arp > 10:
                try:
                    attacker = get_mac(pkt[ARP].psrc)
                    print(f'NETWORK DISCOVERY DETECTED from IP: {pkt[ARP].psrc} MAC: {attacker}')
                except IndexError:
                    print(f'NETWORK DISCOVERY DETECTED from IP: {pkt[ARP].psrc} MAC: UNKNOWN')


def tcp_syn_scan(pkt):
    global nr_tcp
    if pkt[TCP] and pkt[TCP].flags & 2:
        src = pkt.sprintf('{IP: %IP.src%}{IPv6: %IPv6.src%}')
        tcp_cnt[src] += 1
        print('TCP DETECTED', nr_tcp)
        if tcp_cnt.most_common(1)[0][1] > 25 and pkt.ack == 0:
            print('SYN FLOOD IS BEING DETECTED')
