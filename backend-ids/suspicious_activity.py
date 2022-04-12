from datetime import date, datetime
from logging import exception
from types import new_class
from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.style import Style
from scapy.all import sniff, EAPOL, ARP, TCP, Dot11Disas, Dot11Auth, Dot11AssoReq, Dot11ReassoReq, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq
from port_scan import host_discovery, detect_host_discovery, tcp_syn_scan
from layer2 import deauth_flood, association_req, auth_req, new_host, reassociation_req, probe_req, probe_resp, eapol_detect, beacon, diassociation, reassociation_req
from spoof_detection import arp_spoofing
from utils import get_mac

auth_nr = 0
START = 5
deauth_cnt = 0
nr_arp_req = 0
ap_dict = {}
probe_devices = []
MAC_IGNORE_LIST = ['ff:ff:ff:ff:ff:ff']

network_watch = {
    'ssid': 'NOS-30D0',
    'bssid': '84:94:8c:10:30:d8',
    'devices': ['2c:db:07:2b:c7:53', '4a:3e:97:7d:39:83']
}

console = Console()
    
print('Initializing packet capture...')


def suspicious_activity(pkt):
    if pkt.haslayer(ARP):
        arp_spoofing(pkt)
        detect_host_discovery(pkt)
        new_host(pkt)
    elif pkt.haslayer(TCP):
        tcp_syn_scan(pkt)
    elif pkt.haslayer(Dot11AssoReq):
        association_req(pkt)
    elif pkt.haslayer(Dot11Auth):
        print(datetime.now(), str(pkt.time))
        auth_req(pkt)
    elif pkt.haslayer(Dot11Disas):
        diassociation(pkt)
    elif pkt.haslayer(Dot11ReassoReq):
        reassociation_req(pkt)
    elif pkt.haslayer(Dot11ProbeReq):
        probe_req(pkt)
    elif pkt.haslayer(Dot11ProbeResp):
        probe_resp(pkt)
    elif pkt.haslayer(EAPOL):
        eapol_detect(pkt)
    elif pkt.haslayer(Dot11Beacon):
        beacon(pkt)
    elif pkt.haslayer(Dot11Deauth):
        deauth_flood(pkt)
    elif pkt.type == 1 and pkt.subtype == 11:
        if pkt.addr2 not in ap_dict:
            ap_dict[pkt.addr2] = {
                'devices': [pkt.addr1]
            }
            print(ap_dict[pkt.addr2])
    elif pkt.type == 2 and (pkt.subtype == 0 or pkt.subtype == 3 or pkt.subtype == 8 or pkt.subtype == 10 or pkt.subtype == 11):
        #device_detection(pkt)
        pass
    
try:
    sniff(iface=['wlan0', 'wlan1'], prn=suspicious_activity)
except KeyboardInterrupt:
    print('..Exiting')
    exit()