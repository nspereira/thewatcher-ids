from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether, srp

mac = MacLookup()
BROADCAST = 'ff:ff:ff:ff:ff:ff'

def find_mac(addr):
    try:
        return mac.lookup(addr)
    except KeyError:
        return 'Unknown'

def get_mac(ip):
    p = Ether(dst=BROADCAST)/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc