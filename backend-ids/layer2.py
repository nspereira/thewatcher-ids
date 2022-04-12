from scapy.all import sniff, EAPOL, ARP, Ether, sendp, srp, RadioTap, Dot11, Dot11Disas, Dot11Auth, Dot11AssoReq, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq
from utils import find_mac, get_mac
from datetime import datetime
from collections import Counter

auth_nr = 0
START = 5
deauth_cnt = 0
nr_arp_req = 0
ap_dict = {}
probe_devices = []
conn_devices = []

MAC_IGNORE_LIST = ['ff:ff:ff:ff:ff:ff']

network_watch = {
    'ssid': 'NOS-30D0',
    'bssid': '84:94:8c:10:30:d8',
    'devices': ['2c:db:07:2b:c7:53', '4a:3e:97:7d:39:83']
}

def deauthenticate_target(target, gateway, nr, reason):
    frame = RadioTap()/Dot11(addr1=target, addr2=gateway, addr3=gateway)/Dot11Deauth(reason=reason)
    sendp(frame, inter=0.1, count=nr ,iface="wlan1mon", verbose=1)
    

def deauth_flood(pkt):
    global START
    global deauth_cnt
    deauth_cnt += 1 
    attack_occur = 0
    TRESHOLD = 25/5
    #delta = datetime.now() - start
    #print(delta.seconds)
    #if delta.seconds > START and (deauth_cnt/delta.seconds) > TRESHOLD:
    #    print('ATTACK DETECTED', str(deauth_cnt))


def association_req(pkt):
    if pkt.addr1 in ap_dict:
            if pkt.addr1 == network_watch['bssid'] and pkt.addr2 not in network_watch['devices']:
                #console.print('WARNING: Association detected on your network from a not identified device {pkt.addr2}')
                ssid = ap_dict[pkt.addr1]['ssid']
            else:
                pass
    else:
        ssid = 'Unknown'
        print(f'Association Request Detected AP: {ssid} - {pkt.addr1} Device: {pkt.addr2}')

def auth_req(pkt):
    global auth_nr
    if pkt.addr2 in ap_dict and pkt.addr2 == network_watch['bssid']:
            #console.print('WARNING: Authentication detected on your network from a not identified device')
            try:
                ssid = ap_dict[pkt.addr2]['ssid']
            except KeyError:
                pass
            auth_nr += 1
            if auth_nr > 5:
                print('AUTHENTICATION FLOOD')
    else:
        print(f'Authentication Detected AP - {pkt.addr2} Device: {pkt.addr1}')

def diassociation(pkt):
    print('DIASSOCIATION DETECTED',pkt.addr1, pkt.addr2, pkt.addr3)

def new_host(pkt):
    if pkt[ARP].op == 1 and pkt[ARP].hwdst == '00:00:00:00:00:00' and pkt[ARP].hwsrc not in conn_devices:
        conn_devices.append(pkt[ARP].hwsrc)
        print(conn_devices)

def reassociation_req(pkt):
    print('REASSOCIATION DETECTED',pkt.addr1, pkt.addr2, pkt.addr3)

def deauth_detect(pkt):
    if pkt.addr2 in ap_dict and pkt.dBm_AntSignal != None:
            print('RANGE', ap_dict[pkt.addr2]['signal'], str(pkt.dBm_AntSignal))
            #delta_dbm = str(ap_dict[pkt.addr2]['signal']) - str(pkt.dBm_AntSignal)
    else:
        delta_dbm = 0
    if str(pkt.dBm_AntSignal) == None or pkt.reason == 7:
        print('Suspicious Deauth detected: ',pkt.time, pkt.addr1, pkt.addr2, pkt.addr3, str(pkt.dBm_AntSignal), pkt.len, pkt.reason)
    else:
        print(pkt.time, pkt.addr1, pkt.addr2, pkt.addr3, str(pkt.dBm_AntSignal), pkt.len, pkt.reason)

def probe_req(pkt):
    if pkt.addr2 not in probe_devices:
        if pkt.info.decode() == '':
            ssid = 'Probing Broadcast'
            probe_devices.append(pkt.addr2)
            try:
                print('Probe request: ', ssid, find_mac(pkt.addr2))
            except:
                print('Probe Request: ', ssid, 'Vendor: Unkown')
        else:
            probe_devices.append(pkt.addr2)
            try:
                vendor = find_mac(pkt.addr2)
            except:
                vendor = 'unknown'
            print('Probe request: ', pkt.info.decode(), vendor, pkt.addr2, str(pkt.dBm_AntSignal),'Packet length: ' + str(pkt.len))

def beacon(pkt):
    if pkt.addr3 not in ap_dict:
        netstats = pkt[Dot11Beacon].network_stats()
        bssid = pkt.addr3
        ssid = netstats['ssid']
        channel = netstats['channel']
        crypto = '/'.join(netstats['crypto'])
        vendor = ''
        try:
            vendor = find_mac(bssid)
        except:
            vendor = 'Unkown'
        ap_dict[bssid] = {
            'time': str(datetime.fromtimestamp(pkt.time)),
            'ssid': ssid,
            'channel': channel,
            'signal': str(pkt.dBm_AntSignal),
            'crypto': crypto,
            'vendor': vendor,
            'probes': [],
            'devices': []
        }
        #print(ap_dict[bssid])

def eapol_detect(pkt):
    if pkt.type == 2 and pkt.subtype == 0:
        if pkt.addr2 in network_watch['bssid'] and pkt.addr1 not in network_watch['devices']:
            print('Suspicious EAPOL activity detected: ', pkt.addr1, pkt.addr2)
    elif pkt.type == 2 and pkt.subtype == 8:
        if pkt.addr2 in network_watch['bssid'] and pkt.addr1 not in network_watch['devices']:
            print('YOUR NETWORK IS UNDER ATTACK', pkt.addr1, pkt.addr2, pkt.addr3) 
            #deauthenticate_target(pkt.addr1, pkt.addr2, , 2)


def probe_resp(pkt):
    if pkt.addr2 not in ap_dict:
        vendor = ''
        try:
            vendor = find_mac(pkt.addr2)
        except: 
            vendor = 'Unknown'
        print(pkt.info.decode(), pkt.addr2, vendor, str(pkt.dBm_AntSignal))