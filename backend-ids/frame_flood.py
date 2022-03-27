import datetime
from scapy.all import *
THRESH =(25/5)
START = 5
global deauthCNT

def monitorPackets(p):
  global deauthCNT
  if p.haslayer(Dot11):
    type = p.getlayer(Dot11).type
    subtype = p.getlayer(Dot11).subtype
  if ((type==0) and (subtype==12)):
    deauthCNT = deauthCNT + 1
    delta = datetime.now()-start
  if ((delta.seconds > START) and ((deauthCNT/delta.seconds) > THRESH)):
    print ("[*] - Detected Death Attack: "+str(deauthCNT)+" Dauth Frames.")


deauthCNT = 0
start = datetime.now()
sniff(iface='wlan0mon',prn=monitorPackets)
