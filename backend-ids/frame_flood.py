import sys, datetime
import logging
from scapy import Dot11Beacon, Dot11AssoReq, Dot11Auth, Dot11Deauth, Dot11Disas, Dot11ProbeReq, Dot11ReassoReq

global deauthCNT
THRESH =(25/5)
START = 5
deauthCNT = 0

def deauth_flood(pkt):
  if pkt.haslayer(Dot11):
    type = pkt.getlayer(Dot11).type
    subtype = pkt.getlayer(Dot11).subtype
    if ((type==0) and (subtype==12)):
      deauthCNT = deauthCNT + 1
      delta = datetime.datetime.now()-start
    if ((delta.seconds > START) and ((deauthCNT/delta.seconds) > THRESH)):
      print ("[*] - Detected Death Attack: "+str(deauthCNT)+" Dauth Frames.")


def packet_handler(pkt):
  if pkt.haslyer(Dot11AssoReq):
    print()
  elif pkt.haslyer(Dot11Auth):
    print()
  elif pkt.haslayer(Dot11Beacon):
    print()
  elif pkt.haslyer(Dot11Disas):
    print()
  elif pkt.haslyer(Dot11ProbeReq):
    print()
  elif pkt.haslyer(Dot11ReassoReq):
    print()
  elif pkt.haslyer(Dot11Deauth):
    print()


start = datetime.datetime.now()
sniff(iface='wlan0mon',prn=deauth_flood)
