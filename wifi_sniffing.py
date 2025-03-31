from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq

interface  = 'wlo1'
probeReqs = []

def sniffProbes(p):
    if p.haslayer(Dot11ProbeReq):
        netName = p.getlayer(Dot11ProbeReq).info
        if netName not in probeReqs:
            probeReqs.append(netName)
            print(f"[+] Detected new Probe Request: {netName.decode()}")


sniff(iface=interface,prn=sniffProbes)