import socket
import struct
import time
import os

dst_mac = b'\xff\xff\xff\xff\xff\xff'       # broadcast
src_mac = b'\xe0\x8f\x4c\xaf\x16\x08'  # wlan0 MAC
ethertype = struct.pack('!H', 0x0806)       # ARP = 0x0806
eth_hdr = dst_mac + src_mac + ethertype

htype = struct.pack('!H', 1)                # Ethernet
ptype = struct.pack('!H', 0x0800)           # IPv4
hlen  = struct.pack('!B', 6)                # MAC length
plen  = struct.pack('!B', 4)                # IPv4 length
oper  = struct.pack('!H', 1)                # ARP request

sha = src_mac                               # sender MAC
def arp(target,myip):
    if target != myip:
        spa = socket.inet_aton(myip)       # sender IP
        tha = b'\x00\x00\x00\x00\x00\x00'           # target MaAC
        tpa = socket.inet_aton(target)        # target IP

        arp_hdr = htype + ptype + hlen + plen + oper + sha + spa + tha + tpa

        packet = eth_hdr + arp_hdr
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind(('wlan0', 0))
        sock.send(packet)



for i in range(2,255):
    arp("192.168.0."+str(i),"192.168.0.9")

sock.close()