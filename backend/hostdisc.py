#host discovery by sending icmp request

import socket
import struct
import time
import os

def icmp_checksum(data):
    if len(data)%2:
        data+=b'\x00'
    checksum=0
    for i in range(0,len(data),2):
        a=(data[i]<<8)+data[i+1]
        checksum+=a
        carry=checksum >> 16
        checksum=(checksum & 0xFFFF)+carry
    checksum = ~checksum & 0xFFFF

    return checksum

sock_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

echo_request_icmp=8
echo_code_icmp=0
echo_checksum_icmp=0
echo_identifier_icmp=os.getpid() & 0xFFFF
echo_sequence_icmp=0

icmp_header_icmp = struct.pack("!BBHHH",echo_request_icmp,echo_code_icmp,echo_checksum_icmp,echo_identifier_icmp,echo_sequence_icmp)

payload_icmp=b'raw icmp packet'
echo_checksum_icmp=icmp_checksum(icmp_header_icmp+payload_icmp)


packet_icmp = struct.pack("!BBHHH",echo_request_icmp,echo_code_icmp,echo_checksum_icmp,echo_identifier_icmp,echo_sequence_icmp)+payload_icmp

def icmp(target_ip_icmp):
    sock_icmp.sendto(packet_icmp, (target_ip_icmp, 0))
    #print(f"Sent ICMP Echo Request to {target_ip_icmp}")



dst_mac_arp = b'\xff\xff\xff\xff\xff\xff'       # broadcast
src_mac_arp = b'\xe0\x8f\x4c\xaf\x16\x08'       # wlan0 MAC
ethertype_arp = struct.pack('!H', 0x0806)       # ARP = 0x0806
eth_hdr_arp = dst_mac_arp + src_mac_arp + ethertype_arp

htype_arp = struct.pack('!H', 1)                # Ethernet
ptype_arp = struct.pack('!H', 0x0800)           # IPv4
hlen_arp  = struct.pack('!B', 6)                # MAC length
plen_arp  = struct.pack('!B', 4)                # IPv4 length
oper_arp  = struct.pack('!H', 1)                # ARP request

sha_arp = src_mac_arp                           # sender MAC

sock_arp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
def arp(target_ip,myip):
    spa_arp = socket.inet_aton(myip)       # sender IP
    tha_arp = b'\x00\x00\x00\x00\x00\x00'      # target MAC
    tpa_arp = socket.inet_aton(target_ip)     # target IP

    arp_hdr_arp = htype_arp + ptype_arp + hlen_arp + plen_arp + oper_arp + sha_arp + spa_arp + tha_arp + tpa_arp

    packet_arp = eth_hdr_arp + arp_hdr_arp
    sock_arp.bind(('wlan0', 0))
    sock_arp.send(packet_arp)



src_port_syn = 12345
dst_port_syn = 443
seq_syn = 0
ack_syn = 0
data_offset_syn = 6  # header = 24 bytes (20 + 4 options)
reserved_syn = 0
syn_flag_syn = 1  # renamed to avoid conflict with the original `syn` keyword
window_syn = 1024
urg_ptr_syn = 0

offset_reserved_flags_syn = (data_offset_syn << 12) | (reserved_syn << 9) | (syn_flag_syn << 1)

# MSS option
options_syn = struct.pack("!BBH", 2, 4, 1460)

tcp_header_syn = struct.pack(
    "!HHLLHHHH",
    src_port_syn,
    dst_port_syn,
    seq_syn,
    ack_syn,
    offset_reserved_flags_syn,
    window_syn,
    0,
    urg_ptr_syn
)

tcp_header_syn += options_syn
tcp_len_syn = len(tcp_header_syn)

sock_syn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

def tcpsyn(target_ip):
    sock_syn.sendto(tcp_header_syn, (target_ip, 0))

tcpsyn("8.8.7.7")




sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

dest_port_udp = 40125   # High port, likely closed
payload_udp = b''

def udp(target_ip):
    sock_udp.sendto(payload_udp, (target_ip, dest_port_udp))
    #print(f"Sent UDP probe to {target_ip}:{dest_port_udp}")

for i in range(1,225):
    target_ip="192.168.0."+str(i)
    tcpsyn(target_ip)
    icmp(target_ip)
    arp(target_ip,"192.168.0.5")
    udp(target_ip)

sock_udp.close()
sock_syn.close()
sock_icmp.close()
sock_arp.close()