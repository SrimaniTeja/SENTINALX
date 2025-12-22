import socket
import struct
import time
import os


src_port = 12345
dst_port = 443
seq = 0
ack = 0
data_offset = 6  # header = 24 bytes (20 + 4 options)
reserved = 0
syn = 1
window = 1024
urg_ptr = 0

offset_reserved_flags = (data_offset << 12) | (reserved << 9) | (syn << 1)

# MSS option
options = struct.pack("!BBH", 2, 4, 1460)

tcp_header = struct.pack("!HHLLHHHH",src_port,dst_port,seq,ack,offset_reserved_flags,window,0,urg_ptr)

tcp_header += options
tcp_len = len(tcp_header)

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

def tcpsyn(target_ip):
    sock.sendto(tcp_header, (target_ip, 0))


tcpsyn("8.8.7.7")

sock.close()