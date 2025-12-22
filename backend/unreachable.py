#host discovery by sending udp to closed port

import socket
import struct
import time
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

dest_port = 40125   # High port, likely closed
payload = b''

def udp(target_ip):
    sock.sendto(payload, (target_ip, dest_port))
    print(f"Sent UDP probe to {target_ip}:{dest_port}")




for i in range(2,255):
    udp("192.168.0."+str(i))

sock.close()