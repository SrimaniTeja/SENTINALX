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



sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

echo_request=8
echo_code=0
echo_checksum=0
echo_identifier=os.getpid() & 0xFFFF
echo_sequence=0

icmp_header = struct.pack("!BBHHH",echo_request,echo_code,echo_checksum,echo_identifier,echo_sequence)

payload=b'raw icmp packet'
echo_checksum=icmp_checksum(icmp_header+payload)


packet = struct.pack("!BBHHH",echo_request,echo_code,echo_checksum,echo_identifier,echo_sequence)+payload

def icmp(target_ip):
    sock.sendto(packet, (target_ip, 0))
    print(f"Sent ICMP Echo Request to {target_ip}")



for i in range(2,255):
    icmp("192.168.0."+str(i))

sock.close()