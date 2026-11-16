#!/usr/bin/env python3
import socket
import struct
import sys
from scapy.all import sniff

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        try:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            print('\nEthernet Frame:')
            print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        except KeyboardInterrupt:
            print("\rsniffer ended")
            conn.close()
            sys.exit(0)

def packet_callback(packet):
    print(packet.summary())

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

if __name__ == '__main__':
    main()
