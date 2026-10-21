#!/usr/bin/env python3

import socket
import struct

def main():

    ethertype = {0x0800: "IPV4",
                 0x0806: "ARP",
                 0x86DD: "IPv6",
                }
    
    # Create a raw socket catching all eth protocols
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    print("Listening for raw packets... Press Ctrl+C to stop.")
    
    while True:
        # Grab first packet
        packet, addr = s.recvfrom(65535)

        # 6 bytes dest_mac, 6 bytes src_mac, 2 bytes ethtype
        eth_header = packet[:14]

        # Network byte order (!), 6bytes str, 6bytes str, 2bytes unsigned short
        dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', eth_header)

        # Format arrays into readable mac addrs
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        protocol_name = ethertype.get(eth_type)

        print(f"Captured Frame")
        print(f"Destination MAC: {dest_mac}")
        print(f"Source MAC:      {src_mac}")
        print(f"Ethertype:       {protocol_name}\n")

if __name__ == "__main__":
    main()