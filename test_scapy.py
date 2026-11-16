#!/usr/bin/env python3

from scapy.all import Ether, IP, IPv6, ARP, TCP, UDP, ICMP, sniff

# dictionary with ether types in protocol name form
ethertype = {0x0800: "IPV4",
             0x0806: "ARP",
             0x86DD: "IPv6",
             }

def packet_sniffer(packet):
    # make sure it has an ether layer to get packets from
    if not packet.haslayer(Ether):
        return

    # hex value of the code
    ether_code = packet[Ether].type
    # has a backup if code is not in dict
    ether_name = ethertype.get(ether_code, f"Unknown (0x{ether_code:04x})")

    # prnts no matter what type
    ether = packet[Ether]
    print(f"============== Frame =============")
    print(f"Destination MAC: {ether.dst}")
    print(f"Source MAC:      {ether.src}")
    print(f"Ethertype:       {ether_name}")
    print(f"----------------------------------")

    

    # IPv4 Handling
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"    Version: {ip.version}, TTL: {ip.ttl}")
        print(f"    Source IP:      {ip.src}")
        print(f"    Destination IP: {ip.dst}")

        # Transport layer inside IPv4
        if packet.haslayer(TCP):
            print(f"    [TCP]  Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"    [UDP]  Ports: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(f"    [ICMP] Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")

    # ARP Handling
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        op_name = "Request" if arp.op == 1 else ("Reply" if arp.op == 2 else arp.op)
        print(f"    Opcode: {op_name}")
        print(f"    Sender: {arp.hwsrc} ({arp.psrc})")
        print(f"    Target: {arp.hwdst} ({arp.pdst})")

    # IPv6 Handling
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        print(f"    Next Header: {ip6.nh}, Hop Limit: {ip6.hlim}")
        print(f"    Source IP:      {ip6.src}")
        print(f"    Destination IP: {ip6.dst}")

    print()


def main():
    print("Listening for packets with Scapy... Press Ctrl+C to stop.\n")
    try:
        # Explicitly pass iface='eth0' (or your dev name from step 1)
        sniff(iface="eth0", prn=packet_sniffer, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped.")


if __name__ == "__main__":
    main()