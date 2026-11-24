#!/usr/bin/env python3
"""Cross-platform packet sniffer using scapy (Linux, macOS, Windows).

Layers: PacketRecord (data) -> decode() (scapy -> record) ->
Sniffer (capture thread + queue) -> main loop.
"""

import argparse
import os
import queue
import sys
import time
from dataclasses import dataclass
from datetime import datetime

from scapy.all import (
    ARP, ICMP, IP, TCP, UDP, AsyncSniffer, Ether, IPv6, conf, get_if_list,
)

IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


# data
@dataclass
class PacketRecord:
    timestamp: float
    length: int
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str = "unknown"
    src_port: int | None = None
    dst_port: int | None = None
    summary: str = ""
    id: int = 0


# decode
def decode(pkt) -> PacketRecord:
    """Scapy pkt into PacketRecord."""
    rec = PacketRecord(
        timestamp=float(pkt.time),
        length=len(pkt),
        summary=pkt.summary(),
    )

    # macOS loopback / VPN tunnels checker (no ethernet layer)
    if pkt.haslayer(Ether):
        rec.src_mac = pkt[Ether].src
        rec.dst_mac = pkt[Ether].dst

    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec.src_ip, rec.dst_ip = ip.src, ip.dst
        rec.protocol = IP_PROTOCOLS.get(ip.proto, f"IP/{ip.proto}")
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec.src_ip, rec.dst_ip = ip6.src, ip6.dst
        rec.protocol = IP_PROTOCOLS.get(ip6.nh, f"IPv6/{ip6.nh}")
    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec.src_ip, rec.dst_ip = arp.psrc, arp.pdst
        rec.protocol = "ARP"

    # ports
    if pkt.haslayer(TCP):
        rec.src_port, rec.dst_port = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        rec.src_port, rec.dst_port = pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        rec.protocol = "ICMP"

    return rec


# capture
class Sniffer:
    """Runs scapy in a background thread and adds records on a queue."""

    def __init__(self, iface: str, bpf_filter: str | None = None):
        self.iface = iface
        self.records: queue.Queue[PacketRecord] = queue.Queue()
        self._next_id = 1
        self._sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf_filter,
            prn=self._on_packet,
            store=False,  #dont store in memory
        )

    def _on_packet(self, pkt) -> None:
        try:
            rec = decode(pkt)
            rec.id = self._next_id
            self._next_id += 1
            self.records.put(rec)
        except Exception as exc:  #bad packet doesn't break it
            print(f"decode error: {exc}", file=sys.stderr)

    def start(self) -> None:
        self._sniffer.start()
        time.sleep(0.5)  #time to fail (just incase)
        if not self._sniffer.thread.is_alive():
            raise RuntimeError(f"capture failed to start on {self.iface}")

    def stop(self) -> None:
        if self._sniffer.running:
            self._sniffer.stop()


# helpers
def is_admin() -> bool:
    if hasattr(os, "geteuid"):  # Linux/macOS
        return os.geteuid() == 0
    try:  # Windows
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def format_record(r: PacketRecord) -> str:
    t = datetime.fromtimestamp(r.timestamp).strftime("%H:%M:%S")
    src = r.src_ip or r.src_mac or "?"
    dst = r.dst_ip or r.dst_mac or "?"
    if r.src_port is not None:
        src, dst = f"{src}:{r.src_port}", f"{dst}:{r.dst_port}"
    return f"{r.id:>5} {t}  {r.protocol:<8} {src:<28} -> {dst:<28} {r.length:>5}B"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Simple scapy packet sniffer")
    p.add_argument("-i", "--iface", help="interface (default: scapy's pick)")
    p.add_argument("-f", "--filter", help="BPF filter, e.g. 'tcp port 443'")
    p.add_argument("-l", "--list", action="store_true",
                   help="list interfaces and exit")
    return p.parse_args()


# main
def main() -> int:
    args = parse_args()

    if args.list:
        print("\n".join(get_if_list()))
        return 0

    if not is_admin():
        print("Packet capture needs elevated privileges.\n"
              "Linux/macOS: sudo <path-to-venv>/bin/python stickypackets.py\n"
              "Windows: run the terminal as Administrator (install Npcap).",
              file=sys.stderr)
        return 1

    iface = args.iface or str(conf.iface)
    if iface not in get_if_list():
        print(f"Unknown interface {iface!r}. Try --list.", file=sys.stderr)
        return 1

    sniffer = Sniffer(iface, args.filter)
    print(f"Sniffing on {iface}. Ctrl+C to stop.")
    try:
        sniffer.start()
        while True:  # the loop;(to be TUI)
            try:
                print(format_record(sniffer.records.get(timeout=0.1)))
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        pass
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    finally:
        sniffer.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())