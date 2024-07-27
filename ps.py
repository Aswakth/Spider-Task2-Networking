from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import sys

def packet_sniffing(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\nIP Packet: {ip_layer.src} -> {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                print(f"HTTP Request: {http_layer.Host.decode()}{http_layer.Path.decode()}")
            elif packet.haslayer(HTTPResponse):
                http_layer = packet[HTTPResponse]
                print(f"HTTP Response: {http_layer.Status_Code} {http_layer.Reason_Phrase.decode()}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Packet: {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"ICMP Packet: {ip_layer.src} -> {ip_layer.dst}")
        elif packet.haslayer(FTP):
            ftp_layer = packet[FTP]
            print(f"FTP Packet: {ftp_layer}")
        elif packet.haslayer(SNMP):
            snmp_layer = packet[SNMP]
            print(f"SNMP Packet: {snmp_layer}")
        elif packet.haslayer(SMTP):
            smtp_layer = packet[SMTP]
            print(f"SMTP Packet: {smtp_layer}")
        elif packet.haslayer(POP3):
            pop3_layer = packet[POP3]
            print(f"POP3 Packet: {pop3_layer}")

    if ARP in packet:
        arp_layer = packet[ARP]
        if arp_layer.op == 1:
            print(f"ARP Request: {arp_layer.psrc} -> {arp_layer.pdst}")
        elif arp_layer.op == 2:
            print(f"ARP Response: {arp_layer.hwsrc} -> {arp_layer.psrc}")

def sniffer():
    packets = rdpcap("networkcapture.pcapng")
    for packet in packets:
        packet_sniffing(packet)

def main():
    print("Sniffing packets :")
    sniffer()

if __name__ == "__main__":
    main()
    sys.stdout.flush()
