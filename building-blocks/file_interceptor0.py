#echo 1 > /proc/sys/net/ipv4/ip_forward
#command before running this program, "iptables -I OUTPUT -j NFQUEUE --queue-num 0"
#command before running this program, "iptables -I INPUT -j NFQUEUE --queue-num 0"

#!usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("HTTP Request:")
               # print(scapy_packet[scapy.Raw])
                print(scapy_packet[scapy.IP].show())

        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response:")
            print(scapy_packet[scapy.TCP].show())



    #this will forward the all packets
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
# 0 because we specified 0 queue-num in command, "iptables -I INPUT -j NFQUEUE --queue-num 0"
queue.bind(0,process_packet)
queue.run()