#!/usr/bin/python3

from scapy.all import sniff

def packet_callback(packet):
	print(f"Packet: {packet.summary()}")
	#You can add more detailed packet analysis here
	if packet.haslayer('IP'):
		ip_layer = packet['IP']
		print(f"Source_IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")

def start_sniffing(interface="wlan0"):
	print("Starting packet sniffing...")
	#Use sniff function to capture packets
	sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
	#Specify the network interface or leave as None to sniff on all interfaces
	start_sniffing(interface="wlan0")

