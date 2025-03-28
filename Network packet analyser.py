from scapy.all import sniff

# Callback function to process each packet
def process_packet(packet):
    print(packet.summary())  # Print a summary of the packet
    if packet.haslayer("IP"):
        print(f"Source IP: {packet['IP'].src}, Destination IP: {packet['IP'].dst}")

# Capture packets (use 'iface' to specify an interface if needed)
print("Sniffing network packets... Press Ctrl+C to stop.")
sniff(prn=process_packet, filter="ip", count=0)
