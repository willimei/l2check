import scapy.all as scapy
import ipaddress

class Attack:

    def __init__(self, interfaces: list[scapy.NetworkInterface], ip4network: ipaddress.IPv4Network):
        self.interfaces = interfaces
        self.ip4network = ip4network
