from attacks.attack import Attack
from lib.connectivity import *
from lib.interfaces import *
import scapy.all as scapy
import netns
import time

class DHCPServer(Attack):
    """
    This Attacks runs a DHCP server and checks im clients get leases from it.
    """

    def __init__(self, interfaces: list[scapy.NetworkInterface], ip4network: ipaddress.IPv4Network):
        super().__init__(interfaces, ip4network)
        self.dhcp_server = None
        self.victim_if = self.interfaces[1]
        self.attack_if = self.interfaces[0]
    def start_dhcp_server(self):
        with netns.NetNS(nsname='host0'):
            self.dhcp_server= scapy.DHCP_am(iface=self.interfaces[0].name,
                      pool=scapy.Net('192.168.10.0/24'),
                      network='192.168.10.0/24',
                      renewal_time=600, lease_time=3600)
            self.dhcp_server(bg=True)


    def setup(self) -> bool:
        ans0 = arping(self.interfaces, 0, self.interfaces[1].ip)
        ans1 = arping(self.interfaces,1 , self.interfaces[0].ip)
        if len(ans0) > 0 and len(ans1) > 0:
            return True
        else:
            return False

    def attack(self, timeout:int) -> str:
        self.start_dhcp_server()
        start_dhclient(self.victim_if.name, 'host1')

        retry_count = 0
        while retry_count < timeout:
            lease_ip = self.dhcp_server.leases.get(self.victim_if.mac)
            if lease_ip is not None:
                break
            retry_count += 1
            time.sleep(1)
        return lease_ip

    def evaluate(self, lease_ip) -> bool:
        if lease_ip:
            with netns.NetNS(nsname='host1'):
                ipr = IPRoute()
                if ipr.get_addr(address=lease_ip):
                    return True

        return False

    def teardown(self):
        self.dhcp_server.sniffer.stop()
        stop_dhclient(self.victim_if.name, 'host1')

    def run(self, timeout:int = 5) -> bool:
        if not self.setup():
            raise RuntimeError("No connectivity within the network.")
        lease_ip = self.attack(timeout)
        result = self.evaluate(lease_ip)
        self.teardown()
        return result
