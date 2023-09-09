from attacks.attack import Attack
from lib.connectivity import *
from lib.interfaces import *
import scapy.all as scapy
import ipaddress
import netns
import time

class DHCPServer(Attack):
    """
    This Attacks runs a DHCP server and checks im clients get leases from it.
    """

    def __init__(self, config: dict, interfaces: list[scapy.NetworkInterface], ip4network: ipaddress.IPv4Network):
        super().__init__(config, interfaces, ip4network)
        self.dhcp_server = None
        self.victim_if = self.interfaces[1]
        self.attack_if = self.interfaces[0]
        self.victim_ns = 'host1'
        self.attack_ns = 'host0'
        self.server_subnet = '192.168.10.0/24'

    def start_dhcp_server(self):
        with netns.NetNS(nsname='host0'):
            self.dhcp_server= scapy.DHCP_am(iface=self.attack_if.name,
                      pool=scapy.Net(self.server_subnet),
                      network=self.server_subnet,
                      gw='0.0.0.0',
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

        requested_ips = []
        retry_count = 0
        while retry_count < timeout:
            with netns.NetNS(nsname=self.victim_ns):
                scapy.conf.checkIPaddr = False
                ans, _ = scapy.srp(
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=self.victim_if.mac) /
                    scapy.IP(src="0.0.0.0", dst="255.255.255.255") /
                    scapy.UDP(sport=68, dport=67) /
                    scapy.BOOTP(chaddr=self.victim_if.mac, xid=scapy.RandInt(), flags='B') /
                    scapy.DHCP(options=[
                        ('message-type', 'discover'),
                        ('client_id', b'\x01' + scapy.mac2str(self.victim_if.mac)),
                        ('vendor_class_id', b'MSFT 5.0'),
                        ('param_req_list', [
                            1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252
                        ]),
                        'end'
                     ]),
                    timeout=15,
                    iface=self.victim_if.name
                )
                for answer in ans:
                    adr = answer[1].getlayer(scapy.BOOTP).yiaddr
                    if ipaddress.ip_address(adr) in ipaddress.ip_network(self.server_subnet):
                        scapy.sendp(
                            scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=self.victim_if.mac) /
                            scapy.IP(src="0.0.0.0", dst="255.255.255.255") /
                            scapy.UDP(sport=68, dport=67) /
                            scapy.BOOTP(chaddr=self.victim_if.mac, xid=scapy.RandInt(), flags='B') /
                            scapy.DHCP(options=[
                                ('message-type', 'request'),
                                ('client_id', b'\x01' + scapy.mac2str(self.victim_if.mac)),
                                ('requested_addr', adr),
                                ('vendor_class_id', b'MSFT 5.0'),
                                ('param_req_list', [
                                    1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252
                                ]),
                                'end'
                            ]),
                            iface=self.victim_if.name
                        )
                        requested_ips.append(adr)
            lease_ip = self.dhcp_server.leases.get(self.victim_if.mac)
            if lease_ip is not None:
                break
            retry_count += 1
            time.sleep(1)
        return requested_ips

    def evaluate(self, requested_ips) -> bool:
        if len(requested_ips):
            lease_ip = self.dhcp_server.leases.get(self.victim_if.mac)
            for ip in requested_ips:
                if ip == lease_ip:
                    return True

        return False

    def teardown(self):
        self.dhcp_server.sniffer.stop()

    def run(self, timeout:int = 5) -> bool:
        if not self.setup():
            raise RuntimeError("No connectivity within the network.")
        requested_ips = self.attack(timeout)
        result = self.evaluate(requested_ips)
        self.teardown()
        return result
