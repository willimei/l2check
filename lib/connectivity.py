import netns
from scapy.config import conf
from scapy.all import *
import ipaddress


def arping_neighbors(interface, ip4network):
    with netns.NetNS(nsname='host0'):
        conf.ifaces.reload()
        conf.route.resync()
        p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip4network.with_prefixlen)
        ans, unans = srp(p,
                         iface=interface,
                         timeout=2)
        print(ans)
        print(unans)
        print(ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%")))

        return ans


def get_async_sniffer(interfaces: list, index: int, filterstr: str):
    with netns.NetNS(nsname=f'host{index}'):
        conf.ifaces.reload()
        conf.route.resync()
        sniffer = AsyncSniffer(iface=interfaces[index], filter=filterstr)
        sniffer.start()

        return sniffer
