import netns
from scapy.config import conf
from scapy.all import *
import ipaddress


def arping_neighbors(interface, namespace: str, ip4network):
    with netns.NetNS(nsname=namespace):
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


def get_async_sniffer(interfaces: list, ifindex: int, filterstr: str):
    with netns.NetNS(nsname=f'host{ifindex}'):
        conf.ifaces.reload()
        conf.route.resync()
        sniffer = AsyncSniffer(iface=interfaces[ifindex], filter=filterstr)
        sniffer.start()

        return sniffer
