import netns
from scapy.config import conf
from scapy.all import *
import ipaddress


def check_neighbors(interface, ip4network):
    with netns.NetNS(nsname='host0'):
        conf.ifaces.reload()
        conf.route.resync()
        p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip4network.with_prefixlen)
        print(p)
        ans, unans = srp(p,
                         iface=interface,
                         timeout=2)
        print(ans)
        print(unans)
        print(ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%")))
