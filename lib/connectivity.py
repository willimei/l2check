import netns
import scapy.all as scapy
import ipaddress


def arping_neighbors(interface: scapy.NetworkInterface, namespace: str, ip4network: ipaddress.IPv4Address|str) -> scapy.SndRcvList:
    with netns.NetNS(nsname=namespace):
        scapy.conf.ifaces.reload()
        scapy.conf.route.resync()
        p = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ip4network.with_prefixlen)
        ans, unans = scapy.srp(p,
                         iface=interface,
                         timeout=2)
        print(ans)
        print(unans)
        print(ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%")))

        return ans

def arping(interfaces: list[scapy.NetworkInterface], ifindex: int, ip: ipaddress.IPv4Address|str) -> scapy.SndRcvList:
    with netns.NetNS(nsname=f'host{ifindex}'):
        scapy.conf.ifaces.reload()
        scapy.conf.route.resync()
        p = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=str(ip))
        ans, _ = scapy.srp(p, iface=interfaces[ifindex], timeout=2)

        return ans

def icmping(interfaces: list[scapy.NetworkInterface], ifindex: int, ip: ipaddress.IPv4Address|str, count: int = 3, retry: int = 2) -> scapy.SndRcvList:
    with netns.NetNS(nsname=f'host{ifindex}'):
        scapy.conf.ifaces.reload()
        scapy.conf.route.resync()
        ans, _ = scapy.srloop(scapy.IP(dst=ip)/scapy.ICMP(), timeout=3,count=count, retry=retry)

        return ans

def get_async_sniffer(interfaces: list[scapy.NetworkInterface], ifindex: int, filterstr: str):
    sniffer = AsyncSniffer(namespace=f'host{ifindex}', iface=interfaces[ifindex], filter=filterstr)

    return sniffer


class AsyncSniffer(scapy.AsyncSniffer):
    def __init__(self, namespace, *args, **kwargs):
        self.namespace = namespace
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().__init__(*args, **kwargs)

    def join(self, *args, **kwargs):  # type: (*Any, **Any) -> None:
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().join(*args, **kwargs)

    def start(self):  # type: () -> None:
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().start()

    def stop(self, join=True):  # type: (bool) -> Optional[PacketList]|None:
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().stop(join=join)
