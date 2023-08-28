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
        packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=str(ip))
        ans, _ = scapy.srp(packet, iface=interfaces[ifindex], timeout=2)

        return ans

def icmping(interfaces: list[scapy.NetworkInterface], ifindex: int, ip: ipaddress.IPv4Address|str, count: int = 3, retry: int = 2) -> scapy.SndRcvList:
    with netns.NetNS(nsname=f'host{ifindex}'):
        scapy.conf.ifaces.reload()
        scapy.conf.route.resync()
        packet = scapy.IP(dst=ip)/scapy.ICMP()
        ans, _ = scapy.srloop(packet, timeout=3,count=count, retry=retry)

        return ans

def icmping6(interfaces: list[scapy.NetworkInterface], ifindex: int, ip: ipaddress.IPv6Address|str, count: int = 3, retry: int = 2) -> scapy.SndRcvList:
    with netns.NetNS(nsname=f'host{ifindex}'):
        scapy.conf.ifaces.reload()
        scapy.conf.route6.resync()
        src = interfaces[ifindex].ips[6][0]
        packet = scapy.IPv6(dst=ip, src=src, nh=58) / scapy.ICMPv6EchoRequest()
        ans, _ = scapy.srloop(packet, iface=interfaces[ifindex], timeout=3, count=count, retry=retry)

        return ans

def get_async_sniffer(interfaces: list[scapy.NetworkInterface], ifindex: int, filterstr: str = None, *args, **kwargs):
    sniffer = AsyncSniffer(namespace=f'host{ifindex}', iface=interfaces[ifindex], filter=filterstr, *args, **kwargs)

    return sniffer


class AsyncSniffer(scapy.AsyncSniffer):
    def __init__(self, namespace, *args, **kwargs):
        self.namespace = namespace
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().__init__(*args, **kwargs)

    def join(self, *args, **kwargs):  # type: (*Any, **Any) -> None
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().join(*args, **kwargs)

    def start(self):  # type: () -> None
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().start()

    def stop(self, join=True):  # type: (bool) -> Optional[scapy.PacketList]|None
        with netns.NetNS(nsname=self.namespace):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            super().stop(join=join)


class ICMP6Echo_am(scapy.AnsweringMachine):
    """Responds to every ICMPv6 Echo-Requests"""

    def __init__(self, interface: scapy.NetworkInterface, **kwargs):
        self.interface = interface
        self.send_function = staticmethod(scapy.sendp)
        super().__init__(iface=interface.name, **kwargs)
    def is_request(self, req: scapy.Packet) -> int:
        if req.haslayer(scapy.ICMPv6EchoRequest):
            return True
        else:
            return False

    def print_reply(self, req, reply):  # type: (Packet, _T) -> None
        pass

    def make_reply(self, req: scapy.Packet):
        src_mac = self.interface.mac
        dst_mac = req[scapy.Ether].src
        src = req[scapy.IPv6].dst
        dst = req[scapy.IPv6].src
        id = req[scapy.ICMPv6EchoRequest].id
        data = req[scapy.ICMPv6EchoRequest].data
        sequence = req[scapy.ICMPv6EchoRequest].seq
        reply = scapy.Ether(dst=dst_mac, src=src_mac) \
                / scapy.IPv6(dst=dst, src=src) \
                / scapy.ICMPv6EchoReply(id=id, data=data, seq=sequence)

        return reply
