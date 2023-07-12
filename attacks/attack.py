import abc
import scapy.all as scapy
import ipaddress

class Attack(metaclass=abc.ABCMeta):

    def __init__(self, interfaces: list[scapy.NetworkInterface], ip4network: ipaddress.IPv4Network):
        self.interfaces = interfaces
        self.ip4network = ip4network

    @abc.abstractmethod
    def run(self) -> bool:
        """
        Run the attack.
        :return: Boolean which indicates the success of the attack.
        """
