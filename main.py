import importlib
import time

from lib.readconfig import *
from lib.interfaces import *
from lib.connectivity import *
import scapy.all as scapy
import scapy.config
import ipaddress
from pyroute2 import netns as pyrouteNetns, IPRoute
import netns

class L2CheckSuite:

    def initialize(self):
        ipr = IPRoute()
        interfaces = self.config.get("interfaces")
        for index, (ifname, ip) in enumerate(zip(interfaces.keys(), self.ip4network.hosts())):
            namespace = f'host{index}'

            pyrouteNetns.create(namespace)
            ifindex = ipr.link_lookup(ifname=ifname)[0]
            ipr.link('set', index=ifindex, net_ns_fd=namespace)

            ifup(ifname, namespace)
            if self.dhcp:
                start_dhclient(ifname, namespace)
            else:
                add_ip(ifname, ip, self.ip4network.prefixlen, namespace)

            with netns.NetNS(nsname=namespace):
                scapy.config.conf.ifaces.reload()
                scapy.config.conf.route.resync()
                intf = scapy.interfaces.dev_from_networkname(ifname)
                self.Interfaces.append(intf)

        ipr.close()
        print('Initialization successful.')


    def check_base_connectivity(self):
        retry_count = 0
        retrys = 50
        sniffer = []
        for i in range(1,4):
            filterstr = f'arp and ether dst {self.Interfaces[0].mac} and ether src {self.Interfaces[i].mac}'
            sniffer.append(get_async_sniffer(self.Interfaces, i, filterstr))

        while retry_count < retrys:
            error = None

            for s in sniffer:
                s.start()

            ans = arping_neighbors(self.Interfaces[0], 'host0', self.ip4network)

            for s in sniffer:
                s.stop()

            ans_macs = []
            for res in ans.res:
                ans_macs.append(res.answer.src)
            if (not ans_macs.__contains__(self.Interfaces[1].mac)) or \
                    (not ans_macs.__contains__(self.Interfaces[2].mac)):
                print(ans_macs)
                error = RuntimeError('Physical setup not valid. No ARP response.')

            if (ans_macs.__contains__(self.Interfaces[3].mac)) and (len(sniffer[2].results.res) != 0):
                print(ans_macs)
                error = RuntimeError('Physical setup not valid. ARP response from isolated interface.')

            for i in range(2):
                if len(sniffer[i].results.res) != 1:
                    print(sniffer[i].results.res)
                    error = RuntimeError('Physical setup not valid. ARP response from external Interface.')

            if error is None:
                print('Initial setup successful.')
                return True

            retry_count += 1
            time.sleep(1)

        raise error

    def run(self):
        for attack_config in self.config.get("attacks"):
            attack_name = attack_config.get("name")
            attack_class = getattr(importlib.import_module('attacks.'+attack_name), attack_name)
            attack_instance = attack_class(attack_config, self.Interfaces, self.ip4network)
            try:
                result = attack_instance.run()
                print(f'{attack_name}: {result}')
            except RuntimeError as err:
                print(f'{attack_name}: {err}')

    def teardown(self):
        for index, (interface, ip) in enumerate(zip(self.Interfaces, self.ip4network.hosts())):
            namespace = f'host{index}'
            if self.dhcp:
                stop_dhclient(interface.name, namespace)
            pyrouteNetns.remove(namespace)


    def check_config(self):
        if self.config.get('attacks') is None \
            or self.config.get('interfaces') is None:
            raise SystemExit('Invalid Config: Mandatory section "attacks" or "interfaces" does not exist.')

    def __init__(self, configfile: str = 'config.yaml', dhcp: bool = False):
        self.Interfaces = []
        self.ip4network = ipaddress.ip_network('192.168.3.0/24')
        self.dhcp = dhcp
        self.config = read_yaml_file(configfile)
        self.initialize()
        self.check_base_connectivity()

    def __del__(self):
        self.teardown()

def main():
    l2check = L2CheckSuite('config.yaml')
    l2check.run()


if __name__ == '__main__':
    main()

