from lib.readconfig import *
from lib.interfaces import *
from lib.connectivity import *
from scapy.all import *
import scapy.config
import ipaddress
from attacks.arp_cache_poison import ArpCachePoison
from pyroute2 import netns as pyrouteNetns, IPRoute
import netns

class L2CheckSuite:

    def initialize(self, configfilename):
        ipr = IPRoute()
        interfaces = read_interfaces(configfilename)
        for index, (ifname, ip) in enumerate(zip(interfaces, self.ip4network.hosts())):
            namespace = f'host{index}'

            pyrouteNetns.create(namespace)
            ifindex = ipr.link_lookup(ifname=ifname)[0]
            ipr.link('set', index=ifindex, net_ns_fd=namespace)

            add_ip(ifname, ip, self.ip4network.prefixlen, namespace)
            ifup(ifname, namespace)

            with netns.NetNS(nsname=namespace):
                scapy.config.conf.ifaces.reload()
                scapy.config.conf.route.resync()
                intf = dev_from_networkname(ifname)
                self.Interfaces.append(intf)

        ipr.close()


    def check_base_connectivity(self):
        sniffer = []
        for i in range(1,4):
            filterstr = f'arp and ether dst {self.Interfaces[0].mac} and ether src {self.Interfaces[i].mac}'
            sniffer.append(get_async_sniffer(self.Interfaces, i, filterstr))

        ans = arping_neighbors(self.Interfaces[0], 'host0', self.ip4network)

        for s in sniffer:
            s.stop()

        ans_macs = []
        for res in ans.res:
            ans_macs.append(res.answer.src)
        if (not ans_macs.__contains__(self.Interfaces[1].mac)) or \
                (not ans_macs.__contains__(self.Interfaces[2].mac)):
            raise SystemExit('Physical setup not valid. No ARP response.')

        if (ans_macs.__contains__(self.Interfaces[3].mac)) and (len(sniffer[2].results.res) != 0):
            raise SystemExit('Physical setup not valid. ARP response from isolated interface.')

        for i in range(2):
            if len(sniffer[i].results.res) != 1:
                print(sniffer[i].results.res)
                raise SystemExit('Physical setup not valid. ARP response from external Interface.')


    def teardown(self):
        for index, (i, ip) in enumerate(zip(self.Interfaces, self.ip4network.hosts())):
            namespace = f'host{index}'
            pyrouteNetns.remove(namespace)


    def __init__(self, configfile: str = 'config.txt'):
        self.Interfaces = []
        self.ip4network = ipaddress.ip_network('192.168.3.0/24')
        self.initialize(configfile)
        self.check_base_connectivity()

    def __del__(self):
        self.teardown()

def main():
    l2check = L2CheckSuite('config.txt')
    poison = ArpCachePoison(l2check.Interfaces, l2check.ip4network)
    result = poison.run()
    print(f'Poison: {result}')


if __name__ == '__main__':
    main()

