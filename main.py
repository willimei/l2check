import scapy.config

from lib.readconfig import *
from lib.interfaces import *
from lib.connectivity import *
from scapy.all import *
import ipaddress
import os
from pyroute2 import netns, IPRoute

Interfaces = []
ip4network = ipaddress.ip_network('192.168.3.0/24')


def initialize(configfilename):
    ipr = IPRoute()
    interfaces = read_interfaces(configfilename)
    for index, (ifname, ip) in enumerate(zip(interfaces, ip4network.hosts())):
        namespace = f'host{index}'
        intf = dev_from_networkname(ifname)
        Interfaces.append(intf)

        netns.create(namespace)
        ifindex = ipr.link_lookup(ifname=ifname)[0]
        ipr.link('set', index=ifindex, net_ns_fd=namespace)

        add_ip(ifname, ip, ip4network.prefixlen, namespace)
        #all_ifup_netns(namespace)
        ifup(ifname, namespace)

    ipr.close()

    os.system('echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore')
    os.system('echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter')

    scapy.config.conf.ifaces.reload()
    scapy.config.conf.route.resync()


def check_base_connectivity():
    sniffer = []
    for i in range(1,4):
        filterstr = f'arp and ether dst {Interfaces[0].mac} and ether src {Interfaces[i].mac}'
        sniffer.append(get_async_sniffer(Interfaces, i, filterstr))

    ans = arping_neighbors(Interfaces[0], ip4network)

    for s in sniffer:
        s.stop()

    ans_macs = []
    for res in ans.res:
        ans_macs.append(res.answer.src)
    if (not ans_macs.__contains__(Interfaces[1].mac)) or \
            (not ans_macs.__contains__(Interfaces[2].mac)):
        raise SystemExit('Physical setup not valid. No ARP response.')

    if (ans_macs.__contains__(Interfaces[3].mac)) and (len(sniffer[2].results.res) != 0):
        raise SystemExit('Physical setup not valid. ARP response from isolated interface.')

    for i in range(2):
        if len(sniffer[i].results.res) != 1:
            print(sniffer[i].results.res)
            raise SystemExit('Physical setup not valid. ARP response from external Interface.')




def teardown():
    for index, (i, ip) in enumerate(zip(Interfaces, ip4network.hosts())):
        namespace = f'host{index}'
        netns.remove(namespace)


def main():
    try:
        initialize('config.txt')
        check_base_connectivity()
    finally:
        teardown()
        pass


if __name__ == '__main__':
    main()

