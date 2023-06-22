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
    check_neighbors(Interfaces[0], ip4network)


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

