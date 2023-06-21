from lib.readconfig import *
from lib.interfaces import *
from scapy.all import *
import ipaddress
import os
from pyroute2 import netns, NDB

Interfaces = []
ip4network = ipaddress.ip_network('192.168.3.0/24')


def initialize(configfilename):
    ndb = NDB()
    interfaces = read_interfaces(configfilename)
    for index, (iname, ip) in enumerate(zip(interfaces, ip4network.hosts())):
        namespace = f'host{index}'
        intf = dev_from_networkname(iname)
        Interfaces.append(intf)

        #netns.create(namespace)
        ndb.sources.add(netns=namespace)
        with ndb.interfaces[iname] as i:
            i['target'] = namespace

        #add_ip(iname, ip, ip4network.prefixlen, namespace, ndb)
        with ndb.interfaces[{'target': namespace,'ifname': iname}] as i:
            i.add_ip(address=str(ip), prefixlan=ip4network.prefixlen)

    os.system('echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore')
    os.system('echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter')

    ndb.close()


def check_base_connectivity():
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip4network.with_prefixlen),
                     iface=Interfaces[0],
                     timeout=2)
    print(ans)
    print(unans)



def teardown():
    for index, (i, ip) in enumerate(zip(Interfaces, ip4network.hosts())):
        namespace = f'host{index}'
        netns.remove(namespace)
        #remove_ip(i.description, ip, ip4network.prefixlen)
        #'/proc/1/ns/net'


def main():
    try:
        initialize('config.txt')
        #check_base_connectivity()
        #time.sleep(5)
    finally:
        #teardown()
        pass


if __name__ == '__main__':
    main()

