import errno

from pyroute2 import NDB, IPRoute, NetlinkError, netns
import ipaddress


def add_ip(ifname: str, ipaddress: ipaddress, prefixlen: str, namespace: str):
    netns.pushns(namespace)
    ipr = IPRoute()
    ifindex = ipr.link_lookup(ifname=ifname)[0]
    ipr.addr('add', ifindex, address=str(ipaddress), mask=prefixlen)
    ipr.close()
    netns.popns()


def remove_ip(intf: str, ip: ipaddress, mask):
    ipr = IPRoute()
    ifindex = ipr.link_lookup(ifname=intf)
    ipr.addr('delete', ifindex, address=str(ip), mask=mask)
    ipr.close()
