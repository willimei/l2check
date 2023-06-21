import errno

from pyroute2 import NDB, IPRoute, NetlinkError, netns
import ipaddress


def add_ip(intf: str, ip: ipaddress, prefixlen: str, namespace: str, ndb: NDB):
    with ndb.interfaces[{'target': namespace,'ifname': intf}] as i:
        i.add_ip(address=str(ip), prefixlan=prefixlen)
    ndb.close()



def remove_ip(intf: str, ip: ipaddress, mask):
    ipr = IPRoute()
    ifindex = ipr.link_lookup(ifname=intf)
    ipr.addr('delete', ifindex, address=str(ip), mask=mask)
    ipr.close()
