from pyroute2 import NDB, IPRoute
import ipaddress
import netns


def add_ip(ifname: str, ipaddress: ipaddress, prefixlen: str, namespace: str):
    with netns.NetNS(nsname=namespace):
        ipr = IPRoute()
        ifindex = ipr.link_lookup(ifname=ifname)[0]
        ipr.addr('add', ifindex, address=str(ipaddress), mask=prefixlen)
        ipr.close()

def all_ifup_netns(namespace: str):
    with netns.NetNS(nsname=namespace):
        with NDB(log='on') as ndb:
            for key, nic in ndb.interfaces.items():
                nic.set('state', 'up')
                nic.commit()

def ifup(ifname: str, namespace: str):
    with netns.NetNS(nsname=namespace):
        ipr = IPRoute()
        ifindex = ipr.link_lookup(ifname=ifname)[0]
        ipr.link('set', index=ifindex, state='up')
        ipr.poll(ipr.link_lookup, '', ifname=ifname, operstate='UP', timeout=20)
        ipr.close()


def remove_ip(intf: str, ip: ipaddress, mask, namespace: str):
    with netns.NetNS(nsname=namespace):
        ipr = IPRoute()
        ifindex = ipr.link_lookup(ifname=intf)
        ipr.addr('delete', ifindex, address=str(ip), mask=mask)
        ipr.close()
