import os

def random_unicast_mac() -> bytes:
    mac = bytearray(os.urandom(6))
    mac[0] = mac[0]&0xFE # set I/G Bit to 0
    return bytes(mac)

