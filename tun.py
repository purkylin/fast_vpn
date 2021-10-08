import os
import fcntl
import struct
from fcntl import ioctl
from util import sync_to_async, run
import threading
from scapy.all import *


TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
MTU = 1400

class Tunnel:
    def __init__(self, name: str, address: str):
        self.name = name
        self.address = address

        tun_fd = os.open('/dev/net/tun', os.O_RDWR)
        self.fd = tun_fd

        ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
        ioctl(tun_fd, TUNSETIFF, ifr)
        ioctl(tun_fd, TUNSETOWNER, 1000)

    def up(self):
        cmd = f'ifconfig {self.name} {self.address}/24 mtu {MTU} up'
        run(cmd)

    # @sync_to_async
    def read(self, length: int) -> bytes:
        data = os.read(self.fd, length)
        # pkt = IP(data)
        # print(f'read from tun data {len(data)} {pkt.src} -> {pkt.dst}')
        return data

    # @sync_to_async
    def write(self, data: bytes) -> None:
        # pkt = IP(data)
        # print(f'write to tun data {len(data)} {pkt.src} -> {pkt.dst}')
        os.write(self.fd, data)
