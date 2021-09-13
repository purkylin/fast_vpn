import os
import fcntl
import struct
from fcntl import ioctl
import ipaddress
from typing import Union
import subprocess
import functools


TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
MTU = 1400


def run(cmd: str):
    subprocess.run(cmd, shell=True, check=True)


class Tunnel:

    def __init__(self, name: str, address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]):
        self.name = name
        self.address = address

        tun_fd = os.open('/dev/net/tun', os.O_RDWR)
        self.fd = tun_fd

        ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
        ioctl(tun_fd, TUNSETIFF, ifr)
        ioctl(tun_fd, TUNSETOWNER, 1000)

    def up(self):
        cmd = f'ifconfig {self.name} {str(self.address)}/24 mtu {MTU} up'
        run(cmd)

    def read(self, length: int) -> bytes:
        packet = os.read(self.fd, length)
        return packet

    def write(self, packet: bytes) -> None:
        os.write(self.fd, packet)
