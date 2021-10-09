import socket
import threading
from tun import Tunnel
import select
import argparse
from struct import *
from scapy.all import *
import os
from cipher import Cipher

IS_SERVER = True
MTU = 1400  # Shoule less then 1500
TUNNEL_ADDRESS = '10.10.0.1'
ENABLE_CRYPTO = True


class UDP:
    def __init__(self, key):
        self.tun = None
        self.peers = {}
        self.udp = None
        # Remote server address
        self.remote = None

        if ENABLE_CRYPTO:
            self.cipher = Cipher(key)

    def stop(self):
        if self.udp:
            self.udp.close()

    def create_session(self):
        while True:
            rs, ws, es = select.select([self.tun.fd, self.udp], [], [])
            for r in rs:
                try:
                    if r is self.udp:
                        (data, addr) = self.udp.recvfrom(1500)

                        if ENABLE_CRYPTO:
                            payload = self.cipher.decrypt(data)
                        else:
                            payload = data

                        if not payload:
                            print('read or decrypt failed')
                            continue

                        if addr not in self.peers:
                            ip = IP(payload)
                            self.peers[ip.src] = addr

                        self.tun.write(payload)
                    else:
                        data = self.tun.read(MTU)
                        if ENABLE_CRYPTO:
                            payload = self.cipher.encrypt(data)
                        else:
                            payload = data

                        if IS_SERVER:
                            ip = IP(data)
                            peer = self.peers.get(ip.dst)
                            if peer:
                                self.udp.sendto(payload, peer)
                            else:
                                print('not found peer')
                        else:
                            self.udp.sendto(data, self.remote)
                except Exception as e:
                    print(e)
                    print('occur some errors')

    def start(self, host=None, port=6666):
        self.tun = Tunnel('fast', TUNNEL_ADDRESS)
        self.tun.up()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp = s

        if IS_SERVER:
            s.bind(('', port))
            print('Start udp server at port:', port)
        else:
            self.remote = (host, port)
            print(f'Create udp client to {host}:{port}')

        self.create_session()


def read_key(possible_key):
    key = None
    if not possible_key:
        if os.path.isfile("key"):
            with open('key') as fp:
                key = fp.read().strip()
        else:
            key = Cipher.generate_key()
            with open('key', 'w+') as fp:
                fp.write(key)

    return key


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Fast VPN', add_help=False)
    parser.add_argument('-s', '--server', help='server address')
    parser.add_argument('-t', '--tunnel', help='tunnel address')
    parser.add_argument('-p', '--port', help='server address')
    parser.add_argument('-k', '--key', help='key')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')

    args = parser.parse_args()

    key = read_key(args.key)
    print('key:', key)

    if args.server:
        IS_SERVER = False
    if args.tunnel:
        TUNNEL_ADDRESS = args.tunnel
    else:
        if not IS_SERVER:
            TUNNEL_ADDRESS = '10.10.0.3'

    try:
        server = UDP(key)
        server.start(args.server, args.port or 6565)
    except KeyboardInterrupt:
        server.stop()
