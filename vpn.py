'''
    Fast vpn

    Deploy:   Run the program as server in a VPS, and run the program as client in another VPS.
              Should open the port(default: 7777) in your VPS
    Test:     On both sides to ping the address 192.168.2.1 and 192.168.2.2.
    Limit:    Only one client can connect to the server.
    Note:     Not need to set iptables and route
    Payload:  nonce(12)|ciphertext|tag(16)
    Crypto:   AEAD, key(16|24|32)
    Route:    iptables -t nat -I POSTROUTING -s 192.168.2.1/24 ! -d 192.168.2.1/24 -j MASQUERADE
'''

import asyncio
import asyncio_dgram
import argparse
from tun import Tunnel
import ipaddress
from enum import Enum
import threading
from cipher import Cipher
from scapy.all import IP

class RunMode(Enum):
    SERVER = 0
    CLIENT = 1


MODE = RunMode.SERVER
SERVER: str = None
PORT: int = 7777
TARGET: str = None
VERBOSE: bool = False
ENABLE_CRYPTO = False


def try_encrypt(plaintext: bytes) -> bytes:
    if ENABLE_CRYPTO:
        return Cipher.encrypt(plaintext)
    else:
        return plaintext

def try_decrypt(ciphertext: bytes) -> bytes:
    if ENABLE_CRYPTO:
        try:
            return Cipher.decrypt(ciphertext)
        except ValueError:
            if MODE == RunMode.Client:
                print('Error: Decrypt failed as invalid key')
                exit(-1)
            else:
                print('Error: Decrypt failed')
    else:
        return ciphertext

def relay_tun(tun, udp):
    print('begin relay tun')

    async def func(tun, udp):
        while True:
            packet = tun.read(1400)

            if VERBOSE:
                print('receive tun packet with length:', len(packet))

            payload = try_encrypt(packet)

            if not payload or len(payload) < 16:
                continue

            if MODE == RunMode.SERVER:
                if TARGET:
                    await udp.send(payload, TARGET)
            else:
                await udp.send(payload)

    asyncio.run(func(tun, udp))


async def relay_udp(udp, tun):
    print('begin relay udp')
    global TARGET
    while True:
        data, addr = await udp.recv()

        if VERBOSE:
            print('receive udp package with length:', len(data))

        TARGET = addr

        payload = try_decrypt(data)
        tun.write(payload)

        pkt = IP(payload)
        print('udp from', pkt.src, '->', pkt.dst)

async def route(tun: Tunnel):
    if MODE == RunMode.SERVER:
        udp = await asyncio_dgram.bind(("0.0.0.0", PORT))
    else:
        # TODO captch exception
        udp = await asyncio_dgram.connect((SERVER, PORT))

    # relay tun, as os.write and os.read dose not support async so use multi thread here
    thread = threading.Thread(target=relay_tun, args=(tun, udp))
    thread.start()

    tasks = [relay_udp(udp, tun)]
    await asyncio.gather(*tasks)


def main():    
    if MODE == RunMode.SERVER:
        ip = '192.168.2.1'
    else:
        ip = '192.168.2.2'

    tun = Tunnel('my_tun', ipaddress.ip_address(ip))
    tun.up()

    asyncio.run(route(tun))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Fast VPN', add_help=False)
    parser.add_argument('-s', '--server', help='server address')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('-k', '--key', help='used for crypto')
    parser.add_argument('-p', '--port', type=int, help='port for udp')
    parser.add_argument('-g', '--generate', action='store_true', help='generate a key')

    args = parser.parse_args()

    VERBOSE = args.verbose

    if args.generate:
        key = Cipher.generate_key()
        print('Generate key:', key)
        exit(0)

    if args.port:
        PORT = args.port

    if args.key:
        key = bytearray.fromhex(args.key)
        key_length = len(key)
        if key_length not in [16, 24, 32]:
            print('Invalid key, key length must be 16, 24, 32')
            exit(-1)

        Cipher.key = key
        ENABLE_CRYPTO = True
        print('Enable crypto with key:', args.key)
    else:
        print('Please set crypto key')
        exit(-1)

    if args.server:
        SERVER = args.server
        MODE = RunMode.CLIENT
        print(f'[client] connect to {SERVER}:{PORT}')
    else:
        MODE = RunMode.SERVER
        print('[server] has start')

    main()