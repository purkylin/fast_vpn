import socket
import threading
from tun import Tunnel
import argparse
from struct import *
from scapy.all import *
import os
from cipher import Cipher
from util import run

IS_SERVER = True
MTU = 1500
TUNNEL_ADDRESS = '10.10.0.1'
ENABLE_CRYPTO = True

# DEBUG Switch
ENABLE_LOG = False


class TCP:
    def __init__(self, key):
        self.sessions = {}
        self.tun = None
        self.mutex = threading.Lock()
        self.key = key
        self.ciphers = {}

    def clear_session(self, peer):
        print('clear session')
        peer.close()

        # safe to modify sessions
        self.mutex.acquire()
        for item in self.sessions.keys():
            if self.sessions[item][0] is peer:
                del self.sessions[item]
                break
        self.mutex.release()

    def write_packet(self, peer, data, cipher=None):
        if ENABLE_CRYPTO:
            length_data = pack('>H', len(data))
            payload = cipher.encrypt(length_data)
            payload += cipher.encrypt(data)

            sent_total = 0
            while sent_total < len(payload):
                count = min(MTU - 100, len(payload))
                chunk = payload[sent_total:sent_total+count]
                sent = peer.send(chunk)
                sent_total += sent

            assert sent_total == len(payload), 'Error, data not full written'
        else:
            length_data = pack('>H', len(data))
            payload = length_data + data
            sent = peer.send(payload)
            assert sent == len(payload), 'Error, data not full written'

    def read_length(self, peer, length):
        chunks = bytearray()
        read_length = 0

        assert length <= MTU, f'Invalid length {length}'

        while read_length < length:
            chunk = peer.recv(min(length - read_length, MTU))
            if not chunk:
                return chunks

            chunks.extend(chunk)
            read_length += len(chunk)

        return chunks

    def read_packet(self, peer, cipher=None):
        if ENABLE_CRYPTO:
            encrypted_length_data = self.read_length(peer, 18)
            if not encrypted_length_data:
                return
            assert len(
                encrypted_length_data) == 18, 'Error, not consitent length'

            length_data = cipher.decrypt(encrypted_length_data)
            (length, ) = unpack('>H', length_data)

            encrypted_payload_data = self.read_length(peer, length + 16)
            if not encrypted_payload_data:
                return
            assert len(encrypted_payload_data) == (
                length + 16), 'Error, not consitent length'
            payload = cipher.decrypt(encrypted_payload_data)
            return payload
        else:
            # TODO: User read_length
            length_data = peer.recv(2)
            if not length_data:
                return

            assert len(length_data) == 2, 'Error, not consitent length'
            (length, ) = unpack('>H', length_data)

            payload = peer.recv(length)
            if not payload:
                return

            assert len(payload) == length, 'Error, not consitent length'
            return payload

    def read_tun(self):
        while True:
            data = self.tun.read(MTU)
            print('read tun', len(data))
            ip = IP(data)
            if ENABLE_LOG:
                print(
                    f'receive packet {ip.src} -> {ip.dst} {len(data)} bytes from tun')

            result = self.sessions.get(ip.dst)
            if result:
                self.write_packet(result[0], data, result[1])
            else:
                if ENABLE_LOG:
                    print('not found', ip.dst, len(self.sessions))

    def create_session(self, peer):
        cipher = Cipher(self.key, True)
        try:
            while True:
                payload = self.read_packet(peer, cipher)
                if not payload:
                    print('read payload failed')
                    break

                ip = IP(payload)
                if ENABLE_LOG:
                    print(
                        f'receive tcp packet {ip.src} -> {ip.dst} {len(payload)} bytes')

                if ip.src not in self.sessions.keys():
                    self.mutex.acquire()
                    self.sessions[ip.src] = (peer, Cipher(self.key, True))
                    self.mutex.release()

                self.tun.write(payload)
        except Exception as e:
            print('read tcp data failed')
        finally:
            print('disconnect')
            self.clear_session(peer)

    def parse_command(self, cmd):
        '''
        Parse and run command.
        '''

        if cmd == 'toggle_log':
            global ENABLE_LOG
            ENABLE_LOG = not ENABLE_LOG
        elif cmd == 'list_session':
            print(self.sessions)
        elif cmd == 'count_session':
            print('sessions count', len(self.sessions))
        else:
            print('unknown command')

    def debug_socket(self):
        '''
        Setup debug socket.
        '''

        socket_path = './.ds'
        if os.path.exists(socket_path):
            os.unlink(socket_path)

        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(socket_path)

        while True:
            data, addr = s.recvfrom(100)
            cmd = data.decode('utf-8').strip()
            print('command', cmd)
            self.parse_command(cmd)

    def setup_tunnel(self):
        self.tun = Tunnel('fastvpn', TUNNEL_ADDRESS)
        self.tun.up()
        tun_thread = threading.Thread(target=self.read_tun)
        tun_thread.setDaemon(True)
        tun_thread.start()

    def setup_debug(self):
        debug_thread = threading.Thread(target=self.debug_socket)
        debug_thread.setDaemon(True)
        debug_thread.start()

    def setup_socket(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if IS_SERVER:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', port))
            s.listen(5)

            print(f'Start server at port: {port}, tun: {TUNNEL_ADDRESS}')

            while True:
                peer, addr = s.accept()
                print('new connection')
                t = threading.Thread(
                    target=self.create_session, args=(peer,))
                t.setDaemon(True)
                t.start()
        else:
            print(f'Connect to server {host}:{port}, tun: {TUNNEL_ADDRESS}')
            s.connect((host, port))
            cipher = None
            if ENABLE_CRYPTO:
                cipher = Cipher(self.key, True)
            self.sessions['10.10.0.1'] = (s, cipher)
            print('Connect success')
            self.create_session(s)

    def start(self, host, port):
        run('sysctl -w net.ipv4.ip_forward=1')
        run('iptables -t nat -I POSTROUTING -s 10.10.0.1/24 ! -d 10.10.0.1/24 -j MASQUERADE')

        try:
            self.setup_tunnel()
            self.setup_debug()
            self.setup_socket(host, port)
        except KeyboardInterrupt:
            pass
        finally:
            run('iptables -t nat -D POSTROUTING -s 10.10.0.1/24 ! -d 10.10.0.1/24 -j MASQUERADE')


def read_key(possible_key):
    '''
    Read crypto key from termianl or file
    '''

    key = possible_key
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
    parser.add_argument('-p', '--port', help='server port')
    parser.add_argument('-t', '--tunnel', help='tunnel address')
    parser.add_argument('-k', '--key', help='key')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')

    args = parser.parse_args()

    key = read_key(args.key)
    print('key:', key)

    if args.server:
        IS_SERVER = False

    if not IS_SERVER:
        TUNNEL_ADDRESS = args.tunnel or '10.10.0.3'

    server = TCP(key)
    server.start(args.server, args.port or 6565)
