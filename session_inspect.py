import socket
import argparse
import os

socket_path = './.ds'


def server():
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(socket_path)

    while True:
        data, addr = s.recvfrom(100)
        print('receive', data.decode('utf-8'))


def client():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    while True:
        text = input()
        print('execute:', text)
        s.sendto(text.encode(), socket_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Fast VPN', add_help=False)
    parser.add_argument('-s', '--server', action='store_true', help='server')

    args = parser.parse_args()
    if args.server:
        server()
    else:
        client()
