# Fast VPN

Fast & Simple VPN, speeding up your netowork

## Feature

* Use `TCP` or `UDP` to transport
* Fast
* Simple protocol
* Encrypt(AEAD)
* Use `TUN` to bridge server and client

## Payload
* TCP (nonce increment, start with zero)

    | length | length tag | ciphertext | tag(16) |
    | ------ | -----------| ---------- | ------- |

* UDP

    | nonce(12)  | ciphertext | tag(16) |
    |  --------- | ---------  | ------  |


## Usage

* IP forward
```bash
sysctl -w net.ipv4.ip_forward=1

iptables -t nat -I POSTROUTING -s 192.168.2.1/24 ! -d 192.168.2.1/24 -j MASQUERADE
```

* Server

```bash
python tcp.py

```

* Client

```bash
python tcp.py -k aea5b22e73b0a91e7c16c16c710de73c -s <server_ip> 
```