# Fast VPN

Fast & Simple VPN, speeding up your netowork

## Feature

* Use `UDP` to transport
* Fast
* Simple protocol
* Encrypt(AEAD)
* Use `TUN` to bridge server and client

## Limit
* Only one client same time

## Payload

|            |            |         |
|  --------- | ---------  | ------  |
| nonce(12)  | ciphertext | tag(16) |


## Usage

* Server

```bash
python vpn.py -k aea5b22e73b0a91e7c16c16c710de73c -v
iptables -t nat -I POSTROUTING -s 192.168.2.1/24 ! -d 192.168.2.1/24 -j MASQUERADE
```

* Client


```bash
python vpn.py -k aea5b22e73b0a91e7c16c16c710de73c -s <server_ip> 
```