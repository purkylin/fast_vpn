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

    | length(2) | length tag(16) | ciphertext | tag(16) |
    | --------- | ---------------| ---------- | ------- |

* UDP

    | nonce(12)  | ciphertext | tag(16) |
    |  --------- | ---------  | ------  |


## Usage

* Server

```bash
python tcp.py

```

* Client

```bash
python tcp.py -k aea5b22e73b0a91e7c16c16c710de73c -s <server_ip> 
```

## iOS App(Open source)
 Comming