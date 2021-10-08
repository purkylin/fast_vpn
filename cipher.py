from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Cipher:
    header = b'fastvpn'

    def __init__(self, key, increment=False):
        self.key = bytearray.fromhex(key)
        # Used for tcp inc iv
        self.increment = increment
        self.iv = bytearray(12)

    def encrypt(self, payload: bytes) -> bytes:
        if self.increment:
            nonce = self.iv
            self.iv = inc_nonce(self.iv)
        else:
            nonce = get_random_bytes(12)

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        cipher.update(Cipher.header)
        ciphertext, tag = cipher.encrypt_and_digest(payload)

        if self.increment:
            return ciphertext + tag
        else:
            return cipher.nonce + ciphertext + tag
    
    def decrypt(self, payload) -> bytes:
        if len(payload) <= 16:
            return None

        if self.increment:
            nonce = self.iv
            self.iv = inc_nonce(self.iv)
            ciphertext = payload[:-16]
        else:
            nonce = payload[:12]
            ciphertext = payload[12:-16]

        tag = payload[-16:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        cipher.update(Cipher.header)

        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def generate_key(length: int = 16) -> str:
        assert length == 16 or length == 24 or length == 32, 'Key length must be 16, 24, 32'
        return get_random_bytes(length).hex()

def inc_nonce(bytes):
    assert len(bytes) > 1

    buffer = bytes[:]
    arr = list(buffer)

    index = len(buffer) - 1
    overflow = 1

    while index >= 0 and overflow == 1:
        if arr[index] >= 255:
            arr[index] = 0
        else:
            arr[index] = arr[index] + 1
            break
        index -= 1

    return bytearray(arr)


def test():
    key = '6882ea6b1a0c71a2a249f8407a56019d'
    cipher = Cipher(key)

    plaintext = b'helloworld'
    ciphertext = cipher.encrypt(plaintext)
    result = cipher.decrypt(ciphertext)

    assert(plaintext == result)
    assert(b"hello".hex() == "hello".encode().hex())

    n1 = bytearray([0x00, 0x00, 0x00, 0x01])
    assert(inc_nonce(b'\x00\x00\x00\x00') == b'\x00\x00\x00\x01')
    assert(inc_nonce(b'\x00\x00\x00\xff') == b'\x00\x00\x01\x00')
    assert(inc_nonce(b'\xff\xff\xff\xff') == b'\x00\x00\x00\x00')
    assert(inc_nonce(b'\x00\xff\xff\xff') == b'\x01\x00\x00\x00')
    print('test ok')

    cipher2 = Cipher(key, True)
    assert cipher2.encrypt(b'\x00\x3b').hex() == '31c83dacefffa7e78da5156768ea9b3195f1'

    cipher3 = Cipher(key, True)
    assert cipher3.decrypt(bytearray.fromhex('31c83dacefffa7e78da5156768ea9b3195f1')) == b'\x00\x3b'


if __name__ == '__main__':
    try:
        test()
    except ValueError as e:
        if e.args[0] == 'MAC check failed':
            print('Invalid key')



