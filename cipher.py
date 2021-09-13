from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Cipher:
    key: str = None
    header = b'fastvpn'

    @classmethod
    def encrypt(cls, plaintext: bytes) -> bytes:
        assert cls.key, 'Please set crypto key'

        nonce = get_random_bytes(12)
        cipher = AES.new(cls.key, AES.MODE_GCM, nonce=nonce)
        if cls.header:
            cipher.update(cls.header)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce + ciphertext + tag
    
    @classmethod
    def decrypt(cls, ciphertext) -> bytes:
        assert cls.key, 'Please set crypto key'

        if len(ciphertext) <= 16:
            return None

        nonce = ciphertext[:12]
        cipher = AES.new(cls.key, AES.MODE_GCM, nonce=nonce)
        if cls.header:
            cipher.update(cls.header)
        return cipher.decrypt_and_verify(ciphertext[12:-16], ciphertext[-16:])

    @staticmethod
    def generate_key(length: int = 16) -> str:
        assert length == 16 or length == 24 or length == 32, 'Key length must be 16, 24, 32'
        return get_random_bytes(length).hex()


def test():
    Cipher.key = bytearray.fromhex('aea5b22e73b0a91e7c16c16c710de73c')
    print('key', Cipher.key.hex())

    cipher = Cipher()

    plaintext = b'helloworld'
    ciphertext = cipher.encrypt(plaintext)
    result = cipher.decrypt(ciphertext)

    assert(plaintext == result)
    assert(b"hello".hex() == "hello".encode().hex())

if __name__ == '__main__':
    try:
        test()
    except ValueError as e:
        if e.args[0] == 'MAC check failed':
            print('Invalid key')



