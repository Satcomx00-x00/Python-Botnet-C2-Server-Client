from base64 import b64encode, b64decode
from Crypto.Cipher import AES


class AESCipher:
    BLOCK_SIZE = 16
    KEY = b"ChdtkSnUtJ3yz8Uq3SJJ6TTZ"  # 24 bytes key (must be 16, 24, or 32 bytes long)

    @staticmethod
    def pad(s):
        pad_len = AESCipher.BLOCK_SIZE - (len(s) % AESCipher.BLOCK_SIZE)
        return s + chr(pad_len) * pad_len

    @staticmethod
    def unpad(s):
        pad_len = ord(s[-1])
        return s[:-pad_len]

    @staticmethod
    def encrypt(message):
        raw = AESCipher.pad(message)
        cipher = AES.new(AESCipher.KEY, AES.MODE_ECB)
        return b64encode(cipher.encrypt(raw.encode("utf-8"))).decode("utf-8")

    @staticmethod
    def decrypt(enc):
        enc = b64decode(enc)
        cipher = AES.new(AESCipher.KEY, AES.MODE_ECB)
        return AESCipher.unpad(cipher.decrypt(enc).decode("utf-8"))
