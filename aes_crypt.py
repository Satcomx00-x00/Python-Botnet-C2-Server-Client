from base64 import b64encode, b64decode
from Crypto.Cipher import AES

class AESCipher:
    BLOCK_SIZE = 16
    KEY = b'ChdtkSnUtJ3yz8Uq3SJJ6TTZ'  # 24 bytes key (must be 16, 24, or 32 bytes long)

    @staticmethod
    def pad(s):
        return s + (AESCipher.BLOCK_SIZE - len(s) % AESCipher.BLOCK_SIZE) * chr(AESCipher.BLOCK_SIZE - len(s) % AESCipher.BLOCK_SIZE)

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]

    @staticmethod
    def encrypt(message):
        raw = AESCipher.pad(message).encode('utf-8')
        cipher = AES.new(AESCipher.KEY, AES.MODE_ECB)
        return b64encode(cipher.encrypt(raw)).decode('utf-8')

    @staticmethod
    def decrypt(enc):
        enc = b64decode(enc)
        cipher = AES.new(AESCipher.KEY, AES.MODE_ECB)
        return AESCipher.unpad(cipher.decrypt(enc)).decode('utf-8')
