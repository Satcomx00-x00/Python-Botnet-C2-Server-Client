#!/bin/python3
# -*- coding: utf-8 -*-
import pydle
from requests import get

ip = get('https://api.ipify.org').text

class MyOwnBot(pydle.Client):
    async def on_connect(self):
         await self.join('#net')

    async def on_message(self, target, source, message):
         # don't respond to our own messages, as this leads to a positive feedback loop
        if message == "!ip":
            await self.message(target, format(ip))


client = MyOwnBot("random", realname="bot")
client.run('localhost', tls=False, tls_verify=False)

