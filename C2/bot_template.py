#!/bin/python3
# -*- coding: utf-8 -*-
import pydle
class MyOwnBot(pydle.Client):
    async def on_connect(self):
         await self.join('#net')
         await self.message(target, "je suis connnecté")
client = MyOwnBot("Michel", realname="bot")
client.run('109.17.229.155', tls=False, tls_verify=False)

