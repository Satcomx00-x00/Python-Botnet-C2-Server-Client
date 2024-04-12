#!/bin/python3
# -*- coding: utf-8 -*-
import socket
import threading


class DialogueTCP(threading.Thread):
    def __init__(self, client, infos):
        threading.Thread.__init__(self)
        self.client = client
        self.infos = infos

    def run(self):
        print("connexion établie avec ", self.infos)
        message = ""
        while message.upper() != "FIN":
            message = self.client.recv(1024).decode("utf8")
            print("Message de ", self.infos, " - ", message)
            self.client.send("Message OK !".encode("utf8"))
        self.client.close()


def main():
    connexions = []
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hote = "185.220.100.245"
    print(hote)
    port = 2429
    serveur.bind((hote, port))
    print("Serveur en attente de connexion")
    serveur.listen(5)
    while True:
        client, infos = serveur.accept()
        connexions.append(DialogueTCP(client, infos))
        connexions[-1].start()
    for th in connexions:
        th.join()
    serveur.close()


if __name__ == "__main__":
    main()
