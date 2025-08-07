## Recherche et navigation
- `pwd` : Affiche le chemin courant
- `ls` : Liste les fichiers du dossier courant
- `lsblk` : Liste les disques et partitions montées
- `locate <nom_du_fichier>` : Recherche un fichier dans le système
- `which <nom_de_commande>` : Donne le chemin de l'exécutable d'une commande

## Historique & Enregistrement
- `history` : Affiche l'historique des commandes
- `script mon_fichier_log.txt` : Enregistre toute la session dans un fichier texte

## Réseau & Services
- `telnet <host> 80` : Teste la connexion à un service
  - Exemple :
    ```
    telnet example.com 80
    GET / HTTP/1.1
    Host: example.com
    ```

- `finger @<ip>` : Liste les utilisateurs d'une machine distante
- `finger fabiano@<ip>` : Obtenir des informations spécifiques sur un utilisateur (parfois mdp)
- `wget <url>` : Télécharge un fichier via HTTP/HTTPS/FTP
- `wget -r -np -nH --cut-dirs=0 http://192.168.1.100:8000/`:  Récupérer tous les fichiers/dossiers d un repertoire sur lequel tourne un web serveur en python

## Crypto & certificats
- `openssl x509 -in key.pem -text -noout` : Analyse un certificat X.509

## Bases de données
- `sqlite3 filedb.sqlite` : Lance une session SQLite sur un fichier `.sqlite`

## Fichiers
- `file <nom_du_fichier>` : Donne le type du fichier



---