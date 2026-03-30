## Informations à récupérer:

### Sytème:
- Espace disque
- Crontab
- SUID
- Capabilities
- SSH config 
- Fichier sensibe
- Dossier sensible
- Version des binaires sensibles
- AppArmor 



### Network:
- Services
- Interface réseau
- Route réseau

### Users:
- Password policies
- /etc/shadow
- Liste Utilisateurs - Groupe - Shell - UID = 0 ?
- Droit Sudo 
- Info Mot de passe 


find /home /root -maxdepth 2 \( -name .rhosts -o -name .netrc \) 2>/dev/null -> Fichier sensible 

9ccioRccuyo3go4v55Xih2aGgJB8