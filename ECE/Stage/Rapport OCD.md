L'entretien à commencé avec un test technique de une heure. J'avais accès à une IP publique: 15.237.216.194
Dans le cadre d'un pentest, je commence par un scan réseau pour découvrir les différents services disponibles sur la machine.
J'utilise donc le commande:
```
nmap -A 15.237.216.194
```

Cette commande correspond à un scan agressif (`-A`) de la cible. Elle permet d’obtenir rapidement un maximum d’informations en une seule étape : détection des ports ouverts, identification des services et de leurs versions et détection du système d’exploitation.
Dans un contexte de pentest réel,  ce type de scan ne doit pas être utilisé si on veut être discret . Cependant, dans le cadre de ce défi technique, l’objectif était d’obtenir rapidement une vision globale de la surface d’attaque de la machine. L’utilisation d’un scan agressif n’avait donc aucune conséquence et permettait d’optimiser le temps imparti pour l’analyse et l’exploitation potentielle des services exposés.
Voici le résultat du scan:
![[Pasted image 20251210235338.png]]

Le scan révèle 3 services importants:
- Un service SSH qui tourne sur le port 22. La version de OpenSSH est stable, elle ne laisse aucune attaque directe possible sur le service. Dans le cadre d'un exercice technique, je devine qu'on pourra s'authentifier en SSH via des credentials récupérés après une potentielle RCE.
- Un service web est exposé sur le port 80. On observe déjà une information importante : le site web donne accès à un dépôt GitHub, probablement le dépôt de l’application web qui tourne sur ce port.
- Un service web est egalement disponible sur le port 8080. Cela donne l'accès à une page login intitulée “Testa Motors - Employees Listing”, ce qui suggère une application interne potentiellement destinée aux employés , probablement exposée via un reverse proxy.

Je commence donc une analyse du site web sur le port 80. A première vu, aucun chemin suggère une exploit