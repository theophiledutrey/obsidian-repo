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

