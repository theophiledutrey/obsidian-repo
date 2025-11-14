
![[IMG-20251110182159311.png]]


![[IMG-20251110181820897.png]]



![[IMG-20251111022743321.png]]

[CVE-2025-24071](https://github.com/0x6rss/CVE-2025-24071_PoC)

![[IMG-20251114152929514.png]]

On upload le fichier zip créé par le poc de la CVE et:

![[IMG-20251114152916183.png]]

![[IMG-20251114153011461.png]]

dksehdgh712!@#

## 1. Capture et Crack du Hash

### Objectif

Obtenir l'identité d'un utilisateur AD en capturant son authentification
sur un serveur SMB contrôlé.

### Hash NTLMv2 Capturé

    WEB_SVC::NANOCORP:... (NTLMv2)

### À quoi sert NTLMv2 ?

-   Protocole d'authentification Windows challenge/réponse\
-   Ne permet pas le Pass-The-Hash\
-   Je dois le cracker pour obtenir le mot de passe

### Crack du hash

Après crack :

    WEB_SVC / dksehdgh712!@#

### Résultat

Je possède un vrai compte AD → **WEB_SVC**.

------------------------------------------------------------------------

## 2. Reconnaissance SMB

### À quoi sert SMB ?

SMB permet : - les partages réseaux\
- l'accès à `ADMIN$`, `C$`, `SYSVOL`\
- la communication AD via IPC\$

Utile en pentest pour : - analyser les permissions\
- tenter de lire SYSVOL pour récupérer des secrets\
- identifier des chemins d'attaque potentiels

### Commande utilisée

    nxc smb 10.10.11.93 -u WEB_SVC -p 'dksehdgh712!@#'

![[IMG-20251114165833769.png]]

### Informations obtenues

-   Connexion réussie\
-   Le serveur est un **DC Windows Server 2022**\
-   SMB Signing activé\
-   SMBv1 désactivé

### Shares SMB

    nxc smb 10.10.11.93 --shares

![[IMG-20251114170034439.png]]

### Exploration SYSVOL

    smbclient //10.10.11.93/SYSVOL -U WEB_SVC

Résultat : pas de secrets sensibles.

------------------------------------------------------------------------

## 3. LDAP Enumération

### À quoi sert LDAP ?

LDAP permet d'obtenir : - les utilisateurs\
- les groupes\
- les machines\
- les attributs AD

C'est la base de l'énumération Active Directory.

### Groupes

    nxc ldap 10.10.11.93 -u WEB_SVC -p ... --groups

Je récupère : Administrators, Domain Admins, Enterprise Admins...

### Utilisateurs

![[IMG-20251114170138066.png]]

### Pourquoi c'est pertinent ?

Les comptes de service comme **monitoring_svc** : - ont souvent des
droits excessifs\
- utilisent des mots de passe faibles\
- sont liés à des services vulnérables

------------------------------------------------------------------------

## 4. Tentative Kerberoast

### À quoi sert Kerberoasting ?

Permet d'obtenir un TGS chiffré par le mot de passe d'un **service
Kerberos** via son SPN.\
But : cracker le mot de passe du compte.

### Commande

    nxc ldap --kerberoasting kerb.txt

Résultat :

    No entries found

Aucun SPN disponible → impossible de kerberoaster.

------------------------------------------------------------------------

## 5. RPC Enumeration

### À quoi sert RPC ?

RPC permet : - l'énumération des utilisateurs\
- l'accès à des attributs détaillés\
- la lecture de groupes\
- la récupération d'informations réseau

Très utile lorsque LDAP est limité.

### Commandes

Connexion :

    rpcclient -U WEB_SVC 10.10.11.93

Enum utilisateurs :

    enumdomusers

![[IMG-20251114170256840.png]]

Informations détaillées :

    queryuser monitoring_svc

### Informations obtenues

![[IMG-20251114170340507.png]]

Le compte **monitoring_svc** : - actif\
- mot de passe récent\
- probablement lié à un service de supervision

Cible d'escalade potentielle.

------------------------------------------------------------------------

## 6. Test WinRM

### À quoi sert WinRM ?

WinRM est un moyen puissant d'obtenir un **shell PowerShell à distance**
sur le serveur.

### Test

    nxc winrm 10.10.11.93 -u WEB_SVC -p ...

Résultat : accès refusé → pas membre de *Remote Management Users*.

------------------------------------------------------------------------

## 7. BloodHound

### À quoi sert BloodHound ?

-   cartographie complète de l'Active Directory\
-   visualisation des groupes, permissions, ACLs\
-   identification des chemins d'attaque vers Domain Admin

### Récupération des données

    bloodhound-python -u WEB_SVC -p ... -d nanocorp.htb -ns 10.10.11.93 -dc DC01.nanocorp.htb -c All

![[IMG-20251114170414692.png]]

![[IMG-20251114170505871.png]]


### Analyse

-   Aucun chemin direct depuis WEB_SVC\
-   Seulement 1 machine : DC01\
-   monitoring_svc identifiée comme cible potentielle\
-   WEB_SVC n'a aucun privilège exploitable via AD

### Conclusion BloodHound

Une escalade AD classique n'est pas possible.\
Il faudra exploiter un **service**, une **application**, ou
**monitoring_svc**.

```
[Nov 14, 2025 - 19:07:38 (CET)] exegol-htb-vpn /workspace # bloodyAD --host 10.10.11.93 -u WEB_SVC -p 'dksehdgh712!@#' -d nanocorp.htb set password "monitoring_svc" "Password1234"

[+] Password changed successfully!

```