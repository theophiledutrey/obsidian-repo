## 1) Flux d'authentification Kerberos dans AD (TGT, TGS)

### Étapes principales

1. **Authentification initiale (AS — Authentication Service)**
   - Le **client** (utilisateur) envoie une requête **AS-REQ** au KDC en indiquant son principal (ex: `alice@DOMAINE.LOCAL`).
   - Si la pré-authentification est requise, le client prouve connaissance du mot de passe via `PA-ENC-TIMESTAMP` ou un mécanisme équivalent.
   - Le KDC/AS répond par un **AS-REP** qui contient :
     - un **TGT** (Ticket Granting Ticket) chiffré avec la clé longue-terme du **TGS** (donc uniquement déchiffrable par le TGS),
     - une **enc_part** chiffrée avec la clé dérivée du mot de passe du client (K_client) contenant la **clé de session** `K_c_tgs` et d'autres infos.
   - Le client déchiffre l'enc_part avec sa clé dérivée du mot de passe ; s'il réussit il récupère `K_c_tgs`.

2. **Obtention de ticket de service (TGS — Ticket Granting Service)**
   - Le client envoie une **TGS-REQ** au TGS contenant :
     - le **TGT** reçu précédemment,
     - un **authenticator** (contenant identifiant client + timestamp) chiffré avec `K_c_tgs`.
   - Le TGS déchiffre le TGT pour obtenir `K_c_tgs`, déchiffre l'authenticator et vérifie fraîcheur/identité.
   - Si tout est valide, le TGS renvoie une **TGS-REP** contenant un **service ticket** chiffré avec la clé du service ciblé et une copie de la clé de session pour le client.

3. **Accès au service (AP — Application Service Exchange)**
   - Le client envoie au serveur cible le **service ticket** + un nouvel **authenticator** chiffré avec la clé de session client–service.
   - Le serveur déchiffre le ticket (avec sa clé stockée, ex: keytab) et vérifie l'authenticator : si valide, il accorde l'accès.

### Pourquoi le **TGT** existe (vs stocker l'état côté KDC)
- **Statelessness & scalabilité** : le TGT est auto-contenant et évite d'avoir une base de sessions partagée entre AS/TGS ou plusieurs KDCs.
- **Moins de surface d'attaque** : pas de stockage central de clés de session en clair ; un attaquant devrait compromettre la clé du TGS (`krbtgt`) pour lire/forger des TGT.
- **Fonctionnalités** : flags (renewable, forwardable, proxiable) et champs (expiration, realm) sont embarqués dans le ticket, facilitant délégation et cross-realm.

### Comment le client prouve qu'il connaît `K_c_tgs`
- Le client chiffre un **authenticator** (timestamp + principal) avec `K_c_tgs` et l'envoie au TGS. Si le TGS peut déchiffrer et valider le timestamp/freshness, alors il sait que le client connaît `K_c_tgs` sans que le mot de passe ait transité.
- C'est la preuve cryptographique : réussite du déchiffrement + concordance des champs.

---

## 2) Kerberoasting — concept et méthode (synthèse adaptée)

### Principe
- **Kerberoasting** cible les **comptes de service** qui possèdent un **SPN (Service Principal Name)**.
- Quand un client demande un ticket pour un SPN, le TGS renvoie un **service ticket** dont la partie chiffrée (enc_part) est chiffrée avec une clé liée au mot de passe du compte de service.
- Un attaquant authentifié peut demander ces tickets légitimement, extraire le blob chiffré et tenter de récupérer le mot de passe **hors-ligne** (cracker le « hash » chiffré).

### Étapes (conceptuelles)
1. Énumérer les comptes ayant un **SPN** (ex: via LDAP ou `Get-NetUser -SPN`).
2. Demander un ticket TGS pour le SPN ciblé (comportement client normal).
3. Exporter le ticket chiffré (outil d'audit) et lancer une attaque hors-ligne pour cracker la clé dérivée du mot de passe du compte de service.

> **Remarque** : ici on attaque le **mot de passe du compte de service**, pas la clé de session transitoire.

### Conditions favorables
- Comptes de service basés sur des comptes utilisateur (pas gMSA), avec SPN configuré.
- Mots de passe faibles ou peu/rarement renouvelés.
- Chiffrement faible (ex: RC4) ou absence de contrôles supplémentaires.

### Indicateurs de détection
- Pics de requêtes **TGS-REQ** pour de nombreux SPN depuis le même compte/machine.
- Énumération massive d'objets avec SPN via LDAP.
- Requêtes anormales de TGS suivies d'aucune authentification côté service (pattern d'énumération).

### Mitigations clés
- Préférer **gMSA / Managed Service Accounts** (mot de passe géré automatiquement).
- Mots de passe forts et rotation régulière pour comptes de service.
- Restreindre le nombre de comptes avec SPN.
- Forcer l'utilisation d'encryption moderne (AES) et désactiver/en limiter RC4.
- Mettre en place la détection SIEM décrite ci‑dessus.

---

## 2 bis) AS-REP Roasting — explication technique et contre-mesures

### Principe
- **AS-REP Roasting** exploite les comptes pour lesquels **la pré-authentification Kerberos est désactivée** (`Do not require Kerberos preauthentication` dans AD).
- Si la pré-authentification est désactivée, l'AS répondra à une **AS-REQ** sans challenger le client : la réponse `AS-REP` contient un `enc_part` chiffré avec la clé dérivée du mot de passe du compte.
- L'attaquant récupère ce `enc_part` et tente un bruteforce hors-ligne pour retrouver le mot de passe (ou la clé dérivée).

### Ce qu'on brute-force réellement
- On testera des mots de passe candidats, on en dérive la clé (selon l'enctype, salt, iterations) et on tente de déchiffrer/valider l'`enc_part`.
- Validation : si le déchiffrement produit un format attendu (checksum, timestamp valide), le mot de passe candidat est probablement correct.

### Conditions requises
- Compte ciblé avec **pré-auth désactivée**.
- Mot de passe crackable (faible, pas de longueur/complexité suffisante).

### Détections
- AS-REQs en masse pour comptes ayant le flag « does not require preauthentication ».
- Réponses AS-REP anormales corrélées à des activités d'énumération.
- Surveillance des modifications d'attributs AD liés à la pré-authentication.

### Mitigations
- **Activer la pré-authentification** pour tous les comptes (désactiver l'option « does not require preauthentication »).
- Exiger des mots de passe longs et complexes.
- Restreindre/mettre sous contrôle les comptes legacy qui nécessitent la pré-auth désactivée.
- Mettre en place MFA (Smartcard, certificat) pour réduire la dépendance au seul mot de passe.

---

## Glossaire rapide
- **KDC** : Key Distribution Center (AS + TGS).
- **TGT** : Ticket Granting Ticket. Ticket chiffré que le client présente au TGS.
- **TGS** : Ticket Granting Service. Délivre les tickets de service.
- **Ticket** : blob chiffré contenant identité, clé de session, durée, flags.
- **SPN** : Service Principal Name (ex: `HTTP/www.example.com`).
- **gMSA / MSA** : comptes de service gérés (rotations automatiques de mot de passe).


---

## 3) AS-REP roasting — quand applicable et comment

- **Principe**
  - Si un compte utilisateur/service n’exige pas l’authentification pre-auth (PreAuthentication disabled), on peut demander un AS-REP qui est chiffré avec une clé dérivée du mot de passe du compte ; cet AS-REP peut être bruteforcé hors-ligne.
- **Détection**
  - Vérifier l’attribut `DONT_REQUIRE_PREAUTH` sur les comptes (`Get-ADUser -Properties * | where { $_.UserAccountControl -band 4194304 }`).
- **Mitigations**
  - Activer pre-auth pour tous les comptes, forcer mots de passe forts, monitoring des requêtes AS-REP.
- **Glossaire rapide**
  - **Pre-auth** : mécanisme où le client prouve son identité avant que le KDC délivre des tickets.
  - **AS-REP roasting** : extraction brute-force hors-ligne d’un AS-REP pour retrouver mot de passe.

---

## 4) Pass-the-Hash (PtH) et Pass-the-Ticket (PtT)

- **Pass-the-Hash**
  - Réutiliser le NTLM hash d’un compte pour s’authentifier sans connaître le mot de passe en clair.
  - Exécution typique : extraire hash (mimikatz, secretsdump) et utiliser `psexec`, `wmiexec` ou outils équivalents pour s’authentifier.
- **Pass-the-Ticket**
  - Réutiliser un ticket Kerberos (TGT/TGS) obtenu pour s’authentifier sur d’autres services sans mot de passe.
  - Golden Ticket = ticket forgé en utilisant la clé du domaine (`krbtgt`) permettant accès quasi-illimité.
- **Mitigations**
  - LSA protection, rotation régulière du compte `krbtgt` (double rotation recommended), limiter privilèges d’administration locale, use of Protected Users group and Credential Guard.
- **Glossaire rapide**
  - **Golden Ticket** : TGT forgé avec la clé Kerberos du domaine (`krbtgt`) donnant accès complet.
  - **Credential Guard** : protection Microsoft isolant secrets d'authentification.
