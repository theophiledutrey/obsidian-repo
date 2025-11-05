# Web (applications)

(questions orientées exploitation / reconnaissance / post-exploit web). [CyberSapiens+1](https://cybersapiens.com.au/most-asked-web-application-penetration-testing-interview-questions-and-answers/?utm_source=chatgpt.com)

1. Explique le modèle d’attaque pour une application web (recon → fuzzing → exploitation → post-exploitation).

Pour attaquer une application web je fonctionne en étapes : reconnaissance passive d’abord (collecte de sous-domaines, crawl), mapping des endpoints puis fuzzing ciblé avec des outils comme Burp/ffuf. Ensuite je fais des tests manuels sur les vecteurs identifiés (auth, upload, sérialisation) ; si j’obtiens un accès je passe au post-exploitation pour récupérer credentials et pivoter tout en respectant les règles d’engagement.

2. Donne 3 méthodes pour trouver/contourner une authentification vulnérable (session fixation, JWT manipulation, bruteforce + lockout).

Pour tester une authentification je commence par vérifier la régénération des sessions après login (pour détecter une session fixation), j’examine les JWT pour des erreurs de configuration (alg=none, confusion RS/HS, kid mal géré), puis j’évalue les protections contre le brute-force et le credential stuffing avant d’envisager une attaque automatisée.

2. Comment détecter et exploiter une SQL injection (typesSQLi, payloads, exfiltration via time-based)?

Pour détecter une SQLi je fais d’abord des tests simples non bruyants (injection de guillemets, tautologies) et j’observe erreurs ou différences booléennes ; si rien n’apparaît je passe au time-based (SLEEP/IF) pour extraire les données bit par bit. J’automatise quand nécessaire (sqlmap) mais je privilégie la compréhension manuelle du point d’injection pour éviter les faux positifs.

3. Explique XSS (stocké vs réfléchi vs DOM). Donne un exemple d’exfiltration de cookie via XSS.

Le XSS réfléchi renvoie le payload immédiatement via l’URL ou un champ, le XSS stocké est persistant côté serveur et le DOM-based est purement côté client — c’est souvent le plus subtil. Pour exfiltrer un cookie en preuve de concept on peut par exemple envoyer `document.cookie` vers un serveur contrôlé ; en production je mentionne toujours les mitigations : HttpOnly, SameSite et CSP.

3. Qu’est-ce que CSRF et comment l’atténuer / l’exploiter si l’application est vulnérable ?

Le CSRF consiste à déclencher une action au nom d’un utilisateur authentifié sans son consentement. Je vérifie la présence d’un token anti-CSRF unique, la validation des headers Origin/Referer et l’utilisation de SameSite sur les cookies ; si ces protections manquent, un POST depuis un site tiers peut suffire à franchir la protection.

3. Comment tu ferais pour contourner une WAF/IPS côté application ? (bypass d’encodage, fragmentation, polymorphisme)

Contourner une WAF se fait par itérations : changer l’encodage (URL, double-encoding), fragmenter le payload, ajouter commentaires ou variations de casse, et tester des obfuscations polymorphes pour identifier la règle bloquante. Je le fais de manière contrôlée et itérative pour rester discret et ne pas provoquer d’indisponibilité.

3. Comment analyser un JWT mal configuré ? (alg=none, clé faible, alg confusion)
    
4. Quelles sont les étapes pour trouver une RCE (remote code execution) sur une app (upload, template injection, deserialization) ?
    
5. Explique les risques d’une désérialisation non sécurisée (Java/.NET/PHP) et donne une méthode d’exploitation.
    
6. Parle-moi d’un cas réel d’exploitation que tu as réalisé (ou, si hypothétique, décris le plan d’attaque).
    

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
    
5. Décrire la création d’un implant C2 : common techniques pour éviter l’AV/EDR (mutations, off-the-shelf vs custom).
    
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