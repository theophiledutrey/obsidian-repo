🧠 FICHE : XSS, SQLi, CSRF, SSRF
Par Stéphane Dutré – Cybersécurité

1️⃣ XSS — Cross-Site Scripting

Définition
Injection de JavaScript dans une page web, permettant à l’attaquant d'exécuter du code dans le navigateur de la victime.

Objectifs de l’attaquant
- Vol de cookies (sauf HttpOnly)
- Prise de contrôle de session
- Keylogging
- Defacement
- Pivot vers l’admin via les droits de la victime

Préventions principales
1. Output Encoding (la défense n°1)
Encoder selon le contexte :
- HTML → htmlspecialchars()
- JS → json_encode() / escape JS
- URL → urlencode()
- Attribut HTML → escape attribut

2. Interdire le JavaScript inline
Pas de :
- onclick="..."
- <script> ... </script>
- href="javascript:"

3. CSP (Content Security Policy)
Exemple :
Content-Security-Policy: default-src 'self'; script-src 'self';

4. Sanitisation du HTML
- DOMPurify (JS/Node)
- HTML Purifier (PHP)
- Bleach (Python)

5. Frameworks modernes
React, Vue, Angular → échappent automatiquement le contenu utilisateur.


2️⃣ SQLi — SQL Injection

Définition
Injection dans une requête SQL permettant d'exécuter ou de modifier la requête originale.

Objectifs de l’attaquant
- Dump de la base
- Auth bypass (' OR 1=1)
- Modification / suppression de données
- Exécution de commandes (via UDF / MySQL FILE)

Préventions principales
1. Prepared Statements (protection n°1)
Séparent le SQL du paramètre → l'entrée n’est jamais interprétée comme du code.

Exemples :
- PHP PDO :
  $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
  $stmt->execute([$id]);

- Python SQLite :
  cursor.execute("SELECT ... WHERE id = ?", (id,))

- Java JDBC :
  PreparedStatement ps = ...

2. ORMs
Django ORM, SQLAlchemy, Hibernate, Prisma → générent des requêtes paramétrées.

3. Stored Procedures
Si pas de concaténation interne.

4. Least Privilege
Limiter les droits SQL du compte applicatif.

CE QUI NE SUFFIT PAS
- mysqli_real_escape_string() seul
- Filtrer les caractères spéciaux
- Blacklists


3️⃣ CSRF — Cross-Site Request Forgery

Définition
Attaque où un site malveillant force un utilisateur authentifié à exécuter une action involontaire via l’envoi automatique des cookies.

Objectifs de l’attaquant
- Virement frauduleux
- Suppression de compte
- Changement d’adresse email
- Actions admin non voulues

Préventions principales
1. CSRF Token (défense n°1)
- Token aléatoire stocké en session
- Inclus dans un <input type="hidden">
- Vérifié par le serveur

2. SameSite Cookie
SameSite=Lax (recommandé)
SameSite=Strict (max sécurité)

3. Ne jamais utiliser GET pour une action sensible
Toujours POST + token.

4. Vérification Origin / Referer

5. Double Submit Cookie


4️⃣ SSRF — Server-Side Request Forgery

Définition
Attaque permettant de forcer un serveur à émettre une requête HTTP vers une adresse choisie par l’attaquant.

Objectifs de l’attaquant
- Accès services internes
- Scan réseau interne
- Accès localhost
- Vol credentials cloud (169.254.169.254)
- Bypass firewall

Préventions principales
1. Whitelist stricte des domaines
2. Bloquer les IP internes
3. Désactiver redirections
4. Sandbox réseau pour requêtes sortantes
5. Limiter les méthodes HTTP


Résumé rapide

XSS → Cause : mauvais encodage | Objectif : exécuter JS | Protection : Output encoding + CSP  
SQLi → Cause : concaténation SQL | Objectif : lire/modifier DB | Protection : Prepared statements  
CSRF → Cause : cookies envoyés auto | Objectif : action involontaire | Protection : CSRF Token + SameSite  
SSRF → Cause : entrée utilisée pour requêtes serveur | Objectif : accès interne | Protection : Whitelist + blocage IP internes