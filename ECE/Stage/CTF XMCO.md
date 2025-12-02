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

![[IMG-20251202232830158.png]]

![[IMG-20251202232849220.png]]

