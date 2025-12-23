![[Pasted image 20251221131016.png]]

![[Pasted image 20251222185642.png]]

Quand on utilise la fonction `print` dans le champ texte, il ne s’agit pas d’un simple affichage. En réalité, `print(x)` appelle `parent.postMessage(x)` afin d’envoyer une donnée depuis l’iframe vers la page parente.

Lors de cet envoi, le navigateur applique le _structured clone algorithm_ pour copier l’objet transmis. Ce mécanisme refuse de cloner certains types d’objets, notamment les fonctions, les Proxy et les objets natifs complexes.

Dans la sandbox, tous les objets exposés (`console`, `Date`, `Object`, etc.) sont encapsulés dans des Proxy. Ainsi, un appel comme :

```js
print(console);
```

force le navigateur à tenter de cloner un objet Proxy, ce qui provoque une erreur moteur de type `DataCloneError`.

Cette erreur est générée directement par le moteur JavaScript du navigateur, en dehors du contexte de la sandbox. Elle échappe donc aux restrictions mises en place dans `jail.js`.

En entourant cet appel d’un bloc `try/catch`, on peut récupérer l’objet d’erreur natif. Son constructeur (`DOMException`) n’a pas été modifié par la sandbox, et son propre constructeur correspond à la fonction native `Function`. Cela permet alors d’exécuter du code arbitraire hors sandbox.

La payload finale utilisée est la suivante :

```js
try {
    print(sonsole);
} catch (e) {
    e.constructor.constructor(
        'eval("alert(\'[GET OUT OF JAIL]\')")'
    )();
}
```

![[Pasted image 20251222190550.png]]

Cette payload force une erreur moteur, récupère l’erreur dans le `catch`, puis utilise la chaîne des constructeurs pour exécuter un `alert` avec le message attendu par le bot, ce qui permet d’obtenir le flag.

```
FCSC{2fdaccef0afb084f40c4bf38f681262141bcbabfbed0312725f59e40c54edb21}
```

Salut frr, je viens de terminer monopoly et je suis un peu frustré car ap avoir galéré toute l'aprem, c'est chat qui m'a à moitié donné le solve en disant que l'utilsation de parent.postMessage.bind avec comme paramètre un objet "non clonable" génère une erreur en dehors de la sandboxe. C'est frustrant car c'est hyper spécifique comme cas, comment j'aurais pu le deviner autrement?
