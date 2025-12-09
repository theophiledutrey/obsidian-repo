![[IMG-20251209172404463.png]]
![[Pasted image 20251208190315.png]]

![[Pasted image 20251208190330.png]]

![[Pasted image 20251209004618.png]]

![[Pasted image 20251209004647.png]]

En PHP, l’utilisation de l’opérateur de comparaison lâche `==` peut entraîner des conversions automatiques de type (type juggling).  
Ces conversions peuvent provoquer des comportements inattendus, notamment lors de comparaisons entre chaînes de caractères et valeurs numériques.  
Dans un contexte d’authentification, ce mécanisme peut permettre un contournement de contrôle si l’application ne valide pas strictement les types.

## Magic Hashes

Certaines chaînes de caractères prenant la forme d’une notation scientifique, par exemple `0e1234`, sont interprétées par PHP comme des valeurs numériques.  
Lorsqu’une comparaison lâche est effectuée, PHP convertit ces chaînes en nombres flottants. Une chaîne commençant par `0e` suivie uniquement de chiffres est interprétée comme étant égale à 0.

Exemples de conversions implicites :  
`"0e1234" == "0e9999"` est évalué à VRAI car les deux chaînes sont interprétées comme la valeur numérique 0.  
`"0e1234" == 0` est évalué à VRAI pour la même raison.

Ces chaînes sont couramment appelées « Magic Hashes ».

## Exploitation en Cas de Comparaison Lâche

Si un code de vérification utilise une comparaison non stricte, par exemple :
```php
if ($stored_token == $_GET['token']) {
    // accès autorisé
}
```
alors toute valeur de type Magic Hash peut être acceptée comme équivalente à un token légitime si ce dernier est lui aussi convertible en valeur numérique.  
Cela peut conduire à un contournement complet d’un mécanisme d’authentification.

## Comparaison Stricte

L’opérateur strict `===` compare à la fois la valeur et le type des opérandes sans conversion automatique.  
Une chaîne comme `"0e1234"` n’est jamais considérée comme égale à un entier ou à une autre chaîne différente.  
Ainsi, `"0e1234" === "0e9999"` est évalué à FAUX, de même que `"0e1234" === 0`.

Le recours systématique à `===` pour les vérifications de tokens, hachages, identifiants uniques et données sensibles élimine ce type de vulnérabilité.


![[Pasted image 20251208211242.png]]

![[Pasted image 20251209004733.png]]
![[Pasted image 20251209004742.png]]
[CVE-2025-24367](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)
![[Pasted image 20251209003245.png]]

![[Pasted image 20251209003253.png]]

![[Pasted image 20251209004847.png]]

![[Pasted image 20251209120245.png]]


![[Pasted image 20251209120607.png]]

