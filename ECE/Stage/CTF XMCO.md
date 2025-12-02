## Chall 1

### 1. Description de l’application

L’URL fournie par l’instance XMCO renvoie vers une petite application web intitulée.  
L’interface est minimaliste : une barre de navigation et un formulaire contenant :
- un champ texte `Name`
- un bouton `Submit`
- une bannière indiquant “Hello guest” par défaut.

En inspectant le code source HTML, on observe :
![[IMG-20251202153237760.png]]
Cela signifie que le paramètre `username` est réinjecté quelque part dans la page côté serveur.
Le nom du challenge est **“Serpent”**, ce qui suggère fortement un backend en **Python**.  




![[IMG-20251202152530398.png]]


![[IMG-20251202152508040.png]]

