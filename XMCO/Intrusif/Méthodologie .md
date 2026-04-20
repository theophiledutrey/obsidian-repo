Exemple:

On veut vérifier ici si on peut faire du path traversal en injectant une payload dans `chemin` ou `extension`
![[Pasted image 20260420150158.png]]

On regarde pour cela ou est déclaré `documents`

![[Pasted image 20260420150229.png]]

On va ensuite voir ce que fait la fonction `getDocumentsConstatCabineById`

![[Pasted image 20260420150301.png]]

On voit qu'elle va lire dans la table `MATERIEL_CONSTAT_CABINE_DOCUMENT`
On recherche donc via le terminal tous les appels de `MATERIEL_CONSTAT_CABINE_DOCUMENT` afin de trouver quand est ce qu'on INSERT des éléments dans cette table.

```
grep -R "MATERIEL_CONSTAT_CABINE_DOCUMENT" .
```

![[Pasted image 20260420150424.png]]

On voit que 2 INSERT sont réalisés dans  `mdl_materiel.php`

![[Pasted image 20260420150542.png]]

![[Pasted image 20260420150552.png]]

On cherche la définition de `genToken` et `exten`

![[Pasted image 20260420150628.png]]

Ces valeurs ne sont pas modifiable par un utilisateur, donc pas exploitable