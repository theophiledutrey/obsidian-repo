Exemple:

On veut vérifier ici si on peut faire du path traversal en injectant une payload dans `chemin` ou `extension`
![[IMG-20260603160340931.png]]

On regarde pour cela ou est déclaré `documents`

![[IMG-20260603160341172.png]]

On va ensuite voir ce que fait la fonction `getDocumentsConstatCabineById`

![[IMG-20260603160343148.png]]

On voit qu'elle va lire dans la table `MATERIEL_CONSTAT_CABINE_DOCUMENT`
On recherche donc via le terminal tous les appels de `MATERIEL_CONSTAT_CABINE_DOCUMENT` afin de trouver quand est ce qu'on INSERT des éléments dans cette table.

```
grep -R "MATERIEL_CONSTAT_CABINE_DOCUMENT" .
```

![[IMG-20260603160345143.png]]

On voit que 2 INSERT sont réalisés dans  `mdl_materiel.php`

![[IMG-20260603160346859.png]]

![[IMG-20260603160348063.png]]

On cherche la définition de `genToken` et `exten`

![[IMG-20260603160349567.png]]

Ces valeurs ne sont pas modifiable par un utilisateur, donc pas exploitable