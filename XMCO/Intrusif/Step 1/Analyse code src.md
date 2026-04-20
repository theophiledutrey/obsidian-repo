## SSRF

Fichier: ajoutConstatMeteo.php
![[screenshot_84.png]]

## CVE PHPMailer 5.2.28

![[Pasted image 20260420143508.png]]

##  CVE dompdf c7dc571

![[Pasted image 20260420143948.png]]

## XSS 

Fichier: consulterConstatCabine.php et consulterConstatChantier.php et consulterConstatMateriel.php et consulterConstatMeteo.php

![[Pasted image 20260420153801.png]]
$d[nom_fichier] peut contenir du code javascript

Cet élément est ajouté en BDD par la méthode `addConstatCabine` dans le fichier `mdl_materiel.php` et est ajoutable depuis le site via la page `ajoutConstatCabine.php`

## SQLi

Fichier: cronMatriceFormations.php

![[Pasted image 20260420165238.png]]

