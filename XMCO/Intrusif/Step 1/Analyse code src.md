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

Fichier: cronMatriceFormations.php (appelé par le fichier accueilMatriceFormations.php)

![[Pasted image 20260420165238.png]]

Fichier: genererPlanningIndisponibilites.php (appelé par le fichier accueilPlanningIndisponibilites.php)
![[Pasted image 20260421102738.png]]
![[Pasted image 20260421102833.png]]

Fichier: matriceCongesEmploye.php (appelé par les fichiers listeCongesEmploye_OLD.php et calendrierConges.php)
![[Pasted image 20260421103212.png]]
![[Pasted image 20260421103229.png]]

Fichier: matriceRechercheFormations.php (appelé par le fichier resultatRechercheFormationsEmploye.php)
![[Pasted image 20260421103510.png]]
![[Pasted image 20260421104337.png]]

![[Pasted image 20260421103726.png]]



## ACL

Le fichier `adminer1.php` est accessible directement et embarque sa propre gestion de session (`adminer_sid`), indépendante de l’authentification de l’application métier. Ainsi, le contrôle d’accès applicatif reposant sur `$_SESSION['droit']` ne protège pas cette interface. Un utilisateur non autorisé peut donc atteindre l’interface Adminer et tenter une authentification directe à la base de données.

## RCE

Fichier: consulterEvenement.php
![[Pasted image 20260421100951.png]]

![[Pasted image 20260421101009.png]]

![[Pasted image 20260421101020.png]]

Regarder si on ne peut pas maitriser les valeurs dans la variable plan et programme

Fichier: genererFormulaireAccueilChantier2.php
![[Pasted image 20260421102430.png]]
![[Pasted image 20260421102449.png]]

fichier genererCauserie.php 

Appelé par les fichiers suivants:
![[Pasted image 20260421115202.png]]

![[Pasted image 20260421114700.png]]
![[Pasted image 20260421114620.png]]
## Creds admin FTP

Fichier: consulterEvenement.php
![[Pasted image 20260421101150.png]]

## Utilisation de mcrypt_create_iv de nombreuses fois

Fichier: consulterEvenement.php
![[Pasted image 20260421101556.png]]

## Path traversal

fichier: cpns (appelé par le fichier choixFichiersZipCatalogueTotal.php)

![[Pasted image 20260421105239.png]]

![[Pasted image 20260421105223.png]]
Ecraser d'autre ZIP sur le serveur

![[Pasted image 20260421105355.png]]
Peut permettre d'écrire un fichier zip dans un autre dossier -> RCE potentiel 

![[Pasted image 20260421105604.png]]
Si on maitrise la valeur de $doc, on peut récupérer d'autres dossier sur le serveur via path traversal

