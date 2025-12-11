I. Test Technique:

L'entretien à commencé avec un test technique de une heure. J'avais accès à une IP publique: 15.237.216.194
Dans le cadre d'un pentest, je commence par un scan réseau pour découvrir les différents services disponibles sur la machine.
J'utilise donc le commande:
```
nmap -A 15.237.216.194
```

Cette commande correspond à un scan agressif (`-A`) de la cible. Elle permet d’obtenir rapidement un maximum d’informations en une seule étape : détection des ports ouverts, identification des services et de leurs versions et détection du système d’exploitation.
Dans un contexte de pentest réel,  ce type de scan ne doit pas être utilisé si on veut être discret . Cependant, dans le cadre de ce défi technique, l’objectif était d’obtenir rapidement une vision globale de la surface d’attaque de la machine. L’utilisation d’un scan agressif n’avait donc aucune conséquence et permettait d’optimiser le temps imparti pour l’analyse et l’exploitation potentielle des services exposés.
Voici le résultat du scan:
![[Pasted image 20251210235338.png]]

Le scan révèle 3 services importants:
- Un service SSH qui tourne sur le port 22. La version de OpenSSH est stable, elle ne laisse aucune attaque directe possible sur le service. Dans le cadre d'un exercice technique, je devine qu'on pourra s'authentifier en SSH via des credentials récupérés après une potentielle RCE.
- Un service web est exposé sur le port 80. On observe déjà une information importante : le site web donne accès à un dépôt GitHub, probablement le dépôt de l’application web qui tourne sur ce port.
- Un service web est egalement disponible sur le port 8080. Cela donne l'accès à une page login intitulée “Testa Motors - Employees Listing”, ce qui suggère une application interne potentiellement destinée aux employés , probablement exposée via un reverse proxy.

Je commence donc une analyse du site web sur le port 80. À première vue, aucun chemin ne suggère une exploitation directe. Je décide donc de fuzz les différent end point du site. Cela me permet de confirmer la présence d’un dépôt Git accessible via l’URL, déjà identifié lors du scan Nmap.
Je décide donc de récupérer l'intégralité du repo avec la commande:

```
git-dumper http://15.237.216.194/.git/ ./dump
```

Je découvre également, grâce au fuzzing, l’endpoint /admin, qui mène à une page de connexion. J’essaie alors des attaques basiques, telles que des injections SQL ou l’analyse des messages d’erreur afin d’identifier une éventuelle faiblesse permettant un bruteforce des credentials, mais aucune de ces tentatives n’aboutit. J'analyse un peu plus la requête POST créé lors des tentatives de login et je remarque un end point AJAX , utilisé par l’application pour appeler une fonction backend (ici la fonction login) , ce qui peut représenter une surface d’attaque intéressante à analyser:

```
http://15.237.216.194/admin/ajax.php?action=login
```

Je décide donc d'analyser le repo git que j'ai récupérer en local afin de comprendre le fonctionnement du backend. 
J'aperçois le dossier /admin avec à l'interieur un fichier nommé admin_class.php. Je retrouve à l'interieur de ce fichier, l'intégralité des fonctions qui définisses les actions liées à l'admin. Parmi celle ci, j'identifie la fonction login. Surement la même que celle qui est appelé dans la requête POST utilisé pour l'authentification. Je valide mon hypothèse en allant regader le contenu du fichier ajax.php:
```
if($action == 'login'){
	$login = $crud->login();
	if($login)
		echo $login;
}
```

A partir de ce moment là, je me dis que ce end-point me permet d'executer n'importe quelle fonction backend sans pre authentification requise. J'étudie donc les différentes fonctions disponible dans admin_class.php. Une fonction se démarque des autres: save_settings.php. En effet, celle ci permet d'upload un fichier directement sur le server sans aucune vérification de l'extension utilisé. Si j'arrive à upload un fichier php sur le server avec une payload qui me permet d'obtenir un webshell:
```
<?php echo shell_exec($_GET['cmd']); ?>
```
Alors il me manquera plus qu'à retrouver l'endroit où mon fichier à été enregistré afin de pouvoir l'executer sans jamais m'authentifier au site. Cela confirmera la présence d'une RCE qui permettra d'executer un reverse shell sur la machine.

Pour confirmer mon hypothèse je créé une commande curl qui me permet d'uploader ma payload:
```
curl -X POST "http://15.237.216.194/admin/ajax.php?action=save_settings" \
  -F "name=a" \
  -F "email=b" \
  -F "contact=c" \
  -F "about=d" \
  -F "img=@shell.php"
```
Je devine les champs à utiliser dans la requête grâce à l’analyse du code source, en particulier à l’utilisation de extract($POST), qui permet d’identifier directement les paramètres attendus par le backend à partir des variables manipulées dans la fonction.

J'execute donc ma commande qui me retourne 1. Je confirme donc le fait que je puisse executer cette fonction sans m'authentifier depuis l'end point:
```
ajax.php?action=save_settings
```

Il ne me manque plus qu’à identifier l’endpoint ou le chemin exact vers lequel le fichier uploadé a été stocké afin de pouvoir y accéder directement et poursuivre l’exploitation.
Pour cela j'analyse cette partie du code source:
```
if($_FILES['img']['tmp_name'] != ''){
	$fname = strtotime(date('y-m-d H:i')).'_'.$_FILES['img']['name'];
	$move = move_uploaded_file($_FILES['img']['tmp_name'],'assets/uploads/'. $fname);
	$data .= ", avatar = '$fname' ";
}
```
Je comprends alors que mon fichier est stocké dans le répertoire assets/uploads/, sous un nom composé de l’horodatage courant suivi du nom original du fichier uploadé. Je créé donc un script python qui me permet de récupérer le timestamp actuel:
```
import time
from datetime import datetime

now = datetime.now().strftime('%y-%m-%d %H:%M')

timestamp = int(time.mktime(time.strptime(now, '%y-%m-%d %H:%M')))

print(timestamp)
```
Ensuite, j’upload à nouveau ma payload et je lance le script Python simultanément. Cela me permet de reconstituer l’URL globale qui me permettra d’exécuter mon webshell :
```
http://15.237.216.194/assets/uploads/<timestamp>_payload.php
```

Malheureusement, je ne parviens pas à retrouver mon fichier à cette URL et j’arrive à ce moment-là à la fin de l’heure qui m’était impartie pour réaliser le test technique.

II. Hypothèse

Je suppose que je n'avais pas encore les droits d'accéder au fichier upload. En effet après analyse des résultats de mon fuzzing, je remarque bien l'end point asstes mais pas assets/uploads. Cela suggère donc 
