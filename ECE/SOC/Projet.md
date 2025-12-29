![[SOC-Fundamentals_Projet.pdf]]

```
~/Work/ECE/soc/projet/
├── hayabusa-3.7.0-lin-x64-gnu
│   └── Binaire Hayabusa utilisé pour l’analyse des journaux Windows
│
├── rules/
│   └── Règles Sigma et règles personnalisées utilisées par Hayabusa
│
├── Logs/
│   ├── PC01/
│   │   ├── Application.evtx
│   │   ├── PowerShellOperational.evtx
│   │   ├── Security.evtx
│   │   ├── SysmonOperational.evtx
│   │   ├── System.evtx
│   │   └── WindowsPowerShell.evtx
│   │
│   ├── AD01/
│   │   ├── Application.evtx
│   │   ├── PowerShellOperational.evtx
│   │   ├── Security.evtx
│   │   ├── Sysmon.evtx
│   │   ├── System.evtx
│   │   └── WindowsPowerShell.evtx
│   │
│   └── SRV01/
│       ├── Application.evtx
│       ├── PowerShellOperational.evtx
│       ├── Security.evtx
│       ├── Sysmon.evtx
│       ├── System.evtx
│       └── WindowsPowerShell.evtx
|
└── timesketch/
    └── Environnement Timesketch utilisé pour l’import, la corrélation et l’analyse
```

## Etape 1

Commande:
```
./hayabusa-3.7.0-lin-x64-gnu log-metrics -d ./Logs
```

Résultat: 
![[IMG-20251228022951726.png]]
![[IMG-20251228023008497.png]]
![[IMG-20251228023036446.png]]
![[IMG-20251228023058693.png]]

Explication:
Une analyse préliminaire des journaux Windows a été réalisée à l’aide de la commande `log-metrics` de l’outil Hayabusa afin d’obtenir une vue d’ensemble des données disponibles. Cette étape a permis de vérifier la présence, la volumétrie et la couverture temporelle des journaux avant toute analyse approfondie.
Les journaux analysés proviennent de trois machines du périmètre compromis : le poste utilisateur PC01, le contrôleur de domaine AD01 et le serveur applicatif SRV01. Dix-huit fichiers EVTX ont été identifiés, représentant un volume d’environ cent mégaoctets, avec une couverture temporelle cohérente sur l’ensemble des machines autour du 21 octobre 2025 entre 14 h 56 et 16 h 35.
L’analyse met en évidence une activité particulièrement élevée dans les journaux PowerShell sur les trois machines, concentrée sur une période courte, ce qui est compatible avec une activité automatisée. Le contrôleur de domaine présente également une activité soutenue dans les journaux de sécurité et système, indiquant une implication significative au cours de l’incident.
La présence de journaux Sysmon sur l’ensemble du périmètre constitue un élément favorable pour la suite de l’investigation. Ces premiers constats justifient la génération d’une timeline DFIR afin de reconstituer précisément le scénario de la compromission.

## Etape 2

Commande :
```
./hayabusa-3.7.0-lin-x64-gnu csv-timeline -d Logs/ -o timeline_PC_baseline.csv
```
![[IMG-20251228023922683.png]]

Résultat:

```
├── timeline_PC_baseline.csv
│   └── Timeline DFIR générée par Hayabusa à partir des journaux des trois machines
```
![[IMG-20251228024003084.png]]
Explication:
La seconde étape de l’investigation a consisté à générer une timeline DFIR à partir des journaux Windows des trois machines du périmètre à l’aide de la commande `csv-timeline` de l’outil Hayabusa. Cette commande permet de corréler chronologiquement les événements Windows ayant déclenché des règles de détection, afin d’identifier les comportements suspects et de préparer une analyse approfondie.
Lors de l’exécution de la commande, le jeu de règles « Core » a été sélectionné. Ce jeu comprend 2 213 règles dont le niveau de sévérité est élevé ou critique, et dont le statut est stable ou en test. Ce choix vise à se concentrer sur des événements présentant un réel intérêt en matière de sécurité, tout en limitant le bruit généré par des règles de faible pertinence ou purement informatives. Les règles Sysmon ont également été incluses, afin d’exploiter les événements détaillés relatifs à la création de processus, aux accès mémoire et à certaines activités système avancées.
Le périmètre d’analyse a été défini comme l’ensemble du répertoire `Logs`, regroupant les journaux du poste utilisateur, du contrôleur de domaine et du serveur applicatif. Hayabusa a ainsi produit un fichier unique, `timeline_PC_baseline.csv`, contenant une timeline unifiée des événements détectés sur les trois machines.
Le résumé des résultats montre l’absence d’alertes de niveau « emergency » et « critical », mais met en évidence plusieurs alertes de niveau élevé. Celles-ci concernent notamment l’effacement de journaux de sécurité, la désactivation de fonctionnalités de Windows Defender via le registre, la présence de commandes associées à des dumps LSASS, l’accès à des ruches sensibles du registre ainsi que l’exécution d’outils de type Mimikatz. Ces éléments indiquent des comportements typiquement associés à des phases post-compromission, telles que l’évasion des mécanismes de défense, le vol d’identifiants et l’anti-forensic.
Cette timeline constitue la base de l’analyse suivante et a été importée dans Timesketch afin de permettre une exploration chronologique détaillée et une corrélation inter-machines des différentes phases de l’attaque.

## Etape 3

Dans un premier temps, l’investigation a consisté à analyser l’ensemble des journaux Windows extraits des trois machines du périmètre à l’aide de l’outil **Hayabusa**, puis à les importer dans **Timesketch** afin de faciliter l’analyse chronologique des événements.

À l’issue de ce tri, un premier événement critique a été identifié sur le poste du développeur (`PC01.benarfacorp.local`) le **21 octobre 2025 à 13:08:17**.

![[IMG-20251229020033145.png]]
Cet événement correspond à une **création de processus** (Event ID 4688) indiquant l’exécution de `powershell.exe` en tant que processus enfant de `WINWORD.EXE`. Ce comportement est considéré comme anormal dans un contexte bureautique standard, dans la mesure où Microsoft Word n’est pas censé lancer des interpréteurs de commandes tels que PowerShell.

De plus, le processus PowerShell est exécuté avec un **niveau d’intégrité élevé (HIGH)** et un **jeton d’élévation complet (FULL_TOKEN)**, sous le compte `Administrateur`. Ces éléments indiquent que le code exécuté dispose de privilèges élevés sur la machine.

Cet événement est interprété comme le **point d’entrée probable de l’attaque**, suggérant l’ouverture d’un document Microsoft Word malveillant exploitant des mécanismes tels que des macros ou l’exécution de code embarqué.

L’analyse de la timeline montre qu’un **second événement survient immédiatement après**, à **13:08:17.220**, soit quelques millisecondes après le premier.

![[IMG-20251229020112507.png]]

Ce nouvel événement révèle l’exécution d’une commande PowerShell avancée, lancée de manière furtive (`-WindowStyle Hidden`) et en contournant les politiques de sécurité (`-ExecutionPolicy Bypass`). L’analyse de la ligne de commande met en évidence l’établissement d’une **connexion TCP sortante vers l’adresse 192.168.206.25 sur le port 4444**.

Le script PowerShell implémente un **shell interactif distant (reverse shell)** permettant à un attaquant distant d’exécuter des commandes arbitraires sur la machine compromise et de recevoir les résultats en retour. Cette activité confirme que l’attaquant a obtenu un **accès interactif à distance** sur le poste du développeur.

Un événement PowerShell (Event ID 4104) est observé à 13:09:29 sur le poste développeur, indiquant l’exécution de plusieurs commandes `Set-MpPreference` visant à désactiver les principales fonctionnalités de sécurité de Windows Defender.

![[IMG-20251229021140199.png]]

Pris isolément, ce type d’événement peut correspondre à une action administrative légitime dans certains contextes spécifiques. Toutefois, dans le cadre de cette investigation, cet événement survient immédiatement après l’établissement d’un accès distant non autorisé via un reverse shell PowerShell.

La corrélation temporelle et contextuelle avec les événements précédemment identifiés permet d’exclure l’hypothèse d’un faux positif. Cette action est interprétée comme une tentative de contournement des mécanismes de détection et de protection, visant à faciliter la poursuite de l’attaque et le déploiement ultérieur de charges malveillantes.

On observe ensuite un nouvel événement critique sur le poste du développeur (`PC01.benarfacorp.local`) à **13:09:54**, correspondant à l’exécution de la commande `reg.exe` visant à modifier une clé de registre liée à Windows Defender

![[IMG-20251229021900107.png]]

L’analyse de la ligne de commande montre que cette action est **exécutée via un processus PowerShell**, lui-même issu de la session précédemment identifiée comme un **reverse shell établissant une connexion vers l’adresse 192.168.206.25 sur le port 4444**.

La commande ajoute la clé de registre `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` avec la valeur `1`, forçant ainsi la désactivation persistante de la protection en temps réel de Windows Defender.

Cette corrélation entre le processus parent (`powershell.exe`), la connexion distante établie et la modification de clés de stratégie permet d’attribuer cette action à l’attaquant ayant pris le contrôle du poste, et non à une activité administrative légitime.

Cet événement confirme la poursuite des actions de neutralisation des mécanismes de sécurité depuis l’accès distant non autorisé, et marque une étape supplémentaire dans la prise de contrôle complète de la machine.

À 13:12:14, les journaux du poste développeur révèlent l’exécution de l’outil `nslookup.exe`, lancé en tant que processus enfant de `powershell.exe`.

L’analyse de la ligne de commande indique une requête de résolution du nom `AD01`, suggérant une tentative d’identification d’un serveur Active Directory ou d’un contrôleur de domaine présent sur le réseau.

Cette commande est exécutée dans le même contexte que le reverse shell précédemment identifié, sous le compte `Administrateur` et avec des privilèges élevés.

Bien que l’outil `nslookup` soit légitime, son utilisation à ce stade de l’attaque, depuis un accès distant non autorisé, permet d’interpréter cet événement comme une phase de reconnaissance réseau visant à cartographier l’infrastructure Active Directory avant un éventuel mouvement latéral.

![[IMG-20251229022412355.png]]

À 13:19:11, les journaux PowerShell du poste développeur révèlent l’exécution d’un script identifié comme une invocation potentielle de l’outil Mimikatz (Event ID 4104).

![[IMG-20251229022807714.png]]

La commande observée exécute les modules `privilege::debug` et `sekurlsa::logonPasswords`, connus pour permettre l’extraction des identifiants stockés en mémoire, incluant des mots de passe en clair, des hashes NTLM et des tickets Kerberos.

Les résultats de cette commande sont redirigés vers un fichier de sortie, suggérant une récupération structurée des informations d’authentification.

L’utilisation de Mimikatz dans ce contexte ne laisse que peu de place au doute quant à l’intention malveillante de l’attaquant. Cet événement marque une étape critique de l’attaque, visant à compromettre des comptes à privilèges élevés et à faciliter les déplacements latéraux au sein de l’infrastructure Active Directory.

ll est à noter qu’aucun événement ne permet d’identifier explicitement le téléchargement ou le dépôt initial du binaire utilisé pour exécuter Mimikatz sur le poste compromis.

Toutefois, l’exécution du fichier `mz.exe` avec des commandes spécifiques à Mimikatz (`sekurlsa::logonPasswords`) ne laisse aucun doute quant à la nature de l’outil employé.

Plusieurs hypothèses peuvent expliquer l’absence de traces visibles, notamment le renommage du binaire, son transfert via un canal déjà établi (reverse shell), ou l’utilisation de techniques d’exécution éphémère ou en mémoire.

Un événement Sysmon complémentaire est observé à 13:19:11, confirmant l’exécution effective de l’outil Mimikatz sur le poste du développeur.

![[IMG-20251229023044930.png]]

Le journal indique le lancement du binaire `mz.exe`, identifié comme étant Mimikatz pour Windows, depuis le répertoire `C:\temp`, avec l’exécution explicite des modules `privilege::debug` et `sekurlsa::logonPasswords`.

Le processus est exécuté avec des privilèges élevés et a pour processus parent une instance de PowerShell associée au reverse shell précédemment identifié.

