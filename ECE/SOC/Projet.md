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
│
```
![[IMG-20251228024003084.png]]
Explication:
La seconde étape de l’investigation a consisté à générer une timeline DFIR à partir des journaux Windows des trois machines du périmètre à l’aide de la commande `csv-timeline` de l’outil Hayabusa. Cette commande permet de corréler chronologiquement les événements Windows ayant déclenché des règles de détection, afin d’identifier les comportements suspects et de préparer une analyse approfondie.
Lors de l’exécution de la commande, le jeu de règles « Core » a été sélectionné. Ce jeu comprend 2 213 règles dont le niveau de sévérité est élevé ou critique, et dont le statut est stable ou en test. Ce choix vise à se concentrer sur des événements présentant un réel intérêt en matière de sécurité, tout en limitant le bruit généré par des règles de faible pertinence ou purement informatives. Les règles Sysmon ont également été incluses, afin d’exploiter les événements détaillés relatifs à la création de processus, aux accès mémoire et à certaines activités système avancées.
Le périmètre d’analyse a été défini comme l’ensemble du répertoire `Logs`, regroupant les journaux du poste utilisateur, du contrôleur de domaine et du serveur applicatif. Hayabusa a ainsi produit un fichier unique, `timeline_PC_baseline.csv`, contenant une timeline unifiée des événements détectés sur les trois machines.
Le résumé des résultats montre l’absence d’alertes de niveau « emergency » et « critical », mais met en évidence plusieurs alertes de niveau élevé. Celles-ci concernent notamment l’effacement de journaux de sécurité, la désactivation de fonctionnalités de Windows Defender via le registre, la présence de commandes associées à des dumps LSASS, l’accès à des ruches sensibles du registre ainsi que l’exécution d’outils de type Mimikatz. Ces éléments indiquent des comportements typiquement associés à des phases post-compromission, telles que l’évasion des mécanismes de défense, le vol d’identifiants et l’anti-forensic.
Cette timeline constitue la base de l’analyse suivante et a été importée dans Timesketch afin de permettre une exploration chronologique détaillée et une corrélation inter-machines des différentes phases de l’attaque.

## Etape 3

![[IMG-20251228023735830.png]]

