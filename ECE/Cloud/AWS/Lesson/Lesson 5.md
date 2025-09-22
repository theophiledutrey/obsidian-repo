## Objectifs du module
Ce module présente les fondamentaux de la mise en réseau dans AWS et vous amène à concevoir puis déployer une architecture de réseau virtuelle avec Amazon VPC. À l’issue de la première partie, vous saurez décrire la topologie d’un VPC, choisir et découper les plages d’adresses IP, distinguer les sous-réseaux publics et privés, comprendre le rôle des interfaces réseau élastiques (ENI) et manipuler les tables de routage qui gouvernent la circulation du trafic à l’intérieur d’un VPC.

---

## Section 1 – Amazon VPC (ex‑Section 2)

### 1. Définition et périmètre

Amazon Virtual Private Cloud (VPC) permet de créer une section logiquement isolée du Cloud AWS où vous placez vos ressources (instances EC2, bases de données, équilibreurs de charge…). Vous définissez vous‑même l’espace d’adressage IP, les sous‑réseaux, les stratégies de sécurité et les règles de routage. Le VPC supporte IPv4 et IPv6. Un VPC appartient à **une seule région AWS**, mais peut couvrir **plusieurs zones de disponibilité (AZ)** de cette région pour améliorer la tolérance aux pannes.

### 2. VPC, régions, AZ et sous‑réseaux

Un VPC est le conteneur réseau. Il se découpe en sous‑réseaux, chacun rattaché à **une seule AZ**. Ce découpage vous permet d’isoler des couches d’application et de contrôler leur exposition à Internet.

**Classification fonctionnelle des sous‑réseaux**

| Type de sous-réseau | Accès Internet direct | Routes typiques (exemples) | Cas d’usage courants |
|---|---|---|---|
| Public | Oui (via une passerelle Internet, détaillée dans la partie suivante du cours) | 10.0.0.0/16 → local ; 0.0.0.0/0 → Internet (IGW) | Frontaux web, ALB/NLB, bastion/SSM, endpoints publics |
| Privé | Non (pas de route Internet directe) | 10.0.0.0/16 → local ; autres routes internes (NAT/Transit/VPN… selon design) | Bases de données, services internes, backends, jobs batch |

**Insertion du schéma « Topologie de VPC » ici**  
Collez votre image illustrant deux régions avec VPC, sous-réseaux publics et privés répartis sur plusieurs AZ :
![[IMG-20250922152223080.png]]
**Description explicative** : la figure met en évidence qu’un VPC vit dans une région et se décline en plusieurs sous‑réseaux. Chaque sous‑réseau appartient à une AZ précise. Les sous‑réseaux « Public Subnet » accueillent les ressources exposées (par exemple les équilibreurs de charge) tandis que les « Private Subnet » hébergent les composants internes. La redondance vient du fait que l’on réplique ces sous‑réseaux sur au moins deux AZ.

### 3. Adressage IP du VPC et des sous‑réseaux

Au moment de la création, vous assignez au VPC un **bloc CIDR IPv4** qui détermine la capacité maximale d’adresses. Ce bloc n’est **pas modifiable** après coup. Les sous‑réseaux découpent ensuite ce bloc en sous‑plages **sans chevauchement**. Un bloc IPv6 peut être ajouté si nécessaire.

**Capacité d’adresses selon le préfixe IPv4**

| Préfixe | Nombre total d’adresses | Adresses théoriquement utilisables* |
|---:|---:|---:|
| /16 | 65 536 | 65 536 |
| /20 | 4 096 | 4 096 |
| /24 | 256 | 256 |
| /26 | 64 | 64 |
| /27 | 32 | 32 |
| /28 | 16 | 16 |

\* La capacité du VPC est théorique. La réduction liée aux adresses réservées intervient au niveau des sous‑réseaux (voir section suivante).

**Insertion du schéma « Bloc CIDR et taille du VPC » ici**  
Collez votre image montrant la relation entre le préfixe et le nombre d’adresses (ex. /28 = 16, /27 = 32, /16 = 65 536) :
![[IMG-20250922152223176.png]]

**Description explicative** : la figure illustre que plus le préfixe est grand (ex. /28), plus l’espace d’adresses est petit ; à l’inverse, un préfixe court (ex. /16) donne un vaste espace. Ce choix doit anticiper la croissance (nombre de sous‑réseaux, machines, endpoints) sans gaspiller d’adresses.

### 4. Adresses IP réservées dans chaque sous‑réseau

Dans **chaque sous‑réseau**, AWS réserve 5 adresses qui ne sont pas allouables aux instances. Le tableau suivant prend l’exemple d’un sous‑réseau 10.0.0.0/24 pour illustrer ces réservations.

| Adresse (ex /24) | Rôle | Commentaire |
|---|---|---|
| 10.0.0.0 | Adresse réseau | Identifie le sous‑réseau ; non attribuable |
| 10.0.0.1 | Routeur local du VPC | Point de saut par défaut pour le trafic intra‑VPC |
| 10.0.0.2 | DNS VPC | Utilisé pour la résolution interne |
| 10.0.0.3 | Réservée (usage futur) | Conservée par AWS |
| 10.0.0.255 | Adresse de diffusion | Réservée par conception réseau |

Conséquence : un /24 compte 256 adresses au total, **251 seulement** peuvent être affectées à des interfaces (ENI).

### 5. Adresses publiques et Elastic IP

Par défaut, les instances obtiennent toujours une **adresse privée** du sous‑réseau. L’exposition à Internet requiert une adresse publique. Deux mécanismes coexistent et se complètent :

| Caractéristique | Adresse IPv4 publique éphémère | Elastic IP (EIP) |
|---|---|---|
| Nature | Publique, peut changer si l’instance est arrêtée/recréée | Publique, **statique** et détenue par le compte |
| Attribution | Automatique (selon la configuration du sous‑réseau/instance) | Allocation manuelle, puis association à une ENI/instance |
| Portabilité | Faible (liée au cycle de vie de l’instance) | Élevée (remappage rapide vers une autre instance) |
| Coût | Inclus | Facturation si non associée/ inactive |
| Usage typique | Tests, workloads non critiques | Production, reprise après incident, adresses stables |

### 6. Interfaces réseau élastiques (ENI)

Une **ENI** est une interface réseau virtuelle que l’on attache à une instance. Elle porte l’adresse privée principale et, le cas échéant, des adresses privées secondaires et une association d’Elastic IP. Lorsqu’une ENI est détachée puis rattachée à une autre instance, **ses attributs sont conservés** ; cela permet des opérations de maintenance ou de remplacement d’instance sans modifier l’identité réseau.

| Élément transporté par l’ENI | Détails |
|---|---|
| Adresses IP privées | Une principale, éventuellement des secondaires |
| Association d’Elastic IP | Facultative, via une des IP privées |
| Groupes de sécurité | Jeu de règles appliqué au trafic entrant/sortant |
| MAC / ID d’ENI | Identifiants réseau qui suivent l’ENI lors d’un re‑attachement |

Chaque instance EC2 possède une ENI **par défaut**. Selon le type d’instance, des ENI **supplémentaires** peuvent être créées et attachées pour séparer des flux (par exemple, gestion vs données) ou pour fournir une redondance réseau.

### 7. Tables de routage et acheminements

Une **table de routage** contient des couples « destination → cible » qui déterminent où envoyer le trafic issu des ressources d’un sous‑réseau. Par défaut, toute table comporte une **route locale** vers le bloc CIDR du VPC, qui permet la communication interne et **ne peut pas être supprimée**.

Exemple minimal de table de routage (sans sortie Internet, qui sera traitée dans la partie suivante) :

| Destination | Cible | Signification |
|---|---|---|
| 10.0.0.0/16 | local | Routage intra‑VPC : toutes les IP du VPC sont joignables |

Chaque sous‑réseau doit être **associé à une seule table de routage**. En revanche, une même table peut être partagée par plusieurs sous‑réseaux, ce qui simplifie l’administration lorsque leurs besoins en connectivité sont identiques.

## Section 2 – Mise en réseau de VPC (ex‑Section 3 du support)

Dans cette partie, nous allons au‑delà de la simple définition d’un VPC et de ses sous‑réseaux. L’objectif est de comprendre les différentes **options de connectivité** et d’acheminement disponibles dans AWS. Chaque composant est illustré par un schéma que vous pouvez insérer pour documenter vos notes Obsidian.

---

### 1. Passerelle Internet (Internet Gateway)

Une **passerelle Internet (IGW)** est un composant VPC hautement disponible et scalable qui permet la communication entre les instances d’un VPC et Internet.  
Elle a deux rôles principaux :
- Servir de **cible dans les tables de routage** pour le trafic destiné à Internet.
- Réaliser la **traduction d’adresses réseau** (NAT) pour les instances auxquelles une adresse IPv4 publique est attribuée.

Pour qu’un sous‑réseau soit considéré comme **public**, il doit :
1. Être rattaché à une table de routage contenant une entrée `0.0.0.0/0 → IGW-ID`.
2. Avoir une passerelle Internet attachée au VPC.

**Description du schéma** : le diagramme montre un VPC avec un sous‑réseau public et un sous‑réseau privé. La table de routage du subnet public envoie le trafic non local (0.0.0.0/0) vers l’IGW, ce qui permet aux instances d’accéder à Internet.

---

### 2. Passerelle NAT (NAT Gateway)

Une **passerelle NAT** permet aux instances situées dans un sous‑réseau privé de **sortir vers Internet** (par exemple pour télécharger des mises à jour) sans qu’Internet puisse initier une connexion entrante vers ces instances.

Caractéristiques principales :
- La NAT Gateway doit être placée dans un **sous‑réseau public**.
- Une adresse IP Elastic doit être associée à la NAT Gateway.
- Les tables de routage des sous‑réseaux privés doivent contenir une route par défaut `0.0.0.0/0` pointant vers la NAT Gateway.

**Comparaison avec une instance NAT** :

| Caractéristique | NAT Gateway | Instance NAT |
|---|---|---|
| Administration | Entièrement managée par AWS | Nécessite configuration et maintenance |
| Scalabilité | Automatique, jusqu’à 45 Gbps | Dépend du type d’instance |
| Disponibilité | Haute disponibilité par AZ | Il faut configurer une redondance manuelle |
| Coût | Payant par heure et par Go traité | Payant comme une EC2 + transfert |

**Description du schéma** : on observe un sous‑réseau public contenant une NAT Gateway reliée à une IGW. La table de routage publique contient la route vers l’IGW. La table de routage privée redirige le trafic non local vers la NAT Gateway.

---

### 3. Partage de VPC

Le **partage de VPC** permet de partager des sous‑réseaux entre plusieurs comptes AWS appartenant à la même organisation (AWS Organizations).  
Un compte « propriétaire » crée et administre le VPC, tandis que les comptes « participants » peuvent lancer des ressources (EC2, RDS, Lambda, etc.) dans les sous‑réseaux partagés.

**Avantages** :
- **Séparation des responsabilités** : le propriétaire gère le réseau et la sécurité, les participants gèrent leurs ressources.
- **Simplification** : pas besoin de peering complexe entre VPC de la même organisation.
- **Économie** : meilleure densité des ressources, mutualisation des passerelles et endpoints.
- **Contrôle centralisé** : les routes et règles de sécurité sont définies de manière unique.

**Description du schéma** : le diagramme illustre un VPC « Compte A » propriétaire, avec un sous‑réseau privé et un sous‑réseau public. Les comptes B et C participants déploient des instances dans ces sous‑réseaux partagés, mais n’ont pas la possibilité de modifier les éléments du VPC.

---

### 4. Appairage de VPC (VPC Peering)

L’**appairage de VPC** permet de connecter deux VPC (dans le même compte, entre comptes ou même entre régions) pour échanger du trafic de manière privée. Les ressources de chaque VPC peuvent communiquer comme si elles faisaient partie du même réseau.

**Restrictions** :
- Les plages CIDR des deux VPC ne doivent pas se chevaucher.
- L’appairage transitif n’est pas supporté : si A est appairé à B, et B à C, alors A n’est pas automatiquement connecté à C.
- Une seule connexion d’appairage est possible entre deux VPC donnés.

**Description du schéma** : deux VPC distincts (A et B) sont reliés par une connexion de peering. Les tables de routage de chaque VPC incluent une entrée vers l’autre VPC via l’ID de connexion d’appairage.

---

### 5. AWS Site‑to‑Site VPN

Le service **Site‑to‑Site VPN** relie un VPC AWS à un réseau sur site au travers d’un tunnel VPN chiffré IPSec.  
Il nécessite :
1. La création d’une **passerelle de réseau privé virtuel (VGW)** dans le VPC.
2. La configuration d’un périphérique VPN côté client (pare‑feu, routeur, appliance).  
3. Une table de routage adaptée pour diriger le trafic du VPC vers le périphérique client via la VGW.

**Description du schéma** : on voit un VPC connecté à un data center distant. La passerelle VPN côté AWS est reliée à la passerelle client. Le trafic circule à travers le tunnel chiffré, et la table de routage du VPC est configurée pour envoyer le trafic vers la VGW.

---

### 6. AWS Direct Connect

**Direct Connect (DX)** fournit une **connexion réseau privée dédiée** entre un data center client et AWS.  
Caractéristiques :
- Réduction de la latence par rapport à Internet.
- Débit garanti et plus stable.
- Utilise des VLAN 802.1q pour séparer les connexions.

**Description du schéma** : un data center est relié directement au VPC via un lien privé. La connexion ne transite pas par Internet, garantissant une meilleure performance et une plus grande sécurité.

---

### 7. Points de terminaison de VPC (Endpoints)

Les **VPC Endpoints** permettent d’accéder aux services AWS **sans passer par Internet**, en restant dans le réseau privé AWS.

Deux types existent :
- **Endpoints d’interface (Interface Endpoints)** : basés sur AWS PrivateLink, créent une ENI avec une IP privée dans votre VPC pour atteindre des services AWS, APN ou Marketplace.
- **Endpoints de passerelle (Gateway Endpoints)** : utilisables avec S3 et DynamoDB, sans frais supplémentaires.

**Description du schéma** : un sous‑réseau public et un sous‑réseau privé sont reliés à un point de terminaison VPC, représenté comme une ressource rattachée à un service (exemple : Amazon S3). Les tables de routage incluent des entrées pointant vers ce point de terminaison.

---

### 8. AWS Transit Gateway

**Transit Gateway (TGW)** est une solution de connectivité en étoile. Elle permet de relier plusieurs VPC et réseaux sur site à une passerelle centrale.  
Avantages principaux :
- Simplifie la topologie réseau par rapport à l’appairage de VPC point‑à‑point.
- Centralise les politiques de routage et de sécurité.
- Évolue facilement pour gérer des dizaines voire des centaines de VPC.

**Description du schéma** : le premier diagramme illustre un maillage complexe d’appairages entre VPC. Le second schéma montre comment un Transit Gateway simplifie cette architecture : chaque VPC et chaque VPN se connecte directement à la TGW, ce qui réduit le nombre de connexions nécessaires.

---

### 9. Activité : solution complète

Le schéma récapitulatif combine tous les éléments vus : sous‑réseaux publics et privés, IGW, NAT Gateway, tables de routage, Elastic IP, interfaces réseau élastiques.  
Il illustre le modèle de référence typique d’un VPC hybride (public/privé) bien conçu.

---

## Points clés à retenir de la section
- Les options de mise en réseau incluent : Internet Gateway, NAT Gateway, VPC Endpoints, VPC Peering, VPC Sharing, Site‑to‑Site VPN, Direct Connect, Transit Gateway.  
- Le choix dépend des besoins en **sécurité**, **latence**, **coût** et **simplicité de gestion**.  
- L’assistant VPC peut être utilisé pour implémenter rapidement une topologie conforme aux bonnes pratiques.
