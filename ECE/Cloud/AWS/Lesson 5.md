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
![[IMG-20250922093852334.png]]
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
![[IMG-20250922093925603.png]]

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
