## Principaux services AWS

Cette section présente les **services AWS de base** les plus importants.  
Ils se classent en plusieurs grandes catégories :  

- **Amazon VPC (Virtual Private Cloud)** : fournit un réseau privé virtuel isolé dans le cloud AWS.  
- **Amazon EC2 (Elastic Compute Cloud)** : permet de lancer et gérer des instances de calcul virtuelles.  
- **Stockage** : inclut différents services comme Amazon S3, Amazon EBS, Amazon EFS, et Amazon S3 Glacier.  
- **Base de données** : Amazon RDS et Amazon DynamoDB.  
- **Gestion des identités et accès (IAM)** : contrôle des accès et gestion des utilisateurs/permissions.  

### Détails du stockage
- **Stockage d’instance (éphémère)** : stockage temporaire ajouté à une instance EC2, perdu si l’instance s’arrête.  
- **Amazon EBS** : stockage persistant, attaché à une instance EC2, réutilisable et montable.  
- **Amazon EFS** : système de fichiers partagé accessible par plusieurs instances en parallèle.  
- **Amazon S3** : stockage d’objets distribué, chaque fichier devient un objet accessible par URL.  
- **Amazon Glacier** : stockage à très faible coût destiné à l’archivage longue durée.  

---

## Section 1 : Amazon Elastic Block Store (Amazon EBS)

Amazon EBS est un service de **stockage par blocs persistant**, utilisé avec les instances EC2.  
Contrairement au stockage éphémère, EBS conserve les données même après l’arrêt ou la suppression de l’instance.  

---

## Stockage Amazon EBS

Amazon EBS fournit :
- Des volumes persistants, appelés aussi **stockage non-volatil**.  
- Une réplication automatique **au sein d’une même zone de disponibilité**, afin d’assurer haute disponibilité et durabilité.  
- Des performances constantes et une faible latence adaptées aux charges de travail critiques.  

Avec Amazon EBS, il est possible de **mettre à l’échelle dynamiquement** la capacité de stockage en quelques minutes, en ne payant que pour l’espace réellement utilisé.  

---

## Options de stockage : blocs vs objets

Il existe deux grands modèles de stockage :  

| Type de stockage     | Fonctionnement | Exemple d’utilisation |
|----------------------|----------------|-----------------------|
| **Stockage par bloc** | Les fichiers sont découpés en blocs indépendants. Modifier un seul caractère implique seulement la mise à jour du bloc concerné. | Amazon EBS |
| **Stockage par objet** | Chaque fichier est un objet complet. Pour modifier un caractère, il faut réécrire tout le fichier. | Amazon S3 |

- Le **stockage par bloc** est plus rapide et consomme moins de bande passante mais coûte plus cher.  
- Le **stockage par objet** est plus économique et adapté à l’archivage et au stockage distribué.  

---

## Amazon EBS : caractéristiques

Amazon EBS permet de :  
- Créer des volumes individuels.  
- Les attacher à une instance EC2.  
- Fournir un stockage de type bloc, automatiquement répliqué dans la zone de disponibilité.  
- Sauvegarder les volumes sous forme d’**instantanés (snapshots)** dans Amazon S3.  

### Usages typiques :
- Volumes de démarrage et de stockage pour les instances EC2.  
- Stockage de bases de données avec système de fichiers.  
- Applications d’entreprise nécessitant persistance et haute disponibilité.  

---

## Types de volumes Amazon EBS

AWS propose plusieurs types de volumes selon les besoins :  

| Type de volume (EBS) | Taille max | IOPS max | Débit max | Cas d’usage |
|-----------------------|------------|----------|-----------|-------------|
| **SSD polyvalent**    | 16 Tio     | 16 000   | 250 Mio/s | Charges générales, volumes de démarrage |
| **SSD IOPS provisionnés** | 16 Tio | 64 000   | 1 000 Mio/s | Bases de données critiques nécessitant I/O élevé |
| **HDD à débit optimisé** | 16 Tio | 500 | 500 Mio/s | Big Data, streaming |
| **HDD à froid**       | 16 Tio     | 250      | 250 Mio/s | Archivage, faible coût |

Seuls les disques SSD peuvent être utilisés comme **volumes de démarrage EC2**.  

---

## Cas d’utilisation des volumes EBS

| Type de volume | Cas d’usage typiques |
|----------------|----------------------|
| **SSD polyvalent** | Volumes système, environnements de test/développement |
| **SSD IOPS provisionnés** | Bases de données critiques, applications nécessitant une latence très faible |
| **HDD débit optimisé** | Big Data, entrepôts de données, traitement de journaux |
| **HDD à froid** | Archivage à faible coût, scénarios où la performance n’est pas critique |

---

## Fonctions d’Amazon EBS

- **Instantanés** :  
  - Sauvegardes ponctuelles.  
  - Possibilité de recréer un volume depuis un snapshot.  
  - Stockés dans Amazon S3.  

- **Chiffrement** :  
  - Volumes EBS chiffrés sans coût supplémentaire.  
  - Chiffrement des données au repos et en transit entre EC2 et EBS.  

- **Élasticité** :  
  - Changement de type de volume possible.  
  - Redimensionnement dynamique (ex : passer de 50 Go à 16 To).  

---

## Tarification d’Amazon EBS

Le coût dépend de plusieurs paramètres :  

1. **Volumes**  
   - Facturés selon la capacité allouée (Go/mois).  
   - Indépendants du cycle de vie de l’instance EC2.  

2. **IOPS**  
   - Inclus pour SSD polyvalents.  
   - Facturation par requête pour volumes magnétiques.  
   - Pour les SSD IOPS provisionnés : facturation basée sur le nombre d’IOPS alloués × durée d’utilisation.  

3. **Instantanés**  
   - Facturation en fonction du nombre de Go stockés dans Amazon S3.  

4. **Transfert de données**  
   - Gratuit pour les entrées.  
   - Les sorties inter-régions entraînent des frais supplémentaires.  

---

## Introduction à Amazon S3

Amazon Simple Storage Service (S3) est un service de stockage **à base d’objets**. Contrairement au stockage en bloc (EBS), chaque fichier est traité comme un objet unique et complet.  
Lorsqu’une partie d’un fichier doit être modifiée, l’objet entier doit être rechargé.  
Les données sont stockées dans des ressources appelées **compartiments** (buckets).

---

## Présentation générale d’Amazon S3

- Les données sont stockées sous forme **d’objets** dans des compartiments.  
- Capacité de stockage **virtuellement illimitée** (chaque objet peut aller jusqu’à **5 To**).  
- Durabilité conçue à **99,999999999 %** (11 neuf).  
- Chaque compartiment possède un **nom unique** globalement.  
- Stockage redondant : les données sont répliquées sur plusieurs installations au sein d’une région.  
- Amazon S3 gère des milliards d’objets et traite des **millions de requêtes par seconde**.

**Schéma clé :**
- Compartiment = conteneur logique d’objets.  
- Objets = fichiers + métadonnées.  
- URL unique pour chaque objet.  

---

## Classes de stockage Amazon S3

Amazon S3 propose plusieurs classes de stockage adaptées à différents cas d’usage :

| Classe | Description | Cas d’usage |
|--------|-------------|-------------|
| **S3 Standard** | Haute durabilité et performance pour les données fréquemment consultées | Applications web dynamiques, contenu distribué, big data |
| **S3 Intelligent-Tiering** | Déplacement automatique des objets entre niveaux (accès fréquent / peu fréquent) | Réduction des coûts sans impact sur les performances |
| **S3 Standard-IA (Accès peu fréquent)** | Faible coût pour données rarement utilisées, accès rapide si besoin | Sauvegardes, récupération après sinistre |
| **S3 One Zone-IA** | Comme IA mais stocké dans une seule AZ, donc moins cher | Données secondaires ou réplicas |
| **S3 Glacier** | Stockage très peu coûteux, accès en quelques minutes à heures | Archivage long terme |
| **S3 Glacier Deep Archive** | Le moins cher, récupération en plusieurs heures | Archivage légal et réglementaire |

---

## URL et compartiments

Un objet S3 est accessible via une URL qui combine **le code de région + le nom du compartiment + le nom de l’objet**.

Exemple :

- Style chemin :  
  ```
  https://s3.ap-northeast-1.amazonaws.com/mon-compartiment/mon-objet
  ```

- Style hébergement virtuel :  
  ```
  https://mon-compartiment.s3-ap-northeast-1.amazonaws.com/mon-objet
  ```

Chaque compartiment est associé à une **région AWS** spécifique. Les données sont stockées de manière redondante dans plusieurs installations de cette région.

---

## Stockage redondant et haute disponibilité

- Les objets sont stockés **dans plusieurs installations** d’une même région.  
- Résilience même en cas de perte simultanée de deux installations.  
- Garantit la **durabilité** des données sur le long terme.

---

## Mise à l’échelle transparente

- Amazon S3 ajuste automatiquement la capacité en arrière-plan.  
- Pas besoin de prévoir la taille ou le débit à l’avance.  
- Facturation uniquement sur l’espace et les requêtes réellement utilisées.  
- Supporte des **volumes massifs de requêtes** (scalabilité horizontale).

---

## Accès aux données

Amazon S3 est accessible :  
- Via la **console AWS**.  
- Via l’**AWS CLI** (ligne de commande).  
- Via les **SDKs AWS** (API REST).  

Caractéristiques des accès :  
- Support **HTTP/HTTPS**.  
- Les compartiments doivent avoir des noms uniques conformes au **DNS**.  
- Les clés d’objets doivent utiliser des caractères sécurisés pour être utilisés dans une URL.

---

## Cas d’utilisation courants

- **Stockage de ressources d’applications** : fichiers multimédias, logs, données partagées.  
- **Hébergement web statique** : diffusion de contenus HTML, CSS, JS directement depuis un bucket public.  
- **Sauvegarde et reprise après sinistre (RS)** : stockage de sauvegardes critiques avec réplication inter-région.  
- **Big Data et analyse** : zone de transit pour données massives, avec intégration à d’autres services AWS (Athena, Redshift, EMR…).  

---

## Points clés Amazon S3

1. Stockage **illimité**, structuré en compartiments et objets.  
2. Résilience avec une durabilité de **11 neuf**.  
3. Différentes classes de stockage adaptées aux besoins (Standard, IA, Glacier…).  
4. Facturation basée sur l’espace utilisé et les requêtes.  
5. Accès simple via console, CLI ou API REST.  