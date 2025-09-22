## Section 1 : Infrastructure mondiale AWS

## Objectifs du module
- Comprendre l’infrastructure mondiale AWS.  
- Identifier les services et catégories de services AWS.  
- Savoir utiliser la Console de gestion AWS pour explorer cette infrastructure.  

---

## Infrastructure mondiale AWS

- Environnement de cloud computing flexible, fiable et sécurisé.  
- Capable de s’adapter à l’échelle avec des performances réseau mondiales de haute qualité.  
- L’infrastructure AWS est régulièrement mise à jour.  

Ressources utiles :  
- [AWS Global Infrastructure Map](https://aws.amazon.com/about-aws/global-infrastructure/#AWS_Global_Infrastructure_Map)  
- [AWS Regions and AZs](https://aws.amazon.com/about-aws/global-infrastructure/regions_az/)  

---

## Régions AWS

- Une région = une zone géographique.  
- Chaque région est indépendante et contient au moins 2 zones de disponibilité (AZ).  
- Permet :  
  - Redondance & connectivité réseau complètes.  
  - Réplication des données selon vos besoins.  

Les régions ne répliquent pas automatiquement les données entre elles.  

### Cas particuliers :
- AWS Chine : comptes séparés et restreints.  
- AWS GovCloud (USA) : régions isolées pour agences gouvernementales & conformité stricte.  

---

## Choix d'une région

Facteurs à prendre en compte :  
- Gouvernance & obligations légales (conservation de données).  
- Proximité avec les clients (latence).  
- Services disponibles (tous les services ne sont pas dispo partout).  
- Coûts (variables selon la région).  

Outil utile : [CloudPing](http://www.cloudping.info/) pour tester la latence des régions AWS.  

---

## Zones de disponibilité (AZ)

- Une région contient plusieurs zones de disponibilité.  
- Chaque AZ = un ou plusieurs centres de données indépendants.  
- Caractéristiques :  
  - Isolation des défaillances.  
  - Interconnexion haut débit avec les autres AZ.  
  - Réplication recommandée pour assurer la résilience.  

Permet de créer des applications :  
- Hautement disponibles.  
- Résistantes aux pannes (ex : coupure électrique, inondation, séisme).  

---

## Centres de données AWS

- Conçus pour la sécurité et la redondance.  
- Chaque datacenter dispose de :  
  - Alimentation, mise en réseau et connectivité redondantes.  
  - Installation distincte pour limiter les risques.  
- Taille : 50 000 à 80 000 serveurs physiques par centre.  

Mesures de sécurité :  
- Localisation non divulguée.  
- Accès très restreint.  
- Composants critiques sauvegardés dans plusieurs AZ.  

---

## Points de présence (PoP)

- Réseau mondial d’emplacements périphériques & caches régionaux.  
- Utilisés par :  
  - Amazon CloudFront (CDN → diffusion rapide des contenus).  
  - Amazon Route 53 (DNS mondial).  
  - AWS Shield, WAF.  

Fonction :  
- Réduire la latence.  
- Acheminer les requêtes vers le PoP le plus proche.  
- Fournir une expérience quasi instantanée aux utilisateurs.  

---

## Caractéristiques de l’infrastructure AWS

- Élasticité & scalabilité  
  - Ajustement dynamique des ressources.  
  - Adaptation à la croissance.  

- Tolérance aux pannes  
  - Composants redondants.  
  - Continuité de fonctionnement même en cas de panne.  

- Haute disponibilité  
  - Performance constante.  
  - Réduction du temps d’arrêt.  
  - Aucune intervention humaine nécessaire.  

---

## Points clés à retenir

- AWS est composé de régions et de zones de disponibilité.  
- Le choix d’une région dépend de : conformité, latence, coûts, services disponibles.  
- Chaque AZ est isolée, mais interconnectée à haut débit.  
- Les points de présence (PoP) et caches régionaux améliorent les performances en rapprochant les contenus des utilisateurs.  

---

## Section 2 : Présentation des services et catégories de services AWS

### Services de base AWS

L’infrastructure mondiale AWS repose sur trois éléments principaux :  
- **Régions**  
- **Zones de disponibilité**  
- **Points de présence (emplacements périphériques)**  

Ces fondations supportent un large éventail de **services de base**, disponibles à la demande :  
- **Mise en réseau**  
- **Stockage (objet, bloc, archive)**  
- **Calcul (VM, mise à l’échelle, répartition de charge)**  
- **Bases de données**

> Ces services constituent la **plateforme fondamentale** qui permet de construire des solutions cloud complètes.  

---

### Catégories de services AWS

AWS regroupe ses services dans plus de **23 catégories** principales.  

Quelques-unes des plus importantes :  
- **Calcul** : Amazon EC2, Lambda, etc.  
- **Bases de données** : RDS, DynamoDB, Aurora.  
- **Stockage** : S3, EBS, Glacier.  
- **Mise en réseau et diffusion de contenu** : VPC, CloudFront, Route 53.  
- **Sécurité, identité et conformité** : IAM, KMS, Shield, WAF.  
- **Machine Learning** : SageMaker, Rekognition.  
- **Internet des objets (IoT)** : AWS IoT Core.  
- **Migration et transfert** : Snowball, Database Migration Service.  
- **Analytique** : Redshift, Athena, EMR.  
- **Engagement client** : Connect, Pinpoint.  
- **Applications métier** : WorkDocs, Chime.  

Lien officiel pour explorer les services :  
👉 [AWS Products](https://aws.amazon.com/products/)

---

### Exemples de services importants

#### Amazon EC2
- Service phare de calcul.  
- Fournit des instances virtuelles configurables.  
- Facturation à l’usage (à la seconde/minute).  
- Différents modèles d’achat : **à la demande, réservé, spot**.  

#### Amazon S3
- Stockage objet scalable.  
- Haute durabilité (11 9s).  
- Utilisé pour sauvegardes, applications web, big data, etc.  

#### Amazon RDS
- Bases de données relationnelles gérées.  
- Supporte plusieurs moteurs : MySQL, PostgreSQL, MariaDB, Oracle, SQL Server.  
- Sauvegardes automatiques, mise à l’échelle, haute dispo.  

---

### Points clés à retenir

- L’infrastructure AWS sert de base à des **services de calcul, stockage et mise en réseau**.  
- Ces services sont organisés en **catégories** pour simplifier l’exploration.  
- AWS propose plus de **200 services**, mais certains sont plus fondamentaux et plus présents à l’examen (EC2, S3, RDS, IAM, VPC).  

---

### Services de base AWS

L’infrastructure mondiale AWS repose sur trois éléments principaux :  
- **Régions**  
- **Zones de disponibilité**  
- **Points de présence (emplacements périphériques)**  

Ces fondations supportent un large éventail de **services de base**, disponibles à la demande :  
- **Mise en réseau**  
- **Stockage (objet, bloc, archive)**  
- **Calcul (VM, mise à l’échelle, répartition de charge)**  
- **Bases de données**

> Ces services constituent la **plateforme fondamentale** qui permet de construire des solutions cloud complètes.  

---

### Catégories de services AWS

AWS regroupe ses services dans plus de **23 catégories** principales.  

Quelques-unes des plus importantes :  
- **Calcul** : Amazon EC2, Lambda, etc.  
- **Bases de données** : RDS, DynamoDB, Aurora.  
- **Stockage** : S3, EBS, Glacier.  
- **Mise en réseau et diffusion de contenu** : VPC, CloudFront, Route 53.  
- **Sécurité, identité et conformité** : IAM, KMS, Shield, WAF.  
- **Machine Learning** : SageMaker, Rekognition.  
- **Internet des objets (IoT)** : AWS IoT Core.  
- **Migration et transfert** : Snowball, Database Migration Service.  
- **Analytique** : Redshift, Athena, EMR.  
- **Engagement client** : Connect, Pinpoint.  
- **Applications métier** : WorkDocs, Chime.  

Lien officiel pour explorer les services :  
👉 [AWS Products](https://aws.amazon.com/products/)

---

### Catégorie des services de stockage AWS

- **Amazon S3** : stockage objet, scalable, durable et sécurisé.  
- **Amazon EBS** : stockage bloc haute performance, utilisé avec EC2.  
- **Amazon EFS** : système de fichiers managé (NFS).  
- **Amazon Glacier** : stockage d’archives à très bas coût.  

---

### Catégorie des services de calcul AWS

- **Amazon EC2** : instances virtuelles.  
- **Amazon EC2 Auto Scaling** : ajuste dynamiquement le nombre d’instances.  
- **Amazon ECS** : orchestration de conteneurs Docker.  
- **Amazon ECR** : registre privé de conteneurs Docker.  
- **AWS Elastic Beanstalk** : déploiement simplifié d’applications web.  
- **AWS Lambda** : exécution de code serverless, facturé à l’exécution.  
- **Amazon EKS** : orchestration de conteneurs Kubernetes.  
- **AWS Fargate** : exécution de conteneurs sans gestion de serveurs.  

---

### Catégorie des services de base de données AWS

- **Amazon RDS** : bases relationnelles managées.  
- **Amazon Aurora** : base relationnelle compatible MySQL/PostgreSQL, optimisée AWS.  
- **Amazon Redshift** : entrepôt de données analytique (Big Data).  
- **Amazon DynamoDB** : base NoSQL clé-valeur ultra performante.  

---

### Catégorie des services de mise en réseau et diffusion de contenu

- **Amazon VPC** : réseau virtuel isolé.  
- **Elastic Load Balancing** : répartition du trafic applicatif.  
- **Amazon CloudFront** : CDN pour diffusion rapide et sécurisée de contenu.  
- **AWS Transit Gateway** : interconnexion entre VPC et sites distants.  
- **Amazon Route 53** : DNS scalable et hautement disponible.  
- **AWS Direct Connect** : connexion privée dédiée à AWS.  
- **AWS VPN** : connexions sécurisées via Internet.  

---

### Catégorie des services de sécurité, d’identité et conformité

- **IAM** : gestion des identités et accès.  
- **AWS Organizations** : gestion multi-comptes et politiques centralisées.  
- **Amazon Cognito** : gestion des identités pour applications web et mobiles.  
- **AWS Artifact** : accès aux rapports de conformité AWS.  
- **AWS KMS** : gestion des clés de chiffrement.  
- **AWS Shield** : protection contre les attaques DDoS.  

---

### Catégorie des services de gestion des coûts

- **Rapport d’utilisation et de coût AWS** : suivi détaillé des coûts.  
- **AWS Budgets** : définition et suivi de budgets.  
- **AWS Cost Explorer** : analyse graphique et interactive des coûts.  

---

### Catégorie des services de management et gouvernance

- **Console de gestion AWS** : interface utilisateur centrale.  
- **AWS Config** : suivi et audit de la configuration des ressources.  
- **Amazon CloudWatch** : monitoring et alertes.  
- **AWS Auto Scaling** : mise à l’échelle automatique des ressources.  
- **AWS CLI** : gestion des services par ligne de commande.  
- **AWS Trusted Advisor** : recommandations de bonnes pratiques.  
- **AWS Well-Architected Tool** : vérification de l’architecture cloud.  
- **AWS CloudTrail** : journalisation des actions utilisateurs et API.  

---

### Points clés à retenir

- L’infrastructure AWS sert de base à des **services de calcul, stockage et mise en réseau**.  
- Ces services sont organisés en **catégories** pour simplifier l’exploration.  
- AWS propose plus de **200 services**, mais certains sont plus fondamentaux et plus présents à l’examen (EC2, S3, RDS, IAM, VPC).  