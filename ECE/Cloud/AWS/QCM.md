> Chaque question comporte la **réponse correcte**, puis **toutes les autres options fausses avec explication**.

---

### 1) Options de paiement pour **instances réservées** (EC2 / RDS) — choisissez trois
- **Réponse correcte :**  
  - **AURI** (All Upfront Reserved Instance) — paiement **tout à l’avance**.  
  - **PURI** (Partial Upfront Reserved Instance) — paiement **partiel à l’avance** + mensualités.  
  - **NURI** (No Upfront Reserved Instance) — **aucun paiement initial**, facturation mensuelle.
- **Autres options (fausses) :**
  - **MURI** — n’existe pas.
  - **DURI** — n’existe pas.

---

### 2) Obtenir des détails de facturation **EC2** d’il y a 3 mois (meilleure réponse)
- **Réponse correcte :** **AWS Cost Explorer** — analyses et historique de coûts/usage (mois précédents inclus).
- **Autres options (fausses) :**
  - **Tableau de bord Amazon EC2** — vue opérationnelle des instances, pas l’analyse de coûts consolidée.  
  - **Tableau de bord AWS Trusted Advisor** — recommandations de bonnes pratiques/coûts, pas un relevé détaillé historique.  
  - **Journaux AWS CloudTrail dans S3** — audit d’API, **pas** un outil de facturation.

---

### 3) Pour bénéficier du tarif réduit d’une **instance réservée**, il faut payer intégralement à l’avance (V/F)
- **Réponse correcte :** **Faux** — les modes **No Upfront** et **Partial Upfront** existent.
- **Autre option (fausse) :** **Vrai** — incorrect car le paiement intégral n’est pas obligatoire.

---

### 4) Déclaration vraie sur le **modèle de tarification AWS**
- **Réponse correcte :** **Le stockage est généralement facturé par gigaoctet.**
- **Autres options (fausses) :**
  - **Le transfert de données entrantes est facturé par gigaoctet** — la plupart du temps **gratuit**.  
  - **Le calcul est facturé mensuellement selon le type d’instance** — la facturation est à la minute/seconde (selon OS), **pas** forfait mensuel.  
  - **Les données sortantes sont gratuites jusqu’à une certaine limite par compte** — il existe des coûts de sortie (selon volume/région).

---

### 5) **Formules de support AWS**
- **Réponse correcte :** **Basique, Développeur, Business, Enterprise.**
- **Autres options (fausses) :**
  - **Basique, Start‑up, Business, Enterprise** — « Start‑up » n’est pas un plan officiel.  
  - **Gratuit, Bronze, Silver, Gold** — nomenclature non‑AWS.  
  - **Tout le support est gratuit** — faux (seul le plan **Basique** est gratuit).

---

### 6) Outil pour **explorer les services** et **créer une estimation** de coûts
- **Réponse correcte :** **Calculateur de prix AWS**.
- **Autres options (fausses) :**
  - **AWS Budgets** — suivi/alertes budgétaires, pas d’estimation initiale.  
  - **Rapport d’utilisation et de coût AWS (CUR)** — export détaillé des coûts/usage, **après** consommation.  
  - **Tableau de bord de facturation** — vue synthétique, pas un outil de modélisation prospective.

---

### 7) Baisse des coûts répercutée aux clients — comment s’appelle cette optimisation ?
- **Réponse correcte :** **Économies d’échelle** — plus AWS grandit, plus le coût unitaire baisse.
- **Autres options (fausses) :**
  - **Connaissances des dépenses** — notion FinOps, mais ce n’est pas l’effet prix à l’échelle.  
  - **Adéquation de l’offre et de la demande** — principe général, pas spécifique à cette baisse structurelle.  
  - **Dimensionnement approprié EC2 (rightsizing)** — optimisation **interne** à un compte, pas liée à la taille d’AWS.

---

### 8) Services **gratuits** (VPC, IAM, Auto Scaling, CloudFormation…) mais coûts possibles autour (V/F)
- **Réponse correcte :** **Vrai** — le service peut être gratuit, **les ressources** qu’il orchestre **ne le sont pas** (ex. EC2, S3…).
- **Autre option (fausse) :** **Faux** — ignore les coûts des ressources sous‑jacentes.

---

### 9) Avantages d’**AWS Organizations** (choisissez deux)
- **Réponses correctes :**
  - **Créer des groupes de comptes (OU) et leur attacher des politiques** (SCP).  
  - **Automatiser la création/la gestion de comptes via les API** (et SDK/CLI).
- **Autres options (fausses) :**
  - **Remplace les politiques IAM par des SCP plus simples** — SCP **complètent** IAM, ne le remplacent pas.  
  - **Permet de créer un nombre limité d’OU imbriquées** — la limitation existe, mais **ce n’est pas** un avantage (et la phrase est confuse).  
  - **Empêche d’imposer des restrictions au root/admin principal** — **faux** : les SCP **s’appliquent aussi** au root du compte membre.

---

### 10) Offre gratuite AWS : nombre **illimité** de services gratuits pendant 12 mois (V/F)
- **Réponse correcte :** **Faux** — l’offre gratuite couvre un **sous‑ensemble** de services, avec **quotas** et **durées**.
- **Autre option (fausse) :** **Vrai** — surestime la portée de l’offre gratuite.

---


# QCM AWS – Module 3 : Infrastructure mondiale AWS

> Chaque question comporte la **réponse correcte**, puis **toutes les autres options fausses avec explication**.

---

### 1) Composant d’infrastructure utilisé par **Amazon CloudFront** pour une faible latence
- **Réponse correcte :** **Emplacements périphériques (Edge Locations)** — points de présence du CDN.
- **Autres options (fausses) :**
  - **Régions AWS** — domaines géographiques composés de plusieurs AZ, pas des POP du CDN.  
  - **Zones de disponibilité (AZ)** — sous‑ensembles **intra‑région**, pas des nœuds CDN globaux.  
  - **Amazon VPC** — réseau **logique** isolé, sans rôle de distribution CDN.

---

### 2) Exécuter les charges plus près des utilisateurs permet de ______ la latence
- **Réponse correcte :** **réduire**.
- **Autre option (fausse) :** **augmenter**.

---

### 3) Mise en réseau, stockage, calcul et bases de données sont des **catégories de services AWS** (V/F)
- **Réponse correcte :** **Vrai** — ce sont bien des familles de services officielles.
- **Autre option (fausse) :** **Faux**.

---

### 4) Zone géographique hébergeant **au moins deux** zones de disponibilité
- **Réponse correcte :** **Régions AWS**.
- **Autres options (fausses) :**
  - **Origines AWS** — terme non standard ici.  
  - **Zones de calcul** — terme absent dans cette taxonomie.  
  - **Emplacements périphériques** — POP de CloudFront/Route 53, pas des régions.

---

### 5) ______ signifie redondance intégrée des composants et ______ signifie ajustement dynamique de capacité
- **Réponse correcte :** **La tolérance aux pannes**, **l’élasticité/scalabilité**.  
  > Tolérance aux pannes : redondance, continuité de service.  
  > Élasticité : montée/descente automatique selon la demande.
- **Autres options (fausses) :**
  - **L’absence d’intervention humaine, la tolérance aux pannes** — confusion sur les notions.  
  - **L’élasticité/scalabilité, l’absence d’intervention humaine** — ordre/second terme incorrects.  
  - **La tolérance aux pannes, l’absence d’intervention humaine** — deuxième terme incorrect.  
  - **L’élasticité/scalabilité, la tolérance aux pannes** — **inversé** par rapport à l’énoncé.

---

### 6) Les **AZ d’une même région** sont interconnectées par des **liaisons à faible latence** (V/F)
- **Réponse correcte :** **Vrai** — réseau régional à haut débit/faible latence, redondant.
- **Autre option (fausse) :** **Faux**.

---

### 7) Énoncé **qui n’est pas vrai** à propos des **zones de disponibilité**
- **Réponse correcte :** **Un centre de données peut être utilisé pour plusieurs zones de disponibilité.**  
  > **Faux** : un data center appartient à **une seule** AZ.  
- **Autres options (vraies donc fausses pour la question) :**
  - **Les AZ sont conçues pour isoler les pannes.**  
  - **Les AZ sont constituées d’un ou plusieurs centres de données.**  
  - **Les AZ sont interconnectées via des liaisons privées à haut débit.**

---

### 8) Affirmations **vraies** à propos des **régions** (choisissez deux)
- **Réponses correctes :**
  - **Chaque région se trouve dans une zone géographique distincte.**  
  - **Une région est un emplacement physique hébergeant plusieurs AZ.**
- **Autres options (fausses) :**
  - **Toutes les régions figurent dans une seule zone géographique spécifique.** — non, elles sont **réparties** dans le monde.  
  - **Elles constituent les emplacements physiques où se trouvent vos clients.** — régions ≠ localisation clients.

---

### 9) AWS recommande de déployer les ressources de calcul dans ______ zone(s) de disponibilité
- **Réponse correcte :** **plusieurs** — pour la haute disponibilité et la tolérance aux pannes.
- **Autres options (fausses) :**
  - **une seule** — fragilise la disponibilité.  
  - **aucune** — impossible.  
  - **toutes les** — inutile/opérationnellement contraignant.

---

### 10) Les **emplacements périphériques** sont **nécessairement** dans la même zone générale que les **régions** (V/F)
- **Réponse correcte :** **Faux** — les POP sont **beaucoup plus nombreux** et distribués que les régions.
- **Autre option (fausse) :** **Vrai**.

---


# QCM AWS – Module 4 : Sécurité du Cloud AWS

> Chaque question comporte la **réponse correcte**, puis **toutes les autres options fausses avec explication**.

---

### 1) Dans le modèle de responsabilité partagée, quelle fonctionnalité est du ressort d’AWS ?

- **Réponse correcte :** **Sécurité du cloud** — AWS gère l’infrastructure physique, le matériel, les datacenters.
    
- **Autres options (fausses) :**
    
    - **Sécurité dans le cloud** — c’est la responsabilité du client (configurations, IAM, chiffrement).
        
    - **Sécurité vers le cloud** — formulation incorrecte, non utilisée.
        
    - **Sécurité pour le cloud** — formulation générique, non officielle.
        

---

### 2) Exemples de « sécurité dans le cloud » (choisissez deux)

- **Réponses correctes :**
    
    - **Configurations des groupes de sécurité**
        
    - **Chiffrement des données en transit et au repos**
        
- **Autres options (fausses) :**
    
    - **Conformité avec la législation et normes de sécurité** — responsabilité AWS.
        
    - **Sécurité physique des installations** — responsabilité AWS.
        
    - **Protection de l’infrastructure globale** — responsabilité AWS.
        

---

### 3) Responsabilité d’AWS dans le modèle de responsabilité partagée

- **Réponse correcte :** **Entretien du matériel physique**
    
- **Autres options (fausses) :**
    
    - **Configuration d’applications tierces** — relève du client.
        
    - **Sécurisation des données et accès aux applications** — relève du client.
        
    - **Gestion des AMI personnalisées** — relève du client.
        

---

### 4) Types d’accès IAM qu’on peut accorder à un utilisateur (choisissez deux)

- **Réponses correctes :**
    
    - **Accès par programmation** (clé API, SDK, CLI).
        
    - **Accès à AWS Management Console** (login + mot de passe, MFA).
        
- **Autres options (fausses) :**
    
    - **Accès institutionnel** — inexistant.
        
    - **Accès autorisé** — formulation générique.
        
    - **Accès racine d’administrateur** — réservé au compte root, non via IAM.
        

---

### 5) AWS Organizations permet de gérer plusieurs comptes AWS de manière centralisée (V/F)

- **Réponse correcte :** **Vrai**
    
- **Autre option (fausse) :** **Faux** — contredit la fonctionnalité d’AWS Organizations.
    

---

### 6) Bonnes pratiques IAM (choisissez deux)

- **Réponses correctes :**
    
    - **Gérer l’accès aux ressources AWS**
        
    - **Définir des droits d’accès précis** (principe du moindre privilège)
        
- **Autres options (fausses) :**
    
    - **Fournir par défaut des privilèges admin** — contraire aux bonnes pratiques.
        
    - **Laisser en place des utilisateurs inutilisés** — augmente la surface d’attaque.
        
    - **Éviter d’utiliser les groupes IAM** — au contraire, il est recommandé d’utiliser des groupes.
        

---

### 7) Opération qui doit être effectuée par l’utilisateur racine

- **Réponse correcte :** **Modifier le plan AWS Support**
    
- **Autres options (fausses) :**
    
    - **Sécuriser l’accès pour les applications** — relève d’IAM.
        
    - **Effectuer l’intégration à d’autres services AWS** — relève d’IAM.
        
    - **Modifier les autorisations détaillées** — relève d’IAM.
        

---

### 8) Bonne pratique pour le compte racine une fois la configuration initiale faite

- **Réponse correcte :** **Supprimer les clés d’accès de l’utilisateur racine du compte AWS**
    
- **Autres options (fausses) :**
    
    - **Supprimer l’utilisateur racine** — impossible, il est obligatoire.
        
    - **Révoquer toutes les autorisations** — pas applicable au root.
        
    - **Restreindre les autorisations** — le root a toujours accès total.
        

---

### 9) Ajouter une sécurité supplémentaire à la connexion console d’un utilisateur

- **Réponse correcte :** **Activer l’authentification multifacteur (MFA)**
    
- **Autres options (fausses) :**
    
    - **Utiliser Amazon Cloud Directory** — non lié à la connexion console.
        
    - **Auditer les rôles IAM** — ne renforce pas directement la connexion.
        
    - **Activer CloudTrail** — sert à auditer, pas à sécuriser la connexion.
        

---

### 10) AWS KMS permet d’auditer et d’évaluer les configurations de ressources (V/F)

- **Réponse correcte :** **Faux**
    
- **Explication :** AWS KMS sert à gérer des **clés de chiffrement**. Le service qui évalue les configurations est **AWS Config**.
    
- **Autre option (fausse) :** **Vrai**.


# QCM AWS – Module 5 : Réseau et Amazon VPC

> Chaque question comporte la **réponse correcte**, puis **toutes les autres options fausses avec explication**.

---

### 1) Plus petite taille de sous-réseau dans un VPC

- **Réponse correcte :** **/28** — 16 adresses IP, dont 11 utilisables après la réserve AWS.
    
- **Autres options (fausses) :**
    
    - **/30** — non valide pour un sous-réseau VPC.
        
    - **/24** et **/26** — valides mais plus grands que la taille minimale.
        

---

### 2) Taille maximale d’un VPC

- **Réponse correcte :** **/16** — 65 536 adresses IP totales.
    
- **Autres options (fausses) :**
    
    - **/24**, **/28**, **/30** — plages valides mais plus petites.
        

---

### 3) Ressources d’un sous-réseau privé pour accéder à Internet

- **Réponse correcte :** **Passerelle NAT** — permet aux instances privées de sortir vers Internet.
    
- **Autres options (fausses) :**
    
    - **Tables de routage** — nécessaires mais ne suffisent pas.
        
    - **Groupes de sécurité** et **ACL réseau** — contrôlent le trafic mais n’autorisent pas l’accès à Internet.
        

---

### 4) Service permettant de créer un réseau virtuel

- **Réponse correcte :** **Amazon VPC** — crée un réseau virtuel isolé dans AWS.
    
- **Autres options (fausses) :**
    
    - **Amazon Route 53** — service DNS.
        
    - **AWS Direct Connect** — lien privé vers AWS, pas un réseau virtuel.
        
    - **AWS Config** — service d’audit et conformité.
        

---

### 5) Sous-réseaux privés ont un accès direct à Internet (V/F)

- **Réponse correcte :** **Faux** — ils doivent passer par une NAT Gateway.
    
- **Autre option (fausse) :** **Vrai**.
    

---

### 6) Composant utilisé par CloudFront pour faible latence

- **Réponse correcte :** **Emplacements périphériques AWS (Edge Locations)** — points de présence du CDN.
    
- **Autres options (fausses) :**
    
    - **Régions AWS** — regroupent des AZ, pas des POP.
        
    - **Zones de disponibilité** — visent la tolérance aux pannes, pas la distribution CDN.
        
    - **Amazon VPC** — réseau virtuel, pas CDN.
        

---

### 7) Contrôle de sécurité facultatif au niveau sous-réseau

- **Réponse correcte :** **ACL réseau** — liste de contrôle d’accès au niveau sous-réseau.
    
- **Autres options (fausses) :**
    
    - **Groupes de sécurité** — agissent au niveau instance.
        
    - **Pare-feu** / **WAF** — mécanismes génériques ou applicatifs, pas spécifiques au VPC.
        

---

### 8) Création d’un nouveau VPC (non le VPC par défaut)

- **Réponse correcte :** **Une table de routage principale est créée par défaut.**
    
- **Autres options (fausses) :**
    
    - **Trois sous-réseaux créés** — uniquement dans un VPC par défaut, pas un nouveau.
        
    - **Une Internet Gateway créée par défaut** — non, elle doit être ajoutée manuellement.
        

---

### 9) Protection directe d’une instance EC2

- **Réponse correcte :** **Groupe de sécurité** — firewall virtuel au niveau instance.
    
- **Autres options (fausses) :**
    
    - **AMI** — modèle d’instance, pas de protection.
        
    - **Passerelle Internet** — connectivité Internet, pas de sécurité.
        
    - **Toutes les réponses** — incorrect car seules les SG protègent vraiment l’instance.
        

---

### 10) Nombre d’adresses IP utilisables dans un bloc /24

- **Réponse correcte :** **251** — 256 totales, 5 réservées par AWS.
    
- **Autres options (fausses) :**
    
    - **256** — inclut les adresses réservées.
        
    - **250** ou **246** — sous-estimation, car seulement 5 sont réservées.


# QCM AWS – Module 6 : Calcul et Amazon EC2

> Chaque question comporte la **réponse correcte**, puis **les autres options avec explication**.

---

### 1) Pourquoi AWS est-il plus économique que les centres de données traditionnels pour des charges de travail variables ?

- ✅ **Les instances Amazon EC2 peuvent être lancées à la demande, si nécessaire.**
    
- ❌ **Les coûts Amazon EC2 sont facturés mensuellement.** — Faux, facturation **à l’heure/seconde**, pas mensuelle fixe.
    
- ❌ **Les clients conservent un accès administratif complet.** — Vrai mais pas lié à l’économie.
    
- ❌ **Les clients peuvent exécuter en permanence suffisamment d’instances.** — Ce serait coûteux et contraire au principe d’élasticité.
    

---

### 2) Si votre projet nécessite des rapports mensuels sur de très grands volumes de données, quelle option d’achat EC2 est recommandée ?

- ✅ **Instances réservées programmées** — idéales pour des charges récurrentes à intervalles précis (mensuelles).
    
- ❌ **Instances Spot** — économiques mais pas garanties, risqué pour un besoin récurrent.
    
- ❌ **Hôtes dédiés** — répondent aux besoins de conformité/licences, pas à un simple job mensuel.
    
- ❌ **Instances à la demande** — flexibles mais plus coûteuses à long terme que les réservées programmées.
    

---

### 3) Quel élément fait partie intégrante d’une image AMI ?

- ✅ **Tous les éléments ci-dessus** :
    
    - Modèle pour le volume racine.
        
    - Autorisations de lancement.
        
    - Mappage des volumes en mode bloc.
        
- Les autres options isolées (modèle, autorisations, mapping) ne suffisent pas seules.
    

---

### 4) Quelle fonction Amazon EC2 garantit que vos instances ne partageront pas un hôte physique avec celles d’autres clients ?

- ✅ **Instances dédiées** — vos instances sont sur un matériel isolé.
    
- ❌ **Amazon VPC** — isole logiquement le réseau, pas physiquement les serveurs.
    
- ❌ **Groupes de placement** — gèrent la proximité/répartition des instances, pas l’exclusivité physique.
    
- ❌ **Instances réservées** — engagement de facturation, pas d’isolation matérielle.
    

---

### 5) Lequel est un service de calcul **sans serveur** dans AWS ?

- ✅ **AWS Lambda** — exécution de code à la demande, sans gérer de serveurs.
    
- ❌ **AWS Config** — service d’audit/évaluation de la config.
    
- ❌ **AWS OpsWorks** — gestion de configuration (Chef, Puppet).
    
- ❌ **Amazon EC2** — nécessite gestion des serveurs.
    

---

### 6) Quel service permet aux développeurs de déployer et gérer facilement des applications dans le cloud ?

- ✅ **AWS Elastic Beanstalk** — PaaS qui déploie automatiquement apps et ressources associées.
    
- ❌ **Amazon ECS** — gestion des conteneurs, plus technique.
    
- ❌ **AWS OpsWorks** — gestion de configuration, pas un déploiement simple d’apps.
    
- ❌ **AWS CloudFormation** — infrastructure as code, pas directement focalisé sur les apps.
    

---

### 7) Votre application web nécessite 4 instances en continu, mais le dernier jour du mois le trafic triple. Quelle option est la plus rentable ?

- ✅ **Exécuter 4 instances réservées en permanence + ajouter 8 instances à la demande le dernier jour.**
    
- ❌ **12 instances réservées en permanence.** — coûte trop cher inutilement.
    
- ❌ **4 instances à la demande + 8 de plus le dernier jour.** — flexible mais beaucoup plus coûteux que de réserver le socle permanent.
    
- ❌ **4 instances à la demande + 8 réservées le dernier jour.** — incohérent, les réservées s’engagent à long terme, pas pour 1 jour.
    

---

### 8) Vrai ou faux : Les conteneurs contiennent un système d’exploitation complet.

- ✅ **Faux** — ils partagent le noyau de l’OS hôte et contiennent uniquement ce qui est nécessaire pour l’application.
    
- ❌ **Vrai** — ce serait le cas des **VM**, pas des conteneurs.
    

---

### 9) Quelle option EC2 est la plus appropriée pour des charges de travail à long terme avec un usage prévisible ?

- ✅ **Instances réservées** — jusqu’à 75 % d’économie pour des workloads stables et prévisibles.
    
- ❌ **Instances Spot** — risquées car interrompues.
    
- ❌ **Instances à la demande** — flexibles mais plus chères à long terme.
    

---

### 10) Quels éléments doivent être spécifiés lors du lancement d’une instance Windows EC2 ?

- ✅ **Type d’instance EC2** — définit la puissance de calcul.
    
- ✅ **Amazon Machine Image (AMI)** — définit l’OS et les logiciels de base.
    
- ❌ **Mot de passe admin** — généré après le lancement.
    
- ❌ **ID d’instance** — attribué automatiquement.


# QCM AWS – Module 7 : Stockage

> Chaque question comporte la **réponse correcte**, puis **les autres options avec explication**.

---

### 1) Vrai ou faux ? Amazon S3 est un stockage d’objets pour fichiers plats (Word, photos, etc.)

- ✅ **Vrai** — Amazon S3 est conçu pour stocker et gérer des objets (fichiers) de tout type.
    
- ❌ **Faux** — S3 n’est pas un système de fichiers ni une base de données, mais bien du stockage objet.
    

---

### 2) Amazon S3 réplique tous les objets ______.

- ✅ **Dans plusieurs zones de disponibilité au sein de la même région** — garantit durabilité et haute disponibilité.
    
- ❌ **Dans plusieurs volumes au sein d’une AZ** — insuffisant, une AZ seule peut tomber.
    
- ❌ **Dans plusieurs régions** — uniquement si configuré avec S3 Cross-Region Replication.
    
- ❌ **Dans plusieurs compartiments** — réplication entre buckets = configuration manuelle.
    

---

### 3) Quelles classes de stockage peuvent être utilisées pour une politique de cycle de vie S3 ? (3 réponses)

- ✅ **S3 – Accès standard** — pour données fréquemment utilisées.
    
- ✅ **S3 – Accès peu fréquent (IA)** — moins cher, pour données rarement lues.
    
- ✅ **S3 Glacier** — stockage d’archives à très bas coût.
    
- ❌ **S3 – Stockage à redondance réduite** — obsolète, déconseillé.
    
- ❌ **AWS Storage Gateway** — sert pour l’intégration hybride, pas une classe S3.
    
- ❌ **Amazon DynamoDB** — base NoSQL, rien à voir.
    

---

### 4) Le nom d’un compartiment S3 doit être unique ______.

- ✅ **Partout dans le monde, dans tous les comptes AWS** — le namespace S3 est global.
    
- ❌ **Au sein d’une région** — faux, un nom est unique globalement.
    
- ❌ **Dans vos comptes AWS** — faux, il faut éviter les doublons même entre comptes différents.
    
- ❌ **Dans votre compte** — insuffisant, les noms sont partagés mondialement.
    

---

### 5) Vous pouvez utiliser Amazon EFS pour :

- ✅ **Implémenter un stockage partagé pour instances EC2, accessible par plusieurs VM simultanément.**
    
- ❌ **Stockage simple élastique pour AWS uniquement** — correspond plus à S3.
    
- ❌ **Héberger un CDN solide pour contenu statique/dynamique/streaming** — c’est **Amazon CloudFront**.
    
- ❌ **Générer du contenu spécifique à l’utilisateur** — c’est le rôle d’applications, pas du stockage.
    

---

### 6) Amazon Elastic Block Store (EBS) est recommandé lorsque les données ______ et ______. (2 réponses)

- ✅ **Nécessitent un stockage au niveau de l’objet (bloc)** — EBS est du stockage bloc persistant.
    
- ✅ **Doivent être rapidement accessibles avec persistance à long terme** — idéal pour volumes attachés aux EC2.
    
- ❌ **Nécessitent du chiffrement** — possible mais ce n’est pas le critère principal.
    
- ❌ **Doivent être stockées dans une autre AZ** — faux, EBS est limité à une AZ.
    

---

### 7) Vrai ou faux ? Par défaut, toutes les données S3 sont visibles par tous.

- ✅ **Faux** — par défaut, S3 est privé, seul le propriétaire du bucket y a accès.
    
- ❌ **Vrai** — il faut explicitement configurer les ACL/policies pour rendre public.
    

---

### 8) Dans Amazon S3 Glacier, un « coffre » est :

- ✅ **Un conteneur pour le stockage des archives.**
    
- ❌ **Des règles d’accès** — ce sont des policies, pas des coffres.
    
- ❌ **Un objet (photo, vidéo, doc)** — ce sont les archives stockées dans le coffre.
    
- ❌ **Une politique d’accès** — encore une fois, pas la définition.
    

---

### 9) Vrai ou faux ? Lorsqu’on crée un compartiment S3, il est associé à une région spécifique.

- ✅ **Vrai** — un bucket appartient toujours à une région, même si son nom est global.
    
- ❌ **Faux** — il n’est jamais global, le choix de région est obligatoire.
    

---

### 10) Quelles fonctions sont offertes par Amazon EBS ? (2 réponses)

- ✅ **Chiffrement transparent des volumes EBS** — activable avec KMS.
    
- ✅ **Réplication automatique des données dans une AZ** — assure durabilité et haute disponibilité locale.
    
- ❌ **Sauvegarde auto sur bande** — non, il faut créer des **snapshots**.
    
- ❌ **Perte des données à l’arrêt d’une instance** — faux, EBS est persistant (contrairement à Instance Store).


# QCM AWS – Module 8 : Bases de données

> Chaque question comporte la **réponse correcte**, puis **les autres options avec explication**.

---

### 1) En tant que concepteur d’une application e-commerce devant gérer des centaines de milliers d’utilisateurs simultanés, quelle base de données recommander pour maintenir l’état de session ?

- ✅ **Amazon DynamoDB** — base NoSQL serverless, hautement scalable, idéale pour des millions de lectures/écritures par seconde.
    
- ❌ **Amazon RDS** — adapté aux bases relationnelles mais moins scalable à très grande échelle de sessions.
    
- ❌ **Amazon Redshift** — orienté entrepôt de données/analytique, pas pour des sessions temps réel.
    
- ❌ **Amazon S3** — stockage objet, pas une base de données.
    

---

### 2) Pour rechercher un élément DynamoDB via un attribut autre que la clé primaire, quelle opération utiliser ?

- ✅ **Scan** — parcourt l’intégralité de la table pour filtrer sur n’importe quel attribut.
    
- ❌ **PutItem** — insère un nouvel élément.
    
- ❌ **Query** — recherche efficace uniquement par clé primaire (partition + tri).
    
- ❌ **GetItem** — récupère un élément unique par clé primaire.
    

---

### 3) Dans DynamoDB, que permet l’opération **Query** ?

- ✅ **Interroger une table via la clé de partition et optionnellement un filtre sur la clé de tri.**
    
- ❌ **Interroger des index secondaires** — possible mais uniquement avec Query sur l’index défini, ce n’est pas la définition principale.
    
- ❌ **Extraire efficacement d’une table ou d’un index secondaire** — formulation trop vague.
    
- ❌ **Toutes les actions ci-dessus** — incorrect, Query n’est pas universel.
    

---

### 4) Quel service AWS Cloud est le plus approprié pour analyser vos données avec SQL et vos outils BI ?

- ✅ **Amazon Redshift** — entrepôt de données massivement parallèle, conçu pour l’analytique avec SQL.
    
- ❌ **Amazon RDS** — gère des bases relationnelles transactionnelles, pas du big data analytique.
    
- ❌ **Amazon Glacier** — stockage d’archivage, pas d’analytique.
    
- ❌ **Amazon DynamoDB** — NoSQL, pas adapté au SQL analytique.
    

---

### 5) Dans DynamoDB, un **attribut** est :

- ✅ **Un élément de données fondamental** — la plus petite unité (ex. : nom, âge).
    
- ❌ **Une collection d’éléments** — cela correspond à une table.
    
- ❌ **Une collection d’attributs** — cela correspond à un élément/item.
    

---

### 6) Si vous développez une application nécessitant des performances très élevées, une scalabilité rapide et un schéma flexible, quel service choisir ?

- ✅ **Amazon DynamoDB** — NoSQL serverless, conçu pour ces cas.
    
- ❌ **Amazon RDS** — relationnel, pas aussi flexible ni scalable horizontalement.
    
- ❌ **Amazon ElastiCache** — cache en mémoire, pas une base principale.
    
- ❌ **Amazon Redshift** — orienté analytique, pas pour transactions applicatives.
    

---

### 7) Parmi les cas suivants, lequel correspond à Amazon RDS ?

- ✅ **Transactions complexes** — RDS est conçu pour les opérations relationnelles complexes.
    
- ❌ **Taux de lecture/écriture massifs** — mieux gérés par DynamoDB.
    
- ❌ **Requêtes GET/PUT simples** — usage typique de DynamoDB.
    
- ❌ **Toutes les actions ci-dessus** — faux, RDS n’est pas optimal pour tous.
    

---

### 8) Une entreprise utilise une appli .NET avec MySQL et veut migrer sur AWS avec haute dispo et sauvegardes automatisées. Quelle DB choisir ?

- ✅ **Amazon Aurora** — compatible MySQL/PostgreSQL, haute disponibilité, performance améliorée.
    
- ❌ **Amazon RDS (MySQL)** — fonctionne mais Aurora offre plus de scalabilité et de performance.
    
- ❌ **Amazon DynamoDB** — NoSQL, pas compatible SQL.
    
- ❌ **Amazon Redshift** — analytique, pas transactionnel.
    

---

### 9) Vrai ou faux : Amazon RDS applique automatiquement correctifs, sauvegardes et permet restauration point-in-time.

- ✅ **Vrai** — c’est une fonctionnalité clé de RDS.
    
- ❌ **Faux** — incorrect.
    

---

### 10) Que prendre en compte lors du choix d’un type de base de données ?

- ✅ **Toutes les actions ci-dessus** :
    
    - Taille des données.
        
    - Période d’accès.
        
    - Fréquence d’interrogation.
        
    - Haute disponibilité.
