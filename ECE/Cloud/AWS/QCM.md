# QCM AWS – Module 2 : Tarification, Facturation & Support

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